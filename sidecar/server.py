#!/usr/bin/env python3
"""TAG verify sidecar — the generic reverse-proxy/verify service (TRUS-1821).

Exposes the verification core over HTTP so any host that can make an HTTP call
(Kong plugin, Envoy ext_authz, a plain reverse proxy) becomes an AgentCert
verifier without re-implementing crypto. Stdlib only — no framework — so the
container stays tiny (NFR-4).

  POST /verify      {"credential": "<base64 PEM leaf>", "carriage": "header|mtls"}
                    -> VerificationResult JSON (TAG_requirements §5)
  ANY  /ext_authz   ext_authz-native check: reads the AgentCert from a request
                    header, returns 200 (allow) / 403 (deny) with x-agentcert-*
                    verdict headers. Drop-in behind Envoy/agentgateway/Kuadrant
                    ext_authz — no verdict parsing on the gateway side.
  GET  /healthz     -> {"ok": true, "mode": "...", "version": "..."}

Config via env:
  TAG_MODE                 shadow|enforce           (default shadow)
  TAG_FAIL_MODE            open|closed              (default closed)
  TAG_ANCHORS_PEM          path to trust anchor bundle (root[+issuing]) PEM
  TRUSTMODEL_BASE_URL      real backend base (reputation/transparency); omit for sandbox
  TRUSTMODEL_API_KEY       verification-read-only key (Bearer)
  TAG_SANDBOX_SEED         path to seed JSON {agent_uri: score, ...} when no backend
  TAG_PORT                 default 8080

  ext_authz endpoint (all optional, sane defaults):
  TAG_EXTAUTHZ_PATH        path the gateway calls        (default /ext_authz)
  TAG_CERT_HEADER          header carrying b64 PEM leaf  (default x-agent-cert)
  TAG_PROOF_HEADER         header carrying PoP assertion (default x-agent-cert-proof)
  TAG_AGENT_ID_HEADER      claimed agent id (optional)   (default x-agent-id)
  TAG_AUDIENCE_HEADER      PoP audience (optional)       (default x-agent-cert-audience)
  TAG_CARRIAGE_HEADER      header|mtls                   (default x-agent-cert-carriage)
  TAG_MIN_SCORE            enforce: require score >= N to allow (default: VERIFIED alone)
"""
import base64
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from agentcert_tag import (  # noqa: E402
    HttpTrustSource, InMemoryTrustSource, Mode, FailMode, Verifier,
)

MODE = os.environ.get("TAG_MODE", Mode.SHADOW)
FAIL = os.environ.get("TAG_FAIL_MODE", FailMode.CLOSED)

# --- ext_authz endpoint config -------------------------------------------------
EXTAUTHZ_PATH = os.environ.get("TAG_EXTAUTHZ_PATH", "/ext_authz")
CERT_HEADER = os.environ.get("TAG_CERT_HEADER", "x-agent-cert").lower()
PROOF_HEADER = os.environ.get("TAG_PROOF_HEADER", "x-agent-cert-proof").lower()
AGENT_ID_HEADER = os.environ.get("TAG_AGENT_ID_HEADER", "x-agent-id").lower()
AUDIENCE_HEADER = os.environ.get("TAG_AUDIENCE_HEADER", "x-agent-cert-audience").lower()
CARRIAGE_HEADER = os.environ.get("TAG_CARRIAGE_HEADER", "x-agent-cert-carriage").lower()
_min = os.environ.get("TAG_MIN_SCORE")
MIN_SCORE = int(_min) if _min not in (None, "") else None


def _anchors():
    import time
    path = os.environ.get("TAG_ANCHORS_PEM")
    if not path:
        raise SystemExit("TAG_ANCHORS_PEM must point at the trust-anchor bundle")
    # Tolerate the backend/anchor volume not being ready yet at boot.
    for _ in range(50):
        if os.path.exists(path) and os.path.getsize(path) > 0:
            break
        time.sleep(0.2)
    with open(path) as fh:
        blob = fh.read()
    # split concatenated PEM certs
    parts, cur = [], []
    for line in blob.splitlines():
        cur.append(line)
        if "END CERTIFICATE" in line:
            parts.append("\n".join(cur) + "\n")
            cur = []
    return parts


def _build_verifier():
    anchors = _anchors()
    base = os.environ.get("TRUSTMODEL_BASE_URL")
    if base:
        trust = HttpTrustSource(base, anchors, api_key=os.environ.get("TRUSTMODEL_API_KEY"))
    else:
        trust = InMemoryTrustSource(anchors)
        seed = os.environ.get("TAG_SANDBOX_SEED")
        if seed and os.path.exists(seed):
            for agent_uri, score in json.load(open(seed)).items():
                trust.set_score(agent_uri, int(score))
    return Verifier(trust, mode=MODE, fail_mode=FAIL,
                    signing_key=ec.generate_private_key(ec.SECP256R1()))


VERIFIER = _build_verifier()


def _pem_from_header(value):
    """A header carries the leaf as base64 PEM (headers can't hold newlines)."""
    if not value:
        return None
    if "BEGIN CERTIFICATE" in value:
        return value.encode()
    return base64.b64decode(value)


def _would_allow(result):
    """The one place TAG maps a verdict to allow/deny — reached ONLY when the
    operator has opted the sidecar into being the ext_authz decision point.
    VERIFIED (and >= TAG_MIN_SCORE when set) allows; everything else denies.
    An ERROR defers to fail-mode so a backend blip doesn't hard-block traffic
    when the operator chose fail-open."""
    st = result.verification_status.value
    if st == "ERROR":
        return FAIL == FailMode.OPEN
    if st != "VERIFIED":
        return False
    if MIN_SCORE is not None:
        v = result.trust_score.value
        return v is not None and v >= MIN_SCORE
    return True


def _verdict_headers(result, would_allow):
    """x-agentcert-* headers the gateway can log, route on, or inject upstream.
    Emitted on BOTH allow and deny so shadow-mode has full visibility."""
    ts = result.trust_score
    return {
        "x-agentcert-verdict": result.verification_status.value,
        "x-agentcert-agent-id": result.agent_id or "",
        "x-agentcert-trustscore": "" if ts.value is None else str(ts.value),
        "x-agentcert-tier": ts.tier.value,
        "x-agentcert-score-source": ts.source,
        "x-agentcert-cache-hit": "true" if result.cache_hit else "false",
        "x-agentcert-mode": MODE,
        # In shadow we always allow; surface what enforce WOULD do so operators
        # can measure impact before flipping the switch.
        "x-agentcert-shadow-would": "allow" if would_allow else "deny",
        "x-agentcert-decision": "allow" if (MODE == Mode.SHADOW or would_allow) else "deny",
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj, extra_headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # ---- ext_authz check (method-agnostic; cert rides in a header) ----------
    def _handle_extauthz(self):
        try:
            get = self.headers.get
            pem = _pem_from_header(get(CERT_HEADER))
            if pem is None:
                # No credential presented. Fail closed in enforce (identity
                # required); allow + flag in shadow so nothing breaks on install.
                would = FAIL == FailMode.OPEN
                hdrs = {
                    "x-agentcert-verdict": "UNVERIFIED", "x-agentcert-agent-id": "",
                    "x-agentcert-trustscore": "", "x-agentcert-tier": "Unknown",
                    "x-agentcert-score-source": "none", "x-agentcert-cache-hit": "false",
                    "x-agentcert-mode": MODE,
                    "x-agentcert-shadow-would": "allow" if would else "deny",
                    "x-agentcert-decision": "allow" if (MODE == Mode.SHADOW or would) else "deny",
                }
                if MODE == Mode.SHADOW or would:
                    return self._send(200, {"allow": True, "reason": "no credential (shadow/fail-open)"}, hdrs)
                return self._send(403, {"allow": False, "reason": "no AgentCert presented"}, hdrs)

            result = VERIFIER.verify(
                pem,
                claimed_agent_id=get(AGENT_ID_HEADER),
                carriage=get(CARRIAGE_HEADER, "header"),
                proof=get(PROOF_HEADER),
                audience=get(AUDIENCE_HEADER),
            )
            would = _would_allow(result)
            hdrs = _verdict_headers(result, would)
            if MODE == Mode.SHADOW or would:
                return self._send(200, {"allow": True, "verdict": result.verification_status.value}, hdrs)
            return self._send(403, {"allow": False, "verdict": result.verification_status.value,
                                    "reason": "agent failed AgentCert verification"}, hdrs)
        except Exception as exc:  # never 500 the gateway's dependency
            would = FAIL == FailMode.OPEN
            hdrs = {"x-agentcert-verdict": "ERROR", "x-agentcert-mode": MODE,
                    "x-agentcert-decision": "allow" if (MODE == Mode.SHADOW or would) else "deny"}
            if MODE == Mode.SHADOW or would:
                return self._send(200, {"allow": True, "reason": f"sidecar error (fail-open): {exc}"}, hdrs)
            return self._send(403, {"allow": False, "reason": f"sidecar error (fail-closed): {exc}"}, hdrs)

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"ok": True, "mode": MODE, "version": VERIFIER.verifier_id,
                                    "extauthz_path": EXTAUTHZ_PATH})
        if self.path.split("?")[0] == EXTAUTHZ_PATH:
            return self._handle_extauthz()
        self._send(404, {"error": "not found"})

    def do_HEAD(self):
        if self.path.split("?")[0] == EXTAUTHZ_PATH:
            return self._handle_extauthz()
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path.split("?")[0] == EXTAUTHZ_PATH:
            return self._handle_extauthz()
        if self.path != "/verify":
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(n) or b"{}")
            cred = payload.get("credential", "")
            # Accept raw PEM or base64-wrapped PEM (header carriage b64-encodes).
            if "BEGIN CERTIFICATE" in cred:
                pem = cred.encode()
            else:
                pem = base64.b64decode(cred)
            claimed = payload.get("claimed_agent_id")
            # carriage="mtls" (TLS proved possession) skips the stapled assertion;
            # otherwise a header-carried public cert must ship a proof-of-possession.
            result = VERIFIER.verify(
                pem, claimed_agent_id=claimed,
                carriage=payload.get("carriage", "header"),
                proof=payload.get("proof"),
                audience=payload.get("audience"),
            )
            # detail is metadata-only (no PHI/PII) and powers shadow-mode logs.
            self._send(200, result.to_dict(include_detail=True))
        except Exception as exc:  # never 500 the gateway's dependency
            self._send(200, {
                "verification_status": "ERROR", "cert_valid": False,
                "agent_id": None, "trust_score": {"value": None, "tier": "Unknown"},
                "attestation": {"signed_by": VERIFIER.verifier_id},
                "cache_hit": False, "detail": f"sidecar error: {exc}",
            })

    def log_message(self, *args):  # quiet; real deploys ship logs via the host
        pass


def main():
    port = int(os.environ.get("TAG_PORT", "8080"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"TAG verify sidecar on :{port} mode={MODE} fail={FAIL} "
          f"ext_authz={EXTAUTHZ_PATH}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
