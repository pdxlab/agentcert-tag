#!/usr/bin/env python3
"""TAG verify sidecar — the generic reverse-proxy/verify service (TRUS-1821).

Exposes the verification core over HTTP so any host that can make an HTTP call
(Kong plugin, Envoy ext_authz, a plain reverse proxy) becomes an AgentCert
verifier without re-implementing crypto. Stdlib only — no framework — so the
container stays tiny (NFR-4).

  POST /verify   {"credential": "<base64 PEM leaf>", "carriage": "header|mtls"}
                 -> VerificationResult JSON (TAG_requirements §5)
  GET  /healthz  -> {"ok": true, "mode": "...", "version": "..."}

Config via env:
  TAG_MODE                 shadow|enforce           (default shadow)
  TAG_FAIL_MODE            open|closed              (default closed)
  TAG_ANCHORS_PEM          path to trust anchor bundle (root[+issuing]) PEM
  TRUSTMODEL_BASE_URL      real backend base (reputation/transparency); omit for sandbox
  TRUSTMODEL_API_KEY       verification-read-only key (Bearer)
  TAG_SANDBOX_SEED         path to seed JSON {agent_uri: score, ...} when no backend
  TAG_PORT                 default 8080
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


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"ok": True, "mode": MODE, "version": VERIFIER.verifier_id})
        self._send(404, {"error": "not found"})

    def do_POST(self):
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
    print(f"TAG verify sidecar on :{port} mode={MODE} fail={FAIL}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
