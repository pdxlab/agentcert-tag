"""MCP Trust Proxy (TRUS-2032) — a trust-first proxy in front of MCP servers.

Sits between agents and one or more upstream MCP servers and enforces trust in
BOTH directions, reusing the agentcert_tag verify core:

  • inbound  (TRUS-2034): verify the CALLING agent's AgentCert + TrustScore on every
    tools/call (proof-of-possession on the header carriage). shadow → log; enforce → block.
  • outbound (TRUS-2035): gate on the UPSTREAM server's TrustScore vs a threshold.
  • rug-pull (TRUS-2036): pin each server's tool definitions and flag drift.

Shadow by default (decides + logs, blocks nothing). Stdlib-only HTTP so the
container stays tiny. The decision logic below is factored into pure functions so
it is unit-testable without a live upstream.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from agentcert_tag import VerificationStatus  # noqa: E402

log = logging.getLogger("mcp-trust-proxy")

# Verdicts that block a tool call in enforce mode.
DEFAULT_BLOCK_ON = frozenset({"UNVERIFIED", "REVOKED", "EXPIRED"})


# --------------------------------------------------------------------------- #
#  Rug-pull detection — pin tool definitions, flag drift (TRUS-2036)          #
# --------------------------------------------------------------------------- #
class ToolPins:
    """Pins the tool schema a server advertised and reports drift on the next
    listing. A silent change to an approved tool (a "rug pull") is the signal."""

    def __init__(self) -> None:
        self._pins: dict[str, dict[str, str]] = {}

    @staticmethod
    def _hash(tool: dict) -> str:
        return hashlib.sha256(json.dumps(tool, sort_keys=True).encode()).hexdigest()

    def diff(self, server: str, tools: list) -> list[str]:
        cur = {t.get("name", "?"): self._hash(t) for t in tools if isinstance(t, dict)}
        prev = self._pins.get(server)
        drift: list[str] = []
        if prev is not None:
            for name, h in cur.items():
                if name not in prev:
                    drift.append(f"added:{name}")
                elif prev[name] != h:
                    drift.append(f"changed:{name}")
            for name in prev:
                if name not in cur:
                    drift.append(f"removed:{name}")
        self._pins[server] = cur
        return drift


# --------------------------------------------------------------------------- #
#  Pure decision functions (unit-testable)                                    #
# --------------------------------------------------------------------------- #
def extract_cert_pem(headers) -> bytes | None:
    """Pull the AgentCert leaf PEM from the request headers (raw PEM or base64)."""
    val = None
    for k in headers:
        if k.lower() == "x-agentcert-token":
            val = headers[k]
            break
    if not val:
        return None
    if "BEGIN CERTIFICATE" in val:
        return val.encode()
    try:
        return base64.b64decode(val)
    except Exception:  # noqa: BLE001
        return None


def _extract_proof(headers) -> dict | None:
    for k in headers:
        if k.lower() == "x-agentcert-proof":
            try:
                raw = headers[k]
                return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode())
            except Exception:  # noqa: BLE001
                return None
    return None


def _carriage(headers) -> str:
    for k in headers:
        if k.lower() == "x-agentcert-carriage":
            return headers[k]
    return "header"


def inbound_decision(verifier, headers, *, mode: str, block_on=DEFAULT_BLOCK_ON):
    """Verify the calling agent. Returns (allow: bool, status: str). In shadow
    mode allow is always True (log only); in enforce a blocked verdict → False."""
    cert = extract_cert_pem(headers)
    if cert is None:
        status = VerificationStatus.UNVERIFIED.value  # no credential presented
    else:
        result = verifier.verify(cert, carriage=_carriage(headers), proof=_extract_proof(headers))
        status = result.verification_status.value
    allow = mode != "enforce" or status not in block_on
    return allow, status


def server_trust_decision(score, *, min_score: int, mode: str):
    """Gate on the upstream server's TrustScore. Returns (allow, reason)."""
    if min_score <= 0:
        return True, None
    ok = score is not None and score >= min_score
    if ok:
        return True, None
    reason = f"upstream server score {score} < required {min_score}"
    return (mode != "enforce"), reason


# --------------------------------------------------------------------------- #
#  HTTP proxy                                                                  #
# --------------------------------------------------------------------------- #
def _forward(upstream: str, body: bytes, headers) -> tuple[int, bytes, str]:
    fwd = {"Content-Type": headers.get("Content-Type", "application/json")}
    for k in headers:
        if k.lower().startswith("x-agentcert") or k.lower() in ("accept", "mcp-session-id"):
            fwd[k] = headers[k]
    req = urllib.request.Request(upstream, data=body, headers=fwd, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, r.read(), r.headers.get("Content-Type", "application/json")


def make_handler(cfg):
    verifier, pins = cfg["verifier"], cfg["pins"]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet default logging
            pass

        def _send(self, code, body: bytes, ctype="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _rpc_error(self, rid, code, message):
            self._send(200, json.dumps({
                "jsonrpc": "2.0", "id": rid,
                "error": {"code": code, "message": message},
            }).encode())

        def do_GET(self):
            if self.path == "/healthz":
                return self._send(200, b'{"ok":true}')
            self._send(404, b'{"error":"not found"}')

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n) if n else b"{}"
            try:
                req = json.loads(body or b"{}")
            except ValueError:
                req = {}
            method, rid = req.get("method"), req.get("id")

            if method == "tools/call":
                allow, status = inbound_decision(verifier, self.headers, mode=cfg["mode"])
                log.info("[proxy] inbound tools/call verdict=%s allow=%s mode=%s", status, allow, cfg["mode"])
                if not allow:
                    return self._rpc_error(rid, -32001, f"agent not verified: {status}")
                s_allow, s_reason = server_trust_decision(cfg["server_score"], min_score=cfg["min_score"], mode=cfg["mode"])
                if not s_allow:
                    log.warning("[proxy] outbound blocked: %s", s_reason)
                    return self._rpc_error(rid, -32002, s_reason)

            try:
                code, resp, ctype = _forward(cfg["upstream"], body, self.headers)
            except Exception as exc:  # never 500 the caller's dependency
                return self._rpc_error(rid, -32003, f"upstream unreachable: {exc}")

            if method == "tools/list":
                try:
                    tools = json.loads(resp).get("result", {}).get("tools", [])
                    drift = pins.diff(cfg["upstream"], tools)
                    if drift:
                        log.warning("[proxy] RUG-PULL drift on %s: %s", cfg["upstream"], drift)
                except Exception:  # noqa: BLE001
                    pass
            self._send(code, resp, ctype)

    return Handler


def _build_verifier():
    import time
    from cryptography.hazmat.primitives.asymmetric import ec
    from agentcert_tag import HttpTrustSource, InMemoryTrustSource, Mode, FailMode, Verifier
    path = os.environ.get("TAG_ANCHORS_PEM")
    if not path:
        raise SystemExit("TAG_ANCHORS_PEM must point at the trust-anchor bundle")
    for _ in range(50):
        if os.path.exists(path) and os.path.getsize(path) > 0:
            break
        time.sleep(0.2)
    blob = open(path).read()
    parts, cur = [], []
    for line in blob.splitlines():
        cur.append(line)
        if "END CERTIFICATE" in line:
            parts.append("\n".join(cur) + "\n"); cur = []
    base = os.environ.get("TRUSTMODEL_BASE_URL")
    trust = (HttpTrustSource(base, parts, api_key=os.environ.get("TRUSTMODEL_API_KEY"))
             if base else InMemoryTrustSource(parts))
    return Verifier(trust, mode=os.environ.get("TAG_MODE", Mode.SHADOW),
                    fail_mode=os.environ.get("TAG_FAIL_MODE", FailMode.CLOSED),
                    signing_key=ec.generate_private_key(ec.SECP256R1()))


def main():
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    cfg = {
        "upstream": os.environ["MCP_PROXY_UPSTREAM"],
        "mode": os.environ.get("TAG_MODE", "shadow"),
        "min_score": int(os.environ.get("MCP_PROXY_MIN_SERVER_SCORE", "0")),
        "server_score": (int(os.environ["MCP_PROXY_SERVER_SCORE"])
                         if os.environ.get("MCP_PROXY_SERVER_SCORE") else None),
        "verifier": _build_verifier(),
        "pins": ToolPins(),
    }
    port = int(os.environ.get("MCP_PROXY_PORT", "8081"))
    log.info("MCP Trust Proxy → upstream=%s mode=%s port=%s", cfg["upstream"], cfg["mode"], port)
    ThreadingHTTPServer(("0.0.0.0", port), make_handler(cfg)).serve_forever()


if __name__ == "__main__":
    main()
