"""MCP Trust Proxy (TRUS-2032) — a trust-first proxy in front of MCP servers.

Put it in front of any MCP server with **zero changes to the server**: point your
agent at the proxy, the proxy forwards to the upstream, and enforces trust in both
directions using the agentcert_tag verify core.

  • inbound  (TRUS-2034): verify the calling agent's AgentCert + TrustScore on tools/call
  • outbound (TRUS-2035/2038): gate on the upstream server's TrustScore (config or Trust Index)
  • rug-pull (TRUS-2036): pin each server's tool definitions and flag drift
  • guardrails (TRUS-2037): deny patterns on tool arguments (PII / secrets / injection)
  • routing  (TRUS-2033): many upstreams behind one endpoint, by path prefix
  • streamable-HTTP: JSON and SSE responses, session lifecycle (GET/POST/DELETE)
  • observability (TRUS-2041): /healthz /stats /metrics + structured JSON verdict logs

Shadow by default (decide + log, block nothing); enforce blocks with a JSON-RPC error.
Stdlib-only. Config via a JSON file (MCP_PROXY_CONFIG) or env for the single-upstream case.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from agentcert_tag import VerificationStatus  # noqa: E402

log = logging.getLogger("mcp-trust-proxy")
DEFAULT_BLOCK_ON = frozenset({"UNVERIFIED", "REVOKED", "EXPIRED"})


# ═══════════════════════════════════════════════════════════════════════════
#  Config + routing (TRUS-2033)
# ═══════════════════════════════════════════════════════════════════════════
class Upstream:
    def __init__(self, d: dict):
        self.path = d.get("path", "/")
        self.url = d["url"]
        self.min_score = int(d.get("min_score", 0))
        self.server_score = d.get("server_score")           # static score, or None
        self.ans_name = d.get("ans_name")                    # for Trust Index lookup


class Config:
    def __init__(self, raw: dict):
        self.mode = raw.get("mode", os.environ.get("TAG_MODE", "shadow"))
        self.fail_mode = raw.get("fail_mode", os.environ.get("TAG_FAIL_MODE", "closed"))
        self.port = int(raw.get("listen_port", os.environ.get("MCP_PROXY_PORT", "8081")))
        self.trust_index_url = raw.get("trust_index_url") or os.environ.get("MCP_PROXY_TRUST_INDEX_URL")
        self.upstreams = [Upstream(u) for u in raw.get("upstreams", [])]
        if not self.upstreams and os.environ.get("MCP_PROXY_UPSTREAM"):
            self.upstreams = [Upstream({
                "path": "/", "url": os.environ["MCP_PROXY_UPSTREAM"],
                "min_score": int(os.environ.get("MCP_PROXY_MIN_SERVER_SCORE", "0")),
                "server_score": (int(os.environ["MCP_PROXY_SERVER_SCORE"])
                                 if os.environ.get("MCP_PROXY_SERVER_SCORE") else None),
            })]
        self.guardrails = [Guardrail(g) for g in raw.get("guardrails", [])]

    @classmethod
    def load(cls) -> "Config":
        path = os.environ.get("MCP_PROXY_CONFIG")
        raw = json.load(open(path)) if path and os.path.exists(path) else {}
        return cls(raw)

    def route(self, path: str) -> Upstream | None:
        # longest matching path prefix wins
        best = None
        for u in self.upstreams:
            if path.startswith(u.path) and (best is None or len(u.path) > len(best.path)):
                best = u
        return best


# ═══════════════════════════════════════════════════════════════════════════
#  Guardrails (TRUS-2037) — deny patterns on tool arguments
# ═══════════════════════════════════════════════════════════════════════════
class Guardrail:
    def __init__(self, d: dict):
        self.name = d.get("name", "guardrail")
        self.pattern = re.compile(d["deny_pattern"])
        self.action = d.get("action", "block")   # block | flag


def guardrail_scan(guardrails, params: dict) -> list[str]:
    """Return the names of guardrails whose deny-pattern matched the tool arguments."""
    blob = json.dumps(params.get("arguments", params), ensure_ascii=False)
    return [g.name for g in guardrails if g.pattern.search(blob)]


# ═══════════════════════════════════════════════════════════════════════════
#  Rug-pull detection (TRUS-2036)
# ═══════════════════════════════════════════════════════════════════════════
class ToolPins:
    def __init__(self) -> None:
        self._pins: dict[str, dict[str, str]] = {}

    @staticmethod
    def _hash(tool: dict) -> str:
        return hashlib.sha256(json.dumps(tool, sort_keys=True).encode()).hexdigest()

    def diff(self, server: str, tools: list) -> list[str]:
        cur = {t.get("name", "?"): self._hash(t) for t in tools if isinstance(t, dict)}
        prev, drift = self._pins.get(server), []
        if prev is not None:
            for n, h in cur.items():
                drift.append(f"added:{n}" if n not in prev else (f"changed:{n}" if prev[n] != h else None))
            drift += [f"removed:{n}" for n in prev if n not in cur]
        self._pins[server] = cur
        return [d for d in drift if d]


# ═══════════════════════════════════════════════════════════════════════════
#  Discovery / server-trust (TRUS-2035 / 2038)
# ═══════════════════════════════════════════════════════════════════════════
class TrustIndex:
    """Resolves an upstream server's TrustScore. Config score first; else the public
    Trust Index API (agent_corpus); cached. Returns None if unknown."""

    def __init__(self, base_url: str | None):
        self.base = base_url.rstrip("/") if base_url else None
        self._cache: dict[str, tuple[float, int | None]] = {}
        self._ttl = 300

    def score(self, up: Upstream) -> int | None:
        if up.server_score is not None:
            return up.server_score
        if not (self.base and up.ans_name):
            return None
        hit = self._cache.get(up.ans_name)
        if hit and time.time() - hit[0] < self._ttl:
            return hit[1]
        val = None
        try:
            req = urllib.request.Request(f"{self.base}/v1/ans/{up.ans_name}")
            with urllib.request.urlopen(req, timeout=3) as r:
                val = (json.loads(r.read()).get("trust_score") or {}).get("value")
        except Exception:  # noqa: BLE001 - unknown score, gate decides
            val = None
        self._cache[up.ans_name] = (time.time(), val)
        return val


def server_trust_decision(score, *, min_score: int, mode: str):
    if min_score <= 0:
        return True, None
    ok = score is not None and score >= min_score
    return (True, None) if ok else ((mode != "enforce"), f"upstream server score {score} < required {min_score}")


# ═══════════════════════════════════════════════════════════════════════════
#  Inbound verify (TRUS-2034)
# ═══════════════════════════════════════════════════════════════════════════
def extract_cert_pem(headers) -> bytes | None:
    for k in headers:
        if k.lower() == "x-agentcert-token":
            v = headers[k]
            return v.encode() if "BEGIN CERTIFICATE" in v else _b64(v)
    return None


def _b64(v):
    try:
        return base64.b64decode(v)
    except Exception:  # noqa: BLE001
        return None


def _header(headers, name, default=None):
    for k in headers:
        if k.lower() == name:
            return headers[k]
    return default


def _proof(headers):
    raw = _header(headers, "x-agentcert-proof")
    if not raw:
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode())
    except Exception:  # noqa: BLE001
        return None


def inbound_decision(verifier, headers, *, mode: str, block_on=DEFAULT_BLOCK_ON):
    cert = extract_cert_pem(headers)
    if cert is None:
        status = VerificationStatus.UNVERIFIED.value
    else:
        res = verifier.verify(cert, carriage=_header(headers, "x-agentcert-carriage", "header"), proof=_proof(headers))
        status = res.verification_status.value
    return (mode != "enforce" or status not in block_on), status


# ═══════════════════════════════════════════════════════════════════════════
#  Observability (TRUS-2041)
# ═══════════════════════════════════════════════════════════════════════════
class Stats:
    def __init__(self):
        self._c: dict[str, int] = {}
        self._lock = threading.Lock()

    def inc(self, key, n=1):
        with self._lock:
            self._c[key] = self._c.get(key, 0) + n

    def snapshot(self):
        with self._lock:
            return dict(self._c)

    def prometheus(self) -> bytes:
        lines = []
        for k, v in self.snapshot().items():
            metric = "mcp_trust_proxy_" + re.sub(r"[^a-zA-Z0-9_]", "_", k)
            lines.append(f"{metric} {v}")
        return ("\n".join(lines) + "\n").encode()


# ═══════════════════════════════════════════════════════════════════════════
#  HTTP proxy handler
# ═══════════════════════════════════════════════════════════════════════════
def make_handler(ctx):
    cfg, verifier, pins, index, stats = (
        ctx["cfg"], ctx["verifier"], ctx["pins"], ctx["index"], ctx["stats"])

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _rpc_error(self, rid, code, message):
            self._json(200, {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}})

        def do_GET(self):
            if self.path == "/healthz":
                return self._json(200, {"ok": True})
            if self.path == "/stats":
                return self._json(200, stats.snapshot())
            if self.path == "/metrics":
                body = stats.prometheus()
                self.send_response(200); self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
                return
            self._relay("GET", None)          # SSE stream open

        def do_DELETE(self):
            self._relay("DELETE", None)       # session close

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n) if n else b"{}"
            try:
                req = json.loads(body or b"{}")
            except ValueError:
                req = {}
            method, rid = req.get("method"), req.get("id")
            up = cfg.route(self.path)
            if up is None:
                return self._rpc_error(rid, -32004, f"no upstream configured for path {self.path}")
            stats.inc("requests_total")

            if method == "tools/call":
                allow, status = inbound_decision(verifier, self.headers, mode=cfg.mode)
                stats.inc(f"verdict_{status}")
                log.info(json.dumps({"evt": "inbound", "verdict": status, "allow": allow, "mode": cfg.mode, "upstream": up.url}))
                if not allow:
                    stats.inc("blocked_agent"); return self._rpc_error(rid, -32001, f"agent not verified: {status}")
                # guardrails on tool arguments
                hits = guardrail_scan(cfg.guardrails, req.get("params", {}))
                if hits:
                    stats.inc("guardrail_hit")
                    log.warning(json.dumps({"evt": "guardrail", "matched": hits, "mode": cfg.mode}))
                    if cfg.mode == "enforce" and any(g.action == "block" for g in cfg.guardrails if g.name in hits):
                        stats.inc("blocked_guardrail"); return self._rpc_error(rid, -32005, f"guardrail blocked: {hits}")
                # outbound server-trust gate
                s_allow, s_reason = server_trust_decision(index.score(up), min_score=up.min_score, mode=cfg.mode)
                if not s_allow:
                    stats.inc("blocked_server"); log.warning(json.dumps({"evt": "server_gate", "reason": s_reason}))
                    return self._rpc_error(rid, -32002, s_reason)

            self._relay("POST", body, method=method, upstream=up)

        # -- forward + stream ------------------------------------------------
        def _relay(self, http_method, body, *, method=None, upstream=None):
            up = upstream or cfg.route(self.path)
            if up is None:
                self.send_response(404); self.end_headers(); return
            fwd = {}
            for k in self.headers:
                if k.lower().startswith("x-agentcert") or k.lower() in ("content-type", "accept", "mcp-session-id", "last-event-id"):
                    fwd[k] = self.headers[k]
            target = up.url + self.path[len(up.path):] if self.path.startswith(up.path) else up.url
            req = urllib.request.Request(target, data=body, headers=fwd, method=http_method)
            try:
                resp = urllib.request.urlopen(req, timeout=120)
            except Exception as exc:  # noqa: BLE001
                stats.inc("upstream_error"); return self._rpc_error(None, -32003, f"upstream unreachable: {exc}")

            ctype = resp.headers.get("Content-Type", "application/json")
            if "text/event-stream" in ctype:
                # stream SSE straight through (Connection: close so no Content-Length)
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                if resp.headers.get("Mcp-Session-Id"):
                    self.send_header("Mcp-Session-Id", resp.headers["Mcp-Session-Id"])
                self.send_header("Cache-Control", "no-cache"); self.send_header("Connection", "close")
                self.end_headers()
                try:
                    while True:
                        chunk = resp.read(1024)
                        if not chunk:
                            break
                        self.wfile.write(chunk); self.wfile.flush()
                except Exception:  # noqa: BLE001 - client disconnect
                    pass
                return
            # buffered JSON response
            payload = resp.read()
            if method == "tools/list":
                try:
                    drift = pins.diff(up.url, json.loads(payload).get("result", {}).get("tools", []))
                    if drift:
                        stats.inc("rug_pull"); log.warning(json.dumps({"evt": "rug_pull", "upstream": up.url, "drift": drift}))
                except Exception:  # noqa: BLE001
                    pass
            self.send_response(resp.status)
            self.send_header("Content-Type", ctype)
            if resp.headers.get("Mcp-Session-Id"):
                self.send_header("Mcp-Session-Id", resp.headers["Mcp-Session-Id"])
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    return Handler


def _build_verifier():
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
    cfg = Config.load()
    if not cfg.upstreams:
        raise SystemExit("configure at least one upstream (MCP_PROXY_CONFIG or MCP_PROXY_UPSTREAM)")
    ctx = {"cfg": cfg, "verifier": _build_verifier(), "pins": ToolPins(),
           "index": TrustIndex(cfg.trust_index_url), "stats": Stats()}
    log.info(json.dumps({"evt": "start", "mode": cfg.mode, "port": cfg.port,
                         "upstreams": [(u.path, u.url) for u in cfg.upstreams]}))
    ThreadingHTTPServer(("0.0.0.0", cfg.port), make_handler(ctx)).serve_forever()


if __name__ == "__main__":
    main()
