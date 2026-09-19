"""trustmodel-agentcert-tag — verify an AgentCert + TrustScore inside a Python MCP server.

The verification decision itself is made by a TAG verify endpoint (a local sidecar or a
hosted endpoint); this package is a thin, dependency-free client + gate you drop in front
of your tool calls. It is a no-op unless verification is turned on, and defaults to shadow
mode (log, never block), so it is safe to merge.

Typical use inside an MCP server's tool-call path:

    from trustmodel_agentcert_tag import verify_gate, extract_token

    guard = verify_gate(mode="shadow")           # shadow | enforce

    async def handle_tool_call(request):
        token = extract_token(request.headers)   # X-AgentCert-Token or mTLS-derived
        await guard(token)                       # logs (shadow) / raises (enforce) on bad verdict
        return await dispatch(request)

Environment:
    TRUSTMODEL_VERIFY=1            enable (otherwise verify_gate() is a no-op passthrough)
    TRUSTMODEL_VERIFY_URL=...      TAG verify endpoint (default http://localhost:8080/verify)
    TRUSTMODEL_MODE=enforce        override mode to enforce
"""
from __future__ import annotations

import base64
import json
import logging
import os
import urllib.request
from typing import Awaitable, Callable, Iterable, Mapping, Optional

__version__ = "0.2.0"
__all__ = ["verify_gate", "verify", "extract_token", "extract_proof",
           "VerificationResult", "VerifyError"]

log = logging.getLogger("agentcert-tag")

DEFAULT_HEADER = "x-agentcert-token"
# A presented cert is public, so on a non-mTLS carriage the caller must also ship
# a proof-of-possession (a leaf-signed stapled assertion) in this header; we
# forward it to the verify endpoint, which rejects a bare cert without it.
PROOF_HEADER = "x-agentcert-proof"
CARRIAGE_HEADER = "x-agentcert-carriage"
DEFAULT_VERIFY_URL = "http://localhost:8080/verify"
DEFAULT_BLOCK_ON = ("REVOKED", "UNVERIFIED")


class VerificationResult(dict):
    """Structured TAG result. Keys: verification_status, agent_id, cert_valid,
    trust_score{value,tier}, detail."""

    @property
    def status(self) -> str:
        return self.get("verification_status", "ERROR")

    @property
    def score(self):
        return (self.get("trust_score") or {}).get("value")

    @property
    def tier(self) -> str:
        return (self.get("trust_score") or {}).get("tier", "Unknown")


class VerifyError(Exception):
    """Raised in enforce mode when a verdict is in block_on."""

    def __init__(self, result: VerificationResult):
        self.result = result
        super().__init__(f"agentcert-tag blocked: {result.status} ({result.get('detail','')})")


def _enabled() -> bool:
    return os.environ.get("TRUSTMODEL_VERIFY") == "1"


def verify(token: Optional[str], *, proof: Optional[dict] = None, carriage: str = "header",
           verify_url: Optional[str] = None, timeout: float = 3.0) -> VerificationResult:
    """POST the presented credential (+ proof-of-possession) to the TAG verify
    endpoint and return its result. Never raises on transport error — returns an
    ERROR result so the caller's fail policy decides."""
    url = verify_url or os.environ.get("TRUSTMODEL_VERIFY_URL", DEFAULT_VERIFY_URL)
    if not token:
        return VerificationResult(verification_status="UNVERIFIED", cert_valid=False,
                                  detail="no credential presented")
    payload: dict = {"credential": token, "carriage": carriage}
    if proof is not None:
        payload["proof"] = proof
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return VerificationResult(**json.loads(r.read().decode()))
    except Exception as exc:  # noqa: BLE001 - transport failures become an ERROR verdict
        return VerificationResult(verification_status="ERROR", detail=f"verify unreachable: {exc}")


def _header(headers: Optional[Mapping[str, str]], name: str) -> Optional[str]:
    if not headers:
        return None
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v[0] if isinstance(v, (list, tuple)) else v
    return None


def extract_token(headers: Optional[Mapping[str, str]], header: str = DEFAULT_HEADER) -> Optional[str]:
    """Case-insensitive lookup of the AgentCert credential header."""
    return _header(headers, header)


def extract_proof(headers: Optional[Mapping[str, str]], header: str = PROOF_HEADER) -> Optional[dict]:
    """Decode the stapled proof-of-possession header (base64url JSON of
    ``{payload, sig}``). Returns None when absent/malformed."""
    raw = _header(headers, header)
    if not raw:
        return None
    try:
        decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        obj = json.loads(decoded.decode())
        return obj if isinstance(obj, dict) else None
    except Exception:  # noqa: BLE001 - a malformed proof is simply "no proof"
        return None


def verify_gate(
    *,
    mode: str = "shadow",
    block_on: Iterable[str] = DEFAULT_BLOCK_ON,
    verify_url: Optional[str] = None,
    fail_mode: str = "closed",
    on_result: Optional[Callable[[VerificationResult], None]] = None,
) -> Callable[[Optional[str]], Awaitable[VerificationResult]]:
    """Return an async guard(token) -> VerificationResult.

    - Off entirely unless TRUSTMODEL_VERIFY=1 (guard returns immediately).
    - shadow (default): logs the decision, never raises.
    - enforce: raises VerifyError when the verdict is in block_on, or on ERROR when
      fail_mode='closed'.
    """
    effective_mode = "enforce" if os.environ.get("TRUSTMODEL_MODE") == "enforce" else mode
    block = set(block_on)

    async def guard(token: Optional[str], *, proof: Optional[dict] = None,
                    carriage: str = "header") -> VerificationResult:
        if not _enabled():
            return VerificationResult(verification_status="DISABLED")
        result = verify(token, proof=proof, carriage=carriage, verify_url=verify_url)
        log.info("[agentcert-tag] mode=%s status=%s score=%s tier=%s",
                 effective_mode, result.status, result.score, result.tier)
        if on_result:
            try:
                on_result(result)
            except Exception:  # noqa: BLE001 - a callback must never break the request
                log.exception("[agentcert-tag] on_result callback failed")
        if effective_mode == "enforce":
            bad = result.status in block or (result.status == "ERROR" and fail_mode == "closed")
            if bad:
                raise VerifyError(result)
        return result

    return guard
