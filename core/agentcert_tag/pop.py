"""Proof-of-possession (stapled assertion) for the header carriage.

A presented AgentCert is a *public* object (it's discoverable in the ANS directory
and the transparency log), so on a non-mTLS carriage the cert alone proves nothing:
anyone who copies it can claim the identity. To close that replay hole the presenter
staples a short assertion signed with its **leaf private key** over a payload that
binds the identity, an audience, and a freshness window. The verifier checks that
signature against the leaf's public key — which only the true agent can produce.

On the mTLS carriage the TLS handshake already proves possession, so no assertion is
required there. This module is the reference producer; ``Verifier._verify_pop`` is the
consumer. Any re-implementation (Lua/TS) must produce/consume the same bytes.
"""
from __future__ import annotations

import base64
import json
import time
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa

DEFAULT_TTL_S = 120


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(private_key, message: bytes) -> bytes:
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    if isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return private_key.sign(message)
    raise TypeError(f"unsupported leaf key type: {type(private_key).__name__}")


def build_assertion(private_key, sub: str, *, audience: Optional[str] = None,
                    ttl_s: int = DEFAULT_TTL_S, now: Optional[int] = None) -> dict:
    """Build a stapled proof-of-possession assertion for ``sub`` (the agent's
    ans:// identity), signed with the agent's leaf private key. Returns the dict
    the caller ships alongside the cert as ``proof``."""
    iat = int(now if now is not None else time.time())
    claims = {"sub": sub, "iat": iat, "exp": iat + int(ttl_s)}
    if audience is not None:
        claims["aud"] = audience
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    return {"payload": _b64u(payload), "sig": base64.b64encode(_sign(private_key, payload)).decode()}
