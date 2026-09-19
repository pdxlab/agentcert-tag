"""Unit tests for the MCP Trust Proxy decision logic (TRUS-2032)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "proxy"))
sys.path.insert(0, os.path.dirname(__file__))

from test_verify import _pki, _pem  # reuse the PKI + cert builders
from agentcert_tag import InMemoryTrustSource, Verifier, build_assertion
from agentcert_tag.models import VerificationStatus
import mcp_trust_proxy as proxy


# ── rug-pull (ToolPins) ──
def test_toolpins_flags_drift():
    p = proxy.ToolPins()
    assert p.diff("srv", [{"name": "read", "desc": "a"}]) == []          # first pin
    assert p.diff("srv", [{"name": "read", "desc": "a"}]) == []          # unchanged
    assert p.diff("srv", [{"name": "read", "desc": "EVIL"}]) == ["changed:read"]  # rug pull
    assert p.diff("srv", [{"name": "read", "desc": "EVIL"}, {"name": "write"}]) == ["added:write"]
    assert p.diff("srv", [{"name": "write"}]) == ["removed:read"]


# ── inbound verify decision ──
def _headers(pem=None, proof=None, carriage="header"):
    h = {"X-AgentCert-Carriage": carriage}
    if pem is not None:
        h["X-AgentCert-Token"] = pem.decode()
    if proof is not None:
        import base64, json
        h["X-AgentCert-Proof"] = base64.urlsafe_b64encode(json.dumps(proof).encode()).decode()
    return h


def test_inbound_no_credential_shadow_allows_enforce_blocks():
    anchors, _leaf, _ = _pki()
    v = Verifier(InMemoryTrustSource(anchors))
    allow_s, status = proxy.inbound_decision(v, _headers(), mode="shadow")
    assert allow_s is True and status == VerificationStatus.UNVERIFIED.value
    allow_e, _ = proxy.inbound_decision(v, _headers(), mode="enforce")
    assert allow_e is False


def test_inbound_valid_cert_passes_enforce():
    anchors, leaf, lk = _pki(agent="ans://acme/agent/prod")
    ts = InMemoryTrustSource(anchors); ts.set_score("ans://acme/agent/prod", 812)
    v = Verifier(ts)
    proof = build_assertion(lk, "ans://acme/agent/prod")
    allow, status = proxy.inbound_decision(v, _headers(_pem(leaf), proof=proof), mode="enforce")
    assert allow is True and status == VerificationStatus.VERIFIED.value


def test_inbound_replayed_cert_without_key_blocked_in_enforce():
    from cryptography.hazmat.primitives.asymmetric import ec
    anchors, leaf, _ = _pki(agent="ans://acme/agent/prod")
    ts = InMemoryTrustSource(anchors); ts.set_score("ans://acme/agent/prod", 812)
    v = Verifier(ts)
    forged = build_assertion(ec.generate_private_key(ec.SECP256R1()), "ans://acme/agent/prod")
    allow, status = proxy.inbound_decision(v, _headers(_pem(leaf), proof=forged), mode="enforce")
    assert allow is False and status == VerificationStatus.UNVERIFIED.value


# ── outbound server-trust decision ──
def test_server_trust_decision():
    assert proxy.server_trust_decision(300, min_score=0, mode="enforce")[0] is True   # gate off
    assert proxy.server_trust_decision(800, min_score=700, mode="enforce")[0] is True
    assert proxy.server_trust_decision(600, min_score=700, mode="enforce")[0] is False
    assert proxy.server_trust_decision(600, min_score=700, mode="shadow")[0] is True   # shadow never blocks
    assert proxy.server_trust_decision(None, min_score=700, mode="enforce")[0] is False
