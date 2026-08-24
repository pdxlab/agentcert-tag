"""agentcert_tag — TrustModel TAG verification core (reference implementation).

Turn any gateway/firewall into a verifier of AgentCert (X.509) + TrustScore.
See spec/verification-core.md for the language-agnostic contract.
"""
from .models import (
    Attestation,
    TrustScore,
    TrustTier,
    VerificationResult,
    VerificationStatus,
)
from .trust import HttpTrustSource, InMemoryTrustSource, Reputation, TrustSource
from .verify import DEFAULT_REVOCATION_MAX_STALENESS_S, FailMode, Mode, Verifier

__version__ = "0.1.0"
__all__ = [
    "Verifier", "Mode", "FailMode", "DEFAULT_REVOCATION_MAX_STALENESS_S",
    "TrustSource", "HttpTrustSource", "InMemoryTrustSource", "Reputation",
    "VerificationResult", "VerificationStatus", "TrustScore", "TrustTier", "Attestation",
]
