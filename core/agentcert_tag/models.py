"""Data model for the TAG verification response.

Mirrors the schema in TAG_requirements.md §5. `to_dict()` is the exact wire
format host wrappers (Kong plugin, sidecar) surface to the platform's policy
engine — do not rename fields without bumping the response version.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Optional


class VerificationStatus(str, enum.Enum):
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    ERROR = "ERROR"


class TrustTier(str, enum.Enum):
    TRUSTED = "Trusted"
    CAUTION = "Caution"
    UNTRUSTED = "Untrusted"
    UNKNOWN = "Unknown"

    @classmethod
    def from_score(cls, score: Optional[int]) -> "TrustTier":
        # Bands are intentionally simple and documented so a customer can
        # reason about what a tier means without reading our source.
        if score is None:
            return cls.UNKNOWN
        if score >= 750:
            return cls.TRUSTED
        if score >= 500:
            return cls.CAUTION
        return cls.UNTRUSTED


@dataclass
class TrustScore:
    value: Optional[int] = None
    tier: TrustTier = TrustTier.UNKNOWN
    last_updated: Optional[str] = None      # ISO-8601
    score_age_seconds: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "tier": self.tier.value,
            "last_updated": self.last_updated,
            "score_age_seconds": self.score_age_seconds,
        }


@dataclass
class Attestation:
    signed_by: str = "trustmodel-verifier-v1"
    signature: Optional[str] = None         # base64 detached signature over the result
    verified_at: Optional[str] = None       # ISO-8601

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class VerificationResult:
    verification_status: VerificationStatus
    agent_id: Optional[str] = None          # cert-subject / ANS identity
    cert_valid: bool = False
    cert_expiry: Optional[str] = None        # ISO-8601
    trust_score: TrustScore = field(default_factory=TrustScore)
    attestation: Attestation = field(default_factory=Attestation)
    cache_hit: bool = False
    # Non-wire diagnostics (never surfaced to policy, handy in shadow logs).
    detail: Optional[str] = None

    def to_dict(self, include_detail: bool = False) -> dict:
        out = {
            "verification_status": self.verification_status.value,
            "agent_id": self.agent_id,
            "cert_valid": self.cert_valid,
            "cert_expiry": self.cert_expiry,
            "trust_score": self.trust_score.to_dict(),
            "attestation": self.attestation.to_dict(),
            "cache_hit": self.cache_hit,
        }
        if include_detail:
            out["detail"] = self.detail
        return out

    @property
    def allowed_by_default(self) -> bool:
        """Convenience only. TAG never decides allow/deny (FR-14) — this is a
        hint the host policy engine may ignore."""
        return self.verification_status == VerificationStatus.VERIFIED
