"""TrustSource — TAG's read-only view of the TrustModel backend.

Everything TAG needs from TrustModel is behind this interface: the CA trust
anchors (shipped/pinned, not fetched per request), the current TrustScore
(reputation API #466), and revocation state (transparency log + CRL). Keeping
it an interface is what lets the same verify core run against the hosted
sandbox, a customer's real tenant, or an in-memory fixture in tests.

Security (TAG_requirements §7): the credentials behind HttpTrustSource must be
scoped verification-read-only — never able to issue/revoke certs or mutate a
score — and all transport is mTLS.
"""
from __future__ import annotations

import abc
import json
import time
import urllib.request
from dataclasses import dataclass
from typing import Optional


@dataclass
class Reputation:
    value: Optional[int]
    last_updated: Optional[str]
    fetched_at: float


class TrustSource(abc.ABC):
    @abc.abstractmethod
    def root_anchors_pem(self) -> list[str]:
        """PEM trust anchors (root + issuing) that leaves chain up to."""

    @abc.abstractmethod
    def get_reputation(self, agent_id: str) -> Reputation:
        """Current TrustScore for the agent (reputation API)."""

    @abc.abstractmethod
    def is_revoked(self, serial_hex: str) -> Optional[bool]:
        """True/False revocation state, or None if it cannot be determined
        (caller then applies the offline-grace / fail policy)."""


class InMemoryTrustSource(TrustSource):
    """Fixture backend for the demo, tests, and the pre-seeded sandbox."""

    def __init__(self, anchors_pem: list[str]):
        self._anchors = anchors_pem
        self._scores: dict[str, int] = {}
        self._revoked: set[str] = set()

    def set_score(self, agent_id: str, value: int) -> None:
        self._scores[agent_id] = value

    def revoke(self, serial_hex: str) -> None:
        self._revoked.add(serial_hex.lower())

    def root_anchors_pem(self) -> list[str]:
        return list(self._anchors)

    def get_reputation(self, agent_id: str) -> Reputation:
        from datetime import datetime, timezone
        return Reputation(
            value=self._scores.get(agent_id),
            last_updated=datetime.now(timezone.utc).isoformat(),
            fetched_at=time.time(),
        )

    def is_revoked(self, serial_hex: str) -> Optional[bool]:
        return serial_hex.lower() in self._revoked


class HttpTrustSource(TrustSource):
    """Talks to a real TrustModel deployment.

    - reputation:   GET {base}/v1/agentcert/reputation/{agent_id}/
    - transparency: GET {base}/v1/agentcert/transparency/{serial}/   (status field)
    - anchors:      pinned locally (root never fetched per-request); `anchors_pem`
                    is the bundled trust anchor from the CA (TRUS-1568).

    `timeout` keeps us inside the p99 latency budget (NFR-1); on timeout the
    caller falls back to cached state (NFR-3).
    """

    def __init__(self, base_url: str, anchors_pem: list[str], api_key: Optional[str] = None,
                 timeout: float = 0.25):
        self.base_url = base_url.rstrip("/")
        self._anchors = anchors_pem
        self.api_key = api_key
        self.timeout = timeout

    def _get(self, path: str) -> dict:
        req = urllib.request.Request(self.base_url + path)
        if self.api_key:
            req.add_header("Authorization", "Bearer " + self.api_key)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 (mTLS enforced by deploy)
            return json.loads(resp.read().decode("utf-8"))

    def root_anchors_pem(self) -> list[str]:
        return list(self._anchors)

    def get_reputation(self, agent_id: str) -> Reputation:
        data = self._get(f"/v1/agentcert/reputation/{agent_id}/")
        return Reputation(
            value=data.get("trust_score") or data.get("value"),
            last_updated=data.get("last_updated"),
            fetched_at=time.time(),
        )

    def is_revoked(self, serial_hex: str) -> Optional[bool]:
        try:
            data = self._get(f"/v1/agentcert/transparency/{serial_hex}/")
        except Exception:
            return None
        status = (data.get("status") or "").lower()
        if status in ("revoked", "suspended"):
            return True
        if status in ("active", "valid", "good"):
            return False
        return None
