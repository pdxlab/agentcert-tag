"""The TAG verification core (TRUS-1815).

One language-agnostic verification decision that every host wrapper (Kong Lua
plugin, Envoy/sidecar, Cisco module) calls. It answers exactly one question —
"is this agent who it claims to be, and what is its trust posture right now" —
and never decides allow/deny (that stays with the host policy engine, FR-14).

Reference implementation. The normative contract is spec/verification-core.md;
any re-implementation (e.g. pure Lua) must produce the same VerificationResult.
"""
from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.exceptions import InvalidSignature

from .models import (
    Attestation,
    TrustScore,
    TrustTier,
    VerificationResult,
    VerificationStatus,
)
from .oids import ANS_URI_SCHEME, OID_TRUSTSCORE
from .trust import Reputation, TrustSource

# Maximum age a cached revocation answer may reach before it is treated as
# unknown. This number is a hard contract with the origination side: the
# issuance revocation-propagation SLA (TRUS-1813) MUST be <= this, or a revoked
# agent keeps verifying during the gap. Documented in the threat model (1824).
DEFAULT_REVOCATION_MAX_STALENESS_S = 300
DEFAULT_SCORE_TTL_S = 300  # FR-9 default 5 min
DEFAULT_POP_MAX_AGE_S = 300  # reject stapled assertions older than this (replay window)


class Carriage:
    MTLS = "mtls"      # possession proven by the TLS handshake — no assertion needed
    HEADER = "header"  # cert carried in a header: a stapled PoP assertion is REQUIRED


class FailMode:
    OPEN = "open"      # backend unreachable -> UNVERIFIED but cert_valid preserved, host may allow
    CLOSED = "closed"  # backend unreachable -> ERROR, host should deny (default for regulated)


class Mode:
    SHADOW = "shadow"    # default on install: decide + log, never influence enforcement
    ENFORCE = "enforce"  # host policy engine may act on the result


class _TTLCache:
    def __init__(self, ttl: float):
        self.ttl = ttl
        self._d: dict[str, tuple[float, object]] = {}

    def get(self, key: str):
        hit = self._d.get(key)
        if not hit:
            return None
        ts, val = hit
        if time.time() - ts > self.ttl:
            return None
        return val

    def put(self, key: str, val) -> None:
        self._d[key] = (time.time(), val)


class Verifier:
    def __init__(
        self,
        trust_source: TrustSource,
        *,
        mode: str = Mode.SHADOW,
        fail_mode: str = FailMode.CLOSED,
        score_ttl_s: float = DEFAULT_SCORE_TTL_S,
        revocation_max_staleness_s: float = DEFAULT_REVOCATION_MAX_STALENESS_S,
        signing_key: Optional[ec.EllipticCurvePrivateKey] = None,
        verifier_id: str = "trustmodel-verifier-v1",
    ):
        self.trust = trust_source
        self.mode = mode
        self.fail_mode = fail_mode
        self.verifier_id = verifier_id
        self._score_cache = _TTLCache(score_ttl_s)
        self._revocation_cache = _TTLCache(revocation_max_staleness_s)
        self._signing_key = signing_key
        self._anchors = [
            x509.load_pem_x509_certificate(a.encode())
            for a in trust_source.root_anchors_pem()
        ]

    # ---- public API -----------------------------------------------------

    def verify(self, cert_pem: bytes, claimed_agent_id: Optional[str] = None, *,
               carriage: str = Carriage.HEADER, proof: Optional[dict] = None,
               audience: Optional[str] = None) -> VerificationResult:
        """Verify a presented X.509 AgentCert. Never raises — a malformed or
        missing credential yields UNVERIFIED so the request pipeline is never
        crashed (FR-3).

        ``carriage`` says how the cert reached us. On ``mtls`` the TLS handshake
        already proved the presenter holds the leaf key. On ``header`` (the
        default — the only safe assumption for an untrusted caller) the cert is a
        public object, so a stapled proof-of-possession ``proof`` (see ``pop.py``)
        is REQUIRED; without a valid one the result is UNVERIFIED (fail closed)."""
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            leaf = x509.load_pem_x509_certificate(cert_pem)
        except Exception as exc:
            return self._sign(VerificationResult(
                VerificationStatus.UNVERIFIED, cert_valid=False,
                detail=f"unparseable credential: {exc}",
                attestation=Attestation(self.verifier_id, verified_at=now_iso),
            ))

        agent_id = self._agent_id(leaf)

        # FR-5 expiry
        not_after = leaf.not_valid_after_utc
        not_before = leaf.not_valid_before_utc
        now = datetime.now(timezone.utc)
        if now > not_after or now < not_before:
            return self._sign(VerificationResult(
                VerificationStatus.EXPIRED, agent_id=agent_id, cert_valid=False,
                cert_expiry=not_after.isoformat(), detail="outside validity window",
                attestation=Attestation(self.verifier_id, verified_at=now_iso),
            ))

        # FR-4 chain validation to a pinned TrustModel anchor
        if not self._validate_chain(leaf):
            return self._sign(VerificationResult(
                VerificationStatus.UNVERIFIED, agent_id=agent_id, cert_valid=False,
                cert_expiry=not_after.isoformat(),
                detail="chain does not validate to a TrustModel anchor",
                attestation=Attestation(self.verifier_id, verified_at=now_iso),
            ))

        # FR-7 subject/identity match. Fail closed when a claim is made but the
        # cert carries no verifiable identity (agent_id is None) — otherwise a
        # cert with no ans:// SAN would let a caller assert any id uncontested.
        if claimed_agent_id and claimed_agent_id != agent_id:
            return self._sign(VerificationResult(
                VerificationStatus.UNVERIFIED, agent_id=agent_id, cert_valid=True,
                cert_expiry=not_after.isoformat(),
                detail=f"claimed id {claimed_agent_id!r} != cert id {agent_id!r}",
                attestation=Attestation(self.verifier_id, verified_at=now_iso),
            ))

        # Proof-of-possession: a header-carried cert is public, so require a
        # stapled assertion signed by the leaf key. mTLS already proved it.
        if carriage != Carriage.MTLS:
            pop_ok, pop_detail = self._verify_pop(leaf, agent_id, proof, audience)
            if not pop_ok:
                return self._sign(VerificationResult(
                    VerificationStatus.UNVERIFIED, agent_id=agent_id, cert_valid=True,
                    cert_expiry=not_after.isoformat(),
                    detail=f"proof-of-possession failed: {pop_detail}",
                    attestation=Attestation(self.verifier_id, verified_at=now_iso),
                ))

        # FR-6 revocation (cached CRL/transparency, offline-tolerant)
        serial_hex = format(leaf.serial_number, "x")
        revoked, rev_unknown = self._check_revocation(serial_hex)
        if revoked:
            return self._sign(VerificationResult(
                VerificationStatus.REVOKED, agent_id=agent_id, cert_valid=False,
                cert_expiry=not_after.isoformat(), detail="cert is revoked",
                attestation=Attestation(self.verifier_id, verified_at=now_iso),
            ))

        # FR-8..10 TrustScore + tier (cached), with offline fallback to the
        # score baked into the cert extension.
        score, cache_hit, score_unknown = self._trust_score(agent_id, leaf)

        # Fail policy only bites when the backend was unreachable for something
        # we needed (revocation or score) and there was no usable cache.
        if (rev_unknown or score_unknown) and self.fail_mode == FailMode.CLOSED:
            return self._sign(VerificationResult(
                VerificationStatus.ERROR, agent_id=agent_id, cert_valid=True,
                cert_expiry=not_after.isoformat(),
                detail="backend unreachable and no fresh cache (fail-closed)",
                trust_score=score,
                attestation=Attestation(self.verifier_id, verified_at=now_iso),
            ))

        return self._sign(VerificationResult(
            VerificationStatus.VERIFIED, agent_id=agent_id, cert_valid=True,
            cert_expiry=not_after.isoformat(), trust_score=score, cache_hit=cache_hit,
            detail="ok" if not (rev_unknown or score_unknown) else "ok (fail-open, stale backend)",
            attestation=Attestation(self.verifier_id, verified_at=now_iso),
        ))

    # ---- internals ------------------------------------------------------

    @staticmethod
    def _valid_ans_uri(s: Optional[str]) -> bool:
        """A well-formed ans:// identity: correct scheme, non-empty authority, no
        whitespace/control chars, bounded length. Anything else is not a
        trustworthy identity and must not drive a trust decision."""
        prefix = ANS_URI_SCHEME + "://"
        if not s or not s.startswith(prefix) or len(s) > 512:
            return False
        if len(s) <= len(prefix):
            return False
        return all(ord(c) > 32 and c != "\x7f" for c in s)

    def _agent_id(self, leaf: x509.Certificate) -> Optional[str]:
        """The agent identity is the ans:// URI-SAN. We only trust a validated
        ans:// value (SAN preferred; CN accepted only if it is itself a valid
        ans:// URI) — never an arbitrary CN string as an identity."""
        try:
            san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
                if self._valid_ans_uri(uri):
                    return uri
        except x509.ExtensionNotFound:
            pass
        cn = leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        cn_val = cn[0].value if cn else None
        return cn_val if self._valid_ans_uri(cn_val) else None

    @staticmethod
    def _is_ca(cert: x509.Certificate) -> bool:
        try:
            return bool(cert.extensions.get_extension_for_class(
                x509.BasicConstraints).value.ca)
        except x509.ExtensionNotFound:
            return False

    @staticmethod
    def _can_sign_certs(cert: x509.Certificate) -> bool:
        """KeyUsage.keyCertSign must be set when a KeyUsage extension is present.
        Absence is permitted (RFC 5280 leaves KeyUsage optional); present-but-
        without-the-bit is a hard reject."""
        try:
            return bool(cert.extensions.get_extension_for_class(
                x509.KeyUsage).value.key_cert_sign)
        except x509.ExtensionNotFound:
            return True

    def _validate_chain(self, leaf: x509.Certificate) -> bool:
        """Manual path build: leaf -> issuing -> root anchor. We validate
        signatures AND CA basic-constraints / key-usage on every issuing link, so
        a non-CA (or keyCertSign-less) cert can never mint or vouch for a leaf,
        and the same logic ports cleanly to other runtimes (NFR-5)."""
        if self._is_ca(leaf):          # a leaf must not itself be a CA cert
            return False
        anchors_by_subject: dict[bytes, x509.Certificate] = {
            a.subject.public_bytes(): a for a in self._anchors
        }
        cur = leaf
        for _ in range(8):  # bounded chain depth
            issuer = anchors_by_subject.get(cur.issuer.public_bytes())
            if issuer is None:
                # Self-issued leaf pointing straight at an anchor subject we hold?
                return False
            if not self._is_ca(issuer) or not self._can_sign_certs(issuer):
                return False       # issuer must be a cert-signing CA
            if not self._signed_by(cur, issuer):
                return False
            if issuer.subject == issuer.issuer and issuer in self._anchors:
                # reached a trust anchor (self-signed root we pin)
                return True
            cur = issuer
        return False

    @staticmethod
    def _signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
        pub = issuer.public_key()
        try:
            if isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(cert.signature, cert.tbs_certificate_bytes,
                           ec.ECDSA(cert.signature_hash_algorithm))
            elif isinstance(pub, rsa.RSAPublicKey):
                pub.verify(cert.signature, cert.tbs_certificate_bytes,
                           padding.PKCS1v15(), cert.signature_hash_algorithm)
            elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                # EdDSA — no hash algorithm arg. The TrustModel issuer default
                # is Ed25519 (aurora-gateway CertIssuer.ALGO_ED25519).
                pub.verify(cert.signature, cert.tbs_certificate_bytes)
            else:
                return False
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    def _verify_pop(self, leaf: x509.Certificate, agent_id: Optional[str],
                    proof: Optional[dict], audience: Optional[str]) -> tuple[bool, str]:
        """Verify a stapled proof-of-possession: the presenter signed a fresh,
        identity-bound assertion with the leaf private key (see pop.py). Only the
        real key-holder can produce it, which defeats public-cert replay."""
        if not isinstance(proof, dict) or "payload" not in proof or "sig" not in proof:
            return False, "missing stapled assertion (header carriage requires proof-of-possession)"
        try:
            raw = proof["payload"]
            payload = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
            sig = base64.b64decode(proof["sig"])
            claims = json.loads(payload.decode())
        except Exception as exc:
            return False, f"malformed proof: {exc}"
        now = time.time()
        exp, iat = claims.get("exp"), claims.get("iat")
        if not isinstance(exp, (int, float)) or now > exp:
            return False, "proof expired"
        if not isinstance(iat, (int, float)) or (now - iat) > DEFAULT_POP_MAX_AGE_S:
            return False, "proof outside freshness window"
        if audience is not None and claims.get("aud") != audience:
            return False, "proof audience mismatch"
        if not agent_id or claims.get("sub") != agent_id:
            return False, "proof subject does not match cert identity"
        if not self._raw_verify(leaf.public_key(), sig, payload):
            return False, "proof signature invalid — presenter does not hold the leaf key"
        return True, "ok"

    @staticmethod
    def _raw_verify(pub, signature: bytes, message: bytes) -> bool:
        """Verify a raw signature over ``message`` by the leaf's public key."""
        try:
            if isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            elif isinstance(pub, rsa.RSAPublicKey):
                pub.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                pub.verify(signature, message)
            else:
                return False
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    def _check_revocation(self, serial_hex: str) -> tuple[bool, bool]:
        """Returns (is_revoked, unknown). Uses a bounded-staleness cache so a
        backend blip does not force a per-request round-trip (NFR-3)."""
        cached = self._revocation_cache.get(serial_hex)
        if cached is not None:
            return bool(cached), False
        state = self.trust.is_revoked(serial_hex)
        if state is None:
            return False, True  # unknown -> caller's fail policy decides
        self._revocation_cache.put(serial_hex, state)
        return bool(state), False

    def _trust_score(self, agent_id: Optional[str], leaf: x509.Certificate):
        if not agent_id:
            return TrustScore(), False, False
        cached: Optional[Reputation] = self._score_cache.get(agent_id)
        cache_hit = cached is not None
        rep = cached
        unknown = False
        if rep is None:
            try:
                rep = self.trust.get_reputation(agent_id)
                self._score_cache.put(agent_id, rep)
            except Exception:
                rep = None
        if rep is None or rep.value is None:
            # Offline fallback: score baked into the cert at issuance time. It is
            # frozen and may be stale, so stamp its provenance + a synthetic age
            # (from the cert's notBefore) and never present it as a live posture.
            baked = self._score_from_cert(leaf)
            if baked is None:
                unknown = True
                return TrustScore(tier=TrustTier.UNKNOWN, source="none"), cache_hit, unknown
            baked_age = max(0, int(time.time() - leaf.not_valid_before_utc.timestamp()))
            return TrustScore(value=baked, tier=TrustTier.from_score(baked),
                              last_updated=leaf.not_valid_before_utc.isoformat(),
                              score_age_seconds=baked_age, source="cert_baked"), cache_hit, unknown
        age = int(time.time() - rep.fetched_at)
        return (TrustScore(value=rep.value, tier=TrustTier.from_score(rep.value),
                           last_updated=rep.last_updated, score_age_seconds=age,
                           source="live"),
                cache_hit, unknown)

    @staticmethod
    def _score_from_cert(leaf: x509.Certificate) -> Optional[int]:
        try:
            ext = leaf.extensions.get_extension_for_oid(x509.ObjectIdentifier(OID_TRUSTSCORE))
            import json
            return int(json.loads(bytes(ext.value.value).decode()).get("value"))
        except Exception:
            return None

    def _sign(self, result: VerificationResult) -> VerificationResult:
        """Attach a detached signature over the decision so TrustModel can
        later audit that this verifier produced it (FR-11)."""
        if self._signing_key is not None:
            import json
            payload = json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":")).encode()
            sig = self._signing_key.sign(payload, ec.ECDSA(hashes.SHA256()))
            result.attestation.signature = base64.b64encode(sig).decode()
        return result
