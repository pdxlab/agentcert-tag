"""Unit tests for the TAG verification core."""
import datetime
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from agentcert_tag import InMemoryTrustSource, Verifier, FailMode, build_assertion
from agentcert_tag.models import VerificationStatus, TrustTier
from agentcert_tag.oids import OID_TRUSTSCORE
import json


def _sign(subject, subject_key, issuer_cert, issuer_key, ca, days, agent_uri=None, score=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    b = (x509.CertificateBuilder()
         .subject_name(name).issuer_name(issuer_cert.subject if issuer_cert else name)
         .public_key(subject_key).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if agent_uri:
        b = b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(agent_uri)]), False)
    if score is not None:
        b = b.add_extension(x509.UnrecognizedExtension(
            x509.ObjectIdentifier(OID_TRUSTSCORE), json.dumps({"value": score}).encode()), False)
    from cryptography.hazmat.primitives.asymmetric import ed25519, ed448
    algo = None if isinstance(issuer_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)) else hashes.SHA256()
    return b.sign(issuer_key, algo)


def _pki(days=90, agent="ans://acme/agent/prod", score=None, expired=False):
    """Returns (anchors, leaf, leaf_private_key). The leaf key lets tests mint a
    stapled proof-of-possession for the header-carriage path."""
    rk = ec.generate_private_key(ec.SECP256R1())
    root = _sign("Root", rk.public_key(), None, rk, True, 3650)
    ik = ec.generate_private_key(ec.SECP256R1())
    issuing = _sign("Issuing", ik.public_key(), root, rk, True, 1825)
    lk = ec.generate_private_key(ec.SECP256R1())
    d = -1 if expired else days
    leaf = _sign(agent, lk.public_key(), issuing, ik, False, d, agent_uri=agent, score=score)
    anchors = [c.public_bytes(serialization.Encoding.PEM).decode() for c in (root, issuing)]
    return anchors, leaf, lk


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# Cert-logic tests use carriage="mtls" (the TLS handshake proves possession, so
# no stapled assertion is required) to isolate chain/revocation/score behaviour.
# ---------------------------------------------------------------------------

def test_verified_with_score():
    anchors, leaf, _ = _pki(agent="ans://acme/agent/prod")
    ts = InMemoryTrustSource(anchors); ts.set_score("ans://acme/agent/prod", 812)
    res = Verifier(ts).verify(_pem(leaf), carriage="mtls")
    assert res.verification_status == VerificationStatus.VERIFIED
    assert res.trust_score.value == 812
    assert res.trust_score.tier == TrustTier.TRUSTED
    assert res.trust_score.source == "live"
    assert res.agent_id == "ans://acme/agent/prod"


def test_revoked():
    anchors, leaf, _ = _pki()
    ts = InMemoryTrustSource(anchors); ts.revoke(format(leaf.serial_number, "x"))
    res = Verifier(ts).verify(_pem(leaf), carriage="mtls")
    assert res.verification_status == VerificationStatus.REVOKED


def test_forged_root_unverified():
    anchors, _, _ = _pki()
    _, rogue_leaf, _ = _pki(agent="ans://attacker/agent/prod")   # different root
    ts = InMemoryTrustSource(anchors)
    res = Verifier(ts).verify(_pem(rogue_leaf), carriage="mtls")
    assert res.verification_status == VerificationStatus.UNVERIFIED


def test_expired():
    anchors, leaf, _ = _pki(expired=True)
    ts = InMemoryTrustSource(anchors)
    res = Verifier(ts).verify(_pem(leaf), carriage="mtls")
    assert res.verification_status == VerificationStatus.EXPIRED


def test_garbage_never_raises():
    anchors, _, _ = _pki()
    res = Verifier(InMemoryTrustSource(anchors)).verify(b"-----BEGIN CERTIFICATE-----\nxx\n-----END CERTIFICATE-----\n")
    assert res.verification_status == VerificationStatus.UNVERIFIED


def test_offline_score_from_cert_extension():
    # No backend score set; verifier falls back to the score baked into the cert.
    anchors, leaf, _ = _pki(agent="ans://acme/agent/prod", score=640)
    ts = InMemoryTrustSource(anchors)  # no set_score
    res = Verifier(ts).verify(_pem(leaf), carriage="mtls")
    assert res.verification_status == VerificationStatus.VERIFIED
    assert res.trust_score.value == 640
    assert res.trust_score.tier == TrustTier.CAUTION


def test_baked_score_marked_stale():
    # The offline fallback must be tagged so policy can tell it isn't live.
    anchors, leaf, _ = _pki(agent="ans://acme/agent/prod", score=640)
    res = Verifier(InMemoryTrustSource(anchors)).verify(_pem(leaf), carriage="mtls")
    assert res.trust_score.source == "cert_baked"
    assert res.trust_score.score_age_seconds is not None


def test_claimed_id_mismatch():
    anchors, leaf, _ = _pki(agent="ans://acme/agent/prod")
    ts = InMemoryTrustSource(anchors); ts.set_score("ans://acme/agent/prod", 800)
    res = Verifier(ts).verify(_pem(leaf), claimed_agent_id="ans://someone/else/prod", carriage="mtls")
    assert res.verification_status == VerificationStatus.UNVERIFIED


def test_claimed_id_without_cert_identity_fails_closed():
    # Cert has no ans:// SAN and a non-ans CN -> agent_id is None; a claim must
    # not pass uncontested.
    rk = ec.generate_private_key(ec.SECP256R1())
    root = _sign("Root", rk.public_key(), None, rk, True, 3650)
    ik = ec.generate_private_key(ec.SECP256R1())
    issuing = _sign("Issuing", ik.public_key(), root, rk, True, 1825)
    lk = ec.generate_private_key(ec.SECP256R1())
    leaf = _sign("plain-cn-no-ans", lk.public_key(), issuing, ik, False, 90)  # no agent_uri
    anchors = [c.public_bytes(serialization.Encoding.PEM).decode() for c in (root, issuing)]
    res = Verifier(InMemoryTrustSource(anchors)).verify(
        _pem(leaf), claimed_agent_id="ans://acme/agent/prod", carriage="mtls")
    assert res.verification_status == VerificationStatus.UNVERIFIED


def test_non_ca_issuer_rejected():
    # A leaf signed by a cert that is NOT a CA must never validate, even if that
    # cert is (mistakenly) in the anchor bundle.
    rk = ec.generate_private_key(ec.SECP256R1())
    root = _sign("Root", rk.public_key(), None, rk, True, 3650)
    ik = ec.generate_private_key(ec.SECP256R1())
    non_ca = _sign("NotACA", ik.public_key(), root, rk, False, 1825)   # ca=False
    lk = ec.generate_private_key(ec.SECP256R1())
    leaf = _sign("ans://acme/agent/prod", lk.public_key(), non_ca, ik, False, 90,
                 agent_uri="ans://acme/agent/prod", score=800)
    anchors = [c.public_bytes(serialization.Encoding.PEM).decode() for c in (root, non_ca)]
    res = Verifier(InMemoryTrustSource(anchors)).verify(_pem(leaf), carriage="mtls")
    assert res.verification_status == VerificationStatus.UNVERIFIED


def test_verified_with_ed25519_issuer():
    # The TrustModel issuer key defaults to Ed25519 (aurora-gateway
    # CertIssuer.ALGO_ED25519); chain validation must handle EdDSA.
    from cryptography.hazmat.primitives.asymmetric import ed25519
    rk = ed25519.Ed25519PrivateKey.generate()
    root = _sign("Root", rk.public_key(), None, rk, True, 3650)
    lk = ec.generate_private_key(ec.SECP256R1())
    leaf = _sign("ans://acme/ed/prod", lk.public_key(), root, rk, False, 90,
                 agent_uri="ans://acme/ed/prod", score=800)
    anchors = [root.public_bytes(serialization.Encoding.PEM).decode()]
    ts = InMemoryTrustSource(anchors); ts.set_score("ans://acme/ed/prod", 800)
    res = Verifier(ts).verify(_pem(leaf), carriage="mtls")
    assert res.verification_status == VerificationStatus.VERIFIED
    assert res.trust_score.value == 800


def test_attestation_signed():
    anchors, leaf, _ = _pki()
    ts = InMemoryTrustSource(anchors); ts.set_score("ans://acme/agent/prod", 800)
    v = Verifier(ts, signing_key=ec.generate_private_key(ec.SECP256R1()))
    res = v.verify(_pem(leaf), carriage="mtls")
    assert res.attestation.signature is not None


# ---------------------------------------------------------------------------
# Proof-of-possession (header carriage) — the replay defence.
# ---------------------------------------------------------------------------

def test_header_without_proof_fails_closed():
    anchors, leaf, _ = _pki(agent="ans://acme/agent/prod")
    ts = InMemoryTrustSource(anchors); ts.set_score("ans://acme/agent/prod", 812)
    res = Verifier(ts).verify(_pem(leaf))  # default carriage=header, no proof
    assert res.verification_status == VerificationStatus.UNVERIFIED
    assert "proof-of-possession" in (res.detail or "")


def test_header_with_valid_proof_verifies():
    anchors, leaf, lk = _pki(agent="ans://acme/agent/prod")
    ts = InMemoryTrustSource(anchors); ts.set_score("ans://acme/agent/prod", 812)
    proof = build_assertion(lk, "ans://acme/agent/prod")
    res = Verifier(ts).verify(_pem(leaf), proof=proof)
    assert res.verification_status == VerificationStatus.VERIFIED


def test_header_replayed_public_cert_without_key_rejected():
    # THE atttack: an attacker holds the victim's PUBLIC cert but not its key,
    # so it can only staple an assertion signed with a different key -> reject.
    anchors, leaf, _ = _pki(agent="ans://acme/agent/prod")
    ts = InMemoryTrustSource(anchors); ts.set_score("ans://acme/agent/prod", 812)
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    forged = build_assertion(attacker_key, "ans://acme/agent/prod")
    res = Verifier(ts).verify(_pem(leaf), proof=forged)
    assert res.verification_status == VerificationStatus.UNVERIFIED


def test_pop_expired_rejected():
    anchors, leaf, lk = _pki(agent="ans://acme/agent/prod")
    ts = InMemoryTrustSource(anchors); ts.set_score("ans://acme/agent/prod", 812)
    stale = build_assertion(lk, "ans://acme/agent/prod", now=int(time.time()) - 100000, ttl_s=60)
    res = Verifier(ts).verify(_pem(leaf), proof=stale)
    assert res.verification_status == VerificationStatus.UNVERIFIED


def test_pop_subject_must_match_cert():
    anchors, leaf, lk = _pki(agent="ans://acme/agent/prod")
    ts = InMemoryTrustSource(anchors); ts.set_score("ans://acme/agent/prod", 812)
    wrong = build_assertion(lk, "ans://acme/OTHER/prod")   # bound to a different id
    res = Verifier(ts).verify(_pem(leaf), proof=wrong)
    assert res.verification_status == VerificationStatus.UNVERIFIED


def test_pop_audience_binding():
    anchors, leaf, lk = _pki(agent="ans://acme/agent/prod")
    ts = InMemoryTrustSource(anchors); ts.set_score("ans://acme/agent/prod", 812)
    proof = build_assertion(lk, "ans://acme/agent/prod", audience="https://gw.acme.com")
    ok = Verifier(ts).verify(_pem(leaf), proof=proof, audience="https://gw.acme.com")
    assert ok.verification_status == VerificationStatus.VERIFIED
    bad = Verifier(ts).verify(_pem(leaf), proof=proof, audience="https://evil.example")
    assert bad.verification_status == VerificationStatus.UNVERIFIED
