"""Unit tests for the TAG verification core."""
import datetime
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from agentcert_tag import InMemoryTrustSource, Verifier, FailMode
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
    return b.sign(issuer_key, hashes.SHA256())


def _pki(days=90, agent="ans://acme/agent/prod", score=None, expired=False):
    rk = ec.generate_private_key(ec.SECP256R1())
    root = _sign("Root", rk.public_key(), None, rk, True, 3650)
    ik = ec.generate_private_key(ec.SECP256R1())
    issuing = _sign("Issuing", ik.public_key(), root, rk, True, 1825)
    lk = ec.generate_private_key(ec.SECP256R1())
    d = -1 if expired else days
    leaf = _sign(agent, lk.public_key(), issuing, ik, False, d, agent_uri=agent, score=score)
    anchors = [c.public_bytes(serialization.Encoding.PEM).decode() for c in (root, issuing)]
    return anchors, leaf


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def test_verified_with_score():
    anchors, leaf = _pki(agent="ans://acme/agent/prod")
    ts = InMemoryTrustSource(anchors); ts.set_score("ans://acme/agent/prod", 812)
    res = Verifier(ts).verify(_pem(leaf))
    assert res.verification_status == VerificationStatus.VERIFIED
    assert res.trust_score.value == 812
    assert res.trust_score.tier == TrustTier.TRUSTED
    assert res.agent_id == "ans://acme/agent/prod"


def test_revoked():
    anchors, leaf = _pki()
    ts = InMemoryTrustSource(anchors); ts.revoke(format(leaf.serial_number, "x"))
    res = Verifier(ts).verify(_pem(leaf))
    assert res.verification_status == VerificationStatus.REVOKED


def test_forged_root_unverified():
    anchors, _ = _pki()
    _, rogue_leaf = _pki(agent="ans://attacker/agent/prod")   # different root
    ts = InMemoryTrustSource(anchors)
    res = Verifier(ts).verify(_pem(rogue_leaf))
    assert res.verification_status == VerificationStatus.UNVERIFIED


def test_expired():
    anchors, leaf = _pki(expired=True)
    ts = InMemoryTrustSource(anchors)
    res = Verifier(ts).verify(_pem(leaf))
    assert res.verification_status == VerificationStatus.EXPIRED


def test_garbage_never_raises():
    anchors, _ = _pki()
    res = Verifier(InMemoryTrustSource(anchors)).verify(b"-----BEGIN CERTIFICATE-----\nxx\n-----END CERTIFICATE-----\n")
    assert res.verification_status == VerificationStatus.UNVERIFIED


def test_offline_score_from_cert_extension():
    # No backend score set; verifier falls back to the score baked into the cert.
    anchors, leaf = _pki(agent="ans://acme/agent/prod", score=640)
    ts = InMemoryTrustSource(anchors)  # no set_score
    res = Verifier(ts).verify(_pem(leaf))
    assert res.verification_status == VerificationStatus.VERIFIED
    assert res.trust_score.value == 640
    assert res.trust_score.tier == TrustTier.CAUTION


def test_claimed_id_mismatch():
    anchors, leaf = _pki(agent="ans://acme/agent/prod")
    ts = InMemoryTrustSource(anchors); ts.set_score("ans://acme/agent/prod", 800)
    res = Verifier(ts).verify(_pem(leaf), claimed_agent_id="ans://someone/else/prod")
    assert res.verification_status == VerificationStatus.UNVERIFIED


def test_attestation_signed():
    anchors, leaf = _pki()
    ts = InMemoryTrustSource(anchors); ts.set_score("ans://acme/agent/prod", 800)
    v = Verifier(ts, signing_key=ec.generate_private_key(ec.SECP256R1()))
    res = v.verify(_pem(leaf))
    assert res.attestation.signature is not None
