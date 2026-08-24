#!/usr/bin/env python3
"""Closed-loop proof (TRUS-1814) — no Docker, no network required.

Exercises the REAL issuance core and the REAL verification core against a shared
demo root of trust, proving the full origination -> consumption transaction:

  1. CI/CD deploy-time issuance mints an AgentCert bound to repo/env/deploy-id
  2. The agent presents that cert at a gateway; TAG verifies it -> VERIFIED + score
  3. Redeploy rotates the cert and supersedes (revokes) the old one -> old = REVOKED
  4. A forged cert (wrong root) -> UNVERIFIED

Run:  ../../.venv/bin/python run_closed_loop.py   (from agentcert-tag/demo)
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "core"))                       # agentcert_tag
sys.path.insert(0, os.path.join(HERE, "..", "..", "agentcert-issue-action", "core"))  # agentcert_issue

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from agentcert_issue import IdentityBinding, Issuer, LocalDemoCA, MemorySink  # noqa: E402
from agentcert_tag import InMemoryTrustSource, Mode, FailMode, Verifier      # noqa: E402
from agentcert_tag.models import VerificationStatus                          # noqa: E402
import datetime  # noqa: E402


def hr(title):
    print("\n" + "=" * 66 + f"\n {title}\n" + "=" * 66)


def show(res):
    d = res.to_dict()
    ts = d["trust_score"]
    print(f"  status      : {d['verification_status']}")
    print(f"  agent_id    : {d['agent_id']}")
    print(f"  cert_valid  : {d['cert_valid']}   cache_hit: {d['cache_hit']}")
    print(f"  trust_score : {ts['value']}  ({ts['tier']})")
    print(f"  attestation : {d['attestation']['signed_by']} "
          f"sig={'yes' if d['attestation']['signature'] else 'no'}")
    print(f"  detail      : {res.detail}")


def main():
    # ---- Shared root of trust: one CA for both ends (mirrors GCP CAS) --------
    ca = LocalDemoCA()
    trust = InMemoryTrustSource(anchors_pem=ca.anchors_pem())

    # Bridge the demo CA's revocation state into the verifier's trust source.
    _orig_is_revoked = trust.is_revoked
    trust.is_revoked = lambda serial: ca.is_revoked(serial)  # type: ignore

    # TAG verifier as a gateway would construct it: shadow mode, fail-closed,
    # signing its attestations with a verifier key.
    verifier = Verifier(
        trust, mode=Mode.SHADOW, fail_mode=FailMode.CLOSED,
        signing_key=ec.generate_private_key(ec.SECP256R1()),
    )

    # Track prior serial per identity so redeploy supersedes cleanly (FR-6).
    prior = {}
    issuer = Issuer(
        ca,
        register_fn=lambda b, c: True,                 # "registered with backend"
        prior_serial_fn=lambda b: prior.get(b.identity_key),
    )

    def deploy(deployment_id, score):
        b = IdentityBinding(
            repo="pdxlab/sample-agent", environment="production",
            deployment_id=deployment_id,
            issued_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        sink = MemorySink()
        result = issuer.issue(b, sink, initial_score=score)
        prior[b.identity_key] = result.issued.serial_hex
        trust.set_score(b.agent_uri, score)             # backend reputation
        return b, sink, result

    # ---- 1. Deploy #1: issue + verify --------------------------------------
    hr("1. CI/CD deploy #1  ->  mint AgentCert  ->  gateway verifies")
    b1, sink1, r1 = deploy("sha-aaaa1111", score=812)
    print(f"  issued serial {r1.issued.serial_hex[:16]}...  for {b1.agent_uri}")
    print(f"  delivered secrets: {sorted(sink1.store.keys())}")
    v1 = verifier.verify(sink1.store["AGENTCERT_LEAF_PEM"].encode())
    show(v1)
    assert v1.verification_status == VerificationStatus.VERIFIED, v1.detail
    assert v1.trust_score.value == 812

    # ---- 2. Redeploy: rotate + supersede -----------------------------------
    hr("2. Redeploy  ->  new cert, OLD cert superseded (revoked)")
    b2, sink2, r2 = deploy("sha-bbbb2222", score=790)
    print(f"  new serial {r2.issued.serial_hex[:16]}...  superseded {str(r2.superseded_serial)[:16]}...")
    # Revocation propagates to the gateway within the cache-staleness SLA
    # (TRUS-1813 must be <= the verifier's revocation_max_staleness, TRUS-1815).
    # Clearing the cache here simulates that propagation completing.
    verifier._revocation_cache._d.clear()
    v_new = verifier.verify(sink2.store["AGENTCERT_LEAF_PEM"].encode())
    print(" -- new cert:")
    show(v_new)
    assert v_new.verification_status == VerificationStatus.VERIFIED
    v_old = verifier.verify(sink1.store["AGENTCERT_LEAF_PEM"].encode())
    print(" -- old (superseded) cert:")
    show(v_old)
    assert v_old.verification_status == VerificationStatus.REVOKED, v_old.detail

    # ---- 3. Revoke-on-score-drop (continuous assurance wedge) ---------------
    hr("3. Explicit revoke (e.g. TrustScore collapse)  ->  REVOKED")
    ca.revoke(r2.issued.serial_hex)
    # bypass the 5-min revocation cache to show immediate effect
    verifier._revocation_cache._d.clear()
    v_rev = verifier.verify(sink2.store["AGENTCERT_LEAF_PEM"].encode())
    show(v_rev)
    assert v_rev.verification_status == VerificationStatus.REVOKED

    # ---- 4. Forged cert from a different root ------------------------------
    hr("4. Forged cert (attacker's own CA)  ->  UNVERIFIED")
    rogue = LocalDemoCA()
    rb, rsink, _ = _deploy_with(rogue, "rogue", 999)
    v_forge = verifier.verify(rsink.store["AGENTCERT_LEAF_PEM"].encode())
    show(v_forge)
    assert v_forge.verification_status == VerificationStatus.UNVERIFIED

    hr("CLOSED LOOP OK")
    print("  issue -> verify(VERIFIED) -> rotate/supersede(REVOKED) -> "
          "revoke(REVOKED) -> forged(UNVERIFIED)\n")


def _deploy_with(ca, dep, score):
    from agentcert_issue import IdentityBinding as IB, Issuer as IS, MemorySink as MS
    import datetime as dt
    b = IB(repo="attacker/agent", environment="production", deployment_id=dep,
           issued_at=dt.datetime.now(dt.timezone.utc).isoformat())
    sink = MS()
    IS(ca).issue(b, sink, initial_score=score)
    return b, sink, None


if __name__ == "__main__":
    main()
