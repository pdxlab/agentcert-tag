# Conventions — agentcert-tag

- **The verifier is a trust boundary.** `core/agentcert_tag/verify.py` decides whether a
  calling agent's AgentCert + TrustScore is trusted. A logic gap here is an auth bypass —
  review it as adversarially as an authn/authz change.
- **Fail closed.** Every error path (parse error, unreachable backend, missing field,
  missing proof) must resolve to `UNVERIFIED`/`ERROR`, never a silent `VERIFIED`. `verify()`
  must never raise (FR-3) — a malformed credential yields `UNVERIFIED`.
- **A presented cert is public** (ANS directory + transparency log). On a non-mTLS carriage
  the presenter MUST prove key possession (stapled assertion, `pop.py`); a bare cert is not
  an identity.
- **Language-agnostic parity.** `verify.py` is the reference; the Kong Lua plugin and any TS
  re-implementation must produce the same `VerificationResult`. Changes to the decision logic
  must keep `spec/verification-core.md` and the wrappers in sync.
- **Signature verification keys off the trusted issuer's key**, never the cert's self-declared
  algorithm (no algorithm confusion). RSA is pinned to a concrete padding.
- **TrustScore provenance matters.** A live backend read is authoritative; the cert-baked
  fallback is frozen at issuance — tag it `source="cert_baked"` and never present it as live.
