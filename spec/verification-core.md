# TAG Verification Core — Language-Agnostic Spec (v0.1)

This is the normative contract for the TAG verification core (TRUS-1815). The
Python package in `core/` is the reference implementation; any re-implementation
(pure Lua for Kong, Go, Rust, a Cisco module) MUST produce the same
`VerificationResult` for the same inputs. Where this spec and the reference
disagree, this spec wins.

## Input

- A presented credential: an X.509 AgentCert leaf, carried either as
  - an mTLS client certificate (preferred, high-assurance), or
  - a bearer token in the `X-AgentCert-Token` header (base64 PEM or raw PEM).
- Optional `claimed_agent_id` the caller asserts the agent to be.

## Decision procedure (in order)

1. **Parse.** If the credential is missing or unparseable → `UNVERIFIED`,
   `cert_valid=false`. Never raise; never block the pipeline (FR-3).
2. **Validity window.** If `now` is outside `[notBefore, notAfter]` → `EXPIRED`.
3. **Chain.** Build leaf → issuing → root and verify each signature against a
   **pinned** TrustModel trust anchor. Anchors are shipped/pinned, never fetched
   per request. No path to a pinned anchor → `UNVERIFIED`.
4. **Identity match.** The agent id is the first `ans:` URI-SAN, else the subject
   CN. If `claimed_agent_id` is supplied and differs → `UNVERIFIED`.
5. **Revocation.** Consult revocation state (OCSP or cached CRL / transparency
   log). If revoked → `REVOKED`. If it cannot be determined, mark *revocation
   unknown* and continue (the fail policy in step 8 decides).
6. **TrustScore.** Fetch the current score (reputation API) with a TTL cache
   (default 300 s). On backend miss, fall back to the score baked into the cert
   extension (`OID 1.3.6.1.4.1.58888.1.1`). If neither is available, mark *score
   unknown*.
7. **Tier band.** `>= 750 → Trusted`, `>= 500 → Caution`, else `Untrusted`;
   unknown score → `Unknown`.
8. **Fail policy.** If revocation OR score is unknown (backend unreachable, no
   usable cache):
   - `fail_mode = closed` (default for regulated) → `ERROR`.
   - `fail_mode = open` → `VERIFIED` with a stale-backend note.
   Otherwise → `VERIFIED`.
9. **Attest.** Sign the result so TrustModel can later audit that this verifier
   produced it.

## Output (`VerificationResult`)

```json
{
  "verification_status": "VERIFIED | UNVERIFIED | REVOKED | EXPIRED | ERROR",
  "agent_id": "ans://owner/name/environment",
  "cert_valid": true,
  "cert_expiry": "2026-11-22T00:00:00Z",
  "trust_score": { "value": 812, "tier": "Trusted", "last_updated": null, "score_age_seconds": 340 },
  "attestation": { "signed_by": "trustmodel-verifier-v1", "signature": "base64", "verified_at": "..." },
  "cache_hit": true
}
```

MVP-required fields: `verification_status`, `agent_id`, `cert_valid`,
`trust_score.value`, `trust_score.tier`.

## Invariants

- **TAG never decides allow/deny.** It returns the result; the host policy
  engine acts on it (FR-13/14).
- **No PHI/PII** is ever read, logged, cached, or transmitted — only agent
  identity and trust metadata (NFR-7).
- **Latency budget:** p99 < 50 ms on cache hit, < 250 ms on cache miss (NFR-1).
- **Revocation staleness is a contract.** The maximum age a cached "not
  revoked" answer may reach MUST be ≤ the origination-side revocation
  propagation SLA (TRUS-1813), or a revoked agent keeps verifying during the
  gap. Default 300 s. Document the chosen value for regulated customers (1824).
- **Least privilege:** the credential TAG uses to reach the backend is
  verification-read-only — it can never issue/revoke certs or mutate a score.
- **Transport:** all TAG→backend calls are mTLS.

## Carriage modes

| Mode | Assurance | Tier | Notes |
|---|---|---|---|
| Bearer token (`X-AgentCert-Token`) | medium | 1 (sandbox/pilot) | fastest to adopt; must resist replay (proof-of-possession) |
| mTLS client cert | high | 3 (production) | cert presented at TLS handshake |
