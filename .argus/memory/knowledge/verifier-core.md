# Knowledge — the verifier core

`Verifier.verify(cert_pem, claimed_agent_id=None, *, carriage, proof, audience)` runs, in order:
parse → derive agent_id (validated `ans://` SAN/CN only) → expiry → chain-to-pinned-anchor
(enforces `BasicConstraints(ca)` + `KeyUsage.keyCertSign` on issuers, rejects a CA leaf) →
identity match (fail closed if claimed but cert has no id) → **proof-of-possession** (required
unless `carriage="mtls"`; a leaf-signed stapled assertion, freshness + audience + subject
bound) → revocation (bounded-staleness cache) → TrustScore (live, else cert-baked fallback
tagged stale).

**Load-bearing invariants a reviewer should protect:**
- Header carriage without a valid `proof` → `UNVERIFIED`. Never verify a bare public cert
  off mTLS. (This was the original replay hole — TRUS-1824.)
- Revocation `DEFAULT_REVOCATION_MAX_STALENESS_S` must be ≤ the issuance revocation-propagation
  SLA (TRUS-1813) or a revoked cert verifies during the gap.
- `fail_mode="closed"` must turn an unreachable backend into `ERROR`, not a fail-open `VERIFIED`.
- The verify-gate packages (`packages/verify-gate-*`) are thin clients: they extract token +
  proof from request headers and forward them; the decision stays server-side.
