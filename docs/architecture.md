# agentcert-tag — architecture

TAG (Trust Attestation Gateway) is embeddable **AgentCert + TrustScore verification** for any gateway, firewall, sidecar, or in-process host. The verifier decides whether a calling agent's AgentCert is trusted; a logic gap here is an auth bypass, so the crypto core is reviewed as adversarially as any authn/authz change.

Repo: <https://github.com/pdxlab/agentcert-tag>  ·  Ticket: TRUS-1806

---

## 1. System context — who talks to what

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│   Calling agent (bearer of an AgentCert)                            │
│       │                                                             │
│       │  (a) mTLS: cert presented at the TLS handshake              │
│       │  (b) header: cert + proof-of-possession in HTTP headers     │
│       ▼                                                             │
│   ┌──────────────────┐    ┌─────────────────┐    ┌───────────────┐  │
│   │   Kong plugin    │    │  Envoy sidecar  │    │  SDK verify-  │  │
│   │ (Lua, kong/**)   │    │ ext_authz drop- │    │  gate client  │  │
│   │                  │    │ in (sidecar/**) │    │ (packages/**) │  │
│   └──────┬───────────┘    └───────┬─────────┘    └──────┬────────┘  │
│          │                        │                     │           │
│          └────────────┬───────────┴─────────────────────┘           │
│                       │                                             │
│                       ▼ (same decision contract, all 3 hosts)       │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │             TAG verifier core — core/agentcert_tag/         │   │
│   │                                                             │   │
│   │   Verifier.verify(cert_pem, claimed_agent_id,               │   │
│   │                   *, carriage, proof, audience)             │   │
│   │     → VerificationResult {status, agent_id, trust_score,    │   │
│   │                           source, reason}                   │   │
│   └────┬──────────────────────┬──────────────────┬──────────────┘   │
│        │                      │                  │                  │
│   ┌────▼─────────┐    ┌───────▼───────┐   ┌──────▼──────────────┐   │
│   │ Trust anchor │    │  Revocation   │   │   TrustScore live   │   │
│   │  (pinned     │    │  cache / CRL  │   │   backend (aurora-  │   │
│   │   issuer     │    │  / OCSP (file │   │   gateway) + cert-  │   │
│   │   bundle)    │    │  / endpoint)  │   │   baked fallback    │   │
│   └──────────────┘    └───────────────┘   └─────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**One decision contract, three hosts.** The Kong plugin, Envoy sidecar, and SDK client are all thin wrappers that extract (cert, proof, audience) from request headers and ask the verifier core. The *decision* always stays server-side so a Lua or TypeScript re-implementation can't drift from the Python reference.

---

## 2. The verifier pipeline — `Verifier.verify(…)` step by step

```
   cert_pem + claimed_agent_id?
   carriage ∈ {"mtls","header"}
   proof?  audience
         │
         ▼
   ┌─────────────────────────┐
   │  (1) parse              │  bad PEM / malformed → UNVERIFIED
   └─────────────────────────┘
         │
         ▼
   ┌─────────────────────────┐
   │  (2) derive agent_id    │  validated ans:// SAN/CN only
   └─────────────────────────┘
         │
         ▼
   ┌─────────────────────────┐
   │  (3) expiry             │  not-before / not-after
   └─────────────────────────┘
         │
         ▼
   ┌─────────────────────────┐  BasicConstraints(ca) +
   │  (4) chain to pinned    │  KeyUsage.keyCertSign on issuers
   │      trust anchor       │  rejects a CA leaf; sig verified
   │                         │  against the ISSUER's key, not the
   │                         │  cert's self-declared algorithm
   └─────────────────────────┘  (no algorithm confusion)
         │
         ▼
   ┌─────────────────────────┐  claimed_agent_id present but cert
   │  (5) identity match     │  has no id → UNVERIFIED (fail closed)
   └─────────────────────────┘
         │
         ▼
   ┌─────────────────────────┐  carriage == "mtls"  → skip
   │  (6) proof-of-possession│  carriage == "header"→ REQUIRE
   │      (pop.py)           │    leaf-signed stapled assertion
   │                         │    bound by subject + audience +
   │                         │    freshness window.  Missing /
   │                         │    stale → UNVERIFIED  (TRUS-1824:
   │                         │    without this a bare presented
   │                         │    cert is replayable)
   └─────────────────────────┘
         │
         ▼
   ┌─────────────────────────┐  bounded-staleness cache
   │  (7) revocation         │  DEFAULT_REVOCATION_MAX_STALENESS_S
   │                         │  must be ≤ issuance SLA (TRUS-1813)
   └─────────────────────────┘  revoked → UNVERIFIED
         │
         ▼
   ┌─────────────────────────┐  live backend read is authoritative
   │  (8) TrustScore         │  (source="live")
   │      (trust.py)         │  backend unreachable + fail_mode:
   │                         │     "closed" → ERROR  (NEVER a
   │                         │     silent VERIFIED)
   │                         │     "open"   → cert-baked fallback
   │                         │               source="cert_baked"
   └─────────────────────────┘           (frozen at issuance)
         │
         ▼
   VerificationResult {
     status: VERIFIED | UNVERIFIED | ERROR,
     agent_id, trust_score, source, reason
   }
```

**Invariant:** `verify()` **never raises** — a parse error or any failed step resolves to `UNVERIFIED` / `ERROR`. That lets a gateway/sidecar wrap a call-site in a single boolean without `try/except`.

---

## 3. Deployment topologies — three ways to embed TAG

### (A) Kong plugin

```
   Client ─▶ Kong proxy ─[verify-tag plugin]──▶   Upstream service
                 │        allow / deny
                 ▼
              core verifier (Lua that mirrors
              the Python decision)
```

### (B) Envoy ext_authz sidecar

```
   Client ─▶ Envoy / agentgateway / Kuadrant
                   │
                   │ ext_authz gRPC/HTTP
                   ▼
                sidecar process (Python core verifier)
                   │
                   ▼  OK / DENIED
               Envoy forwards or rejects
                   ▼
                Upstream service
```

### (C) In-process SDK

```
     ┌───── Application process ─────┐
     │                               │
     │   handler(req):               │
     │     result = tag.verify(      │
     │         cert, proof, audience │
     │     )                         │
     │     if not result.ok: 401     │
     │     else: business_logic()    │
     │                               │
     │  (packages/verify-gate-*: thin│
     │   wrappers around the core)   │
     └───────────────────────────────┘
```

**Key design insight:** all three topologies call *the same decision function*, so a policy change (for example, tightening the PoP freshness window) applies uniformly whether the enforcement point is a Kong plugin, an Envoy sidecar, or an in-process check. The reference implementation is Python (`verify.py`); the Lua plugin and any TS re-implementation must produce the same `VerificationResult` — this is called out as a convention in `.argus/memory/conventions.md`.

---

## What's not in these diagrams (deliberately)

TAG is the **verifier** side only. The following live in other repos:

- **Issuance** — minting AgentCerts, publishing to ANS + the transparency log — lives in `aurora-gateway` and the ANS registry.
- **Revocation publishing** — the issuer side of the revocation workflow.
- **TrustScore computation** — `aurora-gateway` computes the live score; TAG only reads it (or falls back to the cert-baked value).

---

## Load-bearing invariants a reviewer must protect

(From `.argus/memory/knowledge/verifier-core.md` + `conventions.md`.)

1. **Header carriage without a valid `proof` → `UNVERIFIED`.** Never verify a bare public cert off mTLS. (TRUS-1824 was the original replay hole.)
2. **Revocation freshness must stay ≤ the issuance revocation-propagation SLA** (TRUS-1813), or a revoked cert verifies during the gap.
3. **`fail_mode="closed"`** turns an unreachable backend into `ERROR`, never a silent `VERIFIED`.
4. **Signature verification keys off the trusted issuer's key**, never the cert's self-declared algorithm (no algorithm confusion). RSA pinned to a concrete padding.
5. **TrustScore provenance** — a live backend read is authoritative; the cert-baked fallback is frozen at issuance. Tag it `source="cert_baked"` and never present it as live.
6. **The verifier is a trust boundary.** A logic gap in `verify.py` is an auth bypass; review it adversarially as an authn/authz change.
