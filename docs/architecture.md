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
│   │     → VerificationResult(verification_status, agent_id,     │   │
│   │        cert_valid, cert_expiry, trust_score{value, tier,    │   │
│   │        last_updated, score_age_seconds, source},            │   │
│   │        attestation, cache_hit, detail)                      │   │
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

**One decision contract.** Every host — the Kong plugin, the Envoy sidecar, the `verify-gate-py` / `verify-gate-ts` SDKs — extracts `(cert, proof, audience)` from a request and asks the Python verifier core for the decision. The decision never leaves the Python core: Kong and the SDKs are HTTP clients to `conf.verify_url` / `TRUSTMODEL_VERIFY_URL`, and the only in-process embedding path is to import `agentcert_tag.Verifier` directly. There is no Lua or TypeScript re-implementation of the decision, so there is nothing to keep in sync.

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
   └─────────────────────────┘  outside window → EXPIRED
         │
         ▼
   ┌─────────────────────────┐  BasicConstraints(ca) +
   │  (4) chain to pinned    │  KeyUsage.keyCertSign on issuers
   │      trust anchor       │  rejects a CA leaf; signature-
   │                         │  verification METHOD is picked from
   │                         │  the issuer's key type (not the cert's
   │                         │  self-declared one), which closes the
   │                         │  algorithm-confusion gap.  The hash
   │                         │  used is the cert's own
   │                         │  signature_hash_algorithm; EdDSA —
   │                         │  the TrustModel issuer default
   │                         │  (Ed25519) — takes no hash.
   └─────────────────────────┘
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
   └─────────────────────────┘  revoked → REVOKED
         │
         ▼
   ┌─────────────────────────┐  live backend read is authoritative
   │  (8) TrustScore         │  (trust_score.source="live")
   │      (trust.py)         │
   └─────────────────────────┘
         │
         ▼
   ┌─────────────────────────┐  fires only if (7) OR (8) needed a
   │  (9) fail policy        │  backend that was unreachable AND no
   │                         │  fresh cache was available for it:
   │                         │   fail_mode="closed" → ERROR
   │                         │       detail="backend unreachable
   │                         │       and no fresh cache (fail-closed)"
   │                         │   fail_mode="open"   → VERIFIED
   │                         │       detail="ok (fail-open, stale
   │                         │       backend)"; trust_score.source
   │                         │       falls back to "cert_baked" when
   │                         │       the score was the unknown.
   │                         │
   │                         │  NB: fail-open covers UNKNOWN revocation
   │                         │  state, not just unknown score — so a
   │                         │  revoked cert verifies while the
   │                         │  revocation source is unreachable.
   │                         │  That is the main reason to choose
   │                         │  closed for regulated deployments.
   └─────────────────────────┘
         │
         ▼
   VerificationResult(
     verification_status: VERIFIED | UNVERIFIED | REVOKED | EXPIRED | ERROR,
     agent_id,
     cert_valid: bool,
     cert_expiry: Optional[str],
     trust_score: {value, tier, last_updated, score_age_seconds, source},
     attestation: {signed_by, signature, verified_at},
     cache_hit: bool,
     detail: Optional[str]
   )
```

**Invariant:** `verify()` **never raises** — a parse error or any failed step resolves to a terminal `verification_status` (`UNVERIFIED` for most logic failures, `EXPIRED` for step 3, `REVOKED` for step 7, `ERROR` for infrastructure failures under fail-closed). That lets a gateway/sidecar branch on `result.verification_status` without `try/except`. `VerificationResult.allowed_by_default` is a convenience property that returns `True` iff status is `VERIFIED`; it's a hint the host policy engine may ignore, not a built-in allow/deny decision (FR-14).

---

## 3. Deployment topologies — two ways to reach the verifier

TAG runs the verifier core in a Python process. Every topology either embeds that process in-line (3C) or reaches it over HTTP (3A, 3B).

### (A) Kong plugin — HTTP client

```
   Client ─▶ Kong proxy ─[verify-tag plugin]──▶   Upstream service
                 │                                (block / log based on
                 │                                 config.block_on list)
                 ▼  HTTP POST conf.verify_url
              TAG sidecar (Python core verifier)
```

`kong/agentcert-tag/handler.lua` calls `conf.verify_url` over HTTP via
`resty.http` (250 ms NFR-1 budget per cache-miss). It then reads the
decision out of the JSON response and writes it to
`kong.ctx.shared.trustscore` / `kong.ctx.shared.agentcert` so Kong's own
policy rules can act on it. The plugin itself only blocks in ENFORCE
mode when the verdict is on the operator-supplied `config.block_on`
list (FR-14: the plugin never unilaterally decides allow/deny).

The plugin has its own fail-open / fail-closed behavior when the verify
URL itself is unreachable, independent of the verifier core's
`fail_mode` (which governs the core's own backend lookups to the
transparency log and reputation API). Kong's own behavior is controlled
by `config.fail_mode` (`"open"` or `"closed"`, default `"closed"` —
`kong/agentcert-tag/schema.lua` ships "closed for regulated env"). An
unreachable verifier therefore becomes an operator-visible failure by
default rather than a silent pass; set it to `"open"` only if the host
has its own primary gate and you want availability over provenance.

### (B) Envoy ext_authz sidecar — HTTP

```
   Client ─▶ Envoy / agentgateway / Kuadrant
                   │  ext_authz HTTP check
                   ▼  POST /ext_authz
                TAG sidecar (ThreadingHTTPServer,
                  Python core verifier)
                   │
                   ▼  OK / DENIED (ext_authz semantics)
               Envoy forwards or rejects
                   ▼
                Upstream service
```

`sidecar/server.py` runs a `ThreadingHTTPServer` and exposes two HTTP
endpoints: `POST /verify` (JSON request/response, used by Kong and the
SDKs) and `/ext_authz` (ext_authz HTTP-check semantics, used by Envoy
and compatible proxies). It does **not** speak ext_authz gRPC — ext_authz
in TAG is HTTP throughout.

### (C) In-process embedding

The only way to run TAG in-process (no HTTP hop) is to import the
verifier core directly:

```python
from agentcert_tag import Verifier, Mode, FailMode, InMemoryTrustSource

# A TrustSource supplies trust anchors + reputation + revocation lookups.
# Use InMemoryTrustSource for tests/fixtures; HttpTrustSource against a
# real aurora-gateway deployment.
trust_source = InMemoryTrustSource(anchors_pem=[…])  # pinned issuer bundle

verifier = Verifier(
    trust_source,
    mode=Mode.SHADOW,        # decide + log; never influence enforcement
    fail_mode=FailMode.CLOSED,
)

def handler(req):
    result = verifier.verify(
        cert_pem=req.client_cert_pem,
        carriage="mtls",
        audience="svc-api.example",
    )
    # result.verification_status ∈ {VERIFIED, UNVERIFIED, REVOKED,
    #                               EXPIRED, ERROR}
    # In SHADOW mode you record the result and emit upstream signals,
    # but the application's own policy engine decides what to do.
    emit_signal(result)
    return business_logic(req)
```

`packages/verify-gate-py/trustmodel_agentcert_tag/` and
`packages/verify-gate-ts/src/` are **not** in-process embeddings — they
are thin HTTP clients that call a TAG sidecar's `/verify` endpoint
(default `http://localhost:8080/verify`, overridable via
`TRUSTMODEL_VERIFY_URL`). They belong under topology B; use them when
you want the same JSON decision contract the Kong plugin uses without
writing the HTTP call yourself.

---

### Mode: SHADOW is the default install posture

All three topologies run through `Mode.SHADOW` by default. In SHADOW
the verifier *decides* and *logs*, but it never influences enforcement
— the host application / Kong plugin / Envoy policy chain still has
the final say. TAG is a signal source, not an enforcement point (FR-14):
even in `Mode.ENFORCE`, the *actionable* decision comes from the host
policy engine acting on `verification_status` + `trust_score.tier` +
`cert_valid`. The sidecar's `/ext_authz` endpoint returns an ext_authz
verdict because Envoy requires one, but the verdict is derived from the
same `VerificationResult` the SHADOW path records; nothing in TAG makes
a host-specific allow/deny choice of its own.

A production rollout therefore looks like: start in SHADOW, read the
emitted signals through the existing observability stack until the
traffic pattern is understood, then flip to ENFORCE on the surfaces
where the host policy engine has an explicit `block_on` rule.

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
4. **Signature verification method is dispatched from the issuer's key type** (EC, RSA, Ed25519/Ed448), never from the cert's self-declared `signatureAlgorithm`. That closes the classic algorithm-confusion gap; the cert still supplies its own `signature_hash_algorithm` (consumed for EC and RSA; EdDSA — the TrustModel default — takes no hash). RSA is pinned to PKCS1v15.
5. **TrustScore provenance** — a live backend read is authoritative; the cert-baked fallback is frozen at issuance. Tag it `source="cert_baked"` and never present it as live.
6. **The verifier is a trust boundary.** A logic gap in `verify.py` is an auth bypass; review it adversarially as an authn/authz change.
