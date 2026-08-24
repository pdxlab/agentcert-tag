# TAG — Trusted Agent Gateway

**Turn any API gateway, AI gateway, or firewall into a verifier of TrustModel
AgentCert + TrustScore.** TAG is a lightweight, embeddable module — a Kong
plugin, an Envoy/reverse-proxy sidecar, or (coming) a Cisco Firepower module —
that answers one question on every request:

> *Is this agent who it claims to be, and what is its trust posture right now?*

TAG does **not** replace your gateway's policy engine. It plugs in, exposes the
verification result (and TrustScore) as a variable your native rules already
know how to act on, logs the decision, and gets out of the way.

This is the consumption/verification half of the AgentCert loop. The other half
— minting a cert automatically at CI/CD deploy time — is
[`agentcert-issue-action`](https://github.com/pdxlab/agentcert-issue-action).

---

## Under 10 minutes to your first verification

TAG installs in **shadow mode by default**: it verifies and logs every request
but **blocks nothing**, so you can drop it into real traffic without fear of
breaking anything. You flip to enforcement only once you've seen it work.

```bash
git clone https://github.com/pdxlab/agentcert-tag
cd agentcert-tag/demo
docker compose up --build          # Kong + TAG + a local TrustModel mock
./demo_request.sh                  # mint a cert, call through Kong, see it verified
```

You'll see the "aha" log line from Kong:

```
[agentcert-tag] mode=shadow agent=ans://pdxlab/sample-agent/production status=VERIFIED score=812 tier=Trusted
```

No login, no mTLS, no TrustModel support ticket required for the sandbox path.

## The three-tier adoption path

| Tier | What | Credential | Enforcement |
|---|---|---|---|
| **1 — Sandbox** | try it against pre-seeded demo agents | bearer token, instant | observe-only |
| **2 — Pilot** | point at your real TrustModel account | swap the API key | observe-only, rollback = a config flag |
| **3 — Production** | full enforcement | mTLS | fail-open/closed, explicit; SIEM audit |

Shadow → enforce is a config change, never a reinstall. Tier-3 security
requirements are never relaxed for onboarding speed.

## What's in here

| Path | What |
|---|---|
| `spec/verification-core.md` | the normative, language-agnostic verification contract |
| `core/agentcert_tag/` | reference implementation (Python): chain validation, revocation, TrustScore + cache, structured signed result |
| `kong/agentcert-tag/` | Kong plugin (Lua) — shadow-mode default, exposes `kong.ctx.shared.trustscore` |
| `sidecar/` | generic HTTP verify sidecar + container image (Envoy ext_authz / any reverse proxy) |
| `demo/` | full closed-loop demo (Kong + mock TrustModel) and a no-Docker proof |

## How verification works

Every request carrying an AgentCert (via `X-AgentCert-Token` header or an mTLS
client cert) is checked against:

1. **Chain** — validates to a pinned TrustModel trust anchor (private PKI).
2. **Revocation** — cached CRL / transparency log, offline-tolerant.
3. **TrustScore** — current score from the reputation API (TTL-cached), with an
   offline fallback to the score baked into the cert.

The result is returned as a structured object (see the spec), exposed to your
policy engine, and logged — payload content is **never** touched (metadata only).

## Configuration (Kong, native `kong.yml`)

```yaml
plugins:
  - name: agentcert-tag
    config:
      verify_url: "http://agentcert-tag-sidecar:8080/verify"
      mode: "shadow"              # shadow (default) | enforce
      credential_header: "X-AgentCert-Token"
      cache_ttl: 300
      fail_mode: "closed"         # closed (regulated default) | open
      block_on: []                # e.g. ["REVOKED","UNVERIFIED"] once in enforce mode
```

## Security

All TAG→backend traffic is mTLS. TAG's backend credential is
verification-read-only (it can never issue or revoke a cert or change a score).
CA private keys never touch the host platform — TAG ships only public
verification logic and pinned trust anchors. No PHI/PII is ever logged, cached,
or transmitted. See `spec/verification-core.md` for the full invariant list; a
formal threat model and SOC 2 control mapping gate any regulated-customer
production rollout.

## Status

v0.1 — reference core + Kong plugin + sidecar + demo. Cisco Firepower module,
hosted sandbox, and Kong Plugin Hub listing are tracked in TRUS-1806.

MIT licensed.
