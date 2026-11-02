# TAG × Envoy Gateway (`SecurityPolicy` extAuth)

Verify a calling agent's **AgentCert + live TrustScore** on every request through
[Envoy Gateway](https://github.com/envoyproxy/gateway) — with **no plugin code in
the gateway**. Envoy Gateway's `SecurityPolicy.extAuth.http` calls the TAG verify
sidecar over HTTP; the sidecar does the crypto (chain + revocation + score) and
returns `200` (allow) / `403` (deny) plus `x-agentcert-*` verdict headers that get
injected onto the upstream request.

Upstream example PR:
[envoyproxy/gateway#10465](https://github.com/envoyproxy/gateway/pull/10465).

## 1. Apply the example

[`securitypolicy.yaml`](./securitypolicy.yaml) is self-contained — the sidecar
Deployment + Service, an `HTTPRoute`, and the `SecurityPolicy` that wires them:

```bash
kubectl apply -f securitypolicy.yaml
```

The `SecurityPolicy` targets the route, points `extAuth.http.backendRefs` at the
sidecar Service with `pathOverride: /ext_authz`, forwards the caller's
`x-agent-cert*` headers via `headersToExtAuth`, and injects the `x-agentcert-*`
verdict + TrustScore upstream via `headersToBackend`. Field names are verified
against `api/v1alpha1/ext_auth_types.go`.

## 2. Roll out

1. **Shadow (default).** `failOpen: true` on the policy and `TAG_MODE=shadow` on the
   sidecar — it observes/logs and blocks nothing. Watch `x-agentcert-shadow-would`
   to see what enforce *would* block.
2. **Enforce.** Set `TAG_MODE=enforce` on the sidecar (optionally `TAG_MIN_SCORE=N`)
   and flip `failOpen: false`. Now `VERIFIED` allows, everything else denies.

Header/verdict contract: [`../../docs/ext_authz.md`](../../docs/ext_authz.md).
