# TAG × Kuadrant (Istio `CUSTOM` ext_authz)

Verify a calling agent's **AgentCert + live TrustScore** on every request through
a [Kuadrant](https://github.com/Kuadrant/kuadrant-operator)-managed gateway — with
**no plugin code in the gateway**. Kuadrant runs on Istio/Envoy, so the TAG verify
sidecar plugs in as an Istio external authorizer: the sidecar does the crypto
(chain + revocation + score) and returns `200` (allow) / `403` (deny) plus
`x-agentcert-*` verdict headers. It runs *alongside* Kuadrant's own
`AuthPolicy`/Authorino — it verifies, it doesn't replace Kuadrant's policy engine.

This is the config from the thread with the maintainer in
[Kuadrant/mcp-gateway#1520](https://github.com/Kuadrant/mcp-gateway/issues/1520)
(decoupled ext_authz, no code in the gateway). Upstream example PR:
[Kuadrant/mcp-gateway#1634](https://github.com/Kuadrant/mcp-gateway/pull/1634).

> **Why `CUSTOM` ext_authz, not an `AuthPolicy` `metadata.http` call?** Authorino's
> `metadata.http` exposes only the external service's JSON *body*, and the TAG
> sidecar returns its verdict in response *headers*. The Istio
> `envoyExtAuthzHttp` + `AuthorizationPolicy action: CUSTOM` path reads those
> `x-agentcert-*` headers natively — it's the same ext_authz surface the gateway
> already uses for Authorino.

## 1. Run the sidecar

[`sidecar.yaml`](./sidecar.yaml) — Deployment + Service for
`ghcr.io/pdxlab/agentcert-tag/sidecar`, `TAG_MODE=shadow` by default.

```bash
kubectl apply -f sidecar.yaml
```

## 2. Register + attach it

- [`extension-provider.yaml`](./extension-provider.yaml) — registers the sidecar
  as an Istio `envoyExtAuthzHttp` extension provider (`/ext_authz`), forwarding the
  `x-agent-cert*` request headers and copying the `x-agentcert-*` verdict upstream.
- [`authorizationpolicy.yaml`](./authorizationpolicy.yaml) — an `AuthorizationPolicy`
  with `action: CUSTOM` referencing the provider, scoped to cert-bearing requests.

```bash
kubectl apply -f extension-provider.yaml   # mesh config
kubectl apply -f authorizationpolicy.yaml
```

Adjust the workload selector / namespace in the manifests to match your install.

## 3. Roll out

1. **Shadow (default).** The sidecar decides + logs but allows everything — watch
   `x-agentcert-shadow-would` to see what enforce *would* block. Zero request impact.
2. **Enforce.** Set `TAG_MODE=enforce` on the sidecar (optionally `TAG_MIN_SCORE=N`).
   Now `VERIFIED` allows, everything else denies — no policy change.
3. Keep the sidecar's `TAG_FAIL_MODE` aligned with the provider's `failOpen`.

Header/verdict contract: [`../../docs/ext_authz.md`](../../docs/ext_authz.md).
