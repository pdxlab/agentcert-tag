# TAG × Higress (native `ext-auth` wasm plugin)

Verify a calling agent's **AgentCert + live TrustScore** on every request through
[Higress](https://github.com/higress-group/higress) using its built-in `ext-auth`
wasm plugin — **config, not code**. Higress calls the TAG verify sidecar; the
sidecar does chain + revocation + score and returns `200`/`403` plus
`x-agentcert-*` verdict headers that get injected onto the upstream request.

This is the "reference plugin/config" offered in
[higress#4784](https://github.com/higress-group/higress/issues/4784).

## 1. Deploy the sidecar

Run `ghcr.io/pdxlab/agentcert-tag/sidecar:latest` as a Service named `tag-sidecar`
on port `8080` (shadow mode by default). A minimal Deployment/Service and the
trust-anchor mount are in [`../../sidecar/`](../../sidecar/).

## 2. Apply the plugin

```bash
kubectl apply -f wasmplugin.yaml
```

See [`wasmplugin.yaml`](./wasmplugin.yaml). It uses `endpoint_mode: forward_auth`
with a fixed `path: /ext_authz` (the TAG sidecar matches that path exactly), forwards
the `x-agent-cert*` headers, and copies `x-agentcert-*` back onto the upstream request.

## 3. Roll out

1. **Shadow (default).** `failure_mode_allow: true` + the sidecar's `TAG_MODE=shadow`
   means it verifies + logs but never blocks. Watch `x-agentcert-shadow-would`.
2. **Enforce.** Flip the sidecar to `TAG_MODE=enforce` (and set
   `failure_mode_allow: false` if you also want verifier-down to deny).
3. Optional score floor: `TAG_MIN_SCORE=N` on the sidecar.

Ext-auth config reference:
`plugins/wasm-go/extensions/ext-auth/README_EN.md` in the Higress repo.
Header/verdict contract: [`../../docs/ext_authz.md`](../../docs/ext_authz.md).
