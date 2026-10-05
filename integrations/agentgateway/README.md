# TAG × agentgateway (ext_authz)

Verify a calling agent's **AgentCert + live TrustScore** on every request through
[agentgateway](https://github.com/agentgateway/agentgateway) — with **no plugin
code in the gateway**. agentgateway's `extAuthz` policy calls the TAG verify
sidecar over HTTP; the sidecar does the crypto (chain + revocation + score) and
returns `200` (allow) / `403` (deny) plus `x-agentcert-*` verdict headers.

This is the config the maintainer pointed at in
[agentgateway#3573](https://github.com/agentgateway/agentgateway/issues/3573)
("agentgateway supports ext_authz, so there wouldn't need to be code in
agentgateway itself").

## 1. Run the sidecar

```bash
docker run -p 8080:8080 -e TAG_MODE=shadow \
  -e TAG_ANCHORS_PEM=/anchors/roots.pem -v $PWD/anchors:/anchors:ro \
  ghcr.io/pdxlab/agentcert-tag/sidecar:latest
# health: curl localhost:8080/healthz -> {"ok":true,"extauthz_path":"/ext_authz"}
```

## 2. Point agentgateway at it

See [`config.yaml`](./config.yaml) — add the `extAuthz` policy to the route that
fronts your MCP/agent backend. It forwards the `x-agent-cert*` request headers to
the sidecar and copies the `x-agentcert-*` verdict back onto the upstream request.

## 3. Roll out

1. **Shadow (default).** The sidecar decides + logs but returns `200` on
   everything — watch `x-agentcert-shadow-would` to see what enforce *would* block.
   Zero request impact.
2. **Enforce.** Set `TAG_MODE=enforce` on the sidecar (optionally `TAG_MIN_SCORE=N`
   for a score floor). Now `VERIFIED` allows, everything else denies.
3. Keep the sidecar's `TAG_FAIL_MODE` aligned with `failureMode.denyWithStatus`.

Header/verdict contract: [`../../docs/ext_authz.md`](../../docs/ext_authz.md).
