# TAG integrations — available now

Verify an agent's **AgentCert + TrustScore** at your gateway, firewall, or MCP
server. Everything below is **shadow-mode by default** (decides + logs, blocks
nothing) and opt-in.

## Kong plugin (Lua) — `kong/agentcert-tag/`

A native Kong plugin. Exposes `kong.ctx.shared.trustscore` /
`kong.ctx.shared.agentcert` for Kong's own policy rules; it verifies, it does not
replace Kong's policy engine.

```bash
# from the repo (git/source install)
luarocks make kong/agentcert-tag/kong-plugin-agentcert-tag-0.2.0-1.rockspec
# then enable it
export KONG_PLUGINS=bundled,agentcert-tag
```

Configure `verify_url` to a running TAG verify endpoint (the sidecar below, or a
hosted endpoint). Publishing to LuaRocks.org / Kong Hub is tracked in TRUS-1823.

## Verify sidecar (container) — `sidecar/`

A tiny, stdlib-only HTTP `/verify` service. Any host that can make an HTTP
**ext_authz / ext_proc / webhook** callout (Envoy, Envoy-based gateways such as
Kuadrant, reverse proxies, firewalls) becomes an AgentCert verifier without
re-implementing crypto.

```bash
docker run -p 8080:8080 ghcr.io/pdxlab/agentcert-tag/sidecar:latest
# POST /verify {"credential":"<PEM>","carriage":"header|mtls","proof":{...}}
```

Point your gateway's external-authorization callout at `http://<sidecar>:8080/verify`.

## Language SDKs (MCP servers)

- npm `@trustmodel/agentcert-tag` · PyPI `trustmodel-agentcert-tag` — drop-in
  verify-gate middleware for MCP servers. See each package's README.

## On request / roadmap

Native plugins for **agentgateway, Lasso, LiteLLM, Bifrost, Pomerium, Docker MCP
Gateway** and others are integration-on-request today — the sidecar's ext_authz
path already covers any gateway that supports an external-auth callout. Open an
issue if you'd like a native plugin for your gateway.
