# TAG × Tyk (custom-auth middleware)

Verify a calling agent's **AgentCert + live TrustScore** on every request through
[Tyk](https://github.com/TykTechnologies/tyk) using a custom-auth JSVM middleware
— the "middleware plugin" path the maintainer recommended in
[TykTechnologies/tyk#8732](https://github.com/TykTechnologies/tyk/issues/8732).

The JS hook is a thin caller: it forwards the agent's cert headers to the TAG
verify sidecar (`/ext_authz`) via `TykMakeHttpRequest`, allows on `200`, and
injects the `x-agentcert-*` verdict for downstream. All crypto lives in the
sidecar, so there's no Go plugin to compile.

## 1. Run the sidecar

```bash
docker run -p 8080:8080 -e TAG_MODE=shadow \
  -e TAG_ANCHORS_PEM=/anchors/roots.pem -v $PWD/anchors:/anchors:ro \
  ghcr.io/pdxlab/agentcert-tag/sidecar:latest
```

## 2. Bundle + wire the middleware

- [`verify.js`](./verify.js) — the custom-auth hook (`agentCertAuthCheck`).
- [`manifest.json`](./manifest.json) — bundle manifest (`driver: otto`, `auth_check`).
- [`api-definition.example.json`](./api-definition.example.json) — the API
  definition keys: `custom_plugin_auth_enabled: true`, `custom_middleware.auth_check`,
  `custom_middleware_bundle`.

```bash
# build the plugin bundle (Tyk CLI), host it where the gateway can fetch it
tyk bundle build -o tag-agentcert-bundle.zip
# gateway (tyk.conf): enable_bundle_downloader + bundle_base_url
```

## 3. Roll out

1. **Shadow (default).** The sidecar returns `200` on everything in `TAG_MODE=shadow`,
   so the auth check always allows — it just annotates `x-agentcert-*`. Zero impact.
2. **Enforce.** Set `TAG_MODE=enforce` on the sidecar; now non-`VERIFIED` agents get
   a `403` from the middleware. Optional score floor: `TAG_MIN_SCORE=N`.

> The JSVM return convention (`TykJsResponse`, `request.ReturnOverrides`,
> `request.SetHeaders`) can vary by Tyk version — validate `verify.js` against your
> gateway's custom-auth JS API. A gRPC coprocess variant is also viable if you'd
> rather keep the verifier call out-of-process.

Header/verdict contract: [`../../docs/ext_authz.md`](../../docs/ext_authz.md).
