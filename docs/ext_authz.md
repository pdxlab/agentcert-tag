# AgentCert verification via ext_authz

The TAG verify sidecar exposes a native **ext_authz** endpoint, so any gateway
that speaks the Envoy `ext_authz` HTTP protocol — **agentgateway, Kuadrant/Authorino,
Envoy, Pomerium** — can verify a calling agent's AgentCert + TrustScore on every
request with **no code in the gateway**. Point the gateway's external-authorization
hook at the sidecar and read its response.

- **Off by default.** The sidecar starts in `shadow` mode: it decides and reports
  but returns `200` on every request — it never blocks. Flip `TAG_MODE=enforce`
  when you're ready.
- **Metadata only.** The sidecar reads request headers (the cert), never the body.
- **Fail-safe.** `TAG_FAIL_MODE=open|closed` decides what happens if the backend
  is unreachable (default `closed` in enforce).

## The contract

The gateway forwards the incoming request headers to the sidecar's `/ext_authz`
path. The sidecar reads:

| Header (default name)      | Meaning                                             |
|----------------------------|-----------------------------------------------------|
| `x-agent-cert`             | base64-encoded PEM leaf (the AgentCert)             |
| `x-agent-cert-carriage`    | `header` (default) or `mtls`                        |
| `x-agent-cert-proof`       | stapled proof-of-possession (required for `header`) |
| `x-agent-id`               | claimed ANS id, optional (cross-checked to the SAN) |
| `x-agent-cert-audience`    | PoP audience, optional                              |

> Header names are configurable (`TAG_CERT_HEADER`, …). If the gateway already
> terminates mTLS with the agent's cert, set `x-agent-cert-carriage: mtls` and the
> stapled proof-of-possession is not required (the handshake proved possession).

It returns **`200` (allow)** or **`403` (deny)**, plus verdict headers on *both*
outcomes so your policy/logs get full context:

| Response header             | Example        |
|-----------------------------|----------------|
| `x-agentcert-verdict`       | `VERIFIED` / `REVOKED` / `UNVERIFIED` / `EXPIRED` / `ERROR` |
| `x-agentcert-agent-id`      | `ans://acme/agent/prod` |
| `x-agentcert-trustscore`    | `812` |
| `x-agentcert-tier`          | `Trusted` / `Caution` / `Untrusted` / `Unknown` |
| `x-agentcert-score-source`  | `live` / `cert_baked` / `none` |
| `x-agentcert-mode`          | `shadow` / `enforce` |
| `x-agentcert-shadow-would`  | `allow` / `deny` — what enforce *would* do (shadow visibility) |
| `x-agentcert-decision`      | `allow` / `deny` |

In `enforce`, `VERIFIED` allows and everything else denies. Set `TAG_MIN_SCORE=N`
to additionally require `trust_score >= N`.

## Run the sidecar

```bash
docker run -p 8080:8080 \
  -e TAG_MODE=shadow \
  -e TAG_ANCHORS_PEM=/anchors/roots.pem \
  -v $PWD/anchors:/anchors:ro \
  ghcr.io/pdxlab/agentcert-tag/sidecar:latest
# health: curl localhost:8080/healthz   ->  {"ok":true,"extauthz_path":"/ext_authz"}
```

## Wire it up — Envoy `ext_authz` HTTP (canonical)

This is the reference config that agentgateway / Kuadrant / Pomerium ext_authz
all follow. The sidecar satisfies it as-is:

```yaml
http_filters:
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    transport_api_version: V3
    http_service:
      server_uri:
        uri: tag-sidecar:8080
        cluster: tag_sidecar
        timeout: 0.25s
      path_prefix: /ext_authz
      authorization_request:
        allowed_headers:
          patterns:
          - exact: x-agent-cert
          - exact: x-agent-cert-proof
          - exact: x-agent-cert-carriage
          - exact: x-agent-id
      authorization_response:
        allowed_upstream_headers:      # inject verdict onto the upstream request
          patterns:
          - prefix: x-agentcert-
    failure_mode_allow: true          # gateway-side fail-open; mirror TAG_FAIL_MODE
```

## agentgateway

agentgateway supports the `ext_authz` protocol, so no plugin code is needed in
agentgateway itself — configure an external-authorization target pointing at the
sidecar's `/ext_authz` endpoint, forward the `x-agent-cert*` request headers, and
(optionally) surface the `x-agentcert-*` response headers to your policy. See the
agentgateway ext_authz configuration for the exact stanza; the contract above is
what the sidecar expects and returns.

## Roll-out

1. Deploy in `shadow` (default). Watch `x-agentcert-shadow-would` in logs to see
   what would be blocked — zero request impact.
2. When the deny rate looks right, set `TAG_MODE=enforce` (add `TAG_MIN_SCORE` if
   you want a score floor).
3. Keep `TAG_FAIL_MODE` aligned with the gateway's `failure_mode_allow`.
