# MCP Trust Proxy (TRUS-2032)

Put it **in front of any MCP server — zero changes to the server.** Point your agent
at the proxy; the proxy forwards to the upstream and enforces trust in **both
directions**. Less invasive than adding a verify-gate to the server's code — nothing
to import, just a hop in front.

## What it does
- **Verify the agent (inbound)** — checks the caller's AgentCert + TrustScore (with
  proof-of-possession) on every `tools/call`.
- **Score the server (outbound)** — gates on the upstream's TrustScore (from config
  or the public Trust Index) vs a threshold.
- **Block rug-pulls** — pins each server's tool definitions and flags silent drift.
- **Guardrails** — deny-patterns on tool arguments (PII / secrets / injection).
- **Route many servers** behind one endpoint by path prefix.
- **Streamable-HTTP** — JSON *and* SSE responses, session lifecycle (GET/POST/DELETE).
- **Observability** — `/healthz`, `/stats`, `/metrics` (Prometheus), structured JSON logs.

**Shadow by default** (decide + log, block nothing). Set `TAG_MODE=enforce` to block.

## Quickstart — one command
```bash
docker run -p 8081:8081 \
  -e MCP_PROXY_UPSTREAM=http://your-mcp-server:9000/mcp \
  -e TAG_ANCHORS_PEM=/anchors/anchors.pem -v $PWD/anchors:/anchors:ro \
  ghcr.io/pdxlab/agentcert-tag/mcp-trust-proxy:latest
# point your MCP client at http://localhost:8081 instead of the server
```

## Multi-upstream + guardrails (config file)
Mount a JSON config (`MCP_PROXY_CONFIG=/config/config.json`) — see
[`config.example.json`](config.example.json): route by path, per-upstream score
thresholds, `trust_index_url` for live server scores, and guardrail deny-patterns.

## Deploy
- **Docker Compose:** [`docker-compose.example.yml`](docker-compose.example.yml)
- **Helm:** `helm install trust-proxy ./helm --set upstream=http://your-mcp:9000/mcp`
  (or `--set-json config='{...}'` for multi-upstream). See [`helm/values.yaml`](helm/values.yaml).

## Config reference
| Env / key | Meaning |
|---|---|
| `MCP_PROXY_UPSTREAM` | single upstream URL (or use `upstreams` in config) |
| `MCP_PROXY_CONFIG` | path to a JSON config (multi-upstream, guardrails) |
| `TAG_MODE` | `shadow` (default) / `enforce` |
| `TAG_FAIL_MODE` | `closed` (default) / `open` |
| `MCP_PROXY_MIN_SERVER_SCORE` | block upstreams below this score (0 = off) |
| `MCP_PROXY_TRUST_INDEX_URL` | Trust Index API base for live server scores |
| `TAG_ANCHORS_PEM` | trust-anchor bundle for cert-chain validation |
| `TRUSTMODEL_BASE_URL` | live Reputation/CRL backend (else offline cert-baked scores) |

## Performance — the trust tax
A full AgentCert verification adds **~0.4 ms single-request** (low-single-digit ms
under load); an unverified call is nearly free. Reproducible harness, published
numbers, charts, and the optimization roadmap live in a dedicated repo:
**[mcp-trust-proxy-benchmarking](https://github.com/pdxlab/mcp-trust-proxy-benchmarking)**.
A co-located dev harness is also here: [`benchmarks/`](benchmarks/README.md)
(`python proxy/benchmarks/bench.py`).

Security: [`THREAT_MODEL.md`](THREAT_MODEL.md).
