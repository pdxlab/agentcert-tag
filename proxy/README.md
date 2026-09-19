# MCP Trust Proxy (TRUS-2032)

A **trust-first proxy** that sits in front of one or more MCP servers and enforces
trust in **both directions**, reusing the `agentcert_tag` verify core:

- **inbound** — verifies the calling agent's AgentCert + TrustScore on every
  `tools/call` (proof-of-possession on the header carriage). shadow → log; enforce → block.
- **outbound** — gates on the upstream server's TrustScore vs a threshold.
- **rug-pull** — pins each server's tool definitions and flags silent drift.

**Shadow by default** (decides + logs, blocks nothing). Stdlib-only.

```bash
docker run -p 8081:8081 \
  -e MCP_PROXY_UPSTREAM=http://your-mcp-server:9000/mcp \
  -e TAG_ANCHORS_PEM=/anchors.pem \
  -e TAG_MODE=shadow \
  ghcr.io/pdxlab/agentcert-tag/mcp-trust-proxy:latest
```

| Env | Meaning |
|---|---|
| `MCP_PROXY_UPSTREAM` | upstream MCP server URL (required) |
| `TAG_MODE` | `shadow` (default) or `enforce` |
| `MCP_PROXY_MIN_SERVER_SCORE` | block upstreams below this TrustScore (0 = off) |
| `TAG_ANCHORS_PEM` | trust-anchor bundle for cert-chain validation |
| `TRUSTMODEL_BASE_URL` | live Reputation/CRL backend (else offline cert-baked scores) |

Roadmap (per epic TRUS-2033–2042): multi-upstream routing, discovery from the ANS
Trust Index, AGP inline guardrails, and the console trust dashboard.
