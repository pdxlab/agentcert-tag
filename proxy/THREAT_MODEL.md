# MCP Trust Proxy — threat model (TRUS-2042)

The proxy is a data-path trust boundary. Threats and mitigations:

| Threat | Mitigation |
|---|---|
| **Public-cert replay** — attacker presents a victim's public AgentCert | Header carriage requires a **proof-of-possession** (leaf-signed stapled assertion); mTLS carriage proven by TLS. |
| **Revoked/expired cert still accepted** | Bounded-staleness revocation cache; expiry enforced before chain build; SLA must be ≤ issuance revocation propagation. |
| **Backend unreachable → fail open** | `fail_mode=closed` turns an unreachable reputation/CRL backend into ERROR (blocked in enforce). |
| **Rug-pull** — upstream silently changes tool defs after approval | Tool-def pinning + drift detection on `tools/list`. |
| **Data exfiltration / injection via tool args** | Guardrail deny-patterns on tool arguments (shadow → enforce). |
| **Upstream spoof / MITM** | Deploy proxy↔upstream over mTLS or a private network; pin the anchor bundle. |
| **Latency DoS** — slow upstream stalls the proxy | Per-request timeouts (30s buffered / 120s stream); threaded server. |
| **Untrusted upstream server** | Server-trust gate (TrustScore threshold from config or Trust Index). |

Residual / operator responsibilities: TLS between proxy and upstream; anchor-bundle
provenance; enforce-mode rollout after a shadow-mode soak. Pre-GA review pending.
