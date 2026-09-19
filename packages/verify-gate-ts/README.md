# @trustmodel/agentcert-tag

Verify an **AgentCert + TrustScore** inside a TypeScript MCP server. Thin, dependency-free
client for a [TAG](https://trustmodel.ai/verify) verify endpoint — **off by default**,
**shadow mode** when on (logs, never blocks), safe to merge.

```bash
npm install @trustmodel/agentcert-tag
```

```ts
import { verifyGate, extractToken } from "@trustmodel/agentcert-tag";

const guard = verifyGate({ mode: "shadow" });   // shadow | enforce

// inside your MCP tool-call handler:
await guard(extractToken(request.headers));      // logs (shadow) / throws VerifyError (enforce)
```

Enable per environment — nothing runs until you opt in:

| Env var | Meaning |
|---|---|
| `TRUSTMODEL_VERIFY=1` | turn the gate on (otherwise `guard` is a no-op) |
| `TRUSTMODEL_VERIFY_URL` | TAG verify endpoint (default `http://localhost:8080/verify`) |
| `TRUSTMODEL_MODE=enforce` | switch to enforcement |

Never reads request payloads (metadata only); never makes the allow/deny decision itself —
returns a structured verdict (`VERIFIED` / `REVOKED` / `UNVERIFIED` / `ERROR`) your server
acts on. MIT licensed. Part of [pdxlab/agentcert-tag](https://github.com/pdxlab/agentcert-tag).

## Proof-of-possession (enforce mode)

A presented AgentCert is public, so on a non-mTLS carriage the caller must also send a stapled proof-of-possession (a leaf-signed assertion) in the `X-AgentCert-Proof` header. The gate extracts it (`extract_proof` / `extractProof`) and forwards it with the credential; the verify endpoint rejects a bare cert without it. On mTLS, pass `carriage: "mtls"` — the handshake already proves possession.
