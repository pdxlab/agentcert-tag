# trustmodel-agentcert-tag

Verify an **AgentCert + TrustScore** inside a Python MCP server. Thin, dependency-free
client for a [TAG](https://trustmodel.ai/verify) verify endpoint — **off by default**,
**shadow mode** when on (logs, never blocks), safe to merge.

```bash
pip install trustmodel-agentcert-tag
```

```python
from trustmodel_agentcert_tag import verify_gate, extract_token

guard = verify_gate(mode="shadow")            # shadow | enforce

async def handle_tool_call(request):
    token = extract_token(request.headers)    # X-AgentCert-Token (or mTLS-derived)
    await guard(token)                        # logs (shadow) / raises VerifyError (enforce)
    return await dispatch(request)
```

Enable per environment — nothing runs until you opt in:

| Env var | Meaning |
|---|---|
| `TRUSTMODEL_VERIFY=1` | turn the gate on (otherwise `guard` is a no-op) |
| `TRUSTMODEL_VERIFY_URL` | TAG verify endpoint (default `http://localhost:8080/verify`) |
| `TRUSTMODEL_MODE=enforce` | switch to enforcement |

The gate never reads request payloads (metadata only) and never makes the allow/deny
decision on its own — it returns a structured verdict (`VERIFIED` / `REVOKED` /
`UNVERIFIED` / `ERROR`) your server acts on. MIT licensed. Part of
[pdxlab/agentcert-tag](https://github.com/pdxlab/agentcert-tag).
