-- Kong plugin config schema for TAG (TrustModel AgentCert verification).
-- Config lives in Kong's native format (kong.yml) — no proprietary DSL (FR/impl-guide §2).
local typedefs = require "kong.db.schema.typedefs"

return {
  name = "agentcert-tag",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          -- Where TAG's verify core is reached (sidecar or hosted sandbox).
          { verify_url = { type = "string", required = true,
              default = "http://agentcert-tag-sidecar:8080/verify" } },
          { api_key = { type = "string", required = false, referenceable = true } },

          -- Install default is SHADOW: decide + log, enforce nothing (impl-guide §3,§6).
          { mode = { type = "string", default = "shadow",
              one_of = { "shadow", "enforce" } } },

          -- Credential carriage (FR-1): header token and/or mTLS client cert.
          { credential_header = { type = "string", default = "X-AgentCert-Token" } },
          { use_mtls_client_cert = { type = "boolean", default = false } },

          -- TrustScore/verdict cache TTL to stay inside the latency budget (FR-9/NFR-1).
          { cache_ttl = { type = "number", default = 300 } },

          -- Backend-unreachable policy (NFR-2). Default closed for regulated env.
          { fail_mode = { type = "string", default = "closed",
              one_of = { "open", "closed" } } },

          -- In ENFORCE mode, the customer's own policy: which verdicts to block.
          -- TAG never blocks in shadow mode and never invents a policy (FR-14) —
          -- this list is the customer's explicit choice.
          { block_on = { type = "array", elements = { type = "string" },
              default = {} } },
          { block_status = { type = "number", default = 403 } },
        },
      },
    },
  },
}
