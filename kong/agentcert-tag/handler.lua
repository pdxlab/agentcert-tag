-- TAG — Trusted Agent Gateway (Kong plugin handler).
--
-- Turns Kong into a verifier of TrustModel AgentCert + TrustScore. It does NOT
-- replace Kong's policy engine (FR-14): it verifies the credential, exposes the
-- result at `kong.ctx.shared.trustscore` / `kong.ctx.shared.agentcert` for
-- Kong's native policy rules, sets upstream headers, and logs the decision.
--
-- Default mode is SHADOW: it decides and logs but blocks nothing — the single
-- biggest adoption lever (impl-guide §3). ENFORCE only blocks the verdicts the
-- customer explicitly listed in config.block_on.

local http = require "resty.http"
local cjson = require "cjson.safe"

local AgentCertTAG = {
  PRIORITY = 1000,   -- run after auth, before upstream
  VERSION  = "0.1.0",
}

local function extract_credential(conf)
  if conf.use_mtls_client_cert then
    local cert = kong.client.tls and kong.client.tls.get_full_client_certificate_chain
      and kong.client.tls.get_full_client_certificate_chain()
    if cert then
      return cert, "mtls"
    end
  end
  local token = kong.request.get_header(conf.credential_header)
  if token then
    return token, "header"
  end
  return nil, nil
end

-- Ask TAG's verify core for a decision. Cached by credential fingerprint so we
-- do not round-trip per request (FR-9).
local function verify(conf, credential, carriage)
  local httpc = http.new()
  httpc:set_timeout(250)  -- NFR-1 cache-miss budget
  local headers = { ["Content-Type"] = "application/json" }
  if conf.api_key then
    headers["Authorization"] = "Bearer " .. conf.api_key
  end
  local res, err = httpc:request_uri(conf.verify_url, {
    method = "POST",
    headers = headers,
    body = cjson.encode({ credential = credential, carriage = carriage }),
  })
  if not res or res.status ~= 200 then
    return nil, err or ("verify http " .. tostring(res and res.status))
  end
  return cjson.decode(res.body)
end

function AgentCertTAG:access(conf)
  local credential, carriage = extract_credential(conf)

  local result
  if not credential then
    -- FR-3: never crash the pipeline on a missing credential.
    result = { verification_status = "UNVERIFIED", cert_valid = false,
               trust_score = { value = nil, tier = "Unknown" },
               detail = "no credential presented" }
  else
    local cache_key = "agentcert:" .. ngx.md5(credential)
    local cached, err = kong.cache:get(cache_key, { ttl = conf.cache_ttl },
      verify, conf, credential, carriage)
    if err or not cached then
      -- Backend unreachable: apply fail policy (NFR-2).
      if conf.fail_mode == "closed" then
        result = { verification_status = "ERROR", cert_valid = false,
                   trust_score = { value = nil, tier = "Unknown" },
                   detail = "verify backend unreachable (fail-closed): " .. tostring(err) }
      else
        result = { verification_status = "UNVERIFIED", cert_valid = false,
                   trust_score = { value = nil, tier = "Unknown" },
                   detail = "verify backend unreachable (fail-open): " .. tostring(err) }
      end
    else
      result = cached
    end
  end

  local ts = result.trust_score or {}

  -- FR-13: expose the result to Kong's native policy engine + downstream.
  kong.ctx.shared.agentcert = result
  kong.ctx.shared.trustscore = ts.value
  kong.service.request.set_header("X-AgentCert-Status", result.verification_status or "ERROR")
  kong.service.request.set_header("X-AgentCert-Tier", ts.tier or "Unknown")
  if ts.value ~= nil then
    kong.service.request.set_header("X-AgentCert-Score", tostring(ts.value))
  end

  -- The "aha moment" log line (impl-guide §6.5) — metadata only, no payload (FR-16).
  kong.log.notice(string.format(
    "[agentcert-tag] mode=%s agent=%s status=%s score=%s tier=%s",
    conf.mode, tostring(result.agent_id), tostring(result.verification_status),
    tostring(ts.value), tostring(ts.tier)))

  -- SHADOW mode never blocks. ENFORCE blocks only customer-listed verdicts.
  if conf.mode == "enforce" and conf.block_on then
    for _, status in ipairs(conf.block_on) do
      if result.verification_status == status then
        return kong.response.exit(conf.block_status, {
          message = "AgentCert verification: " .. status,
          agent_id = result.agent_id,
          trust_score = ts.value,
        })
      end
    end
  end
end

return AgentCertTAG
