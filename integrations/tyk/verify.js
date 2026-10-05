// TAG — AgentCert + TrustScore verification as a Tyk custom-auth middleware.
//
// This is the "middleware plugin" path the Tyk maintainer pointed at in
// TykTechnologies/tyk#8732. It's a thin caller: the JSVM hook forwards the
// agent's cert headers to the TAG verify sidecar (/ext_authz) via
// TykMakeHttpRequest, allows on 200, and injects the x-agentcert-* verdict for
// downstream. All crypto (chain + revocation + score) lives in the sidecar.
//
// Shadow-mode by default: run the sidecar with TAG_MODE=shadow and /ext_authz
// returns 200 (allow) on every request, so this blocks nothing until you flip
// TAG_MODE=enforce on the sidecar.
//
// Reference example — validate the JSVM return convention against your Tyk
// version (see Tyk custom-auth JS docs).

function agentCertAuthCheck(request, session, config) {
  var verifyReq = {
    "Method": "GET",
    "Domain": "http://tag-sidecar:8080",
    "Resource": "/ext_authz",
    "Headers": {
      "x-agent-cert": request.Headers["X-Agent-Cert"] || "",
      "x-agent-cert-proof": request.Headers["X-Agent-Cert-Proof"] || "",
      "x-agent-cert-carriage": request.Headers["X-Agent-Cert-Carriage"] || "header",
      "x-agent-id": request.Headers["X-Agent-Id"] || ""
    }
  };

  var resp = JSON.parse(TykMakeHttpRequest(JSON.stringify(verifyReq)));
  var verdict = (resp.Headers && resp.Headers["X-Agentcert-Verdict"]) || "UNVERIFIED";

  // Non-200 = deny. In shadow mode the sidecar returns 200 regardless, so this
  // branch only fires under TAG_MODE=enforce.
  if (resp.Code !== 200) {
    request.ReturnOverrides.ResponseCode = 403;
    request.ReturnOverrides.ResponseError = "agent-trust: " + verdict;
    return TykJsResponse({ Request: request }, session.meta_data);
  }

  // Allow — inject the verdict for downstream services and open a session.
  request.SetHeaders["x-agentcert-verdict"] = verdict;
  if (resp.Headers) {
    request.SetHeaders["x-agentcert-agent-id"] = resp.Headers["X-Agentcert-Agent-Id"] || "";
    request.SetHeaders["x-agentcert-trustscore"] = resp.Headers["X-Agentcert-Trustscore"] || "";
    request.SetHeaders["x-agentcert-tier"] = resp.Headers["X-Agentcert-Tier"] || "";
  }

  session.id_extractor_deadline = 0;
  return TykJsResponse(
    {
      Request: request,
      Session: { allowance: 1000, rate: 1000, per: 60 },
      AuthValue: (resp.Headers && resp.Headers["X-Agentcert-Agent-Id"]) || "agent"
    },
    session.meta_data
  );
}
