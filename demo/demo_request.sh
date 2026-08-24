#!/usr/bin/env bash
# Closed-loop demo driver (run after `docker compose up`).
#   1. mint an AgentCert for a sample agent via the mock CA (origination)
#   2. present it through Kong (X-AgentCert-Token) -> TAG verifies (consumption)
#   3. show the VERIFIED verdict + TrustScore in Kong's log and response headers
set -euo pipefail

MOCK=${MOCK:-http://localhost:9000}
KONG=${KONG:-http://localhost:8000}
AGENT="ans://pdxlab/sample-agent/production"

echo "==> 1. Issue an AgentCert (origination side, via mock CA)"
# Generate a keypair + CSR locally (the private key never leaves here).
tmp=$(mktemp -d)
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/key.pem" 2>/dev/null
# CN is cosmetic — the CA derives identity from agent_uri in the request body.
openssl req -new -key "$tmp/key.pem" -subj "/CN=agent" -out "$tmp/csr.pem" 2>/dev/null
csr=$(python3 -c "import json,sys; print(json.dumps(open('$tmp/csr.pem').read()))")
resp=$(curl -s -X POST "$MOCK/v1/agentcert/issue/" -H 'Content-Type: application/json' \
  -d "{\"agent_uri\":\"${AGENT}\",\"csr_pem\":${csr},\"initial_score\":812}")
echo "$resp" | python3 -c "import json,sys;d=json.load(sys.stdin);print('    serial',d['serial_hex'][:16]+'...')"
leaf=$(echo "$resp" | python3 -c "import json,sys;print(json.load(sys.stdin)['cert_pem'])")
token=$(printf '%s' "$leaf" | base64 | tr -d '\n')

echo "==> 2. Call through Kong presenting the cert"
curl -s -o /dev/null -D - "$KONG/get" -H "X-AgentCert-Token: ${token}" | \
  grep -i -E 'x-agentcert|HTTP/' || true

echo "==> 3. Kong log line (the aha moment):"
docker compose logs --since 10s kong 2>/dev/null | grep agentcert-tag | tail -3 || \
  echo "    (see: docker compose logs kong | grep agentcert-tag)"

rm -rf "$tmp"
