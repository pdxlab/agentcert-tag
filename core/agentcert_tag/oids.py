"""Shared OID constants for the TrustModel AgentCert PKI.

The private enterprise arc 1.3.6.1.4.1.58888 is TrustModel's IANA PEN base
(see aurora-gateway agentcert; PEN registration tracked in TRUS-1570). The
AgentCert profile lives under .1 and mirrors the OIDs the issuance side
(agentcert-issue-action) embeds into each leaf certificate.

Keep this file byte-identical with agentcert-issue-action/core/agentcert_issue/oids.py.
"""

# Base arcs
PEN = "1.3.6.1.4.1.58888"
AGENTCERT = PEN + ".1"

# Custom certificate extensions carried on each agent leaf.
OID_TRUSTSCORE = AGENTCERT + ".1"      # numeric TrustScore, 0-1000 (JSON blob)
OID_TRUST_TIER = AGENTCERT + ".2"      # tier band: Trusted | Caution | Untrusted
OID_DIM_SUMMARY = AGENTCERT + ".3"     # 10-dimension summary (JSON blob)
OID_TRANSPARENCY_URL = AGENTCERT + ".4"  # per-cert transparency-log URL

# URI-SAN scheme that binds a leaf to its Agent Name Service identity.
ANS_URI_SCHEME = "ans"
