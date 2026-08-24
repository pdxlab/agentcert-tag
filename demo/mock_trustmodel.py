#!/usr/bin/env python3
"""Mock TrustModel backend for the docker-compose demo — self-contained.

Stands in for aurora-gateway's agentcert endpoints so the full Kong loop runs
offline, with NO dependency on the issuance repo (keeps agentcert-tag standalone):
  * issuing CA        POST /v1/agentcert/issue/                 (mint a demo leaf)
  * reputation API    GET  /v1/agentcert/reputation/<agent>/    (#466)
  * transparency log  GET  /v1/agentcert/transparency/<serial>/ (status)
  * anchor bundle     GET  /anchors.pem                         (root+issuing)

Real production splits issuance (mTLS + OIDC-scoped) from the read-only verify
surface; sharing one process here is a demo simplification only.
"""
import datetime
import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

OID_TRUSTSCORE = "1.3.6.1.4.1.58888.1.1"

_root_key = ec.generate_private_key(ec.SECP256R1())
_iss_key = ec.generate_private_key(ec.SECP256R1())
SCORES = {}
SERIALS = {}
REVOKED = set()


def _sign(subject, subject_key, issuer_cert, issuer_key, ca, days, agent_uri=None, score=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    b = (x509.CertificateBuilder()
         .subject_name(name)
         .issuer_name(issuer_cert.subject if issuer_cert else name)
         .public_key(subject_key)
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(minutes=1))
         .not_valid_after(now + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if agent_uri:
        b = b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(agent_uri)]),
                            critical=False)
    if score is not None:
        b = b.add_extension(x509.UnrecognizedExtension(
            x509.ObjectIdentifier(OID_TRUSTSCORE), json.dumps({"value": score}).encode()),
            critical=False)
    return b.sign(issuer_key, hashes.SHA256())


ROOT = _sign("TrustModel Demo Root CA", _root_key.public_key(), None, _root_key, True, 3650)
ISSUING = _sign("TrustModel Demo Issuing CA", _iss_key.public_key(), ROOT, _root_key, True, 1825)


def anchors_pem() -> str:
    return (ROOT.public_bytes(serialization.Encoding.PEM).decode()
            + ISSUING.public_bytes(serialization.Encoding.PEM).decode())


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj, raw=False):
        body = obj.encode() if raw else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/x-pem-file" if raw else "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/anchors.pem":
            return self._send(200, anchors_pem(), raw=True)
        if path.startswith("/v1/agentcert/reputation/"):
            agent = urllib.parse.unquote(path.split("/v1/agentcert/reputation/")[1].rstrip("/"))
            return self._send(200, {"agent_id": agent, "trust_score": SCORES.get(agent),
                                    "last_updated": None})
        if path.startswith("/v1/agentcert/transparency/"):
            serial = path.split("/v1/agentcert/transparency/")[1].rstrip("/").lower()
            status = "revoked" if serial in REVOKED else ("active" if serial in SERIALS else "unknown")
            return self._send(200, {"serial": serial, "status": status})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        n = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(n) or b"{}")
        if path == "/v1/agentcert/issue/":
            agent_uri = payload["agent_uri"]
            csr = x509.load_pem_x509_csr(payload["csr_pem"].encode())
            score = payload.get("initial_score")
            leaf = _sign(agent_uri, csr.public_key(), ISSUING, _iss_key, False, 90,
                         agent_uri=agent_uri, score=score)
            serial = format(leaf.serial_number, "x")
            SERIALS[serial.lower()] = agent_uri
            if score is not None:
                SCORES[agent_uri] = score
            return self._send(200, {"cert_pem": leaf.public_bytes(serialization.Encoding.PEM).decode(),
                                    "serial_hex": serial,
                                    "not_after": leaf.not_valid_after_utc.isoformat()})
        if path == "/v1/agentcert/revoke/":
            REVOKED.add(payload["serial_hex"].lower())
            return self._send(200, {"revoked": payload["serial_hex"]})
        self._send(404, {"error": "not found"})

    def log_message(self, *a):
        pass


def main():
    out = os.environ.get("ANCHORS_OUT", "/shared/anchors.pem")
    try:
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w") as fh:
            fh.write(anchors_pem())
    except Exception:
        pass
    port = int(os.environ.get("MOCK_PORT", "9000"))
    print(f"mock-trustmodel on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
