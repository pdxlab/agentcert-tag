"""MCP Trust Proxy benchmark — measures the trust tax.

Stands up a mock MCP upstream and the real proxy (shadow mode), then drives four
scenarios concurrently and reports p50/p95/p99 latency, throughput, and the
per-request overhead the proxy adds versus talking to the upstream directly:

  direct              client -> mock                      (baseline)
  proxy_relay         client -> proxy -> mock, non-tools  (pure plumbing)
  proxy_call_nocert   client -> proxy -> mock, tools/call, no credential
  proxy_call_cert     client -> proxy -> mock, tools/call, full AgentCert verify

Usage:  python bench.py [--requests N] [--concurrency C]
Everything is stdlib + cryptography (already a dep). Numbers are machine-relative;
run it on the target hardware and publish alongside CPU/OS.
"""
import argparse
import base64
import datetime
import json
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PROXY = os.path.join(HERE, "..", "mcp_trust_proxy.py")
MOCK = os.path.join(HERE, "mock_mcp_server.py")
AGENT = "ans://bench/agent/prod"


# ── fixture: a real AgentCert chain + anchors + score seed ──────────────────
def _fixture():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    def sign(cn, subkey, issuer, ikey, ca, days, uri=None):
        now = datetime.datetime.now(datetime.timezone.utc)
        b = (x509.CertificateBuilder()
             .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
             .issuer_name(issuer.subject if issuer else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
             .public_key(subkey).serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(days=1))
             .not_valid_after(now + datetime.timedelta(days=days))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True))
        if uri:
            b = b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), False)
        return b.sign(ikey, hashes.SHA256())

    rk = ec.generate_private_key(ec.SECP256R1())
    root = sign("Root", rk.public_key(), None, rk, True, 3650)
    ik = ec.generate_private_key(ec.SECP256R1())
    issuing = sign("Issuing", ik.public_key(), root, rk, True, 1825)
    lk = ec.generate_private_key(ec.SECP256R1())
    leaf = sign(AGENT, lk.public_key(), issuing, ik, False, 90, uri=AGENT)
    d = tempfile.mkdtemp()
    apath = os.path.join(d, "anchors.pem")
    with open(apath, "wb") as fh:
        for c in (root, issuing):
            fh.write(c.public_bytes(serialization.Encoding.PEM))
    leaf_b64 = base64.b64encode(leaf.public_bytes(serialization.Encoding.PEM)).decode()
    return apath, leaf_b64


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def _wait(url, tries=100):
    for _ in range(tries):
        try:
            urllib.request.urlopen(url, timeout=1).read(); return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError(f"service not up: {url}")


def _call(url, body, headers):
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        r.read()


def _run(url, body, headers, requests, concurrency):
    per = requests // concurrency
    lat, lock = [], threading.Lock()

    def worker():
        local = []
        for _ in range(per):
            t = time.perf_counter()
            _call(url, body, headers)
            local.append((time.perf_counter() - t) * 1000.0)
        with lock:
            lat.extend(local)

    ths = [threading.Thread(target=worker) for _ in range(concurrency)]
    t0 = time.perf_counter()
    for th in ths: th.start()
    for th in ths: th.join()
    wall = time.perf_counter() - t0
    lat.sort()
    pct = lambda p: lat[min(len(lat) - 1, int(len(lat) * p))]
    return {"p50": statistics.median(lat), "p95": pct(0.95), "p99": pct(0.99),
            "mean": statistics.fmean(lat), "rps": len(lat) / wall, "n": len(lat)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", type=int, default=4000)
    ap.add_argument("--concurrency", type=int, default=16)
    args = ap.parse_args()

    apath, leaf_b64 = _fixture()
    mock_port, proxy_port = _free_port(), _free_port()

    env_mock = dict(os.environ, MOCK_PORT=str(mock_port))
    mock = subprocess.Popen([sys.executable, MOCK], env=env_mock,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    env_proxy = dict(os.environ, MCP_PROXY_PORT=str(proxy_port), TAG_MODE="shadow",
                     TAG_ANCHORS_PEM=apath, MCP_PROXY_UPSTREAM=f"http://127.0.0.1:{mock_port}/")
    proxy = subprocess.Popen([sys.executable, PROXY], env=env_proxy,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait(f"http://127.0.0.1:{mock_port}/", tries=50) if False else None
        _wait(f"http://127.0.0.1:{proxy_port}/healthz")
        # mock has no healthz; a direct POST proves it's up
        direct_url = f"http://127.0.0.1:{mock_port}/"
        proxy_url = f"http://127.0.0.1:{proxy_port}/"
        _wait_post(direct_url)

        jh = {"Content-Type": "application/json"}
        call = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "echo", "arguments": {"msg": "hi"}}}).encode()
        ping = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
        cert_h = dict(jh, **{"x-agentcert-token": leaf_b64, "x-agentcert-carriage": "mtls"})

        scen = [
            ("direct", direct_url, call, jh),
            ("proxy_relay", proxy_url, ping, jh),
            ("proxy_call_nocert", proxy_url, call, jh),
            ("proxy_call_cert", proxy_url, call, cert_h),
        ]
        # warmup
        for _, u, b, h in scen:
            for _ in range(50): _call(u, b, h)

        results = {}
        for name, u, b, h in scen:
            results[name] = _run(u, b, h, args.requests, args.concurrency)

        base = results["direct"]["p50"]
        print(f"\nMCP Trust Proxy benchmark — {args.requests} req × {args.concurrency} conc, shadow mode\n")
        print(f"| scenario | p50 ms | p95 ms | p99 ms | RPS | added p50 |")
        print(f"|---|---|---|---|---|---|")
        for name, _u, _b, _h in scen:
            r = results[name]
            add = "—" if name == "direct" else f"+{r['p50'] - base:.3f} ms"
            print(f"| {name} | {r['p50']:.3f} | {r['p95']:.3f} | {r['p99']:.3f} | {r['rps']:.0f} | {add} |")
        print()
        print(json.dumps({k: {m: round(v, 4) for m, v in r.items()} for k, r in results.items()}))
    finally:
        proxy.terminate(); mock.terminate()
        proxy.wait(timeout=5); mock.wait(timeout=5)


def _wait_post(url, tries=50):
    body = json.dumps({"jsonrpc": "2.0", "id": 0, "method": "ping"}).encode()
    for _ in range(tries):
        try:
            _call(url, body, {"Content-Type": "application/json"}); return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError(f"mock not up: {url}")


if __name__ == "__main__":
    main()
