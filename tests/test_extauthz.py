"""Integration tests for the sidecar's ext_authz-native endpoint (/ext_authz).

Launches the real sidecar as a subprocess (as a gateway would run it) and drives
it over HTTP, asserting the allow(200)/deny(403) decision and the x-agentcert-*
verdict headers across enforce, min-score, and shadow modes.
"""
import base64
import contextlib
import os
import socket
import subprocess
import sys
import tempfile
import time
import json
import urllib.error
import urllib.request

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "core"))

from test_verify import _pki, _pem  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

SERVER = os.path.join(HERE, "..", "sidecar", "server.py")
AGENT = "ans://acme/agent/prod"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _fixture(score=812):
    anchors, leaf, _lk = _pki(agent=AGENT, score=None)
    ad = tempfile.mkdtemp()
    apath = os.path.join(ad, "anchors.pem")
    with open(apath, "w") as fh:
        fh.write("".join(anchors))
    spath = os.path.join(ad, "seed.json")
    with open(spath, "w") as fh:
        json.dump({AGENT: score}, fh)
    leaf_b64 = base64.b64encode(_pem(leaf)).decode()
    return apath, spath, leaf_b64


@contextlib.contextmanager
def _server(extra_env):
    apath, spath, leaf_b64 = _fixture(score=extra_env.pop("_score", 812))
    port = _free_port()
    env = dict(os.environ)
    env.update({"TAG_ANCHORS_PEM": apath, "TAG_SANDBOX_SEED": spath,
                "TAG_PORT": str(port)})
    env.update(extra_env)
    proc = subprocess.Popen([sys.executable, SERVER], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(base + "/healthz", timeout=1).read()
                break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("sidecar did not come up")
        yield base, leaf_b64
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def _call(base, headers=None):
    """Returns (status_code, headers_dict). Never raises on 403."""
    req = urllib.request.Request(base + "/ext_authz", headers=headers or {})
    try:
        r = urllib.request.urlopen(req, timeout=3)
        return r.status, {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}


def test_enforce_verified_allows():
    with _server({"TAG_MODE": "enforce"}) as (base, leaf):
        code, h = _call(base, {"x-agent-cert": leaf, "x-agent-cert-carriage": "mtls"})
        assert code == 200
        assert h["x-agentcert-verdict"] == "VERIFIED"
        assert h["x-agentcert-decision"] == "allow"
        assert h["x-agentcert-agent-id"] == AGENT
        assert h["x-agentcert-trustscore"] == "812"


def test_enforce_no_cert_denies():
    with _server({"TAG_MODE": "enforce"}) as (base, _leaf):
        code, h = _call(base, {})
        assert code == 403
        assert h["x-agentcert-verdict"] == "UNVERIFIED"
        assert h["x-agentcert-decision"] == "deny"


def test_enforce_garbage_denies():
    with _server({"TAG_MODE": "enforce"}) as (base, _leaf):
        junk = base64.b64encode(b"-----BEGIN CERTIFICATE-----\nxx\n-----END CERTIFICATE-----\n").decode()
        code, h = _call(base, {"x-agent-cert": junk, "x-agent-cert-carriage": "mtls"})
        assert code == 403
        assert h["x-agentcert-decision"] == "deny"


def test_enforce_min_score_below_denies():
    # Verified chain but score 812 < TAG_MIN_SCORE 900 -> deny.
    with _server({"TAG_MODE": "enforce", "TAG_MIN_SCORE": "900"}) as (base, leaf):
        code, h = _call(base, {"x-agent-cert": leaf, "x-agent-cert-carriage": "mtls"})
        assert code == 403
        assert h["x-agentcert-verdict"] == "VERIFIED"
        assert h["x-agentcert-decision"] == "deny"


def test_shadow_never_blocks_but_reports():
    with _server({"TAG_MODE": "shadow"}) as (base, _leaf):
        # No credential: shadow allows (200) but flags what enforce would do.
        code, h = _call(base, {})
        assert code == 200
        assert h["x-agentcert-decision"] == "allow"
        assert h["x-agentcert-shadow-would"] == "deny"
