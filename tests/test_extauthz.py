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

import pytest
from agentcert_tag.pop import build_assertion
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
    anchors, leaf, leaf_key = _pki(agent=AGENT, score=None)
    ad = tempfile.mkdtemp()
    apath = os.path.join(ad, "anchors.pem")
    with open(apath, "w") as fh:
        fh.write("".join(anchors))
    spath = os.path.join(ad, "seed.json")
    with open(spath, "w") as fh:
        json.dump({AGENT: score}, fh)
    leaf_b64 = base64.b64encode(_pem(leaf)).decode()
    return apath, spath, leaf_b64, leaf_key


@contextlib.contextmanager
def _server(extra_env):
    proof_audience = extra_env.pop("_proof_audience", "test-gateway")
    apath, spath, leaf_b64, leaf_key = _fixture(score=extra_env.pop("_score", 812))
    port = _free_port()
    env = dict(os.environ)
    env.update({"TAG_ANCHORS_PEM": apath, "TAG_SANDBOX_SEED": spath,
                "TAG_PORT": str(port), "TAG_POP_AUDIENCE": "test-gateway"})
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
        yield base, {"x-agent-cert": leaf_b64, "x-agent-cert-proof": json.dumps(build_assertion(leaf_key, AGENT, audience=proof_audience))}
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def _call(base, headers=None, path="/ext_authz", method="GET"):
    """Returns (status_code, headers_dict). Never raises on 403."""
    req = urllib.request.Request(base + path, headers=headers or {}, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=3)
        return r.status, {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}


def test_enforce_verified_allows():
    with _server({"TAG_MODE": "enforce"}) as (base, leaf):
        code, h = _call(base, leaf)
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
        code, h = _call(base, leaf)
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


@pytest.mark.parametrize("method", ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CUSTOM"])
def test_envoy_prefixed_path_and_methods(method):
    with _server({"TAG_MODE": "enforce"}) as (base, headers):
        assert _call(base, headers, path="/ext_authz/orders/123?include=details", method=method)[0] == 200
        assert _call(base, {}, path="/ext_authz/orders/123", method=method)[0] == 403
        assert _call(base, headers, path="/ext_authz_other", method=method)[0] == 404


def test_caller_cannot_claim_mtls_to_skip_possession():
    with _server({"TAG_MODE": "enforce"}) as (base, headers):
        headers.pop("x-agent-cert-proof")
        headers["x-agent-cert-carriage"] = "mtls"
        assert _call(base, headers)[0] == 403


@pytest.mark.parametrize("proof", ["not-json", "[]", '"string"', '{"payload":"bad","sig":"bad"}'])
def test_bad_proof_is_denied_even_in_fail_open(proof):
    with _server({"TAG_MODE": "enforce", "TAG_FAIL_MODE": "open"}) as (base, headers):
        headers["x-agent-cert-proof"] = proof
        assert _call(base, headers)[0] == 403


def test_bad_base64_is_denied_even_in_fail_open():
    with _server({"TAG_MODE": "enforce", "TAG_FAIL_MODE": "open"}) as (base, headers):
        headers["x-agent-cert"] = "not-valid-base64!"
        assert _call(base, headers)[0] == 403


def test_operator_audience_cannot_be_overridden_by_caller():
    with _server({"TAG_MODE": "enforce", "TAG_POP_AUDIENCE": "different-gateway"}) as (base, headers):
        headers["x-agent-cert-audience"] = "test-gateway"
        assert _call(base, headers)[0] == 403
    with _server({"TAG_MODE": "enforce", "TAG_POP_AUDIENCE": "test-gateway"}) as (base, headers):
        assert _call(base, headers)[0] == 200


@pytest.mark.parametrize("claims", [[], None, "text", 42])
def test_non_object_signed_payload_cannot_trigger_fail_open(claims):
    with _server({"TAG_MODE": "enforce", "TAG_FAIL_MODE": "open"}) as (base, headers):
        headers["x-agent-cert-proof"] = json.dumps({
            "payload": base64.urlsafe_b64encode(json.dumps(claims).encode()).decode(),
            "sig": base64.b64encode(b"invalid").decode(),
        })
        assert _call(base, headers)[0] == 403


@pytest.mark.parametrize("audience", [None, "", "   "])
def test_enforce_refuses_startup_without_audience(audience):
    env = dict(os.environ, TAG_MODE="enforce")
    env.pop("TAG_POP_AUDIENCE", None)
    if audience is not None:
        env["TAG_POP_AUDIENCE"] = audience
    result = subprocess.run([sys.executable, SERVER], env=env,
                            capture_output=True, text=True, timeout=5)
    assert result.returncode != 0
    assert "TAG_POP_AUDIENCE must be non-empty in enforce mode" in result.stderr


def test_shadow_still_starts_without_audience():
    with _server({"TAG_MODE": "shadow", "TAG_POP_AUDIENCE": ""}) as (base, headers):
        assert _call(base, headers)[0] == 200


def test_shadow_warns_about_unbound_audience():
    env = dict(os.environ, TAG_MODE="shadow")
    env.pop("TAG_POP_AUDIENCE", None)
    env.pop("TAG_ANCHORS_PEM", None)
    result = subprocess.run([sys.executable, SERVER], env=env,
                            capture_output=True, text=True, timeout=5)
    assert "WARNING: TAG_POP_AUDIENCE is unset" in result.stderr
    # Startup continues past the audience check to the separate anchor check.
    assert "TAG_ANCHORS_PEM must point" in result.stderr


def test_enforce_rejects_signed_proof_without_audience():
    with _server({"TAG_MODE": "enforce", "_proof_audience": None}) as (base, headers):
        assert _call(base, headers)[0] == 403
