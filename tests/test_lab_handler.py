"""Tests for the lab's synthetic HTTP server. Runs a real (but ephemeral,
localhost-only) server thread — no Playwright and no external network
needed, since the server itself is the whole point of the lab.
"""
import threading
from http.server import ThreadingHTTPServer

import pytest
import requests

from sessionguard.engine import run_scan
from sessionguard.lab_handler import LabHandler


@pytest.fixture
def lab_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    thread.join(timeout=2)


def test_root_sets_good_cookie(lab_server):
    response = requests.get(lab_server + "/")
    assert "Secure" in response.headers.get("Set-Cookie", "")


def test_insecure_route_missing_flags(lab_server):
    response = requests.get(lab_server + "/insecure")
    cookie = response.headers.get("Set-Cookie", "")
    assert "Secure" not in cookie


def test_leaky_token_route_embeds_jwt(lab_server):
    response = requests.get(lab_server + "/leaky-token")
    assert "eyJ" in response.text


def test_scan_engine_against_good_route_is_clean(lab_server):
    """The only expected failure on plain local HTTP is https-enforcement
    (there's no TLS on a localhost demo server) — every cookie, entropy,
    and exposure check should pass."""
    result = run_scan(lab_server + "/")
    non_https_failures = [f.check for f in result.failed if f.check != "https-enforcement"]
    assert non_https_failures == []


def test_scan_engine_against_insecure_route_flags_cookie(lab_server):
    # The lab server is plain HTTP by design (it also demonstrates the
    # https-enforcement failure), so cookie-secure-flag — which only
    # fires for a cookie missing Secure on an HTTPS target — correctly
    # doesn't apply here. httponly and samesite still do.
    result = run_scan(lab_server + "/insecure")
    assert "cookie-httponly-flag" in [f.check for f in result.failed]
    assert "cookie-samesite" in [f.check for f in result.failed]


def test_scan_engine_against_samesite_none_route_flags_samesite(lab_server):
    result = run_scan(lab_server + "/samesite-none")
    assert "cookie-samesite" in [f.check for f in result.failed]


def test_scan_engine_against_leaky_token_route_flags_exposure(lab_server):
    result = run_scan(lab_server + "/leaky-token")
    assert "exposed-jwt-in-body" in [f.check for f in result.failed]


def test_scan_engine_flags_token_in_query_string(lab_server):
    result = run_scan(lab_server + "/?access_token=demo123")
    assert "token-in-url" in [f.check for f in result.failed]
