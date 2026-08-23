"""Tests for HTTPS enforcement / HSTS checks."""
from sessionguard.checks.https import check_https
from sessionguard.models import ScanResult


class FakeResponse:
    def __init__(self, url, headers=None):
        self.url = url
        self.headers = headers or {}


def test_https_requested_directly_passes():
    result = ScanResult(target="https://example.test")
    check_https("https://example.test", FakeResponse("https://example.test"), result)
    assert "https-enforcement" not in [f.check for f in result.failed]


def test_http_redirected_to_https_passes():
    result = ScanResult(target="http://example.test")
    check_https("http://example.test", FakeResponse("https://example.test"), result)
    assert "https-enforcement" not in [f.check for f in result.failed]


def test_http_without_redirect_fails():
    result = ScanResult(target="http://example.test")
    check_https("http://example.test", FakeResponse("http://example.test"), result)
    assert "https-enforcement" in [f.check for f in result.failed]


def test_hsts_present_passes():
    result = ScanResult(target="https://example.test")
    response = FakeResponse("https://example.test", {"Strict-Transport-Security": "max-age=31536000"})
    check_https("https://example.test", response, result)
    assert "hsts-header" not in [f.check for f in result.failed]


def test_hsts_missing_flagged():
    result = ScanResult(target="https://example.test")
    response = FakeResponse("https://example.test", {})
    check_https("https://example.test", response, result)
    assert "hsts-header" in [f.check for f in result.failed]
