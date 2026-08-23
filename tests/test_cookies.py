"""Tests for cookie security checks. Uses a fake response object so these
run with no network at all."""
from sessionguard.checks.cookies import _parse_set_cookie, check_cookies
from sessionguard.models import ScanResult


class FakeHeaders:
    def __init__(self, set_cookies):
        self._set_cookies = set_cookies

    def getlist(self, key):
        return self._set_cookies if key == "Set-Cookie" else []


class FakeRaw:
    def __init__(self, set_cookies):
        self.headers = FakeHeaders(set_cookies)


class FakeResponse:
    def __init__(self, url, set_cookies):
        self.url = url
        self.raw = FakeRaw(set_cookies)


def test_parse_set_cookie_flags():
    cookie = _parse_set_cookie("session=abc123; Secure; HttpOnly; SameSite=Strict")
    assert cookie["name"] == "session"
    assert cookie["secure"] is True
    assert cookie["httponly"] is True
    assert cookie["samesite"] == "Strict"


def test_missing_secure_flag_flagged_on_https():
    response = FakeResponse("https://example.test", ["session=abc123; HttpOnly"])
    result = ScanResult(target="https://example.test")
    check_cookies(response, result)
    assert "cookie-secure-flag" in [f.check for f in result.failed]


def test_missing_samesite_flagged():
    response = FakeResponse("https://example.test", ["session=abc123; Secure; HttpOnly"])
    result = ScanResult(target="https://example.test")
    check_cookies(response, result)
    assert "cookie-samesite" in [f.check for f in result.failed]


def test_full_flags_pass():
    response = FakeResponse(
        "https://example.test",
        ["session=abc123; Secure; HttpOnly; SameSite=Strict"],
    )
    result = ScanResult(target="https://example.test")
    check_cookies(response, result)
    assert result.failed == []


def test_no_cookies_is_informational_only():
    response = FakeResponse("https://example.test", [])
    result = ScanResult(target="https://example.test")
    check_cookies(response, result)
    assert result.failed == []
