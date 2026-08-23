"""Tests for the session-token entropy heuristic."""
from sessionguard.checks.entropy import check_token_entropy
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
    def __init__(self, set_cookies):
        self.raw = FakeRaw(set_cookies)


def test_low_entropy_session_cookie_flagged():
    response = FakeResponse(["session=abc123"])
    result = ScanResult(target="https://example.test")
    check_token_entropy(response, result)
    assert "token-entropy" in [f.check for f in result.failed]


def test_high_entropy_session_cookie_passes():
    response = FakeResponse(["session=e1f8a3c6d9b2f47a08c5e6d1a9f3b7c2e4d6f8a1"])
    result = ScanResult(target="https://example.test")
    check_token_entropy(response, result)
    assert "token-entropy" not in [f.check for f in result.failed]


def test_non_session_cookie_not_checked():
    response = FakeResponse(["theme=dark"])
    result = ScanResult(target="https://example.test")
    check_token_entropy(response, result)
    assert result.failed == []


def test_no_cookies_is_informational_only():
    response = FakeResponse([])
    result = ScanResult(target="https://example.test")
    check_token_entropy(response, result)
    assert result.failed == []
