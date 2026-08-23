"""Tests for exposed-token/secret detection."""
from sessionguard.checks.exposure import check_exposure
from sessionguard.models import ScanResult


class FakeResponse:
    def __init__(self, url, text="", headers=None):
        self.url = url
        self.text = text
        self.headers = headers or {}


def test_clean_page_passes():
    result = ScanResult(target="https://example.test")
    check_exposure(FakeResponse("https://example.test/", "<html>hello</html>"), result)
    assert result.failed == []


def test_token_in_query_string_flagged():
    result = ScanResult(target="https://example.test")
    response = FakeResponse("https://example.test/page?access_token=abc123")
    check_exposure(response, result)
    assert "token-in-url" in [f.check for f in result.failed]


def test_jwt_in_body_flagged_and_redacted():
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abcdefghijklmnop"
    response = FakeResponse("https://example.test/", f"<script>var t='{fake_jwt}'</script>")
    result = ScanResult(target="https://example.test")
    check_exposure(response, result)
    failed = [f for f in result.failed if f.check == "exposed-jwt-in-body"]
    assert len(failed) == 1
    assert fake_jwt not in failed[0].message  # raw token must never appear
    assert "sha256:" in failed[0].message


def test_aws_key_in_body_flagged():
    response = FakeResponse("https://example.test/", "config: AKIAABCDEFGHIJKLMNOP")
    result = ScanResult(target="https://example.test")
    check_exposure(response, result)
    assert "exposed-aws-key-in-body" in [f.check for f in result.failed]


def test_generic_secret_pattern_flagged_and_redacted():
    secret = "sk_live_abcdefghijklmnopqrstuvwx"
    response = FakeResponse("https://example.test/", f'api_key: "{secret}"')
    result = ScanResult(target="https://example.test")
    check_exposure(response, result)
    failed = [f for f in result.failed if f.check == "exposed-secret-in-body"]
    assert len(failed) == 1
    assert secret not in failed[0].message


def test_secret_in_response_header_flagged():
    response = FakeResponse(
        "https://example.test/", headers={"X-Debug-Token": "AKIAABCDEFGHIJKLMNOP"}
    )
    result = ScanResult(target="https://example.test")
    check_exposure(response, result)
    assert "exposed-secret-in-headers" in [f.check for f in result.failed]
