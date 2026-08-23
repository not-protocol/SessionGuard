"""Exposed-token / leaked-secret detection.

Looks for tokens or secrets leaking somewhere they shouldn't be — baked
into a URL (logged everywhere, cached, sent via Referer), hard-coded into
a response body, or sitting in a response header. Detection is purely
pattern-based (regex) against a response SessionGuard already
legitimately fetched for its own checks; nothing here reaches out to any
other system.

Redaction is mandatory: any matched value is masked with _mask() before
it's ever put in a Finding, so raw secrets never end up in terminal
output, JSON/HTML reports, or the persisted last-run file.
"""
import hashlib
import re
from urllib.parse import parse_qs, urlsplit

from sessionguard.models import ScanResult, Severity

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
_GENERIC_SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|secret|access[_-]?token|auth[_-]?token)"
    r"[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-.]{16,})[\"']"
)
_SENSITIVE_QUERY_PARAMS = {
    "token", "access_token", "id_token", "session", "sessionid", "jwt", "api_key", "apikey", "auth",
}


def _mask(value: str) -> str:
    """Redact a discovered secret: a short visible prefix/suffix plus a
    SHA-256 fingerprint, never the raw value."""
    digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]
    visible = f"{value[:3]}…{value[-3:]}" if len(value) > 6 else "…"
    return f"{visible} (sha256:{digest})"


def check_exposure(response, result: ScanResult) -> None:
    """Look for tokens/secrets leaking via the URL, response body, or headers."""
    _check_url_params(response.url, result)
    _check_body(getattr(response, "text", "") or "", result)
    _check_headers(getattr(response, "headers", {}) or {}, result)


def _check_url_params(url: str, result: ScanResult) -> None:
    query = parse_qs(urlsplit(url).query)
    leaked = sorted(p for p in query if p.lower() in _SENSITIVE_QUERY_PARAMS)
    if leaked:
        result.add(
            "token-in-url", Severity.HIGH,
            f"Sensitive-looking value(s) in the URL query string: {', '.join(leaked)} "
            "(URLs are logged, cached, and leak via Referer headers)",
            passed=False,
        )
    else:
        result.add("token-in-url", Severity.INFO,
                    "No sensitive-looking query parameters in URL", passed=True)


def _check_body(body: str, result: ScanResult) -> None:
    jwt_match = _JWT_RE.search(body)
    aws_match = _AWS_KEY_RE.search(body)
    generic_match = _GENERIC_SECRET_RE.search(body)

    if jwt_match:
        result.add(
            "exposed-jwt-in-body", Severity.HIGH,
            f"A JWT-shaped string was found in the response body: {_mask(jwt_match.group(0))}",
            passed=False,
        )
    if aws_match:
        result.add(
            "exposed-aws-key-in-body", Severity.CRITICAL,
            f"A string matching the AWS Access Key ID format was found: {_mask(aws_match.group(0))}",
            passed=False,
        )
    if generic_match:
        result.add(
            "exposed-secret-in-body", Severity.HIGH,
            f"A string matching a common API key/secret/token pattern was found: "
            f"{_mask(generic_match.group(2))}",
            passed=False,
        )
    if not (jwt_match or aws_match or generic_match):
        result.add("exposed-secret-in-body", Severity.INFO,
                    "No obvious tokens or secrets found in response body", passed=True)


def _check_headers(headers, result: ScanResult) -> None:
    suspicious = []
    for key, value in dict(headers).items():
        value = str(value)
        if _JWT_RE.search(value) or _AWS_KEY_RE.search(value) or _GENERIC_SECRET_RE.search(value):
            suspicious.append(key)
    if suspicious:
        result.add(
            "exposed-secret-in-headers", Severity.HIGH,
            f"Response header(s) contain a token/secret-shaped value: {', '.join(sorted(suspicious))}",
            passed=False,
        )
    else:
        result.add("exposed-secret-in-headers", Severity.INFO,
                    "No obvious tokens or secrets found in response headers", passed=True)
