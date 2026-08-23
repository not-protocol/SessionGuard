"""Core scan engine: runs the full check suite against a single URL.

This is the one place that knows the full list of checks SessionGuard
runs. `scan` (one target) and `audit` (many targets) both call
run_scan() so the two commands can never drift out of sync with each
other about what actually gets checked.
"""
import requests

from sessionguard.checks.cookies import check_cookies
from sessionguard.checks.entropy import check_token_entropy
from sessionguard.checks.exposure import check_exposure
from sessionguard.checks.https import check_https
from sessionguard.models import ScanResult


class TargetUnreachable(Exception):
    """Raised when a target can't be reached at all (DNS failure, refused
    connection, timeout, etc.) — as opposed to a target that responds but
    fails one or more security checks."""

    def __init__(self, url: str, original: Exception):
        self.url = url
        self.original = original
        super().__init__(f"Could not reach {url}: {original}")


def run_scan(url: str, timeout: int = 10) -> ScanResult:
    """Run every check against a single URL and return its ScanResult.

    Raises TargetUnreachable if the request itself fails. Callers decide
    whether that's fatal (scan: one target, so abort) or something to
    log and continue past (audit: many targets, so keep going).
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = ScanResult(target=url)
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        raise TargetUnreachable(url, exc) from exc

    check_https(url, response, result)
    check_cookies(response, result)
    check_token_entropy(response, result)
    check_exposure(response, result)
    return result
