"""HTTPS enforcement and HSTS checks."""
from sessionguard.models import ScanResult, Severity


def check_https(url: str, response, result: ScanResult) -> None:
    started_https = url.startswith("https://")
    ended_https = response.url.startswith("https://")

    if started_https:
        result.add("https-enforcement", Severity.INFO,
                    "Target URL was requested over HTTPS", passed=True)
    elif ended_https:
        result.add("https-enforcement", Severity.INFO,
                    "HTTP request redirected to HTTPS", passed=True)
    else:
        result.add("https-enforcement", Severity.CRITICAL,
                    "Site served content over HTTP without redirecting to HTTPS",
                    passed=False)

    if ended_https:
        hsts = response.headers.get("Strict-Transport-Security")
        if hsts:
            result.add("hsts-header", Severity.INFO,
                        "Strict-Transport-Security header present", passed=True)
        else:
            result.add("hsts-header", Severity.LOW,
                        "No Strict-Transport-Security header present", passed=False)
