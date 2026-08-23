"""Cookie security checks (Secure / HttpOnly / SameSite / lifetime).

Takes a response-like object (needs .url and .raw.headers.getlist) rather
than a strict requests.Response type, so it stays easy to unit test with a
fake — see tests/test_cookies.py.
"""
from sessionguard.models import ScanResult, Severity


def _parse_set_cookie(raw: str) -> dict:
    """Parse a single raw Set-Cookie header into its name, value, and
    attributes. 'value' is exposed (in addition to the original fields)
    so other checks — e.g. checks/entropy.py — can inspect it without
    re-parsing the header themselves.
    """
    parts = [p.strip() for p in raw.split(";")]
    name_value = parts[0]
    if "=" in name_value:
        name, value = name_value.split("=", 1)
    else:
        name, value = name_value, ""

    attrs = {
        "secure": False,
        "httponly": False,
        "samesite": None,
        "expires": None,
        "max_age": None,
    }
    for part in parts[1:]:
        lower = part.lower()
        if lower == "secure":
            attrs["secure"] = True
        elif lower == "httponly":
            attrs["httponly"] = True
        elif lower.startswith("samesite="):
            attrs["samesite"] = part.split("=", 1)[1]
        elif lower.startswith("expires="):
            attrs["expires"] = part.split("=", 1)[1]
        elif lower.startswith("max-age="):
            attrs["max_age"] = part.split("=", 1)[1]

    return {"name": name, "value": value, **attrs}


def check_cookies(response, result: ScanResult) -> None:
    """Inspect every Set-Cookie header on a response and record findings.

    NOTE: only inspects the final response's headers. If a redirect chain
    sets cookies along the way, those live in response.history and aren't
    checked yet — worth adding once `audit` is wired up.
    """
    raw_cookies = response.raw.headers.getlist("Set-Cookie")

    if not raw_cookies:
        result.add("cookies", Severity.INFO, "No cookies set on this response", passed=True)
        return

    is_https = response.url.startswith("https://")

    for raw in raw_cookies:
        cookie = _parse_set_cookie(raw)
        name = cookie["name"]

        if is_https and not cookie["secure"]:
            result.add(
                "cookie-secure-flag", Severity.HIGH,
                f"Cookie '{name}' is missing the Secure flag on an HTTPS site",
                passed=False,
            )
        else:
            result.add("cookie-secure-flag", Severity.INFO,
                        f"Cookie '{name}' Secure flag OK", passed=True)

        if not cookie["httponly"]:
            result.add(
                "cookie-httponly-flag", Severity.MEDIUM,
                f"Cookie '{name}' is missing HttpOnly — readable by JavaScript",
                passed=False,
            )
        else:
            result.add("cookie-httponly-flag", Severity.INFO,
                        f"Cookie '{name}' HttpOnly flag OK", passed=True)

        if cookie["samesite"] is None:
            result.add(
                "cookie-samesite", Severity.MEDIUM,
                f"Cookie '{name}' has no SameSite attribute (browser defaults vary)",
                passed=False,
            )
        elif cookie["samesite"].lower() == "none" and not cookie["secure"]:
            result.add(
                "cookie-samesite", Severity.HIGH,
                f"Cookie '{name}' uses SameSite=None without Secure",
                passed=False,
            )
        else:
            result.add("cookie-samesite", Severity.INFO,
                        f"Cookie '{name}' SameSite={cookie['samesite']}", passed=True)

        if cookie["expires"] is None and cookie["max_age"] is None:
            result.add("cookie-lifetime", Severity.INFO,
                        f"Cookie '{name}' is a session cookie (no persistent expiry)",
                        passed=True)
