"""Coarse session-token entropy heuristic.

The project's design doc calls out "session token with <64-bit
randomness" as a rule worth flagging. This estimates Shannon entropy on
cookie VALUES that look like session/auth identifiers by name — it's a
heuristic signal that a value doesn't look random enough, not a
cryptographic audit, and the finding message says so.
"""
import math
from collections import Counter

from sessionguard.checks.cookies import _parse_set_cookie
from sessionguard.models import ScanResult, Severity

_ENTROPY_THRESHOLD_BITS = 64.0
_NAME_HINTS = ("session", "sess", "token", "auth", "sid", "jwt")


def _looks_like_session_token(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _NAME_HINTS)


def _shannon_entropy_bits(value: str) -> float:
    """Total estimated entropy of `value` in bits (per-character Shannon
    entropy times length) — a coarse stand-in for true randomness."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    per_char = -sum((n / length) * math.log2(n / length) for n in counts.values())
    return per_char * length


def check_token_entropy(response, result: ScanResult) -> None:
    """Flag session/auth-looking cookies whose value doesn't look random
    enough to resist guessing."""
    raw_cookies = response.raw.headers.getlist("Set-Cookie")
    checked_any = False

    for raw in raw_cookies:
        cookie = _parse_set_cookie(raw)
        name = cookie.get("name", "")
        value = cookie.get("value", "")
        if not _looks_like_session_token(name) or not value:
            continue

        checked_any = True
        bits = _shannon_entropy_bits(value)
        if bits < _ENTROPY_THRESHOLD_BITS:
            result.add(
                "token-entropy", Severity.HIGH,
                f"Cookie '{name}' value has an estimated {bits:.0f} bits of entropy "
                f"(below the {_ENTROPY_THRESHOLD_BITS:.0f}-bit heuristic) — "
                "may not be random enough for a session identifier",
                passed=False,
            )
        else:
            result.add(
                "token-entropy", Severity.INFO,
                f"Cookie '{name}' value has an estimated {bits:.0f} bits of entropy",
                passed=True,
            )

    if not checked_any:
        result.add("token-entropy", Severity.INFO,
                    "No session/token-like cookies found to check for entropy", passed=True)
