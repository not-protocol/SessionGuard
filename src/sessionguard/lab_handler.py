"""HTTP handler for the SessionGuard lab's local, synthetic test target.

This is the actual implementation of the "disposable browser profile
with synthetic cookies" idea from the roadmap: rather than needing a
real account anywhere, SessionGuard can spin up a small HTTP server on
127.0.0.1 that emits its own fake cookies (a mix of good and bad
configurations) and a fake leaked token, purely so `scan`/`audit` have
something safe and realistic to point at.

This never reads from, writes to, or otherwise touches a real browser
profile, a real website, or a real account — every byte this server
returns is generated right here.
"""
from http.server import BaseHTTPRequestHandler

# A long, high-entropy value — deliberately NOT a short/simple demo string,
# so the "good" route can pass every check SessionGuard runs, including
# the token-entropy heuristic.
_GOOD_SESSION_VALUE = "e1f8a3c6d9b2f47a08c5e6d1a9f3b7c2e4d6f8a1"

_FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJsYWIiLCJuYW1lIjoiU2Vzc2lvbkd1YXJkIExhYiJ9."
    "ZmFrZS1zaWduYXR1cmUtZm9yLXRlc3Rpbmctb25seQ"
)

ROUTES_HELP = (
    "  /               a fully-correct cookie (Secure; HttpOnly; SameSite=Strict)\n"
    "  /insecure       a cookie missing Secure and HttpOnly\n"
    "  /samesite-none  SameSite=None without Secure\n"
    "  /leaky-token    a fake JWT-shaped token embedded in the page body\n"
    "  (append e.g. ?access_token=demo123 to any route to see the "
    "token-in-url check fire)"
)

_PAGE = "<html><body><h1>SessionGuard Lab</h1><p>Synthetic test page — not a real site.</p></body></html>"


class LabHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quiet the default stderr access log
        pass

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/insecure":
            self._serve_cookie("lab_session=insecure-demo-value")
        elif path == "/samesite-none":
            self._serve_cookie(f"lab_session={_GOOD_SESSION_VALUE}; SameSite=None")
        elif path == "/leaky-token":
            self._serve_leaky_token()
        else:
            self._serve_cookie(
                f"lab_session={_GOOD_SESSION_VALUE}; Secure; HttpOnly; SameSite=Strict"
            )

    def _serve_cookie(self, set_cookie_value: str) -> None:
        body = _PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", set_cookie_value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_leaky_token(self) -> None:
        body = (
            f"<html><body><h1>SessionGuard Lab</h1>"
            f"<script>var token='{_FAKE_JWT}';</script></body></html>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
