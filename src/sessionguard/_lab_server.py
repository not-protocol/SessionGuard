"""Standalone entry point for the SessionGuard lab's local test server.

Launched as a detached background process by `sessionguard lab start`
(see commands/lab.py) — not meant to be imported or run directly.
"""
import argparse
from http.server import ThreadingHTTPServer

from sessionguard.lab_handler import LabHandler


def main() -> None:
    parser = argparse.ArgumentParser(description="SessionGuard lab server (internal)")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), LabHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
