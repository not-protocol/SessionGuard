"""`sessionguard lab` — manage a disposable, local-only test target with
synthetic, mixed-quality cookies, so `scan`/`audit` can be exercised
safely with no real account or website involved.

'start' launches a small HTTP server bound to 127.0.0.1 as a detached
background process (see _lab_server.py / lab_handler.py) — SessionGuard
generates every byte it serves itself. The --browser option is purely
cosmetic: if set, it also opens that local page in a disposable
Playwright browser context (never your real browser profile) so you can
see it, on whichever engine(s) you choose. Nothing here reads real
browser data on Windows, macOS, or Linux — the server and the optional
preview are the entire feature.
"""
import json
import os
import platform
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import click

from sessionguard.lab_handler import ROUTES_HELP

STATE_PATH = Path(".sessionguard/lab-state.json")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _read_state():
    if not STATE_PATH.exists():
        return None
    try:
        return json.loads(STATE_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _spawn_server(port: int) -> int:
    """Launch _lab_server.py as a detached background process and return
    its PID. Detachment is handled differently per OS since POSIX and
    Windows have no common API for it."""
    cmd = [sys.executable, "-m", "sessionguard._lab_server", "--port", str(port)]
    if platform.system() == "Windows":
        creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags,
        )
    else:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
        )
    return proc.pid


def _open_in_browser(url: str, engine: str) -> None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        click.echo(
            "Playwright isn't installed, so I can't open a preview browser "
            "(the lab server itself is running fine without it). "
            "Install with: pip install 'sessionguard[lab]' && playwright install"
        )
        return

    engines = ["chromium", "firefox", "webkit"] if engine == "all" else [engine]
    with sync_playwright() as p:
        for name in engines:
            browser_type = getattr(p, name)
            browser = browser_type.launch()
            # A fresh, throwaway context every time — never the user's real profile.
            context = browser.new_context()
            page = context.new_page()
            page.goto(url)
            click.echo(f"Opened {url} in a disposable {name} instance.")
            time.sleep(1.5)
            browser.close()


@click.command()
@click.argument("action", type=click.Choice(["start", "stop", "status"]))
@click.option(
    "--browser",
    type=click.Choice(["chromium", "firefox", "webkit", "all", "none"]),
    default="none",
    help="Also preview the lab page in a disposable Playwright browser instance (optional).",
)
def lab(action: str, browser: str):
    """Manage the disposable synthetic-cookie test lab.

    Never touches a real website, account, or browser profile — every
    cookie and every page byte comes from a local server SessionGuard
    starts and controls itself.
    """
    if action == "start":
        state = _read_state()
        if state and _is_alive(state["pid"]):
            click.echo(f"Lab is already running at {state['url']}")
        else:
            port = _free_port()
            pid = _spawn_server(port)
            time.sleep(0.3)  # give the server a moment to bind the port
            url = f"http://127.0.0.1:{port}"
            STATE_PATH.parent.mkdir(exist_ok=True)
            STATE_PATH.write_text(json.dumps({"pid": pid, "port": port, "url": url}))
            click.echo(f"Lab running at {url}")
            click.echo(ROUTES_HELP)
            click.echo(f"Try: sessionguard scan {url}/insecure")

        if browser != "none":
            state = _read_state()
            _open_in_browser(state["url"], browser)

    elif action == "stop":
        state = _read_state()
        if not state or not _is_alive(state["pid"]):
            click.echo("Lab isn't running.")
        else:
            try:
                os.kill(state["pid"], signal.SIGTERM)
            except OSError:
                pass
            click.echo("Lab stopped.")
        if STATE_PATH.exists():
            STATE_PATH.unlink()

    elif action == "status":
        state = _read_state()
        if state and _is_alive(state["pid"]):
            click.echo(f"Lab running at {state['url']} (pid {state['pid']})")
        else:
            click.echo("Lab isn't running.")
