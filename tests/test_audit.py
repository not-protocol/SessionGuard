"""Tests for the `audit` command. Patches requests.get (as used inside
engine.py) so these run with no real network access."""
import json
from unittest.mock import patch

from click.testing import CliRunner

from sessionguard.commands.audit import audit


class FakeHeaders:
    def __init__(self, cookies=None):
        self._cookies = cookies or []

    def getlist(self, key):
        return self._cookies if key == "Set-Cookie" else []


class FakeRaw:
    def __init__(self, cookies=None):
        self.headers = FakeHeaders(cookies)


class FakeResponse:
    def __init__(self, url, cookies=None, text="", headers=None):
        self.url = url
        self.raw = FakeRaw(cookies)
        self.text = text
        self.headers = headers or {}


def _fake_get(url, timeout=10, allow_redirects=True):
    return FakeResponse(
        url,
        cookies=["session=e1f8a3c6d9b2f47a08c5e6d1a9f3b7c2e4d6f8a1; Secure; HttpOnly; SameSite=Strict"],
    )


def _write_targets(text):
    with open("targets.yaml", "w") as f:
        f.write(text)


def test_audit_missing_file_errors():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(audit, ["--targets", "nope.yaml"])
        assert result.exit_code != 0
        assert "No targets file" in result.output


def test_audit_empty_file_errors():
    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_targets("targets: []\n")
        result = runner.invoke(audit, [])
        assert result.exit_code != 0
        assert "no entries" in result.output


def test_audit_runs_all_targets():
    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_targets(
            "targets:\n"
            "  - name: A\n    url: https://a.test\n"
            "  - name: B\n    url: https://b.test\n"
        )
        with patch("sessionguard.engine.requests.get", side_effect=_fake_get):
            result = runner.invoke(audit, [])

        assert result.exit_code == 0
        assert "a.test" in result.output
        assert "b.test" in result.output


def test_audit_json_format():
    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_targets("targets:\n  - name: A\n    url: https://a.test\n")
        with patch("sessionguard.engine.requests.get", side_effect=_fake_get):
            result = runner.invoke(audit, ["--format", "json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data[0]["target"] == "https://a.test"


def test_audit_skips_unreachable_targets():
    import requests

    def _flaky_get(url, timeout=10, allow_redirects=True):
        if "down" in url:
            raise requests.RequestException("connection refused")
        return _fake_get(url, timeout, allow_redirects)

    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_targets(
            "targets:\n"
            "  - name: Down\n    url: https://down.test\n"
            "  - name: Up\n    url: https://up.test\n"
        )
        with patch("sessionguard.engine.requests.get", side_effect=_flaky_get):
            result = runner.invoke(audit, [])

        assert result.exit_code == 0
        assert "up.test" in result.output
