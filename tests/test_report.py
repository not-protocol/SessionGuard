"""Tests for the `report` command (re-rendering the last run)."""
import json

from click.testing import CliRunner

from sessionguard.commands.report import report
from sessionguard.models import ScanResult, Severity
from sessionguard.storage import save_last_run


def _sample_results():
    result = ScanResult(target="https://example.test")
    result.add("https-enforcement", Severity.INFO, "ok", passed=True)
    result.add("cookie-secure-flag", Severity.HIGH, "missing Secure", passed=False)
    return [result]


def test_report_no_previous_run_errors():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(report, [])
        assert result.exit_code != 0
        assert "No previous run" in result.output


def test_report_terminal_after_save():
    runner = CliRunner()
    with runner.isolated_filesystem():
        save_last_run(_sample_results())
        result = runner.invoke(report, [])
        assert result.exit_code == 0
        assert "example.test" in result.output


def test_report_json_format():
    runner = CliRunner()
    with runner.isolated_filesystem():
        save_last_run(_sample_results())
        result = runner.invoke(report, ["--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data[0]["target"] == "https://example.test"


def test_report_html_format_writes_file():
    runner = CliRunner()
    with runner.isolated_filesystem():
        save_last_run(_sample_results())
        result = runner.invoke(report, ["--format", "html"])
        assert result.exit_code == 0
        assert "written to" in result.output
