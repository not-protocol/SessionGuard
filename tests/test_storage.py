"""Tests for persisting/loading the last scan/audit run."""
from sessionguard.models import ScanResult, Severity
from sessionguard.storage import load_last_run, save_last_run


def test_roundtrip(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = ScanResult(target="https://example.test")
    result.add("https-enforcement", Severity.INFO, "ok", passed=True)
    save_last_run([result])

    loaded = load_last_run()
    assert loaded[0].target == "https://example.test"
    assert loaded[0].findings[0].check == "https-enforcement"


def test_load_when_nothing_saved(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert load_last_run() is None


def test_save_overwrites_previous_run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    first = ScanResult(target="https://first.test")
    save_last_run([first])

    second = ScanResult(target="https://second.test")
    save_last_run([second])

    loaded = load_last_run()
    assert len(loaded) == 1
    assert loaded[0].target == "https://second.test"
