"""Persist scan results between commands, so `report` can re-render the
last `scan`/`audit` run in a different format without re-scanning.

Only findings and non-sensitive metadata are ever written here — the
check modules themselves are responsible for redacting anything
secret-shaped before it becomes part of a Finding, so there's nothing
extra to scrub at the storage layer. Kept as a single flat JSON file
(not a database) since it only ever needs to hold the most recent run.
"""
import json
from pathlib import Path
from typing import Optional

from sessionguard.models import ScanResult, Severity

STORE_DIR = Path(".sessionguard")
LAST_RUN_PATH = STORE_DIR / "last-run.json"


def save_last_run(results: list) -> None:
    """Persist a list of ScanResult objects, overwriting any previous run."""
    STORE_DIR.mkdir(exist_ok=True)
    payload = [
        {
            "target": r.target,
            "findings": [
                {
                    "check": f.check,
                    "severity": f.severity.value,
                    "message": f.message,
                    "passed": f.passed,
                }
                for f in r.findings
            ],
        }
        for r in results
    ]
    LAST_RUN_PATH.write_text(json.dumps(payload, indent=2))


def load_last_run() -> Optional[list]:
    """Load the most recently saved run, or None if nothing's been saved
    (or saved in the current directory) yet."""
    if not LAST_RUN_PATH.exists():
        return None

    payload = json.loads(LAST_RUN_PATH.read_text())
    results = []
    for entry in payload:
        result = ScanResult(target=entry["target"])
        for f in entry["findings"]:
            result.add(f["check"], Severity(f["severity"]), f["message"], f["passed"])
        results.append(result)
    return results
