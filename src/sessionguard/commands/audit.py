"""`sessionguard audit` — run the full check suite against every target
listed in an authorized targets file.
"""
from pathlib import Path

import click
import yaml

from sessionguard.engine import TargetUnreachable, run_scan
from sessionguard.report_writer import print_terminal_report, render_html, render_json
from sessionguard.storage import save_last_run


@click.command()
@click.option("--targets", default="targets.yaml", help="Path to authorized targets file")
@click.option("--timeout", default=10, help="Request timeout in seconds, per target")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json", "html"]), default="terminal")
def audit(targets: str, timeout: int, fmt: str):
    """Scan every target listed in a targets file.

    Only list systems you own or are explicitly authorized to test — see
    targets.example.yaml for the expected format.
    """
    path = Path(targets)
    if not path.exists():
        click.echo(f"No targets file at {targets}.", err=True)
        click.echo("Copy targets.example.yaml to targets.yaml and list your authorized targets.", err=True)
        raise SystemExit(1)

    data = yaml.safe_load(path.read_text()) or {}
    entries = data.get("targets") or []
    if not entries:
        click.echo(f"{targets} has no entries under 'targets:'.", err=True)
        raise SystemExit(1)

    results = []
    for entry in entries:
        name = entry.get("name", entry.get("url", "unnamed"))
        url = entry.get("url")
        if not url:
            click.echo(f"Skipping '{name}': no url set", err=True)
            continue
        try:
            results.append(run_scan(url, timeout=timeout))
        except TargetUnreachable as exc:
            click.echo(f"[{name}] {exc}", err=True)

    if not results:
        click.echo("No targets were reachable.", err=True)
        raise SystemExit(1)

    save_last_run(results)

    if fmt == "terminal":
        print_terminal_report(results)
    elif fmt == "json":
        click.echo(render_json(results))
    elif fmt == "html":
        out_path = Path(".sessionguard/audit-report.html")
        out_path.parent.mkdir(exist_ok=True)
        out_path.write_text(render_html(results))
        click.echo(f"HTML report written to {out_path}")
