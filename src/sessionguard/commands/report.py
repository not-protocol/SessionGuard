"""`sessionguard report` — re-render the last scan/audit run in a
different format, without re-scanning anything."""
from pathlib import Path

import click

from sessionguard.report_writer import print_terminal_report, render_html, render_json
from sessionguard.storage import load_last_run


@click.command()
@click.option("--format", "fmt", type=click.Choice(["terminal", "json", "html"]), default="terminal")
def report(fmt: str):
    """Re-render the last scan/audit run in a given format."""
    results = load_last_run()
    if results is None:
        click.echo("No previous run found — run 'scan' or 'audit' first.", err=True)
        raise SystemExit(1)

    if fmt == "terminal":
        print_terminal_report(results)
    elif fmt == "json":
        click.echo(render_json(results))
    elif fmt == "html":
        out_path = Path(".sessionguard/report.html")
        out_path.parent.mkdir(exist_ok=True)
        out_path.write_text(render_html(results))
        click.echo(f"HTML report written to {out_path}")
