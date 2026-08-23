"""`sessionguard scan` — audit HTTPS, cookie, entropy, and token-exposure
security for a single target."""
import click

from sessionguard.engine import TargetUnreachable, run_scan
from sessionguard.report_writer import print_terminal_report
from sessionguard.storage import save_last_run


@click.command()
@click.argument("url")
@click.option("--timeout", default=10, help="Request timeout in seconds")
def scan(url: str, timeout: int):
    """Scan a single URL for cookie, HTTPS, entropy, and token-exposure issues.

    Only run this against systems you own or are authorized to test.
    """
    try:
        result = run_scan(url, timeout=timeout)
    except TargetUnreachable as exc:
        click.echo(str(exc), err=True)
        raise SystemExit(1)

    print_terminal_report([result])
    save_last_run([result])
