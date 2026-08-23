"""SessionGuard CLI entry point."""
import click

from sessionguard import __version__
from sessionguard.commands.analyze_token import analyze_token
from sessionguard.commands.audit import audit
from sessionguard.commands.lab import lab
from sessionguard.commands.report import report
from sessionguard.commands.scan import scan
from sessionguard.commands.version_cmd import version_cmd


@click.group()
@click.version_option(__version__, prog_name="sessionguard")
def cli():
    """SessionGuard — portable session/cookie security auditor.

    Only point this at systems you own or are explicitly authorized to test.
    """
    pass


cli.add_command(scan)
cli.add_command(audit)
cli.add_command(analyze_token, name="analyze-token")
cli.add_command(report)
cli.add_command(lab)
cli.add_command(version_cmd)


if __name__ == "__main__":
    cli()
