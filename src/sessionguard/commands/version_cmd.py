"""`sessionguard version` — print the installed SessionGuard version."""
import click

from sessionguard import __version__


@click.command(name="version")
def version_cmd():
    """Print the installed SessionGuard version."""
    click.echo(f"SessionGuard {__version__}")
