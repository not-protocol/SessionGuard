"""Allows `python -m sessionguard`, and serves as PyInstaller's entry
point for building the single-file executable (see packaging/build.py)."""
from sessionguard.cli import cli

if __name__ == "__main__":
    cli()
