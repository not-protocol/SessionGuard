#!/usr/bin/env python3
"""Build a single-file SessionGuard executable for whichever OS this
script is run on.

PyInstaller does not cross-compile — a Windows .exe has to be built on
Windows, a macOS binary on macOS, and a Linux binary on Linux. To get
all three from one push, run this via the .github/workflows/build.yml
matrix (build.yml runs it on windows-latest, macos-latest, and
ubuntu-latest), or run it locally on each OS by hand.

Usage:
    pip install -e ".[build]"
    python packaging/build.py

Output: dist/sessionguard (or dist/sessionguard.exe on Windows)
"""
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    system = platform.system()
    name = "sessionguard"
    entry = str(ROOT / "src" / "sessionguard" / "__main__.py")

    args = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", name,
        "--paths", str(ROOT / "src"),
        "--distpath", str(ROOT / "dist"),
        "--workpath", str(ROOT / "build"),
        "--specpath", str(ROOT / "build"),
        "--console",
        "--clean",
        "--noconfirm",
        entry,
    ]

    print(f"Building SessionGuard for {system}...")
    subprocess.run(args, check=True)

    binary_name = f"{name}.exe" if system == "Windows" else name
    print(f"Done — binary at dist/{binary_name}")


if __name__ == "__main__":
    main()
