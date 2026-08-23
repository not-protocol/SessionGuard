# Packaging SessionGuard as a single-file binary

SessionGuard's `pip install` path already gives you a portable *Python*
tool. This step goes further: a single-file executable with no Python
install required at all, for the USB / no-install goal in the main
README.

## Why three separate builds

PyInstaller bundles the interpreter and dependencies for the OS it runs
on — it does not cross-compile. A Windows `.exe` must be built on
Windows, a macOS binary on macOS, a Linux binary on Linux. There's no
way around this from a single machine; the two options are:

1. **CI (recommended):** push a tag, let `.github/workflows/build.yml`
   build all three in parallel on GitHub-hosted runners, and download
   the artifacts.
2. **Manually, per OS:** run the steps below natively on each machine
   you have access to.

## Manual build (run on the target OS)

```bash
git clone <this repo> && cd sessionguard
python -m venv .venv && source .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -e ".[build]"
python packaging/build.py
```

Output lands in `dist/`:
- Linux/macOS: `dist/sessionguard`
- Windows: `dist/sessionguard.exe`

Run it directly — no Python install needed on the machine you copy it to:

```bash
./dist/sessionguard scan https://example.test
```

## CI build (all three OSes)

`.github/workflows/build.yml` runs the same `packaging/build.py` script
on `ubuntu-latest`, `windows-latest`, and `macos-latest` in a matrix,
and uploads each binary as a workflow artifact. Trigger it by pushing a
`v*` tag, or manually from the Actions tab (`workflow_dispatch`).

## Notes

- The `lab` command's optional `--browser` preview needs Playwright's
  browser binaries (`playwright install`), which are *not* bundled into
  the PyInstaller binary — that's a deliberate size/complexity
  trade-off. `scan`, `audit`, `analyze-token`, `report`, and the lab's
  local server all work fully standalone with no extra install.
- Antivirus/SmartScreen may flag freshly-built, unsigned PyInstaller
  binaries on first run (this is common for any unsigned onefile
  executable, not specific to this project) — code-signing is out of
  scope here but is the standard next step if you plan to distribute
  the binary widely.
