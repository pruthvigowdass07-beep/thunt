#!/usr/bin/env python3
"""Build a standalone single-file `thunt` binary with PyInstaller.

Run:  python -m pip install pyinstaller && python build_binary.py

Produces dist/thunt (dist/thunt.exe on Windows) that runs on any machine of the same
OS/arch with no Python installed. The optional Playwright scraper is NOT bundled.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ENTRY = Path(__file__).parent / "thunt" / "__main__.py"


def main() -> int:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller not installed. Run: python -m pip install pyinstaller")
        return 1

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", "thunt",
        "--console",
        # Sources are imported dynamically via the registry; make sure they're bundled.
        "--collect-submodules", "thunt.sources",
        "--hidden-import", "thunt.scrape",
        str(ENTRY),
    ]
    print("running:", " ".join(cmd))
    result = subprocess.run(cmd)
    if result.returncode == 0:
        out = "dist/thunt.exe" if sys.platform == "win32" else "dist/thunt"
        print(f"\nBuilt {out} — copy it to any {sys.platform} host and run it.")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
