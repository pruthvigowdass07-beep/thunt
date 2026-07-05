"""Entry point for `python -m thunt` and the PyInstaller binary."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
