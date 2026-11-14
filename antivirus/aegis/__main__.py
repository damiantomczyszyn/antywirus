"""Allow ``python3 -m aegis <polecenie>``.

Kept to a single line of logic so that every behaviour (including the exit
codes) lives in :mod:`aegis.cli` and stays unit-testable.
"""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
