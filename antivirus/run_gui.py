#!/usr/bin/env python3
"""Launcher for the Aegis AV window - double-click me or ``python3 run_gui.py``.

The only job of this file is to make ``aegis`` importable when the project has
not been installed with pip (which is the normal case for a student/lab setup)
and then to hand over to the real entry point.
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def main() -> int:
    try:
        from aegis.gui import run
    except ImportError as exc:  # pragma: no cover - broken checkout
        sys.stderr.write(
            "Nie udało się zaimportować paczki 'aegis'.\n"
            f"Szczegóły: {exc}\n"
            "Uruchom ten plik z katalogu 'antivirus' projektu Aegis AV.\n"
        )
        return 2
    return run(sys.argv[1:])


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
