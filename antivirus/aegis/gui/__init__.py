"""Desktop user interface for Aegis AV.

The package is deliberately split in two:

* :mod:`aegis.gui.controller` holds **all** application logic and imports no
  GUI toolkit at all, so it can be unit-tested headlessly on a machine without
  Tkinter (CI containers, servers).
* :mod:`aegis.gui.app` holds only widgets and wiring.

Importing this package never imports Tkinter; :func:`run` does that lazily so
that ``from aegis.gui import AegisController`` keeps working on a box where
``python3-tk`` is not installed.
"""

from __future__ import annotations

from typing import Sequence

from .controller import AegisController

__all__ = ["AegisController", "run"]


def run(argv: Sequence[str] | None = None) -> int:
    """Launch the graphical interface.  Returns a process exit code."""
    from . import app  # imported lazily: pulls in Tkinter

    return app.main(argv)
