"""Aegis AV - a teaching-grade antivirus with hybrid (static + behavioural) analysis.

Public surface::

    from aegis import Config, EventBus, Scanner, SignatureDB

The package is deliberately dependency-light: everything works on a bare
CPython 3.10+ install, and optional extras (``watchdog``, ``psutil``) only make
realtime protection faster, never mandatory.
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = [
    "__version__",
    "Config",
    "EventBus",
    "EventType",
    "Event",
    "Severity",
    "Indicator",
    "IndicatorKind",
    "Detection",
    "DetectionLayer",
    "FileVerdict",
    "ProcessVerdict",
    "BehaviorEvent",
    "BehaviorKind",
    "ActionKind",
    "ActionResult",
    "QuarantineEntry",
    "ScanStats",
    "FeedResult",
]

from .config import Config
from .events import Event, EventBus, EventType
from .models import (
    ActionKind,
    ActionResult,
    BehaviorEvent,
    BehaviorKind,
    Detection,
    DetectionLayer,
    FeedResult,
    FileVerdict,
    Indicator,
    IndicatorKind,
    ProcessVerdict,
    QuarantineEntry,
    ScanStats,
    Severity,
)
