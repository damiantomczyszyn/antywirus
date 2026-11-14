"""Realtime protection, behavioural analysis and automated response.

The three pieces are deliberately separable, so each can be tested and reasoned
about on its own:

:class:`~aegis.realtime.behavior.BehaviorEngine`
    Pure correlation.  Takes :class:`~aegis.models.BehaviorEvent` observations,
    returns :class:`~aegis.models.Detection` objects.  No I/O at all.
:class:`~aegis.realtime.procmon.ProcessMonitor`
    Produces observations about processes and their outbound connections.
:class:`~aegis.realtime.watcher.RealtimeMonitor`
    Produces observations about the filesystem *and* drives the static scanner
    over every change, which is what makes the analysis hybrid.
:class:`~aegis.realtime.responder.Responder`
    Turns a verdict into action: quarantine, delete, report or kill a process
    tree - with self-protection that refuses to kill Aegis itself.

Importing this package has no side effects and requires neither ``watchdog``
nor ``psutil``; both are used when importable and cleanly replaced when not.
"""

from __future__ import annotations

from .behavior import BEHAVIOR_RULES, BehaviorEngine
from .procmon import ProcessMonitor
from .responder import Responder
from .watcher import RealtimeMonitor

__all__ = [
    "BehaviorEngine",
    "BEHAVIOR_RULES",
    "ProcessMonitor",
    "RealtimeMonitor",
    "Responder",
]
