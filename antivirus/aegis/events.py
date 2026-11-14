"""Thread-safe event bus used to decouple the engine from the user interface.

The scanning engine, the realtime monitor and the intel updater all run on
worker threads.  Tkinter may only be touched from the main thread, so the GUI
does not subscribe with a callback: it asks for a :class:`queue.Queue` via
:meth:`EventBus.listen` and drains it from a ``root.after`` timer.
"""

from __future__ import annotations

import itertools
import queue
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable

__all__ = ["EventType", "Event", "EventBus"]


class EventType(str, Enum):
    """Everything the UI may want to react to."""

    LOG = "log"

    SCAN_STARTED = "scan_started"
    SCAN_PROGRESS = "scan_progress"
    SCAN_FILE_DONE = "scan_file_done"
    SCAN_FINISHED = "scan_finished"
    SCAN_CANCELLED = "scan_cancelled"

    THREAT_FOUND = "threat_found"
    BEHAVIOR_ALERT = "behavior_alert"
    ACTION_TAKEN = "action_taken"

    REALTIME_STARTED = "realtime_started"
    REALTIME_STOPPED = "realtime_stopped"

    DB_UPDATE_STARTED = "db_update_started"
    DB_UPDATE_FEED = "db_update_feed"
    DB_UPDATE_FINISHED = "db_update_finished"
    DB_LOADED = "db_loaded"

    QUARANTINE_CHANGED = "quarantine_changed"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass(slots=True)
class Event:
    """One message on the bus."""

    type: EventType
    message: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    level: str = "info"  # info | warning | error | success

    def __post_init__(self) -> None:
        self.type = EventType(self.type)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["type"] = self.type.value
        return data


class EventBus:
    """Fan-out of :class:`Event` objects to callbacks and/or queues.

    Safe to publish from any thread.  A slow or crashing subscriber can never
    break the publisher: callbacks are wrapped and full queues drop their
    oldest entry instead of blocking the engine.
    """

    def __init__(self, history: int = 500) -> None:
        self._lock = threading.RLock()
        self._callbacks: dict[int, Callable[[Event], None]] = {}
        self._queues: dict[int, queue.Queue[Event]] = {}
        self._ids = itertools.count(1)
        self._history: deque[Event] = deque(maxlen=history)
        self._counts: dict[EventType, int] = {}

    # -- subscription ----------------------------------------------------
    def subscribe(self, callback: Callable[[Event], None]) -> int:
        """Register *callback*; returns a token for :meth:`unsubscribe`."""
        with self._lock:
            token = next(self._ids)
            self._callbacks[token] = callback
            return token

    def listen(self, maxsize: int = 2000) -> tuple[int, "queue.Queue[Event]"]:
        """Register a queue sink; returns ``(token, queue)``."""
        with self._lock:
            token = next(self._ids)
            q: queue.Queue[Event] = queue.Queue(maxsize=maxsize)
            self._queues[token] = q
            return token, q

    def unsubscribe(self, token: int) -> None:
        with self._lock:
            self._callbacks.pop(token, None)
            self._queues.pop(token, None)

    # -- publishing ------------------------------------------------------
    def publish(
        self,
        type: EventType | str,
        message: str = "",
        level: str = "info",
        **payload: Any,
    ) -> Event:
        """Build and dispatch an event.  Returns the dispatched event."""
        event = Event(type=EventType(type), message=message, level=level, payload=payload)
        self.emit(event)
        return event

    def emit(self, event: Event) -> None:
        """Dispatch an already-built event."""
        with self._lock:
            self._history.append(event)
            self._counts[event.type] = self._counts.get(event.type, 0) + 1
            callbacks = list(self._callbacks.values())
            queues = list(self._queues.values())

        for cb in callbacks:
            try:
                cb(event)
            except Exception:  # noqa: BLE001 - a bad subscriber must not stop the engine
                pass

        for q in queues:
            try:
                q.put_nowait(event)
            except queue.Full:
                try:
                    q.get_nowait()        # drop the oldest, keep the newest
                    q.put_nowait(event)
                except (queue.Empty, queue.Full):
                    pass

    # -- convenience -----------------------------------------------------
    def log(self, message: str, level: str = "info", **payload: Any) -> Event:
        return self.publish(EventType.LOG, message, level=level, **payload)

    def history(self, limit: int | None = None, types: set[EventType] | None = None) -> list[Event]:
        with self._lock:
            items = list(self._history)
        if types:
            items = [e for e in items if e.type in types]
        if limit is not None:
            items = items[-limit:]
        return items

    def counts(self) -> dict[str, int]:
        with self._lock:
            return {k.value: v for k, v in self._counts.items()}

    def clear_history(self) -> None:
        with self._lock:
            self._history.clear()

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._callbacks) + len(self._queues)
