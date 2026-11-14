"""Realtime filesystem protection - the hybrid entry point.

Every change inside ``config.realtime_paths`` is translated into **two**
independent things:

1. a **scan request** for the static engine (hash / pattern / heuristics), and
2. a **behaviour observation** for :class:`~aegis.realtime.behavior.BehaviorEngine`.

That dual path is the whole point of hybrid realtime protection: the scan
catches what has been seen before, the behaviour stream catches the ransomware
that was compiled this morning.  A file whose content is unknown but which is
one of fifty rewritten with ciphertext in the last ten seconds gets caught by
the second path, and the two paths together reach a verdict neither would reach
alone (see :func:`aegis.engine.verdict.fuse`).

Backends
--------
``watchdog``
    Kernel notifications (inotify / FSEvents / ReadDirectoryChangesW).
``polling``
    A snapshot differ: walk the watched trees, keep a ``path -> (size,
    mtime_ns)`` map and diff it on an interval.  Slower, but it needs nothing
    but the standard library, and it also notices changes that happened while
    the monitor was down.

Safety properties
-----------------
* **No feedback loop.** ``config.is_internal(path)`` is checked when an event is
  queued *and* again when it is processed, so quarantining a file can never
  make the monitor rescan its own vault forever.
* **Debounce.** Editors write the same file three to five times in a row;
  events for one path are coalesced, and an unchanged path is not rescanned
  within ``config.realtime_debounce_ms``.
* **Bounded queue.** A flood (``unzip`` of a big archive) fills a bounded
  pending map; past the cap, events are dropped and counted instead of growing
  the queue until the process dies.
* **Bounded reads.** Entropy is computed from a bounded prefix of the changed
  file, never the whole thing.
"""

from __future__ import annotations

import hashlib
import math
import os
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Sequence

from ..config import Config
from ..events import EventBus, EventType
from ..models import (
    BehaviorEvent,
    BehaviorKind,
    FileVerdict,
    Severity,
)
from .behavior import BehaviorEngine, parse_severity, severity_at_least
from .responder import Responder

if TYPE_CHECKING:  # pragma: no cover - optional sibling modules
    from ..core.quarantine import Quarantine
    from ..core.scanner import Scanner

try:  # pragma: no cover - presence depends on the environment
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    HAVE_WATCHDOG = True
except Exception:  # noqa: BLE001 - watchdog raises more than ImportError
    FileSystemEventHandler = object  # type: ignore[assignment,misc]
    Observer = None  # type: ignore[assignment]
    HAVE_WATCHDOG = False

__all__ = ["RealtimeMonitor", "HAVE_WATCHDOG", "ENTROPY_PREFIX_BYTES"]

#: How much of a changed file is read to estimate entropy and hash content.
ENTROPY_PREFIX_BYTES = 64 * 1024

#: Longest text snippet handed to the ransom-note language rule.
SAMPLE_TEXT_BYTES = 8 * 1024

_MAX_PENDING = 2048
_MAX_WALK_FILES = 50_000
_MAX_FILE_STATE = 8192
_PROCESS_ACTION_COOLDOWN = 60.0


@dataclass(slots=True)
class _Pending:
    """One coalesced, debounced change waiting to be processed."""

    path: str
    kind: BehaviorKind
    first_ts: float
    last_ts: float
    old_path: str | None = None
    hits: int = 1

    @property
    def ready_at(self) -> float:
        return self.last_ts


def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte, 0.0..8.0.

    Prefers :func:`aegis.core.heuristics.shannon_entropy` so that the whole
    product agrees on one definition, but keeps a local implementation so that
    realtime protection never depends on the static engine being importable.
    """
    if not data:
        return 0.0
    external = _external_entropy()
    if external is not None:
        try:
            return float(external(data))
        except Exception:  # noqa: BLE001 - fall back to the local version
            pass
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


_entropy_fn: Callable[[bytes], float] | None = None
_entropy_looked_up = False


def _external_entropy() -> Callable[[bytes], float] | None:
    global _entropy_fn, _entropy_looked_up
    if not _entropy_looked_up:
        _entropy_looked_up = True
        try:  # pragma: no cover - depends on the static engine being present
            from ..core.heuristics import shannon_entropy

            _entropy_fn = shannon_entropy
        except Exception:  # noqa: BLE001
            _entropy_fn = None
    return _entropy_fn


if HAVE_WATCHDOG:  # pragma: no cover - thin adapter, exercised by the live demo

    class _WatchdogHandler(FileSystemEventHandler):  # type: ignore[misc,valid-type]
        """Translates watchdog callbacks into queue entries."""

        def __init__(self, monitor: "RealtimeMonitor") -> None:
            super().__init__()
            self._monitor = monitor

        def on_created(self, event: Any) -> None:
            if not event.is_directory:
                self._monitor.submit(event.src_path, BehaviorKind.FILE_CREATE)

        def on_modified(self, event: Any) -> None:
            if not event.is_directory:
                self._monitor.submit(event.src_path, BehaviorKind.FILE_MODIFY)

        def on_moved(self, event: Any) -> None:
            if not event.is_directory:
                self._monitor.submit(
                    event.dest_path, BehaviorKind.FILE_RENAME, old_path=event.src_path
                )

        def on_deleted(self, event: Any) -> None:
            if not event.is_directory:
                self._monitor.submit(event.src_path, BehaviorKind.FILE_DELETE)

else:  # pragma: no cover
    _WatchdogHandler = None  # type: ignore[assignment,misc]


class RealtimeMonitor:
    """Watches directories and drives the scanner, behaviour engine and responder."""

    def __init__(
        self,
        scanner: "Scanner",
        config: Config,
        bus: EventBus,
        quarantine: "Quarantine | None" = None,
        behavior: BehaviorEngine | None = None,
        responder: Responder | None = None,
        *,
        backend: str | None = None,
    ) -> None:
        self._scanner = scanner
        self._config = config
        self._bus = bus
        self._quarantine = quarantine
        self._behavior = behavior
        self._responder = responder

        if backend in ("watchdog", "polling"):
            self._backend = backend
        else:
            self._backend = "watchdog" if HAVE_WATCHDOG else "polling"
        if self._backend == "watchdog" and not HAVE_WATCHDOG:
            self._backend = "polling"

        # Let the responder verify files after it stops a process, without
        # requiring the GUI controller to wire it up by hand.
        if responder is not None and scanner is not None:
            setter = getattr(responder, "set_scanner", None)
            if callable(setter):
                setter(scanner)

        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._observer: Any = None
        self._paths: list[str] = []
        self._pending: dict[str, _Pending] = {}
        self._snapshot: dict[str, tuple[int, int]] = {}
        self._primed = False
        self._file_state: dict[str, tuple[int, float | None]] = {}
        self._file_state_order: list[str] = []
        self._last_handled: dict[str, tuple[float, int, int]] = {}
        self._handled_actors: dict[int | None, tuple[float, float]] = {}

        self._counters: dict[str, int] = {
            "events": 0,
            "coalesced": 0,
            "dropped": 0,
            "debounced": 0,
            "processed": 0,
            "scanned": 0,
            "threats": 0,
            "actions": 0,
            "skipped_internal": 0,
            "skipped_excluded": 0,
            "skipped_large": 0,
            "deleted": 0,
            "errors": 0,
        }
        self._max_pending = int(getattr(config, "realtime_queue_size", 0) or _MAX_PENDING)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    @property
    def backend(self) -> str:
        return self._backend

    @property
    def is_running(self) -> bool:
        if self._stop.is_set():
            return False
        thread = self._thread
        if thread is not None and thread.is_alive():
            return True
        # Manual-pump mode (``start(background=False)``): no drain thread, but
        # the backend is armed and the watched paths are live.
        return bool(self._paths) and (self._observer is not None or self._backend == "polling")

    @property
    def paths(self) -> list[str]:
        with self._lock:
            return list(self._paths)

    @property
    def behavior(self) -> BehaviorEngine | None:
        return self._behavior

    def status(self) -> dict[str, Any]:
        with self._lock:
            data: dict[str, Any] = {
                "backend": self._backend,
                "running": self.is_running,
                "paths": list(self._paths),
                "pending": len(self._pending),
                "queue_limit": self._max_pending,
                "debounce_ms": int(self._config.realtime_debounce_ms),
                "min_severity": self._file_floor().value,
                "action": self._config.realtime_action.value,
            }
            data.update(self._counters)
            return data

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self, paths: Sequence[str] | None = None, *, background: bool = True) -> None:
        """Begin watching *paths* (default: ``config.realtime_paths``).

        With ``background=False`` the backend is armed but no drain thread is
        started, so the caller owns the pump and must call :meth:`drain_once`
        itself.  That is what the tests use: a background thread racing an
        explicit ``drain_once()`` would make the processed counts
        non-deterministic.
        """
        if self.is_running:
            return
        wanted = list(paths) if paths else list(self._config.realtime_paths)
        usable: list[str] = []
        for raw in wanted:
            path = os.path.abspath(os.path.expanduser(str(raw)))
            if self._config.is_internal(path):
                self._log(
                    f"Pomijam ścieżkę należącą do Aegis: {path}", level="warning"
                )
                continue
            if not os.path.isdir(path):
                self._log(f"Pomijam nieistniejący katalog: {path}", level="warning")
                continue
            usable.append(path)

        if not usable:
            self._log(
                "Ochrona w czasie rzeczywistym nie wystartowała: brak katalogów do obserwacji.",
                level="error",
            )
            return

        with self._lock:
            self._paths = usable
            self._pending.clear()
            self._primed = False
            self._snapshot.clear()
        self._stop.clear()

        if self._backend == "watchdog":
            if not self._start_watchdog(usable):
                self._backend = "polling"
        if self._backend == "polling":
            self._poll_filesystem()  # prime: existing files are not "changes"

        if background:
            thread = threading.Thread(target=self._loop, name="aegis-realtime", daemon=True)
            self._thread = thread
            thread.start()

        self._publish(
            EventType.REALTIME_STARTED,
            f"Ochrona w czasie rzeczywistym włączona (backend: {self._backend}, "
            f"katalogi: {len(usable)}).",
            level="success",
            backend=self._backend,
            paths=list(usable),
        )

    def _start_watchdog(self, paths: Sequence[str]) -> bool:
        try:
            observer = Observer()
            handler = _WatchdogHandler(self)
            for path in paths:
                observer.schedule(handler, path, recursive=True)
            observer.daemon = True
            observer.start()
        except Exception as exc:  # noqa: BLE001 - inotify limits, permissions, ...
            self._log(
                f"Backend watchdog niedostępny ({exc}); przechodzę na odpytywanie.",
                level="warning",
            )
            self._observer = None
            return False
        self._observer = observer
        return True

    def stop(self, timeout: float = 5.0) -> None:
        """Stop watching and release the backend."""
        self._stop.set()
        observer = self._observer
        self._observer = None
        if observer is not None:
            try:
                observer.stop()
                observer.join(timeout=timeout)
            except Exception:  # noqa: BLE001 - never let shutdown raise
                pass
        thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=timeout)
        self._thread = None
        self._publish(
            EventType.REALTIME_STOPPED,
            "Ochrona w czasie rzeczywistym wyłączona.",
            level="info",
        )

    def _loop(self) -> None:
        interval = max(0.1, float(self._config.realtime_debounce_ms) / 1000.0)
        if self._backend == "polling":
            interval = max(interval, 0.5)
        while not self._stop.is_set():
            try:
                self.drain_once(force=False)
            except Exception as exc:  # noqa: BLE001 - the thread must survive anything
                with self._lock:
                    self._counters["errors"] += 1
                self._log(f"Błąd pętli ochrony: {exc}", level="error")
            self._stop.wait(interval)

    # ------------------------------------------------------------------
    # Event intake
    # ------------------------------------------------------------------
    def submit(
        self, path: str, kind: BehaviorKind, *, old_path: str | None = None
    ) -> bool:
        """Queue one filesystem change.  Thread-safe; called by both backends."""
        if not path:
            return False
        path = os.path.abspath(path)
        if self._should_skip(path):
            return False

        now = time.time()
        with self._lock:
            self._counters["events"] += 1
            existing = self._pending.get(path)
            if existing is not None:
                existing.last_ts = now
                existing.hits += 1
                existing.kind = self._merge_kind(existing.kind, kind)
                if old_path and not existing.old_path:
                    existing.old_path = old_path
                self._counters["coalesced"] += 1
                return True
            if len(self._pending) >= self._max_pending:
                # A bounded queue that drops and counts beats an unbounded one
                # that eats the machine during a big unzip.
                self._counters["dropped"] += 1
                return False
            self._pending[path] = _Pending(
                path=path, kind=kind, first_ts=now, last_ts=now, old_path=old_path
            )
            return True

    @staticmethod
    def _merge_kind(current: BehaviorKind, incoming: BehaviorKind) -> BehaviorKind:
        """Keep the most informative kind when several events coalesce."""
        order = {
            BehaviorKind.FILE_MODIFY: 0,
            BehaviorKind.FILE_CREATE: 1,
            BehaviorKind.FILE_RENAME: 2,
            BehaviorKind.FILE_DELETE: 3,
        }
        return incoming if order.get(incoming, 0) > order.get(current, 0) else current

    def _should_skip(self, path: str) -> bool:
        """The loop breaker: never look at our own data directory."""
        try:
            if self._config.is_internal(path):
                with self._lock:
                    self._counters["skipped_internal"] += 1
                return True
        except Exception:  # noqa: BLE001 - a weird path is not a reason to crash
            return True
        if self._is_excluded(path):
            with self._lock:
                self._counters["skipped_excluded"] += 1
            return True
        return False

    def _is_excluded(self, path: str) -> bool:
        normalised = path.replace("\\", "/")
        parts = set(normalised.split("/"))
        for name in self._config.excluded_names:
            if name.startswith("/"):
                if normalised == name or normalised.startswith(name.rstrip("/") + "/"):
                    return True
            elif name in parts:
                return True
        for excluded in self._config.excluded_paths:
            try:
                prefix = os.path.abspath(os.path.expanduser(str(excluded)))
            except Exception:  # noqa: BLE001
                continue
            if normalised == prefix or normalised.startswith(prefix.rstrip("/") + "/"):
                return True
        return False

    # ------------------------------------------------------------------
    # Draining
    # ------------------------------------------------------------------
    def drain_once(self, force: bool = True) -> int:
        """Process the pending queue and return how many files were handled.

        With ``force=True`` (the default, and what the tests use) every pending
        entry is processed immediately.  The background thread calls it with
        ``force=False``, which only processes entries whose debounce window has
        elapsed.  In ``polling`` mode a fresh filesystem snapshot is taken
        first, so a test can drive the whole pipeline synchronously without a
        single ``sleep``.
        """
        if self._backend == "polling":
            self._poll_filesystem()

        debounce = max(0.0, float(self._config.realtime_debounce_ms) / 1000.0)
        now = time.time()
        with self._lock:
            if force:
                ready = list(self._pending.values())
                self._pending.clear()
            else:
                ready = [p for p in self._pending.values() if now - p.ready_at >= debounce]
                for item in ready:
                    self._pending.pop(item.path, None)

        handled = 0
        for item in ready:
            try:
                processed, _fired = self._process(item, debounce)
            except Exception as exc:  # noqa: BLE001 - one bad file is not fatal
                with self._lock:
                    self._counters["errors"] += 1
                self._log(f"Błąd przetwarzania {item.path}: {exc}", level="error")
                continue
            handled += int(processed)

        with self._lock:
            self._counters["processed"] += handled
        # Unconditionally, even when no file changed: an actor can also escalate
        # on evidence from the process monitor (a shadow-copy command line, a
        # blocklisted connection), and ProcessMonitor has no responder of its
        # own by contract.
        self._check_process_threats()
        return handled

    def _process(self, item: _Pending, debounce: float) -> tuple[bool, bool]:
        """Handle one change: behaviour observation + scan + response."""
        path = item.path
        # Second guard: the path may have become internal (or the config may
        # have changed) between queueing and processing.
        if self._config.is_internal(path):
            with self._lock:
                self._counters["skipped_internal"] += 1
            return False, False

        try:
            stat = os.stat(path, follow_symlinks=bool(self._config.follow_symlinks))
        except (OSError, ValueError):
            stat = None

        if stat is None or item.kind is BehaviorKind.FILE_DELETE:
            fired = self._observe(
                BehaviorEvent(
                    kind=BehaviorKind.FILE_DELETE,
                    path=path,
                    old_path=item.old_path,
                    extra={"backend": self._backend},
                )
            )
            with self._lock:
                self._counters["deleted"] += 1
                self._forget(path)
            return True, fired

        if not os.path.isfile(path):
            return False, False

        size = int(stat.st_size)
        mtime_ns = int(stat.st_mtime_ns)
        now = time.time()
        previous_handled = self._last_handled.get(path)
        if (
            previous_handled is not None
            and now - previous_handled[0] < debounce
            and (size, mtime_ns) == previous_handled[1:]
        ):
            # The editor wrote the same bytes again: nothing new to look at.
            with self._lock:
                self._counters["debounced"] += 1
            return False, False

        data, complete = self._read_prefix(path, size)
        entropy = _shannon_entropy(data) if data else None
        prev_size, prev_entropy = self._file_state.get(path, (None, None))

        extra: dict[str, Any] = {"backend": self._backend, "hits": item.hits}
        if prev_size is not None:
            extra["prev_size"] = prev_size
        if prev_entropy is not None:
            extra["prev_entropy"] = prev_entropy
        if complete and data:
            extra["content_hash"] = hashlib.sha256(data).hexdigest()
        sample = self._sample_text(data)
        if sample:
            extra["sample_text"] = sample

        fired = self._observe(
            BehaviorEvent(
                kind=item.kind,
                timestamp=now,
                path=path,
                old_path=item.old_path,
                size=size,
                entropy=entropy,
                extra=extra,
            )
        )
        self._remember(path, size, entropy)
        with self._lock:
            self._last_handled[path] = (now, size, mtime_ns)
            if len(self._last_handled) > _MAX_FILE_STATE:
                self._last_handled.clear()

        self._scan_and_respond(path, size, data if complete else None)
        return True, fired

    def _scan_and_respond(self, path: str, size: int, data: bytes | None) -> None:
        if self._scanner is None:
            return
        if size > int(self._config.max_file_size):
            with self._lock:
                self._counters["skipped_large"] += 1
            return
        try:
            verdict = self._scanner.scan_file(path, data=data)
        except TypeError:
            # A scanner that does not accept pre-read bytes is still fine.
            try:
                verdict = self._scanner.scan_file(path)
            except Exception as exc:  # noqa: BLE001
                self._log(f"Skanowanie {path} nie powiodło się: {exc}", level="error")
                with self._lock:
                    self._counters["errors"] += 1
                return
        except Exception as exc:  # noqa: BLE001 - a scanner bug must not stop realtime
            self._log(f"Skanowanie {path} nie powiodło się: {exc}", level="error")
            with self._lock:
                self._counters["errors"] += 1
            return

        with self._lock:
            self._counters["scanned"] += 1
        if verdict is None or not isinstance(verdict, FileVerdict) or not verdict.is_threat:
            return
        with self._lock:
            self._counters["threats"] += 1

        if self._responder is None:
            self._log(
                f"Zagrożenie {verdict.threat_name} w {path} - brak modułu reakcji, "
                "tylko zgłoszenie.",
                level="warning",
            )
            return
        if not severity_at_least(verdict.severity, self._file_floor()):
            return
        try:
            results = self._responder.handle_file_threat(verdict)
        except Exception as exc:  # noqa: BLE001
            self._log(f"Reakcja na {path} nie powiodła się: {exc}", level="error")
            with self._lock:
                self._counters["errors"] += 1
            return
        with self._lock:
            self._counters["actions"] += len(results)

    def _check_process_threats(self) -> None:
        """Hand escalated behavioural verdicts to the responder, once each."""
        if self._behavior is None or self._responder is None:
            return
        floor = getattr(self._responder, "process_min_severity", Severity.HIGH)
        try:
            verdicts = self._behavior.verdicts(min_severity=floor)
        except Exception:  # noqa: BLE001
            return
        now = time.time()
        for verdict in verdicts:
            last = self._handled_actors.get(verdict.pid)
            if last is not None:
                last_ts, last_score = last
                if now - last_ts < _PROCESS_ACTION_COOLDOWN and verdict.score <= last_score:
                    continue
            if len(self._handled_actors) > 512:
                self._handled_actors.clear()
            self._handled_actors[verdict.pid] = (now, verdict.score)
            try:
                results = self._responder.handle_process_threat(verdict)
            except Exception as exc:  # noqa: BLE001
                self._log(f"Reakcja na proces {verdict.pid} nie powiodła się: {exc}", level="error")
                continue
            with self._lock:
                self._counters["actions"] += len(results)

    # ------------------------------------------------------------------
    # Polling backend
    # ------------------------------------------------------------------
    def _poll_filesystem(self) -> int:
        """Diff a fresh snapshot of the watched trees against the previous one."""
        current = self._walk()
        with self._lock:
            previous = self._snapshot
            self._snapshot = current
            primed = self._primed
            self._primed = True
        if not primed:
            return 0  # the files that already existed are not changes

        queued = 0
        for path, signature in current.items():
            old = previous.get(path)
            if old is None:
                queued += int(self.submit(path, BehaviorKind.FILE_CREATE))
            elif old != signature:
                queued += int(self.submit(path, BehaviorKind.FILE_MODIFY))
        for path in previous:
            if path not in current:
                queued += int(self.submit(path, BehaviorKind.FILE_DELETE))
        return queued

    def _walk(self) -> dict[str, tuple[int, int]]:
        out: dict[str, tuple[int, int]] = {}
        follow = bool(self._config.follow_symlinks)
        for root in self.paths:
            stack = [root]
            while stack:
                if len(out) >= _MAX_WALK_FILES:
                    self._log(
                        f"Przerwano przeglądanie po {_MAX_WALK_FILES} plikach - "
                        "zawęź listę obserwowanych katalogów.",
                        level="warning",
                    )
                    return out
                directory = stack.pop()
                try:
                    entries = list(os.scandir(directory))
                except (OSError, ValueError):
                    continue
                for entry in entries:
                    try:
                        path = entry.path
                        if self._config.is_internal(path) or self._is_excluded(path):
                            continue
                        if entry.is_dir(follow_symlinks=follow):
                            stack.append(path)
                            continue
                        if not entry.is_file(follow_symlinks=follow):
                            continue
                        stat = entry.stat(follow_symlinks=follow)
                        out[os.path.abspath(path)] = (int(stat.st_size), int(stat.st_mtime_ns))
                    except (OSError, ValueError):
                        continue  # vanished mid-walk: normal
        return out

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _file_floor(self) -> Severity:
        return parse_severity(self._config.realtime_min_severity, Severity.MEDIUM)

    def _observe(self, event: BehaviorEvent) -> bool:
        if self._behavior is None:
            return False
        try:
            return bool(self._behavior.observe(event))
        except Exception as exc:  # noqa: BLE001 - a rule bug must not stop scanning
            self._log(f"Analiza behawioralna nie powiodła się: {exc}", level="error")
            with self._lock:
                self._counters["errors"] += 1
            return False

    @staticmethod
    def _read_prefix(path: str, size: int) -> tuple[bytes, bool]:
        """Read at most :data:`ENTROPY_PREFIX_BYTES`; report whether that is all of it."""
        try:
            with open(path, "rb") as fh:
                data = fh.read(ENTROPY_PREFIX_BYTES)
        except OSError:
            return b"", False
        return data, len(data) == size

    @staticmethod
    def _sample_text(data: bytes) -> str:
        """Decode a short text prefix for the ransom-note language rule."""
        if not data or b"\x00" in data[:512]:
            return ""
        try:
            return data[:SAMPLE_TEXT_BYTES].decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            return ""

    def _remember(self, path: str, size: int, entropy: float | None) -> None:
        with self._lock:
            if path not in self._file_state:
                self._file_state_order.append(path)
                while len(self._file_state_order) > _MAX_FILE_STATE:
                    self._file_state.pop(self._file_state_order.pop(0), None)
            self._file_state[path] = (size, entropy)

    def _forget(self, path: str) -> None:
        self._file_state.pop(path, None)
        self._last_handled.pop(path, None)

    def _log(self, message: str, level: str = "info") -> None:
        self._publish(EventType.LOG, message, level=level, source="realtime")

    def _publish(self, kind: EventType, message: str, level: str = "info", **payload: Any) -> None:
        if self._bus is None:
            return
        try:
            self._bus.publish(kind, message, level=level, **payload)
        except Exception:  # noqa: BLE001 - best effort
            pass
