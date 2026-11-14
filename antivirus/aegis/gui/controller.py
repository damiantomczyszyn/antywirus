"""Headless application controller - every bit of UI logic lives here.

Design rules enforced by this module
------------------------------------
* **Zero GUI imports.**  Nothing here knows that Tkinter exists, which is what
  makes the whole interface testable on a headless box.
* **Lazy, fault tolerant engine imports.**  ``aegis.core``, ``aegis.intel`` and
  ``aegis.realtime`` are imported through :func:`_import_module` and every
  subsystem is built inside its own ``try``.  A missing or broken subsystem
  degrades the controller instead of killing it: the object still constructs,
  :meth:`availability` reports what is gone, and the affected operations return
  ``False`` / a failed :class:`~aegis.models.ActionResult` after publishing a
  Polish warning on the bus.
* **Threading.**  Long jobs (scan, database update) run on worker threads owned
  by this class.  Mutable controller state is guarded by one re-entrant lock;
  engine calls themselves happen outside the lock so a running scan never
  blocks :meth:`dashboard`.  The UI thread only ever calls short, locked
  methods and drains :meth:`EventBus.listen` - it never touches an engine
  object from a worker callback.
"""

from __future__ import annotations

import importlib
import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Sequence

from ..config import Config
from ..engine.verdict import explain
from ..events import Event, EventBus, EventType
from ..models import (
    ActionKind,
    ActionResult,
    Detection,
    DetectionLayer,
    FileVerdict,
    Indicator,
    QuarantineEntry,
    Severity,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..core.scanner import ScanResult

__all__ = [
    "AegisController",
    "SEVERITY_LABELS_PL",
    "LAYER_LABELS_PL",
    "ACTION_LABELS_PL",
    "STATUS_PROTECTED",
    "STATUS_WARNING",
    "STATUS_THREAT",
    "SETTINGS_FIELDS",
]

# --------------------------------------------------------------------------
# Presentation vocabulary (Polish).  Kept next to the logic so that the widget
# layer stays dumb and so that the CLI and the GUI always agree on wording.
# --------------------------------------------------------------------------
STATUS_PROTECTED = "protected"
STATUS_WARNING = "warning"
STATUS_THREAT = "threat"

STATUS_LABELS_PL: dict[str, str] = {
    STATUS_PROTECTED: "Chroniony",
    STATUS_WARNING: "Uwaga",
    STATUS_THREAT: "Zagrożenie",
}

SEVERITY_LABELS_PL: dict[Severity, str] = {
    Severity.CLEAN: "czysty",
    Severity.LOW: "niski",
    Severity.MEDIUM: "średni",
    Severity.HIGH: "wysoki",
    Severity.CRITICAL: "krytyczny",
}

LAYER_LABELS_PL: dict[DetectionLayer, str] = {
    DetectionLayer.SIGNATURE: "sygnatura",
    DetectionLayer.HEURISTIC: "heurystyka",
    DetectionLayer.INTEL: "intel",
    DetectionLayer.BEHAVIOR: "behawior",
}

ACTION_LABELS_PL: dict[ActionKind, str] = {
    ActionKind.NONE: "brak",
    ActionKind.REPORT: "tylko zgłoś",
    ActionKind.QUARANTINE: "kwarantanna",
    ActionKind.DELETE: "usuń plik",
    ActionKind.KILL_PROCESS: "zabij proces",
    ActionKind.RESTORE: "przywróć",
}

#: Human label for every subsystem, used in degraded-mode messages.
SUBSYSTEM_LABELS_PL: dict[str, str] = {
    "db": "baza sygnatur",
    "scanner": "skaner plików",
    "quarantine": "kwarantanna",
    "behavior": "silnik behawioralny",
    "responder": "moduł reakcji",
    "monitor": "monitor plików",
    "procmon": "monitor procesów",
    "updater": "aktualizacja bazy wirusów",
}

_MB = 1024 * 1024

#: Declarative description of the settings the UI exposes.  ``app.py`` renders
#: this list; :meth:`AegisController.apply_settings` validates it.  Keeping the
#: schema here means the settings tab is covered by headless tests.
SETTINGS_FIELDS: list[dict[str, Any]] = [
    {
        "key": "realtime_action",
        "label": "Akcja przy wykryciu (czas rzeczywisty)",
        "kind": "choice",
        "choices": [
            (ActionKind.REPORT.value, ACTION_LABELS_PL[ActionKind.REPORT]),
            (ActionKind.QUARANTINE.value, ACTION_LABELS_PL[ActionKind.QUARANTINE]),
            (ActionKind.DELETE.value, ACTION_LABELS_PL[ActionKind.DELETE]),
        ],
    },
    {
        "key": "behavior_action",
        "label": "Akcja przy wykryciu behawioralnym",
        "kind": "choice",
        "choices": [
            (ActionKind.REPORT.value, ACTION_LABELS_PL[ActionKind.REPORT]),
            (ActionKind.QUARANTINE.value, ACTION_LABELS_PL[ActionKind.QUARANTINE]),
            (ActionKind.KILL_PROCESS.value, ACTION_LABELS_PL[ActionKind.KILL_PROCESS]),
        ],
    },
    {
        "key": "realtime_min_severity",
        "label": "Reaguj od poziomu",
        "kind": "choice",
        "choices": [
            (Severity.LOW.value, SEVERITY_LABELS_PL[Severity.LOW]),
            (Severity.MEDIUM.value, SEVERITY_LABELS_PL[Severity.MEDIUM]),
            (Severity.HIGH.value, SEVERITY_LABELS_PL[Severity.HIGH]),
            (Severity.CRITICAL.value, SEVERITY_LABELS_PL[Severity.CRITICAL]),
        ],
    },
    {
        "key": "max_file_size",
        "label": "Maksymalny rozmiar pliku (MB)",
        "kind": "int",
        "scale": _MB,
        "min": 1,
        "max": 8192,
    },
    {"key": "scan_threads", "label": "Liczba wątków skanowania", "kind": "int", "min": 1, "max": 64},
    {"key": "scan_archives", "label": "Skanuj archiwa (zip/tar)", "kind": "bool"},
    {
        "key": "archive_max_depth",
        "label": "Maksymalna głębokość archiwów",
        "kind": "int",
        "min": 0,
        "max": 8,
    },
    {"key": "use_scan_cache", "label": "Używaj pamięci podręcznej skanowania", "kind": "bool"},
    {"key": "behavior_enabled", "label": "Analiza behawioralna", "kind": "bool"},
    {"key": "procmon_enabled", "label": "Monitor procesów", "kind": "bool"},
    {
        "key": "behavior_mass_ops_threshold",
        "label": "Próg operacji masowych",
        "kind": "int",
        "min": 2,
        "max": 10_000,
    },
    {
        "key": "behavior_entropy_threshold",
        "label": "Próg entropii (0-8)",
        "kind": "float",
        "min": 0.0,
        "max": 8.0,
    },
    {"key": "auto_update_on_start", "label": "Aktualizuj bazę przy starcie", "kind": "bool"},
    {
        "key": "update_interval_hours",
        "label": "Odstęp aktualizacji (godziny)",
        "kind": "float",
        "min": 0.5,
        "max": 720.0,
    },
    {
        "key": "excluded_paths",
        "label": "Wykluczone ścieżki (jedna na wiersz)",
        "kind": "list",
    },
    {
        "key": "language",
        "label": "Język interfejsu",
        "kind": "choice",
        "choices": [("pl", "polski"), ("en", "angielski")],
    },
    {
        "key": "theme",
        "label": "Motyw",
        "kind": "choice",
        "choices": [("dark", "ciemny"), ("light", "jasny")],
    },
]

_ROOT_PACKAGE = (__package__ or "aegis.gui").rsplit(".", 1)[0] or "aegis"


def _import_module(relative: str) -> Any | None:
    """Import ``aegis.<relative>``; return ``None`` if it is missing or broken.

    Agents A/B/C may not have landed their packages yet, and optional third
    party extras may be absent, so *any* exception has to degrade gracefully -
    not only :class:`ImportError`.
    """
    try:
        return importlib.import_module(f"{_ROOT_PACKAGE}.{relative}")
    except Exception:  # noqa: BLE001 - a broken subsystem must not kill the UI
        return None


def _safe_bool(value: Any) -> bool:
    """Read a possibly-property-backed flag without ever raising."""
    try:
        return bool(value)
    except Exception:  # noqa: BLE001
        return False


def _fmt_timestamp(value: float | None) -> str:
    if not value:
        return "nigdy"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(value)))
    except (OSError, OverflowError, ValueError):
        return "nieznana"


def _fmt_size(size: int | float | None) -> str:
    try:
        value = float(size or 0)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def detection_from_dict(data: dict[str, Any]) -> Detection | None:
    """Rebuild a :class:`Detection` from its ``to_dict()`` form.

    Needed because quarantine entries and bus payloads carry detections as
    plain dictionaries, while :func:`aegis.engine.verdict.explain` wants
    objects.
    """
    if not isinstance(data, dict):
        return None
    try:
        indicator = data.get("indicator")
        return Detection(
            layer=DetectionLayer(data.get("layer", DetectionLayer.HEURISTIC)),
            rule=str(data.get("rule", "?")),
            threat_name=str(data.get("threat_name", "")),
            score=float(data.get("score", 0.0) or 0.0),
            confidence=float(data.get("confidence", 1.0)),
            detail=str(data.get("detail", "") or ""),
            path=data.get("path"),
            pid=data.get("pid"),
            indicator=Indicator.from_dict(indicator) if isinstance(indicator, dict) else None,
            timestamp=float(data.get("timestamp", 0.0) or time.time()),
        )
    except Exception:  # noqa: BLE001 - malformed payloads are not fatal
        return None


def detections_from_dicts(items: Iterable[Any]) -> list[Detection]:
    out: list[Detection] = []
    for item in items or ():
        if isinstance(item, Detection):
            out.append(item)
            continue
        rebuilt = detection_from_dict(item)
        if rebuilt is not None:
            out.append(rebuilt)
    return out


class _FallbackToken:
    """Stand-in for ``aegis.core.scanner.CancellationToken``.

    Used when the scanner package is unavailable (or does not export the
    token), so cancellation semantics are identical either way.
    """

    __slots__ = ("_event",)

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


class AegisController:
    """Owns the lifecycle of every engine object and all UI-facing logic."""

    #: Events drained per GUI tick is bounded by the view; the controller keeps
    #: its own bounded buffers so a flood can never grow without limit.
    MAX_ROWS = 5000
    MAX_ALERTS = 400
    DB_STATS_TTL = 2.0

    def __init__(self, config: Config | None = None, bus: EventBus | None = None) -> None:
        self.config: Config = config or Config.load()
        self.bus: EventBus = bus or EventBus()

        self._lock = threading.RLock()
        self._scan_thread: threading.Thread | None = None
        self._update_thread: threading.Thread | None = None
        self._tasks: list[threading.Thread] = []
        self._token: Any | None = None
        self._last_scan: Any | None = None
        self._shutdown = False

        self._rows: list[dict[str, Any]] = []
        self._row_index: dict[str, int] = {}
        self._row_cursor = 0
        self._verdicts: dict[str, FileVerdict] = {}
        self._alerts: deque[dict[str, Any]] = deque(maxlen=self.MAX_ALERTS)
        self._outstanding: dict[str, str] = {}
        self._counts: dict[str, int] = {
            "scanned": 0,
            "threats": 0,
            "quarantined": 0,
            "deleted": 0,
            "behavior_alerts": 0,
            "actions": 0,
        }
        self._progress: dict[str, Any] = self._blank_progress()
        self._update_results: list[Any] = []
        self._quarantine_cache: list[QuarantineEntry] | None = None
        self._db_stats_cache: tuple[float, dict[str, Any]] | None = None
        self._errors: dict[str, str] = {}

        # Subsystems (any of them may legitimately be ``None``).
        self.db: Any | None = None
        self.scanner: Any | None = None
        self.quarantine: Any | None = None
        self.behavior: Any | None = None
        self.responder: Any | None = None
        self.monitor: Any | None = None
        self.procmon: Any | None = None
        self.updater: Any | None = None
        self._token_factory: Any | None = None

        try:
            self.config.ensure_dirs()
        except OSError as exc:
            self._errors["config"] = str(exc)

        self._bus_token = self.bus.subscribe(self._on_event)
        self._build_subsystems()

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _blank_progress() -> dict[str, Any]:
        return {
            "running": False,
            "current": "",
            "done": 0,
            "total": None,
            "estimated": False,
            "percent": 0.0,
            "threats": 0,
            "started_at": None,
            "finished_at": None,
            "cancelled": False,
            "paths": [],
        }

    def _build_subsystems(self) -> None:
        """Instantiate everything that is available, remember what is not."""
        signatures = _import_module("core.signatures")
        heuristics_mod = _import_module("core.heuristics")
        scanner_mod = _import_module("core.scanner")
        quarantine_mod = _import_module("core.quarantine")
        baseline_mod = _import_module("intel.baseline")
        feeds_mod = _import_module("intel.feeds")
        behavior_mod = _import_module("realtime.behavior")
        responder_mod = _import_module("realtime.responder")
        watcher_mod = _import_module("realtime.watcher")
        procmon_mod = _import_module("realtime.procmon")

        self._heuristics = heuristics_mod
        self._feeds_mod = feeds_mod

        self.db = self._make("db", signatures, "SignatureDB", lambda cls: cls(self.config.db_path, bus=self.bus))
        if self.db is not None and baseline_mod is not None:
            try:
                added = baseline_mod.ensure_baseline(self.db)
                if added:
                    self.bus.publish(
                        EventType.DB_LOADED,
                        f"Wczytano wbudowane sygnatury: {added}.",
                        level="info",
                        added=added,
                    )
            except Exception as exc:  # noqa: BLE001
                self._errors["baseline"] = str(exc)

        if scanner_mod is not None:
            self._token_factory = getattr(scanner_mod, "CancellationToken", None)
        if self.db is not None:
            self.scanner = self._make(
                "scanner", scanner_mod, "Scanner", lambda cls: cls(self.db, self.config, bus=self.bus)
            )
        else:
            self._errors.setdefault("scanner", "brak bazy sygnatur")

        self.quarantine = self._make(
            "quarantine", quarantine_mod, "Quarantine", lambda cls: cls(self.config, bus=self.bus)
        )
        self.behavior = self._make(
            "behavior",
            behavior_mod,
            "BehaviorEngine",
            lambda cls: cls(self.config, bus=self.bus, db=self.db),
        )
        if self.quarantine is not None:
            self.responder = self._make(
                "responder",
                responder_mod,
                "Responder",
                lambda cls: cls(self.config, self.bus, self.quarantine),
            )
        else:
            self._errors.setdefault("responder", "brak kwarantanny")

        if self.scanner is not None:
            self.monitor = self._make(
                "monitor",
                watcher_mod,
                "RealtimeMonitor",
                lambda cls: cls(
                    self.scanner,
                    self.config,
                    self.bus,
                    quarantine=self.quarantine,
                    behavior=self.behavior,
                    responder=self.responder,
                ),
            )
        else:
            self._errors.setdefault("monitor", "brak skanera")

        if self.behavior is not None:
            self.procmon = self._make(
                "procmon",
                procmon_mod,
                "ProcessMonitor",
                lambda cls: cls(self.config, self.bus, self.behavior, db=self.db),
            )
        else:
            self._errors.setdefault("procmon", "brak silnika behawioralnego")

        if self.db is not None:
            self.updater = self._make(
                "updater", feeds_mod, "IntelUpdater", lambda cls: cls(self.db, self.config, bus=self.bus)
            )
        else:
            self._errors.setdefault("updater", "brak bazy sygnatur")

        missing = self.missing_subsystems()
        if missing:
            names = ", ".join(SUBSYSTEM_LABELS_PL.get(key, key) for key in missing)
            self.bus.publish(
                EventType.LOG,
                f"Tryb ograniczony — niedostępne moduły: {names}.",
                level="warning",
                missing=missing,
            )

    def _make(self, key: str, module: Any | None, attr: str, factory: Any) -> Any | None:
        """Build one subsystem, recording why it could not be built."""
        if module is None:
            self._errors.setdefault(key, f"nie zaimportowano {attr}")
            return None
        cls = getattr(module, attr, None)
        if cls is None:
            self._errors.setdefault(key, f"moduł nie udostępnia {attr}")
            return None
        try:
            return factory(cls)
        except Exception as exc:  # noqa: BLE001
            self._errors[key] = f"{type(exc).__name__}: {exc}"
            return None

    # ------------------------------------------------------------------
    # Availability / degraded mode
    # ------------------------------------------------------------------
    def availability(self) -> dict[str, bool]:
        """Which subsystems are live.  Rendered by the dashboard."""
        return {
            "db": self.db is not None,
            "scanner": self.scanner is not None,
            "quarantine": self.quarantine is not None,
            "behavior": self.behavior is not None,
            "responder": self.responder is not None,
            "monitor": self.monitor is not None,
            "procmon": self.procmon is not None,
            "updater": self.updater is not None,
        }

    def missing_subsystems(self) -> list[str]:
        return [key for key, ok in self.availability().items() if not ok]

    def subsystem_errors(self) -> dict[str, str]:
        with self._lock:
            return dict(self._errors)

    @property
    def degraded(self) -> bool:
        return bool(self.missing_subsystems())

    def _warn(self, message: str, **payload: Any) -> None:
        """Publish a Polish warning for the log tab / CLI."""
        self.bus.publish(EventType.LOG, message, level="warning", **payload)

    def _unavailable(self, key: str, action: str) -> str:
        label = SUBSYSTEM_LABELS_PL.get(key, key)
        reason = self.subsystem_errors().get(key, "moduł niedostępny")
        return f"Nie można {action} — brak modułu „{label}” ({reason})."

    # ------------------------------------------------------------------
    # Bus plumbing.  NOTE: runs on the *publisher* thread - keep it cheap and
    # never publish from here (that would recurse through EventBus.emit).
    # ------------------------------------------------------------------
    def _on_event(self, event: Event) -> None:
        try:
            self._handle_event(event)
        except Exception:  # noqa: BLE001 - a bookkeeping bug must not stop the engine
            pass

    def _handle_event(self, event: Event) -> None:
        payload = event.payload if isinstance(event.payload, dict) else {}
        etype = event.type

        if etype is EventType.SCAN_FILE_DONE or etype is EventType.SCAN_PROGRESS:
            row = self._row_from_payload(payload, event.message)
            with self._lock:
                if etype is EventType.SCAN_FILE_DONE:
                    self._counts["scanned"] += 1
                    self._progress["done"] += 1
                if row:
                    self._progress["current"] = row.get("path", self._progress["current"])
                    if etype is EventType.SCAN_FILE_DONE:
                        self._remember_row(row)
                total = self._progress.get("total")
                done = self._progress.get("done", 0)
                if isinstance(total, int) and total > 0:
                    self._progress["percent"] = min(100.0, 100.0 * done / total)
            return

        if etype is EventType.THREAT_FOUND:
            row = self._row_from_payload(payload, event.message)
            with self._lock:
                self._counts["threats"] += 1
                self._progress["threats"] += 1
                if row:
                    row["result"] = "zagrożenie"
                    self._remember_row(row)
                    self._outstanding[row["path"]] = row.get("threat", "")
            return

        if etype is EventType.BEHAVIOR_ALERT:
            with self._lock:
                self._counts["behavior_alerts"] += 1
                self._alerts.append(
                    {
                        "timestamp": event.timestamp,
                        "time": _fmt_timestamp(event.timestamp),
                        "message": event.message,
                        "level": event.level,
                        "pid": payload.get("pid"),
                        "process": payload.get("process") or payload.get("name") or "",
                        "rule": payload.get("rule", ""),
                        "threat": payload.get("threat_name", "") or event.message,
                        "severity": str(payload.get("severity", "")),
                    }
                )
            return

        if etype is EventType.ACTION_TAKEN:
            kind = str(payload.get("kind", payload.get("action", "")))
            target = str(payload.get("target", payload.get("path", "")))
            ok = payload.get("ok", True)
            with self._lock:
                self._counts["actions"] += 1
                if ok and kind == ActionKind.QUARANTINE.value:
                    self._counts["quarantined"] += 1
                    self._quarantine_cache = None
                if ok and kind == ActionKind.DELETE.value:
                    self._counts["deleted"] += 1
                if ok and target:
                    self._outstanding.pop(target, None)
            return

        if etype is EventType.QUARANTINE_CHANGED:
            with self._lock:
                self._quarantine_cache = None
            return

        if etype in (EventType.DB_UPDATE_FINISHED, EventType.DB_LOADED):
            with self._lock:
                self._db_stats_cache = None
            return

    def _remember_row(self, row: dict[str, Any]) -> None:
        """Insert or upgrade one result row (caller holds the lock)."""
        path = row.get("path") or ""
        if not path:
            return
        existing = self._row_index.get(path)
        if existing is not None:
            old = self._rows[existing]
            if float(row.get("score", 0.0)) >= float(old.get("score", 0.0)):
                row["seq"] = old.get("seq", existing)
                self._rows[existing] = row
                self._row_cursor = min(self._row_cursor, existing)
            return
        if len(self._rows) >= self.MAX_ROWS:
            return
        row["seq"] = len(self._rows)
        self._row_index[path] = len(self._rows)
        self._rows.append(row)

    # ------------------------------------------------------------------
    # Row / verdict presentation
    # ------------------------------------------------------------------
    def row_from_verdict(self, verdict: FileVerdict) -> dict[str, Any]:
        """Flatten a :class:`FileVerdict` into the dict the table renders."""
        layers = sorted({d.layer for d in verdict.detections}, key=lambda layer: layer.value)
        if verdict.skipped:
            result = "pominięty"
        elif verdict.error:
            result = "błąd"
        elif verdict.is_threat:
            result = "zagrożenie"
        else:
            result = "czysty"
        return {
            "path": verdict.path,
            "name": os.path.basename(verdict.path) or verdict.path,
            "threat": verdict.threat_name or ("-" if not verdict.is_threat else "nieznane"),
            "layers": "+".join(LAYER_LABELS_PL.get(layer, layer.value) for layer in layers) or "-",
            "score": float(verdict.score),
            "severity": verdict.severity.value,
            "severity_label": SEVERITY_LABELS_PL.get(verdict.severity, verdict.severity.value),
            "result": result,
            "size": int(verdict.size or 0),
            "size_text": _fmt_size(verdict.size),
            "sha256": verdict.sha256,
            "detail": verdict.skipped or verdict.error or "",
            "is_threat": verdict.is_threat,
        }

    def _row_from_payload(self, payload: dict[str, Any], message: str = "") -> dict[str, Any] | None:
        """Build a row from whatever shape the engine put on the bus.

        The scanner is free to publish a :class:`FileVerdict`, its ``to_dict``
        form, or just a path - all three are accepted.
        """
        verdict = payload.get("verdict") or payload.get("file_verdict") or payload.get("result")
        if isinstance(verdict, FileVerdict):
            self._verdicts[verdict.path] = verdict
            return self.row_from_verdict(verdict)

        if isinstance(verdict, dict):
            data = verdict
        elif any(key in payload for key in ("path", "file", "target", "current")):
            data = payload
        else:
            return None

        path = str(data.get("path") or data.get("file") or data.get("target") or data.get("current") or "")
        if not path:
            return None
        detections = detections_from_dicts(data.get("detections") or ())
        if detections:
            self._verdicts.setdefault(
                path,
                FileVerdict(
                    path=path,
                    size=int(data.get("size", 0) or 0),
                    sha256=str(data.get("sha256", "") or ""),
                    score=float(data.get("score", 0.0) or 0.0),
                    severity=Severity(data.get("severity", Severity.CLEAN)),
                    detections=detections,
                ),
            )
        severity_raw = data.get("severity", Severity.CLEAN)
        try:
            severity = Severity(severity_raw)
        except ValueError:
            severity = Severity.CLEAN
        layers = sorted({d.layer for d in detections}, key=lambda layer: layer.value)
        threat = str(data.get("threat_name") or data.get("threat") or "")
        if not threat and detections:
            threat = max(detections, key=lambda d: d.weighted).threat_name
        is_threat = severity is not Severity.CLEAN or bool(data.get("is_threat"))
        return {
            "path": path,
            "name": os.path.basename(path) or path,
            "threat": threat or ("-" if not is_threat else message or "nieznane"),
            "layers": "+".join(LAYER_LABELS_PL.get(layer, layer.value) for layer in layers) or "-",
            "score": float(data.get("score", 0.0) or 0.0),
            "severity": severity.value,
            "severity_label": SEVERITY_LABELS_PL.get(severity, severity.value),
            "result": "zagrożenie" if is_threat else ("pominięty" if data.get("skipped") else "czysty"),
            "size": int(data.get("size", 0) or 0),
            "size_text": _fmt_size(data.get("size", 0)),
            "sha256": str(data.get("sha256", "") or ""),
            "detail": str(data.get("skipped") or data.get("error") or ""),
            "is_threat": is_threat,
        }

    def scan_rows(self) -> list[dict[str, Any]]:
        """Every row of the current/last scan."""
        with self._lock:
            return [dict(row) for row in self._rows]

    def take_new_rows(self) -> list[dict[str, Any]]:
        """Rows added since the previous call - the GUI appends these live."""
        with self._lock:
            fresh = [dict(row) for row in self._rows[self._row_cursor :]]
            self._row_cursor = len(self._rows)
            return fresh

    def clear_rows(self) -> None:
        with self._lock:
            self._rows.clear()
            self._row_index.clear()
            self._verdicts.clear()
            self._row_cursor = 0

    def verdict_for_path(self, path: str) -> FileVerdict | None:
        with self._lock:
            return self._verdicts.get(path)

    def explain_path(self, path: str) -> str:
        """The hybrid-analysis breakdown shown in the details dialog."""
        verdict = self.verdict_for_path(path)
        if verdict is None:
            return (
                "Brak szczegółów dla tego obiektu — nie zachowano wykryć.\n"
                "Uruchom skanowanie ponownie, aby odświeżyć analizę."
            )
        header = [
            f"Plik: {verdict.path}",
            f"Rozmiar: {_fmt_size(verdict.size)}",
            f"SHA-256: {verdict.sha256 or '-'}",
            f"Poziom: {SEVERITY_LABELS_PL.get(verdict.severity, verdict.severity.value)}",
            "",
            "Analiza hybrydowa — wkład poszczególnych warstw:",
            "",
        ]
        return "\n".join(header) + explain(verdict.detections)

    def explain_detections(self, detections: Iterable[Any]) -> str:
        return explain(detections_from_dicts(detections))

    def explain_quarantine_entry(self, entry_id: str) -> str:
        entry = self.quarantine_entry(entry_id)
        if entry is None:
            return "Nie znaleziono wpisu kwarantanny."
        header = [
            f"Plik: {entry.original_path}",
            f"Zagrożenie: {entry.threat_name or '-'}",
            f"Poziom: {SEVERITY_LABELS_PL.get(entry.severity, entry.severity.value)}",
            f"Rozmiar: {_fmt_size(entry.size)}",
            f"SHA-256: {entry.sha256 or '-'}",
            f"Data: {_fmt_timestamp(entry.quarantined_at)}",
            "",
        ]
        return "\n".join(header) + self.explain_detections(entry.detections)

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------
    def _new_token(self) -> Any:
        factory = self._token_factory
        if factory is not None:
            try:
                return factory()
            except Exception:  # noqa: BLE001
                pass
        return _FallbackToken()

    def quick_scan_paths(self) -> list[str]:
        """Directories a quick scan covers: the protected user folders."""
        paths = [p for p in (self.config.realtime_paths or []) if p and os.path.isdir(p)]
        if not paths:
            home = str(Path.home())
            paths = [home]
        return paths

    def full_scan_paths(self) -> list[str]:
        """Everything the OS exposes; excluded names keep /proc & co out."""
        if os.name == "nt":  # pragma: no cover - Windows only
            drives = [f"{letter}:\\" for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ"]
            found = [d for d in drives if os.path.isdir(d)]
            return found or [str(Path.home())]
        return ["/"]

    @property
    def scan_running(self) -> bool:
        with self._lock:
            thread = self._scan_thread
        return thread is not None and thread.is_alive()

    def last_scan(self) -> "ScanResult | None":
        with self._lock:
            return self._last_scan

    def scan_progress(self) -> dict[str, Any]:
        with self._lock:
            progress = dict(self._progress)
        progress["running"] = self.scan_running
        return progress

    def start_scan(self, paths: Sequence[str], *, recursive: bool = True) -> bool:
        """Spawn a scan worker.  ``False`` if a scan already runs or is impossible."""
        targets = [str(p) for p in (paths or []) if str(p).strip()]
        if not targets:
            self._warn("Nie wskazano żadnej ścieżki do skanowania.")
            return False
        if self.scanner is None:
            self._warn(self._unavailable("scanner", "rozpocząć skanowania"))
            return False
        with self._lock:
            if self._shutdown:
                return False
            if self._scan_thread is not None and self._scan_thread.is_alive():
                self._warn("Skanowanie już trwa — najpierw je zakończ lub anuluj.")
                return False
            token = self._new_token()
            self._token = token
            self._rows.clear()
            self._row_index.clear()
            self._verdicts.clear()
            self._row_cursor = 0
            self._progress = self._blank_progress()
            self._progress.update(running=True, started_at=time.time(), paths=list(targets))
            thread = threading.Thread(
                target=self._scan_worker,
                args=(targets, recursive, token),
                name="aegis-scan",
                daemon=True,
            )
            self._scan_thread = thread
        thread.start()
        return True

    def start_quick_scan(self) -> bool:
        return self.start_scan(self.quick_scan_paths(), recursive=True)

    def start_full_scan(self) -> bool:
        return self.start_scan(self.full_scan_paths(), recursive=True)

    def cancel_scan(self) -> None:
        """Ask the running scan to stop.  Safe to call when nothing runs."""
        with self._lock:
            token = self._token
            running = self._scan_thread is not None and self._scan_thread.is_alive()
            if running:
                self._progress["cancelled"] = True
        if token is not None:
            try:
                token.cancel()
            except Exception:  # noqa: BLE001
                pass
        if running:
            self.bus.publish(EventType.LOG, "Anulowanie skanowania...", level="warning")

    def wait_for_scan(self, timeout: float | None = None) -> bool:
        """Block until the scan worker finishes.  ``True`` when it is done."""
        with self._lock:
            thread = self._scan_thread
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    def _scan_worker(self, paths: list[str], recursive: bool, token: Any) -> None:
        result: Any | None = None
        try:
            total, truncated = self._estimate_total(paths, recursive, token)
            with self._lock:
                self._progress["total"] = total
                self._progress["estimated"] = truncated or total is None
            scanner = self.scanner
            if scanner is None:  # pragma: no cover - guarded by start_scan
                return
            result = scanner.scan_paths(paths, token=token, recursive=recursive)
        except Exception as exc:  # noqa: BLE001 - engine bugs must not kill the UI
            self.bus.publish(
                EventType.LOG,
                f"Skanowanie zakończone błędem: {type(exc).__name__}: {exc}",
                level="error",
            )
        finally:
            self._finish_scan(result, token)

    def _finish_scan(self, result: Any | None, token: Any) -> None:
        verdicts: list[FileVerdict] = []
        stats: Any | None = None
        if result is not None:
            verdicts = list(getattr(result, "verdicts", []) or [])
            stats = getattr(result, "stats", None)

        with self._lock:
            observed_rows = len(self._rows)
            for verdict in verdicts:
                if isinstance(verdict, FileVerdict):
                    self._verdicts[verdict.path] = verdict
                    self._remember_row(self.row_from_verdict(verdict))
            # If the engine published no per-file events, trust the stats.
            if observed_rows == 0 and stats is not None:
                scanned = int(getattr(stats, "files_scanned", 0) or 0)
                if scanned and self._progress["done"] == 0:
                    self._progress["done"] = scanned
                    self._counts["scanned"] += scanned
            threats = [v for v in verdicts if isinstance(v, FileVerdict) and v.is_threat]
            if threats and self._progress["threats"] == 0:
                self._progress["threats"] = len(threats)
                self._counts["threats"] += len(threats)
            for verdict in threats:
                self._outstanding.setdefault(verdict.path, verdict.threat_name)
            self._last_scan = result
            self._progress["running"] = False
            self._progress["finished_at"] = time.time()
            self._progress["cancelled"] = bool(
                getattr(result, "cancelled", False) or _safe_bool(getattr(token, "cancelled", False))
            )
            total = self._progress.get("total")
            if isinstance(total, int) and total > 0:
                self._progress["percent"] = min(100.0, 100.0 * self._progress["done"] / total)
            else:
                self._progress["percent"] = 100.0 if result is not None else 0.0
            done = self._progress["done"]
            found = self._progress["threats"]
            cancelled = self._progress["cancelled"]
            self._scan_thread = None

        if result is not None:
            verb = "przerwane" if cancelled else "zakończone"
            level = "warning" if found else "success"
            self.bus.publish(
                EventType.LOG,
                f"Skanowanie {verb}: przeskanowano {done} plików, "
                f"wykryto zagrożeń: {found}.",
                level=level,
                files=done,
                threats=found,
                cancelled=cancelled,
            )

    def _estimate_total(
        self,
        paths: Sequence[str],
        recursive: bool,
        token: Any,
        *,
        cap: int = 40_000,
        budget: float = 1.5,
    ) -> tuple[int | None, bool]:
        """Cheap bounded pre-count so the progress bar can be determinate.

        Returns ``(total, truncated)``.  ``truncated`` means the walk hit its
        time/entry budget, so the UI should show an indeterminate bar.
        """
        deadline = time.monotonic() + budget
        excluded = set(self.config.excluded_names or ())
        total = 0
        truncated = False
        for raw in paths:
            if _safe_bool(getattr(token, "cancelled", False)):
                return (total or None), True
            try:
                if os.path.isfile(raw):
                    total += 1
                    continue
            except OSError:
                continue
            stack = [str(raw)]
            while stack:
                if (
                    total >= cap
                    or time.monotonic() > deadline
                    or _safe_bool(getattr(token, "cancelled", False))
                ):
                    truncated = True
                    stack.clear()
                    break
                current = stack.pop()
                try:
                    with os.scandir(current) as entries:
                        for entry in entries:
                            try:
                                if entry.is_dir(follow_symlinks=False):
                                    if not recursive or entry.name in excluded:
                                        continue
                                    if self.config.is_internal(entry.path):
                                        continue
                                    stack.append(entry.path)
                                elif entry.is_file(follow_symlinks=False):
                                    total += 1
                            except OSError:
                                continue
                except OSError:
                    continue
        return (total or None), truncated

    # ------------------------------------------------------------------
    # Per-result actions
    # ------------------------------------------------------------------
    def quarantine_path(self, path: str) -> ActionResult:
        """Move one file into the vault."""
        if self.quarantine is None:
            detail = self._unavailable("quarantine", "przenieść pliku do kwarantanny")
            self._warn(detail)
            return ActionResult(kind=ActionKind.QUARANTINE, target=str(path), ok=False, detail=detail)
        verdict = self.verdict_for_path(str(path))
        try:
            result = self.quarantine.quarantine(
                path, verdict=verdict, threat_name=verdict.threat_name if verdict else ""
            )
        except Exception as exc:  # noqa: BLE001
            detail = f"Błąd kwarantanny: {type(exc).__name__}: {exc}"
            self._warn(detail)
            return ActionResult(kind=ActionKind.QUARANTINE, target=str(path), ok=False, detail=detail)
        self._after_action(result, str(path))
        return result

    def delete_path(self, path: str) -> ActionResult:
        """Remove one file from disk permanently."""
        target = str(path)
        try:
            os.remove(target)
            result = ActionResult(
                kind=ActionKind.DELETE, target=target, ok=True, detail="Plik usunięty trwale."
            )
        except OSError as exc:
            result = ActionResult(
                kind=ActionKind.DELETE, target=target, ok=False, detail=f"Nie można usunąć pliku: {exc}"
            )
        self._after_action(result, target)
        return result

    def ignore_path(self, path: str) -> ActionResult:
        """Whitelist a path: it is excluded from future scans."""
        target = str(path)
        if target not in self.config.excluded_paths:
            self.config.excluded_paths.append(target)
        result = ActionResult(
            kind=ActionKind.NONE, target=target, ok=True, detail="Dodano do wykluczeń."
        )
        self._after_action(result, target)
        return result

    def _after_action(self, result: ActionResult, target: str) -> None:
        """Publish the outcome and refresh derived state."""
        with self._lock:
            self._quarantine_cache = None
            if result.ok:
                self._outstanding.pop(target, None)
        try:
            payload = result.to_dict()
        except Exception:  # noqa: BLE001
            payload = {"kind": str(result.kind), "target": target, "ok": result.ok}
        label = ACTION_LABELS_PL.get(result.kind, str(result.kind))
        message = (
            f"Akcja '{label}' wykonana: {target}"
            if result.ok
            else f"Akcja '{label}' nieudana: {target} - {result.detail}"
        )
        self.bus.publish(
            EventType.ACTION_TAKEN,
            message,
            level="success" if result.ok else "error",
            **payload,
        )
        if result.kind is not ActionKind.NONE:
            self.bus.publish(EventType.QUARANTINE_CHANGED, "Zmieniono zawartość kwarantanny.")

    def handle_threats(self, verdicts: Sequence[FileVerdict] | None = None) -> list[ActionResult]:
        """Apply the configured response to every threat of the last scan."""
        if verdicts is None:
            result = self.last_scan()
            verdicts = [
                v
                for v in (getattr(result, "verdicts", []) or [])
                if isinstance(v, FileVerdict) and v.is_threat
            ]
        actions: list[ActionResult] = []
        for verdict in verdicts:
            if self.responder is not None:
                try:
                    actions.extend(self.responder.handle_file_threat(verdict) or [])
                    continue
                except Exception as exc:  # noqa: BLE001
                    self._warn(f"Moduł reakcji zawiódł dla {verdict.path}: {exc}")
            actions.append(self.quarantine_path(verdict.path))
        return actions

    # ------------------------------------------------------------------
    # Quarantine
    # ------------------------------------------------------------------
    def quarantine_items(self) -> list[QuarantineEntry]:
        with self._lock:
            cached = self._quarantine_cache
        if cached is not None:
            return list(cached)
        if self.quarantine is None:
            return []
        try:
            items = list(self.quarantine.list() or [])
        except Exception as exc:  # noqa: BLE001
            self._warn(f"Nie można odczytać kwarantanny: {exc}")
            return []
        items.sort(key=lambda e: e.quarantined_at, reverse=True)
        with self._lock:
            self._quarantine_cache = items
        return list(items)

    def quarantine_entry(self, entry_id: str) -> QuarantineEntry | None:
        if self.quarantine is None:
            return None
        try:
            entry = self.quarantine.get(entry_id)
        except Exception:  # noqa: BLE001
            entry = None
        if entry is not None:
            return entry
        for item in self.quarantine_items():
            if item.entry_id == entry_id:
                return item
        return None

    def quarantine_rows(self) -> list[dict[str, Any]]:
        """Table rows for the quarantine tab."""
        rows: list[dict[str, Any]] = []
        for entry in self.quarantine_items():
            rows.append(
                {
                    "entry_id": entry.entry_id,
                    "path": entry.original_path,
                    "name": os.path.basename(entry.original_path) or entry.original_path,
                    "threat": entry.threat_name or "-",
                    "severity": entry.severity.value,
                    "severity_label": SEVERITY_LABELS_PL.get(entry.severity, entry.severity.value),
                    "date": _fmt_timestamp(entry.quarantined_at),
                    "size": int(entry.size or 0),
                    "size_text": _fmt_size(entry.size),
                    "sha256": entry.sha256,
                }
            )
        return rows

    def restore(self, entry_id: str) -> ActionResult:
        if self.quarantine is None:
            detail = self._unavailable("quarantine", "przywrócić pliku")
            self._warn(detail)
            return ActionResult(kind=ActionKind.RESTORE, target=str(entry_id), ok=False, detail=detail)
        try:
            result = self.quarantine.restore(entry_id)
        except Exception as exc:  # noqa: BLE001
            detail = f"Błąd przywracania: {type(exc).__name__}: {exc}"
            self._warn(detail)
            return ActionResult(kind=ActionKind.RESTORE, target=str(entry_id), ok=False, detail=detail)
        self._after_action(result, result.target or str(entry_id))
        return result

    def delete(self, entry_id: str) -> ActionResult:
        if self.quarantine is None:
            detail = self._unavailable("quarantine", "usunąć pliku z kwarantanny")
            self._warn(detail)
            return ActionResult(kind=ActionKind.DELETE, target=str(entry_id), ok=False, detail=detail)
        try:
            result = self.quarantine.delete(entry_id)
        except Exception as exc:  # noqa: BLE001
            detail = f"Błąd usuwania: {type(exc).__name__}: {exc}"
            self._warn(detail)
            return ActionResult(kind=ActionKind.DELETE, target=str(entry_id), ok=False, detail=detail)
        self._after_action(result, result.target or str(entry_id))
        return result

    def purge_quarantine(self) -> int:
        if self.quarantine is None:
            self._warn(self._unavailable("quarantine", "wyczyścić kwarantanny"))
            return 0
        try:
            removed = int(self.quarantine.purge_all() or 0)
        except Exception as exc:  # noqa: BLE001
            self._warn(f"Nie można wyczyścić kwarantanny: {exc}")
            return 0
        with self._lock:
            self._quarantine_cache = None
        self.bus.publish(
            EventType.QUARANTINE_CHANGED,
            f"Kwarantanna wyczyszczona — usunięto {removed} wpisów.",
            level="success",
            removed=removed,
        )
        return removed

    def rescan_quarantine_entry(self, entry_id: str) -> FileVerdict | None:
        """Re-analyse a vaulted sample without restoring it to disk."""
        if self.quarantine is None or self.scanner is None:
            self._warn(self._unavailable("scanner", "przeskanować wpisu kwarantanny"))
            return None
        entry = self.quarantine_entry(entry_id)
        if entry is None:
            self._warn(f"Nie znaleziono wpisu kwarantanny: {entry_id}")
            return None
        try:
            payload = self.quarantine.read_payload(entry_id)
            verdict = self.scanner.scan_bytes(payload, entry.original_path)
        except Exception as exc:  # noqa: BLE001
            self._warn(f"Nie można przeskanować wpisu {entry_id}: {exc}")
            return None
        if isinstance(verdict, FileVerdict):
            with self._lock:
                self._verdicts[verdict.path] = verdict
            self.bus.publish(
                EventType.LOG,
                f"Ponowna analiza: {entry.original_path} -> "
                f"{SEVERITY_LABELS_PL.get(verdict.severity, verdict.severity.value)} "
                f"({verdict.score:.1f}/100).",
                level="warning" if verdict.is_threat else "success",
            )
        return verdict

    # ------------------------------------------------------------------
    # Realtime protection
    # ------------------------------------------------------------------
    def set_realtime(self, enabled: bool) -> bool:
        """Turn realtime protection on/off.  Idempotent, never raises."""
        monitor = self.monitor
        procmon = self.procmon
        if enabled:
            if monitor is None:
                self._warn(self._unavailable("monitor", "włączyć ochrony w czasie rzeczywistym"))
                return False
            try:
                if not _safe_bool(getattr(monitor, "is_running", False)):
                    monitor.start(list(self.config.realtime_paths or []))
            except Exception as exc:  # noqa: BLE001
                self._warn(f"Nie można włączyć ochrony w czasie rzeczywistym: {exc}")
                return False
            if procmon is not None and self.config.procmon_enabled:
                try:
                    if not _safe_bool(getattr(procmon, "is_running", False)):
                        procmon.start()
                except Exception as exc:  # noqa: BLE001
                    self._warn(f"Nie można uruchomić monitora procesów: {exc}")
            self.config.realtime_enabled = True
            return True

        ok = True
        if monitor is not None:
            try:
                if _safe_bool(getattr(monitor, "is_running", False)):
                    monitor.stop()
            except Exception as exc:  # noqa: BLE001
                self._warn(f"Nie można zatrzymać ochrony w czasie rzeczywistym: {exc}")
                ok = False
        if procmon is not None:
            try:
                if _safe_bool(getattr(procmon, "is_running", False)):
                    procmon.stop()
            except Exception as exc:  # noqa: BLE001
                self._warn(f"Nie można zatrzymać monitora procesów: {exc}")
                ok = False
        self.config.realtime_enabled = False
        return ok

    @property
    def realtime_running(self) -> bool:
        monitor = self.monitor
        return monitor is not None and _safe_bool(getattr(monitor, "is_running", False))

    def realtime_status(self) -> dict[str, Any]:
        """Everything the realtime tab shows."""
        monitor = self.monitor
        status: dict[str, Any] = {}
        if monitor is not None:
            try:
                raw = monitor.status()
                if isinstance(raw, dict):
                    status = dict(raw)
            except Exception:  # noqa: BLE001
                status = {}
        running = self.realtime_running
        status.setdefault("backend", getattr(monitor, "backend", "brak") if monitor else "brak")
        status.setdefault("paths", list(self.config.realtime_paths or []))
        status.update(
            {
                "available": monitor is not None,
                "running": running,
                "enabled": bool(self.config.realtime_enabled),
                "min_severity": self.config.realtime_min_severity,
                "action": self.config.realtime_action.value,
                "action_label": ACTION_LABELS_PL.get(
                    self.config.realtime_action, self.config.realtime_action.value
                ),
            }
        )
        return status

    def procmon_status(self) -> dict[str, Any]:
        procmon = self.procmon
        status: dict[str, Any] = {}
        if procmon is not None:
            try:
                raw = procmon.status()
                if isinstance(raw, dict):
                    status = dict(raw)
            except Exception:  # noqa: BLE001
                status = {}
        status.setdefault("backend", getattr(procmon, "backend", "brak") if procmon else "brak")
        status.update(
            {
                "available": procmon is not None,
                "running": procmon is not None and _safe_bool(getattr(procmon, "is_running", False)),
                "enabled": bool(self.config.procmon_enabled),
            }
        )
        return status

    def behavior_status(self) -> dict[str, Any]:
        engine = self.behavior
        verdicts: list[Any] = []
        if engine is not None:
            try:
                verdicts = list(engine.verdicts() or [])
            except Exception:  # noqa: BLE001
                verdicts = []
        threats = [v for v in verdicts if _safe_bool(getattr(v, "is_threat", False))]
        with self._lock:
            alerts = self._counts["behavior_alerts"]
        return {
            "available": engine is not None,
            "enabled": bool(self.config.behavior_enabled),
            "rules": len(self.behavior_rules()),
            "tracked": len(verdicts),
            "threats": len(threats),
            "alerts": alerts,
            "window_sec": self.config.behavior_window_sec,
            "mass_ops_threshold": self.config.behavior_mass_ops_threshold,
            "entropy_threshold": self.config.behavior_entropy_threshold,
        }

    def behavior_rules(self) -> list[dict[str, Any]]:
        engine = self.behavior
        if engine is None:
            return []
        try:
            return [dict(rule) for rule in (engine.rules() or []) if isinstance(rule, dict)]
        except Exception:  # noqa: BLE001
            return []

    def behavior_verdicts(self) -> list[dict[str, Any]]:
        engine = self.behavior
        if engine is None:
            return []
        try:
            raw = list(engine.verdicts() or [])
        except Exception:  # noqa: BLE001
            return []
        rows: list[dict[str, Any]] = []
        for verdict in raw:
            try:
                rows.append(
                    {
                        "pid": getattr(verdict, "pid", None),
                        "process": getattr(verdict, "process", "") or "(nieprzypisane)",
                        "threat": verdict.threat_name or "-",
                        "score": float(getattr(verdict, "score", 0.0) or 0.0),
                        "severity": str(getattr(verdict, "severity", Severity.CLEAN)),
                        "events": int(getattr(verdict, "event_count", 0) or 0),
                    }
                )
            except Exception:  # noqa: BLE001
                continue
        return rows

    def recent_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._alerts)
        return items[-limit:]

    def add_realtime_path(self, path: str) -> bool:
        target = str(path).strip()
        if not target:
            return False
        if not os.path.isdir(target):
            self._warn(f"Ścieżka nie jest katalogiem: {target}")
            return False
        if target in self.config.realtime_paths:
            return False
        self.config.realtime_paths.append(target)
        self.bus.publish(
            EventType.LOG, f"Dodano katalog do ochrony: {target}", level="info", path=target
        )
        if self.realtime_running:
            self.set_realtime(False)
            self.set_realtime(True)
        return True

    def remove_realtime_path(self, path: str) -> bool:
        target = str(path)
        if target not in self.config.realtime_paths:
            return False
        self.config.realtime_paths.remove(target)
        self.bus.publish(
            EventType.LOG, f"Usunięto katalog z ochrony: {target}", level="info", path=target
        )
        if self.realtime_running:
            self.set_realtime(False)
            self.set_realtime(True)
        return True

    # ------------------------------------------------------------------
    # Virus database / threat intel
    # ------------------------------------------------------------------
    def db_version(self) -> str:
        if self.db is None:
            return "brak"
        try:
            return str(self.db.version())
        except Exception:  # noqa: BLE001
            return "nieznana"

    def db_stats(self) -> dict[str, Any]:
        """Cached snapshot of the signature database (dashboard polls it)."""
        now = time.monotonic()
        with self._lock:
            cached = self._db_stats_cache
            if cached is not None and now - cached[0] < self.DB_STATS_TTL:
                return dict(cached[1])
        if self.db is None:
            stats = {"total": 0, "by_kind": {}, "by_source": {}, "version": "brak"}
        else:
            try:
                raw = self.db.stats()
                stats = dict(raw) if isinstance(raw, dict) else {}
            except Exception as exc:  # noqa: BLE001
                stats = {"total": 0, "by_kind": {}, "by_source": {}, "version": "nieznana", "error": str(exc)}
        stats.setdefault("total", 0)
        stats.setdefault("by_kind", {})
        stats.setdefault("by_source", {})
        stats.setdefault("version", self.db_version())
        with self._lock:
            self._db_stats_cache = (now, dict(stats))
        return stats

    def db_last_update(self) -> float | None:
        if self.updater is None:
            return None
        try:
            value = self.updater.last_update()
            return float(value) if value else None
        except Exception:  # noqa: BLE001
            return None

    def feeds(self) -> list[dict[str, Any]]:
        """Rows for the virus-database tab."""
        if self.updater is None:
            return []
        try:
            raw = self.updater.available() or []
        except Exception as exc:  # noqa: BLE001
            self._warn(f"Nie można odczytać listy źródeł: {exc}")
            return []
        enabled = set(self.config.feeds_enabled or ())
        rows: list[dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            row = dict(item)
            feed_id = str(row.get("id") or row.get("feed_id") or row.get("name") or "")
            row["id"] = feed_id
            row.setdefault("name", feed_id)
            row["enabled"] = bool(row.get("enabled", feed_id in enabled))
            row.setdefault("source", row.get("url", ""))
            row.setdefault("indicators", row.get("count", 0))
            last = row.get("last_update") or row.get("last_updated") or row.get("updated_at")
            row["last_update"] = last
            row["last_update_text"] = _fmt_timestamp(last if isinstance(last, (int, float)) else None)
            row.setdefault("status", "nieaktualne" if not last else "aktualne")
            rows.append(row)
        return rows

    def set_feed_enabled(self, feed_id: str, enabled: bool) -> None:
        feeds = self.config.feeds_enabled
        if enabled and feed_id not in feeds:
            feeds.append(feed_id)
        elif not enabled and feed_id in feeds:
            feeds.remove(feed_id)

    @property
    def update_running(self) -> bool:
        with self._lock:
            thread = self._update_thread
        return thread is not None and thread.is_alive()

    def update_database(self, feed_ids: Sequence[str] | None = None, *, force: bool = False) -> bool:
        """Pull threat-intel feeds on a worker thread.

        ``force`` is a controller-level extension used by ``aegis update
        --force``; it is forwarded to :meth:`IntelUpdater.update`.
        """
        if self.updater is None:
            self._warn(self._unavailable("updater", "zaktualizować bazy wirusów"))
            return False
        with self._lock:
            if self._shutdown:
                return False
            if self._update_thread is not None and self._update_thread.is_alive():
                self._warn("Aktualizacja bazy już trwa.")
                return False
            ids = list(feed_ids) if feed_ids else None
            thread = threading.Thread(
                target=self._update_worker,
                args=(ids, bool(force)),
                name="aegis-update",
                daemon=True,
            )
            self._update_thread = thread
        thread.start()
        return True

    def _update_worker(self, feed_ids: list[str] | None, force: bool = False) -> None:
        results: list[Any] = []
        try:
            results = list(self.updater.update(feed_ids, force=force) or [])
        except Exception as exc:  # noqa: BLE001
            self.bus.publish(
                EventType.LOG,
                f"Aktualizacja bazy nie udała się: {type(exc).__name__}: {exc}",
                level="error",
            )
        finally:
            added = sum(int(getattr(r, "added", 0) or 0) for r in results)
            updated = sum(int(getattr(r, "updated", 0) or 0) for r in results)
            failed = [getattr(r, "feed_id", "?") for r in results if not _safe_bool(getattr(r, "ok", False))]
            with self._lock:
                self._update_results = results
                self._update_thread = None
                self._db_stats_cache = None
            message = f"Aktualizacja bazy zakończona: nowych {added}, zmienionych {updated}."
            if failed:
                message += f" Nieudane źródła: {', '.join(failed)}."
            self.bus.publish(
                EventType.LOG,
                message,
                level="warning" if failed else "success",
                added=added,
                updated=updated,
                failed=failed,
            )

    def wait_for_update(self, timeout: float | None = None) -> bool:
        with self._lock:
            thread = self._update_thread
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    def last_update_results(self) -> list[Any]:
        with self._lock:
            return list(self._update_results)

    def export_database(self, path: str) -> int:
        if self.db is None:
            self._warn(self._unavailable("db", "wyeksportować bazy"))
            return 0
        try:
            count = int(self.db.export_json(path) or 0)
        except Exception as exc:  # noqa: BLE001
            self._warn(f"Eksport bazy nie udał się: {exc}")
            return 0
        self.bus.publish(
            EventType.LOG, f"Wyeksportowano {count} wskaźników do {path}.", level="success"
        )
        return count

    def import_database(self, path: str) -> tuple[int, int]:
        if self.db is None:
            self._warn(self._unavailable("db", "zaimportować bazy"))
            return (0, 0)
        try:
            added, updated = self.db.import_json(path)
        except Exception as exc:  # noqa: BLE001
            self._warn(f"Import bazy nie udał się: {exc}")
            return (0, 0)
        with self._lock:
            self._db_stats_cache = None
        self.bus.publish(
            EventType.LOG,
            f"Zaimportowano wskaźniki z {path}: nowych {added}, zmienionych {updated}.",
            level="success",
        )
        return (int(added), int(updated))

    def heuristic_rules(self) -> list[dict[str, Any]]:
        module = getattr(self, "_heuristics", None)
        rules = getattr(module, "HEURISTIC_RULES", None) if module else None
        if not rules:
            return []
        return [dict(rule) for rule in rules if isinstance(rule, dict)]

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------
    def dashboard(self) -> dict[str, Any]:
        """One flat dict the GUI renders.  All 'am I protected' logic is here."""
        stats = self.db_stats()
        realtime = self.realtime_status()
        behavior = self.behavior_status()
        last_update = self.db_last_update()
        progress = self.scan_progress()
        with self._lock:
            counts = dict(self._counts)
            outstanding = dict(self._outstanding)
            last_scan = self._last_scan
        counts["quarantined"] = max(counts.get("quarantined", 0), len(self.quarantine_items()))
        counts["outstanding"] = len(outstanding)

        reasons: list[str] = []
        status = STATUS_PROTECTED

        if outstanding:
            status = STATUS_THREAT
            reasons.append(
                f"Nieobsłużone zagrożenia: {len(outstanding)}. Przenieś je do kwarantanny lub usuń."
            )
        if behavior["threats"]:
            status = STATUS_THREAT
            reasons.append(f"Podejrzane procesy: {behavior['threats']}.")

        warnings: list[str] = []
        missing = self.missing_subsystems()
        if missing:
            names = ", ".join(SUBSYSTEM_LABELS_PL.get(key, key) for key in missing)
            warnings.append(f"Tryb ograniczony — brak modułów: {names}.")
        if not realtime["running"]:
            warnings.append("Ochrona w czasie rzeczywistym jest wyłączona.")
        if not stats.get("total"):
            warnings.append("Baza wirusów jest pusta — zaktualizuj ją.")
        elif last_update is None:
            warnings.append("Baza wirusów nie była jeszcze aktualizowana.")
        else:
            age_hours = max(0.0, (time.time() - last_update) / 3600.0)
            if age_hours > max(1.0, float(self.config.update_interval_hours) * 2):
                warnings.append(
                    f"Baza wirusów jest przestarzała (ostatnia aktualizacja {age_hours / 24:.1f} dni temu)."
                )
        if not behavior["enabled"] or not behavior["available"]:
            warnings.append("Analiza behawioralna jest nieaktywna.")

        if status is not STATUS_THREAT and warnings:
            status = STATUS_WARNING
        reasons.extend(warnings)
        if status is STATUS_PROTECTED:
            reasons.append("Wszystkie moduły ochrony działają poprawnie.")

        last_scan_info: dict[str, Any] | None = None
        if last_scan is not None:
            scan_stats = getattr(last_scan, "stats", None)
            verdicts = getattr(last_scan, "verdicts", []) or []
            threats = [v for v in verdicts if isinstance(v, FileVerdict) and v.is_threat]
            finished = getattr(scan_stats, "finished_at", None) if scan_stats else None
            last_scan_info = {
                "files_scanned": int(getattr(scan_stats, "files_scanned", len(verdicts)) or 0),
                "files_skipped": int(getattr(scan_stats, "files_skipped", 0) or 0),
                "threats_found": int(getattr(scan_stats, "threats_found", len(threats)) or 0),
                "errors": int(getattr(scan_stats, "errors", 0) or 0),
                "bytes_scanned": int(getattr(scan_stats, "bytes_scanned", 0) or 0),
                "duration": float(getattr(scan_stats, "duration", 0.0) or 0.0),
                "finished_at": finished,
                "finished_text": _fmt_timestamp(finished),
                "cancelled": _safe_bool(getattr(last_scan, "cancelled", False)),
            }

        return {
            "status": status,
            "status_label": STATUS_LABELS_PL[status],
            "status_detail": reasons[0] if reasons else "",
            "status_reasons": reasons,
            "db_version": str(stats.get("version") or self.db_version()),
            "db_indicators": int(stats.get("total") or 0),
            "db_stats": stats,
            "db_last_update": last_update,
            "db_last_update_text": _fmt_timestamp(last_update),
            "counts": counts,
            "last_scan": last_scan_info,
            "scan": progress,
            "realtime": realtime,
            "behavior": behavior,
            "procmon": self.procmon_status(),
            "degraded": bool(missing),
            "missing": missing,
            "subsystems": self.availability(),
            "data_dir": str(self.config.data_dir),
            "version": self._app_version(),
            "update_running": self.update_running,
        }

    @staticmethod
    def _app_version() -> str:
        try:
            from .. import __version__

            return str(__version__)
        except Exception:  # noqa: BLE001
            return "?"

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------
    def settings_fields(self) -> list[dict[str, Any]]:
        return [dict(field) for field in SETTINGS_FIELDS]

    def form_values(self) -> dict[str, Any]:
        """Current config rendered as form-ready values (strings / bools)."""
        values: dict[str, Any] = {}
        for field in SETTINGS_FIELDS:
            key = field["key"]
            raw = getattr(self.config, key, None)
            kind = field["kind"]
            if kind == "bool":
                values[key] = bool(raw)
            elif kind == "list":
                values[key] = "\n".join(str(item) for item in (raw or []))
            elif kind == "int":
                scale = int(field.get("scale", 1) or 1)
                values[key] = str(int(raw or 0) // scale)
            elif kind == "float":
                values[key] = f"{float(raw or 0.0):g}"
            else:
                values[key] = str(getattr(raw, "value", raw) or "")
        return values

    def apply_settings(self, values: dict[str, Any]) -> tuple[bool, list[str]]:
        """Validate and apply a settings form.  Returns ``(ok, errors_pl)``."""
        errors: list[str] = []
        staged: dict[str, Any] = {}
        for field in SETTINGS_FIELDS:
            key = field["key"]
            if key not in values:
                continue
            raw = values[key]
            label = field["label"]
            kind = field["kind"]
            try:
                if kind == "bool":
                    staged[key] = bool(raw)
                elif kind == "list":
                    if isinstance(raw, (list, tuple)):
                        items = [str(item).strip() for item in raw]
                    else:
                        items = [line.strip() for line in str(raw).splitlines()]
                    staged[key] = [item for item in items if item]
                elif kind == "int":
                    scale = int(field.get("scale", 1) or 1)
                    number = int(float(str(raw).strip().replace(",", ".")))
                    if number < int(field.get("min", 0)) or number > int(field.get("max", 1 << 40)):
                        errors.append(
                            f"{label}: wartość musi być w zakresie "
                            f"{field.get('min', 0)}-{field.get('max', '?')}."
                        )
                        continue
                    staged[key] = number * scale
                elif kind == "float":
                    number = float(str(raw).strip().replace(",", "."))
                    if number < float(field.get("min", 0.0)) or number > float(field.get("max", 1e9)):
                        errors.append(
                            f"{label}: wartość musi być w zakresie "
                            f"{field.get('min', 0)}-{field.get('max', '?')}."
                        )
                        continue
                    staged[key] = number
                else:
                    allowed = {choice[0] for choice in field.get("choices", ())}
                    text = str(getattr(raw, "value", raw))
                    if allowed and text not in allowed:
                        errors.append(f"{label}: nieznana wartość '{text}'.")
                        continue
                    if key in ("realtime_action", "behavior_action"):
                        staged[key] = ActionKind(text)
                    else:
                        staged[key] = text
            except (TypeError, ValueError):
                errors.append(f"{label}: '{raw}' nie jest poprawną wartością.")
        if errors:
            self._warn("Nie zapisano ustawień: " + " ".join(errors))
            return False, errors
        for key, value in staged.items():
            setattr(self.config, key, value)
        return True, []

    def save_config(self) -> bool:
        try:
            self.config.save()
        except OSError as exc:
            self._warn(f"Nie można zapisać konfiguracji: {exc}")
            return False
        self.bus.publish(EventType.LOG, "Ustawienia zapisane.", level="success")
        return True

    def reset_settings(self) -> dict[str, Any]:
        """Restore defaults (keeping the data directory) and return the form."""
        defaults = Config(data_dir=self.config.data_dir)
        for field in SETTINGS_FIELDS:
            key = field["key"]
            setattr(self.config, key, getattr(defaults, key))
        self.bus.publish(EventType.LOG, "Przywrócono ustawienia domyślne.", level="info")
        return self.form_values()

    # ------------------------------------------------------------------
    # Log helpers
    # ------------------------------------------------------------------
    def log_history(self, limit: int = 500, min_level: str | None = None) -> list[Event]:
        events = self.bus.history(limit=None)
        if min_level:
            order = {"info": 0, "success": 0, "warning": 1, "error": 2}
            floor = order.get(min_level, 0)
            events = [e for e in events if order.get(e.level, 0) >= floor]
        return events[-limit:]

    @staticmethod
    def format_event(event: Event) -> str:
        return f"[{_fmt_timestamp(event.timestamp)}] {event.type.value}: {event.message}"

    def export_log(self, path: str) -> bool:
        try:
            with open(path, "w", encoding="utf-8") as handle:
                for event in self.bus.history(limit=None):
                    handle.write(self.format_event(event) + "\n")
        except OSError as exc:
            self._warn(f"Nie można zapisać dziennika: {exc}")
            return False
        self.bus.publish(EventType.LOG, f"Dziennik zapisany do {path}.", level="success")
        return True

    # ------------------------------------------------------------------
    # Generic background task helper
    # ------------------------------------------------------------------
    def run_background(self, func: Any, *args: Any, label: str = "operacja", **kwargs: Any) -> bool:
        """Run one short engine call off the UI thread.

        The GUI uses this for per-row actions (quarantine, delete, rescan) and
        for the realtime switch, so that a slow filesystem can never freeze the
        Tk main loop.  Outcomes reach the UI as bus events, never as a return
        value, because the caller must not block waiting for one.
        """
        with self._lock:
            if self._shutdown:
                return False

        def worker() -> None:
            try:
                func(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001
                self.bus.publish(
                    EventType.LOG,
                    f"Operacja „{label}” nie udała się: {type(exc).__name__}: {exc}",
                    level="error",
                )

        thread = threading.Thread(target=worker, name=f"aegis-task-{label}", daemon=True)
        with self._lock:
            self._tasks = [t for t in self._tasks if t.is_alive()]
            self._tasks.append(thread)
        thread.start()
        return True

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------
    def shutdown(self) -> None:
        """Stop every thread and close the database.  Safe to call twice."""
        with self._lock:
            if self._shutdown:
                return
            self._shutdown = True
            scan_thread = self._scan_thread
            update_thread = self._update_thread
            tasks = list(self._tasks)
            token = self._token

        if token is not None:
            try:
                token.cancel()
            except Exception:  # noqa: BLE001
                pass
        self.set_realtime(False)

        for thread in [scan_thread, update_thread, *tasks]:
            if thread is not None and thread.is_alive():
                thread.join(5.0)

        try:
            self.bus.unsubscribe(self._bus_token)
        except Exception:  # noqa: BLE001
            pass
        if self.db is not None:
            try:
                self.db.close()
            except Exception:  # noqa: BLE001
                pass

    def __enter__(self) -> "AegisController":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.shutdown()
