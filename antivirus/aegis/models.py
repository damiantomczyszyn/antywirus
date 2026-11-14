"""Core data model shared by every Aegis AV subsystem.

This module is the contract between the scanning engine, the threat-intel
feeds, the realtime/behaviour monitor and the user interface.  Nothing here
performs I/O, so it is safe to import from any thread.

Scoring model (hybrid analysis)
-------------------------------
Every finding is a :class:`Detection` carrying a ``score`` in 0..100 and a
``confidence`` in 0..1.  Findings from different analysis layers (static
signature, static heuristic, threat intel, runtime behaviour) are fused by
:func:`aegis.engine.verdict.fuse` into a single score which maps onto a
:class:`Severity` through :func:`severity_for_score`.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

__all__ = [
    "Severity",
    "IndicatorKind",
    "Indicator",
    "DetectionLayer",
    "Detection",
    "FileVerdict",
    "BehaviorKind",
    "BehaviorEvent",
    "ProcessVerdict",
    "ActionKind",
    "ActionResult",
    "QuarantineEntry",
    "ScanStats",
    "FeedResult",
    "severity_for_score",
    "SEVERITY_ORDER",
    "SCORE_HASH_MATCH",
    "SCORE_PATTERN_MATCH",
    "SCORE_INTEL_NETWORK",
    "SCORE_HEURISTIC_STRONG",
    "SCORE_HEURISTIC_WEAK",
    "SCORE_BEHAVIOR_STRONG",
    "SCORE_BEHAVIOR_WEAK",
    "THRESHOLD_LOW",
    "THRESHOLD_MEDIUM",
    "THRESHOLD_HIGH",
    "THRESHOLD_CRITICAL",
]


# --------------------------------------------------------------------------
# Severity
# --------------------------------------------------------------------------
class Severity(str, Enum):
    """How bad a verdict is.  Ordered via :data:`SEVERITY_ORDER`."""

    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CLEAN: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Canonical score thresholds.  Keep every subsystem in agreement by importing
# these instead of hard-coding numbers.
THRESHOLD_LOW = 15.0
THRESHOLD_MEDIUM = 40.0
THRESHOLD_HIGH = 70.0
THRESHOLD_CRITICAL = 100.0

# Canonical per-layer score budgets.
SCORE_HASH_MATCH = 100.0       # exact known-bad hash: certain
SCORE_PATTERN_MATCH = 75.0     # byte-pattern / signature body match
SCORE_INTEL_NETWORK = 60.0     # contacted a blocklisted host/IP/URL
SCORE_HEURISTIC_STRONG = 30.0  # e.g. packed PE with no imports
SCORE_HEURISTIC_WEAK = 12.0    # e.g. double extension
SCORE_BEHAVIOR_STRONG = 55.0   # e.g. mass encryption in place
SCORE_BEHAVIOR_WEAK = 18.0     # e.g. single autostart write


def severity_for_score(score: float) -> Severity:
    """Map a fused 0..100 score onto a :class:`Severity`."""
    if score >= THRESHOLD_CRITICAL:
        return Severity.CRITICAL
    if score >= THRESHOLD_HIGH:
        return Severity.HIGH
    if score >= THRESHOLD_MEDIUM:
        return Severity.MEDIUM
    if score >= THRESHOLD_LOW:
        return Severity.LOW
    return Severity.CLEAN


# --------------------------------------------------------------------------
# Indicators of compromise (the "virus database")
# --------------------------------------------------------------------------
class IndicatorKind(str, Enum):
    """Type of a stored indicator.

    ``PATTERN`` values are hex strings that may contain ``??`` wildcard bytes,
    e.g. ``"4d5a??0003"``.  Use :meth:`Indicator.pattern_from_text` to build one
    from a plain ASCII string.
    """

    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    PATTERN = "pattern"
    URL = "url"
    DOMAIN = "domain"
    IPV4 = "ipv4"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


HASH_KINDS: frozenset[IndicatorKind] = frozenset(
    {IndicatorKind.SHA256, IndicatorKind.SHA1, IndicatorKind.MD5}
)
NETWORK_KINDS: frozenset[IndicatorKind] = frozenset(
    {IndicatorKind.URL, IndicatorKind.DOMAIN, IndicatorKind.IPV4}
)


@dataclass(frozen=True, slots=True)
class Indicator:
    """A single row of the virus database."""

    kind: IndicatorKind
    value: str
    name: str = "Unnamed.Threat"
    severity: Severity = Severity.HIGH
    source: str = "builtin"
    tags: tuple[str, ...] = ()
    description: str = ""
    added_at: float = 0.0

    def __post_init__(self) -> None:
        # Normalise so that lookups are cheap and case-insensitive.
        object.__setattr__(self, "kind", IndicatorKind(self.kind))
        object.__setattr__(self, "severity", Severity(self.severity))
        value = self.value.strip()
        if self.kind in HASH_KINDS or self.kind is IndicatorKind.PATTERN:
            value = value.lower().replace(" ", "")
        elif self.kind in (IndicatorKind.DOMAIN, IndicatorKind.IPV4):
            value = value.lower()
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "tags", tuple(self.tags))

    @staticmethod
    def pattern_from_text(text: str) -> str:
        """Encode plain text as a ``PATTERN`` value."""
        return text.encode("utf-8", "surrogateescape").hex()

    @property
    def base_score(self) -> float:
        """Default score contribution when this indicator matches."""
        if self.kind in HASH_KINDS:
            return SCORE_HASH_MATCH
        if self.kind is IndicatorKind.PATTERN:
            return SCORE_PATTERN_MATCH
        return SCORE_INTEL_NETWORK

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["kind"] = self.kind.value
        data["severity"] = self.severity.value
        data["tags"] = list(self.tags)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Indicator":
        return cls(
            kind=IndicatorKind(data["kind"]),
            value=data["value"],
            name=data.get("name", "Unnamed.Threat"),
            severity=Severity(data.get("severity", Severity.HIGH)),
            source=data.get("source", "builtin"),
            tags=tuple(data.get("tags", ())),
            description=data.get("description", ""),
            added_at=float(data.get("added_at", 0.0) or 0.0),
        )

    @property
    def key(self) -> tuple[str, str]:
        """Dedup key: an indicator is identified by its kind and value."""
        return (self.kind.value, self.value)


# --------------------------------------------------------------------------
# Detections
# --------------------------------------------------------------------------
class DetectionLayer(str, Enum):
    """Which analysis layer produced a finding.  Used by score fusion."""

    SIGNATURE = "signature"   # exact hash or byte pattern from the database
    HEURISTIC = "heuristic"   # static structural analysis
    INTEL = "intel"           # network indicator from a threat feed
    BEHAVIOR = "behavior"     # runtime behaviour rule

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass(slots=True)
class Detection:
    """One reason why something looks malicious."""

    layer: DetectionLayer
    rule: str                       # stable id, e.g. "sha256_match", "mass_encrypt"
    threat_name: str                # human facing, e.g. "Sim.Ransom.Fake"
    score: float                    # 0..100 contribution before confidence
    confidence: float = 1.0         # 0..1
    detail: str = ""
    path: str | None = None
    pid: int | None = None
    indicator: Indicator | None = None
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        self.layer = DetectionLayer(self.layer)
        self.score = max(0.0, min(100.0, float(self.score)))
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    @property
    def weighted(self) -> float:
        return self.score * self.confidence

    @property
    def source(self) -> str:
        return f"{self.layer.value}:{self.rule}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "layer": self.layer.value,
            "rule": self.rule,
            "threat_name": self.threat_name,
            "score": self.score,
            "confidence": self.confidence,
            "detail": self.detail,
            "path": self.path,
            "pid": self.pid,
            "indicator": self.indicator.to_dict() if self.indicator else None,
            "timestamp": self.timestamp,
        }


    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Detection":
        """Rebuild a Detection from :meth:`to_dict`.

        Bus payloads and quarantine metadata store detections as plain dicts,
        but :func:`aegis.engine.verdict.explain` needs objects - so the round
        trip has to exist here rather than being reinvented per consumer.
        Unknown keys are ignored and missing ones fall back to defaults, so a
        payload written by an older version still loads.
        """
        indicator = data.get("indicator")
        return cls(
            layer=DetectionLayer(data.get("layer", DetectionLayer.HEURISTIC)),
            rule=data.get("rule", "unknown"),
            threat_name=data.get("threat_name", ""),
            score=float(data.get("score", 0.0) or 0.0),
            confidence=float(data.get("confidence", 1.0) or 0.0),
            detail=data.get("detail", ""),
            path=data.get("path"),
            pid=data.get("pid"),
            indicator=Indicator.from_dict(indicator) if isinstance(indicator, dict) else None,
            timestamp=float(data.get("timestamp", 0.0) or 0.0) or time.time(),
        )


@dataclass(slots=True)
class FileVerdict:
    """Result of analysing one file."""

    path: str
    size: int = 0
    sha256: str = ""
    md5: str = ""
    score: float = 0.0
    severity: Severity = Severity.CLEAN
    detections: list[Detection] = field(default_factory=list)
    scanned_at: float = field(default_factory=time.time)
    duration_ms: float = 0.0
    error: str | None = None
    skipped: str | None = None      # reason if the file was not analysed

    @property
    def is_threat(self) -> bool:
        return self.severity is not Severity.CLEAN

    @property
    def threat_name(self) -> str:
        if not self.detections:
            return ""
        worst = max(self.detections, key=lambda d: d.weighted)
        return worst.threat_name

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "md5": self.md5,
            "score": self.score,
            "severity": self.severity.value,
            "threat_name": self.threat_name,
            "detections": [d.to_dict() for d in self.detections],
            "scanned_at": self.scanned_at,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "skipped": self.skipped,
        }


    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FileVerdict":
        """Rebuild a FileVerdict from :meth:`to_dict`.

        ``threat_name`` is intentionally not restored: it is derived from the
        detections, so storing and reloading it could contradict them.
        """
        return cls(
            path=data.get("path", ""),
            size=int(data.get("size", 0) or 0),
            sha256=data.get("sha256", ""),
            md5=data.get("md5", ""),
            score=float(data.get("score", 0.0) or 0.0),
            severity=Severity(data.get("severity", Severity.CLEAN)),
            detections=[
                Detection.from_dict(d) for d in data.get("detections", ()) if isinstance(d, dict)
            ],
            scanned_at=float(data.get("scanned_at", 0.0) or 0.0) or time.time(),
            duration_ms=float(data.get("duration_ms", 0.0) or 0.0),
            error=data.get("error"),
            skipped=data.get("skipped"),
        )


@dataclass(slots=True)
class ScanStats:
    """Aggregate counters for one scan job."""

    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    threats_found: int = 0
    errors: int = 0
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None

    @property
    def duration(self) -> float:
        return (self.finished_at or time.time()) - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "bytes_scanned": self.bytes_scanned,
            "threats_found": self.threats_found,
            "errors": self.errors,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": self.duration,
        }


# --------------------------------------------------------------------------
# Behaviour monitoring
# --------------------------------------------------------------------------
class BehaviorKind(str, Enum):
    """A raw, observed runtime event.  Rules correlate these into detections."""

    FILE_CREATE = "file_create"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    FILE_RENAME = "file_rename"
    PROCESS_START = "process_start"
    PROCESS_STOP = "process_stop"
    NET_CONNECT = "net_connect"
    AUTOSTART_WRITE = "autostart_write"
    SCRIPT_EXEC = "script_exec"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass(slots=True)
class BehaviorEvent:
    """One observation fed into the behaviour engine."""

    kind: BehaviorKind
    timestamp: float = field(default_factory=time.time)
    path: str | None = None
    old_path: str | None = None
    pid: int | None = None
    ppid: int | None = None
    process: str | None = None
    cmdline: str = ""
    remote_host: str | None = None
    remote_port: int | None = None
    size: int = 0
    entropy: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.kind = BehaviorKind(self.kind)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["kind"] = self.kind.value
        return data


@dataclass(slots=True)
class ProcessVerdict:
    """Behavioural verdict about one actor (process or the unattributed group)."""

    pid: int | None
    process: str = ""
    cmdline: str = ""
    score: float = 0.0
    severity: Severity = Severity.CLEAN
    detections: list[Detection] = field(default_factory=list)
    event_count: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    touched_paths: list[str] = field(default_factory=list)

    @property
    def is_threat(self) -> bool:
        return self.severity is not Severity.CLEAN

    @property
    def threat_name(self) -> str:
        if not self.detections:
            return ""
        return max(self.detections, key=lambda d: d.weighted).threat_name

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "process": self.process,
            "cmdline": self.cmdline,
            "score": self.score,
            "severity": self.severity.value,
            "threat_name": self.threat_name,
            "detections": [d.to_dict() for d in self.detections],
            "event_count": self.event_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "touched_paths": list(self.touched_paths),
        }


# --------------------------------------------------------------------------
# Response actions
# --------------------------------------------------------------------------
class ActionKind(str, Enum):
    """What the product did (or should do) about a threat."""

    NONE = "none"
    REPORT = "report"
    QUARANTINE = "quarantine"
    DELETE = "delete"
    KILL_PROCESS = "kill_process"
    RESTORE = "restore"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass(slots=True)
class ActionResult:
    """Outcome of a response action."""

    kind: ActionKind
    target: str
    ok: bool
    detail: str = ""
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        self.kind = ActionKind(self.kind)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "target": self.target,
            "ok": self.ok,
            "detail": self.detail,
            "timestamp": self.timestamp,
        }


@dataclass(slots=True)
class QuarantineEntry:
    """Metadata for one file sitting in the quarantine vault."""

    entry_id: str
    original_path: str
    vault_name: str
    size: int
    sha256: str
    threat_name: str
    severity: Severity = Severity.HIGH
    quarantined_at: float = field(default_factory=time.time)
    detections: list[dict[str, Any]] = field(default_factory=list)
    original_mode: int | None = None

    def __post_init__(self) -> None:
        self.severity = Severity(self.severity)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "QuarantineEntry":
        return cls(
            entry_id=data["entry_id"],
            original_path=data["original_path"],
            vault_name=data["vault_name"],
            size=int(data.get("size", 0)),
            sha256=data.get("sha256", ""),
            threat_name=data.get("threat_name", ""),
            severity=Severity(data.get("severity", Severity.HIGH)),
            quarantined_at=float(data.get("quarantined_at", 0.0) or 0.0),
            detections=list(data.get("detections", [])),
            original_mode=data.get("original_mode"),
        )


# --------------------------------------------------------------------------
# Threat intel
# --------------------------------------------------------------------------
@dataclass(slots=True)
class FeedResult:
    """Outcome of pulling one threat-intel feed."""

    feed_id: str
    ok: bool
    indicators: list[Indicator] = field(default_factory=list)
    added: int = 0
    updated: int = 0
    skipped_unchanged: bool = False
    error: str = ""
    duration_ms: float = 0.0
    fetched_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "feed_id": self.feed_id,
            "ok": self.ok,
            "count": len(self.indicators),
            "added": self.added,
            "updated": self.updated,
            "skipped_unchanged": self.skipped_unchanged,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "fetched_at": self.fetched_at,
        }
