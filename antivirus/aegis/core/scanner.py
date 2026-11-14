"""The scan pipeline.

For every file:

``stat`` -> skip checks -> read (capped) -> hashes -> known-bad hash lookup ->
byte-pattern match -> heuristics -> archive members (recursively) ->
:func:`aegis.engine.verdict.apply_to_file_verdict`.

:meth:`Scanner.iter_scan` is a generator so the GUI can stream verdicts into a
table while the walk is still running; :meth:`Scanner.scan_paths` is the
collecting wrapper.  Directory walks are spread over a
:class:`~concurrent.futures.ThreadPoolExecutor` (``config.scan_threads``) -
the work is dominated by file I/O plus C-level hashing and regex, both of which
release the GIL, so threads genuinely help.

Results arrive in completion order, *not* in walk order: never rely on the
sequence of :meth:`iter_scan`.
"""

from __future__ import annotations

import io
import json
import os
import stat as stat_module
import tempfile
import threading
import time
import zipfile
from collections.abc import Iterable, Iterator, Sequence
from concurrent import futures
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import Config
from ..engine.verdict import apply_to_file_verdict
from ..events import EventBus, EventType
from ..models import (
    SCORE_PATTERN_MATCH,
    Detection,
    DetectionLayer,
    FileVerdict,
    Indicator,
    ScanStats,
    Severity,
)
from . import heuristics
from .hashing import FileHashes, hash_bytes, hash_file
from .signatures import SignatureDB

__all__ = ["CancellationToken", "ScanResult", "Scanner"]

#: Content handed to the pattern matcher and the heuristics.  Hashes always
#: cover the whole file; only the *analysis* window is capped, so a 60 MiB
#: installer does not cost 60 MiB of regex work.
ANALYSIS_LIMIT = 24 * 1024 * 1024

#: At most ~20 progress events per second, whatever the disk does.
PROGRESS_INTERVAL = 0.05

#: Upper bound on cached verdicts kept on disk.
CACHE_MAX_ENTRIES = 20_000

# Reasons stored in ``FileVerdict.skipped``.  They are shown verbatim in the
# GUI and the CLI report, hence Polish.
_SKIP_SYMLINK = "link symboliczny"
_SKIP_INTERNAL = "dane robocze Aegis"
_SKIP_EXCLUDED = "wykluczony z skanowania"
_SKIP_TOO_BIG = "plik zbyt duży"
_SKIP_NOT_FILE = "nie jest zwykłym plikiem"
_SKIP_ERROR = "błąd odczytu"


class CancellationToken:
    """Cooperative cancellation shared between the GUI and a scan thread."""

    __slots__ = ("_event",)

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def reset(self) -> None:
        self._event.clear()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)

    def __bool__(self) -> bool:  # pragma: no cover - avoids "if token" surprises
        return True


@dataclass(slots=True)
class ScanResult:
    """Everything one finished scan job produced."""

    verdicts: list[FileVerdict]
    stats: ScanStats
    cancelled: bool = False

    @property
    def threats(self) -> list[FileVerdict]:
        return [v for v in self.verdicts if v.is_threat]

    def to_dict(self) -> dict[str, Any]:
        return {
            "stats": self.stats.to_dict(),
            "cancelled": self.cancelled,
            "threats": [v.to_dict() for v in self.threats],
            "count": len(self.verdicts),
        }


@dataclass(slots=True)
class _ArchiveBudget:
    """Shared ceiling for one archive tree, so a zip bomb cannot run away."""

    members_left: int
    bytes_left: int
    truncated: bool = False


@dataclass(slots=True)
class _Walked:
    path: Path
    skipped: str | None = None
    stat_result: os.stat_result | None = None
    error: str | None = None


class Scanner:
    """Static scanning engine."""

    def __init__(self, db: SignatureDB, config: Config, bus: EventBus | None = None) -> None:
        self.db = db
        self.config = config
        self._bus = bus
        self._cache_lock = threading.RLock()
        self._cache: dict[str, dict[str, Any]] | None = None
        self._cache_dirty = False
        self._progress_lock = threading.Lock()
        self._last_progress = 0.0

    # ------------------------------------------------------------------
    # events
    # ------------------------------------------------------------------
    def _publish(self, kind: EventType, message: str = "", level: str = "info", **payload: Any) -> None:
        if self._bus is not None:
            self._bus.publish(kind, message, level=level, **payload)

    def _maybe_progress(self, stats: ScanStats, current: str, force: bool = False) -> None:
        if self._bus is None:
            return
        now = time.monotonic()
        with self._progress_lock:
            if not force and now - self._last_progress < PROGRESS_INTERVAL:
                return
            self._last_progress = now
        self._publish(
            EventType.SCAN_PROGRESS,
            f"Przeskanowano {stats.files_scanned} plików, zagrożeń: {stats.threats_found}",
            current=current,
            files_scanned=stats.files_scanned,
            files_skipped=stats.files_skipped,
            threats_found=stats.threats_found,
            bytes_scanned=stats.bytes_scanned,
        )

    # ------------------------------------------------------------------
    # single file
    # ------------------------------------------------------------------
    def scan_file(self, path: str | os.PathLike[str], *, data: bytes | None = None) -> FileVerdict:
        """Analyse one file.  Never raises: problems land in the verdict."""
        started = time.perf_counter()
        path_obj = Path(path)
        verdict = FileVerdict(path=str(path_obj))
        stat_result: os.stat_result | None = None

        if data is None:
            decision = self._pre_check(path_obj)
            stat_result = decision.stat_result
            if decision.skipped:
                verdict.skipped = decision.skipped
                verdict.error = decision.error
                verdict.size = stat_result.st_size if stat_result else 0
                verdict.duration_ms = (time.perf_counter() - started) * 1000
                return verdict

            cached = self._cache_get(str(path_obj), stat_result)
            if cached is not None:
                cached.duration_ms = (time.perf_counter() - started) * 1000
                self._announce(cached, cached_hit=True)
                return cached

            try:
                data, hashes = self._read_and_hash(path_obj, stat_result)
            except OSError as exc:
                verdict.error = f"Nie można odczytać pliku: {exc.strerror or exc}"
                verdict.skipped = _SKIP_ERROR
                verdict.duration_ms = (time.perf_counter() - started) * 1000
                self._publish(
                    EventType.LOG,
                    f"Pomijam {path_obj}: {verdict.error}",
                    level="warning",
                    path=str(path_obj),
                )
                return verdict
        else:
            data = bytes(data)
            hashes = hash_bytes(data)

        verdict.size = hashes.size
        verdict.sha256 = hashes.sha256
        verdict.md5 = hashes.md5
        verdict.detections = self._analyse(label=str(path_obj), data=data, hashes=hashes)
        apply_to_file_verdict(verdict)
        verdict.duration_ms = (time.perf_counter() - started) * 1000

        if stat_result is not None:
            self._cache_put(str(path_obj), stat_result, verdict)
        self._announce(verdict)
        return verdict

    def scan_bytes(self, data: bytes, name: str = "<memory>") -> FileVerdict:
        """Analyse an in-memory blob (realtime hooks, archive re-checks, tests)."""
        started = time.perf_counter()
        payload = bytes(data)
        hashes = hash_bytes(payload)
        verdict = FileVerdict(
            path=name, size=hashes.size, sha256=hashes.sha256, md5=hashes.md5
        )
        verdict.detections = self._analyse(label=name, data=payload, hashes=hashes)
        apply_to_file_verdict(verdict)
        verdict.duration_ms = (time.perf_counter() - started) * 1000
        self._announce(verdict)
        return verdict

    def _safe_scan_file(self, path: Path) -> FileVerdict:
        """Pool entry point: an unexpected bug must not abort the whole scan."""
        try:
            return self.scan_file(path)
        except Exception as exc:  # noqa: BLE001
            return FileVerdict(
                path=str(path),
                error=f"Błąd wewnętrzny skanera: {type(exc).__name__}: {exc}",
                skipped=_SKIP_ERROR,
            )

    def _announce(self, verdict: FileVerdict, cached_hit: bool = False) -> None:
        if self._bus is None:
            return
        self._publish(
            EventType.SCAN_FILE_DONE,
            verdict.path,
            level="warning" if verdict.is_threat else "info",
            path=verdict.path,
            severity=verdict.severity.value,
            score=verdict.score,
            threat_name=verdict.threat_name,
            cached=cached_hit,
        )
        if verdict.is_threat:
            self._publish(
                EventType.THREAT_FOUND,
                f"{verdict.severity.value.upper()}: {verdict.threat_name} - {verdict.path}",
                level="error" if verdict.severity is Severity.CRITICAL else "warning",
                path=verdict.path,
                severity=verdict.severity.value,
                score=verdict.score,
                threat_name=verdict.threat_name,
                verdict=verdict.to_dict(),
            )

    # ------------------------------------------------------------------
    # skip rules
    # ------------------------------------------------------------------
    def _pre_check(self, path: Path) -> _Walked:
        try:
            lstat = path.lstat()
        except OSError as exc:
            return _Walked(
                path,
                skipped=_SKIP_ERROR,
                error=f"Nie można odczytać metadanych: {exc.strerror or exc}",
            )

        if stat_module.S_ISLNK(lstat.st_mode):
            if not self.config.follow_symlinks:
                return _Walked(path, skipped=_SKIP_SYMLINK, stat_result=lstat)
            try:
                lstat = path.stat()
            except OSError as exc:
                return _Walked(
                    path,
                    skipped=_SKIP_ERROR,
                    error=f"Zepsuty link symboliczny: {exc.strerror or exc}",
                )

        if not stat_module.S_ISREG(lstat.st_mode):
            return _Walked(path, skipped=_SKIP_NOT_FILE, stat_result=lstat)
        if self.config.is_internal(path):
            return _Walked(path, skipped=_SKIP_INTERNAL, stat_result=lstat)
        if self._is_excluded(path):
            return _Walked(path, skipped=_SKIP_EXCLUDED, stat_result=lstat)
        if lstat.st_size > self.config.max_file_size:
            return _Walked(path, skipped=_SKIP_TOO_BIG, stat_result=lstat)
        return _Walked(path, stat_result=lstat)

    def _is_excluded(self, path: Path) -> bool:
        text = str(path)
        name = path.name
        for item in self.config.excluded_names:
            if not item:
                continue
            if os.sep in item or item.startswith("/"):
                if text == item or text.startswith(item.rstrip(os.sep) + os.sep):
                    return True
            elif name == item:
                return True
        for item in self.config.excluded_paths:
            if not item:
                continue
            if text == item or text.startswith(item.rstrip(os.sep) + os.sep):
                return True
        return False

    # ------------------------------------------------------------------
    # reading
    # ------------------------------------------------------------------
    def _read_and_hash(self, path: Path, stat_result: os.stat_result) -> tuple[bytes, FileHashes]:
        """Return ``(analysis window, hashes of the whole file)``."""
        size = stat_result.st_size
        if size > ANALYSIS_LIMIT:
            # Two passes, but the hash must cover every byte while the analysis
            # window stays bounded.
            hashes = hash_file(path, self.config.hash_chunk_size or 1 << 20)
            with open(path, "rb") as fh:
                data = fh.read(ANALYSIS_LIMIT)
            return data, hashes
        with open(path, "rb") as fh:
            data = fh.read(size + 1 if size else ANALYSIS_LIMIT)
        return data, hash_bytes(data)

    # ------------------------------------------------------------------
    # analysis
    # ------------------------------------------------------------------
    def _analyse(
        self,
        *,
        label: str,
        data: bytes,
        hashes: FileHashes,
        token: CancellationToken | None = None,
    ) -> list[Detection]:
        """Run every static layer over one blob.

        *label* is what the finding is attributed to: a real path for a file on
        disk, the member name for an archive entry, ``"<memory>"`` for a buffer.
        The name-based heuristics use it too.
        """
        detections: list[Detection] = []
        detections.extend(self._signature_detections(data, hashes, label))
        detections.extend(heuristics.analyze(label, data, config=self.config))
        if self.config.scan_archives:
            budget = _ArchiveBudget(
                members_left=max(0, self.config.archive_max_members),
                bytes_left=max(0, self.config.archive_max_uncompressed),
            )
            detections.extend(
                self._scan_archive(
                    data=data,
                    outer_path=label,
                    depth=0,
                    budget=budget,
                    token=token,
                    prefix="",
                )
            )
        return detections

    def _signature_detections(
        self, data: bytes, hashes: FileHashes, path: str | None
    ) -> list[Detection]:
        out: list[Detection] = []
        known = self.db.lookup_hash(sha256=hashes.sha256, sha1=hashes.sha1, md5=hashes.md5)
        if known is not None:
            out.append(
                Detection(
                    layer=DetectionLayer.SIGNATURE,
                    rule="hash_match",
                    threat_name=known.name,
                    score=known.base_score,
                    confidence=1.0,
                    detail=f"Dokładne trafienie {known.kind.value} w bazie sygnatur "
                    f"(źródło: {known.source}).",
                    path=path,
                    indicator=known,
                )
            )
        for indicator, offset in self.db.match_bytes(data):
            out.append(self._pattern_detection(indicator, offset, path))
        return out

    @staticmethod
    def _pattern_detection(indicator: Indicator, offset: int, path: str | None) -> Detection:
        return Detection(
            layer=DetectionLayer.SIGNATURE,
            rule="pattern_match",
            threat_name=indicator.name,
            score=min(indicator.base_score, SCORE_PATTERN_MATCH),
            confidence=0.95,
            detail=f"Wzorzec bajtowy dopasowany na pozycji {offset} (0x{offset:x}), "
            f"źródło: {indicator.source}.",
            path=path,
            indicator=indicator,
        )

    # ------------------------------------------------------------------
    # archives
    # ------------------------------------------------------------------
    def _scan_archive(
        self,
        *,
        data: bytes,
        outer_path: str | None,
        depth: int,
        budget: _ArchiveBudget,
        token: CancellationToken | None,
        prefix: str,
    ) -> list[Detection]:
        """Recurse into zip members in memory.

        A member's findings are attributed to the *outer* file (that is the
        thing on disk the user can act on); the member name goes into
        ``Detection.detail``.
        """
        if depth >= max(0, self.config.archive_max_depth):
            return []
        if data[:2] != b"PK":
            return []
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except (zipfile.BadZipFile, OSError, ValueError, EOFError):
            return []

        out: list[Detection] = []
        with archive:
            try:
                members = archive.infolist()
            except (zipfile.BadZipFile, OSError, ValueError):
                return []
            for info in members:
                if token is not None and token.cancelled:
                    break
                if budget.members_left <= 0 or budget.bytes_left <= 0:
                    budget.truncated = True
                    break
                if info.is_dir():
                    continue
                budget.members_left -= 1
                name = f"{prefix}{info.filename}"
                cap = min(budget.bytes_left, self.config.max_file_size)
                try:
                    with archive.open(info) as member:
                        payload = member.read(cap + 1)
                except (zipfile.BadZipFile, OSError, ValueError, EOFError, NotImplementedError, RuntimeError):
                    # Encrypted or broken member: nothing to analyse, and that
                    # is worth a note rather than an exception.
                    continue
                if len(payload) > cap:
                    payload = payload[:cap]
                    budget.truncated = True
                budget.bytes_left -= len(payload)
                if not payload:
                    continue

                hashes = hash_bytes(payload)
                found: list[Detection] = list(
                    self._signature_detections(payload, hashes, outer_path)
                )
                found.extend(heuristics.analyze(name, payload, config=self.config))
                for detection in found:
                    detection.path = outer_path
                    detection.detail = f"[w archiwum: {name}] {detection.detail}".strip()
                out.extend(found)

                out.extend(
                    self._scan_archive(
                        data=payload,
                        outer_path=outer_path,
                        depth=depth + 1,
                        budget=budget,
                        token=token,
                        prefix=f"{name}!/",
                    )
                )
        return out

    # ------------------------------------------------------------------
    # walking
    # ------------------------------------------------------------------
    def _walk(
        self,
        paths: Iterable[str | os.PathLike[str]],
        recursive: bool,
        token: CancellationToken | None,
    ) -> Iterator[Path]:
        for raw in paths:
            if token is not None and token.cancelled:
                return
            root = Path(raw)
            try:
                is_dir = root.is_dir()
            except OSError:
                is_dir = False
            if not is_dir:
                yield root
                continue
            if self.config.is_internal(root) or self._is_excluded(root):
                continue
            yield from self._walk_dir(root, recursive, token)

    def _walk_dir(
        self, root: Path, recursive: bool, token: CancellationToken | None
    ) -> Iterator[Path]:
        stack: list[Path] = [root]
        while stack:
            if token is not None and token.cancelled:
                return
            current = stack.pop()
            try:
                with os.scandir(current) as scan:
                    entries = list(scan)
            except OSError as exc:
                self._publish(
                    EventType.LOG,
                    f"Nie można otworzyć katalogu {current}: {exc.strerror or exc}",
                    level="warning",
                    path=str(current),
                )
                continue
            for entry in entries:
                if token is not None and token.cancelled:
                    return
                child = Path(entry.path)
                try:
                    entry_is_dir = entry.is_dir(follow_symlinks=self.config.follow_symlinks)
                except OSError:  # pragma: no cover - racing filesystem
                    continue
                if entry_is_dir:
                    if not recursive:
                        continue
                    if entry.name in self.config.excluded_names:
                        continue
                    if self._is_excluded(child) or self.config.is_internal(child):
                        continue
                    stack.append(child)
                else:
                    yield child

    # ------------------------------------------------------------------
    # jobs
    # ------------------------------------------------------------------
    def iter_scan(
        self,
        paths: Sequence[str | os.PathLike[str]] | str | os.PathLike[str],
        *,
        token: CancellationToken | None = None,
        recursive: bool = True,
    ) -> Iterator[FileVerdict]:
        """Stream verdicts as they are produced (completion order)."""
        stats = ScanStats()
        yield from self._run(paths, token=token, recursive=recursive, stats=stats, sink=None)

    def scan_paths(
        self,
        paths: Sequence[str | os.PathLike[str]] | str | os.PathLike[str],
        *,
        token: CancellationToken | None = None,
        recursive: bool = True,
    ) -> ScanResult:
        """Scan everything under *paths* and collect the result."""
        stats = ScanStats()
        sink: dict[str, Any] = {"cancelled": False}
        verdicts = list(self._run(paths, token=token, recursive=recursive, stats=stats, sink=sink))
        return ScanResult(verdicts=verdicts, stats=stats, cancelled=bool(sink["cancelled"]))

    def _run(
        self,
        paths: Sequence[str | os.PathLike[str]] | str | os.PathLike[str],
        *,
        token: CancellationToken | None,
        recursive: bool,
        stats: ScanStats,
        sink: dict[str, Any] | None,
    ) -> Iterator[FileVerdict]:
        if isinstance(paths, (str, os.PathLike)):
            targets: list[str | os.PathLike[str]] = [paths]
        else:
            targets = list(paths)

        self._publish(
            EventType.SCAN_STARTED,
            "Rozpoczęto skanowanie: " + ", ".join(str(p) for p in targets[:4]),
            paths=[str(p) for p in targets],
            recursive=recursive,
            db_version=self.db.version(),
        )
        cancelled = False
        try:
            walker = self._walk(targets, recursive, token)
            threads = max(1, int(self.config.scan_threads or 1))
            if threads == 1:
                for path in walker:
                    if token is not None and token.cancelled:
                        cancelled = True
                        break
                    verdict = self._safe_scan_file(path)
                    self._account(stats, verdict)
                    self._maybe_progress(stats, verdict.path)
                    yield verdict
            else:
                yield from self._run_pool(walker, token, stats, threads)
                cancelled = token is not None and token.cancelled
        finally:
            if token is not None and token.cancelled:
                cancelled = True
            stats.finished_at = time.time()
            if sink is not None:
                sink["cancelled"] = cancelled
            self._cache_save()
            if cancelled:
                self._publish(
                    EventType.SCAN_CANCELLED,
                    f"Skanowanie przerwane po {stats.files_scanned} plikach.",
                    level="warning",
                    **stats.to_dict(),
                )
            else:
                self._publish(
                    EventType.SCAN_FINISHED,
                    f"Skanowanie zakończone: {stats.files_scanned} plików, "
                    f"{stats.threats_found} zagrożeń, {stats.duration:.1f}s",
                    level="warning" if stats.threats_found else "success",
                    **stats.to_dict(),
                )

    def _run_pool(
        self,
        walker: Iterator[Path],
        token: CancellationToken | None,
        stats: ScanStats,
        threads: int,
    ) -> Iterator[FileVerdict]:
        window = max(threads * 4, threads + 2)
        pending: set[Future[FileVerdict]] = set()
        exhausted = False
        with ThreadPoolExecutor(max_workers=threads, thread_name_prefix="aegis-scan") as pool:
            try:
                while True:
                    while not exhausted and len(pending) < window:
                        if token is not None and token.cancelled:
                            exhausted = True
                            break
                        try:
                            path = next(walker)
                        except StopIteration:
                            exhausted = True
                            break
                        pending.add(pool.submit(self._safe_scan_file, path))
                    if not pending:
                        break
                    done, pending = futures.wait(
                        pending, return_when=futures.FIRST_COMPLETED
                    )
                    for future in done:
                        verdict = future.result()
                        self._account(stats, verdict)
                        self._maybe_progress(stats, verdict.path)
                        yield verdict
                    if token is not None and token.cancelled:
                        break
            finally:
                for future in pending:
                    future.cancel()

    @staticmethod
    def _account(stats: ScanStats, verdict: FileVerdict) -> None:
        if verdict.skipped:
            stats.files_skipped += 1
            if verdict.error:
                stats.errors += 1
        elif verdict.error:
            stats.errors += 1
        else:
            stats.files_scanned += 1
            stats.bytes_scanned += verdict.size
        if verdict.is_threat:
            stats.threats_found += 1

    # ------------------------------------------------------------------
    # result cache
    # ------------------------------------------------------------------
    def _cache_enabled(self) -> bool:
        return bool(self.config.use_scan_cache)

    def _cache_entries(self) -> dict[str, dict[str, Any]]:
        """Load the on-disk cache, dropping it when the database moved on."""
        if self._cache is not None:
            return self._cache
        entries: dict[str, dict[str, Any]] = {}
        try:
            raw = json.loads(self.config.cache_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and raw.get("db_version") == self.db.version():
                stored = raw.get("entries")
                if isinstance(stored, dict):
                    entries = stored
        except (OSError, ValueError, TypeError):
            entries = {}
        self._cache = entries
        return entries

    def _cache_get(self, path: str, stat_result: os.stat_result | None) -> FileVerdict | None:
        if not self._cache_enabled() or stat_result is None:
            return None
        with self._cache_lock:
            record = self._cache_entries().get(path)
            if not record:
                return None
            if (
                record.get("size") != stat_result.st_size
                or record.get("mtime_ns") != stat_result.st_mtime_ns
                or record.get("inode") != stat_result.st_ino
            ):
                return None
            try:
                return _verdict_from_cache(path, record)
            except (KeyError, TypeError, ValueError):
                return None

    def _cache_put(self, path: str, stat_result: os.stat_result, verdict: FileVerdict) -> None:
        if not self._cache_enabled() or verdict.skipped or verdict.error:
            return
        with self._cache_lock:
            entries = self._cache_entries()
            entries[path] = {
                "size": stat_result.st_size,
                "mtime_ns": stat_result.st_mtime_ns,
                "inode": stat_result.st_ino,
                "verdict": verdict.to_dict(),
            }
            self._cache_dirty = True

    def _cache_save(self) -> None:
        if not self._cache_enabled():
            return
        with self._cache_lock:
            if not self._cache_dirty or self._cache is None:
                return
            entries = self._cache
            if len(entries) > CACHE_MAX_ENTRIES:
                ordered = sorted(
                    entries.items(),
                    key=lambda item: item[1].get("verdict", {}).get("scanned_at", 0.0),
                    reverse=True,
                )
                entries = dict(ordered[:CACHE_MAX_ENTRIES])
                self._cache = entries
            payload = {
                "db_version": self.db.version(),
                "saved_at": time.time(),
                "entries": entries,
            }
            try:
                target = self.config.cache_path
                target.parent.mkdir(parents=True, exist_ok=True)
                fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".cache-", suffix=".tmp")
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as fh:
                        fh.write(json.dumps(payload, ensure_ascii=False))
                    os.replace(tmp, target)
                finally:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
                self._cache_dirty = False
            except OSError:
                # A read-only data directory must not break scanning.
                self._cache_dirty = False

    def clear_cache(self) -> None:
        """Forget cached verdicts (used after a database update)."""
        with self._cache_lock:
            self._cache = {}
            self._cache_dirty = True
            try:
                self.config.cache_path.unlink()
            except OSError:
                pass
            self._cache_dirty = False


# --------------------------------------------------------------------------
# cache (de)serialisation
# --------------------------------------------------------------------------
def _detection_from_dict(data: dict[str, Any]) -> Detection:
    indicator = data.get("indicator")
    return Detection(
        layer=DetectionLayer(data["layer"]),
        rule=data["rule"],
        threat_name=data.get("threat_name", ""),
        score=float(data.get("score", 0.0)),
        confidence=float(data.get("confidence", 1.0)),
        detail=data.get("detail", ""),
        path=data.get("path"),
        pid=data.get("pid"),
        indicator=Indicator.from_dict(indicator) if isinstance(indicator, dict) else None,
        timestamp=float(data.get("timestamp", 0.0) or time.time()),
    )


def _verdict_from_cache(path: str, record: dict[str, Any]) -> FileVerdict:
    stored = record["verdict"]
    verdict = FileVerdict(
        path=path,
        size=int(stored.get("size", 0)),
        sha256=stored.get("sha256", ""),
        md5=stored.get("md5", ""),
        detections=[_detection_from_dict(d) for d in stored.get("detections", [])],
        scanned_at=float(stored.get("scanned_at", 0.0) or time.time()),
    )
    return apply_to_file_verdict(verdict)
