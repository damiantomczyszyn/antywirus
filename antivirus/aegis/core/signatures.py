"""The virus database: an SQLite-backed store of indicators of compromise.

Design constraints that shaped this module
------------------------------------------
* **Threat feeds are big.**  A single MalwareBazaar pull is 100k+ rows, so
  :meth:`SignatureDB.add_many` is one transaction with ``executemany`` and an
  ``ON CONFLICT`` upsert.  Row-at-a-time inserts turned a 3 second update into
  minutes.
* **The realtime monitor queries from worker threads.**  The connection is
  opened with ``check_same_thread=False`` and every statement runs under a
  :class:`threading.RLock`, which is what SQLite needs to stay consistent.
* **Byte patterns must be fast.**  ``PATTERN`` indicators are compiled once into
  a handful of big alternation regexes and cached; the cache is invalidated by
  any mutation.

``path=None`` opens an in-memory database - used by the test suite and by
anything that just needs a scratch store.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import Any

from ..events import EventBus, EventType
from ..models import Indicator, IndicatorKind, Severity

__all__ = [
    "SignatureDB",
    "compile_pattern",
    "pattern_literal",
    "PatternError",
    "PATTERN_CHUNK",
    "MIN_PATTERN_SPECIFICITY",
]

#: Patterns per compiled regex.  Big alternations are fast to run but slow to
#: compile, so they are chunked.
PATTERN_CHUNK = 200

#: Safety valve: at most this many regex hits are inspected per chunk, so a
#: pathological one-byte pattern over a 64 MiB file cannot stall a scan.
_MAX_MATCH_ITERATIONS = 4096

#: How many prefilter hits per chunk get fully identified (every remaining
#: pattern probed at that offset).  Real samples trip a handful of patterns, so
#: this is generous; it only exists so a pattern that matches everywhere cannot
#: turn into quadratic work.
_MAX_SHADOW_PROBES = 64

#: Minimum "specificity" of a byte pattern - see :func:`compile_pattern`.
MIN_PATTERN_SPECIFICITY = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    kind        TEXT NOT NULL,
    value       TEXT NOT NULL,
    name        TEXT NOT NULL DEFAULT 'Unnamed.Threat',
    severity    TEXT NOT NULL DEFAULT 'high',
    source      TEXT NOT NULL DEFAULT 'builtin',
    tags        TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    added_at    REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (kind, value)
);
CREATE INDEX IF NOT EXISTS idx_indicators_value  ON indicators(value);
CREATE INDEX IF NOT EXISTS idx_indicators_source ON indicators(source);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_COLUMNS = "kind, value, name, severity, source, tags, description, added_at"


class PatternError(ValueError):
    """Raised for a ``PATTERN`` value that cannot be compiled."""


class _PatternChunk:
    """A prefilter regex for a group of patterns, plus how to identify its hits.

    The prefilter contains **no capture groups on purpose**.  A group (or a
    lookahead) inside a branch makes CPython give up on its first-byte
    prefilter and fall back to trying every alternative at every offset: with
    200 patterns that is a 20 *second* scan of one megabyte instead of half a
    millisecond.  Measured, not guessed - see
    ``test_match_bytes_stays_fast_with_many_patterns``.

    Which pattern matched is therefore worked out after the fact: from the
    matched bytes for wildcard-free patterns (a dict lookup), or by probing the
    few remaining patterns at that offset.
    """

    __slots__ = ("regex", "indicators", "sources", "literals", "literal_map", "_singles")

    def __init__(
        self,
        regex: "re.Pattern[bytes]",
        indicators: list[Indicator],
        sources: list[bytes],
        literals: list[bytes | None],
    ) -> None:
        self.regex = regex
        self.indicators = indicators
        self.sources = sources
        self.literals = literals
        self.literal_map: dict[bytes, int] = {
            literal: index for index, literal in enumerate(literals) if literal
        }
        self._singles: dict[int, "re.Pattern[bytes] | None"] = {}

    def single(self, index: int) -> "re.Pattern[bytes] | None":
        """Regex for one member pattern, compiled on first use.

        Only needed once something already matched, which is rare, so clean
        files never pay for it.
        """
        if index not in self._singles:
            try:
                self._singles[index] = re.compile(self.sources[index], re.DOTALL)
            except re.error:  # pragma: no cover
                self._singles[index] = None
        return self._singles[index]

    def probe(
        self, data: bytes, offset: int, candidates: Iterable[int], skip: int | None
    ) -> list[int]:
        """Which of *candidates* also match at *offset*.

        The prefilter reports one alternative per offset, so without this a
        pattern sharing a prefix with a longer one would stay invisible.
        """
        found: list[int] = []
        for index in sorted(candidates):
            if index == skip:
                continue
            literal = self.literals[index]
            if literal is not None:
                if data.startswith(literal, offset):
                    found.append(index)
                continue
            single = self.single(index)
            if single is not None and single.match(data, offset):
                found.append(index)
        return found


def _escape_byte(value: int) -> bytes:
    return b"\\x%02x" % value


def compile_pattern(value: str) -> bytes:
    """Translate a hex indicator value into a byte-regex source.

    ``??`` matches any byte and a single ``?`` matches any nibble, so
    ``"4d5a????0003"`` is "MZ, two arbitrary bytes, 0x00 0x03" and ``"4?5a"``
    is "any byte 0x40..0x4f followed by 0x5a".

    Patterns that are too generic to be useful are rejected rather than
    silently turned into a disaster: every literal byte is worth 2 points, every
    nibble-wildcard byte 1 point, ``??`` nothing, and at least
    :data:`MIN_PATTERN_SPECIFICITY` points are required.  ``"????"`` (matches
    every file) and ``"?f"`` (matches one byte in sixteen) therefore raise.
    """
    text = re.sub(r"[\s:_-]", "", value).lower()
    if not text:
        raise PatternError("pusty wzorzec")
    if len(text) % 2:
        raise PatternError(f"nieparzysta liczba znaków hex: {value!r}")
    if not re.fullmatch(r"[0-9a-f?]+", text):
        raise PatternError(f"niedozwolone znaki we wzorcu: {value!r}")

    out: list[bytes] = []
    specificity = 0
    for i in range(0, len(text), 2):
        hi, lo = text[i], text[i + 1]
        if hi == "?" and lo == "?":
            out.append(b".")
        elif hi == "?":
            low = int(lo, 16)
            specificity += 1
            out.append(b"[" + b"".join(_escape_byte((h << 4) | low) for h in range(16)) + b"]")
        elif lo == "?":
            high = int(hi, 16) << 4
            specificity += 1
            out.append(b"[" + _escape_byte(high) + b"-" + _escape_byte(high | 0x0F) + b"]")
        else:
            specificity += 2
            out.append(_escape_byte(int(text[i : i + 2], 16)))
    if specificity < MIN_PATTERN_SPECIFICITY:
        raise PatternError(f"wzorzec zbyt ogólny: {value!r}")
    return b"".join(out)


def pattern_literal(value: str) -> bytes | None:
    """Raw bytes of a wildcard-free pattern, else ``None``.

    Used to identify which alternative of a prefilter regex matched without
    paying for capture groups.
    """
    text = re.sub(r"[\s:_-]", "", value).lower()
    if not text or "?" in text or len(text) % 2:
        return None
    try:
        return bytes.fromhex(text)
    except ValueError:
        return None


def _row_to_indicator(row: Sequence[Any]) -> Indicator:
    tags = tuple(t for t in str(row[5] or "").split(",") if t)
    return Indicator(
        kind=IndicatorKind(row[0]),
        value=row[1],
        name=row[2],
        severity=Severity(row[3]),
        source=row[4],
        tags=tags,
        description=row[6] or "",
        added_at=float(row[7] or 0.0),
    )


def _indicator_to_row(ind: Indicator) -> tuple[Any, ...]:
    return (
        ind.kind.value,
        ind.value,
        ind.name,
        ind.severity.value,
        ind.source,
        ",".join(ind.tags),
        ind.description,
        ind.added_at or time.time(),
    )


class SignatureDB:
    """Thread-safe indicator store.

    Lifetime: construct, use, :meth:`close`.  All methods are safe to call from
    several threads at once.
    """

    def __init__(self, path: Path | str | None = None, bus: EventBus | None = None) -> None:
        self._bus = bus
        self._lock = threading.RLock()
        self._closed = False
        self._pattern_cache: list[_PatternChunk] | None = None

        if path is None:
            self.path: Path | None = None
            target = ":memory:"
        else:
            self.path = Path(path)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            target = str(self.path)

        self._conn = sqlite3.connect(target, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA foreign_keys=ON")
        for pragma in ("PRAGMA journal_mode=WAL", "PRAGMA synchronous=NORMAL"):
            try:
                self._conn.execute(pragma)
            except sqlite3.DatabaseError:  # pragma: no cover - exotic filesystems
                pass
        self._conn.executescript(_SCHEMA)
        self._revision = self._read_revision()
        self._publish(
            EventType.DB_LOADED,
            f"Baza sygnatur gotowa: {len(self)} wskaźników (wersja {self.version()})",
            count=len(self),
            version=self.version(),
            path=str(self.path) if self.path else ":memory:",
        )

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------
    def _publish(self, kind: EventType, message: str, **payload: Any) -> None:
        if self._bus is not None:
            self._bus.publish(kind, message, **payload)

    def _read_revision(self) -> int:
        cur = self._conn.execute("SELECT value FROM meta WHERE key='revision'")
        row = cur.fetchone()
        try:
            return int(row[0]) if row else 0
        except (TypeError, ValueError):  # pragma: no cover - corrupted meta
            return 0

    def _bump(self) -> None:
        """Record a mutation: invalidate caches and move the version forward."""
        self._revision += 1
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES('revision', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(self._revision),),
        )
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES('changed_at', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (repr(time.time()),),
        )
        self._pattern_cache = None

    def _check_open(self) -> None:
        if self._closed:
            raise sqlite3.ProgrammingError("SignatureDB jest zamknięta")

    # ------------------------------------------------------------------
    # writing
    # ------------------------------------------------------------------
    def add(self, indicator: Indicator) -> bool:
        """Insert or update one indicator.  Returns ``True`` if it was new."""
        with self._lock:
            self._check_open()
            cur = self._conn.execute(
                "SELECT 1 FROM indicators WHERE kind=? AND value=?",
                (indicator.kind.value, indicator.value),
            )
            is_new = cur.fetchone() is None
            self._conn.execute(
                f"INSERT INTO indicators ({_COLUMNS}) VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT(kind, value) DO UPDATE SET "
                "name=excluded.name, severity=excluded.severity, source=excluded.source, "
                "tags=excluded.tags, description=excluded.description, added_at=excluded.added_at",
                _indicator_to_row(indicator),
            )
            self._bump()
            return is_new

    def add_many(self, indicators: Iterable[Indicator]) -> tuple[int, int]:
        """Bulk upsert in a single transaction.  Returns ``(added, updated)``.

        ``added`` counts rows that did not exist, ``updated`` counts rows that
        existed *and whose payload actually changed*.  Re-importing an
        unchanged feed therefore reports ``(0, 0)`` instead of pretending to
        have done work.
        """
        # Deduplicate inside the batch - feeds happily list the same hash twice
        # and SQLite would otherwise abort the whole executemany.
        deduped: dict[tuple[str, str], Indicator] = {}
        for ind in indicators:
            deduped[(ind.kind.value, ind.value)] = ind
        if not deduped:
            return (0, 0)
        rows = [_indicator_to_row(ind) for ind in deduped.values()]

        with self._lock:
            self._check_open()
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DROP TABLE IF EXISTS temp.incoming")
                self._conn.execute(
                    "CREATE TEMP TABLE incoming ("
                    "kind TEXT, value TEXT, name TEXT, severity TEXT, source TEXT, "
                    "tags TEXT, description TEXT, added_at REAL, PRIMARY KEY(kind, value))"
                )
                self._conn.executemany(
                    f"INSERT OR REPLACE INTO temp.incoming ({_COLUMNS}) VALUES (?,?,?,?,?,?,?,?)",
                    rows,
                )
                added = self._conn.execute(
                    "SELECT COUNT(*) FROM temp.incoming i "
                    "LEFT JOIN indicators x ON x.kind=i.kind AND x.value=i.value "
                    "WHERE x.value IS NULL"
                ).fetchone()[0]
                updated = self._conn.execute(
                    "SELECT COUNT(*) FROM temp.incoming i "
                    "JOIN indicators x ON x.kind=i.kind AND x.value=i.value "
                    "WHERE x.name IS NOT i.name OR x.severity IS NOT i.severity "
                    "OR x.source IS NOT i.source OR x.tags IS NOT i.tags "
                    "OR x.description IS NOT i.description"
                ).fetchone()[0]
                self._conn.execute(
                    f"INSERT INTO indicators ({_COLUMNS}) "
                    f"SELECT {_COLUMNS} FROM temp.incoming WHERE true "
                    "ON CONFLICT(kind, value) DO UPDATE SET "
                    "name=excluded.name, severity=excluded.severity, source=excluded.source, "
                    "tags=excluded.tags, description=excluded.description, "
                    "added_at=excluded.added_at"
                )
                self._conn.execute("DROP TABLE temp.incoming")
                if added or updated:
                    self._bump()
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                self._pattern_cache = None
                self._revision = self._read_revision()
                raise
        return (int(added), int(updated))

    def remove(self, kind: IndicatorKind, value: str) -> bool:
        """Delete one indicator.  Returns ``True`` if a row disappeared."""
        probe = Indicator(kind=kind, value=value)  # reuse value normalisation
        with self._lock:
            self._check_open()
            cur = self._conn.execute(
                "DELETE FROM indicators WHERE kind=? AND value=?",
                (probe.kind.value, probe.value),
            )
            if cur.rowcount:
                self._bump()
                return True
            return False

    def clear_source(self, source: str) -> int:
        """Drop every indicator that came from *source*.  Returns the count."""
        with self._lock:
            self._check_open()
            cur = self._conn.execute("DELETE FROM indicators WHERE source=?", (source,))
            removed = cur.rowcount or 0
            if removed:
                self._bump()
            return removed

    # ------------------------------------------------------------------
    # reading
    # ------------------------------------------------------------------
    def lookup_hash(
        self,
        *,
        sha256: str | None = None,
        sha1: str | None = None,
        md5: str | None = None,
    ) -> Indicator | None:
        """Find a known-bad hash.  Strongest digest wins when several match."""
        candidates = [
            (IndicatorKind.SHA256, sha256),
            (IndicatorKind.SHA1, sha1),
            (IndicatorKind.MD5, md5),
        ]
        with self._lock:
            self._check_open()
            for kind, digest in candidates:
                if not digest:
                    continue
                cur = self._conn.execute(
                    f"SELECT {_COLUMNS} FROM indicators WHERE kind=? AND value=?",
                    (kind.value, digest.strip().lower()),
                )
                row = cur.fetchone()
                if row is not None:
                    return _row_to_indicator(row)
        return None

    def lookup_network(
        self,
        *,
        host: str | None = None,
        url: str | None = None,
        ip: str | None = None,
    ) -> Indicator | None:
        """Find a blocklisted URL, domain (or any parent domain) or IPv4."""
        with self._lock:
            self._check_open()
            if url:
                for candidate in _url_variants(url):
                    found = self._lookup_one(IndicatorKind.URL, candidate)
                    if found:
                        return found
                host = host or _host_of(url)
            if host:
                for candidate in _domain_parents(host):
                    found = self._lookup_one(IndicatorKind.DOMAIN, candidate)
                    if found:
                        return found
                if _looks_like_ipv4(host) and not ip:
                    ip = host
            if ip:
                found = self._lookup_one(IndicatorKind.IPV4, ip.strip().lower())
                if found:
                    return found
        return None

    def _lookup_one(self, kind: IndicatorKind, value: str) -> Indicator | None:
        if not value:
            return None
        cur = self._conn.execute(
            f"SELECT {_COLUMNS} FROM indicators WHERE kind=? AND value=?",
            (kind.value, value),
        )
        row = cur.fetchone()
        return _row_to_indicator(row) if row is not None else None

    def iter_indicators(self, kind: IndicatorKind | None = None) -> Iterator[Indicator]:
        """Stream indicators out of the database in batches.

        The lock is released between batches so a 400k-row export does not
        block the realtime monitor for the whole walk.
        """
        offset = 0
        batch = 1000
        while True:
            with self._lock:
                self._check_open()
                if kind is None:
                    cur = self._conn.execute(
                        f"SELECT {_COLUMNS} FROM indicators ORDER BY kind, value "
                        "LIMIT ? OFFSET ?",
                        (batch, offset),
                    )
                else:
                    cur = self._conn.execute(
                        f"SELECT {_COLUMNS} FROM indicators WHERE kind=? ORDER BY value "
                        "LIMIT ? OFFSET ?",
                        (IndicatorKind(kind).value, batch, offset),
                    )
                rows = cur.fetchall()
            if not rows:
                return
            for row in rows:
                yield _row_to_indicator(row)
            if len(rows) < batch:
                return
            offset += len(rows)

    # ------------------------------------------------------------------
    # pattern matching
    # ------------------------------------------------------------------
    def _compiled_patterns(self) -> list[_PatternChunk]:
        """Compile every ``PATTERN`` indicator into chunked alternation regexes.

        Each alternative is wrapped in a lookahead so matches are zero-width:
        that way a pattern starting inside another pattern's match is still
        found.  Longer patterns go first so the most specific one wins at a
        given offset.
        """
        cache = self._pattern_cache
        if cache is not None:
            return cache

        items: list[tuple[bytes, bytes | None, Indicator]] = []
        for ind in self.iter_indicators(IndicatorKind.PATTERN):
            try:
                items.append((compile_pattern(ind.value), pattern_literal(ind.value), ind))
            except PatternError:
                continue  # a malformed feed row must not break scanning
        # Longest first: the most specific pattern should win at a given offset.
        items.sort(key=lambda it: len(it[2].value), reverse=True)

        # A pattern starting with "??" compiles to a leading ".", which also
        # defeats the first-byte prefilter, so those live in their own chunks
        # and cannot slow the (overwhelming) majority down.
        groups = (
            [it for it in items if not it[0].startswith(b".")],
            [it for it in items if it[0].startswith(b".")],
        )

        compiled: list[_PatternChunk] = []
        for group in groups:
            for start in range(0, len(group), PATTERN_CHUNK):
                chunk = group[start : start + PATTERN_CHUNK]
                source = b"(?:" + b"|".join(b"(?:" + src + b")" for src, _, _ in chunk) + b")"
                sources = [src for src, _, _ in chunk]
                literals = [lit for _, lit, _ in chunk]
                indicators = [ind for _, _, ind in chunk]
                try:
                    regex = re.compile(source, re.DOTALL)
                except re.error:  # pragma: no cover - one regex per pattern instead
                    for src, lit, ind in chunk:
                        try:
                            compiled.append(
                                _PatternChunk(re.compile(src, re.DOTALL), [ind], [src], [lit])
                            )
                        except re.error:
                            pass
                    continue
                compiled.append(_PatternChunk(regex, indicators, sources, literals))

        with self._lock:
            self._pattern_cache = compiled
        return compiled

    def match_bytes(self, data: bytes, limit: int = 8) -> list[tuple[Indicator, int]]:
        """Scan *data* for ``PATTERN`` indicators.

        Returns ``(indicator, offset)`` pairs, at most *limit* of them and at
        most one per indicator (the first offset), so a pattern that occurs
        10 000 times reports once instead of flooding the verdict.
        """
        if limit <= 0 or not data:
            return []
        hits: list[tuple[Indicator, int]] = []
        seen: set[tuple[str, str]] = set()

        def record(indicator: Indicator, offset: int) -> bool:
            """Append a hit; return True once *limit* is reached."""
            if indicator.key in seen:
                return False
            seen.add(indicator.key)
            hits.append((indicator, offset))
            return len(hits) >= limit

        for chunk in self._compiled_patterns():
            remaining = set(range(len(chunk.indicators)))
            probes_left = _MAX_SHADOW_PROBES
            position = 0
            for _ in range(_MAX_MATCH_ITERATIONS):
                match = chunk.regex.search(data, position)
                if match is None:
                    break
                offset = match.start()
                # Continue one byte further, not past the match, so patterns
                # overlapping this one are still found.
                position = offset + 1

                here: list[int] = []
                index = chunk.literal_map.get(match.group(0))
                if index is not None and index in remaining:
                    here.append(index)
                if remaining and probes_left > 0:
                    probes_left -= 1
                    here.extend(chunk.probe(data, offset, remaining, skip=index))
                elif index is None:
                    # Out of probe budget and the hit is a wildcard pattern:
                    # identify it with a single probe of the wildcard patterns.
                    here.extend(
                        chunk.probe(
                            data,
                            offset,
                            [i for i in remaining if chunk.literals[i] is None],
                            skip=None,
                        )[:1]
                    )
                for found in here:
                    remaining.discard(found)
                    if record(chunk.indicators[found], offset):
                        return hits
                if not remaining:
                    break
        return hits

    # ------------------------------------------------------------------
    # bookkeeping
    # ------------------------------------------------------------------
    def stats(self) -> dict[str, Any]:
        """Counters for the GUI dashboard."""
        with self._lock:
            self._check_open()
            total = self._conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
            by_kind = {
                str(k): int(c)
                for k, c in self._conn.execute(
                    "SELECT kind, COUNT(*) FROM indicators GROUP BY kind ORDER BY kind"
                )
            }
            by_source = {
                str(s): int(c)
                for s, c in self._conn.execute(
                    "SELECT source, COUNT(*) FROM indicators GROUP BY source "
                    "ORDER BY COUNT(*) DESC"
                )
            }
            return {
                "total": int(total),
                "by_kind": by_kind,
                "by_source": by_source,
                "version": self.version(),
                "path": str(self.path) if self.path else ":memory:",
            }

    def version(self) -> str:
        """Database version string, e.g. ``"2026.11.14.1532.7"``.

        Timestamp of the last mutation plus a revision counter.  The counter is
        what makes the string change even for two edits in the same minute,
        which the scanner's result cache relies on to invalidate itself.
        """
        with self._lock:
            self._check_open()
            row = self._conn.execute("SELECT value FROM meta WHERE key='changed_at'").fetchone()
            changed_at: float | None = None
            if row:
                try:
                    changed_at = float(row[0])
                except (TypeError, ValueError):  # pragma: no cover
                    changed_at = None
            if changed_at is None:
                return f"0000.00.00.0000.{self._revision}"
            stamp = time.strftime("%Y.%m.%d.%H%M", time.localtime(changed_at))
            return f"{stamp}.{self._revision}"

    def revision(self) -> int:
        """Monotonic mutation counter behind :meth:`version`."""
        with self._lock:
            return self._revision

    # ------------------------------------------------------------------
    # import / export
    # ------------------------------------------------------------------
    def export_json(self, path: str | os.PathLike[str]) -> int:
        """Write every indicator to *path* as JSON.  Returns the row count."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": self.version(),
            "exported_at": time.time(),
            "indicators": [ind.to_dict() for ind in self.iter_indicators()],
        }
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, target)
        return len(payload["indicators"])

    def import_json(self, path: str | os.PathLike[str]) -> tuple[int, int]:
        """Load indicators written by :meth:`export_json`.  ``(added, updated)``."""
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            rows = raw.get("indicators", [])
        else:
            rows = raw
        indicators: list[Indicator] = []
        for item in rows:
            try:
                indicators.append(Indicator.from_dict(item))
            except (KeyError, TypeError, ValueError):
                continue  # one bad row must not abort the import
        return self.add_many(indicators)

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._pattern_cache = None
            try:
                self._conn.close()
            except sqlite3.Error:  # pragma: no cover
                pass

    def __len__(self) -> int:
        with self._lock:
            if self._closed:
                return 0
            return int(self._conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0])

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        where = str(self.path) if self.path else ":memory:"
        return f"<SignatureDB {where} rows={len(self)} version={self.version()}>"

    def __enter__(self) -> "SignatureDB":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# --------------------------------------------------------------------------
# small helpers for network lookups
# --------------------------------------------------------------------------
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _looks_like_ipv4(text: str) -> bool:
    text = text.strip()
    if not _IPV4_RE.match(text):
        return False
    return all(0 <= int(part) <= 255 for part in text.split("."))


def _host_of(url: str) -> str:
    rest = url.split("://", 1)[-1]
    rest = rest.split("/", 1)[0].split("?", 1)[0]
    if "@" in rest:
        rest = rest.rsplit("@", 1)[1]
    if rest.count(":") == 1:          # strip a :port, keep IPv6-ish text alone
        rest = rest.rsplit(":", 1)[0]
    return rest.strip().lower()


def _domain_parents(host: str) -> list[str]:
    """``a.b.evil.com`` -> itself, ``b.evil.com``, ``evil.com`` (never the TLD)."""
    host = host.strip().lower().rstrip(".")
    if not host:
        return []
    if _looks_like_ipv4(host):
        return [host]
    parts = host.split(".")
    return [".".join(parts[i:]) for i in range(0, max(1, len(parts) - 1))]


def _url_variants(url: str) -> list[str]:
    """Normalised spellings of *url* worth probing in the database."""
    raw = url.strip()
    low = raw.lower()
    out = [raw, low]
    for prefix in ("http://", "https://"):
        if low.startswith(prefix):
            out.append(low[len(prefix) :])
    if low.endswith("/"):
        out.append(low.rstrip("/"))
    else:
        out.append(low + "/")
    seen: set[str] = set()
    unique = []
    for item in out:
        if item and item not in seen:
            seen.add(item)
            unique.append(item)
    return unique
