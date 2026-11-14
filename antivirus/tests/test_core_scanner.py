"""Tests for aegis.core.scanner (the pipeline)."""

from __future__ import annotations

import hashlib
import io
import math
import os
import threading
import time
import zipfile

import pytest

from aegis.core.scanner import CancellationToken, ScanResult, Scanner
from aegis.core.signatures import SignatureDB
from aegis.models import (
    Indicator,
    IndicatorKind,
    Severity,
    SCORE_HEURISTIC_STRONG,
)

MARKER = b"AEGIS-SIM-MARKER"


@pytest.fixture()
def db(eicar_bytes):
    """A database that knows the EICAR hash and one byte pattern."""
    database = SignatureDB(None)
    database.add_many(
        [
            Indicator(
                kind=IndicatorKind.SHA256,
                value=hashlib.sha256(eicar_bytes).hexdigest(),
                name="Sim.Eicar.TestFile",
                severity=Severity.CRITICAL,
                source="builtin",
            ),
            Indicator(
                kind=IndicatorKind.PATTERN,
                value=Indicator.pattern_from_text(MARKER.decode()),
                name="Sim.Marker.Pattern",
                severity=Severity.HIGH,
                source="builtin",
            ),
        ]
    )
    yield database
    database.close()


@pytest.fixture()
def samples(tmp_path, eicar_bytes):
    """A small tree: one known-bad, one pattern hit, one benign."""
    root = tmp_path / "samples"
    (root / "sub").mkdir(parents=True)
    (root / "eicar.com").write_bytes(eicar_bytes)
    (root / "sub" / "marked.bin").write_bytes(b"\x00" * 64 + MARKER + b"\x00" * 64)
    (root / "sub" / "notatka.txt").write_text("Zwyczajna notatka.\n" * 20, encoding="utf-8")
    return root


@pytest.fixture()
def scanner(db, config, bus) -> Scanner:
    config.use_scan_cache = False
    return Scanner(db, config, bus)


def make_zip(items: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in items.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def by_name(result: ScanResult) -> dict[str, "object"]:
    return {os.path.basename(v.path): v for v in result.verdicts}


# --------------------------------------------------------------------------
# single file
# --------------------------------------------------------------------------
def test_known_hash_is_critical(scanner: Scanner, samples, eicar_bytes) -> None:
    verdict = scanner.scan_file(samples / "eicar.com")
    assert verdict.severity is Severity.CRITICAL
    assert verdict.score == 100.0
    assert verdict.threat_name == "Sim.Eicar.TestFile"
    assert verdict.sha256 == hashlib.sha256(eicar_bytes).hexdigest()
    assert verdict.size == len(eicar_bytes)
    assert verdict.skipped is None and verdict.error is None
    assert verdict.duration_ms >= 0.0
    rules = {d.rule for d in verdict.detections}
    assert "hash_match" in rules, "sygnatura hash musi trafić"
    assert "eicar" in rules, "heurystyka też powinna się wypowiedzieć"


def test_byte_pattern_match(scanner: Scanner, samples) -> None:
    verdict = scanner.scan_file(samples / "sub" / "marked.bin")
    assert verdict.is_threat
    assert verdict.severity is Severity.HIGH
    detection = next(d for d in verdict.detections if d.rule == "pattern_match")
    assert detection.threat_name == "Sim.Marker.Pattern"
    assert detection.indicator is not None
    assert "64" in detection.detail, "offset trafienia musi być w opisie"


def test_benign_file_is_clean(scanner: Scanner, samples) -> None:
    verdict = scanner.scan_file(samples / "sub" / "notatka.txt")
    assert verdict.severity is Severity.CLEAN
    assert verdict.score == 0.0
    assert verdict.detections == []
    assert verdict.is_threat is False


def test_scan_bytes(scanner: Scanner, eicar_bytes) -> None:
    verdict = scanner.scan_bytes(eicar_bytes, "probka-w-pamieci")
    assert verdict.path == "probka-w-pamieci"
    assert verdict.severity is Severity.CRITICAL
    assert scanner.scan_bytes(b"nic ciekawego").severity is Severity.CLEAN


def test_explicit_data_overrides_the_file(scanner: Scanner, samples, eicar_bytes) -> None:
    verdict = scanner.scan_file(samples / "sub" / "notatka.txt", data=eicar_bytes)
    assert verdict.severity is Severity.CRITICAL


def test_missing_file_becomes_an_error_verdict(scanner: Scanner, tmp_path) -> None:
    verdict = scanner.scan_file(tmp_path / "nie-ma.exe")
    assert verdict.error
    assert verdict.skipped
    assert verdict.severity is Severity.CLEAN


# --------------------------------------------------------------------------
# skip rules
# --------------------------------------------------------------------------
def test_oversized_file_is_skipped(scanner: Scanner, tmp_path, eicar_bytes) -> None:
    scanner.config.max_file_size = 16
    target = tmp_path / "duzy.bin"
    target.write_bytes(eicar_bytes)
    verdict = scanner.scan_file(target)
    assert verdict.skipped
    assert "duży" in verdict.skipped
    assert verdict.detections == []


def test_internal_paths_are_skipped(scanner: Scanner, config, eicar_bytes) -> None:
    """Without this the scanner finds the samples in its own quarantine, forever."""
    internal = config.quarantine_dir / "sample.bin"
    internal.write_bytes(eicar_bytes)
    assert scanner.scan_file(internal).skipped


def test_excluded_directory_is_not_walked(scanner: Scanner, samples, eicar_bytes) -> None:
    cache = samples / "__pycache__"
    cache.mkdir()
    (cache / "x.pyc").write_bytes(eicar_bytes)
    paths = {os.path.basename(v.path) for v in scanner.scan_paths([samples]).verdicts}
    assert "x.pyc" not in paths


def test_excluded_paths_from_config(scanner: Scanner, samples) -> None:
    scanner.config.excluded_paths = [str(samples / "sub")]
    names = {os.path.basename(v.path) for v in scanner.scan_paths([samples]).verdicts}
    assert "marked.bin" not in names
    assert "eicar.com" in names


def test_symlinks_are_skipped_by_default(scanner: Scanner, samples) -> None:
    link = samples / "link.com"
    link.symlink_to(samples / "eicar.com")
    verdict = scanner.scan_file(link)
    assert verdict.skipped == "link symboliczny"
    assert not verdict.is_threat


def test_symlinks_are_followed_when_configured(scanner: Scanner, samples) -> None:
    scanner.config.follow_symlinks = True
    link = samples / "link.com"
    link.symlink_to(samples / "eicar.com")
    assert scanner.scan_file(link).severity is Severity.CRITICAL


def test_directories_and_devices_are_not_files(scanner: Scanner, samples) -> None:
    assert scanner.scan_file(samples / "sub").skipped


# --------------------------------------------------------------------------
# archives
# --------------------------------------------------------------------------
def test_archive_member_is_found_and_attributed_to_the_container(
    scanner: Scanner, tmp_path, eicar_bytes
) -> None:
    target = tmp_path / "paczka.zip"
    target.write_bytes(make_zip({"czyste.txt": b"nic", "kat/eicar.com": eicar_bytes}))
    verdict = scanner.scan_file(target)
    assert verdict.severity is Severity.CRITICAL
    assert verdict.path == str(target)
    detection = next(d for d in verdict.detections if d.rule == "hash_match")
    assert detection.path == str(target), "wykrycie dotyczy pliku na dysku"
    assert "kat/eicar.com" in detection.detail, "nazwa wpisu musi być w opisie"


def test_nested_archives_up_to_the_depth_limit(scanner: Scanner, tmp_path, eicar_bytes) -> None:
    level1 = make_zip({"eicar.com": eicar_bytes})
    level2 = make_zip({"level1.zip": level1})
    target = tmp_path / "nested.zip"
    target.write_bytes(level2)

    scanner.config.archive_max_depth = 2
    assert scanner.scan_file(target).severity is Severity.CRITICAL

    scanner.config.archive_max_depth = 1
    assert scanner.scan_file(target).severity is Severity.CLEAN

    scanner.config.archive_max_depth = 0
    assert scanner.scan_file(target).severity is Severity.CLEAN


def test_archives_can_be_switched_off(scanner: Scanner, tmp_path, eicar_bytes) -> None:
    target = tmp_path / "p.zip"
    target.write_bytes(make_zip({"eicar.com": eicar_bytes}))
    scanner.config.scan_archives = False
    assert scanner.scan_file(target).severity is Severity.CLEAN


def test_member_budget_is_enforced(scanner: Scanner, tmp_path, eicar_bytes) -> None:
    items = {f"pad{n:03d}.txt": b"wypelniacz" for n in range(40)}
    items["zzz-eicar.com"] = eicar_bytes
    target = tmp_path / "wiele.zip"
    target.write_bytes(make_zip(items))

    scanner.config.archive_max_members = 5
    assert scanner.scan_file(target).severity is Severity.CLEAN
    scanner.config.archive_max_members = 500
    assert scanner.scan_file(target).severity is Severity.CRITICAL


def test_uncompressed_budget_is_enforced(scanner: Scanner, tmp_path, eicar_bytes) -> None:
    target = tmp_path / "budget.zip"
    target.write_bytes(make_zip({"aaa.bin": b"\x00" * 100000, "zzz-eicar.com": eicar_bytes}))
    scanner.config.archive_max_uncompressed = 1000
    verdict = scanner.scan_file(target)
    assert not any(d.rule == "hash_match" for d in verdict.detections)


def test_broken_archive_does_not_raise(scanner: Scanner, tmp_path) -> None:
    target = tmp_path / "zepsute.zip"
    target.write_bytes(b"PK\x03\x04" + os.urandom(500))
    verdict = scanner.scan_file(target)
    assert verdict.error is None


def test_encrypted_member_is_skipped_quietly(scanner: Scanner, tmp_path, eicar_bytes) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("eicar.com", eicar_bytes)
    raw = bytearray(buffer.getvalue())
    raw[6] |= 0x01  # claim "encrypted" in the local header's general purpose flags
    target = tmp_path / "zaszyfrowane.zip"
    target.write_bytes(bytes(raw))
    verdict = scanner.scan_file(target)
    assert verdict.error is None


# --------------------------------------------------------------------------
# jobs
# --------------------------------------------------------------------------
def test_iter_scan_is_a_generator_and_covers_the_tree(scanner: Scanner, samples) -> None:
    import types

    stream = scanner.iter_scan([samples])
    assert isinstance(stream, types.GeneratorType)
    names = {os.path.basename(v.path) for v in stream}
    assert names == {"eicar.com", "marked.bin", "notatka.txt"}


def test_non_recursive_scan_stays_at_the_top_level(scanner: Scanner, samples) -> None:
    names = {os.path.basename(v.path) for v in scanner.iter_scan([samples], recursive=False)}
    assert names == {"eicar.com"}


def test_scan_paths_stats_and_threats(scanner: Scanner, samples) -> None:
    result = scanner.scan_paths([samples])
    assert isinstance(result, ScanResult)
    assert result.cancelled is False
    assert result.stats.files_scanned == 3
    assert result.stats.threats_found == 2
    assert result.stats.errors == 0
    assert result.stats.bytes_scanned > 0
    assert result.stats.finished_at is not None
    assert result.stats.duration >= 0.0
    assert {os.path.basename(v.path) for v in result.threats} == {"eicar.com", "marked.bin"}


def test_scan_paths_accepts_a_bare_path(scanner: Scanner, samples) -> None:
    assert scanner.scan_paths(samples / "eicar.com").stats.files_scanned == 1
    assert scanner.scan_paths(str(samples)).stats.files_scanned == 3


def test_skipped_files_are_counted_separately(scanner: Scanner, samples) -> None:
    (samples / "link.com").symlink_to(samples / "eicar.com")
    result = scanner.scan_paths([samples])
    assert result.stats.files_scanned == 3
    assert result.stats.files_skipped == 1


@pytest.mark.parametrize("threads", [1, 2, 4])
def test_thread_count_does_not_change_the_outcome(db, config, bus, samples, threads) -> None:
    config.use_scan_cache = False
    config.scan_threads = threads
    result = Scanner(db, config, bus).scan_paths([samples])
    assert result.stats.files_scanned == 3
    assert len(result.threats) == 2


def test_many_files_are_all_scanned(db, config, tmp_path, eicar_bytes) -> None:
    config.use_scan_cache = False
    config.scan_threads = 4
    root = tmp_path / "duzo"
    root.mkdir()
    for index in range(120):
        (root / f"f{index:03d}.bin").write_bytes(eicar_bytes if index % 10 == 0 else b"czysty")
    result = Scanner(db, config).scan_paths([root])
    assert result.stats.files_scanned == 120
    assert len(result.threats) == 12


# --------------------------------------------------------------------------
# cancellation
# --------------------------------------------------------------------------
def test_cancellation_token_basics() -> None:
    token = CancellationToken()
    assert token.cancelled is False
    token.cancel()
    assert token.cancelled is True
    token.reset()
    assert token.cancelled is False


def test_cancelled_before_start(scanner: Scanner, samples) -> None:
    token = CancellationToken()
    token.cancel()
    result = scanner.scan_paths([samples], token=token)
    assert result.cancelled is True
    assert result.verdicts == []
    assert result.stats.files_scanned == 0


def test_cancellation_mid_stream_stops_promptly(db, config, tmp_path, eicar_bytes) -> None:
    config.use_scan_cache = False
    config.scan_threads = 1
    root = tmp_path / "wiele"
    root.mkdir()
    for index in range(400):
        (root / f"f{index:04d}.bin").write_bytes(eicar_bytes)
    scanner = Scanner(db, config)
    token = CancellationToken()
    seen = 0
    for _ in scanner.iter_scan([root], token=token):
        seen += 1
        if seen == 5:
            token.cancel()
    assert 5 <= seen < 400, f"skan nie zatrzymał się szybko (przeskanowano {seen})"


def test_cancellation_is_reported_on_the_bus(scanner: Scanner, samples, bus) -> None:
    token = CancellationToken()
    token.cancel()
    scanner.scan_paths([samples], token=token)
    types = [event.type.value for event in bus.history()]
    assert "scan_cancelled" in types
    assert "scan_finished" not in types


# --------------------------------------------------------------------------
# events
# --------------------------------------------------------------------------
def test_scan_lifecycle_events(scanner: Scanner, samples, bus) -> None:
    scanner.scan_paths([samples])
    counts = bus.counts()
    assert counts.get("scan_started") == 1
    assert counts.get("scan_finished") == 1
    assert counts.get("scan_file_done") == 3
    assert counts.get("threat_found") == 2
    threat = next(e for e in bus.history() if e.type.value == "threat_found")
    assert threat.payload["threat_name"]
    assert threat.payload["severity"] in {"high", "critical"}
    assert "verdict" in threat.payload
    finished = next(e for e in bus.history() if e.type.value == "scan_finished")
    assert finished.payload["files_scanned"] == 3


def test_progress_events_are_throttled(db, config, tmp_path) -> None:
    """A 20k-file scan must not push 20k progress events into the GUI queue."""
    from aegis.events import EventBus

    config.use_scan_cache = False
    config.scan_threads = 2
    root = tmp_path / "duzo"
    root.mkdir()
    for index in range(600):
        (root / f"f{index:04d}.txt").write_bytes(b"tresc %d" % index)
    bus = EventBus(history=4000)
    scanner = Scanner(db, config, bus)
    started = time.monotonic()
    result = scanner.scan_paths([root])
    elapsed = time.monotonic() - started
    progress = bus.counts().get("scan_progress", 0)
    assert result.stats.files_scanned == 600
    assert progress <= 2 + math.ceil(elapsed * 21), f"{progress} zdarzeń w {elapsed:.2f}s"


def test_scanner_without_a_bus(db, config, samples) -> None:
    config.use_scan_cache = False
    assert Scanner(db, config).scan_paths([samples]).stats.files_scanned == 3


# --------------------------------------------------------------------------
# result cache
# --------------------------------------------------------------------------
def test_cache_hit_on_second_scan(db, config, bus, samples) -> None:
    config.use_scan_cache = True
    scanner = Scanner(db, config, bus)
    first = scanner.scan_paths([samples])
    assert config.cache_path.is_file()
    assert not any(e.payload.get("cached") for e in bus.history() if e.type.value == "scan_file_done")

    bus.clear_history()
    second = scanner.scan_paths([samples])
    cached = [e for e in bus.history() if e.type.value == "scan_file_done" and e.payload["cached"]]
    assert len(cached) == 3
    # iter_scan yields in completion order, so compare by path, never by index.
    assert {v.path: v.score for v in second.threats} == {v.path: v.score for v in first.threats}
    assert {v.path: v.threat_name for v in second.threats} == {
        v.path: v.threat_name for v in first.threats
    }


def test_cache_is_invalidated_by_modification(db, config, samples) -> None:
    config.use_scan_cache = True
    scanner = Scanner(db, config)
    assert scanner.scan_file(samples / "sub" / "notatka.txt").severity is Severity.CLEAN
    (samples / "sub" / "notatka.txt").write_bytes(MARKER * 3)
    os.utime(samples / "sub" / "notatka.txt", (1000, 1000))
    assert scanner.scan_file(samples / "sub" / "notatka.txt").is_threat


def test_cache_is_invalidated_by_a_database_update(db, config, samples) -> None:
    """A fresh signature feed must not be ignored because of yesterday's cache."""
    config.use_scan_cache = True
    marked = samples / "sub" / "czysty.bin"
    marked.write_bytes(b"\x00" * 10 + b"NOWY-WZORZEC" + b"\x00" * 10)

    scanner = Scanner(db, config)
    assert scanner.scan_file(marked).severity is Severity.CLEAN

    db.add(
        Indicator(
            kind=IndicatorKind.PATTERN,
            value=Indicator.pattern_from_text("NOWY-WZORZEC"),
            name="Sim.Nowy.Wzorzec",
        )
    )
    fresh = Scanner(db, config)      # re-reads the cache file
    assert fresh.scan_file(marked).is_threat


def test_cache_can_be_disabled_and_cleared(db, config, samples) -> None:
    config.use_scan_cache = True
    scanner = Scanner(db, config)
    scanner.scan_paths([samples])
    assert config.cache_path.is_file()
    scanner.clear_cache()
    assert not config.cache_path.exists()

    config.use_scan_cache = False
    other = Scanner(db, config)
    other.scan_paths([samples])
    assert not config.cache_path.exists()


def test_unreadable_cache_file_is_ignored(db, config, samples) -> None:
    config.use_scan_cache = True
    config.cache_path.write_text("{to nie jest json", encoding="utf-8")
    assert Scanner(db, config).scan_paths([samples]).stats.files_scanned == 3


# --------------------------------------------------------------------------
# robustness
# --------------------------------------------------------------------------
def test_an_exploding_heuristic_does_not_abort_the_scan(scanner: Scanner, samples, monkeypatch) -> None:
    from aegis.core import scanner as module

    def explode(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(module.heuristics, "analyze", explode)
    result = scanner.scan_paths([samples])
    assert len(result.verdicts) == 3
    assert result.stats.errors == 3
    assert all("Błąd wewnętrzny" in (v.error or "") for v in result.verdicts)


def test_file_vanishing_mid_scan_is_an_error_not_a_crash(scanner: Scanner, tmp_path) -> None:
    target = tmp_path / "ulotny.bin"
    target.write_bytes(b"x" * 100)
    original = Scanner._read_and_hash

    def vanish(self, path, stat_result):
        os.unlink(path)
        return original(self, path, stat_result)

    Scanner._read_and_hash = vanish
    try:
        verdict = scanner.scan_file(target)
    finally:
        Scanner._read_and_hash = original
    assert verdict.error and verdict.skipped


def test_large_file_is_hashed_whole_but_analysed_in_a_window(db, config, tmp_path, eicar_bytes, monkeypatch) -> None:
    """Hashes must cover every byte even when the analysis window is capped."""
    from aegis.core import scanner as module

    monkeypatch.setattr(module, "ANALYSIS_LIMIT", 4096)
    payload = b"\x00" * 8192 + eicar_bytes
    target = tmp_path / "big.bin"
    target.write_bytes(payload)
    config.use_scan_cache = False

    verdict = Scanner(db, config).scan_file(target)
    assert verdict.sha256 == hashlib.sha256(payload).hexdigest()
    assert verdict.size == len(payload)
    assert verdict.detections == [], "treść poza okienkiem nie jest analizowana"

    db.add(
        Indicator(
            kind=IndicatorKind.SHA256,
            value=hashlib.sha256(payload).hexdigest(),
            name="Sim.Big.Sample",
        )
    )
    assert Scanner(db, config).scan_file(target).severity is Severity.CRITICAL


def test_concurrent_scans_share_the_scanner_safely(db, config, samples) -> None:
    config.use_scan_cache = True
    config.scan_threads = 2
    scanner = Scanner(db, config)
    errors: list[BaseException] = []
    results: list[int] = []

    def worker() -> None:
        try:
            results.append(len(scanner.scan_paths([samples]).threats))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    assert not errors, errors
    assert results == [2, 2, 2, 2]


def test_heuristic_only_file_stays_below_quarantine_level(scanner: Scanner, tmp_path) -> None:
    """Heuristics alone must never reach CRITICAL - that is the fusion contract."""
    target = tmp_path / "faktura.pdf.exe"
    target.write_bytes(b"MZ" + b"\x00" * 400)
    verdict = scanner.scan_file(target)
    assert verdict.severity in (Severity.CLEAN, Severity.LOW, Severity.MEDIUM)
    assert all(d.score <= SCORE_HEURISTIC_STRONG for d in verdict.detections)
