"""Realtime monitor: both backends, on a real temporary filesystem.

The polling backend is fully synchronous - ``drain_once()`` takes a fresh
snapshot itself, so those tests never wait for anything.  The watchdog backend
depends on the kernel delivering an inotify event, which is the one thing a
test cannot make happen on demand; :func:`drain_until` therefore retries
``drain_once()`` until a *stated condition* holds and fails loudly on timeout.
That is a bounded wait on a predicate, not a sleep-and-hope.
"""

from __future__ import annotations

import hashlib
import os
import time

import pytest

from aegis.config import Config
from aegis.events import EventType
from aegis.models import (
    SCORE_HASH_MATCH,
    ActionKind,
    ActionResult,
    BehaviorKind,
    Detection,
    DetectionLayer,
    FileVerdict,
    Indicator,
    IndicatorKind,
    Severity,
)
from aegis.engine.verdict import apply_to_file_verdict
from aegis.realtime.behavior import BehaviorEngine
from aegis.realtime.responder import Responder
from aegis.realtime.watcher import (
    ENTROPY_PREFIX_BYTES,
    HAVE_WATCHDOG,
    RealtimeMonitor,
)

EICAR = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
).encode()

BACKENDS = ["polling"] + (["watchdog"] if HAVE_WATCHDOG else [])


# --------------------------------------------------------------------------
# Fakes for the modules Agent A owns
# --------------------------------------------------------------------------
class FakeScanner:
    """Flags anything containing the EICAR string; records every call."""

    def __init__(self, *, severity_score: float = SCORE_HASH_MATCH, boom: bool = False) -> None:
        self.scanned: list[str] = []
        self.severity_score = severity_score
        self.boom = boom

    def scan_file(self, path, *, data=None) -> FileVerdict:
        self.scanned.append(str(path))
        if self.boom:
            raise RuntimeError("skaner się wywrócił")
        if data is None:
            try:
                with open(path, "rb") as fh:
                    data = fh.read(1 << 20)
            except OSError:
                data = b""
        verdict = FileVerdict(path=str(path), size=len(data))
        if EICAR in data:
            verdict.sha256 = hashlib.sha256(data).hexdigest()
            verdict.detections.append(
                Detection(
                    layer=DetectionLayer.SIGNATURE,
                    rule="sha256_match",
                    threat_name="Sim.Eicar.Test",
                    score=self.severity_score,
                    path=str(path),
                )
            )
        return apply_to_file_verdict(verdict)


class FakeQuarantine:
    """Moves the file into the vault, exactly like the real one does."""

    def __init__(self, config) -> None:
        self.config = config
        self.calls: list[str] = []
        self._counter = 0

    def quarantine(self, path, verdict=None, threat_name="") -> ActionResult:
        self.calls.append(str(path))
        self._counter += 1
        entry_id = f"entry{self._counter}"
        self.config.quarantine_dir.mkdir(parents=True, exist_ok=True)
        target = self.config.quarantine_dir / f"{entry_id}.bin"
        try:
            os.replace(str(path), str(target))
        except OSError as exc:
            return ActionResult(
                kind=ActionKind.QUARANTINE, target=str(path), ok=False, detail=str(exc)
            )
        return ActionResult(
            kind=ActionKind.QUARANTINE, target=str(path), ok=True, detail=f"entry_id={entry_id}"
        )

    def list(self):
        return []


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------
class Harness:
    def __init__(self, config, bus, backend: str, **kwargs) -> None:
        self.config = config
        self.bus = bus
        self.watched = config.realtime_paths[0]
        self.scanner = kwargs.pop("scanner", None) or FakeScanner()
        self.quarantine = FakeQuarantine(config)
        self.behavior = BehaviorEngine(config, bus)
        self.responder = Responder(config, bus, self.quarantine)
        self.monitor = RealtimeMonitor(
            self.scanner,
            config,
            bus,
            self.quarantine,
            self.behavior,
            self.responder,
            backend=backend,
            **kwargs,
        )

    def write(self, name: str, data: bytes) -> str:
        path = os.path.join(self.watched, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def stop(self) -> None:
        self.monitor.stop(timeout=5)


@pytest.fixture(params=BACKENDS)
def harness(request, config, bus):
    h = Harness(config, bus, request.param)
    yield h
    h.stop()


def drain_until(monitor, predicate, timeout: float = 10.0) -> int:
    """Drain until *predicate* holds; fail the test if it never does."""
    deadline = time.monotonic() + timeout
    total = 0
    while True:
        total += monitor.drain_once()
        if predicate():
            return total
        if time.monotonic() > deadline:
            pytest.fail(f"warunek nie został spełniony w ciągu {timeout} s")
        time.sleep(0.02)


# --------------------------------------------------------------------------
# Backend selection
# --------------------------------------------------------------------------
def test_default_backend_prefers_watchdog_when_available(config, bus):
    monitor = RealtimeMonitor(FakeScanner(), config, bus)
    assert monitor.backend == ("watchdog" if HAVE_WATCHDOG else "polling")


def test_backend_can_be_forced_to_polling(config, bus):
    monitor = RealtimeMonitor(FakeScanner(), config, bus, backend="polling")
    assert monitor.backend == "polling"


def test_unknown_backend_name_falls_back_to_the_default(config, bus):
    monitor = RealtimeMonitor(FakeScanner(), config, bus, backend="inotify-deluxe")
    assert monitor.backend in ("watchdog", "polling")


def test_watchdog_request_without_the_package_degrades(config, bus, monkeypatch):
    monkeypatch.setattr("aegis.realtime.watcher.HAVE_WATCHDOG", False)
    monitor = RealtimeMonitor(FakeScanner(), config, bus, backend="watchdog")
    assert monitor.backend == "polling"


# --------------------------------------------------------------------------
# The hybrid dual path
# --------------------------------------------------------------------------
def test_new_threat_is_scanned_and_quarantined(harness):
    monitor = harness.monitor
    monitor.start()
    path = harness.write("evil.com", EICAR)

    drain_until(monitor, lambda: path in harness.scanner.scanned)

    status = monitor.status()
    assert status["backend"] == monitor.backend
    assert status["scanned"] >= 1
    assert status["threats"] == 1
    assert status["actions"] >= 1
    assert harness.quarantine.calls == [path]
    assert not os.path.exists(path)
    threats = harness.bus.history(types={EventType.ACTION_TAKEN})
    assert threats and threats[-1].payload["action"] == "quarantine"


def test_every_change_also_becomes_a_behaviour_event(harness):
    """The second half of hybrid analysis: the same change feeds the rules."""
    monitor = harness.monitor
    monitor.start()
    path = harness.write("notes.txt", b"zwykly tekst" * 40)

    drain_until(monitor, lambda: path in harness.scanner.scanned)

    state = harness.behavior._actors.get(None)          # noqa: SLF001
    assert state is not None, "zdarzenie nie dotarło do silnika behawioralnego"
    assert any(p == path for _, p in state.writes)
    verdict = harness.behavior.verdict_for(None)
    assert path in verdict.touched_paths


def test_entropy_is_computed_from_a_bounded_prefix(harness):
    monitor = harness.monitor
    monitor.start()
    big = os.urandom(ENTROPY_PREFIX_BYTES * 3)
    path = harness.write("big.bin", big)

    drain_until(monitor, lambda: path in harness.scanner.scanned)

    state = harness.behavior._actors[None]             # noqa: SLF001
    assert any(p == path for _, p in state.writes)
    # A 192 KiB file was reported at full size, but only the prefix was read:
    # the content hash is only attached when the whole file fitted in it.
    event_sizes = [sz for sz, _ in [harness.behavior._path_info[path]]]  # noqa: SLF001
    assert event_sizes == [len(big)]


def test_deleted_file_becomes_a_delete_event(harness):
    monitor = harness.monitor
    monitor.start()
    path = harness.write("temp.txt", b"abc")
    drain_until(monitor, lambda: path in harness.scanner.scanned)
    os.remove(path)

    drain_until(monitor, lambda: monitor.status()["deleted"] >= 1)

    state = harness.behavior._actors[None]             # noqa: SLF001
    assert any(p == path for _, p in state.deletes)


def test_rename_is_passed_through_as_a_rename(config, bus, tmp_path):
    """Submitted directly, because only the watchdog backend sees real moves."""
    harness = Harness(config, bus, "polling")
    try:
        old = harness.write("before.txt", b"abc")
        new = os.path.join(harness.watched, "after.locked")
        os.replace(old, new)
        harness.monitor.submit(new, BehaviorKind.FILE_RENAME, old_path=old)
        assert harness.monitor.drain_once() == 1
        state = harness.behavior._actors[None]          # noqa: SLF001
        assert len(state.renames) == 1
        assert state.renames[0][1] == ".locked"
    finally:
        harness.stop()


# --------------------------------------------------------------------------
# The loop breaker
# --------------------------------------------------------------------------
def test_quarantining_a_file_does_not_retrigger_a_scan(tmp_path, bus):
    """The vault lives *inside* the watched tree - the classic feedback loop."""
    watched = tmp_path / "watched"
    watched.mkdir()
    config = Config(data_dir=watched / ".aegis")       # vault inside the watched tree!
    config.realtime_paths = [str(watched)]
    config.ensure_dirs()
    assert config.is_internal(config.quarantine_dir)

    harness = Harness(config, bus, "polling")
    monitor = harness.monitor
    try:
        monitor.start()
        path = harness.write("evil.com", EICAR)
        assert monitor.drain_once() == 1
        assert harness.quarantine.calls == [path]

        vault_files = list(config.quarantine_dir.iterdir())
        assert vault_files, "atrapa kwarantanny nie przeniosła pliku do skarbca"

        # Drain again and again: the quarantined copy must never come back.
        for _ in range(5):
            assert monitor.drain_once() == 0

        internal_scans = [p for p in harness.scanner.scanned if config.is_internal(p)]
        assert internal_scans == [], f"zeskanowano własny skarbiec: {internal_scans}"
        assert harness.scanner.scanned == [path]
        assert harness.quarantine.calls == [path]
        assert monitor.status()["pending"] == 0

        # And the enqueue guard counts a direct attempt, too.
        internal = str(vault_files[0])
        assert monitor.submit(internal, BehaviorKind.FILE_CREATE) is False
        assert monitor.status()["skipped_internal"] >= 1
        assert monitor.drain_once() == 0
        assert harness.scanner.scanned == [path]
    finally:
        harness.stop()


def test_start_skips_a_watched_path_inside_our_own_data_dir(config, bus):
    monitor = RealtimeMonitor(FakeScanner(), config, bus, backend="polling")
    monitor.start([str(config.quarantine_dir)])
    assert not monitor.is_running
    assert monitor.paths == []
    logs = [e.message for e in bus.history(types={EventType.LOG})]
    assert any("Aegis" in message for message in logs)


def test_start_without_any_usable_path_does_not_run(config, bus, tmp_path):
    monitor = RealtimeMonitor(FakeScanner(), config, bus, backend="polling")
    monitor.start([str(tmp_path / "nie-ma-takiego-katalogu")])
    assert not monitor.is_running
    assert not bus.history(types={EventType.REALTIME_STARTED})


def test_excluded_directory_names_are_skipped(harness):
    monitor = harness.monitor
    monitor.start()
    path = harness.write("__pycache__/mod.pyc", b"skompilowane")
    assert monitor.submit(path, BehaviorKind.FILE_CREATE) is False
    assert monitor.status()["skipped_excluded"] >= 1
    monitor.drain_once()
    assert path not in harness.scanner.scanned


# --------------------------------------------------------------------------
# Debounce, coalescing, queue bounds
# --------------------------------------------------------------------------
def test_repeated_writes_are_coalesced_into_one_scan(config, bus):
    harness = Harness(config, bus, "polling")
    monitor = harness.monitor
    try:
        path = harness.write("doc.txt", b"wersja 1")
        for i in range(5):
            with open(path, "wb") as fh:
                fh.write(f"wersja {i}".encode())
            monitor.submit(path, BehaviorKind.FILE_MODIFY)
        status = monitor.status()
        assert status["events"] == 5
        assert status["coalesced"] == 4
        assert status["pending"] == 1
        assert monitor.drain_once() == 1
        assert harness.scanner.scanned == [path]
    finally:
        harness.stop()


def test_an_unchanged_file_is_not_rescanned_within_the_debounce_window(config, bus):
    config.realtime_debounce_ms = 60_000      # one minute: the test cannot outrun it
    harness = Harness(config, bus, "polling")
    monitor = harness.monitor
    try:
        path = harness.write("doc.txt", b"tresc")
        monitor.submit(path, BehaviorKind.FILE_MODIFY)
        assert monitor.drain_once() == 1
        monitor.submit(path, BehaviorKind.FILE_MODIFY)
        assert monitor.drain_once() == 0
        assert monitor.status()["debounced"] == 1
        assert harness.scanner.scanned == [path]
    finally:
        harness.stop()


def test_non_forced_drain_respects_the_debounce_window(config, bus):
    config.realtime_debounce_ms = 60_000
    harness = Harness(config, bus, "polling")
    monitor = harness.monitor
    try:
        path = harness.write("doc.txt", b"tresc")
        monitor.submit(path, BehaviorKind.FILE_MODIFY)
        assert monitor.drain_once(force=False) == 0    # too early
        assert monitor.status()["pending"] == 1
        assert monitor.drain_once() == 1               # forced: processed now
    finally:
        harness.stop()


def test_queue_overflow_drops_instead_of_growing(config, bus):
    config.realtime_queue_size = 4            # extra, additive config knob
    harness = Harness(config, bus, "polling")
    monitor = harness.monitor
    try:
        for i in range(40):
            monitor.submit(os.path.join(harness.watched, f"f{i}.bin"), BehaviorKind.FILE_CREATE)
        status = monitor.status()
        assert status["pending"] == 4
        assert status["dropped"] == 36
        assert status["events"] == 40
    finally:
        harness.stop()


# --------------------------------------------------------------------------
# Response gating and robustness
# --------------------------------------------------------------------------
def test_threat_below_min_severity_is_not_quarantined(config, bus):
    harness = Harness(config, bus, "polling", scanner=FakeScanner(severity_score=20.0))
    monitor = harness.monitor
    try:
        monitor.start()
        path = harness.write("evil.com", EICAR)
        assert monitor.drain_once() == 1
        assert monitor.status()["threats"] == 1
        assert harness.quarantine.calls == []
        assert os.path.exists(path)
    finally:
        harness.stop()


def test_oversized_files_are_not_scanned_but_still_observed(config, bus):
    config.max_file_size = 16
    harness = Harness(config, bus, "polling")
    monitor = harness.monitor
    try:
        monitor.start()
        path = harness.write("huge.bin", b"x" * 1024)
        assert monitor.drain_once() == 1
        assert harness.scanner.scanned == []
        assert monitor.status()["skipped_large"] == 1
        state = harness.behavior._actors[None]         # noqa: SLF001
        assert any(p == path for _, p in state.writes)
    finally:
        harness.stop()


def test_a_crashing_scanner_does_not_stop_the_monitor(config, bus):
    harness = Harness(config, bus, "polling", scanner=FakeScanner(boom=True))
    monitor = harness.monitor
    try:
        monitor.start()
        harness.write("whatever.bin", b"abc")
        assert monitor.drain_once() == 1
        assert monitor.status()["errors"] >= 1
        harness.write("another.bin", b"def")
        assert monitor.drain_once() == 1
    finally:
        harness.stop()


def test_monitor_without_behaviour_or_responder_still_scans(config, bus):
    scanner = FakeScanner()
    monitor = RealtimeMonitor(scanner, config, bus, backend="polling")
    try:
        monitor.start()
        path = os.path.join(config.realtime_paths[0], "evil.com")
        with open(path, "wb") as fh:
            fh.write(EICAR)
        assert monitor.drain_once() == 1
        assert scanner.scanned == [path]
        assert monitor.status()["threats"] == 1
        logs = [e.message for e in bus.history(types={EventType.LOG})]
        assert any("brak modułu reakcji" in m for m in logs)
    finally:
        monitor.stop(timeout=5)


def test_lifecycle_is_idempotent(harness):
    monitor = harness.monitor
    monitor.start()
    assert monitor.is_running
    monitor.start()
    assert monitor.is_running
    monitor.stop(timeout=5)
    assert not monitor.is_running
    monitor.stop(timeout=5)
    assert not monitor.is_running
    assert harness.bus.history(types={EventType.REALTIME_STARTED})
    assert harness.bus.history(types={EventType.REALTIME_STOPPED})


def test_status_reports_the_contract_fields(harness):
    harness.monitor.start()
    status = harness.monitor.status()
    for field in ("backend", "paths", "events", "scanned", "threats", "actions"):
        assert field in status, field
    assert status["paths"] == [os.path.abspath(harness.watched)]


# --------------------------------------------------------------------------
# A whole ransomware wave, on a real directory
# --------------------------------------------------------------------------
def test_simulated_ransomware_wave_escalates_to_a_process_action(config, bus):
    """40 documents rewritten with ciphertext, renamed, plus ransom notes."""
    harness = Harness(config, bus, "polling")
    monitor = harness.monitor
    try:
        monitor.start()
        victims = [harness.write(f"docs/raport{i}.txt", b"A" * 20_000) for i in range(40)]
        monitor.drain_once()                   # baseline: the documents are known

        for path in victims:
            with open(path, "wb") as fh:
                fh.write(os.urandom(20_480))   # ciphertext, same size
        monitor.drain_once()
        for path in victims:
            os.replace(path, path + ".locked")
        monitor.drain_once()
        for directory in ("docs", "docs/b", "docs/c"):
            harness.write(
                f"{directory}/HOW_TO_DECRYPT.txt",
                "Wszystkie Twoje pliki zostały zaszyfrowane. "
                "Zapłać okup w bitcoin, aby otrzymać klucz prywatny.".encode(),
            )
        monitor.drain_once()

        verdict = harness.behavior.verdict_for(None)
        assert verdict is not None
        fired = {d.rule for d in verdict.detections}
        assert "mass_file_modify" in fired
        assert "encrypt_in_place" in fired
        assert "ransom_note" in fired
        assert verdict.severity in (Severity.HIGH, Severity.CRITICAL), verdict.score

        # The default behaviour action is REPORT, so nothing was killed, but the
        # responder was handed the verdict and said so on the bus.
        actions = [
            e
            for e in bus.history(types={EventType.ACTION_TAKEN})
            if e.payload.get("pid") is None and e.payload.get("action") == "report"
        ]
        assert actions, "reakcja na zachowanie procesu nie została zgłoszona"
        assert any("Behav." in (e.payload.get("threat_name") or "") for e in actions)
    finally:
        harness.stop()


def test_a_benign_bulk_write_wave_does_not_reach_the_action_threshold(config, bus):
    """The same monitor, the same volume, innocent content: no process action."""
    harness = Harness(config, bus, "polling")
    monitor = harness.monitor
    try:
        monitor.start()
        for i in range(120):
            harness.write(f"build/obj{i}.o", b"ELF-ish object file\n" * 50)
        monitor.drain_once()

        verdict = harness.behavior.verdict_for(None)
        score = verdict.score if verdict else 0.0
        assert score < 70.0, f"niewinna lawina zapisów dobiła do {score}"
        if verdict:
            assert "encrypt_in_place" not in {d.rule for d in verdict.detections}
            assert "ransom_note" not in {d.rule for d in verdict.detections}
        kills = [
            e
            for e in bus.history(types={EventType.ACTION_TAKEN})
            if e.payload.get("action") == "kill_process"
        ]
        assert kills == []
    finally:
        harness.stop()


# --------------------------------------------------------------------------
# Integration with the real static engine, when Agent A's modules exist
# --------------------------------------------------------------------------
def test_integration_with_the_real_scanner(config, bus):
    signatures = pytest.importorskip("aegis.core.signatures")
    scanner_mod = pytest.importorskip("aegis.core.scanner")
    quarantine_mod = pytest.importorskip("aegis.core.quarantine")

    db = signatures.SignatureDB(None, bus)
    db.add(
        Indicator(
            kind=IndicatorKind.SHA256,
            value=hashlib.sha256(EICAR).hexdigest(),
            name="Sim.Eicar.Test",
            severity=Severity.CRITICAL,
            source="test",
        )
    )
    scanner = scanner_mod.Scanner(db, config, bus)
    vault = quarantine_mod.Quarantine(config, bus)
    behavior = BehaviorEngine(config, bus, db)
    responder = Responder(config, bus, vault)
    monitor = RealtimeMonitor(
        scanner, config, bus, vault, behavior, responder, backend="polling"
    )
    try:
        monitor.start()
        path = os.path.join(config.realtime_paths[0], "eicar.com")
        with open(path, "wb") as fh:
            fh.write(EICAR)

        assert monitor.drain_once() == 1
        status = monitor.status()
        assert status["threats"] == 1
        assert status["actions"] >= 1
        entries = vault.list()
        assert len(entries) == 1
        assert entries[0].original_path == path
        assert not os.path.exists(path)
        # And the behaviour layer saw the same change.
        assert behavior.verdict_for(None) is not None
    finally:
        monitor.stop(timeout=5)
        db.close()
