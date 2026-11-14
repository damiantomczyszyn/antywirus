"""Process monitor: real processes, real sockets, no sleeping.

``poll_once()`` is synchronous, so every test here drives the monitor by hand:
prime the baseline, change the world, poll again, inspect the events.
"""

from __future__ import annotations

import os
import socket
import subprocess
import threading

import pytest

from aegis.models import BehaviorEvent, BehaviorKind, DetectionLayer, Indicator, IndicatorKind
from aegis.realtime.behavior import BehaviorEngine
from aegis.realtime.procmon import HAVE_PSUTIL, ProcessMonitor

try:  # pragma: no cover - mirrors the module under test
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


class FakeSignatureDB:
    def __init__(self, *indicators: Indicator) -> None:
        self.indicators = list(indicators)

    def lookup_network(self, *, host=None, url=None, ip=None):
        needle = (host or ip or url or "").lower()
        for indicator in self.indicators:
            if indicator.value == needle:
                return indicator
        return None


class RecordingEngine:
    """Captures what the monitor feeds the behaviour layer."""

    def __init__(self, raises: bool = False) -> None:
        self.events: list[BehaviorEvent] = []
        self.raises = raises

    def observe(self, event):
        self.events.append(event)
        if self.raises:
            raise RuntimeError("błąd reguły")
        return []


@pytest.fixture()
def spawn():
    children: list[subprocess.Popen] = []

    def _spawn(args=("sleep", "30")) -> subprocess.Popen:
        proc = subprocess.Popen(list(args))
        children.append(proc)
        return proc

    yield _spawn

    for proc in children:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            pass


@pytest.fixture()
def loopback_server():
    """A real listening socket on 127.0.0.1, so NET_CONNECT has something to find."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    accepted: list[socket.socket] = []
    stop = threading.Event()

    def accept_loop() -> None:
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except OSError:
                continue
            accepted.append(conn)

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    yield server.getsockname()[1]
    stop.set()
    thread.join(timeout=2)
    for conn in accepted:
        conn.close()
    server.close()


def events_of(events, kind: BehaviorKind) -> list[BehaviorEvent]:
    return [e for e in events if e.kind is kind]


# --------------------------------------------------------------------------
# Backend selection and degradation
# --------------------------------------------------------------------------
def test_backend_is_detected(config, bus):
    monitor = ProcessMonitor(config, bus, BehaviorEngine(config, bus))
    assert monitor.backend in ("psutil", "procfs", "none")
    if HAVE_PSUTIL:
        assert monitor.backend == "psutil"
    elif os.path.isdir("/proc"):  # pragma: no cover - psutil is installed here
        assert monitor.backend == "procfs"


def test_none_backend_degrades_silently(config, bus):
    monitor = ProcessMonitor(config, bus, BehaviorEngine(config, bus))
    monitor._backend = "none"                 # noqa: SLF001
    assert monitor.poll_once() == []
    monitor.start()
    assert not monitor.is_running
    assert monitor.status()["backend"] == "none"
    monitor.stop()


def test_disabled_monitor_does_not_start(config, bus):
    config.procmon_enabled = False
    monitor = ProcessMonitor(config, bus, BehaviorEngine(config, bus))
    monitor.start()
    assert not monitor.is_running
    monitor.stop()


# --------------------------------------------------------------------------
# Process lifecycle
# --------------------------------------------------------------------------
def test_first_poll_only_primes_the_baseline(config, bus):
    engine = RecordingEngine()
    monitor = ProcessMonitor(config, bus, engine)  # type: ignore[arg-type]
    assert monitor.poll_once() == []
    assert engine.events == []
    status = monitor.status()
    assert status["primed"] is True
    assert status["processes"] > 0
    assert status["polls"] == 1


def test_new_process_is_reported_as_process_start(config, bus, spawn):
    engine = RecordingEngine()
    monitor = ProcessMonitor(config, bus, engine)  # type: ignore[arg-type]
    monitor.poll_once()

    proc = spawn()
    events = monitor.poll_once()

    starts = {e.pid: e for e in events_of(events, BehaviorKind.PROCESS_START)}
    assert proc.pid in starts, "nowy proces nie został zauważony"
    event = starts[proc.pid]
    assert event.ppid == os.getpid()
    assert "sleep" in (event.process or "") or "sleep" in (event.path or "")
    assert event.extra["backend"] == monitor.backend
    # The behaviour engine really was fed.
    assert any(e.pid == proc.pid for e in engine.events)


def test_exiting_process_is_reported_as_process_stop(config, bus, spawn):
    proc = spawn()
    monitor = ProcessMonitor(config, bus, BehaviorEngine(config, bus))
    monitor.poll_once()                 # baseline: the process is alive

    proc.kill()
    proc.wait(timeout=5)
    events = monitor.poll_once()

    stops = [e.pid for e in events_of(events, BehaviorKind.PROCESS_STOP)]
    assert proc.pid in stops
    assert monitor.status()["events"] >= 1


def test_process_start_feeds_real_behaviour_rules(config, bus, spawn):
    """End to end: procmon observation -> behaviour engine state."""
    engine = BehaviorEngine(config, bus)
    monitor = ProcessMonitor(config, bus, engine)
    monitor.poll_once()
    proc = spawn()
    monitor.poll_once()
    assert engine.verdict_for(proc.pid) is not None


def test_poll_survives_a_crashing_rule(config, bus, spawn):
    engine = RecordingEngine(raises=True)
    monitor = ProcessMonitor(config, bus, engine)  # type: ignore[arg-type]
    monitor.poll_once()
    spawn()
    events = monitor.poll_once()
    assert events, "zdarzenia powinny zostać zwrócone nawet gdy reguła rzuca wyjątek"
    assert monitor.status()["errors"] >= 1


def test_poll_survives_an_unreadable_process_table(config, bus, monkeypatch):
    engine = RecordingEngine()
    monitor = ProcessMonitor(config, bus, engine)  # type: ignore[arg-type]
    monitor.poll_once()

    class Exploding:
        @property
        def info(self):
            raise RuntimeError("proces zniknął w trakcie iteracji")

    if HAVE_PSUTIL:
        monkeypatch.setattr(psutil, "process_iter", lambda *a, **k: [Exploding()])
    else:  # pragma: no cover
        monkeypatch.setattr(monitor, "_sample_processes_procfs", dict)
    assert isinstance(monitor.poll_once(), list)


@pytest.mark.skipif(not os.path.isdir("/proc"), reason="backend procfs wymaga /proc")
def test_procfs_backend_sees_processes(config, bus, spawn):
    """The stdlib-only fallback must work even though psutil is installed."""
    engine = RecordingEngine()
    monitor = ProcessMonitor(config, bus, engine)  # type: ignore[arg-type]
    monitor._backend = "procfs"               # noqa: SLF001
    monitor.poll_once()
    proc = spawn()
    events = monitor.poll_once()
    starts = {e.pid for e in events_of(events, BehaviorKind.PROCESS_START)}
    assert proc.pid in starts
    event = next(e for e in events if e.pid == proc.pid)
    assert event.process == "sleep"
    assert event.ppid == os.getpid()


# --------------------------------------------------------------------------
# Connections
# --------------------------------------------------------------------------
def _connections_readable() -> bool:
    if not HAVE_PSUTIL:
        return os.path.isfile("/proc/net/tcp")
    try:
        psutil.net_connections(kind="inet")
    except Exception:  # noqa: BLE001 - AccessDenied on locked-down systems
        return False
    return True


@pytest.mark.skipif(not _connections_readable(), reason="brak dostępu do tablicy połączeń")
def test_outbound_connection_is_reported(config, bus, loopback_server):
    engine = RecordingEngine()
    monitor = ProcessMonitor(config, bus, engine)  # type: ignore[arg-type]
    monitor.poll_once()

    client = socket.create_connection(("127.0.0.1", loopback_server), timeout=5)
    try:
        events = monitor.poll_once()
        mine = [
            e
            for e in events_of(events, BehaviorKind.NET_CONNECT)
            if e.pid == os.getpid() and e.remote_port == loopback_server
        ]
        assert mine, "połączenie wychodzące nie zostało zauważone"
        assert mine[0].remote_host == "127.0.0.1"
        # The same endpoint is not reported twice.
        again = monitor.poll_once()
        assert not [
            e
            for e in events_of(again, BehaviorKind.NET_CONNECT)
            if e.pid == os.getpid() and e.remote_port == loopback_server
        ]
    finally:
        client.close()


@pytest.mark.skipif(not _connections_readable(), reason="brak dostępu do tablicy połączeń")
def test_connection_to_a_blocklisted_address_fires_the_intel_rule(config, bus, loopback_server):
    """procmon -> behaviour -> intel, with a blocklisted loopback address."""
    db = FakeSignatureDB(
        Indicator(
            kind=IndicatorKind.IPV4,
            value="127.0.0.1",
            name="Sim.C2.Loopback",
            source="test",
        )
    )
    engine = BehaviorEngine(config, bus, db)
    monitor = ProcessMonitor(config, bus, engine, db)
    monitor.poll_once()

    client = socket.create_connection(("127.0.0.1", loopback_server), timeout=5)
    try:
        monitor.poll_once()
        verdict = engine.verdict_for(os.getpid())
        assert verdict is not None
        intel = [d for d in verdict.detections if d.layer is DetectionLayer.INTEL]
        assert intel, "reguła intel nie zadziałała"
        assert intel[0].rule == "blocklisted_connection"
        assert intel[0].threat_name == "Sim.C2.Loopback"
    finally:
        client.close()


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("0100007F:1F90", ("127.0.0.1", 8080)),
        ("4D71D9AC:01BB", ("172.217.113.77", 443)),
        ("0100007F:0000", None),
        ("brak", None),
        ("ZZ:01BB", None),
        (
            "000080FE00000000FF7A5BDA3B0C2AFE:0050",
            ("fe80:0000:0000:0000:da5b:7aff:fe2a:0c3b", 80),
        ),
    ],
)
def test_hex_endpoint_parser(raw, expected):
    assert ProcessMonitor._parse_hex_endpoint(raw) == expected   # noqa: SLF001


# --------------------------------------------------------------------------
# Threading
# --------------------------------------------------------------------------
def test_start_and_stop_the_sampling_thread(config, bus):
    config.procmon_interval_sec = 0.1
    monitor = ProcessMonitor(config, bus, BehaviorEngine(config, bus))
    monitor.start()
    try:
        assert monitor.is_running
        monitor.start()                       # idempotent
        assert monitor.is_running
    finally:
        monitor.stop(timeout=5)
    assert not monitor.is_running
    status = monitor.status()
    assert status["polls"] >= 1
    assert status["running"] is False


def test_stop_without_start_is_safe(config, bus):
    monitor = ProcessMonitor(config, bus, BehaviorEngine(config, bus))
    monitor.stop()
    assert not monitor.is_running


def test_status_shape(config, bus):
    monitor = ProcessMonitor(config, bus, BehaviorEngine(config, bus))
    status = monitor.status()
    assert set(status) >= {
        "backend", "running", "primed", "processes", "polls", "events",
        "errors", "interval", "enabled",
    }
