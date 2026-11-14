"""End-to-end tests that cross every subsystem boundary.

These are the integrator's tests: each one exercises code written by a
different part of the project at the same time, so a contract drift that the
per-module unit tests happily miss shows up here.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from aegis.config import Config
from aegis.core.quarantine import Quarantine
from aegis.core.scanner import Scanner
from aegis.core.signatures import SignatureDB
from aegis.engine.verdict import explain, fuse
from aegis.events import EventBus, EventType
from aegis.intel.baseline import ensure_baseline
from aegis.models import (
    ActionKind,
    BehaviorEvent,
    BehaviorKind,
    DetectionLayer,
    Severity,
)
from aegis.realtime.behavior import BehaviorEngine
from aegis.realtime.responder import Responder
from aegis.realtime.watcher import RealtimeMonitor

EICAR = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
).encode()


@pytest.fixture()
def stack(tmp_path):
    """A fully wired product instance rooted in tmp_path."""
    cfg = Config(data_dir=tmp_path / "state")
    cfg.realtime_paths = [str(tmp_path / "watched")]
    cfg.realtime_action = ActionKind.QUARANTINE
    cfg.procmon_enabled = False
    cfg.ensure_dirs()
    (tmp_path / "watched").mkdir(parents=True, exist_ok=True)

    bus = EventBus()
    db = SignatureDB(cfg.db_path, bus=bus)
    added = ensure_baseline(db)
    assert added > 0, "baseline DB shipped empty"

    quarantine = Quarantine(cfg, bus=bus)
    scanner = Scanner(db, cfg, bus=bus)
    behavior = BehaviorEngine(cfg, bus=bus, db=db)
    responder = Responder(cfg, bus, quarantine)

    yield dict(
        cfg=cfg, bus=bus, db=db, scanner=scanner, quarantine=quarantine,
        behavior=behavior, responder=responder, tmp=tmp_path,
    )
    db.close()


# ---------------------------------------------------------------- signatures
def test_baseline_detects_eicar_by_hash(stack, tmp_path):
    """The shipped DB must catch EICAR on a machine that has never seen a feed."""
    sample = tmp_path / "eicar.com"
    sample.write_bytes(EICAR)

    verdict = stack["scanner"].scan_file(sample)

    assert verdict.severity is Severity.CRITICAL, explain(verdict.detections)
    assert verdict.score == 100.0
    layers = {d.layer for d in verdict.detections}
    assert DetectionLayer.SIGNATURE in layers


def test_benign_files_stay_clean(stack, tmp_path):
    """False positives are the thing that makes people uninstall an antivirus."""
    benign = {
        "notes.txt": b"Lista zakupow: mleko, chleb, kawa.\n" * 40,
        "config.json": json.dumps({"host": "localhost", "port": 8080}).encode(),
        "script.py": b"import sys\n\ndef main():\n    print('hello')\n\nmain()\n",
        "data.csv": b"id,name,value\n" + b"".join(b"%d,row,%d\n" % (i, i) for i in range(200)),
    }
    for name, data in benign.items():
        (tmp_path / name).write_bytes(data)

    result = stack["scanner"].scan_paths([tmp_path])
    flagged = [v for v in result.verdicts if v.is_threat and Path(v.path).name in benign]
    assert not flagged, "\n".join(f"{v.path}: {explain(v.detections)}" for v in flagged)


def test_archive_member_is_found(stack, tmp_path):
    """Malware in a zip is still malware."""
    import zipfile

    archive = tmp_path / "paczka.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("faktura.txt", "nic ciekawego")
        zf.writestr("payload.com", EICAR)

    verdict = stack["scanner"].scan_file(archive)
    assert verdict.is_threat, explain(verdict.detections)


# ---------------------------------------------------------------- heuristics
def test_heuristics_alone_never_reach_quarantine_threshold(stack, tmp_path):
    """A packed-but-unknown file is suspicious, not condemned."""
    import os

    blob = tmp_path / "packed.bin"
    blob.write_bytes(b"MZ" + os.urandom(200_000))

    verdict = stack["scanner"].scan_file(blob)
    heur_only = all(d.layer is DetectionLayer.HEURISTIC for d in verdict.detections)
    if verdict.detections and heur_only:
        assert verdict.score <= 55.0, explain(verdict.detections)
        assert verdict.severity in (Severity.CLEAN, Severity.LOW, Severity.MEDIUM)


# ------------------------------------------------------------------ behavior
def _ransomware_burst(engine: BehaviorEngine, tmp_path: Path, count: int = 40):
    """Replay what RealtimeMonitor actually emits during a ransomware run.

    The shape matters as much as the volume: the engine's encrypt_in_place rule
    compares each write against the file's previous size and entropy (which the
    real watcher carries in BehaviorEvent.extra), and the ransom-note rule wants
    notes in more than one directory. A burst without that context is not a
    ransomware burst - it is just a lot of writes, and it should score lower.
    """
    now = time.time()
    dirs = [tmp_path / "dokumenty", tmp_path / "zdjecia", tmp_path / "projekty"]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)

    for i in range(count):
        target = dirs[i % len(dirs)] / f"dokument_{i}.docx"
        engine.observe(BehaviorEvent(
            kind=BehaviorKind.FILE_MODIFY, timestamp=now + i * 0.05, path=str(target),
            pid=4242, process="sim_ransom.py", size=24_000, entropy=7.93,
            # Same size, entropy jumped from ordinary-document to noise:
            # rewritten in place, i.e. encrypted rather than replaced.
            extra={"prev_size": 23_800, "prev_entropy": 4.20},
        ))
        engine.observe(BehaviorEvent(
            kind=BehaviorKind.FILE_RENAME, timestamp=now + i * 0.05, pid=4242,
            process="sim_ransom.py", old_path=str(target),
            path=str(target) + ".aegislocked",
        ))

    for d in dirs:
        engine.observe(BehaviorEvent(
            kind=BehaviorKind.FILE_CREATE, timestamp=now + 3, pid=4242,
            process="sim_ransom.py", path=str(d / "PRZECZYTAJ_MNIE.txt"),
            extra={"sample_text": "Twoje pliki zostały zaszyfrowane. "
                                  "Zapłać okup, aby odzyskać dostęp do danych."},
        ))


def test_ransomware_behaviour_is_caught_without_any_signature(stack, tmp_path):
    """The whole point of behavioural analysis: zero signatures, still caught."""
    engine = stack["behavior"]
    _ransomware_burst(engine, tmp_path)

    verdicts = engine.verdicts()
    assert verdicts, "behaviour engine produced no verdict for a ransomware burst"
    worst = max(verdicts, key=lambda v: v.score)
    assert worst.severity in (Severity.HIGH, Severity.CRITICAL), explain(worst.detections)


def test_benign_bulk_write_does_not_trigger_response(stack, tmp_path):
    """An unzip or a compiler writes a lot of files fast. That is not an attack."""
    engine = stack["behavior"]
    now = time.time()
    for i in range(60):
        engine.observe(BehaviorEvent(
            kind=BehaviorKind.FILE_CREATE, timestamp=now + i * 0.02,
            path=str(tmp_path / f"build/obj_{i}.o"), pid=777, process="make",
            size=4096, entropy=4.1,
        ))
    worst = max((v.score for v in engine.verdicts()), default=0.0)
    assert worst < 70.0, "benign bulk write escalated to HIGH"


def test_blocklisted_connection_fires_on_the_intel_layer(stack):
    """A network hit must come in as INTEL so the cross-layer bonus can apply."""
    from aegis.models import Indicator, IndicatorKind

    stack["db"].add(Indicator(
        kind=IndicatorKind.IPV4, value="203.0.113.77", name="Intel.C2.Test",
        source="test",
    ))
    dets = stack["behavior"].observe(BehaviorEvent(
        kind=BehaviorKind.NET_CONNECT, pid=99, process="sim_beacon.py",
        remote_host="203.0.113.77", remote_port=8443,
    ))
    assert any(d.layer is DetectionLayer.INTEL for d in dets), dets


def test_cross_layer_fusion_beats_either_layer_alone(stack, tmp_path):
    """Static suspicion + runtime behaviour must outrank both on their own."""
    from aegis.models import Detection

    heur = Detection(DetectionLayer.HEURISTIC, "high_entropy", "Heur.Packed", 30.0)
    behav = Detection(DetectionLayer.BEHAVIOR, "mass_file_modify", "Behav.MassWrite", 55.0)

    only_heur, _ = fuse([heur])
    only_behav, _ = fuse([behav])
    both, severity = fuse([heur, behav])

    assert both > only_heur + only_behav - 1e-9
    assert severity is Severity.HIGH


# ----------------------------------------------------------------- quarantine
def test_quarantine_round_trip_preserves_bytes(stack, tmp_path):
    sample = tmp_path / "watched" / "probka.com"
    sample.write_bytes(EICAR)
    original = sample.read_bytes()

    verdict = stack["scanner"].scan_file(sample)
    action = stack["quarantine"].quarantine(sample, verdict)
    assert action.ok, action.detail
    assert not sample.exists(), "quarantine left the original in place"

    entries = stack["quarantine"].list()
    assert len(entries) == 1
    assert stack["quarantine"].read_payload(entries[0].entry_id) == original

    restored = stack["quarantine"].restore(entries[0].entry_id)
    assert restored.ok, restored.detail
    assert sample.read_bytes() == original


def test_vault_file_is_not_stored_verbatim(stack, tmp_path):
    """A quarantined sample must not sit on disk ready to be double-clicked."""
    sample = tmp_path / "watched" / "probka2.com"
    sample.write_bytes(EICAR)
    stack["quarantine"].quarantine(sample, stack["scanner"].scan_file(sample))

    for path in stack["cfg"].quarantine_dir.rglob("*"):
        if path.is_file() and path.name != "index.json":
            assert EICAR not in path.read_bytes(), f"{path} holds the raw sample"


# ------------------------------------------------------------------- realtime
def test_realtime_quarantines_a_dropped_threat(stack, tmp_path):
    """Drop EICAR into a watched folder; it should not survive."""
    watched = tmp_path / "watched"
    monitor = RealtimeMonitor(
        stack["scanner"], stack["cfg"], stack["bus"],
        quarantine=stack["quarantine"], behavior=stack["behavior"],
        responder=stack["responder"],
    )
    seen: list = []
    stack["bus"].subscribe(lambda e: seen.append(e) if e.type in (
        EventType.THREAT_FOUND, EventType.ACTION_TAKEN) else None)

    monitor.start([str(watched)])
    try:
        dropped = watched / "pobrane.com"
        dropped.write_bytes(EICAR)
        deadline = time.time() + 15
        while time.time() < deadline:
            monitor.drain_once()
            if not dropped.exists():
                break
            time.sleep(0.2)
    finally:
        monitor.stop()

    assert not dropped.exists(), f"threat survived realtime protection; events={seen}"
    assert any(e.type is EventType.THREAT_FOUND for e in seen)
    assert stack["quarantine"].list(), "nothing landed in quarantine"


def test_realtime_never_scans_its_own_quarantine(stack, tmp_path):
    """Without this guard, quarantining triggers a scan that triggers a quarantine."""
    cfg = stack["cfg"]
    assert cfg.is_internal(cfg.quarantine_dir / "anything.aegisq")
    monitor = RealtimeMonitor(stack["scanner"], cfg, stack["bus"],
                              quarantine=stack["quarantine"])
    monitor.start([str(cfg.quarantine_dir)])
    try:
        (cfg.quarantine_dir / "loop.aegisq").write_bytes(EICAR)
        for _ in range(5):
            monitor.drain_once()
            time.sleep(0.1)
    finally:
        monitor.stop()
    assert monitor.status().get("threats", 0) == 0


# ------------------------------------------------------------------ responder
def test_responder_refuses_to_kill_itself(stack):
    import os

    result = stack["responder"].kill_process_tree(os.getpid(), dry_run=True)
    assert not result.ok, "responder was willing to kill its own process"

    result = stack["responder"].kill_process_tree(1, dry_run=True)
    assert not result.ok, "responder was willing to kill PID 1"


# ----------------------------------------------------------------- controller
def test_controller_boots_and_reports_a_dashboard(tmp_path):
    from aegis.gui.controller import AegisController

    cfg = Config(data_dir=tmp_path / "ctrl")
    cfg.realtime_paths = [str(tmp_path / "w")]
    (tmp_path / "w").mkdir()
    cfg.ensure_dirs()

    controller = AegisController(cfg)
    try:
        dash = controller.dashboard()
        assert isinstance(dash, dict) and dash
        sample = tmp_path / "w" / "eicar.com"
        sample.write_bytes(EICAR)
        assert controller.start_scan([str(tmp_path / "w")])
        deadline = time.time() + 30
        while controller.scan_running and time.time() < deadline:
            time.sleep(0.1)
        result = controller.last_scan()
        assert result is not None and result.threats, "controller scan found nothing"
    finally:
        controller.shutdown()
