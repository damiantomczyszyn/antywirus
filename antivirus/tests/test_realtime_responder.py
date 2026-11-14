"""Responder: does it act, and does it refuse to shoot itself in the foot?"""

from __future__ import annotations

import os
import shutil
import subprocess
import time

import pytest

from aegis.events import EventType
from aegis.models import (
    SCORE_BEHAVIOR_STRONG,
    SCORE_HASH_MATCH,
    ActionKind,
    ActionResult,
    Detection,
    DetectionLayer,
    FileVerdict,
    ProcessVerdict,
    Severity,
)
from aegis.engine.verdict import apply_to_file_verdict, apply_to_process_verdict
from aegis.realtime.responder import HAVE_PSUTIL, Responder


# --------------------------------------------------------------------------
# Lightweight stand-ins for Agent A's modules
# --------------------------------------------------------------------------
class FakeQuarantine:
    """Records calls and really moves the file, like the contract's vault."""

    def __init__(self, config, fail: bool = False) -> None:
        self.config = config
        self.calls: list[tuple[str, str]] = []
        self.fail = fail
        self._counter = 0

    def quarantine(self, path, verdict=None, threat_name="") -> ActionResult:
        self.calls.append((str(path), threat_name))
        if self.fail:
            raise OSError("skarbiec niedostępny")
        self._counter += 1
        entry_id = f"entry{self._counter}"
        self.config.quarantine_dir.mkdir(parents=True, exist_ok=True)
        target = self.config.quarantine_dir / f"{entry_id}.bin"
        try:
            shutil.move(str(path), str(target))
        except OSError as exc:
            return ActionResult(
                kind=ActionKind.QUARANTINE, target=str(path), ok=False, detail=str(exc)
            )
        return ActionResult(
            kind=ActionKind.QUARANTINE,
            target=str(path),
            ok=True,
            detail=f"entry_id={entry_id}",
        )


class FakeScanner:
    """Flags every path listed in ``bad`` as a signature hit."""

    def __init__(self, bad: set[str] | None = None) -> None:
        self.bad = {str(p) for p in (bad or set())}
        self.scanned: list[str] = []

    def scan_file(self, path, *, data=None) -> FileVerdict:
        self.scanned.append(str(path))
        verdict = FileVerdict(path=str(path), size=os.path.getsize(path) if os.path.exists(path) else 0)
        if str(path) in self.bad:
            verdict.detections.append(
                Detection(
                    layer=DetectionLayer.SIGNATURE,
                    rule="sha256_match",
                    threat_name="Sim.Ransom.Payload",
                    score=SCORE_HASH_MATCH,
                )
            )
        return apply_to_file_verdict(verdict)


def file_threat(path, *, severity_score: float = SCORE_HASH_MATCH) -> FileVerdict:
    verdict = FileVerdict(path=str(path), size=68)
    verdict.detections.append(
        Detection(
            layer=DetectionLayer.SIGNATURE,
            rule="sha256_match",
            threat_name="Sim.Eicar.Test",
            score=severity_score,
        )
    )
    return apply_to_file_verdict(verdict)


def process_threat(pid: int | None, *, touched: list[str] | None = None) -> ProcessVerdict:
    verdict = ProcessVerdict(pid=pid, process="locker.bin", cmdline="./locker.bin")
    for rule in ("mass_file_modify", "encrypt_in_place", "mass_rename_extension"):
        verdict.detections.append(
            Detection(
                layer=DetectionLayer.BEHAVIOR,
                rule=rule,
                threat_name=f"Behav.{rule}",
                score=SCORE_BEHAVIOR_STRONG,
                pid=pid,
            )
        )
    verdict.touched_paths = list(touched or [])
    return apply_to_process_verdict(verdict)


@pytest.fixture()
def spawn():
    """Spawn throwaway child processes and guarantee they are reaped."""
    children: list[subprocess.Popen] = []

    def _spawn(args=("sleep", "30")) -> subprocess.Popen:
        proc = subprocess.Popen(list(args))
        children.append(proc)
        return proc

    yield _spawn

    for proc in children:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            pass


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------
def test_quarantine_is_the_default_file_action(config, bus, tmp_path):
    sample = tmp_path / "watched" / "evil.bin"
    sample.write_bytes(b"X5O!P%@AP")
    vault = FakeQuarantine(config)
    responder = Responder(config, bus, vault)

    results = responder.handle_file_threat(file_threat(sample))

    assert [r.kind for r in results] == [ActionKind.QUARANTINE]
    assert results[0].ok
    assert "entry_id=" in results[0].detail
    assert vault.calls == [(str(sample), "Sim.Eicar.Test")]
    assert not sample.exists()
    actions = bus.history(types={EventType.ACTION_TAKEN})
    assert actions and actions[-1].payload["action"] == "quarantine"


def test_file_threat_below_min_severity_is_only_reported(config, bus, tmp_path):
    sample = tmp_path / "watched" / "maybe.bin"
    sample.write_bytes(b"data")
    config.realtime_min_severity = "high"
    vault = FakeQuarantine(config)
    responder = Responder(config, bus, vault)

    # 12 points of heuristic evidence -> LOW, far under the HIGH floor.
    verdict = file_threat(sample, severity_score=20.0)
    assert verdict.severity is Severity.LOW
    results = responder.handle_file_threat(verdict)

    assert [r.kind for r in results] == [ActionKind.REPORT]
    assert vault.calls == []
    assert sample.exists()


def test_delete_action_removes_the_file(config, bus, tmp_path):
    sample = tmp_path / "watched" / "evil.bin"
    sample.write_bytes(b"evil")
    config.realtime_action = ActionKind.DELETE
    responder = Responder(config, bus, FakeQuarantine(config))

    results = responder.handle_file_threat(file_threat(sample))

    assert results[0].kind is ActionKind.DELETE and results[0].ok
    assert not sample.exists()


def test_report_action_leaves_the_file_alone(config, bus, tmp_path):
    sample = tmp_path / "watched" / "evil.bin"
    sample.write_bytes(b"evil")
    config.realtime_action = ActionKind.REPORT
    vault = FakeQuarantine(config)
    responder = Responder(config, bus, vault)

    results = responder.handle_file_threat(file_threat(sample))

    assert results[0].kind is ActionKind.REPORT and results[0].ok
    assert vault.calls == []
    assert sample.exists()


def test_dry_run_never_touches_the_file(config, bus, tmp_path):
    sample = tmp_path / "watched" / "evil.bin"
    sample.write_bytes(b"evil")
    vault = FakeQuarantine(config)
    responder = Responder(config, bus, vault, dry_run=True)

    results = responder.handle_file_threat(file_threat(sample))

    assert results[0].ok and "[próba]" in results[0].detail
    assert vault.calls == []
    assert sample.exists()

    # Per-call override works too, in both directions.
    assert "[próba]" in responder.handle_file_threat(
        file_threat(sample), dry_run=True
    )[0].detail
    responder.dry_run = False
    config.realtime_action = ActionKind.DELETE
    assert responder.handle_file_threat(file_threat(sample))[0].ok
    assert not sample.exists()


def test_clean_verdict_triggers_no_action(config, bus, tmp_path):
    sample = tmp_path / "watched" / "ok.txt"
    sample.write_text("nic ciekawego", encoding="utf-8")
    responder = Responder(config, bus, FakeQuarantine(config))
    assert responder.handle_file_threat(FileVerdict(path=str(sample))) == []


def test_threat_inside_our_own_data_dir_is_refused(config, bus):
    internal = config.quarantine_dir / "entry1.bin"
    internal.write_bytes(b"zaciemniony")
    vault = FakeQuarantine(config)
    responder = Responder(config, bus, vault)

    results = responder.handle_file_threat(file_threat(internal))

    assert results[0].kind is ActionKind.REPORT
    assert not results[0].ok
    assert vault.calls == []
    assert internal.exists()


def test_quarantine_failure_is_reported_not_raised(config, bus, tmp_path):
    sample = tmp_path / "watched" / "evil.bin"
    sample.write_bytes(b"evil")
    responder = Responder(config, bus, FakeQuarantine(config, fail=True))

    results = responder.handle_file_threat(file_threat(sample))

    assert results[0].kind is ActionKind.QUARANTINE
    assert not results[0].ok
    assert "skarbiec" in results[0].detail
    assert sample.exists()


def test_missing_quarantine_module_degrades_to_report(config, bus, tmp_path):
    sample = tmp_path / "watched" / "evil.bin"
    sample.write_bytes(b"evil")
    responder = Responder(config, bus, None)  # type: ignore[arg-type]
    results = responder.handle_file_threat(file_threat(sample))
    assert results[0].kind is ActionKind.REPORT and not results[0].ok
    assert sample.exists()


# --------------------------------------------------------------------------
# Self-protection: the rules that keep the antivirus alive
# --------------------------------------------------------------------------
def test_kill_process_tree_refuses_init(config, bus):
    responder = Responder(config, bus, FakeQuarantine(config))
    result = responder.kill_process_tree(1)
    assert isinstance(result, ActionResult)
    assert result.kind is ActionKind.KILL_PROCESS
    assert not result.ok
    assert "PID 1" in result.detail
    assert alive(1)


def test_kill_process_tree_refuses_own_process(config, bus):
    responder = Responder(config, bus, FakeQuarantine(config))
    result = responder.kill_process_tree(os.getpid())
    assert not result.ok
    assert "własny proces" in result.detail
    assert alive(os.getpid())


def test_kill_process_tree_refuses_its_own_parent(config, bus):
    responder = Responder(config, bus, FakeQuarantine(config))
    result = responder.kill_process_tree(os.getppid())
    assert not result.ok
    assert "przodkiem" in result.detail
    assert alive(os.getppid())


def test_kill_process_tree_refuses_every_ancestor(config, bus):
    """Walk the whole chain up from the test process; none may be killable."""
    responder = Responder(config, bus, FakeQuarantine(config))
    ancestors = responder._own_ancestors()          # noqa: SLF001
    assert ancestors, "nie udało się ustalić przodków procesu testowego"
    for pid in ancestors:
        result = responder.kill_process_tree(pid)
        assert not result.ok, f"zgodzono się zabić przodka {pid}"
        assert alive(pid) or pid == 1


@pytest.mark.parametrize("pid", [0, -1, -4242])
def test_kill_process_tree_refuses_nonsense_pids(config, bus, pid):
    responder = Responder(config, bus, FakeQuarantine(config))
    result = responder.kill_process_tree(pid)
    assert not result.ok
    assert "odmowa" in result.detail


def test_kill_process_tree_reports_a_missing_process(config, bus):
    responder = Responder(config, bus, FakeQuarantine(config))
    result = responder.kill_process_tree(4_000_000)
    assert not result.ok
    assert "nie istnieje" in result.detail


def test_kill_refusal_is_published(config, bus):
    responder = Responder(config, bus, FakeQuarantine(config))
    responder.kill_process_tree(1)
    actions = bus.history(types={EventType.ACTION_TAKEN})
    assert len(actions) == 1
    assert actions[0].payload["ok"] is False
    assert actions[0].level == "warning"


# --------------------------------------------------------------------------
# Real termination
# --------------------------------------------------------------------------
def test_dry_run_kill_leaves_the_process_running(config, bus, spawn):
    proc = spawn()
    responder = Responder(config, bus, FakeQuarantine(config))
    result = responder.kill_process_tree(proc.pid, dry_run=True)
    assert result.ok
    assert "[próba]" in result.detail
    assert alive(proc.pid)


def test_kill_process_tree_kills_the_whole_tree(config, bus, spawn):
    # A shell that forks a child and waits: two pids, one tree.
    parent = spawn(("sh", "-c", "sleep 30 & sleep 30"))
    deadline = time.monotonic() + 5.0
    children: list[int] = []
    while time.monotonic() < deadline and not children:
        children = _children_of(parent.pid)
    assert children, "proces potomny nie wystartował"

    responder = Responder(config, bus, FakeQuarantine(config))
    result = responder.kill_process_tree(parent.pid)

    assert result.ok, result.detail
    parent.wait(timeout=5)
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and any(alive(pid) for pid in children):
        pass
    assert not any(alive(pid) for pid in children), "potomek przeżył zabicie drzewa"


def _children_of(pid: int) -> list[int]:
    out: list[int] = []
    try:
        entries = [int(name) for name in os.listdir("/proc") if name.isdigit()]
    except OSError:  # pragma: no cover - non-Linux
        return out
    for candidate in entries:
        try:
            with open(f"/proc/{candidate}/stat", "rb") as fh:
                raw = fh.read()
            tail = raw[raw.rindex(b")") + 2 :].split()
            if int(tail[1]) == pid:
                out.append(candidate)
        except (OSError, ValueError, IndexError):
            continue
    return out


# --------------------------------------------------------------------------
# Processes
# --------------------------------------------------------------------------
def test_default_config_never_kills_anything(config, bus, spawn):
    """``behavior_action`` defaults to REPORT - that default must be harmless."""
    proc = spawn()
    assert config.behavior_action is ActionKind.REPORT
    responder = Responder(config, bus, FakeQuarantine(config))

    verdict = process_threat(proc.pid)
    assert verdict.severity in (Severity.HIGH, Severity.CRITICAL)
    results = responder.handle_process_threat(verdict)

    assert [r.kind for r in results] == [ActionKind.REPORT]
    assert results[0].ok
    assert alive(proc.pid)


def test_process_threat_below_threshold_is_only_reported(config, bus):
    responder = Responder(config, bus, FakeQuarantine(config))
    assert responder.process_min_severity is Severity.HIGH

    verdict = ProcessVerdict(pid=1234)
    verdict.detections.append(
        Detection(
            layer=DetectionLayer.BEHAVIOR,
            rule="exec_from_temp",
            threat_name="Behav.ExecFromTemp",
            score=30.0,
        )
    )
    apply_to_process_verdict(verdict)
    assert verdict.severity is Severity.LOW

    results = responder.handle_process_threat(verdict)
    assert [r.kind for r in results] == [ActionKind.REPORT]
    assert "poniżej progu" in results[0].detail


def test_kill_action_stops_the_process_and_quarantines_its_payload(config, bus, spawn, tmp_path):
    proc = spawn()
    payload = tmp_path / "watched" / "payload.bin"
    payload.write_bytes(b"malicious")
    innocent = tmp_path / "watched" / "notes.txt"
    innocent.write_text("moje notatki", encoding="utf-8")

    config.behavior_action = ActionKind.KILL_PROCESS
    vault = FakeQuarantine(config)
    scanner = FakeScanner(bad={str(payload)})
    responder = Responder(config, bus, vault, scanner=scanner)

    results = responder.handle_process_threat(
        process_threat(proc.pid, touched=[str(payload), str(innocent)])
    )

    kinds = [r.kind for r in results]
    assert ActionKind.KILL_PROCESS in kinds
    assert ActionKind.QUARANTINE in kinds
    proc.wait(timeout=5)
    assert not alive(proc.pid)
    # Only the file that still scans dirty is taken away.
    assert vault.calls == [(str(payload), "Sim.Ransom.Payload")]
    assert not payload.exists()
    assert innocent.exists()


def test_kill_action_without_a_scanner_quarantines_nothing(config, bus, spawn, tmp_path):
    """Without verification, the user's documents stay where they are."""
    proc = spawn()
    doc = tmp_path / "watched" / "praca.docx"
    doc.write_bytes(b"x" * 100)
    config.behavior_action = ActionKind.KILL_PROCESS
    vault = FakeQuarantine(config)
    responder = Responder(config, bus, vault)

    results = responder.handle_process_threat(process_threat(proc.pid, touched=[str(doc)]))

    assert [r.kind for r in results] == [ActionKind.KILL_PROCESS]
    proc.wait(timeout=5)
    assert vault.calls == []
    assert doc.exists()


def test_kill_action_on_unattributed_events_reports_instead(config, bus):
    config.behavior_action = ActionKind.KILL_PROCESS
    responder = Responder(config, bus, FakeQuarantine(config))
    results = responder.handle_process_threat(process_threat(None))
    assert [r.kind for r in results] == [ActionKind.REPORT]
    assert not results[0].ok
    assert "nieprzypisane" in results[0].detail


def test_quarantine_action_on_a_process_verdict(config, bus, tmp_path):
    payload = tmp_path / "watched" / "dropper.bin"
    payload.write_bytes(b"dropper")
    config.behavior_action = ActionKind.QUARANTINE
    vault = FakeQuarantine(config)
    responder = Responder(config, bus, vault, scanner=FakeScanner(bad={str(payload)}))

    results = responder.handle_process_threat(process_threat(None, touched=[str(payload)]))

    assert [r.kind for r in results] == [ActionKind.QUARANTINE]
    assert not payload.exists()


def test_clean_process_verdict_triggers_no_action(config, bus):
    responder = Responder(config, bus, FakeQuarantine(config))
    assert responder.handle_process_threat(ProcessVerdict(pid=5)) == []


def test_set_scanner_and_stats(config, bus, tmp_path):
    sample = tmp_path / "watched" / "evil.bin"
    sample.write_bytes(b"evil")
    responder = Responder(config, bus, FakeQuarantine(config))
    assert responder.scanner is None
    scanner = FakeScanner()
    responder.set_scanner(scanner)
    assert responder.scanner is scanner
    responder.set_scanner(None)          # must not clear an existing scanner
    assert responder.scanner is scanner

    responder.handle_file_threat(file_threat(sample))
    assert responder.stats()["quarantine_ok"] == 1


@pytest.mark.skipif(not HAVE_PSUTIL, reason="psutil nie jest dostępny")
def test_psutil_backend_is_the_one_in_use():
    """Documents which backend this run exercised."""
    assert HAVE_PSUTIL is True


# --------------------------------------------------------------------------
# The psutil-free fallback path (psutil is installed here, so force it off)
# --------------------------------------------------------------------------
def test_self_protection_without_psutil(config, bus, monkeypatch):
    monkeypatch.setattr("aegis.realtime.responder.HAVE_PSUTIL", False)
    responder = Responder(config, bus, FakeQuarantine(config))

    ancestors = responder._own_ancestors()           # noqa: SLF001
    assert os.getppid() in ancestors
    assert 1 in ancestors
    assert not responder.kill_process_tree(1).ok
    assert not responder.kill_process_tree(os.getpid()).ok
    assert not responder.kill_process_tree(os.getppid()).ok
    assert not responder.kill_process_tree(4_000_000).ok


def test_os_kill_fallback_terminates_the_tree(config, bus, monkeypatch, spawn):
    monkeypatch.setattr("aegis.realtime.responder.HAVE_PSUTIL", False)
    parent = spawn(("sh", "-c", "sleep 30 & sleep 30"))
    deadline = time.monotonic() + 5.0
    children: list[int] = []
    while time.monotonic() < deadline and not children:
        children = _children_of(parent.pid)
    assert children

    responder = Responder(config, bus, FakeQuarantine(config))
    result = responder.kill_process_tree(parent.pid)

    assert result.ok, result.detail
    parent.wait(timeout=5)
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and any(alive(pid) for pid in children):
        time.sleep(0.02)
    assert not any(alive(pid) for pid in children)
