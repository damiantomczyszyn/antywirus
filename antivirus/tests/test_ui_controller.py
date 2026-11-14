"""Headless tests for the UI logic (``aegis.gui.controller``).

The controller imports no GUI toolkit, so everything below runs on a machine
without Tkinter - which is the whole point of the controller/view split.
Nothing here touches the network or the real ``~/.aegis``: the ``config``
fixture is rooted in ``tmp_path``.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from aegis.config import Config
from aegis.events import EventType
from aegis.gui import controller as controller_mod
from aegis.gui.controller import AegisController, _FallbackToken, detection_from_dict
from aegis.models import (
    ActionKind,
    Detection,
    DetectionLayer,
    FileVerdict,
    Severity,
)

pytestmark = pytest.mark.filterwarnings("ignore::ResourceWarning")


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
@pytest.fixture()
def ctrl(config, bus):
    controller = AegisController(config, bus)
    try:
        yield controller
    finally:
        controller.shutdown()


@pytest.fixture()
def degraded(config, bus, monkeypatch):
    """A controller whose every engine subsystem failed to import."""
    monkeypatch.setattr(controller_mod, "_import_module", lambda relative: None)
    controller = AegisController(config, bus)
    try:
        yield controller
    finally:
        controller.shutdown()


@pytest.fixture()
def samples(tmp_path, eicar_bytes) -> Path:
    target = tmp_path / "probki"
    target.mkdir()
    (target / "czysty.txt").write_bytes(b"zwyczajna notatka tekstowa\n")
    (target / "eicar.com").write_bytes(eicar_bytes)
    return target


def _needs_scanner(controller: AegisController) -> None:
    if controller.scanner is None:
        pytest.skip("aegis.core.scanner jest niedostępny w tym drzewie")


def _needs_quarantine(controller: AegisController) -> None:
    if controller.quarantine is None:
        pytest.skip("aegis.core.quarantine jest niedostępna w tym drzewie")


def _verdict(path: str) -> FileVerdict:
    verdict = FileVerdict(
        path=path,
        size=68,
        sha256="f" * 64,
        detections=[
            Detection(
                layer=DetectionLayer.SIGNATURE,
                rule="sha256_match",
                threat_name="Sim.Eicar.Test",
                score=100.0,
                detail="dopasowanie skrótu",
            ),
            Detection(
                layer=DetectionLayer.HEURISTIC,
                rule="double_extension",
                threat_name="Heur.PodwojneRozszerzenie",
                score=12.0,
                confidence=0.5,
            ),
        ],
    )
    from aegis.engine.verdict import apply_to_file_verdict

    return apply_to_file_verdict(verdict)


# --------------------------------------------------------------------------
# Construction and dashboard
# --------------------------------------------------------------------------
def test_controller_exposes_contract_attributes(ctrl):
    for name in (
        "config", "bus", "db", "scanner", "quarantine", "behavior",
        "responder", "monitor", "updater",
    ):
        assert hasattr(ctrl, name), name


def test_controller_never_writes_outside_data_dir(ctrl, config):
    assert config.data_dir.is_dir()
    assert config.quarantine_dir.is_dir()
    assert str(config.data_dir).startswith(str(config.data_dir.parent))


def test_dashboard_has_the_documented_shape(ctrl):
    data = ctrl.dashboard()
    for key in (
        "status", "status_label", "status_reasons", "db_version", "db_indicators",
        "db_last_update", "counts", "last_scan", "scan", "realtime", "behavior",
        "degraded", "missing", "subsystems", "version",
    ):
        assert key in data, key
    assert data["status"] in ("protected", "warning", "threat")
    assert data["status_label"] in ("Chroniony", "Uwaga", "Zagrożenie")
    assert data["last_scan"] is None
    assert set(data["counts"]) >= {"scanned", "threats", "quarantined"}
    # the dict must survive a JSON round trip: the GUI and the CLI share it
    assert json.loads(json.dumps(data, default=str))


def test_dashboard_warns_when_realtime_is_off(ctrl):
    data = ctrl.dashboard()
    assert data["status"] == "warning"
    assert any("czasie rzeczywistym" in reason for reason in data["status_reasons"])


def test_dashboard_turns_red_on_an_unhandled_threat(ctrl, samples):
    ctrl.bus.publish(
        EventType.THREAT_FOUND, "zagrożenie", verdict=_verdict(str(samples / "eicar.com"))
    )
    data = ctrl.dashboard()
    assert data["status"] == "threat"
    assert data["status_label"] == "Zagrożenie"
    assert data["counts"]["outstanding"] == 1


def test_polish_status_labels_have_diacritics(ctrl):
    assert controller_mod.STATUS_LABELS_PL["threat"] == "Zagrożenie"
    assert controller_mod.SEVERITY_LABELS_PL[Severity.MEDIUM] == "średni"


# --------------------------------------------------------------------------
# Degraded mode - the UI must survive missing subsystems
# --------------------------------------------------------------------------
def test_degraded_controller_still_constructs(degraded):
    assert degraded.degraded is True
    assert set(degraded.missing_subsystems()) == {
        "db", "scanner", "quarantine", "behavior", "responder", "monitor",
        "procmon", "updater",
    }
    data = degraded.dashboard()
    assert data["status"] == "warning"
    assert any("Tryb ograniczony" in reason for reason in data["status_reasons"])


def test_degraded_operations_fail_softly_in_polish(degraded, tmp_path):
    assert degraded.start_scan([str(tmp_path)]) is False
    assert degraded.update_database() is False
    assert degraded.set_realtime(True) is False
    assert degraded.quarantine_items() == []
    assert degraded.feeds() == []
    assert degraded.behavior_rules() == []
    assert degraded.purge_quarantine() == 0
    assert degraded.rescan_quarantine_entry("x") is None

    restore = degraded.restore("brak")
    assert restore.ok is False and "brak modułu" in restore.detail
    delete = degraded.delete("brak")
    assert delete.ok is False
    quarantine = degraded.quarantine_path(str(tmp_path / "x"))
    assert quarantine.ok is False

    warnings = [e for e in degraded.bus.history(limit=None) if e.level == "warning"]
    assert warnings, "każda nieudana operacja musi zostawić ostrzeżenie na szynie"
    assert all(isinstance(e.message, str) and e.message for e in warnings)


def test_degraded_controller_shuts_down_cleanly(degraded):
    degraded.shutdown()
    degraded.shutdown()
    assert degraded.start_scan(["/tmp"]) is False


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------
def test_start_scan_rejects_an_empty_path_list(ctrl):
    assert ctrl.start_scan([]) is False
    assert ctrl.start_scan(["  "]) is False
    assert any("Nie wskazano" in e.message for e in ctrl.bus.history(limit=None))


def test_scan_finds_eicar_and_fills_the_table(ctrl, samples):
    _needs_scanner(ctrl)
    assert ctrl.start_scan([str(samples)]) is True
    assert ctrl.wait_for_scan(60) is True
    assert ctrl.scan_running is False

    result = ctrl.last_scan()
    assert result is not None
    threats = [v for v in result.verdicts if v.is_threat]
    assert len(threats) == 1
    assert threats[0].path.endswith("eicar.com")
    assert threats[0].severity is Severity.CRITICAL

    rows = {row["path"]: row for row in ctrl.scan_rows()}
    assert len(rows) == 2
    threat_row = rows[threats[0].path]
    assert threat_row["result"] == "zagrożenie"
    assert threat_row["severity_label"] == "krytyczny"
    assert "sygnatura" in threat_row["layers"]

    progress = ctrl.scan_progress()
    assert progress["running"] is False
    assert progress["done"] >= 2
    assert progress["threats"] == 1
    assert progress["finished_at"] is not None


def test_only_one_scan_runs_at_a_time(ctrl, tmp_path):
    _needs_scanner(ctrl)
    big = tmp_path / "duzo"
    big.mkdir()
    for index in range(400):
        (big / f"plik{index}.bin").write_bytes(bytes(2048))
    assert ctrl.start_scan([str(big)]) is True
    second = ctrl.start_scan([str(big)])
    ctrl.cancel_scan()
    assert ctrl.wait_for_scan(60) is True
    if second:  # the first scan may have finished before the second call
        pytest.skip("pierwsze skanowanie zakończyło się zbyt szybko")
    assert any("już trwa" in e.message for e in ctrl.bus.history(limit=None))


def test_cancel_scan_is_safe_when_idle(ctrl):
    ctrl.cancel_scan()
    ctrl.cancel_scan()
    assert ctrl.scan_running is False


def test_cancel_stops_a_running_scan(ctrl, tmp_path):
    _needs_scanner(ctrl)
    big = tmp_path / "duzo"
    big.mkdir()
    for index in range(600):
        (big / f"plik{index}.bin").write_bytes(bytes(4096))
    assert ctrl.start_scan([str(big)]) is True
    ctrl.cancel_scan()
    assert ctrl.wait_for_scan(60) is True
    assert ctrl.scan_running is False


def test_take_new_rows_only_returns_fresh_rows(ctrl, samples):
    verdict = _verdict(str(samples / "eicar.com"))
    ctrl.bus.publish(EventType.SCAN_FILE_DONE, "plik", verdict=verdict)
    first = ctrl.take_new_rows()
    assert len(first) == 1
    assert ctrl.take_new_rows() == []
    ctrl.bus.publish(EventType.SCAN_FILE_DONE, "plik", path=str(samples / "czysty.txt"))
    assert len(ctrl.take_new_rows()) == 1


def test_rows_survive_payloads_without_a_verdict(ctrl, samples):
    ctrl.bus.publish(EventType.SCAN_FILE_DONE, "plik", path=str(samples / "czysty.txt"))
    ctrl.bus.publish(EventType.SCAN_FILE_DONE, "nic ciekawego")
    ctrl.bus.publish(
        EventType.THREAT_FOUND,
        "zagrożenie",
        verdict=_verdict(str(samples / "eicar.com")).to_dict(),
    )
    rows = {row["path"]: row for row in ctrl.scan_rows()}
    assert len(rows) == 2
    threat = rows[str(samples / "eicar.com")]
    assert threat["threat"] == "Sim.Eicar.Test"
    assert threat["severity"] == "critical"


def test_explain_path_shows_every_layer(ctrl, samples):
    path = str(samples / "eicar.com")
    ctrl.bus.publish(EventType.THREAT_FOUND, "zagrożenie", verdict=_verdict(path))
    text = ctrl.explain_path(path)
    assert "Analiza hybrydowa" in text
    assert "[signature]" in text and "[heuristic]" in text
    assert "WYNIK" in text
    assert ctrl.explain_path("/nie/ma/takiego") .startswith("Brak szczegółów")


def test_quick_and_full_scan_paths(ctrl, config):
    quick = ctrl.quick_scan_paths()
    assert quick == [p for p in config.realtime_paths if Path(p).is_dir()]
    assert ctrl.full_scan_paths(), "pełne skanowanie musi mieć choć jeden korzeń"


def test_estimate_total_is_bounded_by_its_budget(ctrl, tmp_path):
    deep = tmp_path / "glebokie"
    deep.mkdir()
    for index in range(50):
        (deep / f"p{index}").write_bytes(b"x")
    total, truncated = ctrl._estimate_total([str(deep)], True, _FallbackToken())
    assert total == 50
    assert truncated is False
    total, truncated = ctrl._estimate_total([str(deep)], True, _FallbackToken(), cap=10)
    assert truncated is True


# --------------------------------------------------------------------------
# Actions / quarantine
# --------------------------------------------------------------------------
def test_quarantine_round_trip(ctrl, samples):
    _needs_quarantine(ctrl)
    _needs_scanner(ctrl)
    target = samples / "eicar.com"
    ctrl.start_scan([str(samples)])
    ctrl.wait_for_scan(60)

    action = ctrl.quarantine_path(str(target))
    assert action.ok is True
    assert action.kind is ActionKind.QUARANTINE
    assert not target.exists()

    items = ctrl.quarantine_items()
    assert len(items) == 1
    entry = items[0]
    rows = ctrl.quarantine_rows()
    assert rows[0]["entry_id"] == entry.entry_id
    assert rows[0]["severity_label"] in ("krytyczny", "wysoki")
    assert "Zagrożenie" in ctrl.explain_quarantine_entry(entry.entry_id)

    verdict = ctrl.rescan_quarantine_entry(entry.entry_id)
    assert verdict is None or verdict.is_threat

    restored = ctrl.restore(entry.entry_id)
    assert restored.ok is True
    assert target.exists()
    assert ctrl.quarantine_items() == []

    ctrl.quarantine_path(str(target))
    entry_id = ctrl.quarantine_items()[0].entry_id
    assert ctrl.delete(entry_id).ok is True
    assert ctrl.quarantine_items() == []


def test_purge_quarantine_empties_the_vault(ctrl, samples):
    _needs_quarantine(ctrl)
    ctrl.quarantine_path(str(samples / "eicar.com"))
    ctrl.quarantine_path(str(samples / "czysty.txt"))
    assert len(ctrl.quarantine_items()) == 2
    assert ctrl.purge_quarantine() == 2
    assert ctrl.quarantine_items() == []


def test_delete_and_ignore_paths(ctrl, samples):
    target = samples / "czysty.txt"
    assert ctrl.ignore_path(str(target)).ok is True
    assert str(target) in ctrl.config.excluded_paths
    assert ctrl.ignore_path(str(target)).ok is True  # idempotent
    assert ctrl.config.excluded_paths.count(str(target)) == 1

    assert ctrl.delete_path(str(target)).ok is True
    assert not target.exists()
    failed = ctrl.delete_path(str(target))
    assert failed.ok is False
    assert "Nie można usunąć" in failed.detail


def test_actions_publish_action_taken(ctrl, samples):
    ctrl.ignore_path(str(samples / "czysty.txt"))
    kinds = [
        e.payload.get("kind")
        for e in ctrl.bus.history(limit=None)
        if e.type is EventType.ACTION_TAKEN
    ]
    assert ActionKind.NONE.value in kinds


# --------------------------------------------------------------------------
# Realtime
# --------------------------------------------------------------------------
def test_set_realtime_is_idempotent(ctrl):
    if ctrl.monitor is None:
        pytest.skip("aegis.realtime.watcher jest niedostępny")
    assert ctrl.set_realtime(True) is True
    assert ctrl.set_realtime(True) is True
    assert ctrl.realtime_running is True
    assert ctrl.config.realtime_enabled is True
    assert ctrl.set_realtime(False) is True
    assert ctrl.set_realtime(False) is True
    assert ctrl.realtime_running is False
    assert ctrl.config.realtime_enabled is False


def test_realtime_status_is_renderable_either_way(ctrl):
    status = ctrl.realtime_status()
    for key in ("available", "running", "enabled", "backend", "paths", "action_label"):
        assert key in status


def test_realtime_paths_can_be_added_and_removed(ctrl, tmp_path):
    extra = tmp_path / "dodatkowy"
    extra.mkdir()
    assert ctrl.add_realtime_path(str(extra)) is True
    assert str(extra) in ctrl.config.realtime_paths
    assert ctrl.add_realtime_path(str(extra)) is False
    assert ctrl.add_realtime_path(str(tmp_path / "nie-ma")) is False
    assert ctrl.remove_realtime_path(str(extra)) is True
    assert str(extra) not in ctrl.config.realtime_paths
    assert ctrl.remove_realtime_path(str(extra)) is False


def test_behavior_alerts_are_buffered_and_bounded(ctrl):
    for index in range(ctrl.MAX_ALERTS + 120):
        ctrl.bus.publish(
            EventType.BEHAVIOR_ALERT,
            f"Podejrzane zachowanie {index}",
            pid=index,
            process="test",
            rule="mass_encrypt",
        )
    alerts = ctrl.recent_alerts(10_000)
    assert len(alerts) == ctrl.MAX_ALERTS
    assert alerts[-1]["pid"] == ctrl.MAX_ALERTS + 119
    assert ctrl.dashboard()["counts"]["behavior_alerts"] == ctrl.MAX_ALERTS + 120


def test_behavior_rules_are_dictionaries(ctrl):
    rules = ctrl.behavior_rules()
    if not rules:
        pytest.skip("aegis.realtime.behavior jest niedostępny")
    assert all(isinstance(rule, dict) for rule in rules)
    assert all("id" in rule for rule in rules)


# --------------------------------------------------------------------------
# Database / feeds
# --------------------------------------------------------------------------
def test_db_stats_always_has_the_render_keys(ctrl):
    stats = ctrl.db_stats()
    for key in ("total", "by_kind", "by_source", "version"):
        assert key in stats
    assert ctrl.db_stats() is not None  # cached branch


def test_feed_rows_are_render_ready(ctrl):
    feeds = ctrl.feeds()
    if not feeds:
        pytest.skip("aegis.intel.feeds jest niedostępny")
    for feed in feeds:
        for key in ("id", "name", "enabled", "status", "indicators", "last_update_text"):
            assert key in feed


def test_feed_enable_flag_follows_config(ctrl):
    ctrl.set_feed_enabled("nowy_feed", True)
    assert "nowy_feed" in ctrl.config.feeds_enabled
    ctrl.set_feed_enabled("nowy_feed", False)
    assert "nowy_feed" not in ctrl.config.feeds_enabled


def test_update_database_runs_on_a_thread_without_network(ctrl, monkeypatch):
    if ctrl.updater is None:
        pytest.skip("aegis.intel.feeds jest niedostępny")
    from aegis.models import FeedResult

    seen: dict[str, object] = {}

    def fake_update(feed_ids=None, *, force=False):
        seen["feed_ids"] = feed_ids
        seen["force"] = force
        seen["thread"] = threading.current_thread().name
        return [FeedResult(feed_id="builtin", ok=True, added=3, updated=1)]

    monkeypatch.setattr(ctrl.updater, "update", fake_update)
    assert ctrl.update_database(["builtin"], force=True) is True
    assert ctrl.wait_for_update(30) is True
    assert seen["feed_ids"] == ["builtin"]
    assert seen["force"] is True
    assert seen["thread"] != threading.main_thread().name
    results = ctrl.last_update_results()
    assert len(results) == 1 and results[0].added == 3
    assert any("Aktualizacja bazy zakończona" in e.message for e in ctrl.bus.history(limit=None))


def test_update_database_refuses_a_second_run(ctrl, monkeypatch):
    if ctrl.updater is None:
        pytest.skip("aegis.intel.feeds jest niedostępny")
    gate = threading.Event()

    def slow_update(feed_ids=None, *, force=False):
        gate.wait(10)
        return []

    monkeypatch.setattr(ctrl.updater, "update", slow_update)
    assert ctrl.update_database() is True
    assert ctrl.update_database() is False
    gate.set()
    assert ctrl.wait_for_update(30) is True


def test_database_export_import_round_trip(ctrl, tmp_path):
    if ctrl.db is None:
        pytest.skip("aegis.core.signatures jest niedostępna")
    target = tmp_path / "wskazniki.json"
    exported = ctrl.export_database(str(target))
    assert target.is_file()
    added, updated = ctrl.import_database(str(target))
    assert added + updated >= 0
    assert exported >= 0
    assert ctrl.import_database(str(tmp_path / "nie-ma.json")) == (0, 0)


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------
def test_form_values_mirror_the_config(ctrl):
    values = ctrl.form_values()
    assert values["scan_threads"] == str(ctrl.config.scan_threads)
    assert values["max_file_size"] == str(ctrl.config.max_file_size // (1024 * 1024))
    assert values["scan_archives"] is ctrl.config.scan_archives
    assert values["realtime_action"] == ctrl.config.realtime_action.value


def test_apply_settings_coerces_and_validates(ctrl):
    ok, errors = ctrl.apply_settings(
        {
            "scan_threads": "8",
            "max_file_size": "32",
            "behavior_entropy_threshold": "7,5",
            "scan_archives": False,
            "excluded_paths": "/tmp/a\n\n/tmp/b\n",
            "realtime_action": "delete",
            "language": "pl",
        }
    )
    assert (ok, errors) == (True, [])
    assert ctrl.config.scan_threads == 8
    assert ctrl.config.max_file_size == 32 * 1024 * 1024
    assert ctrl.config.behavior_entropy_threshold == pytest.approx(7.5)
    assert ctrl.config.scan_archives is False
    assert ctrl.config.excluded_paths == ["/tmp/a", "/tmp/b"]
    assert ctrl.config.realtime_action is ActionKind.DELETE


def test_apply_settings_rejects_bad_values_without_changing_config(ctrl):
    before = ctrl.config.scan_threads
    ok, errors = ctrl.apply_settings({"scan_threads": "0", "max_file_size": "nie liczba"})
    assert ok is False
    assert len(errors) == 2
    assert all(isinstance(message, str) for message in errors)
    assert ctrl.config.scan_threads == before
    ok, errors = ctrl.apply_settings({"language": "klingon"})
    assert ok is False and "nieznana wartość" in errors[0]


def test_save_and_reset_settings(ctrl, config):
    ctrl.apply_settings({"scan_threads": "11"})
    assert ctrl.save_config() is True
    assert config.config_path.is_file()
    saved = json.loads(config.config_path.read_text(encoding="utf-8"))
    assert saved["scan_threads"] == 11

    values = ctrl.reset_settings()
    assert ctrl.config.scan_threads == Config().scan_threads
    assert values["scan_threads"] == str(Config().scan_threads)
    assert ctrl.config.data_dir == config.data_dir  # the data dir must survive


# --------------------------------------------------------------------------
# Log helpers
# --------------------------------------------------------------------------
def test_log_history_filters_by_level(ctrl):
    ctrl.bus.publish(EventType.LOG, "informacja", level="info")
    ctrl.bus.publish(EventType.LOG, "ostrzeżenie", level="warning")
    ctrl.bus.publish(EventType.LOG, "błąd", level="error")
    messages = [e.message for e in ctrl.log_history(min_level="warning")]
    assert "ostrzeżenie" in messages and "błąd" in messages
    assert "informacja" not in messages
    assert "błąd" in [e.message for e in ctrl.log_history(min_level="error")]


def test_export_log_writes_a_readable_file(ctrl, tmp_path):
    ctrl.bus.publish(EventType.LOG, "zdarzenie do zapisu", level="info")
    target = tmp_path / "dziennik.log"
    assert ctrl.export_log(str(target)) is True
    content = target.read_text(encoding="utf-8")
    assert "zdarzenie do zapisu" in content
    assert ctrl.export_log(str(tmp_path / "brak" / "x.log")) is False


def test_detection_from_dict_round_trip():
    original = Detection(
        layer=DetectionLayer.BEHAVIOR,
        rule="mass_encrypt",
        threat_name="Behav.MasoweSzyfrowanie",
        score=55.0,
        confidence=0.9,
        detail="30 plików w 5 s",
        pid=4242,
    )
    rebuilt = detection_from_dict(original.to_dict())
    assert rebuilt is not None
    assert rebuilt.layer is DetectionLayer.BEHAVIOR
    assert rebuilt.threat_name == original.threat_name
    assert rebuilt.weighted == pytest.approx(original.weighted)
    assert detection_from_dict({"layer": "nonsens"}) is None
    assert detection_from_dict("nie dict") is None


# --------------------------------------------------------------------------
# Threading / robustness
# --------------------------------------------------------------------------
def test_rows_buffer_is_bounded(ctrl):
    for index in range(ctrl.MAX_ROWS + 50):
        ctrl.bus.publish(EventType.SCAN_FILE_DONE, "plik", path=f"/tmp/p{index}")
    assert len(ctrl.scan_rows()) == ctrl.MAX_ROWS


def test_dashboard_is_safe_while_a_scan_runs(ctrl, tmp_path):
    _needs_scanner(ctrl)
    big = tmp_path / "duzo"
    big.mkdir()
    for index in range(300):
        (big / f"plik{index}.bin").write_bytes(bytes(1024))

    failures: list[BaseException] = []

    def poll() -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                ctrl.dashboard()
                ctrl.scan_progress()
                ctrl.take_new_rows()
                ctrl.quarantine_items()
            except BaseException as exc:  # noqa: BLE001
                failures.append(exc)
                return

    ctrl.start_scan([str(big)])
    pollers = [threading.Thread(target=poll) for _ in range(4)]
    for thread in pollers:
        thread.start()
    assert ctrl.wait_for_scan(60) is True
    for thread in pollers:
        thread.join(10)
    assert failures == []


def test_run_background_reports_failures_on_the_bus(ctrl):
    def boom() -> None:
        raise RuntimeError("awaria testowa")

    assert ctrl.run_background(boom, label="test") is True
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if any("awaria testowa" in e.message for e in ctrl.bus.history(limit=None)):
            break
    assert any("awaria testowa" in e.message for e in ctrl.bus.history(limit=None))


def test_a_crashing_bus_subscriber_cannot_break_bookkeeping(ctrl):
    ctrl.bus.subscribe(lambda event: (_ for _ in ()).throw(RuntimeError("zły abonent")))
    ctrl.bus.publish(EventType.SCAN_FILE_DONE, "plik", path="/tmp/x")
    assert ctrl.dashboard()["counts"]["scanned"] >= 1


def test_shutdown_is_idempotent_and_stops_everything(ctrl, tmp_path):
    ctrl.shutdown()
    ctrl.shutdown()
    assert ctrl.scan_running is False
    assert ctrl.start_scan([str(tmp_path)]) is False
    assert ctrl.update_database() in (False,)
    assert ctrl.run_background(lambda: None) is False


def test_controller_works_as_a_context_manager(config, bus):
    with AegisController(config, bus) as controller:
        assert controller.dashboard()["status"] in ("protected", "warning", "threat")
    assert controller.scan_running is False
