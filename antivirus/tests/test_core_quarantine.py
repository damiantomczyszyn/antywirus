"""Tests for aegis.core.quarantine (the obfuscated vault)."""

from __future__ import annotations

import errno
import json
import os
import stat

import pytest

from aegis.core.quarantine import ENTRY_SUFFIX, VAULT_KEY_NAME, Quarantine
from aegis.models import ActionKind, FileVerdict, Severity


@pytest.fixture()
def vault(config, bus) -> Quarantine:
    return Quarantine(config, bus)


@pytest.fixture()
def victim(tmp_path, eicar_bytes) -> os.PathLike:
    target = tmp_path / "zarazone" / "eicar.com"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(eicar_bytes)
    target.chmod(0o644)
    return target


def quarantine_one(vault: Quarantine, path) -> str:
    result = vault.quarantine(path, threat_name="Sim.Eicar.TestFile")
    assert result.ok, result.detail
    return result.detail


# --------------------------------------------------------------------------
# happy path
# --------------------------------------------------------------------------
def test_quarantine_moves_and_obfuscates(vault: Quarantine, victim, eicar_bytes, config) -> None:
    result = vault.quarantine(victim, threat_name="Sim.Eicar.TestFile")

    assert result.ok is True
    assert result.kind is ActionKind.QUARANTINE
    assert result.target == str(victim)
    entry_id = result.detail
    assert entry_id and vault.get(entry_id) is not None
    assert not os.path.exists(victim), "oryginał musi zniknąć z dysku użytkownika"

    stored = config.quarantine_dir / f"{entry_id}{ENTRY_SUFFIX}"
    assert stored.is_file()
    raw = stored.read_bytes()
    assert len(raw) == len(eicar_bytes)
    assert raw != eicar_bytes
    assert eicar_bytes not in raw, "próbka nie może leżeć w skarbcu w czystej postaci"
    assert stat.S_IMODE(stored.stat().st_mode) == 0o600


def test_entry_metadata(vault: Quarantine, victim, eicar_bytes) -> None:
    import hashlib

    verdict = FileVerdict(
        path=str(victim),
        size=len(eicar_bytes),
        sha256=hashlib.sha256(eicar_bytes).hexdigest(),
        severity=Severity.CRITICAL,
    )
    entry_id = vault.quarantine(victim, verdict=verdict, threat_name="Sim.Eicar.TestFile").detail
    entry = vault.get(entry_id)
    assert entry is not None
    assert entry.original_path == str(victim)
    assert entry.size == len(eicar_bytes)
    assert entry.sha256 == hashlib.sha256(eicar_bytes).hexdigest()
    assert entry.threat_name == "Sim.Eicar.TestFile"
    assert entry.severity is Severity.CRITICAL
    assert entry.original_mode == 0o644
    assert entry.vault_name.endswith(ENTRY_SUFFIX)


def test_threat_name_falls_back_to_the_verdict(vault: Quarantine, victim) -> None:
    from aegis.models import Detection, DetectionLayer

    verdict = FileVerdict(path=str(victim))
    verdict.detections = [
        Detection(
            layer=DetectionLayer.SIGNATURE,
            rule="hash_match",
            threat_name="Sim.Family.FromVerdict",
            score=100.0,
        )
    ]
    entry_id = vault.quarantine(victim, verdict=verdict).detail
    assert vault.get(entry_id).threat_name == "Sim.Family.FromVerdict"


def test_read_payload_roundtrip(vault: Quarantine, victim, eicar_bytes) -> None:
    entry_id = quarantine_one(vault, victim)
    assert vault.read_payload(entry_id) == eicar_bytes


@pytest.mark.parametrize("size", [0, 1, 63, 64, 65, 4096, 1024 * 1024 + 7])
def test_read_payload_roundtrip_across_keystream_blocks(
    vault: Quarantine, tmp_path, size: int
) -> None:
    """A chunk/keystream alignment bug only shows up at odd sizes."""
    payload = os.urandom(size)
    target = tmp_path / f"blob-{size}.bin"
    target.write_bytes(payload)
    entry_id = quarantine_one(vault, target)
    assert vault.read_payload(entry_id) == payload


def test_identical_files_get_different_vault_bytes(vault: Quarantine, tmp_path) -> None:
    """Per-entry keys: two copies of one sample must not look identical."""
    payload = b"IDENTYCZNA-TRESC" * 100
    first = tmp_path / "a.bin"
    second = tmp_path / "b.bin"
    first.write_bytes(payload)
    second.write_bytes(payload)
    id_a = quarantine_one(vault, first)
    id_b = quarantine_one(vault, second)
    raw_a = (vault.vault_dir / vault.get(id_a).vault_name).read_bytes()
    raw_b = (vault.vault_dir / vault.get(id_b).vault_name).read_bytes()
    assert raw_a != raw_b
    assert vault.read_payload(id_a) == vault.read_payload(id_b) == payload


def test_vault_key_is_private_and_stable(vault: Quarantine, victim) -> None:
    quarantine_one(vault, victim)
    key_path = vault.vault_dir / VAULT_KEY_NAME
    assert key_path.is_file()
    assert len(key_path.read_bytes()) == 32
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


# --------------------------------------------------------------------------
# index
# --------------------------------------------------------------------------
def test_index_is_written_atomically_and_privately(vault: Quarantine, victim, config) -> None:
    entry_id = quarantine_one(vault, victim)
    index = config.quarantine_index
    assert index.is_file()
    assert stat.S_IMODE(index.stat().st_mode) == 0o600
    data = json.loads(index.read_text(encoding="utf-8"))
    assert [row["entry_id"] for row in data["entries"]] == [entry_id]
    leftovers = [p.name for p in config.quarantine_dir.glob(".index-*")]
    assert leftovers == [], "plik tymczasowy indeksu nie został posprzątany"


def test_index_is_reloaded_by_a_fresh_instance(config, bus, victim) -> None:
    entry_id = quarantine_one(Quarantine(config, bus), victim)
    reopened = Quarantine(config, bus)
    assert [e.entry_id for e in reopened.list()] == [entry_id]
    assert reopened.get(entry_id).threat_name == "Sim.Eicar.TestFile"


def test_corrupted_index_does_not_crash(config, bus) -> None:
    config.quarantine_index.write_text("{to nie jest json", encoding="utf-8")
    assert Quarantine(config, bus).list() == []


def test_corrupted_row_is_skipped(config, bus, victim) -> None:
    entry_id = quarantine_one(Quarantine(config, bus), victim)
    data = json.loads(config.quarantine_index.read_text(encoding="utf-8"))
    data["entries"].append({"nonsense": True})
    config.quarantine_index.write_text(json.dumps(data), encoding="utf-8")
    assert [e.entry_id for e in Quarantine(config, bus).list()] == [entry_id]


def test_list_is_newest_first(vault: Quarantine, tmp_path) -> None:
    ids = []
    for index in range(3):
        target = tmp_path / f"s{index}.bin"
        target.write_bytes(b"x" * (index + 1))
        ids.append(quarantine_one(vault, target))
    assert [e.entry_id for e in vault.list()] == list(reversed(ids))
    assert len(vault) == 3


# --------------------------------------------------------------------------
# restore
# --------------------------------------------------------------------------
def test_restore_puts_the_file_back(vault: Quarantine, victim, eicar_bytes) -> None:
    entry_id = quarantine_one(vault, victim)
    result = vault.restore(entry_id)
    assert result.ok is True
    assert result.kind is ActionKind.RESTORE
    assert result.target == str(victim)
    assert os.path.exists(victim)
    assert open(victim, "rb").read() == eicar_bytes
    assert stat.S_IMODE(os.stat(victim).st_mode) == 0o644
    assert vault.list() == []
    assert not (vault.vault_dir / f"{entry_id}{ENTRY_SUFFIX}").exists()


def test_restore_refuses_to_overwrite(vault: Quarantine, victim) -> None:
    entry_id = quarantine_one(vault, victim)
    with open(victim, "wb") as fh:
        fh.write(b"nowa tresc uzytkownika")
    result = vault.restore(entry_id)
    assert result.ok is False
    assert "istnieje" in result.detail
    assert open(victim, "rb").read() == b"nowa tresc uzytkownika"
    assert vault.get(entry_id) is not None, "wpis musi zostać w kwarantannie"


def test_restore_recreates_missing_parent_directories(vault: Quarantine, victim, eicar_bytes) -> None:
    entry_id = quarantine_one(vault, victim)
    os.rmdir(os.path.dirname(victim))
    assert not os.path.isdir(os.path.dirname(victim))
    assert vault.restore(entry_id).ok is True
    assert open(victim, "rb").read() == eicar_bytes


def test_restore_unknown_entry(vault: Quarantine) -> None:
    result = vault.restore("nie-ma-takiego")
    assert result.ok is False
    assert result.kind is ActionKind.RESTORE


def test_restore_reports_a_missing_vault_file(vault: Quarantine, victim) -> None:
    entry_id = quarantine_one(vault, victim)
    (vault.vault_dir / vault.get(entry_id).vault_name).unlink()
    result = vault.restore(entry_id)
    assert result.ok is False
    assert not os.path.exists(victim)


def test_relocate_falls_back_to_copy_on_cross_device(vault, victim, eicar_bytes, monkeypatch) -> None:
    """os.replace fails with EXDEV between filesystems; restore must still work."""
    from aegis.core import quarantine as module

    entry_id = quarantine_one(vault, victim)
    real_replace = os.replace
    calls: list[int] = []

    def fake_replace(src, dst, *args, **kwargs):
        if str(dst) == str(victim):
            calls.append(1)
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(module.os, "replace", fake_replace)
    assert vault.restore(entry_id).ok is True
    assert calls, "test nie wymusił ścieżki awaryjnej"
    assert open(victim, "rb").read() == eicar_bytes


# --------------------------------------------------------------------------
# delete / purge
# --------------------------------------------------------------------------
def test_delete(vault: Quarantine, victim) -> None:
    entry_id = quarantine_one(vault, victim)
    result = vault.delete(entry_id)
    assert result.ok is True
    assert result.kind is ActionKind.DELETE
    assert vault.get(entry_id) is None
    assert not (vault.vault_dir / f"{entry_id}{ENTRY_SUFFIX}").exists()
    assert vault.delete(entry_id).ok is False


def test_delete_tolerates_a_missing_vault_file(vault: Quarantine, victim) -> None:
    entry_id = quarantine_one(vault, victim)
    (vault.vault_dir / vault.get(entry_id).vault_name).unlink()
    assert vault.delete(entry_id).ok is True


def test_purge_all(vault: Quarantine, tmp_path) -> None:
    for index in range(4):
        target = tmp_path / f"p{index}.bin"
        target.write_bytes(b"y" * (index + 1))
        quarantine_one(vault, target)
    assert vault.purge_all() == 4
    assert vault.list() == []
    assert vault.purge_all() == 0
    assert not list(vault.vault_dir.glob(f"*{ENTRY_SUFFIX}"))


def test_read_payload_unknown_entry_raises(vault: Quarantine) -> None:
    with pytest.raises(KeyError):
        vault.read_payload("brak")


# --------------------------------------------------------------------------
# refusals
# --------------------------------------------------------------------------
def test_quarantine_missing_file(vault: Quarantine, tmp_path) -> None:
    result = vault.quarantine(tmp_path / "nie-ma.exe")
    assert result.ok is False
    assert result.kind is ActionKind.QUARANTINE
    assert vault.list() == []


def test_quarantine_directory_is_refused(vault: Quarantine, tmp_path) -> None:
    folder = tmp_path / "katalog"
    folder.mkdir()
    result = vault.quarantine(folder)
    assert result.ok is False
    assert folder.is_dir()


def test_quarantine_refuses_its_own_data(vault: Quarantine, config) -> None:
    """Otherwise the product eats its own vault and database."""
    internal = config.data_dir / "signatures.db"
    internal.write_bytes(b"udaje baze")
    result = vault.quarantine(internal)
    assert result.ok is False
    assert internal.is_file()


def test_failure_to_remove_the_original_rolls_back(vault, victim, monkeypatch) -> None:
    """A file must never be both live on disk and inside the vault."""
    from aegis.core import quarantine as module

    real_unlink = os.unlink

    def fail_unlink(path, *args, **kwargs):
        # Only the original is write-protected, as it would be on a read-only
        # mount; the rollback of the vault copy must still succeed.
        if str(path) == str(victim):
            raise OSError(errno.EACCES, "Permission denied")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(module.os, "unlink", fail_unlink)
    result = vault.quarantine(victim)
    assert result.ok is False
    assert os.path.exists(victim)
    assert vault.list() == []
    assert not list(vault.vault_dir.glob(f"*{ENTRY_SUFFIX}")), "skarbiec musi być posprzątany"


# --------------------------------------------------------------------------
# events and stats
# --------------------------------------------------------------------------
def test_events_are_published(vault: Quarantine, victim, bus) -> None:
    entry_id = quarantine_one(vault, victim)
    vault.restore(entry_id)
    types = [event.type.value for event in bus.history()]
    assert types.count("action_taken") == 2
    assert types.count("quarantine_changed") == 2
    payloads = [e.payload for e in bus.history() if e.type.value == "action_taken"]
    assert payloads[0]["entry_id"] == entry_id
    assert payloads[0]["action"] == "quarantine"
    assert payloads[1]["action"] == "restore"


def test_stats(vault: Quarantine, victim, eicar_bytes) -> None:
    assert vault.stats()["count"] == 0
    quarantine_one(vault, victim)
    stats = vault.stats()
    assert stats["count"] == 1
    assert stats["bytes"] == len(eicar_bytes)
    assert stats["newest"] is not None
    assert sum(stats["by_severity"].values()) == 1


def test_quarantine_without_a_bus_works(config, victim) -> None:
    assert Quarantine(config).quarantine(victim).ok is True
