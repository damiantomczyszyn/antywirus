"""Tests for the offline starter database.

The EICAR hashes are never compared against hard-coded constants copied from
somewhere: every test recomputes them from the real 68 bytes written to a file
on disk, so a typo in the shipped string cannot pass.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from aegis.intel import baseline
from aegis.models import HASH_KINDS, Indicator, IndicatorKind, Severity


class FakeDB:
    """Records ``add_many`` and enforces the real ``(kind, value)`` primary key."""

    def __init__(self) -> None:
        self.calls: list[list[Indicator]] = []
        self.rows: dict[tuple[str, str], Indicator] = {}

    def add_many(self, indicators: Any) -> tuple[int, int]:
        batch = list(indicators)
        self.calls.append(batch)
        added = updated = 0
        for indicator in batch:
            if indicator.key in self.rows:
                updated += 1
            else:
                added += 1
            self.rows[indicator.key] = indicator
        return added, updated

    def __len__(self) -> int:
        return len(self.rows)


@pytest.fixture()
def real_eicar_hashes(tmp_path: Path) -> dict[str, str]:
    """Hash the EICAR bytes by writing them to a real file and reading it back."""
    sample = tmp_path / "eicar.com"
    sample.write_bytes(baseline.EICAR_BYTES)
    assert sample.stat().st_size == 68, "EICAR is exactly 68 bytes"
    out: dict[str, str] = {}
    for algo in ("sha256", "sha1", "md5"):
        digest = hashlib.new(algo)
        with sample.open("rb") as handle:
            for chunk in iter(lambda: handle.read(4096), b""):
                digest.update(chunk)
        out[algo] = digest.hexdigest()
    return out


# ==========================================================================
# EICAR
# ==========================================================================
def test_eicar_body_matches_the_frozen_fixture(eicar_bytes: bytes) -> None:
    """``eicar_bytes`` is the frozen conftest fixture - the project's canonical copy."""
    assert baseline.EICAR_BYTES == eicar_bytes
    assert len(baseline.EICAR_BYTES) == 68


def test_eicar_hashes_are_computed_from_the_real_bytes(
    real_eicar_hashes: dict[str, str], eicar_bytes: bytes
) -> None:
    assert baseline.EICAR_BYTES == eicar_bytes
    indicators = baseline.builtin_indicators()
    by_kind = {i.kind: i for i in indicators if i.kind in HASH_KINDS}

    assert by_kind[IndicatorKind.SHA256].value == real_eicar_hashes["sha256"]
    assert by_kind[IndicatorKind.SHA1].value == real_eicar_hashes["sha1"]
    assert by_kind[IndicatorKind.MD5].value == real_eicar_hashes["md5"]
    assert all(i.name == "EICAR.Test.File" for i in by_kind.values())


def test_eicar_also_shipped_as_a_content_pattern(eicar_bytes: bytes) -> None:
    """Hash alone misses EICAR appended to another file; the pattern catches it."""
    patterns = [
        i
        for i in baseline.builtin_indicators()
        if i.kind is IndicatorKind.PATTERN and i.name == "EICAR.Test.File"
    ]
    assert len(patterns) == 1
    assert bytes.fromhex(patterns[0].value) == eicar_bytes


# ==========================================================================
# Simulator handshake
# ==========================================================================
def test_all_six_simulator_markers_are_present() -> None:
    expected = {
        "AEGIS-SIM-PAYLOAD-MARKER",
        "AEGIS-SIM-RANSOM-NOTE",
        "AEGIS-SIM-BEACON",
        "AEGIS-SIM-PERSISTENCE",
        "AEGIS-SIM-EXFIL",
        "AEGIS-SIM-DROPPER",
    }
    assert set(baseline.SIM_MARKERS) == expected

    patterns = {
        bytes.fromhex(i.value).decode(): i
        for i in baseline.builtin_indicators()
        if i.kind is IndicatorKind.PATTERN
    }
    for marker in expected:
        assert marker in patterns, f"missing pattern for {marker}"
        indicator = patterns[marker]
        assert indicator.name.startswith("Sim."), indicator.name
        assert indicator.name.endswith(".Marker"), indicator.name
        assert indicator.severity is Severity.HIGH


def test_simulator_threat_names_follow_the_convention() -> None:
    names = {
        i.name
        for i in baseline.builtin_indicators()
        if i.name.startswith("Sim.")
    }
    assert names == {
        "Sim.Payload.Marker",
        "Sim.Ransom.Marker",
        "Sim.Beacon.Marker",
        "Sim.Persistence.Marker",
        "Sim.Exfil.Marker",
        "Sim.Dropper.Marker",
    }


def test_markers_do_not_appear_contiguously_in_this_packages_source() -> None:
    """Self-protection: Aegis must not detect its own source tree.

    The literals are assembled from fragments at runtime, so the bytes the
    scanner hunts for never exist contiguously inside ``aegis/intel/*.py``.
    """
    package = Path(baseline.__file__).resolve().parent
    sources = {path: path.read_bytes() for path in package.glob("*.py")}
    for marker in baseline.SIM_MARKERS:
        for path, blob in sources.items():
            assert marker.encode() not in blob, f"{marker} appears literally in {path.name}"
    assert baseline.EICAR_BYTES not in b"".join(sources.values())


# ==========================================================================
# Generic script patterns
# ==========================================================================
def test_generic_script_patterns_are_shipped() -> None:
    decoded = {
        bytes.fromhex(i.value).decode(): i.name
        for i in baseline.builtin_indicators()
        if i.kind is IndicatorKind.PATTERN and i.name.startswith("Generic.")
    }
    assert "vssadmin delete shadows" in decoded
    assert "powershell -nop -w hidden -enc " in decoded
    assert ">& /dev/tcp/" in decoded
    assert any("FromBase64String(" in text for text in decoded)
    assert any("DownloadString(" in text for text in decoded)
    assert len(decoded) >= 5, "a handful of generic patterns"


def test_generic_patterns_are_specific_enough_to_be_safe() -> None:
    """A PATTERN hit scores 75 on its own, so short patterns are dangerous."""
    for indicator in baseline.builtin_indicators():
        if indicator.kind is not IndicatorKind.PATTERN:
            continue
        if not indicator.name.startswith("Generic."):
            continue
        text = bytes.fromhex(indicator.value).decode()
        assert len(text) >= 12, f"{text!r} is too generic to ship"


def test_generic_patterns_do_not_match_ordinary_text() -> None:
    innocent = (
        b"#!/bin/bash\necho hello world\n"
        b"import json\nprint(json.dumps({'a': 1}))\n"
        b"SELECT * FROM users WHERE id = 1;\n"
        b"<html><body><h1>Hello</h1></body></html>\n"
    )
    for indicator in baseline.builtin_indicators():
        if indicator.kind is not IndicatorKind.PATTERN:
            continue
        needle = bytes.fromhex(indicator.value)
        assert needle not in innocent, f"false positive on innocent text: {needle!r}"


# ==========================================================================
# Shape of the whole baseline
# ==========================================================================
def test_every_indicator_is_well_formed() -> None:
    indicators = baseline.builtin_indicators()
    assert len(indicators) >= 15
    seen: set[tuple[str, str]] = set()
    for indicator in indicators:
        assert indicator.value, "empty value"
        assert indicator.source == "builtin"
        assert indicator.name and indicator.name != "Unnamed.Threat"
        assert indicator.description, f"{indicator.name} needs a description"
        assert "baseline" in indicator.tags
        # Reproducible dump: no wall-clock timestamps baked in.
        assert indicator.added_at == 0.0
        assert indicator.key not in seen, f"duplicate indicator {indicator.key}"
        seen.add(indicator.key)
        if indicator.kind is IndicatorKind.PATTERN:
            bytes.fromhex(indicator.value)      # must be valid hex


def test_baseline_covers_hashes_and_patterns() -> None:
    counts = Counter(i.kind for i in baseline.builtin_indicators())
    assert counts[IndicatorKind.SHA256] >= 1
    assert counts[IndicatorKind.SHA1] >= 1
    assert counts[IndicatorKind.MD5] >= 1
    assert counts[IndicatorKind.PATTERN] >= 10


def test_builtin_indicators_is_deterministic() -> None:
    assert baseline.builtin_indicators() == baseline.builtin_indicators()


# ==========================================================================
# ensure_baseline
# ==========================================================================
def test_ensure_baseline_is_idempotent() -> None:
    db = FakeDB()
    first = baseline.ensure_baseline(db)
    assert first == len(baseline.builtin_indicators()) > 0
    second = baseline.ensure_baseline(db)
    assert second == 0, "calling it twice must add nothing"
    assert len(db) == first


def test_ensure_baseline_writes_nothing_outside_the_db(tmp_path: Path) -> None:
    before = sorted(p.name for p in tmp_path.iterdir())
    baseline.ensure_baseline(FakeDB())
    assert sorted(p.name for p in tmp_path.iterdir()) == before


# ==========================================================================
# The shipped JSON dump
# ==========================================================================
def test_shipped_json_exists_and_matches_the_code() -> None:
    """The committed dump must be exactly what the generator produces now."""
    path = baseline.baseline_path()
    assert path.is_file(), f"{path} must be committed to the repository"

    document = json.loads(path.read_text(encoding="utf-8"))
    assert set(document) >= {"version", "generated_at", "indicators"}
    assert document["version"] == baseline.BASELINE_VERSION
    assert document["generated_at"] == baseline.BASELINE_GENERATED_AT

    expected = [i.to_dict() for i in baseline.builtin_indicators()]
    assert document["indicators"] == expected, (
        "signatures_baseline.json is stale - regenerate with "
        "'python3 -m aegis.intel.baseline'"
    )


def test_shipped_json_is_a_list_of_indicator_to_dict() -> None:
    document = json.loads(baseline.baseline_path().read_text(encoding="utf-8"))
    for row in document["indicators"]:
        assert set(row) == {
            "kind", "value", "name", "severity", "source",
            "tags", "description", "added_at",
        }
        assert isinstance(row["tags"], list)
        rebuilt = Indicator.from_dict(row)
        assert rebuilt.to_dict() == row


def test_generation_is_reproducible(tmp_path: Path) -> None:
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    baseline.generate_baseline_file(first)
    baseline.generate_baseline_file(second)
    assert first.read_bytes() == second.read_bytes()
    # And byte-identical to the committed file.
    assert first.read_bytes() == baseline.baseline_path().read_bytes()


def test_load_baseline_file_roundtrip(tmp_path: Path) -> None:
    target = tmp_path / "dump.json"
    baseline.generate_baseline_file(target)
    assert baseline.load_baseline_file(target) == baseline.builtin_indicators()


def test_load_baseline_file_tolerates_rubbish(tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    assert baseline.load_baseline_file(missing) == []

    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert baseline.load_baseline_file(broken) == []

    partial = tmp_path / "partial.json"
    partial.write_text(
        json.dumps({"indicators": [{"kind": "sha256", "value": "ab"}, "junk", {}]}),
        encoding="utf-8",
    )
    loaded = baseline.load_baseline_file(partial)
    assert len(loaded) == 1 and loaded[0].value == "ab"


def test_import_has_no_side_effects(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-importing the module must not touch the filesystem."""
    import importlib

    monkeypatch.chdir(tmp_path)
    importlib.reload(baseline)
    assert list(tmp_path.iterdir()) == []


# ==========================================================================
# Integration with the real SignatureDB (skipped until Agent A lands)
# ==========================================================================
def test_ensure_baseline_against_real_signature_db(eicar_bytes: bytes) -> None:
    signatures = pytest.importorskip(
        "aegis.core.signatures", reason="aegis.core.signatures not available yet"
    )
    db = signatures.SignatureDB(None)
    try:
        added = baseline.ensure_baseline(db)
        assert added == len(baseline.builtin_indicators())
        assert baseline.ensure_baseline(db) == 0, "idempotent against the real DB"
        assert len(db) == added

        # The EICAR file is detected both ways.
        digest = hashlib.sha256(eicar_bytes).hexdigest()
        hit = db.lookup_hash(sha256=digest)
        assert hit is not None and hit.name == "EICAR.Test.File"

        matches = db.match_bytes(eicar_bytes)
        assert any(i.name == "EICAR.Test.File" for i, _ in matches)

        # A simulator sample is detected by its marker, at the right offset.
        sample = b"junk header " + b"AEGIS-SIM-" + b"BEACON" + b" trailing bytes"
        hits = db.match_bytes(sample)
        assert any(i.name == "Sim.Beacon.Marker" for i, _ in hits)
        offset = next(off for i, off in hits if i.name == "Sim.Beacon.Marker")
        assert sample[offset : offset + 16] == b"AEGIS-SIM-BEACON"

        # And the whole baseline can be rolled back by source.
        assert db.clear_source("builtin") == added
        assert len(db) == 0
    finally:
        db.close()
