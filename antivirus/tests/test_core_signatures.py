"""Tests for aegis.core.signatures (the virus database)."""

from __future__ import annotations

import os
import sqlite3
import threading

import pytest

from aegis.core.signatures import PatternError, SignatureDB, compile_pattern
from aegis.models import Indicator, IndicatorKind, Severity

SHA = "a" * 64
SHA_B = "b" * 64
MD5 = "c" * 32
SHA1 = "d" * 40


@pytest.fixture()
def db():
    database = SignatureDB(None)
    yield database
    database.close()


def ind(kind: IndicatorKind, value: str, **kwargs) -> Indicator:
    return Indicator(kind=kind, value=value, **kwargs)


# --------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------
def test_memory_database_starts_empty(db: SignatureDB) -> None:
    assert len(db) == 0
    assert db.stats()["total"] == 0
    assert db.path is None


def test_add_reports_new_versus_update(db: SignatureDB) -> None:
    item = ind(IndicatorKind.SHA256, SHA, name="Test.A")
    assert db.add(item) is True
    assert db.add(item) is False
    assert len(db) == 1


def test_values_are_normalised_for_lookup(db: SignatureDB) -> None:
    db.add(ind(IndicatorKind.SHA256, SHA.upper(), name="Test.Upper"))
    assert db.lookup_hash(sha256=SHA.upper()) is not None
    assert db.lookup_hash(sha256=SHA) is not None
    assert db.lookup_hash(sha256="  " + SHA + " ") is not None


def test_lookup_hash_prefers_sha256_then_sha1_then_md5(db: SignatureDB) -> None:
    db.add(ind(IndicatorKind.MD5, MD5, name="Weak.Md5"))
    db.add(ind(IndicatorKind.SHA256, SHA, name="Strong.Sha256"))
    found = db.lookup_hash(sha256=SHA, sha1=SHA1, md5=MD5)
    assert found is not None and found.name == "Strong.Sha256"
    only_md5 = db.lookup_hash(sha256=SHA_B, md5=MD5)
    assert only_md5 is not None and only_md5.name == "Weak.Md5"


def test_lookup_hash_miss_and_empty_arguments(db: SignatureDB) -> None:
    db.add(ind(IndicatorKind.SHA256, SHA))
    assert db.lookup_hash(sha256=SHA_B) is None
    assert db.lookup_hash() is None
    assert db.lookup_hash(sha256="", md5=None) is None


def test_indicator_metadata_survives_a_roundtrip(db: SignatureDB) -> None:
    db.add(
        ind(
            IndicatorKind.SHA256,
            SHA,
            name="Sim.Family.Variant",
            severity=Severity.CRITICAL,
            source="feed-x",
            tags=("ransom", "pl"),
            description="Opis zagrożenia",
            added_at=1234.5,
        )
    )
    found = db.lookup_hash(sha256=SHA)
    assert found is not None
    assert found.name == "Sim.Family.Variant"
    assert found.severity is Severity.CRITICAL
    assert found.source == "feed-x"
    assert found.tags == ("ransom", "pl")
    assert found.description == "Opis zagrożenia"
    assert found.added_at == 1234.5


def test_remove(db: SignatureDB) -> None:
    db.add(ind(IndicatorKind.SHA256, SHA))
    assert db.remove(IndicatorKind.SHA256, SHA.upper()) is True   # normalised
    assert db.remove(IndicatorKind.SHA256, SHA) is False
    assert len(db) == 0


def test_clear_source(db: SignatureDB) -> None:
    db.add_many(
        [ind(IndicatorKind.SHA256, f"{n:064x}", source="feed") for n in range(5)]
        + [ind(IndicatorKind.SHA256, SHA, source="builtin")]
    )
    assert db.clear_source("feed") == 5
    assert db.clear_source("feed") == 0
    assert len(db) == 1


# --------------------------------------------------------------------------
# bulk import
# --------------------------------------------------------------------------
def test_add_many_counts_added_and_updated_honestly(db: SignatureDB) -> None:
    batch = [ind(IndicatorKind.SHA256, f"{n:064x}", name=f"T{n}", added_at=1.0) for n in range(50)]
    assert db.add_many(batch) == (50, 0)
    # Re-importing an unchanged feed is a no-op, not 50 "updates".
    assert db.add_many(batch) == (0, 0)
    changed = [
        ind(IndicatorKind.SHA256, f"{n:064x}", name=f"T{n}-v2", added_at=1.0) for n in range(5)
    ]
    assert db.add_many(changed) == (0, 5)
    assert db.lookup_hash(sha256=f"{0:064x}").name == "T0-v2"
    assert len(db) == 50


def test_add_many_deduplicates_within_the_batch(db: SignatureDB) -> None:
    same = [ind(IndicatorKind.SHA256, SHA, name="first"), ind(IndicatorKind.SHA256, SHA, name="last")]
    assert db.add_many(same) == (1, 0)
    assert len(db) == 1
    assert db.lookup_hash(sha256=SHA).name == "last"


def test_add_many_empty_is_free(db: SignatureDB) -> None:
    before = db.version()
    assert db.add_many([]) == (0, 0)
    assert db.version() == before


def test_add_many_is_fast_enough_for_a_real_feed(db: SignatureDB) -> None:
    """A row-at-a-time implementation takes minutes here; one transaction seconds."""
    import time

    batch = [ind(IndicatorKind.SHA256, f"{n:064x}", source="feed") for n in range(20000)]
    started = time.perf_counter()
    added, updated = db.add_many(batch)
    elapsed = time.perf_counter() - started
    assert (added, updated) == (20000, 0)
    assert elapsed < 10.0, f"add_many(20k) took {elapsed:.1f}s"


# --------------------------------------------------------------------------
# iteration and stats
# --------------------------------------------------------------------------
def test_iter_indicators_filters_by_kind_and_pages(db: SignatureDB) -> None:
    db.add_many([ind(IndicatorKind.SHA256, f"{n:064x}") for n in range(2500)])
    db.add_many([ind(IndicatorKind.DOMAIN, f"evil{n}.example")for n in range(3)])
    assert sum(1 for _ in db.iter_indicators()) == 2503
    assert sum(1 for _ in db.iter_indicators(IndicatorKind.SHA256)) == 2500
    domains = list(db.iter_indicators(IndicatorKind.DOMAIN))
    assert len(domains) == 3
    assert all(d.kind is IndicatorKind.DOMAIN for d in domains)


def test_stats_groups_by_kind_and_source(db: SignatureDB) -> None:
    db.add_many(
        [
            ind(IndicatorKind.SHA256, SHA, source="builtin"),
            ind(IndicatorKind.MD5, MD5, source="feed"),
            ind(IndicatorKind.DOMAIN, "evil.example", source="feed"),
        ]
    )
    stats = db.stats()
    assert stats["total"] == 3
    assert stats["by_kind"] == {"domain": 1, "md5": 1, "sha256": 1}
    assert stats["by_source"] == {"feed": 2, "builtin": 1}
    assert stats["version"] == db.version()


def test_version_changes_on_mutation_only(db: SignatureDB) -> None:
    first = db.version()
    db.add(ind(IndicatorKind.SHA256, SHA))
    second = db.version()
    assert second != first
    db.add(ind(IndicatorKind.SHA256, SHA))          # same payload -> still a write
    db.remove(IndicatorKind.MD5, MD5)               # nothing removed
    third = db.version()
    assert db.revision() >= 2
    assert third != first


# --------------------------------------------------------------------------
# patterns
# --------------------------------------------------------------------------
def test_compile_pattern_wildcards() -> None:
    assert compile_pattern("4d5a") == rb"\x4d\x5a"
    assert compile_pattern("4d5a????0003") == rb"\x4d\x5a..\x00\x03"
    assert compile_pattern("4D 5A") == rb"\x4d\x5a"
    assert compile_pattern("4d:5a") == rb"\x4d\x5a"
    assert compile_pattern("4?5a") == rb"[\x40-\x4f]\x5a"
    assert b"\\x0f" in compile_pattern("?f?f")   # low-nibble class


@pytest.mark.parametrize("bad", ["", "4d5", "zz", "????", "??", "4d5azz", "?f", "4???"])
def test_compile_pattern_rejects_garbage(bad: str) -> None:
    with pytest.raises(PatternError):
        compile_pattern(bad)


def test_match_bytes_finds_pattern_with_offset(db: SignatureDB) -> None:
    db.add(ind(IndicatorKind.PATTERN, Indicator.pattern_from_text("AEGIS-MARK"), name="Sim.Mark"))
    data = b"\x00" * 17 + b"AEGIS-MARK" + b"\xff" * 5
    hits = db.match_bytes(data)
    assert len(hits) == 1
    indicator, offset = hits[0]
    assert indicator.name == "Sim.Mark"
    assert offset == 17


def test_match_bytes_wildcards_and_clean_data(db: SignatureDB) -> None:
    db.add(ind(IndicatorKind.PATTERN, "4d5a????0003", name="Sim.MzWild"))
    assert db.match_bytes(b"\x4d\x5a\xaa\xbb\x00\x03")
    assert db.match_bytes(b"\x4d\x5a\x11\x22\x00\x04") == []
    assert db.match_bytes(b"zwyczajny tekst") == []
    assert db.match_bytes(b"") == []


def test_match_bytes_respects_limit_and_reports_each_pattern_once(db: SignatureDB) -> None:
    db.add_many(
        [
            ind(IndicatorKind.PATTERN, Indicator.pattern_from_text(f"MARK{n}"), name=f"P{n}")
            for n in range(6)
        ]
    )
    data = b"".join(f"MARK{n}".encode() + b"...." for n in range(6)) * 3
    assert len(db.match_bytes(data, limit=3)) == 3
    assert len(db.match_bytes(data, limit=100)) == 6     # once per indicator, not per hit
    assert db.match_bytes(data, limit=0) == []


def test_match_bytes_finds_overlapping_patterns(db: SignatureDB) -> None:
    """A short generic pattern must not hide a longer, more specific one."""
    db.add_many(
        [
            ind(IndicatorKind.PATTERN, "4d5a", name="Short.MZ"),
            ind(IndicatorKind.PATTERN, "4d5a9000", name="Long.MZ"),
        ]
    )
    names = {i.name for i, _ in db.match_bytes(b"\x4d\x5a\x90\x00rest")}
    assert names == {"Short.MZ", "Long.MZ"}


def test_pattern_cache_is_invalidated_by_mutations(db: SignatureDB) -> None:
    data = b"xxx" + b"LATER-MARK" + b"yyy"
    assert db.match_bytes(data) == []                       # compiles an empty set
    db.add(ind(IndicatorKind.PATTERN, Indicator.pattern_from_text("LATER-MARK"), name="Late"))
    assert [i.name for i, _ in db.match_bytes(data)] == ["Late"]
    db.remove(IndicatorKind.PATTERN, Indicator.pattern_from_text("LATER-MARK"))
    assert db.match_bytes(data) == []


def test_malformed_pattern_rows_do_not_break_matching(db: SignatureDB) -> None:
    db.add(ind(IndicatorKind.PATTERN, "nonsense??", name="Broken"))
    db.add(ind(IndicatorKind.PATTERN, Indicator.pattern_from_text("GOOD"), name="Good"))
    assert [i.name for i, _ in db.match_bytes(b"--GOOD--")] == ["Good"]


def test_many_patterns_are_chunked_and_still_match(db: SignatureDB) -> None:
    from aegis.core.signatures import PATTERN_CHUNK

    count = PATTERN_CHUNK * 2 + 5
    db.add_many(
        [
            ind(IndicatorKind.PATTERN, Indicator.pattern_from_text(f"SIG{n:04d}X"), name=f"S{n}")
            for n in range(count)
        ]
    )
    for probe in (0, PATTERN_CHUNK, count - 1):
        hits = db.match_bytes(b"pad" + f"SIG{probe:04d}X".encode() + b"pad", limit=4)
        assert [i.name for i, _ in hits] == [f"S{probe}"]


def test_match_bytes_stays_fast_with_many_patterns(db: SignatureDB) -> None:
    """Performance regression guard.

    An early version wrapped every alternative in a capture group, which makes
    CPython drop its first-byte prefilter: the scan below took over three
    *minutes* instead of a fraction of a second.
    """
    import time

    db.add_many(
        [
            ind(IndicatorKind.PATTERN, Indicator.pattern_from_text(f"WZORZEC-{n:05d}-KONIEC"),
                name=f"W{n}")
            for n in range(500)
        ]
    )
    blob = os.urandom(1024 * 1024)
    db.match_bytes(blob)                      # pay the one-off compilation
    started = time.perf_counter()
    assert db.match_bytes(blob) == []
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0, f"skan 1 MiB z 500 wzorcami zajął {elapsed:.2f}s"

    needle = b"x" * 5000 + b"WZORZEC-00499-KONIEC" + b"y" * 5000
    assert [i.name for i, _ in db.match_bytes(needle)] == ["W499"]


def test_wildcard_leading_pattern_still_matches(db: SignatureDB) -> None:
    """Patterns starting with ?? live in their own chunk - they must still work."""
    db.add_many(
        [ind(IndicatorKind.PATTERN, "????4a4b4c", name="Wild.Lead")]
        + [ind(IndicatorKind.PATTERN, Indicator.pattern_from_text(f"LIT{n:03d}"), name=f"L{n}")
           for n in range(20)]
    )
    hits = db.match_bytes(b"\x00\x11\x22JKL" + b"LIT007")
    assert {i.name for i, _ in hits} == {"Wild.Lead", "L7"}


def test_a_pattern_matching_everywhere_does_not_stall(db: SignatureDB) -> None:
    import time

    db.add(ind(IndicatorKind.PATTERN, "0000", name="Zeros"))
    db.add(ind(IndicatorKind.PATTERN, Indicator.pattern_from_text("IGLA"), name="Needle"))
    data = b"\x00" * (2 * 1024 * 1024) + b"IGLA"
    started = time.perf_counter()
    names = {i.name for i, _ in db.match_bytes(data, limit=8)}
    assert time.perf_counter() - started < 3.0
    assert "Zeros" in names


# --------------------------------------------------------------------------
# network indicators
# --------------------------------------------------------------------------
def test_lookup_network_domain_parents_and_urls(db: SignatureDB) -> None:
    db.add(ind(IndicatorKind.DOMAIN, "evil.example", name="Bad.Domain"))
    db.add(ind(IndicatorKind.URL, "http://host.example/payload.bin", name="Bad.Url"))
    db.add(ind(IndicatorKind.IPV4, "203.0.113.7", name="Bad.Ip"))

    assert db.lookup_network(host="evil.example").name == "Bad.Domain"
    assert db.lookup_network(host="a.b.evil.example").name == "Bad.Domain"
    assert db.lookup_network(url="https://deep.evil.example/x").name == "Bad.Domain"
    assert db.lookup_network(url="http://host.example/payload.bin").name == "Bad.Url"
    assert db.lookup_network(url="HTTP://HOST.EXAMPLE/payload.bin").name == "Bad.Url"
    assert db.lookup_network(ip="203.0.113.7").name == "Bad.Ip"
    assert db.lookup_network(host="203.0.113.7").name == "Bad.Ip"
    assert db.lookup_network(host="example") is None
    assert db.lookup_network(host="good.example") is None
    assert db.lookup_network() is None


def test_lookup_network_does_not_match_a_bare_tld(db: SignatureDB) -> None:
    db.add(ind(IndicatorKind.DOMAIN, "example", name="Tld"))
    assert db.lookup_network(host="innocent.example") is None


# --------------------------------------------------------------------------
# persistence, import/export, lifecycle
# --------------------------------------------------------------------------
def test_file_database_persists_across_reopen(tmp_path) -> None:
    path = tmp_path / "nested" / "signatures.db"
    first = SignatureDB(path)
    first.add(ind(IndicatorKind.SHA256, SHA, name="Persisted"))
    first.add(ind(IndicatorKind.PATTERN, Indicator.pattern_from_text("KEEP"), name="KeepPattern"))
    revision = first.revision()
    first.close()

    assert path.is_file()
    second = SignatureDB(path)
    try:
        assert len(second) == 2
        assert second.lookup_hash(sha256=SHA).name == "Persisted"
        assert [i.name for i, _ in second.match_bytes(b"..KEEP..")] == ["KeepPattern"]
        assert second.revision() == revision
    finally:
        second.close()


def test_export_import_roundtrip(tmp_path, db: SignatureDB) -> None:
    db.add_many(
        [
            ind(IndicatorKind.SHA256, SHA, name="A", tags=("x", "y")),
            ind(IndicatorKind.DOMAIN, "evil.example", name="B", severity=Severity.MEDIUM),
        ]
    )
    target = tmp_path / "out" / "export.json"
    assert db.export_json(target) == 2

    other = SignatureDB(None)
    try:
        assert other.import_json(target) == (2, 0)
        assert other.lookup_hash(sha256=SHA).tags == ("x", "y")
        assert other.lookup_network(host="evil.example").severity is Severity.MEDIUM
        assert other.import_json(target) == (0, 0)
    finally:
        other.close()


def test_import_json_tolerates_broken_rows(tmp_path, db: SignatureDB) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text(
        '{"indicators": [{"kind": "sha256", "value": "' + SHA + '"}, {"kind": "???"}, 42]}',
        encoding="utf-8",
    )
    assert db.import_json(broken) == (1, 0)


def test_close_is_idempotent_and_blocks_further_use(db: SignatureDB) -> None:
    db.add(ind(IndicatorKind.SHA256, SHA))
    db.close()
    db.close()
    assert len(db) == 0                       # a closed database reports nothing
    with pytest.raises(sqlite3.ProgrammingError):
        db.lookup_hash(sha256=SHA)


def test_context_manager(tmp_path) -> None:
    with SignatureDB(tmp_path / "ctx.db") as database:
        database.add(ind(IndicatorKind.SHA256, SHA))
        assert len(database) == 1
    with pytest.raises(sqlite3.ProgrammingError):
        database.add(ind(IndicatorKind.MD5, MD5))


def test_concurrent_access_from_worker_threads(tmp_path) -> None:
    """The realtime monitor queries from several threads; SQLite needs the lock."""
    database = SignatureDB(tmp_path / "threads.db")
    database.add_many([ind(IndicatorKind.SHA256, f"{n:064x}", source="seed") for n in range(200)])
    database.add(ind(IndicatorKind.PATTERN, Indicator.pattern_from_text("THREAD"), name="T"))
    errors: list[BaseException] = []
    stop = threading.Event()

    def reader() -> None:
        try:
            while not stop.is_set():
                assert database.lookup_hash(sha256=f"{7:064x}") is not None
                database.match_bytes(b"pad THREAD pad")
                database.stats()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def writer() -> None:
        try:
            for n in range(200, 400):
                database.add(ind(IndicatorKind.SHA256, f"{n:064x}", source="writer"))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(3)]
    threads.append(threading.Thread(target=writer))
    for thread in threads[:3]:
        thread.start()
    threads[3].start()
    threads[3].join(30)
    stop.set()
    for thread in threads[:3]:
        thread.join(30)
    database.close()
    assert not errors, errors


def test_bus_receives_db_loaded(bus) -> None:
    database = SignatureDB(None, bus)
    try:
        types = [event.type.value for event in bus.history()]
        assert "db_loaded" in types
    finally:
        database.close()
