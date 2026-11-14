"""Tests for aegis.core.hashing."""

from __future__ import annotations

import hashlib
import os

import pytest

from aegis.core.hashing import (
    EMPTY_SHA256,
    FileHashes,
    hash_bytes,
    hash_file,
    hash_path_safe,
    sha256_file,
)

HELLO = b"hello world"
HELLO_SHA256 = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
HELLO_SHA1 = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
HELLO_MD5 = "5eb63bbbe01eeed093cb22bb8f5acdc3"


def test_hash_bytes_known_digests() -> None:
    hashes = hash_bytes(HELLO)
    assert hashes.sha256 == HELLO_SHA256
    assert hashes.sha1 == HELLO_SHA1
    assert hashes.md5 == HELLO_MD5
    assert hashes.size == len(HELLO)


def test_hash_bytes_empty() -> None:
    hashes = hash_bytes(b"")
    assert hashes.sha256 == EMPTY_SHA256
    assert hashes.size == 0


def test_hash_file_matches_hash_bytes(tmp_path) -> None:
    target = tmp_path / "sample.bin"
    payload = os.urandom(5000)
    target.write_bytes(payload)
    assert hash_file(target) == hash_bytes(payload)


@pytest.mark.parametrize("chunk", [1, 3, 7, 64, 4096, 1 << 20])
def test_hash_file_is_chunk_size_independent(tmp_path, chunk: int) -> None:
    """A streaming bug shows up as a digest that depends on the chunk size."""
    target = tmp_path / "chunky.bin"
    payload = bytes(range(256)) * 97          # 24 832 bytes: not a round number
    target.write_bytes(payload)
    assert hash_file(target, chunk_size=chunk) == hash_bytes(payload)


def test_hash_file_handles_multi_megabyte_file(tmp_path) -> None:
    target = tmp_path / "big.bin"
    payload = os.urandom(3 * 1024 * 1024 + 12345)
    target.write_bytes(payload)
    hashes = hash_file(target)
    assert hashes.size == len(payload)
    assert hashes.sha256 == hashlib.sha256(payload).hexdigest()


def test_bad_chunk_size_falls_back(tmp_path) -> None:
    target = tmp_path / "zero.bin"
    target.write_bytes(b"abc")
    assert hash_file(target, chunk_size=0).sha256 == hash_bytes(b"abc").sha256
    assert sha256_file(target, chunk_size=-5) == hash_bytes(b"abc").sha256


def test_sha256_file_agrees_with_hash_file(tmp_path) -> None:
    target = tmp_path / "x.bin"
    target.write_bytes(b"A" * 100000)
    assert sha256_file(target) == hash_file(target).sha256


def test_hash_file_raises_oserror_for_missing_file(tmp_path) -> None:
    """The scanner relies on OSError propagating, not on a sentinel value."""
    with pytest.raises(OSError):
        hash_file(tmp_path / "does-not-exist")
    with pytest.raises(OSError):
        sha256_file(tmp_path / "does-not-exist")


def test_hash_path_safe_returns_none_instead_of_raising(tmp_path) -> None:
    assert hash_path_safe(tmp_path / "nope") is None
    target = tmp_path / "ok.bin"
    target.write_bytes(b"data")
    assert hash_path_safe(target) == hash_bytes(b"data")


def test_filehashes_is_frozen_and_comparable() -> None:
    hashes = hash_bytes(b"abc")
    with pytest.raises(Exception):
        hashes.sha256 = "x"  # type: ignore[misc]
    assert hashes == hash_bytes(b"abc")
    assert hashes != hash_bytes(b"abd")


def test_matches_accepts_any_of_the_three_digests() -> None:
    hashes = hash_bytes(HELLO)
    assert hashes.matches(HELLO_SHA256.upper())
    assert hashes.matches("  " + HELLO_MD5 + "  ")
    assert hashes.matches(HELLO_SHA1)
    assert not hashes.matches("deadbeef")


def test_as_dict_shape() -> None:
    data = hash_bytes(b"x").as_dict()
    assert set(data) == {"sha256", "sha1", "md5", "size"}
    assert isinstance(FileHashes(**data), FileHashes)  # type: ignore[arg-type]
