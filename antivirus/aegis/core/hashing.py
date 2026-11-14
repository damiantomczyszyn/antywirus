"""File digests.

Three digests of the same bytes are needed for every scan (the virus database
indexes SHA-256, SHA-1 and MD5 because threat feeds publish all three), so the
file is read exactly **once** and fed to the three hash objects in parallel.
Reading a 64 MiB sample three times would triple the I/O for nothing.

MD5 and SHA-1 are used here purely as *database keys* for known-bad samples -
never as a security primitive.

``OSError`` is deliberately **not** swallowed: the scanner knows how to turn it
into ``FileVerdict.error`` and the GUI knows how to show it.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

__all__ = ["FileHashes", "hash_file", "hash_bytes", "sha256_file", "EMPTY_SHA256"]

#: SHA-256 of b"" - handy for tests and for short-circuiting empty files.
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

_DEFAULT_CHUNK = 1 << 20  # 1 MiB


@dataclass(frozen=True, slots=True)
class FileHashes:
    """The three digests of one blob plus its length in bytes."""

    sha256: str
    sha1: str
    md5: str
    size: int

    def as_dict(self) -> dict[str, str | int]:
        return {"sha256": self.sha256, "sha1": self.sha1, "md5": self.md5, "size": self.size}

    def matches(self, digest: str) -> bool:
        """True if *digest* (any of the three algorithms) identifies this blob."""
        d = digest.strip().lower()
        return d in (self.sha256, self.sha1, self.md5)


def _new_trio() -> tuple["hashlib._Hash", "hashlib._Hash", "hashlib._Hash"]:
    # usedforsecurity=False keeps MD5/SHA-1 usable on FIPS-restricted builds,
    # where they are otherwise refused outright.
    try:
        return (
            hashlib.sha256(),
            hashlib.sha1(usedforsecurity=False),
            hashlib.md5(usedforsecurity=False),
        )
    except (TypeError, ValueError):  # pragma: no cover - very old interpreters
        return hashlib.sha256(), hashlib.sha1(), hashlib.md5()


def hash_file(path: str | os.PathLike[str], chunk_size: int = _DEFAULT_CHUNK) -> FileHashes:
    """Compute SHA-256 + SHA-1 + MD5 of *path* in a single streaming pass.

    Memory use is bounded by *chunk_size*, so a 4 GiB file costs 1 MiB of RAM.
    Raises :class:`OSError` if the file cannot be read - callers decide what to
    do about that.
    """
    if chunk_size <= 0:
        chunk_size = _DEFAULT_CHUNK
    sha256, sha1, md5 = _new_trio()
    size = 0
    # readinto() into a reused buffer avoids allocating a fresh bytes object
    # per chunk, which matters when walking tens of thousands of files.
    buf = bytearray(chunk_size)
    view = memoryview(buf)
    with open(path, "rb", buffering=0) as fh:
        while True:
            read = fh.readinto(buf)
            if not read:
                break
            block = view[:read]
            sha256.update(block)
            sha1.update(block)
            md5.update(block)
            size += read
    return FileHashes(sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest(), size)


def hash_bytes(data: bytes) -> FileHashes:
    """Same as :func:`hash_file` for an in-memory blob (archive members)."""
    sha256, sha1, md5 = _new_trio()
    sha256.update(data)
    sha1.update(data)
    md5.update(data)
    return FileHashes(sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest(), len(data))


def sha256_file(path: str | os.PathLike[str], chunk_size: int = _DEFAULT_CHUNK) -> str:
    """SHA-256 only - used where the other two digests would be wasted work."""
    if chunk_size <= 0:
        chunk_size = _DEFAULT_CHUNK
    digest = hashlib.sha256()
    buf = bytearray(chunk_size)
    view = memoryview(buf)
    with open(path, "rb", buffering=0) as fh:
        while True:
            read = fh.readinto(buf)
            if not read:
                break
            digest.update(view[:read])
    return digest.hexdigest()


def hash_path_safe(path: str | os.PathLike[str]) -> FileHashes | None:
    """Convenience wrapper returning ``None`` instead of raising."""
    try:
        return hash_file(Path(path))
    except OSError:
        return None
