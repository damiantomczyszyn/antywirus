"""The quarantine vault.

A quarantined sample is moved out of the user's tree into
``config.quarantine_dir`` and **obfuscated** on the way in.

Why obfuscate at all
--------------------
Three practical reasons, none of them secrecy:

1. a quarantined binary must not be runnable by a double-click;
2. the bytes must not trip *another* scanner on the machine (or a cloud backup
   agent), which would delete Aegis' vault from under it;
3. the original bytes must come back exactly for restore and re-scanning.

How it works
------------
A 32-byte vault key is generated once with :func:`secrets.token_bytes` and
stored mode ``0o600``.  Each entry derives its own key with BLAKE2b over
``vault_key || entry_id`` and the payload is XOR-ed with a BLAKE2b keystream.

**This is not encryption.**  The key sits next to the data, so anyone who can
read the vault can undo it.  It is a speed bump against accidental execution,
nothing more, and it is not advertised as protection anywhere in the UI.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import secrets
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Iterable

from ..config import Config
from ..events import EventBus, EventType
from ..models import ActionKind, ActionResult, FileVerdict, QuarantineEntry, Severity

__all__ = ["Quarantine", "VAULT_KEY_NAME", "ENTRY_SUFFIX"]

VAULT_KEY_NAME = "vault.key"
ENTRY_SUFFIX = ".aegis-quarantine"

_KEYSTREAM_BLOCK = 64          # BLAKE2b digest size used per keystream block
_CHUNK = 1 << 20               # obfuscate 1 MiB at a time


def _keystream(key: bytes, length: int, start_block: int = 0) -> bytes:
    """Deterministic pseudo-random byte stream derived from *key*."""
    out = bytearray()
    block = start_block
    while len(out) < length:
        out += hashlib.blake2b(
            block.to_bytes(8, "little"), key=key, digest_size=_KEYSTREAM_BLOCK
        ).digest()
        block += 1
    return bytes(out[:length])


def _xor(data: bytes, stream: bytes) -> bytes:
    """XOR two equal-length buffers (big-int trick: C speed, no per-byte loop)."""
    size = len(data)
    if size == 0:
        return b""
    return (
        int.from_bytes(data, "big") ^ int.from_bytes(stream[:size], "big")
    ).to_bytes(size, "big")


def _xor_at(key: bytes, offset: int, data: bytes) -> bytes:
    """Obfuscate/deobfuscate *data* that lives at absolute *offset*.

    Keying on the absolute offset (instead of on a chunk counter) keeps the
    transform independent of how the file happens to be chunked, so a short
    read can never desynchronise the keystream.  The operation is its own
    inverse.
    """
    if not data:
        return b""
    start_block, skip = divmod(offset, _KEYSTREAM_BLOCK)
    stream = _keystream(key, skip + len(data), start_block)[skip:]
    return _xor(data, stream)


def _relocate(src: Path, dst: Path) -> None:
    """Move *src* to *dst*, falling back to copy+unlink across filesystems."""
    try:
        os.replace(src, dst)
        return
    except OSError as exc:
        if exc.errno not in (errno.EXDEV, errno.EPERM):
            raise
    shutil.copy2(src, dst)
    os.unlink(src)


class Quarantine:
    """Vault manager.  Safe to use from several threads."""

    def __init__(self, config: Config, bus: EventBus | None = None) -> None:
        self.config = config
        self._bus = bus
        self._lock = threading.RLock()
        self._entries: dict[str, QuarantineEntry] | None = None
        self._vault_key: bytes | None = None

    # ------------------------------------------------------------------
    # plumbing
    # ------------------------------------------------------------------
    @property
    def vault_dir(self) -> Path:
        return self.config.quarantine_dir

    @property
    def index_path(self) -> Path:
        return self.config.quarantine_index

    def _publish(self, kind: EventType, message: str, level: str = "info", **payload: Any) -> None:
        if self._bus is not None:
            self._bus.publish(kind, message, level=level, **payload)

    def _ensure_vault(self) -> None:
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.vault_dir.chmod(0o700)
        except OSError:  # pragma: no cover - exotic filesystems
            pass

    def _key(self) -> bytes:
        """Load (or create) the 32-byte vault key, mode ``0o600``."""
        if self._vault_key is not None:
            return self._vault_key
        self._ensure_vault()
        key_path = self.vault_dir / VAULT_KEY_NAME
        try:
            key = key_path.read_bytes()
            if len(key) == 32:
                self._vault_key = key
                return key
        except OSError:
            pass
        key = secrets.token_bytes(32)
        fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        self._vault_key = key
        return key

    def _entry_key(self, entry_id: str) -> bytes:
        return hashlib.blake2b(
            entry_id.encode("utf-8"), key=self._key(), digest_size=32
        ).digest()

    # ------------------------------------------------------------------
    # index
    # ------------------------------------------------------------------
    def _load(self) -> dict[str, QuarantineEntry]:
        if self._entries is not None:
            return self._entries
        entries: dict[str, QuarantineEntry] = {}
        try:
            raw = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = None
        if isinstance(raw, dict):
            rows: Iterable[Any] = raw.get("entries", [])
        elif isinstance(raw, list):
            rows = raw
        else:
            rows = []
        for row in rows:
            try:
                entry = QuarantineEntry.from_dict(row)
            except (KeyError, TypeError, ValueError):
                continue  # a corrupted row must not hide the rest of the vault
            entries[entry.entry_id] = entry
        self._entries = entries
        return entries

    def _save(self) -> None:
        """Write ``index.json`` atomically with private permissions."""
        entries = self._load()
        self._ensure_vault()
        payload = json.dumps(
            {
                "updated_at": time.time(),
                "entries": [entry.to_dict() for entry in entries.values()],
            },
            ensure_ascii=False,
            indent=1,
        )
        fd, tmp = tempfile.mkstemp(dir=str(self.vault_dir), prefix=".index-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.index_path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    def quarantine(
        self,
        path: str | os.PathLike[str],
        verdict: FileVerdict | None = None,
        threat_name: str = "",
    ) -> ActionResult:
        """Move *path* into the vault.  ``ActionResult.detail`` holds the entry id."""
        source = Path(path)
        target_label = str(source)
        with self._lock:
            try:
                stat = source.stat()
            except OSError as exc:
                return ActionResult(
                    kind=ActionKind.QUARANTINE,
                    target=target_label,
                    ok=False,
                    detail=f"Nie można odczytać pliku: {exc.strerror or exc}",
                )
            if not source.is_file():
                return ActionResult(
                    kind=ActionKind.QUARANTINE,
                    target=target_label,
                    ok=False,
                    detail="Obiekt nie jest zwykłym plikiem - pomijam.",
                )
            if self.config.is_internal(source):
                return ActionResult(
                    kind=ActionKind.QUARANTINE,
                    target=target_label,
                    ok=False,
                    detail="Plik należy do danych roboczych Aegis - nie poddaję kwarantannie.",
                )

            entry_id = secrets.token_hex(8)
            vault_name = f"{entry_id}{ENTRY_SUFFIX}"
            vault_path = self.vault_dir / vault_name
            self._ensure_vault()
            key = self._entry_key(entry_id)

            digest = hashlib.sha256()
            size = 0
            tmp_fd, tmp_name = tempfile.mkstemp(dir=str(self.vault_dir), prefix=".q-", suffix=".tmp")
            try:
                with open(source, "rb") as src, os.fdopen(tmp_fd, "wb") as dst:
                    while True:
                        chunk = src.read(_CHUNK)
                        if not chunk:
                            break
                        digest.update(chunk)
                        dst.write(_xor_at(key, size, chunk))
                        size += len(chunk)
                    dst.flush()
                    os.fsync(dst.fileno())
                os.chmod(tmp_name, 0o600)
                os.replace(tmp_name, vault_path)
            except OSError as exc:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
                return ActionResult(
                    kind=ActionKind.QUARANTINE,
                    target=target_label,
                    ok=False,
                    detail=f"Zapis do skarbca nie udał się: {exc.strerror or exc}",
                )

            # Only now remove the original: if the unlink fails the vault copy
            # is rolled back, so a file is never both live and quarantined.
            try:
                os.unlink(source)
            except OSError as exc:
                try:
                    os.unlink(vault_path)
                except OSError:  # pragma: no cover
                    pass
                return ActionResult(
                    kind=ActionKind.QUARANTINE,
                    target=target_label,
                    ok=False,
                    detail=f"Nie można usunąć oryginału: {exc.strerror or exc}",
                )

            name = threat_name or (verdict.threat_name if verdict else "") or "Nieznane.Zagrozenie"
            entry = QuarantineEntry(
                entry_id=entry_id,
                original_path=str(source.absolute()),
                vault_name=vault_name,
                size=size,
                sha256=verdict.sha256 if verdict and verdict.sha256 else digest.hexdigest(),
                threat_name=name,
                severity=verdict.severity if verdict else Severity.HIGH,
                quarantined_at=time.time(),
                detections=[d.to_dict() for d in verdict.detections] if verdict else [],
                original_mode=stat.st_mode & 0o7777,
            )
            self._load()[entry_id] = entry
            self._save()

        self._publish(
            EventType.ACTION_TAKEN,
            f"Plik przeniesiony do kwarantanny: {source.name} ({name})",
            level="warning",
            action=ActionKind.QUARANTINE.value,
            path=str(source),
            entry_id=entry_id,
            threat_name=name,
        )
        self._publish(
            EventType.QUARANTINE_CHANGED,
            "Zawartość kwarantanny się zmieniła.",
            count=len(self._load()),
        )
        return ActionResult(
            kind=ActionKind.QUARANTINE,
            target=str(source.absolute()),
            ok=True,
            detail=entry_id,
        )

    def restore(self, entry_id: str) -> ActionResult:
        """Put a quarantined file back where it came from.

        Refuses when something already exists at the original path - silently
        overwriting a file the user created in the meantime would be worse than
        the malware.
        """
        with self._lock:
            entry = self._load().get(entry_id)
            if entry is None:
                return ActionResult(
                    kind=ActionKind.RESTORE,
                    target=entry_id,
                    ok=False,
                    detail="Nie ma takiego wpisu w kwarantannie.",
                )
            destination = Path(entry.original_path)
            if destination.exists() or destination.is_symlink():
                return ActionResult(
                    kind=ActionKind.RESTORE,
                    target=entry.original_path,
                    ok=False,
                    detail="W miejscu docelowym już istnieje plik - przywrócenie przerwane.",
                )
            try:
                payload = self.read_payload(entry_id)
            except (OSError, KeyError) as exc:
                return ActionResult(
                    kind=ActionKind.RESTORE,
                    target=entry.original_path,
                    ok=False,
                    detail=f"Nie można odczytać pliku ze skarbca: {exc}",
                )
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                fd, tmp = tempfile.mkstemp(dir=str(destination.parent), prefix=".restore-")
                with os.fdopen(fd, "wb") as fh:
                    fh.write(payload)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.chmod(tmp, entry.original_mode or 0o600)
                _relocate(Path(tmp), destination)
            except OSError as exc:
                return ActionResult(
                    kind=ActionKind.RESTORE,
                    target=entry.original_path,
                    ok=False,
                    detail=f"Zapis pliku nie udał się: {exc.strerror or exc}",
                )

            try:
                (self.vault_dir / entry.vault_name).unlink()
            except OSError:  # pragma: no cover - vault file already gone
                pass
            self._load().pop(entry_id, None)
            self._save()
            count = len(self._load())

        self._publish(
            EventType.ACTION_TAKEN,
            f"Plik przywrócony z kwarantanny: {entry.original_path}",
            action=ActionKind.RESTORE.value,
            path=entry.original_path,
            entry_id=entry_id,
        )
        self._publish(EventType.QUARANTINE_CHANGED, "Zawartość kwarantanny się zmieniła.", count=count)
        return ActionResult(
            kind=ActionKind.RESTORE,
            target=entry.original_path,
            ok=True,
            detail=entry_id,
        )

    def delete(self, entry_id: str) -> ActionResult:
        """Destroy a quarantined sample for good."""
        with self._lock:
            entry = self._load().get(entry_id)
            if entry is None:
                return ActionResult(
                    kind=ActionKind.DELETE,
                    target=entry_id,
                    ok=False,
                    detail="Nie ma takiego wpisu w kwarantannie.",
                )
            try:
                (self.vault_dir / entry.vault_name).unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                return ActionResult(
                    kind=ActionKind.DELETE,
                    target=entry.original_path,
                    ok=False,
                    detail=f"Nie można usunąć pliku ze skarbca: {exc.strerror or exc}",
                )
            self._load().pop(entry_id, None)
            self._save()
            count = len(self._load())

        self._publish(
            EventType.ACTION_TAKEN,
            f"Usunięto z kwarantanny: {entry.original_path}",
            action=ActionKind.DELETE.value,
            path=entry.original_path,
            entry_id=entry_id,
        )
        self._publish(EventType.QUARANTINE_CHANGED, "Zawartość kwarantanny się zmieniła.", count=count)
        return ActionResult(
            kind=ActionKind.DELETE,
            target=entry.original_path,
            ok=True,
            detail=entry_id,
        )

    def purge_all(self) -> int:
        """Delete every entry.  Returns how many were removed."""
        with self._lock:
            entries = list(self._load().values())
            removed = 0
            for entry in entries:
                try:
                    (self.vault_dir / entry.vault_name).unlink()
                except FileNotFoundError:
                    pass
                except OSError:  # pragma: no cover
                    continue
                self._load().pop(entry.entry_id, None)
                removed += 1
            self._save()
        if removed:
            self._publish(
                EventType.QUARANTINE_CHANGED,
                f"Wyczyszczono kwarantannę ({removed}).",
                count=0,
                removed=removed,
            )
        return removed

    def list(self) -> list[QuarantineEntry]:
        """Entries, newest first."""
        with self._lock:
            return sorted(self._load().values(), key=lambda e: e.quarantined_at, reverse=True)

    def get(self, entry_id: str) -> QuarantineEntry | None:
        with self._lock:
            return self._load().get(entry_id)

    def read_payload(self, entry_id: str) -> bytes:
        """De-obfuscated original bytes - used to re-scan a quarantined sample.

        Raises :class:`KeyError` for an unknown id and :class:`OSError` if the
        vault file has disappeared.
        """
        with self._lock:
            entry = self._load().get(entry_id)
            if entry is None:
                raise KeyError(entry_id)
            key = self._entry_key(entry_id)
            vault_path = self.vault_dir / entry.vault_name
            out = bytearray()
            with open(vault_path, "rb") as fh:
                while True:
                    chunk = fh.read(_CHUNK)
                    if not chunk:
                        break
                    out += _xor_at(key, len(out), chunk)
            return bytes(out)

    def stats(self) -> dict[str, Any]:
        """Summary for the dashboard."""
        entries = self.list()
        return {
            "count": len(entries),
            "bytes": sum(e.size for e in entries),
            "newest": entries[0].quarantined_at if entries else None,
            "by_severity": {
                sev.value: sum(1 for e in entries if e.severity is sev) for sev in Severity
            },
        }

    def __len__(self) -> int:
        with self._lock:
            return len(self._load())
