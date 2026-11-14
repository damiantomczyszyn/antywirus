"""Static heuristics - what catches malware the database has never seen.

A signature only knows yesterday's samples.  These rules look at *structure*
instead: entropy, PE layout, API strings, obfuscation, container tricks and
file-name games.  Every rule returns :class:`Detection` objects on the
``HEURISTIC`` layer, which :func:`aegis.engine.verdict.fuse` caps at 55 points -
so heuristics alone can raise suspicion up to MEDIUM but can never, on their
own, declare a file CRITICAL.  That is deliberate: false positives here are
cheap, a wrongly quarantined document is not.

Expensive facts (entropy, file type, decoded text, the parsed PE header, the
zip directory) are computed **once** per file in :class:`_FileFacts` and shared
by all rules.

The PE parser is hand-written on top of :mod:`struct`: ``pefile`` is a fine
library but the contract keeps the critical path on the standard library only.
"""

from __future__ import annotations

import io
import math
import os
import re
import struct
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any, Callable

from ..config import Config
from ..models import (
    SCORE_HEURISTIC_STRONG,
    SCORE_HEURISTIC_WEAK,
    Detection,
    DetectionLayer,
)

__all__ = [
    "shannon_entropy",
    "detect_file_type",
    "analyze",
    "HEURISTIC_RULES",
    "SUSPICIOUS_API_CATEGORIES",
]

# --------------------------------------------------------------------------
# tunables
# --------------------------------------------------------------------------
_WEAK = SCORE_HEURISTIC_WEAK          # 12.0
_STRONG = SCORE_HEURISTIC_STRONG      # 30.0

#: Entropy above which a whole executable looks packed or encrypted.
ENTROPY_PACKED = 7.4
#: Entropy above which a single window looks like an embedded payload.
ENTROPY_WINDOW = 7.5
#: A file whose overall entropy is below this is "otherwise low entropy".
ENTROPY_CALM = 6.8

_WINDOW_SIZE = 4096
_MAX_WINDOWS = 256            # bounds the sliding-window pass on huge files
_ENTROPY_SAMPLE = 3 * (1 << 20)  # at most 3 MiB fed to the whole-file histogram
_HEAD = 4096                  # bytes considered "the header" by several rules

# EICAR is split so that this source file does not itself contain the
# contiguous test string - otherwise Aegis would flag its own engine (and so
# would every other scanner on the machine).
_EICAR = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR" + r"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
).encode("ascii")

_EXEC_EXTENSIONS = frozenset(
    {
        "exe", "dll", "sys", "scr", "com", "pif", "cpl", "ocx", "drv", "msi",
        "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
        "hta", "jar", "lnk", "apk", "sh", "elf", "so", "run", "bin", "app",
    }
)

_DECOY_EXTENSIONS = frozenset(
    {
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
        "jpg", "jpeg", "png", "gif", "bmp", "svg", "mp3", "mp4", "avi", "mkv",
        "zip", "rar", "7z", "htm", "html", "xml", "json", "odt", "ods",
    }
)

#: Bidi / invisible characters used to hide the real extension in a file name.
_RTL_CHARS = "‪‫‬‭‮‎‏⁦⁧⁨⁩"

_DECOY_WORDS = (
    "faktura", "invoice", "zamowienie", "zamówienie", "umowa", "cv", "scan",
    "skan", "zdjecie", "zdjęcie", "photo", "dokument", "document", "paczka",
    "przesylka", "przesyłka", "payment", "receipt", "potwierdzenie", "wezwanie",
)

#: Packer / dropper section names.  Hand-written packers rarely bother to fake
#: a plausible name, which makes this a cheap and reliable signal.
_PACKER_SECTIONS = frozenset(
    {
        "upx0", "upx1", "upx2", "upx!", ".upx", ".aspack", ".adata", ".packed",
        "fsg!", "mew", ".mpress1", ".mpress2", ".petite", "nsp0", "nsp1", "nsp2",
        ".themida", ".vmp0", ".vmp1", ".vmp2", ".enigma1", ".enigma2", ".boom",
        ".shrink", ".taz", ".winapi", ".yc", "pec1", "pec2", ".perplex", "kkrunchy",
    }
)

#: API / command strings grouped by behaviour.  The score scales with the
#: number of distinct *categories* that fire, not with the raw hit count: ten
#: injection APIs are still just "process injection".
SUSPICIOUS_API_CATEGORIES: dict[str, tuple[str, ...]] = {
    "wstrzykiwanie kodu": (
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext",
        "RtlCreateUserThread", "NtWriteVirtualMemory",
    ),
    "przechwytywanie klawiatury": (
        "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState",
        "GetRawInputData", "AttachThreadInput",
    ),
    "kryptografia": (
        "CryptEncrypt", "CryptAcquireContext", "CryptGenKey", "CryptDeriveKey",
        "BCryptEncrypt", "CryptImportKey",
    ),
    "niszczenie kopii zapasowych": (
        "vssadmin delete shadows", "vssadmin.exe delete", "bcdedit",
        "wbadmin delete", "wmic shadowcopy delete", "shadowcopy delete",
        "recoveryenabled no",
    ),
    "trwałość w systemie": (
        "schtasks /create", "schtasks.exe /create", "reg add",
        r"currentversion\run", "sc create", "crontab -", "systemctl enable",
        r"start menu\programs\startup",
    ),
    "powershell / skrypty": (
        "powershell -enc", "powershell.exe -enc", "-encodedcommand",
        "frombase64string", "iex(", "iex (", "invoke-expression",
        "downloadstring", "downloadfile", "-nop -w hidden", "-windowstyle hidden",
        "invoke-webrequest",
    ),
    "host skryptowy": (
        "WScript.Shell", "Shell.Application", "ActiveXObject", "wscript.exe",
        "cscript.exe", "Scripting.FileSystemObject",
    ),
    "powłoka zwrotna / unix": (
        "nc -e", "ncat -e", "/dev/tcp/", "bash -i >&", "chmod +x",
        "base64 -d", "curl -s", "wget -q", "nohup ",
    ),
    "omijanie zabezpieczeń": (
        "amsiInitFailed", "AmsiScanBuffer", "EtwEventWrite", "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent", "Set-MpPreference", "-DisableRealtimeMonitoring",
    ),
}

# --------------------------------------------------------------------------
# rule catalogue (consumed by the GUI)
# --------------------------------------------------------------------------
_RULE_META: tuple[dict[str, Any], ...] = (
    {
        "id": "eicar",
        "name": "Plik testowy EICAR",
        "description": "Standardowy, nieszkodliwy ciąg testowy EICAR - używany do weryfikacji, "
        "czy skaner w ogóle działa.",
        "score": _STRONG,
    },
    {
        "id": "high_entropy",
        "name": "Wysoka entropia (upakowanie/szyfrowanie)",
        "description": "Entropia Shannona całego pliku wykonywalnego powyżej "
        f"{ENTROPY_PACKED} lub wyraźnie zaszyfrowany fragment w spokojnym pliku - "
        "typowe dla packerów i ukrytego ładunku.",
        "score": 28.0,
    },
    {
        "id": "pe_anomaly",
        "name": "Anomalie struktury PE",
        "description": "Brak importów, zapisywalna sekcja .text, sekcja o zerowym rozmiarze, "
        "punkt wejścia poza sekcjami lub nazwy sekcji typowe dla packerów.",
        "score": _STRONG,
    },
    {
        "id": "suspicious_api_strings",
        "name": "Podejrzane API i komendy",
        "description": "Ciągi znaków (ASCII i UTF-16LE) wskazujące na wstrzykiwanie kodu, "
        "keylogging, szyfrowanie plików, usuwanie kopii zapasowych lub trwałość w systemie.",
        "score": _STRONG,
    },
    {
        "id": "script_obfuscation",
        "name": "Zaciemniony skrypt",
        "description": "Długie bloki base64/hex, wykonywanie zdekodowanego kodu, budowanie "
        "tekstu z kodów znaków, bardzo długie linie lub dużo znaków niedrukowalnych.",
        "score": _STRONG,
    },
    {
        "id": "office_macro",
        "name": "Makra w dokumencie",
        "description": "Dokument OOXML lub OLE zawierający projekt VBA, albo RTF z obiektem "
        "OLE - klasyczny wektor phishingu.",
        "score": 28.0,
    },
    {
        "id": "double_extension",
        "name": "Podwójne rozszerzenie / sztuczki w nazwie",
        "description": "Nazwy w stylu faktura.pdf.exe, znaki sterujące kierunkiem tekstu "
        "(RTL override) albo plik wykonywalny udający dokument.",
        "score": _WEAK,
    },
    {
        "id": "embedded_executable",
        "name": "Osadzony plik wykonywalny",
        "description": "Nagłówek MZ/PE albo ELF znaleziony w środku pliku, który nie jest "
        "programem - typowy dropper.",
        "score": 22.0,
    },
    {
        "id": "archive_bomb_hint",
        "name": "Podejrzane archiwum (bomba dekompresyjna)",
        "description": "Zadeklarowany rozmiar po rozpakowaniu drastycznie przewyższa rozmiar "
        "archiwum - próba wyczerpania zasobów skanera lub dysku.",
        "score": 24.0,
    },
)

#: ``{"id", "name", "description", "score"}`` for every rule - the GUI lists
#: these in its "Heurystyki" tab.
HEURISTIC_RULES: list[dict[str, Any]] = [dict(meta) for meta in _RULE_META]


# --------------------------------------------------------------------------
# public primitives
# --------------------------------------------------------------------------
def shannon_entropy(data: bytes) -> float:
    """Byte-level Shannon entropy of *data* in bits per byte (0.0 .. 8.0).

    0.0 for a single repeated byte, 8.0 for uniformly random bytes.  Compressed
    and encrypted content sits above ~7.9, English text around 4.5, source code
    around 5.
    """
    total = len(data)
    if total <= 1:
        return 0.0
    # Counter() uses the C _count_elements helper: roughly 30 ms per MiB, which
    # is about four times faster than 256 passes of bytes.count().
    histogram = Counter(data)
    entropy = 0.0
    for count in histogram.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def detect_file_type(data: bytes) -> str:
    """Classify *data* by magic bytes / shape.

    Returns one of ``"pe"``, ``"elf"``, ``"macho"``, ``"zip"``, ``"ole"``,
    ``"pdf"``, ``"script"``, ``"text"``, ``"data"``.
    """
    if not data:
        return "data"
    head = data[:_HEAD]
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if head[:5] == b"%PDF-" or head[:4] == b"%PDF":
        return "pdf"
    if _is_texty(head):
        text = _decode_head(head)
        if _looks_like_script(text):
            return "script"
        return "text"
    return "data"


def analyze(
    path: str | Path | None,
    data: bytes,
    *,
    config: Config | None = None,
) -> list[Detection]:
    """Run every heuristic rule over one file.

    *path* is only used for name-based rules and may be ``None`` (archive
    members, in-memory buffers).  *data* is the file content - already capped
    by the scanner.
    """
    facts = _FileFacts(data=bytes(data), path=str(path) if path is not None else None, config=config)
    out: list[Detection] = []
    for rule in _RULES:
        try:
            found = rule(facts)
        except Exception:  # noqa: BLE001 - one broken rule must not kill the scan
            continue
        if found:
            out.extend(found)
    return out


# --------------------------------------------------------------------------
# shared, lazily computed facts
# --------------------------------------------------------------------------
@dataclass
class _Section:
    name: str
    raw_name: bytes
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_pointer: int
    characteristics: int

    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_WRITE = 0x80000000

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & self.IMAGE_SCN_MEM_WRITE)

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & self.IMAGE_SCN_MEM_EXECUTE)


@dataclass
class _PeInfo:
    pe_offset: int
    machine: int
    num_sections: int
    characteristics: int
    opt_magic: int
    entry_rva: int
    image_base: int
    sections: list[_Section] = field(default_factory=list)
    import_rva: int = 0
    import_size: int = 0
    import_dlls: int = 0
    is_dotnet: bool = False
    truncated: bool = False

    @property
    def is_dll(self) -> bool:
        return bool(self.characteristics & 0x2000)


@dataclass
class _FileFacts:
    """Everything the rules need, each computed at most once."""

    data: bytes
    path: str | None = None
    config: Config | None = None

    # -- cheap ---------------------------------------------------------
    @cached_property
    def size(self) -> int:
        return len(self.data)

    @cached_property
    def head(self) -> bytes:
        return self.data[:_HEAD]

    @cached_property
    def name(self) -> str:
        return os.path.basename(self.path) if self.path else ""

    @cached_property
    def lower_name(self) -> str:
        return self.name.lower()

    @cached_property
    def extension(self) -> str:
        _, _, ext = self.lower_name.rpartition(".")
        return ext if "." in self.lower_name else ""

    @cached_property
    def file_type(self) -> str:
        return detect_file_type(self.data)

    # -- entropy -------------------------------------------------------
    @cached_property
    def entropy(self) -> float:
        """Whole-file entropy, computed on a bounded sample of big files."""
        if self.size <= _ENTROPY_SAMPLE:
            return shannon_entropy(self.data)
        third = _ENTROPY_SAMPLE // 3
        middle = (self.size - third) // 2
        sample = self.data[:third] + self.data[middle : middle + third] + self.data[-third:]
        return shannon_entropy(sample)

    @cached_property
    def window_entropies(self) -> list[tuple[int, float]]:
        """``(offset, entropy)`` for up to :data:`_MAX_WINDOWS` windows."""
        if self.size < _WINDOW_SIZE * 2:
            return []
        count = self.size // _WINDOW_SIZE
        step = max(1, count // _MAX_WINDOWS)
        out: list[tuple[int, float]] = []
        for index in range(0, count, step):
            offset = index * _WINDOW_SIZE
            out.append((offset, shannon_entropy(self.data[offset : offset + _WINDOW_SIZE])))
        return out

    # -- text ----------------------------------------------------------
    @cached_property
    def printable_ratio(self) -> float:
        sample = self.data[: 1 << 20]
        if not sample:
            return 1.0
        printable = sum(sample.count(b) for b in _PRINTABLE_BYTES)
        return printable / len(sample)

    @cached_property
    def is_texty(self) -> bool:
        return self.file_type in ("text", "script") or _is_texty(self.head)

    @cached_property
    def text(self) -> str:
        """Best-effort decoding, used by the script rules."""
        return _decode_head(self.data[: 4 << 20])

    @cached_property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    @cached_property
    def lowered(self) -> bytes:
        """ASCII-lowercased copy of the buffer.

        Lowercasing the raw bytes also lowercases UTF-16LE text (where ASCII
        characters are ``c`` followed by ``\\x00``), so one buffer serves both
        the ASCII and the UTF-16LE string search.
        """
        return self.data.lower()

    # -- containers ----------------------------------------------------
    @cached_property
    def pe(self) -> _PeInfo | None:
        return _parse_pe(self.data)

    @cached_property
    def zip_entries(self) -> list[zipfile.ZipInfo]:
        if self.file_type != "zip":
            return []
        try:
            with zipfile.ZipFile(io.BytesIO(self.data)) as zf:
                return list(zf.infolist())
        except (zipfile.BadZipFile, OSError, ValueError, EOFError):
            return []

    # -- helpers -------------------------------------------------------
    def contains(self, needle: str) -> bool:
        """Case-insensitive search for *needle* in ASCII **and** UTF-16LE."""
        low = needle.lower()
        blob = self.lowered
        if low.encode("utf-8", "ignore") in blob:
            return True
        return low.encode("utf-16-le", "ignore") in blob

    def detection(
        self,
        rule: str,
        threat_name: str,
        score: float,
        confidence: float,
        detail: str,
    ) -> Detection:
        return Detection(
            layer=DetectionLayer.HEURISTIC,
            rule=rule,
            threat_name=threat_name,
            score=max(_WEAK, min(_STRONG, score)),
            confidence=confidence,
            detail=detail,
            path=self.path,
        )


_PRINTABLE_BYTES = bytes(range(0x20, 0x7F)) + b"\t\n\r\f\v"


def _is_texty(head: bytes) -> bool:
    if not head:
        return False
    if head[:2] in (b"\xff\xfe", b"\xfe\xff") or head[:3] == b"\xef\xbb\xbf":
        return True
    if b"\x00" in head[:512] and head[:2] not in (b"\xff\xfe", b"\xfe\xff"):
        return False
    printable = sum(head.count(b) for b in _PRINTABLE_BYTES)
    return printable / len(head) >= 0.90


def _decode_head(data: bytes) -> str:
    for encoding in ("utf-8", "utf-16"):
        try:
            if encoding == "utf-16" and data[:2] not in (b"\xff\xfe", b"\xfe\xff"):
                continue
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", "replace")


_SCRIPT_MARKERS = (
    "#!", "<?php", "<script", "function ", "function(", "=>", "var ", "const ",
    "import ", "from ", "def ", "class ", "powershell", "param(", "echo ",
    "$(", "#include", "sub ", "dim ", "set ", "@echo", "if(", "if (", "require(",
)


def _looks_like_script(text: str) -> bool:
    low = text[:4096].lower()
    if low.startswith("#!"):
        return True
    return sum(1 for marker in _SCRIPT_MARKERS if marker in low) >= 2


# --------------------------------------------------------------------------
# PE parsing (struct only, no third-party dependency)
# --------------------------------------------------------------------------
def _parse_pe(data: bytes) -> _PeInfo | None:
    """Parse just enough of a PE header to reason about it.

    Returns ``None`` when *data* is not a PE at all.  A PE that is damaged or
    truncated is still returned, with ``truncated=True`` - a broken header is
    itself interesting.
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew <= 0 or e_lfanew + 24 > len(data):
        return None
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None

    coff = e_lfanew + 4
    machine, num_sections, _stamp, _symtab, _symcount, size_of_opt, characteristics = (
        struct.unpack_from("<HHIIIHH", data, coff)
    )
    opt = coff + 20
    info = _PeInfo(
        pe_offset=e_lfanew,
        machine=machine,
        num_sections=num_sections,
        characteristics=characteristics,
        opt_magic=0,
        entry_rva=0,
        image_base=0,
    )
    if opt + 2 > len(data) or size_of_opt == 0:
        info.truncated = True
        return info

    (info.opt_magic,) = struct.unpack_from("<H", data, opt)
    plus = info.opt_magic == 0x20B
    try:
        (info.entry_rva,) = struct.unpack_from("<I", data, opt + 16)
        if plus:
            (info.image_base,) = struct.unpack_from("<Q", data, opt + 24)
            dir_start = opt + 112
        else:
            (info.image_base,) = struct.unpack_from("<I", data, opt + 28)
            dir_start = opt + 96
        # Data directory 1 = imports, 14 = CLR header (.NET).
        if dir_start + 16 <= len(data):
            info.import_rva, info.import_size = struct.unpack_from("<II", data, dir_start + 8)
        if dir_start + 120 <= len(data):
            clr_rva, clr_size = struct.unpack_from("<II", data, dir_start + 112)
            info.is_dotnet = bool(clr_rva and clr_size)
    except struct.error:  # pragma: no cover - guarded by the length checks
        info.truncated = True

    table = opt + size_of_opt
    for index in range(min(num_sections, 96)):
        entry = table + index * 40
        if entry + 40 > len(data):
            info.truncated = True
            break
        raw_name = data[entry : entry + 8]
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, entry + 8)
        (chars,) = struct.unpack_from("<I", data, entry + 36)
        info.sections.append(
            _Section(
                name=raw_name.rstrip(b"\x00").decode("latin-1"),
                raw_name=raw_name,
                virtual_size=vsize,
                virtual_address=vaddr,
                raw_size=raw_size,
                raw_pointer=raw_ptr,
                characteristics=chars,
            )
        )
    if len(info.sections) < num_sections:
        info.truncated = True
    info.import_dlls = _count_import_dlls(data, info)
    return info


def _rva_to_offset(info: _PeInfo, rva: int) -> int | None:
    for section in info.sections:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva < section.virtual_address + max(span, 1):
            delta = rva - section.virtual_address
            if delta < section.raw_size:
                return section.raw_pointer + delta
            return None
    return None


def _count_import_dlls(data: bytes, info: _PeInfo) -> int:
    """Number of IMAGE_IMPORT_DESCRIPTOR entries that name a DLL."""
    if not info.import_rva:
        return 0
    offset = _rva_to_offset(info, info.import_rva)
    if offset is None:
        return 0
    count = 0
    for index in range(256):  # no real binary imports from 256 DLLs
        entry = offset + index * 20
        if entry + 20 > len(data):
            break
        chunk = data[entry : entry + 20]
        if chunk == b"\x00" * 20:
            break
        name_rva = struct.unpack_from("<I", chunk, 12)[0]
        if name_rva:
            count += 1
    return count


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------
def _rule_eicar(facts: _FileFacts) -> list[Detection]:
    if _EICAR not in facts.data:
        return []
    offset = facts.data.find(_EICAR)
    return [
        facts.detection(
            "eicar",
            "Sim.Eicar.TestFile",
            _STRONG,
            1.0,
            f"Wykryto standardowy ciąg testowy EICAR na pozycji {offset} "
            "(plik nieszkodliwy, służy do sprawdzenia skanera).",
        )
    ]


def _rule_high_entropy(facts: _FileFacts) -> list[Detection]:
    kind = facts.file_type
    # Archives, media and PDFs are legitimately high-entropy: skip them or the
    # rule becomes a false-positive generator.
    if kind in ("zip", "pdf") or facts.size < 1024:
        return []
    if _looks_compressed(facts.head):
        return []

    whole = facts.entropy
    if kind in ("pe", "elf", "macho") and whole >= ENTROPY_PACKED:
        return [
            facts.detection(
                "high_entropy",
                "Heur.Packed.HighEntropy",
                28.0,
                0.8,
                f"Entropia całego pliku wykonywalnego to {whole:.2f}/8.00 "
                f"(próg {ENTROPY_PACKED}) - plik jest najpewniej upakowany lub zaszyfrowany.",
            )
        ]

    if whole >= ENTROPY_CALM:
        return []
    windows = facts.window_entropies
    if not windows:
        return []
    hot = [(off, ent) for off, ent in windows if ent >= ENTROPY_WINDOW]
    if not hot or len(hot) / len(windows) < 0.08:
        return []
    first = hot[0]
    return [
        facts.detection(
            "high_entropy",
            "Heur.Packed.EncryptedBlob",
            22.0,
            0.6,
            f"Spokojny plik (entropia {whole:.2f}) zawiera {len(hot)} "
            f"wysokoentropijnych fragmentów, pierwszy na pozycji {first[0]} "
            f"(entropia {first[1]:.2f}) - możliwy ukryty, zaszyfrowany ładunek.",
        )
    ]


_COMPRESSED_MAGIC = (
    b"\x1f\x8b", b"BZh", b"\xfd7zXZ", b"Rar!", b"7z\xbc\xaf\x27\x1c",
    b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF", b"OggS", b"fLaC",
    b"\x00\x00\x01\xba", b"\x00\x00\x01\xb3", b"ID3", b"\x28\xb5\x2f\xfd",
)


def _looks_compressed(head: bytes) -> bool:
    return any(head.startswith(magic) for magic in _COMPRESSED_MAGIC)


def _rule_pe_anomaly(facts: _FileFacts) -> list[Detection]:
    info = facts.pe
    if info is None:
        return []
    problems: list[str] = []

    if info.truncated:
        problems.append("nagłówek PE jest niekompletny lub uszkodzony")
    if not info.sections:
        problems.append("brak tablicy sekcji")

    if info.import_rva == 0 or info.import_dlls == 0:
        problems.append("brak tablicy importów (API rozwiązywane dynamicznie)")
    elif info.import_dlls == 1 and not info.is_dotnet:
        problems.append(f"tylko {info.import_dlls} importowana biblioteka")

    for section in info.sections:
        lowered = section.name.lower()
        if lowered in (".text", "code", ".code") and section.writable:
            problems.append(f"sekcja kodu {section.name} jest zapisywalna")
        if section.virtual_size > 0 and section.raw_size == 0:
            problems.append(f"sekcja {section.name or '<bez nazwy>'} ma zerowy rozmiar na dysku")
        if lowered in _PACKER_SECTIONS:
            problems.append(f"nazwa sekcji {section.name} jest typowa dla packera")
        elif section.raw_name and not _plausible_section_name(section.raw_name):
            problems.append(f"losowa/niepoprawna nazwa sekcji {section.raw_name!r}")

    if info.sections and info.entry_rva:
        inside = any(
            s.virtual_address <= info.entry_rva
            < s.virtual_address + max(s.virtual_size, s.raw_size, 1)
            for s in info.sections
        )
        if not inside:
            problems.append(f"punkt wejścia 0x{info.entry_rva:x} leży poza wszystkimi sekcjami")
    elif info.sections and not info.entry_rva and not info.is_dll:
        problems.append("zerowy punkt wejścia w pliku, który nie jest biblioteką DLL")

    if not problems:
        return []
    # Deduplicate while keeping order - several sections can raise the same note.
    unique: list[str] = []
    for item in problems:
        if item not in unique:
            unique.append(item)

    score, confidence = _scale(len(unique), (16.0, 0.6), (22.0, 0.75), (27.0, 0.85), (30.0, 0.95))
    return [
        facts.detection(
            "pe_anomaly",
            "Heur.PE.Anomaly",
            score,
            confidence,
            f"Struktura PE odbiega od normy ({len(unique)}): " + "; ".join(unique[:6]) + ".",
        )
    ]


def _plausible_section_name(raw: bytes) -> bool:
    name = raw.rstrip(b"\x00")
    if not name:
        return False
    return all(0x20 <= byte < 0x7F for byte in name)


def _rule_suspicious_api_strings(facts: _FileFacts) -> list[Detection]:
    hits: dict[str, list[str]] = {}
    for category, needles in SUSPICIOUS_API_CATEGORIES.items():
        for needle in needles:
            if facts.contains(needle):
                hits.setdefault(category, []).append(needle)
    if not hits:
        return []
    score, confidence = _scale(
        len(hits), (12.0, 0.5), (18.0, 0.7), (24.0, 0.85), (28.0, 0.95), (_STRONG, 1.0)
    )
    summary = "; ".join(
        f"{category}: {', '.join(sorted(found)[:3])}" for category, found in list(hits.items())[:4]
    )
    return [
        facts.detection(
            "suspicious_api_strings",
            "Heur.Suspicious.ApiStrings",
            score,
            confidence,
            f"Podejrzane ciągi znaków w {len(hits)} kategoriach - {summary}.",
        )
    ]


_RE_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{240,}={0,2}")
_RE_HEX_BLOB = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{240,}(?![0-9A-Za-z])")
_RE_CHARCODE = re.compile(r"(?:chr|chrw|fromcharcode|char)\s*\(", re.IGNORECASE)
_RE_ESCAPES = re.compile(r"\\x[0-9a-fA-F]{2}|%[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}")
_DECODE_EXEC = (
    "eval(atob(", "eval(base64", "exec(base64", "eval(unescape(", "eval(decode",
    "exec(compile(", "frombase64string", "invoke-expression", "iex(", "iex (",
    "eval(gzinflate(", "eval(str_rot13(", "exec(__import__", "settimeout(atob",
    "new function(", "wscript.shell", "document.write(unescape(",
)


def _blob_like(match: "re.Match[str] | None", distinct: int) -> bool:
    """True when *match* is a real encoded blob, not a long run of filler.

    ``"A" * 4000`` matches the base64 character class but carries no payload;
    requiring a minimum alphabet keeps padding and ASCII art out of the rule.
    """
    if match is None:
        return False
    return len(set(match.group(0))) >= distinct


def _rule_script_obfuscation(facts: _FileFacts) -> list[Detection]:
    # Only genuine text/script files.  PDFs, OLE documents and PE files are
    # binary by nature: running the "long line / non-printable" signals on them
    # would flag half the disk.
    if facts.file_type not in ("script", "text"):
        return []
    if facts.size < 64:
        return []
    text = facts.text
    low = text.lower()
    signals: list[str] = []

    if _blob_like(_RE_BASE64_BLOB.search(text), 16):
        signals.append("długi blok base64")
    elif _blob_like(_RE_HEX_BLOB.search(text), 8):
        # A hex blob also matches the base64 character class, so only one of the
        # two ever counts - otherwise a single blob would score twice.
        signals.append("długi blok szesnastkowy")
    found_exec = [needle for needle in _DECODE_EXEC if needle in low]
    if found_exec:
        signals.append(f"wykonanie zdekodowanego kodu ({found_exec[0]})")
    if len(_RE_CHARCODE.findall(text)) >= 12 or len(_RE_ESCAPES.findall(text)) >= 80:
        signals.append("budowanie tekstu z kodów znaków / sekwencji ucieczki")
    longest = max((len(line) for line in facts.lines), default=0)
    if longest >= 2000:
        signals.append(f"bardzo długa linia ({longest} znaków)")
    if facts.printable_ratio < 0.85:
        signals.append(f"tylko {facts.printable_ratio * 100:.0f}% znaków drukowalnych")

    if not signals:
        return []
    score, confidence = _scale(
        len(signals), (12.0, 0.5), (18.0, 0.7), (24.0, 0.85), (_STRONG, 0.95)
    )
    return [
        facts.detection(
            "script_obfuscation",
            "Heur.Script.Obfuscated",
            score,
            confidence,
            f"Skrypt wygląda na zaciemniony ({len(signals)} przesłanek): "
            + "; ".join(signals)
            + ".",
        )
    ]


_MACRO_FREE_OOXML = ("docx", "xlsx", "pptx", "dotx", "xltx", "potx")


def _rule_office_macro(facts: _FileFacts) -> list[Detection]:
    kind = facts.file_type

    if kind == "zip":
        names = [entry.filename.lower() for entry in facts.zip_entries]
        macro_parts = [n for n in names if n.endswith("vbaproject.bin") or "/vbaproject" in n]
        if not macro_parts:
            return []
        mismatch = facts.extension in _MACRO_FREE_OOXML
        detail = (
            f"Dokument OOXML zawiera projekt VBA ({macro_parts[0]})."
            if not mismatch
            else f"Plik o rozszerzeniu .{facts.extension} nie powinien zawierać makr, "
            f"a zawiera {macro_parts[0]} - rozszerzenie wprowadza w błąd."
        )
        return [
            facts.detection(
                "office_macro",
                "Heur.Office.Macro",
                _STRONG if mismatch else 28.0,
                0.95 if mismatch else 0.8,
                detail,
            )
        ]

    if kind == "ole":
        # Deliberately *not* a bare "VBA": that substring shows up in plenty of
        # macro-free documents.  These four mean a real VBA project.
        markers = [
            m
            for m in ("_VBA_PROJECT", "vbaProject", "Macros", "ThisDocument")
            if facts.contains(m)
        ]
        if not markers:
            return []
        return [
            facts.detection(
                "office_macro",
                "Heur.Office.Macro",
                28.0,
                0.8,
                "Dokument OLE (starszy format Office) zawiera strumienie makr: "
                + ", ".join(markers)
                + ".",
            )
        ]

    head_low = facts.head.lower()
    if head_low.lstrip()[:5] == b"{\\rtf":
        markers = [m for m in (rb"\objdata", b"objupdate", rb"\objocx", rb"\objemb") if m in facts.lowered]
        if markers:
            return [
                facts.detection(
                    "office_macro",
                    "Heur.Office.RtfObject",
                    26.0,
                    0.75,
                    "Dokument RTF zawiera osadzony obiekt OLE ("
                    + ", ".join(m.decode("latin-1") for m in markers)
                    + ") - typowy nośnik exploitów.",
                )
            ]
    return []


def _rule_double_extension(facts: _FileFacts) -> list[Detection]:
    if not facts.name:
        return []
    out: list[Detection] = []

    bad_chars = [ch for ch in facts.name if ch in _RTL_CHARS]
    if bad_chars:
        codes = ", ".join(f"U+{ord(ch):04X}" for ch in dict.fromkeys(bad_chars))
        out.append(
            facts.detection(
                "double_extension",
                "Heur.Name.RtlOverride",
                _WEAK,
                0.95,
                f"Nazwa pliku zawiera znaki sterujące kierunkiem tekstu ({codes}) - "
                "prawdziwe rozszerzenie jest ukryte przed użytkownikiem.",
            )
        )

    parts = facts.lower_name.split(".")
    if len(parts) >= 3 and parts[-1] in _EXEC_EXTENSIONS and parts[-2] in _DECOY_EXTENSIONS:
        out.append(
            facts.detection(
                "double_extension",
                "Heur.Name.DoubleExtension",
                _WEAK,
                0.85,
                f"Podwójne rozszerzenie: plik udaje .{parts[-2]}, a jest .{parts[-1]}.",
            )
        )
    elif parts[-1] in _EXEC_EXTENSIONS and any(word in facts.lower_name for word in _DECOY_WORDS):
        out.append(
            facts.detection(
                "double_extension",
                "Heur.Name.DecoyName",
                _WEAK,
                0.5,
                f"Program (.{parts[-1]}) o nazwie typowej dla dokumentu lub przesyłki: "
                f"{facts.name}.",
            )
        )
    return out


def _rule_embedded_executable(facts: _FileFacts) -> list[Detection]:
    kind = facts.file_type
    # Archive members are scanned separately by the scanner, so an exe inside a
    # zip is not reported here (it would double-count and annoy users).
    if kind in ("pe", "elf", "macho", "zip") or facts.size < 4096:
        return []

    found: list[str] = []
    probes = 0
    position = facts.data.find(b"MZ", 2048)
    while position != -1 and len(found) < 3 and probes < 2000:
        probes += 1
        if _looks_like_pe_at(facts.data, position):
            found.append(f"nagłówek MZ/PE na pozycji {position}")
        position = facts.data.find(b"MZ", position + 2)

    position = facts.data.find(b"\x7fELF", 1024)
    while position != -1 and len(found) < 4:
        if facts.data[position + 4 : position + 5] in (b"\x01", b"\x02") and facts.data[
            position + 5 : position + 6
        ] in (b"\x01", b"\x02"):
            found.append(f"nagłówek ELF na pozycji {position}")
        position = facts.data.find(b"\x7fELF", position + 4)

    if not found:
        return []
    return [
        facts.detection(
            "embedded_executable",
            "Heur.Embedded.Executable",
            22.0,
            0.7,
            f"Plik typu '{kind}' zawiera osadzony program: " + "; ".join(found) + ".",
        )
    ]


def _looks_like_pe_at(data: bytes, offset: int) -> bool:
    if offset + 0x40 > len(data):
        return False
    try:
        (e_lfanew,) = struct.unpack_from("<I", data, offset + 0x3C)
    except struct.error:  # pragma: no cover
        return False
    pe = offset + e_lfanew
    if e_lfanew <= 0 or e_lfanew > 0x1000 or pe + 4 > len(data):
        return False
    return data[pe : pe + 4] == b"PE\x00\x00"


def _rule_archive_bomb(facts: _FileFacts) -> list[Detection]:
    entries = facts.zip_entries
    if not entries:
        return []
    uncompressed = sum(max(0, entry.file_size) for entry in entries)
    compressed = sum(max(0, entry.compress_size) for entry in entries) or 1
    ratio = uncompressed / compressed
    limit = (
        facts.config.archive_max_uncompressed
        if facts.config is not None
        else 256 * 1024 * 1024
    )

    reasons: list[str] = []
    if uncompressed > 10 * 1024 * 1024 and ratio >= 100:
        reasons.append(
            f"{len(entries)} wpisów rozpakuje się do {uncompressed / 1048576:.1f} MiB "
            f"z {compressed / 1024:.1f} KiB (współczynnik {ratio:.0f}:1)"
        )
    if uncompressed > limit:
        reasons.append(
            f"zadeklarowany rozmiar po rozpakowaniu ({uncompressed / 1048576:.1f} MiB) "
            f"przekracza limit skanera ({limit / 1048576:.0f} MiB)"
        )
    if not reasons:
        return []
    return [
        facts.detection(
            "archive_bomb_hint",
            "Heur.Archive.Bomb",
            24.0,
            0.8,
            "Archiwum wygląda na bombę dekompresyjną: " + "; ".join(reasons) + ".",
        )
    ]


def _scale(
    count: int,
    *levels: tuple[float, float],
) -> tuple[float, float]:
    """Pick ``(score, confidence)`` for *count* signals from an escalating table."""
    index = min(max(count, 1), len(levels)) - 1
    return levels[index]


#: Rule execution order.  Cheap and certain rules go first so a hit is visible
#: in the log immediately, but every rule always runs: the fusion engine wants
#: all of the evidence.
_RULES: tuple[Callable[[_FileFacts], list[Detection]], ...] = (
    _rule_eicar,
    _rule_pe_anomaly,
    _rule_high_entropy,
    _rule_suspicious_api_strings,
    _rule_script_obfuscation,
    _rule_office_macro,
    _rule_double_extension,
    _rule_embedded_executable,
    _rule_archive_bomb,
)
