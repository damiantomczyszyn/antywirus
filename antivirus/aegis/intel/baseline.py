"""The offline starter database that ships inside the repository.

A fresh install with no network must still detect *something*, otherwise the
product looks broken before the first update.  :func:`builtin_indicators`
builds that starter set and :func:`ensure_baseline` loads it into the database.

Contents
--------
1. **EICAR** - the industry-standard, completely inert test string: its
   SHA256/SHA1/MD5 plus a ``PATTERN`` for the string body, so the file is
   caught by hash *and* by content (e.g. when embedded in an archive member or
   appended to another file).
2. **Simulator markers** - the ``AEGIS-SIM-*`` strings that the behaviour
   simulator in ``malware-sim/`` embeds in its samples.  This is the agreed
   handshake between this database and those samples.
3. **Generic malicious-script patterns** - a small, deliberately specific set
   of one-liner shapes (shadow-copy wiping, hidden encoded PowerShell, bash
   reverse shell, download cradles).

Why the literals are assembled from fragments
---------------------------------------------
Every string in this module is a string the scanner is told to hunt for.  If
the literals appeared contiguously in this source file, Aegis would flag its
own source tree (and so would every other AV on the developer's machine).
:func:`_j` joins the fragments at runtime, so the searched-for bytes never
exist contiguously on disk here - only in memory, and in the hex-encoded
``PATTERN`` values of the generated JSON.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from ..models import Indicator, IndicatorKind, Severity

__all__ = [
    "builtin_indicators",
    "ensure_baseline",
    "baseline_path",
    "load_baseline_file",
    "generate_baseline_file",
    "BASELINE_VERSION",
    "BASELINE_GENERATED_AT",
    "SIM_MARKERS",
]

#: Bumped by hand whenever the baseline content changes.
BASELINE_VERSION = "2026.11.14.1"

#: Fixed, not ``time.time()``: the generated JSON must be byte-for-byte
#: reproducible so a regeneration shows up as "no diff" instead of churn.
BASELINE_GENERATED_AT = "2026-11-14T00:00:00Z"

#: Default file name of the shipped dump, next to this package.
BASELINE_FILENAME = "signatures_baseline.json"


def _j(*parts: str) -> str:
    """Join fragments so the searched-for literal never appears in this file."""
    return "".join(parts)


# --------------------------------------------------------------------------
# EICAR
# --------------------------------------------------------------------------
#: The canonical 68-byte EICAR anti-malware test string (inert by design).
EICAR_BODY: str = _j(
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
    "EICAR-STANDARD-",
    "ANTIVIRUS-TEST-FILE",
    "!$H+H*",
)
EICAR_BYTES: bytes = EICAR_BODY.encode("ascii")


def _eicar_hashes() -> dict[IndicatorKind, str]:
    """Hash the EICAR bytes through a real file on disk.

    Hashing the in-memory bytes would give the same answer, but going through
    a temporary file is the same code path the scanner uses, so a stray
    newline or encoding slip in :data:`EICAR_BODY` cannot silently produce a
    hash that no real file ever has.  The temp file lives in the OS temp
    directory and is removed immediately; nothing is written to the repository
    or to the user's data directory.
    """
    digests = {
        IndicatorKind.SHA256: hashlib.sha256(),
        IndicatorKind.SHA1: hashlib.sha1(),
        IndicatorKind.MD5: hashlib.md5(),
    }
    fd, tmp = tempfile.mkstemp(prefix="aegis-eicar-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(EICAR_BYTES)
        with open(tmp, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 16), b""):
                for digest in digests.values():
                    digest.update(chunk)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return {kind: digest.hexdigest() for kind, digest in digests.items()}


# --------------------------------------------------------------------------
# Simulator handshake
# --------------------------------------------------------------------------
#: ``marker -> (family, what the sample simulates)``.  Agent E embeds these
#: markers verbatim in ``malware-sim/`` samples; threat name ``Sim.<Family>.Marker``.
SIM_MARKERS: dict[str, tuple[str, str]] = {
    _j("AEGIS-SIM-", "PAYLOAD-MARKER"): ("Payload", "ogólny znacznik próbki symulatora"),
    _j("AEGIS-SIM-", "RANSOM-NOTE"): ("Ransom", "symulowana notatka okupu"),
    _j("AEGIS-SIM-", "BEACON"): ("Beacon", "symulowana komunikacja z serwerem C2"),
    _j("AEGIS-SIM-", "PERSISTENCE"): ("Persistence", "symulowane utrwalanie w autostarcie"),
    _j("AEGIS-SIM-", "EXFIL"): ("Exfil", "symulowana eksfiltracja danych"),
    _j("AEGIS-SIM-", "DROPPER"): ("Dropper", "symulowany dropper"),
}


# --------------------------------------------------------------------------
# Generic malicious-script shapes
# --------------------------------------------------------------------------
#: ``(literal, threat name, severity, description)``.
#:
#: Kept deliberately long and specific: a ``PATTERN`` hit is worth
#: ``SCORE_PATTERN_MATCH`` (75) on its own, which is already HIGH, so a short
#: or ambiguous pattern would be a false-positive machine.  Matching is
#: byte-exact (``match_bytes`` has no case folding), so the casing below is the
#: one actually seen in the wild.
_SCRIPT_PATTERNS: tuple[tuple[str, str, Severity, str], ...] = (
    (
        _j("vssadmin delete ", "shadows"),
        "Generic.Script.ShadowCopyWipe",
        Severity.HIGH,
        "Usuwanie kopii w cieniu (Volume Shadow Copy) - typowe dla ransomware "
        "przed szyfrowaniem plików.",
    ),
    (
        _j("wbadmin delete ", "catalog"),
        "Generic.Script.BackupWipe",
        Severity.HIGH,
        "Niszczenie katalogu kopii zapasowych systemu Windows - typowe dla "
        "ransomware.",
    ),
    (
        _j("powershell -nop -w ", "hidden -enc "),
        "Generic.Script.HiddenEncodedPowerShell",
        Severity.HIGH,
        "Ukryty PowerShell z poleceniem zakodowanym w Base64 - klasyczny "
        "sposób uruchamiania złośliwego kodu bez okna.",
    ),
    (
        _j("-WindowStyle Hidden ", "-EncodedCommand "),
        "Generic.Script.HiddenEncodedPowerShell",
        Severity.HIGH,
        "Ukryte okno PowerShell z zakodowanym poleceniem - wariant pisany "
        "pełnymi nazwami parametrów.",
    ),
    (
        _j(">& /dev/", "tcp/"),
        "Generic.Script.ReverseShell",
        Severity.HIGH,
        "Odwrotna powłoka w Bash (przekierowanie deskryptorów do /dev/tcp) - "
        "daje atakującemu zdalny dostęp do powłoki.",
    ),
    (
        _j("IEX(New-Object Net.", "WebClient).DownloadString("),
        "Generic.Script.DownloadCradle",
        Severity.HIGH,
        "Pobranie i natychmiastowe uruchomienie skryptu z sieci "
        "(download cradle) - typowy pierwszy etap infekcji.",
    ),
    (
        _j("IEX (New-Object Net.", "WebClient).DownloadString("),
        "Generic.Script.DownloadCradle",
        Severity.HIGH,
        "Pobranie i natychmiastowe uruchomienie skryptu z sieci "
        "(download cradle), wariant ze spacją.",
    ),
    (
        _j("GetString([System.Convert]::", "FromBase64String("),
        "Generic.Script.Base64Payload",
        Severity.MEDIUM,
        "Dekodowanie ładunku z Base64 w pamięci - w połączeniu z IEX oznacza "
        "bezplikowe uruchomienie kodu.",
    ),
)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def builtin_indicators() -> list[Indicator]:
    """Build the shipped starter database.

    Deterministic and side-effect free apart from one short-lived temporary
    file used to hash EICAR.  ``added_at`` is left at ``0.0`` so the generated
    JSON is reproducible.
    """
    out: list[Indicator] = []

    # 1. EICAR, by hash and by content.
    hashes = _eicar_hashes()
    for kind, value in hashes.items():
        out.append(
            Indicator(
                kind=kind,
                value=value,
                name="EICAR.Test.File",
                severity=Severity.HIGH,
                source="builtin",
                tags=("eicar", "test-file", "baseline"),
                description=(
                    "Standardowy ciąg testowy EICAR - całkowicie nieszkodliwy "
                    "plik używany w całej branży do sprawdzania, czy antywirus "
                    f"działa (skrót {kind.value})."
                ),
            )
        )
    out.append(
        Indicator(
            kind=IndicatorKind.PATTERN,
            value=Indicator.pattern_from_text(EICAR_BODY),
            name="EICAR.Test.File",
            severity=Severity.HIGH,
            source="builtin",
            tags=("eicar", "test-file", "baseline", "content"),
            description=(
                "Treść ciągu testowego EICAR wykryta w zawartości pliku - "
                "łapie go także wtedy, gdy jest osadzony w archiwum lub "
                "dopisany do innego pliku."
            ),
        )
    )

    # 2. Simulator markers (handshake with malware-sim/).
    for marker, (family, what) in SIM_MARKERS.items():
        out.append(
            Indicator(
                kind=IndicatorKind.PATTERN,
                value=Indicator.pattern_from_text(marker),
                name=f"Sim.{family}.Marker",
                severity=Severity.HIGH,
                source="builtin",
                tags=("simulator", "baseline", family.lower()),
                description=(
                    f"Znacznik próbki symulatora Aegis ({what}). Próbka jest "
                    "atrapą - nie wykonuje żadnych szkodliwych działań."
                ),
            )
        )

    # 3. Generic malicious-script shapes.
    for literal, name, severity, description in _SCRIPT_PATTERNS:
        out.append(
            Indicator(
                kind=IndicatorKind.PATTERN,
                value=Indicator.pattern_from_text(literal),
                name=name,
                severity=severity,
                source="builtin",
                tags=("script", "generic", "baseline"),
                description=description,
            )
        )

    return out


def ensure_baseline(db: Any) -> int:
    """Load the starter database into *db*; returns how many rows were new.

    Idempotent: the second call adds 0 because ``(kind, value)`` is the primary
    key of the signature store.
    """
    indicators = builtin_indicators()
    if not indicators:
        return 0
    added, _updated = db.add_many(indicators)
    return int(added)


# --------------------------------------------------------------------------
# The shipped JSON dump
# --------------------------------------------------------------------------
def baseline_path() -> Path:
    """Path of the JSON dump shipped inside the package."""
    return Path(__file__).resolve().parent.parent / "data" / BASELINE_FILENAME


def baseline_document() -> dict[str, Any]:
    """The exact document written to :func:`baseline_path`."""
    return {
        "version": BASELINE_VERSION,
        "generated_at": BASELINE_GENERATED_AT,
        "indicators": [indicator.to_dict() for indicator in builtin_indicators()],
    }


def _serialise(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def load_baseline_file(path: str | os.PathLike[str] | None = None) -> list[Indicator]:
    """Read indicators back from a dump; returns ``[]`` if it is missing/broken."""
    target = Path(path) if path is not None else baseline_path()
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    rows = document.get("indicators") if isinstance(document, dict) else document
    if not isinstance(rows, list):
        return []
    out: list[Indicator] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            out.append(Indicator.from_dict(row))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def generate_baseline_file(path: str | os.PathLike[str] | None = None) -> Path:
    """Write the reproducible JSON dump; returns the path written.

    Run it after changing the baseline content, from ``antivirus/``::

        python3 -m aegis.intel.baseline

    (``runpy`` prints a harmless RuntimeWarning because ``aegis.intel``
    re-exports this module eagerly; the file is still written correctly.)
    """
    target = Path(path) if path is not None else baseline_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = _serialise(baseline_document())
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".baseline-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
        # mkstemp creates 0600; this dump ships in the repository and is read
        # by every install, so it must not be private to the generating user.
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return target


def main() -> int:  # pragma: no cover - developer entry point
    """Regenerate the shipped JSON dump."""
    written = generate_baseline_file()
    document = baseline_document()
    print(f"{written}: {len(document['indicators'])} wskaźników, wersja {document['version']}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
