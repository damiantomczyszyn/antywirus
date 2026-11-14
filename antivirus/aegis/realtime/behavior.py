"""Runtime behaviour correlation - catching malware by what it does.

The static engine (``aegis.core``) answers "have we seen this file before?".
This module answers a different question: "is something on this machine acting
like malware *right now*?".  It never looks at a file's identity, only at the
stream of :class:`~aegis.models.BehaviorEvent` observations produced by
:mod:`aegis.realtime.watcher` (filesystem) and :mod:`aegis.realtime.procmon`
(processes and sockets).

State model
-----------
Observations are grouped per *actor*.  An actor is a pid, or the special
``pid=None`` bucket for events we could not attribute - which on Linux is the
normal case for filesystem events, since attributing them would need fanotify
with ``FAN_REPORT_PID`` or an audit rule.  Each actor keeps a set of
time-windowed deques (``config.behavior_window_sec``) that are pruned on every
:meth:`BehaviorEngine.observe`, so memory stays bounded no matter how long the
monitor runs or how hard a process hammers the disk.

False positives
---------------
A compiler, an installer, ``git clone`` and ``unzip`` all write hundreds of
files in a few seconds - exactly the shape of ransomware.  Four mitigations are
applied, in order of importance:

1. **Corroboration.** The bulk rules (``mass_file_modify``, ``mass_delete``,
   ``self_propagation``) are emitted with a *low confidence* when they fire
   alone, and their confidence is raised as other, far more specific rules
   (in-place entropy rewrites, a uniform unknown rename extension, a ransom
   note, shadow-copy tampering) corroborate them.  Bulk writes alone therefore
   top out at MEDIUM and can never trigger an automated response.
2. **Actor attribution.** Counters are per pid, so ten processes writing three
   files each never look like one process writing thirty.
3. **Name allowlist** (:data:`BENIGN_PROCESS_NAMES`, overridable with a
   ``behavior_allowlist`` attribute on the config) suppresses the *bulk* rules
   for build tools, package managers and archivers.  It deliberately does **not**
   suppress the specific rules: a process called ``gcc`` is not licensed to
   encrypt the home directory, and a name is trivially spoofed.
4. **Shape gates.** Entropy rewrites require a stable file size and ignore
   natively-compressed extensions; ransom-note matching ignores ``README.md``
   style developer documentation and needs either several directories or actual
   extortion language in the body.

Every rule also has a per-actor cooldown, so one rampage produces a handful of
detections instead of five hundred identical ones.
"""

from __future__ import annotations

import ipaddress
import math
import re
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..config import Config
from ..engine.verdict import apply_to_process_verdict
from ..events import EventBus, EventType
from ..models import (
    SCORE_BEHAVIOR_STRONG,
    SCORE_BEHAVIOR_WEAK,
    SCORE_INTEL_NETWORK,
    SEVERITY_ORDER,
    BehaviorEvent,
    BehaviorKind,
    Detection,
    DetectionLayer,
    Indicator,
    ProcessVerdict,
    Severity,
)

if TYPE_CHECKING:  # pragma: no cover - import cycle / optional dependency
    from ..core.signatures import SignatureDB

__all__ = [
    "BehaviorEngine",
    "BEHAVIOR_RULES",
    "BENIGN_PROCESS_NAMES",
    "RANSOM_NOTE_LANGUAGE",
    "parse_severity",
    "severity_at_least",
]


# --------------------------------------------------------------------------
# Rule catalogue
# --------------------------------------------------------------------------
RULE_MASS_FILE_MODIFY = "mass_file_modify"
RULE_ENCRYPT_IN_PLACE = "encrypt_in_place"
RULE_MASS_RENAME_EXTENSION = "mass_rename_extension"
RULE_RANSOM_NOTE = "ransom_note"
RULE_AUTOSTART_WRITE = "autostart_write"
RULE_SELF_PROPAGATION = "self_propagation"
RULE_MASS_DELETE = "mass_delete"
RULE_SHADOW_COPY_TAMPER = "shadow_copy_tamper"
RULE_BLOCKLISTED_CONNECTION = "blocklisted_connection"
RULE_BEACON_PATTERN = "beacon_pattern"
RULE_SCRIPT_SPAWN_CHAIN = "script_spawn_chain"
RULE_EXEC_FROM_TEMP = "exec_from_temp"

#: Scores sit inside ``SCORE_BEHAVIOR_WEAK..SCORE_BEHAVIOR_STRONG`` (18..55).
#: ``blocklisted_connection`` is the exception: its evidence comes from the
#: intel layer, so it carries ``SCORE_INTEL_NETWORK`` and
#: ``DetectionLayer.INTEL`` - which is what makes the cross-layer
#: corroboration bonus in :func:`aegis.engine.verdict.fuse` fire.
_SCORE_MEDIUM = 40.0
_SCORE_BULK_DELETE = 42.0
_SCORE_BEACON = 32.0
_SCORE_SPAWN_CHAIN = 30.0
_SCORE_AUTOSTART = 22.0
_SCORE_EXEC_TEMP = 20.0

BEHAVIOR_RULES: list[dict[str, Any]] = [
    {
        "id": RULE_MASS_FILE_MODIFY,
        "name": "Masowa modyfikacja plików",
        "description": (
            "Jeden proces zapisuje lub zmienia nazwy wielu plików w krótkim "
            "czasie - klasyczny kształt ransomware. Samodzielnie ma obniżoną "
            "pewność, bo tak samo wygląda kompilacja albo rozpakowanie archiwum."
        ),
        "score": SCORE_BEHAVIOR_STRONG,
    },
    {
        "id": RULE_ENCRYPT_IN_PLACE,
        "name": "Szyfrowanie plików w miejscu",
        "description": (
            "Istniejące pliki są nadpisywane treścią o bardzo wysokiej entropii "
            "przy zachowanym rozmiarze. Najsilniejsza przesłanka ransomware; "
            "wymaga kilku wystąpień."
        ),
        "score": SCORE_BEHAVIOR_STRONG,
    },
    {
        "id": RULE_MASS_RENAME_EXTENSION,
        "name": "Masowa zmiana rozszerzenia",
        "description": (
            "Wiele zmian nazw zbiegających się do jednego, nieznanego "
            "rozszerzenia (np. .locked, .encrypted) - podpis okupu na dysku."
        ),
        "score": SCORE_BEHAVIOR_STRONG,
    },
    {
        "id": RULE_RANSOM_NOTE,
        "name": "List z żądaniem okupu",
        "description": (
            "Pliki o nazwach typu READ_ME.txt, HOW_TO_DECRYPT.html tworzone w "
            "wielu katalogach albo plik zawierający język żądania okupu."
        ),
        "score": SCORE_BEHAVIOR_STRONG,
    },
    {
        "id": RULE_AUTOSTART_WRITE,
        "name": "Zapis do autostartu",
        "description": (
            "Modyfikacja lokalizacji autostartu (usługa systemd, cron, "
            "~/.config/autostart, rejestr Run, LaunchAgents). Sama w sobie "
            "słaba, zabójcza w połączeniu z innymi regułami."
        ),
        "score": _SCORE_AUTOSTART,
    },
    {
        "id": RULE_SELF_PROPAGATION,
        "name": "Samo-rozprzestrzenianie",
        "description": (
            "Ta sama treść (skrót) lub ta sama nazwa pliku zapisywana do kilku "
            "różnych katalogów - robak kopiujący się po dysku."
        ),
        "score": _SCORE_MEDIUM,
    },
    {
        "id": RULE_MASS_DELETE,
        "name": "Masowe usuwanie plików",
        "description": (
            "Hurtowe usuwanie plików przez jeden proces - wiper albo sprzątanie "
            "po szyfrowaniu oryginałów."
        ),
        "score": _SCORE_BULK_DELETE,
    },
    {
        "id": RULE_SHADOW_COPY_TAMPER,
        "name": "Niszczenie kopii zapasowych",
        "description": (
            "Polecenie usuwające kopie w tle lub wyłączające odzyskiwanie "
            "systemu (vssadmin delete shadows, wmic shadowcopy delete, "
            "bcdedit /set recoveryenabled no, wbadmin delete)."
        ),
        "score": SCORE_BEHAVIOR_STRONG,
    },
    {
        "id": RULE_BLOCKLISTED_CONNECTION,
        "name": "Połączenie z adresem z listy zagrożeń",
        "description": (
            "Proces łączy się z hostem, adresem IP lub URL-em obecnym w bazie "
            "wskaźników. Zgłaszane w warstwie intel, więc uruchamia premię za "
            "zgodność warstw."
        ),
        "score": SCORE_INTEL_NETWORK,
    },
    {
        "id": RULE_BEACON_PATTERN,
        "name": "Regularny sygnał do C2",
        "description": (
            "Powtarzalne połączenia wychodzące do tego samego hosta w "
            "podejrzanie równych odstępach - tak wygląda beaconing do serwera "
            "zarządzającego."
        ),
        "score": _SCORE_BEACON,
    },
    {
        "id": RULE_SCRIPT_SPAWN_CHAIN,
        "name": "Dokument uruchamia powłokę",
        "description": (
            "Proces pakietu biurowego lub hosta skryptów (winword, soffice, "
            "wscript, mshta) uruchamia powłokę albo interpreter - typowy "
            "łańcuch z makra w załączniku."
        ),
        "score": _SCORE_SPAWN_CHAIN,
    },
    {
        "id": RULE_EXEC_FROM_TEMP,
        "name": "Uruchomienie z katalogu tymczasowego",
        "description": (
            "Proces wystartował z katalogu tymczasowego lub z folderu pobranych "
            "plików. Samodzielnie poniżej progu alarmu."
        ),
        "score": _SCORE_EXEC_TEMP,
    },
]

_RULE_SCORES: dict[str, float] = {r["id"]: float(r["score"]) for r in BEHAVIOR_RULES}
_RULE_NAMES: dict[str, str] = {r["id"]: str(r["name"]) for r in BEHAVIOR_RULES}

#: ``Behav.<Rule>`` threat names, per the naming convention in the contract.
_THREAT_NAMES: dict[str, str] = {
    RULE_MASS_FILE_MODIFY: "Behav.MassFileModify",
    RULE_ENCRYPT_IN_PLACE: "Behav.EncryptInPlace",
    RULE_MASS_RENAME_EXTENSION: "Behav.MassRenameExtension",
    RULE_RANSOM_NOTE: "Behav.RansomNote",
    RULE_AUTOSTART_WRITE: "Behav.AutostartWrite",
    RULE_SELF_PROPAGATION: "Behav.SelfPropagation",
    RULE_MASS_DELETE: "Behav.MassDelete",
    RULE_SHADOW_COPY_TAMPER: "Behav.ShadowCopyTamper",
    RULE_BLOCKLISTED_CONNECTION: "Behav.BlocklistedConnection",
    RULE_BEACON_PATTERN: "Behav.BeaconPattern",
    RULE_SCRIPT_SPAWN_CHAIN: "Behav.ScriptSpawnChain",
    RULE_EXEC_FROM_TEMP: "Behav.ExecFromTemp",
}

#: Seconds before the same rule may fire again for the same actor.
_DEFAULT_COOLDOWN = 30.0
_RULE_COOLDOWN: dict[str, float] = {
    RULE_MASS_FILE_MODIFY: 30.0,
    RULE_ENCRYPT_IN_PLACE: 30.0,
    RULE_MASS_RENAME_EXTENSION: 30.0,
    RULE_RANSOM_NOTE: 60.0,
    RULE_AUTOSTART_WRITE: 60.0,
    RULE_SELF_PROPAGATION: 60.0,
    RULE_MASS_DELETE: 30.0,
    RULE_SHADOW_COPY_TAMPER: 120.0,
    RULE_BLOCKLISTED_CONNECTION: 60.0,
    RULE_BEACON_PATTERN: 120.0,
    RULE_SCRIPT_SPAWN_CHAIN: 60.0,
    RULE_EXEC_FROM_TEMP: 120.0,
}

#: Rules whose confidence grows with corroboration from the specific rules.
_CORROBORATION_SCALED = frozenset(
    {RULE_MASS_FILE_MODIFY, RULE_MASS_DELETE, RULE_SELF_PROPAGATION, RULE_AUTOSTART_WRITE}
)

#: Rules specific enough to corroborate a bulk rule.
_CORROBORATORS = frozenset(
    {
        RULE_ENCRYPT_IN_PLACE,
        RULE_MASS_RENAME_EXTENSION,
        RULE_RANSOM_NOTE,
        RULE_SHADOW_COPY_TAMPER,
        RULE_BLOCKLISTED_CONNECTION,
        RULE_SELF_PROPAGATION,
        RULE_AUTOSTART_WRITE,
    }
)

#: Rules the name allowlist is allowed to suppress.  Everything else stays
#: armed even for a "trusted" name, because the name proves nothing.
_ALLOWLISTABLE = frozenset(
    {
        RULE_MASS_FILE_MODIFY,
        RULE_MASS_DELETE,
        RULE_MASS_RENAME_EXTENSION,
        RULE_SELF_PROPAGATION,
        RULE_EXEC_FROM_TEMP,
        RULE_SCRIPT_SPAWN_CHAIN,
    }
)

# --------------------------------------------------------------------------
# Tunables that the frozen Config does not carry.  Each one is read from the
# config first (``getattr``), so a future Config field overrides it without a
# code change here.
# --------------------------------------------------------------------------
ENCRYPT_MIN_HITS = 3            # in-place entropy rewrites before firing
RENAME_EXT_MIN = 5              # renames converging on one extension
RENAME_EXT_SHARE = 0.75         # share of renames that must agree
NOTE_MIN_DIRS_STRONG = 2        # unambiguous note names (HOW_TO_DECRYPT...)
NOTE_MIN_DIRS_WEAK = 3          # ambiguous note names (READ_ME...)
NOTE_MIN_LANGUAGE_HITS = 2      # extortion phrases in the body
PROPAGATION_MIN_DIRS = 3
BEACON_MIN_SAMPLES = 5
BEACON_MIN_INTERVAL = 1.0       # seconds; faster than this is a burst, not a beacon
BEACON_MAX_CV = 0.25            # coefficient of variation of inter-arrival times
SIZE_STABLE_LOW = 0.75
SIZE_STABLE_HIGH = 1.35
SIZE_STABLE_SLACK = 512

_MAX_TRACKED = 4096             # per-deque cap, so one rampage cannot eat RAM
_MAX_ACTORS = 512
_MAX_DETECTIONS_PER_ACTOR = 32
_MAX_TOUCHED_PATHS = 256
_MAX_PATH_CACHE = 4096
_GC_EVERY = 256

#: Build tools, package managers and archivers: bulk file churn is their job.
BENIGN_PROCESS_NAMES: frozenset[str] = frozenset(
    {
        # compilers / build systems
        "gcc", "g++", "cc", "c++", "clang", "clang++", "ld", "as", "ar", "ranlib",
        "make", "gmake", "ninja", "cmake", "meson", "scons", "bazel", "msbuild",
        "rustc", "cargo", "go", "javac", "java", "gradle", "gradlew", "mvn",
        "dotnet", "tsc", "webpack", "esbuild", "rollup", "vite", "sphinx-build",
        # package managers
        "npm", "yarn", "pnpm", "pip", "pip3", "poetry", "uv", "conda", "mamba",
        "apt", "apt-get", "aptitude", "dpkg", "rpm", "dnf", "yum", "zypper",
        "pacman", "snap", "snapd", "flatpak", "brew", "nix", "nix-build",
        # version control / sync / archives
        "git", "git-lfs", "hg", "svn", "bzr", "rsync", "rclone", "cp", "mv",
        "tar", "zip", "unzip", "gzip", "gunzip", "bzip2", "xz", "zstd", "7z",
        "7za", "unrar", "rar", "cpio", "dd", "cabextract", "msiexec",
        # runtimes / editors / containers
        "python", "python3", "pytest", "node", "deno", "bun", "ruby", "perl",
        "php", "code", "codium", "vim", "nvim", "emacs", "subl", "idea",
        "docker", "dockerd", "containerd", "podman", "buildkitd", "runc",
        # system maintenance
        "systemd", "systemd-journald", "journalctl", "rsyslogd", "logrotate",
        "updatedb", "mandb", "fc-cache", "fontconfig", "ldconfig", "dracut",
        "mkinitramfs", "update-initramfs", "tracker-miner-fs", "baloo_file",
        # the product itself
        "aegis", "aegis-gui", "aegis-cli",
    }
)

#: Extensions whose content is high-entropy by nature, so a high-entropy
#: rewrite of one of them proves nothing.
_COMPRESSED_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".zst", ".lz4", ".tgz",
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".avif", ".bmp",
        ".mp3", ".mp4", ".m4a", ".mkv", ".avi", ".mov", ".webm", ".flac", ".ogg",
        ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub",
        ".jar", ".apk", ".whl", ".deb", ".rpm", ".iso", ".dmg", ".pack", ".crypt",
    }
)

#: Extensions that are common enough that converging on them is not a signal.
_COMMON_EXTENSIONS: frozenset[str] = frozenset(
    {
        "", ".txt", ".md", ".rst", ".log", ".json", ".xml", ".yaml", ".yml",
        ".csv", ".ini", ".cfg", ".conf", ".toml", ".html", ".htm", ".css",
        ".js", ".ts", ".tsx", ".jsx", ".py", ".pyc", ".pyo", ".c", ".h", ".cpp",
        ".hpp", ".cc", ".java", ".class", ".go", ".rs", ".rb", ".php", ".sh",
        ".o", ".obj", ".a", ".so", ".dll", ".exe", ".lib", ".d", ".gcda", ".gcno",
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf", ".odt",
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".mp3", ".mp4", ".zip",
        ".tar", ".gz", ".bak", ".tmp", ".temp", ".swp", ".part", ".crdownload",
        ".lock", ".pid", ".db", ".sqlite", ".bin", ".dat", ".map", ".ico",
    }
)

#: File extensions a ransom note plausibly uses (``README.md`` is developer
#: documentation, not extortion).
_NOTE_EXTENSIONS: frozenset[str] = frozenset(
    {"", ".txt", ".html", ".htm", ".hta", ".rtf", ".url", ".vbs", ".lnk", ".inf"}
)

#: Unambiguous ransom-note name shapes.
_NOTE_PATTERNS_STRONG: tuple[re.Pattern[str], ...] = (
    re.compile(r"decrypt"),
    re.compile(r"^how[\W_]{0,3}to"),
    re.compile(r"restore[\W_]{0,3}(my[\W_]{0,3})?files"),
    re.compile(r"recover[\W_]{0,3}(my[\W_]{0,3})?files"),
    re.compile(r"unlock[\W_]{0,3}(my[\W_]{0,3})?files"),
    re.compile(r"your[\W_]{0,3}files"),
    re.compile(r"ransom"),
    re.compile(r"odszyfr"),
    re.compile(r"okup"),
    re.compile(r"recovery[\W_]{0,3}(key|instruction)"),
)

#: Ambiguous shapes - ``README.txt`` lives in half the source trees on earth.
_NOTE_PATTERNS_WEAK: tuple[re.Pattern[str], ...] = (
    re.compile(r"read[\W_]{0,3}me"),
    re.compile(r"important[\W_]{0,3}(info|read)"),
    re.compile(r"attention"),
    re.compile(r"uwaga"),
)

#: Extortion language, English and Polish.  Two hits fire the rule.
RANSOM_NOTE_LANGUAGE: tuple[str, ...] = (
    "your files have been encrypted",
    "all your files",
    "have been encrypted",
    "files are encrypted",
    "pay the ransom",
    "bitcoin",
    "btc wallet",
    "monero",
    "decryption key",
    "decrypt your files",
    "private key",
    "tor browser",
    "onion",
    "do not rename",
    "contact us",
    "twoje pliki",
    "zostaly zaszyfrowane",
    "zostały zaszyfrowane",
    "zaszyfrowane",
    "odszyfrowanie",
    "klucz prywatny",
    "zaplac",
    "zapłać",
    "okup",
)

#: Shadow-copy / backup destruction.  Each entry is a set of substrings that
#: must all be present in the normalised command line.
_SHADOW_PATTERNS: tuple[tuple[str, ...], ...] = (
    ("vssadmin", "delete shadows"),
    ("vssadmin", "resize shadowstorage"),
    ("wmic", "shadowcopy delete"),
    ("bcdedit", "recoveryenabled no"),
    ("bcdedit", "bootstatuspolicy ignoreallfailures"),
    ("wbadmin", "delete"),
    ("win32_shadowcopy", "delete"),
)

#: Autostart locations, matched case-insensitively against the whole path.
_AUTOSTART_MARKERS: tuple[str, ...] = (
    "/.config/autostart/",
    "/.config/systemd/user/",
    "/etc/systemd/system/",
    "/etc/systemd/user/",
    "/lib/systemd/system/",
    "/etc/init.d/",
    "/etc/rc.local",
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/crontab",
    "/var/spool/cron/",
    "/.bashrc",
    "/.bash_profile",
    "/.profile",
    "/.zshrc",
    "/.xprofile",
    "/library/launchagents/",
    "/library/launchdaemons/",
    "\\start menu\\programs\\startup\\",
    "/start menu/programs/startup/",
    "\\currentversion\\run",
    "/currentversion/run",
    "\\windows\\system32\\tasks\\",
)

#: Temp / download locations an executable has no business living in.
_TEMP_MARKERS: tuple[str, ...] = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/private/var/folders/",
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "/downloads/",
    "/pobrane/",
    "/.cache/",
)

#: Parents that should never be spawning a shell.
_SCRIPT_PARENTS: frozenset[str] = frozenset(
    {
        "winword", "excel", "powerpnt", "outlook", "onenote", "msaccess",
        "visio", "mspub", "soffice", "soffice.bin", "libreoffice",
        "acrord32", "acrobat", "wscript", "cscript", "mshta", "hh",
        "eqnedt32", "msdt", "wordpad",
    }
)

#: Shells and LOLBins that such a parent typically reaches for.
_SHELL_CHILDREN: frozenset[str] = frozenset(
    {
        "cmd", "command", "powershell", "pwsh", "powershell_ise",
        "sh", "bash", "dash", "zsh", "ksh", "csh", "fish",
        "wscript", "cscript", "mshta", "rundll32", "regsvr32", "msiexec",
        "certutil", "bitsadmin", "curl", "wget", "python", "python3", "perl",
        "ruby", "node", "osascript", "schtasks", "at", "reg", "wmic",
    }
)

_WS_RE = re.compile(r"\s+")

#: Event kinds that count as "this actor wrote a file".
_FILE_WRITE_KINDS = frozenset(
    {
        BehaviorKind.FILE_CREATE,
        BehaviorKind.FILE_MODIFY,
        BehaviorKind.FILE_RENAME,
        BehaviorKind.AUTOSTART_WRITE,
    }
)


# --------------------------------------------------------------------------
# Small shared helpers (also imported by watcher.py / responder.py)
# --------------------------------------------------------------------------
def parse_severity(value: Any, default: Severity = Severity.MEDIUM) -> Severity:
    """Coerce a config string such as ``"medium"`` into a :class:`Severity`."""
    if isinstance(value, Severity):
        return value
    try:
        return Severity(str(value).strip().lower())
    except (ValueError, AttributeError):
        return default


def severity_at_least(value: Severity, floor: Severity) -> bool:
    """True when *value* is at least as severe as *floor*."""
    return SEVERITY_ORDER.get(value, 0) >= SEVERITY_ORDER.get(floor, 0)


def _basename(path: str | None) -> str:
    if not path:
        return ""
    cleaned = path.replace("\\", "/").rstrip("/")
    return cleaned.rsplit("/", 1)[-1]


def _dirname(path: str | None) -> str:
    if not path:
        return ""
    cleaned = path.replace("\\", "/")
    if "/" not in cleaned:
        return ""
    return cleaned.rsplit("/", 1)[0] or "/"


def _extension(path: str | None) -> str:
    name = _basename(path)
    if "." not in name[1:]:
        return ""
    return "." + name.rsplit(".", 1)[-1].lower()


def _norm_name(name: str | None) -> str:
    """Normalise a process name: basename, lowercase, no ``.exe``."""
    if not name:
        return ""
    base = _basename(name).lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base


def _normalise_cmdline(cmdline: str) -> str:
    return _WS_RE.sub(" ", (cmdline or "").replace('"', " ").replace("'", " ")).strip().lower()


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _size_is_stable(old: int, new: int) -> bool:
    """True when a rewrite kept roughly the same size (encryption, not replacement)."""
    if old <= 0 or new <= 0:
        return False
    low = old * SIZE_STABLE_LOW - SIZE_STABLE_SLACK
    high = old * SIZE_STABLE_HIGH + SIZE_STABLE_SLACK
    return low <= new <= high


# --------------------------------------------------------------------------
# Per-actor state
# --------------------------------------------------------------------------
@dataclass(slots=True)
class _ActorState:
    """Windowed observations for one pid (or the unattributed bucket)."""

    pid: int | None
    process: str = ""
    cmdline: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    event_count: int = 0

    writes: deque[tuple[float, str]] = field(default_factory=lambda: deque(maxlen=_MAX_TRACKED))
    deletes: deque[tuple[float, str]] = field(default_factory=lambda: deque(maxlen=_MAX_TRACKED))
    renames: deque[tuple[float, str]] = field(default_factory=lambda: deque(maxlen=_MAX_TRACKED))
    encrypt_hits: deque[tuple[float, str]] = field(default_factory=lambda: deque(maxlen=_MAX_TRACKED))
    notes: deque[tuple[float, str, bool]] = field(default_factory=lambda: deque(maxlen=256))
    propagation: deque[tuple[float, str, str]] = field(default_factory=lambda: deque(maxlen=_MAX_TRACKED))
    connects: dict[str, deque[float]] = field(default_factory=dict)

    touched_paths: dict[str, None] = field(default_factory=dict)
    detections: list[Detection] = field(default_factory=list)
    cooldowns: dict[tuple[str, str], float] = field(default_factory=dict)
    note_language_seen: bool = False

    def touch(self, path: str | None) -> None:
        if not path:
            return
        if path in self.touched_paths:
            return
        if len(self.touched_paths) >= _MAX_TOUCHED_PATHS:
            return
        self.touched_paths[path] = None


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------
class BehaviorEngine:
    """Correlates :class:`BehaviorEvent` observations into :class:`Detection`s.

    Thread-safe: the filesystem watcher and the process monitor feed it from
    two different threads, and the GUI reads :meth:`verdicts` from a third.
    """

    def __init__(
        self,
        config: Config,
        bus: EventBus | None = None,
        db: "SignatureDB | None" = None,
    ) -> None:
        self._config = config
        self._bus = bus
        self._db = db
        self._lock = threading.RLock()
        self._actors: dict[int | None, _ActorState] = {}
        self._proc_names: dict[int, str] = {}
        self._path_info: dict[str, tuple[int, float | None]] = {}
        self._path_order: deque[str] = deque()
        self._observed = 0
        self._fired = 0
        self._since_gc = 0

        allow = getattr(config, "behavior_allowlist", None)
        if allow:
            self._allowlist = frozenset(_norm_name(n) for n in allow)
        else:
            self._allowlist = BENIGN_PROCESS_NAMES

    # -- public API ------------------------------------------------------
    @property
    def config(self) -> Config:
        return self._config

    def rules(self) -> list[dict[str, Any]]:
        """The armed rule catalogue, for the GUI's "what is watching" table."""
        return [dict(rule) for rule in BEHAVIOR_RULES]

    def reset(self) -> None:
        with self._lock:
            self._actors.clear()
            self._proc_names.clear()
            self._path_info.clear()
            self._path_order.clear()
            self._observed = 0
            self._fired = 0
            self._since_gc = 0

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "actors": len(self._actors),
                "observed": self._observed,
                "detections": self._fired,
                "window_sec": float(self._config.behavior_window_sec),
                "rules": len(BEHAVIOR_RULES),
                "intel": self._db is not None,
            }

    def observe(self, event: BehaviorEvent) -> list[Detection]:
        """Ingest one observation; return the detections it newly triggered."""
        if not getattr(self._config, "behavior_enabled", True):
            return []
        if not isinstance(event, BehaviorEvent):  # defensive: never trust a producer
            return []

        with self._lock:
            self._observed += 1
            now = float(event.timestamp or time.time())
            state = self._state_for(event)
            state.last_seen = max(state.last_seen, now)
            state.event_count += 1
            self._prune(state, now)
            self._ingest(state, event, now)
            fired = self._evaluate(state, event, now)
            if fired:
                self._fired += len(fired)
                self._rescore(state)
            self._since_gc += 1
            if self._since_gc >= _GC_EVERY:
                self._since_gc = 0
                self._gc(now)

        for det in fired:  # publish outside the lock: subscribers may be slow
            self._publish(det, state)
        return fired

    def verdicts(self, min_severity: Severity = Severity.LOW) -> list[ProcessVerdict]:
        """Current per-actor verdicts at or above *min_severity*, worst first."""
        floor = parse_severity(min_severity, Severity.LOW)
        out: list[ProcessVerdict] = []
        with self._lock:
            for state in self._actors.values():
                if not state.detections:
                    continue
                verdict = self._build_verdict(state)
                if severity_at_least(verdict.severity, floor):
                    out.append(verdict)
        out.sort(key=lambda v: v.score, reverse=True)
        return out

    def verdict_for(self, pid: int | None) -> ProcessVerdict | None:
        with self._lock:
            state = self._actors.get(pid)
            if state is None:
                return None
            return self._build_verdict(state)

    # -- state management ------------------------------------------------
    def _state_for(self, event: BehaviorEvent) -> _ActorState:
        pid = event.pid
        state = self._actors.get(pid)
        if state is None:
            if len(self._actors) >= _MAX_ACTORS:
                self._evict_actor()
            state = _ActorState(
                pid=pid,
                first_seen=float(event.timestamp or time.time()),
                last_seen=float(event.timestamp or time.time()),
            )
            self._actors[pid] = state
        if event.process and not state.process:
            state.process = event.process
        if event.cmdline and not state.cmdline:
            state.cmdline = event.cmdline
        return state

    def _evict_actor(self) -> None:
        """Drop the least interesting actor: oldest with no detections."""
        candidates = [s for s in self._actors.values() if not s.detections and s.pid is not None]
        if not candidates:
            candidates = [s for s in self._actors.values() if s.pid is not None]
        if not candidates:
            return
        victim = min(candidates, key=lambda s: s.last_seen)
        self._actors.pop(victim.pid, None)

    def _gc(self, now: float) -> None:
        """Forget actors that have been quiet for ten windows and look clean."""
        idle = float(self._config.behavior_window_sec) * 10.0
        for pid in [
            p
            for p, s in self._actors.items()
            if p is not None and not s.detections and now - s.last_seen > idle
        ]:
            self._actors.pop(pid, None)
        for pid in [p for p in self._proc_names if p not in self._actors]:
            if len(self._proc_names) > _MAX_ACTORS * 4:
                self._proc_names.pop(pid, None)

    def _prune(self, state: _ActorState, now: float) -> None:
        """Drop everything that fell out of the correlation window."""
        cutoff = now - float(self._config.behavior_window_sec)
        for dq in (state.writes, state.deletes, state.renames, state.encrypt_hits):
            while dq and dq[0][0] < cutoff:
                dq.popleft()
        while state.notes and state.notes[0][0] < cutoff:
            state.notes.popleft()
        while state.propagation and state.propagation[0][0] < cutoff:
            state.propagation.popleft()

        # Beaconing needs a longer memory than the file-churn window.
        beacon_cutoff = now - self._beacon_window()
        for host in list(state.connects):
            dq = state.connects[host]
            while dq and dq[0] < beacon_cutoff:
                dq.popleft()
            if not dq:
                del state.connects[host]

    def _beacon_window(self) -> float:
        return max(float(self._config.behavior_window_sec) * 3.0, 60.0)

    def _remember_path(self, path: str, size: int, entropy: float | None) -> None:
        if path not in self._path_info:
            self._path_order.append(path)
            while len(self._path_order) > _MAX_PATH_CACHE:
                self._path_info.pop(self._path_order.popleft(), None)
        self._path_info[path] = (int(size), entropy)

    # -- ingestion -------------------------------------------------------
    def _ingest(self, state: _ActorState, event: BehaviorEvent, now: float) -> None:
        kind = event.kind
        path = event.path

        if event.pid is not None and event.process:
            self._proc_names[event.pid] = event.process

        if path:
            state.touch(path)

        if kind in (BehaviorKind.FILE_CREATE, BehaviorKind.FILE_MODIFY, BehaviorKind.AUTOSTART_WRITE):
            state.writes.append((now, path or ""))
            self._check_encrypt_in_place(state, event, now)
            self._check_propagation(state, event, now)
            self._check_note(state, event, now)
            if path:
                self._remember_path(path, event.size, event.entropy)
        elif kind is BehaviorKind.FILE_RENAME:
            state.writes.append((now, path or ""))
            state.renames.append((now, _extension(path)))
            if event.old_path:
                state.touch(event.old_path)
            self._check_note(state, event, now)
            self._check_propagation(state, event, now)
            if path:
                self._remember_path(path, event.size, event.entropy)
        elif kind is BehaviorKind.FILE_DELETE:
            state.deletes.append((now, path or ""))
            if path:
                self._path_info.pop(path, None)
        elif kind is BehaviorKind.NET_CONNECT:
            host = (event.remote_host or "").strip().lower()
            if host:
                state.connects.setdefault(host, deque(maxlen=256)).append(now)

    def _check_encrypt_in_place(self, state: _ActorState, event: BehaviorEvent, now: float) -> None:
        """Record a rewrite that looks like in-place encryption."""
        if event.kind is BehaviorKind.FILE_CREATE:
            return  # a brand new .zip is high entropy and perfectly innocent
        if event.entropy is None or not event.path:
            return
        threshold = float(self._config.behavior_entropy_threshold)
        if event.entropy < threshold:
            return

        prev_size = event.extra.get("prev_size")
        prev_entropy = event.extra.get("prev_entropy")
        cached = self._path_info.get(event.path)
        if prev_size is None and cached is not None:
            prev_size = cached[0]
        if prev_entropy is None and cached is not None:
            prev_entropy = cached[1]
        if prev_size is None:
            return
        if not _size_is_stable(int(prev_size), int(event.size)):
            return

        # A file that used to be low-entropy and is now ciphertext is the
        # strongest form of this signal, and it holds even for .jpg or .zip.
        entropy_jumped = prev_entropy is not None and float(prev_entropy) < threshold - 0.8
        if not entropy_jumped and _extension(event.path) in _COMPRESSED_EXTENSIONS:
            return
        state.encrypt_hits.append((now, event.path))

    def _check_propagation(self, state: _ActorState, event: BehaviorEvent, now: float) -> None:
        if not event.path:
            return
        directory = _dirname(event.path)
        if not directory:
            return
        content_hash = (
            event.extra.get("content_hash")
            or event.extra.get("sha256")
            or event.extra.get("prefix_sha256")
        )
        if content_hash:
            state.propagation.append((now, f"hash:{content_hash}", directory))
        name = _basename(event.path).lower()
        if name and _extension(name) not in ("", ".tmp", ".part", ".swp", ".log"):
            state.propagation.append((now, f"name:{name}", directory))

    def _check_note(self, state: _ActorState, event: BehaviorEvent, now: float) -> None:
        if not event.path:
            return
        name = _basename(event.path).lower()
        if not name:
            return
        if _extension(name) not in _NOTE_EXTENSIONS:
            strong_name = False
            weak_name = False
        else:
            strong_name = any(p.search(name) for p in _NOTE_PATTERNS_STRONG)
            weak_name = not strong_name and any(p.search(name) for p in _NOTE_PATTERNS_WEAK)

        if self._note_language_hits(event) >= NOTE_MIN_LANGUAGE_HITS:
            state.note_language_seen = True
            state.notes.append((now, _dirname(event.path), True))
        elif strong_name or weak_name:
            state.notes.append((now, _dirname(event.path), strong_name))

    @staticmethod
    def _note_language_hits(event: BehaviorEvent) -> int:
        sample = ""
        for key in ("sample_text", "text", "content", "preview"):
            value = event.extra.get(key)
            if isinstance(value, str) and value:
                sample = value
                break
            if isinstance(value, bytes) and value:
                sample = value.decode("utf-8", "replace")
                break
        if not sample:
            return 0
        lowered = sample.lower()
        return sum(1 for phrase in RANSOM_NOTE_LANGUAGE if phrase in lowered)

    # -- rule evaluation -------------------------------------------------
    def _evaluate(self, state: _ActorState, event: BehaviorEvent, now: float) -> list[Detection]:
        fired: list[Detection] = []
        threshold = max(1, int(self._config.behavior_mass_ops_threshold))

        # --- ransomware cluster, specific rules first so that the bulk rules
        # --- fire with corroboration already on the record.
        if len(state.encrypt_hits) >= self._min_encrypt_hits():
            hits = len(state.encrypt_hits)
            det = self._fire(
                state,
                RULE_ENCRYPT_IN_PLACE,
                now,
                confidence=min(1.0, 0.6 + 0.12 * hits),
                detail=(
                    f"{hits} plików nadpisanych treścią o entropii powyżej "
                    f"{self._config.behavior_entropy_threshold:.1f}/8.0 przy zachowanym rozmiarze"
                ),
                path=state.encrypt_hits[-1][1],
            )
            if det:
                fired.append(det)

        rename_ext, rename_count, rename_share = (None, 0, 0.0)
        if event.kind is BehaviorKind.FILE_RENAME:
            rename_ext, rename_count, rename_share = self._dominant_rename_extension(state)
        if rename_ext is not None:
            det = self._fire(
                state,
                RULE_MASS_RENAME_EXTENSION,
                now,
                confidence=0.9,
                detail=(
                    f"{rename_count} zmian nazw zbiegających się do rozszerzenia "
                    f"{rename_ext} ({rename_share * 100:.0f}% wszystkich zmian nazw)"
                ),
                path=event.path,
            )
            if det:
                fired.append(det)

        note_det = self._evaluate_note(state, now, event)
        if note_det:
            fired.append(note_det)

        shadow = self._matched_shadow_pattern(event)
        if shadow:
            det = self._fire(
                state,
                RULE_SHADOW_COPY_TAMPER,
                now,
                confidence=1.0,
                detail=f"polecenie niszczące kopie zapasowe: {shadow}",
                path=event.path,
            )
            if det:
                fired.append(det)

        prop_key, prop_dirs = (None, 0)
        if event.kind in _FILE_WRITE_KINDS:
            prop_key, prop_dirs = self._propagation_hit(state)
        if prop_key is not None:
            det = self._fire(
                state,
                RULE_SELF_PROPAGATION,
                now,
                confidence=max(0.7, self._scaled_confidence(state, RULE_SELF_PROPAGATION)),
                detail=(
                    f"ta sama treść/nazwa ({prop_key}) zapisana w {prop_dirs} różnych katalogach"
                ),
                path=event.path,
            )
            if det:
                fired.append(det)

        if self._is_autostart(event):
            det = self._fire(
                state,
                RULE_AUTOSTART_WRITE,
                now,
                confidence=max(0.6, self._scaled_confidence(state, RULE_AUTOSTART_WRITE)),
                detail=f"zapis do lokalizacji autostartu: {event.path}",
                path=event.path,
            )
            if det:
                fired.append(det)

        # --- bulk rules, deliberately last and confidence-scaled -------
        if len(state.writes) > threshold:
            det = self._fire(
                state,
                RULE_MASS_FILE_MODIFY,
                now,
                confidence=self._scaled_confidence(state, RULE_MASS_FILE_MODIFY),
                detail=(
                    f"{len(state.writes)} zapisów/zmian nazw w ciągu "
                    f"{self._config.behavior_window_sec:.0f} s (próg {threshold})"
                ),
                path=event.path,
            )
            if det:
                fired.append(det)

        if len(state.deletes) > threshold:
            det = self._fire(
                state,
                RULE_MASS_DELETE,
                now,
                confidence=self._scaled_confidence(state, RULE_MASS_DELETE),
                detail=(
                    f"{len(state.deletes)} usunięć w ciągu "
                    f"{self._config.behavior_window_sec:.0f} s (próg {threshold})"
                ),
                path=event.path,
            )
            if det:
                fired.append(det)

        # --- network and process rules ---------------------------------
        if event.kind is BehaviorKind.NET_CONNECT:
            det = self._evaluate_blocklist(state, event, now)
            if det:
                fired.append(det)
            det = self._evaluate_beacon(state, event, now)
            if det:
                fired.append(det)

        if event.kind is BehaviorKind.PROCESS_START:
            parent = self._spawn_chain_parent(event)
            if parent:
                det = self._fire(
                    state,
                    RULE_SCRIPT_SPAWN_CHAIN,
                    now,
                    confidence=0.8,
                    detail=(
                        f"{parent} (PID {event.ppid}) uruchomił "
                        f"{_norm_name(event.process) or '?'}"
                    ),
                    path=event.path,
                )
                if det:
                    fired.append(det)

            temp_dir = self._temp_exec_marker(event)
            if temp_dir:
                det = self._fire(
                    state,
                    RULE_EXEC_FROM_TEMP,
                    now,
                    confidence=0.6,
                    detail=f"proces uruchomiony z {temp_dir}: {event.path}",
                    path=event.path,
                )
                if det:
                    fired.append(det)

        return fired

    def _min_encrypt_hits(self) -> int:
        return max(2, int(getattr(self._config, "behavior_encrypt_min_hits", ENCRYPT_MIN_HITS)))

    def _evaluate_note(
        self, state: _ActorState, now: float, event: BehaviorEvent
    ) -> Detection | None:
        if not state.notes:
            return None
        strong_dirs = {d for _, d, strong in state.notes if strong}
        all_dirs = {d for _, d, _ in state.notes}
        if state.note_language_seen:
            detail = "plik zawiera język żądania okupu"
            confidence = 1.0
        elif len(strong_dirs) >= NOTE_MIN_DIRS_STRONG:
            detail = f"jednoznaczne nazwy listów okupowych w {len(strong_dirs)} katalogach"
            confidence = 0.9
        elif len(all_dirs) >= NOTE_MIN_DIRS_WEAK:
            detail = f"pliki typu README/UWAGA utworzone w {len(all_dirs)} katalogach"
            confidence = 0.75
        else:
            return None
        return self._fire(
            state,
            RULE_RANSOM_NOTE,
            now,
            confidence=confidence,
            detail=detail,
            path=event.path,
        )

    def _dominant_rename_extension(self, state: _ActorState) -> tuple[str | None, int, float]:
        """The unknown extension that renames are converging on, if any."""
        if len(state.renames) < RENAME_EXT_MIN:
            return None, 0, 0.0
        counts: dict[str, int] = {}
        for _, ext in state.renames:
            counts[ext] = counts.get(ext, 0) + 1
        ext, count = max(counts.items(), key=lambda kv: kv[1])
        share = count / len(state.renames)
        if count < RENAME_EXT_MIN or share < RENAME_EXT_SHARE:
            return None, 0, 0.0
        if ext in _COMMON_EXTENSIONS:
            return None, 0, 0.0  # a save storm converging on .docx is not an attack
        return ext, count, share

    def _propagation_hit(self, state: _ActorState) -> tuple[str | None, int]:
        if not state.propagation:
            return None, 0
        dirs: dict[str, set[str]] = {}
        for _, key, directory in state.propagation:
            dirs.setdefault(key, set()).add(directory)
        key, seen = max(dirs.items(), key=lambda kv: len(kv[1]))
        if len(seen) < PROPAGATION_MIN_DIRS:
            return None, 0
        return key, len(seen)

    def _is_autostart(self, event: BehaviorEvent) -> bool:
        if event.kind is BehaviorKind.AUTOSTART_WRITE:
            return True
        if event.kind not in (
            BehaviorKind.FILE_CREATE,
            BehaviorKind.FILE_MODIFY,
            BehaviorKind.FILE_RENAME,
        ):
            return False
        if not event.path:
            return False
        probe = event.path.replace("\\", "/").lower()
        normalised = event.path.lower()
        return any(
            marker in probe or marker in normalised
            for marker in _AUTOSTART_MARKERS
        )

    @staticmethod
    def _matched_shadow_pattern(event: BehaviorEvent) -> str | None:
        cmdline = _normalise_cmdline(event.cmdline)
        if not cmdline:
            return None
        for parts in _SHADOW_PATTERNS:
            if all(part in cmdline for part in parts):
                return " ".join(parts)
        return None

    def _spawn_chain_parent(self, event: BehaviorEvent) -> str | None:
        child = _norm_name(event.process) or _norm_name(event.path)
        if child not in _SHELL_CHILDREN:
            return None
        parent = _norm_name(
            event.extra.get("parent_name")
            or event.extra.get("parent")
            or (self._proc_names.get(event.ppid) if event.ppid is not None else None)
        )
        if parent and parent in _SCRIPT_PARENTS:
            return parent
        return None

    def _temp_exec_marker(self, event: BehaviorEvent) -> str | None:
        exe = event.path or event.extra.get("exe") or ""
        if not exe:
            return None
        if self._config.is_internal(exe):
            return None
        probe = exe.replace("\\", "/").lower()
        for marker in _TEMP_MARKERS:
            needle = marker.replace("\\", "/")
            if needle in probe:
                return marker
        return None

    def _evaluate_blocklist(
        self, state: _ActorState, event: BehaviorEvent, now: float
    ) -> Detection | None:
        host = (event.remote_host or "").strip()
        if not host or self._db is None:
            return None
        indicator = self._lookup_network(host, event.extra.get("url"))
        if indicator is None:
            return None
        port = f":{event.remote_port}" if event.remote_port else ""
        return self._fire(
            state,
            RULE_BLOCKLISTED_CONNECTION,
            now,
            confidence=1.0,
            detail=f"połączenie z {host}{port} - wskaźnik {indicator.kind}: {indicator.value}",
            path=event.path,
            layer=DetectionLayer.INTEL,
            score=SCORE_INTEL_NETWORK,
            threat_name=indicator.name or _THREAT_NAMES[RULE_BLOCKLISTED_CONNECTION],
            indicator=indicator,
            cooldown_key=host.lower(),
        )

    def _lookup_network(self, host: str, url: Any = None) -> Indicator | None:
        """Ask the signature database; never let its failure stop monitoring."""
        if self._db is None:
            return None
        attempts: list[dict[str, Any]] = []
        if _looks_like_ip(host):
            attempts.append({"ip": host})
        else:
            attempts.append({"host": host})
        if isinstance(url, str) and url:
            attempts.append({"url": url})
        for kwargs in attempts:
            try:
                found = self._db.lookup_network(**kwargs)
            except Exception:  # noqa: BLE001 - intel layer must not break realtime
                return None
            if found is not None:
                return found
        return None

    def _evaluate_beacon(
        self, state: _ActorState, event: BehaviorEvent, now: float
    ) -> Detection | None:
        host = (event.remote_host or "").strip().lower()
        samples = state.connects.get(host)
        if not samples or len(samples) < BEACON_MIN_SAMPLES:
            return None
        stamps = list(samples)
        intervals = [b - a for a, b in zip(stamps, stamps[1:]) if b > a]
        if len(intervals) < BEACON_MIN_SAMPLES - 1:
            return None
        mean = statistics.fmean(intervals)
        if mean < BEACON_MIN_INTERVAL:
            return None  # a burst of connections is not a beacon
        stdev = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
        cv = stdev / mean if mean else math.inf
        if cv > BEACON_MAX_CV:
            return None
        return self._fire(
            state,
            RULE_BEACON_PATTERN,
            now,
            confidence=0.7,
            detail=(
                f"{len(stamps)} połączeń do {host} co ~{mean:.1f} s "
                f"(odchylenie {stdev:.2f} s, zmienność {cv * 100:.0f}%)"
            ),
            path=event.path,
            cooldown_key=host,
        )

    # -- detection plumbing ----------------------------------------------
    def _allowlisted(self, state: _ActorState) -> bool:
        names = {_norm_name(state.process)}
        if state.cmdline:
            names.add(_norm_name(state.cmdline.split()[0] if state.cmdline.split() else ""))
        names.discard("")
        return bool(names & self._allowlist)

    def _scaled_confidence(self, state: _ActorState, rule: str) -> float:
        """Confidence of a bulk rule, as a function of corroborating evidence."""
        fired = {d.rule for d in state.detections} & _CORROBORATORS
        fired.discard(rule)
        signals = len(fired)
        threshold = max(1, int(self._config.behavior_mass_ops_threshold))
        if len(state.writes) > threshold and len(state.deletes) > threshold:
            signals += 1
        if (
            RULE_ENCRYPT_IN_PLACE not in fired
            and len(state.encrypt_hits) >= self._min_encrypt_hits()
        ):
            signals += 1
        if signals >= 2:
            return 1.0
        if signals == 1:
            return 0.8
        return 0.55

    def _fire(
        self,
        state: _ActorState,
        rule: str,
        now: float,
        *,
        confidence: float,
        detail: str,
        path: str | None = None,
        layer: DetectionLayer = DetectionLayer.BEHAVIOR,
        score: float | None = None,
        threat_name: str | None = None,
        indicator: Indicator | None = None,
        cooldown_key: str = "",
    ) -> Detection | None:
        """Emit a detection unless the allowlist or the cooldown says otherwise."""
        if rule in _ALLOWLISTABLE and self._allowlisted(state):
            return None

        key = (rule, cooldown_key)
        last = state.cooldowns.get(key)
        cooldown = float(
            getattr(self._config, "behavior_cooldown_sec", 0) or 0
        ) or _RULE_COOLDOWN.get(rule, _DEFAULT_COOLDOWN)
        if last is not None and now - last < cooldown:
            return None
        state.cooldowns[key] = now
        if len(state.cooldowns) > 512:  # pathological host churn
            for stale in [k for k, t in state.cooldowns.items() if now - t > cooldown * 4][:256]:
                state.cooldowns.pop(stale, None)

        detection = Detection(
            layer=layer,
            rule=rule,
            threat_name=threat_name or _THREAT_NAMES.get(rule, f"Behav.{rule}"),
            score=_RULE_SCORES[rule] if score is None else score,
            confidence=confidence,
            detail=detail,
            path=path,
            pid=state.pid,
            indicator=indicator,
            timestamp=now,
        )
        state.detections.append(detection)
        if len(state.detections) > _MAX_DETECTIONS_PER_ACTOR:
            # Keep the strongest evidence, drop the weakest.
            state.detections.sort(key=lambda d: d.weighted, reverse=True)
            del state.detections[_MAX_DETECTIONS_PER_ACTOR:]
        return detection

    def _rescore(self, state: _ActorState) -> None:
        """Raise the confidence of bulk detections once corroboration arrives.

        A ``mass_file_modify`` recorded before the entropy rewrites were
        visible would otherwise stay stuck at its initial low confidence, and
        the actor would never cross the response threshold even though the
        evidence is now overwhelming.
        """
        for det in state.detections:
            if det.rule not in _CORROBORATION_SCALED:
                continue
            scaled = self._scaled_confidence(state, det.rule)
            floor = 0.6 if det.rule == RULE_AUTOSTART_WRITE else 0.0
            floor = max(floor, 0.7 if det.rule == RULE_SELF_PROPAGATION else 0.0)
            det.confidence = max(det.confidence, scaled, floor)

    def _build_verdict(self, state: _ActorState) -> ProcessVerdict:
        verdict = ProcessVerdict(
            pid=state.pid,
            process=state.process,
            cmdline=state.cmdline,
            detections=list(state.detections),
            event_count=state.event_count,
            first_seen=state.first_seen,
            last_seen=state.last_seen,
            touched_paths=list(state.touched_paths),
        )
        return apply_to_process_verdict(verdict)

    def _publish(self, detection: Detection, state: _ActorState) -> None:
        if self._bus is None:
            return
        who = f"PID {state.pid}" if state.pid is not None else "nieprzypisany"
        name = _RULE_NAMES.get(detection.rule, detection.rule)
        process = state.process or "?"
        try:
            self._bus.publish(
                EventType.BEHAVIOR_ALERT,
                f"Behawior: {name} ({who}, {process}) - {detection.detail}",
                level="warning",
                rule=detection.rule,
                pid=state.pid,
                process=state.process,
                score=detection.score,
                confidence=detection.confidence,
                threat_name=detection.threat_name,
                layer=detection.layer.value,
                detection=detection.to_dict(),
            )
        except Exception:  # noqa: BLE001 - the bus is best effort
            pass
