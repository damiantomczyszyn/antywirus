"""Persistent configuration for Aegis AV.

Everything the product writes at runtime lives under :attr:`Config.data_dir`
(``~/.aegis`` by default), so the product never pollutes the directories it
is asked to protect.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from .models import ActionKind

__all__ = ["Config", "default_data_dir", "default_scan_roots"]

# Directory names that are pointless or dangerous to walk.
DEFAULT_EXCLUDED_NAMES: tuple[str, ...] = (
    "__pycache__", ".git", ".hg", ".svn", "node_modules", ".venv", "venv",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages",
    "/proc", "/sys", "/dev", "/run", "/snap",
)

# Extensions worth a deep look even when "fast mode" is on.
DEFAULT_PRIORITY_EXTENSIONS: tuple[str, ...] = (
    ".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl", ".ocx", ".drv",
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".hta", ".jar", ".py", ".sh", ".elf", ".so", ".bin", ".lnk",
    ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf", ".pdf",
    ".zip", ".rar", ".7z", ".gz", ".tar", ".iso", ".img", ".msi",
)


def default_data_dir() -> Path:
    """Per-user state directory, honouring platform conventions."""
    env = os.environ.get("AEGIS_DATA_DIR")
    if env:
        return Path(env).expanduser()
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / "Aegis"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Aegis"
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "aegis"
    return Path.home() / ".aegis"


def default_scan_roots() -> list[str]:
    """Sensible directories to protect in realtime."""
    home = Path.home()
    candidates = [home / "Downloads", home / "Desktop", home / "Documents", home / "Pobrane", home / "Pulpit", home / "Dokumenty"]
    found = [str(p) for p in candidates if p.is_dir()]
    return found or [str(home)]


@dataclass
class Config:
    """User-tunable settings.  Load with :meth:`load`, persist with :meth:`save`."""

    # --- locations ---
    data_dir: Path = field(default_factory=default_data_dir)

    # --- scanning ---
    max_file_size: int = 64 * 1024 * 1024       # skip bigger files
    hash_chunk_size: int = 1024 * 1024
    scan_threads: int = 4
    follow_symlinks: bool = False
    scan_archives: bool = True
    archive_max_depth: int = 2
    archive_max_members: int = 500
    archive_max_uncompressed: int = 256 * 1024 * 1024
    excluded_names: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDED_NAMES))
    excluded_paths: list[str] = field(default_factory=list)
    priority_extensions: list[str] = field(default_factory=lambda: list(DEFAULT_PRIORITY_EXTENSIONS))
    use_scan_cache: bool = True

    # --- realtime protection ---
    realtime_enabled: bool = False
    realtime_paths: list[str] = field(default_factory=default_scan_roots)
    realtime_action: ActionKind = ActionKind.QUARANTINE
    realtime_debounce_ms: int = 400
    realtime_min_severity: str = "medium"       # act at or above this severity

    # --- behaviour monitoring ---
    behavior_enabled: bool = True
    behavior_action: ActionKind = ActionKind.REPORT   # KILL_PROCESS once trusted
    behavior_window_sec: float = 20.0
    behavior_mass_ops_threshold: int = 25
    behavior_entropy_threshold: float = 7.2
    procmon_enabled: bool = True
    procmon_interval_sec: float = 2.0

    # --- threat intel ---
    # Only feeds that actually serve data anonymously, verified 2026-11-14.
    # Deliberately NOT here:
    #   malwarebazaar_recent / urlhaus_online / threatfox_iocs - abuse.ch
    #     retired its anonymous bulk exports (HTTP 410 Gone); the replacements
    #     live on *-api.abuse.ch and need a free Auth-Key, so enabling them by
    #     default would only produce warnings on a fresh install.
    #   sslbl_ipblocklist - upstream deprecated it on 2025-01-03; it still
    #     returns 200 but the body is a header and zero addresses.
    #   sslbl_certs - TLS certificate fingerprints, not file hashes; they can
    #     never match file content, so they would just pollute the hash space.
    #   clamav_daily - large download, and Cloudflare blocks some egress.
    # Add any of them in Settings (and a key via feed_api_keys) to turn on.
    feeds_enabled: list[str] = field(
        default_factory=lambda: [
            "builtin",
            "feodo_ipblocklist",
            "feodo_aggressive",
        ]
    )
    feed_api_keys: dict[str, str] = field(default_factory=dict)
    feed_timeout_sec: float = 30.0
    feed_max_indicators: int = 400_000
    auto_update_on_start: bool = False
    update_interval_hours: float = 24.0

    # --- ui ---
    language: str = "pl"
    theme: str = "dark"

    # ------------------------------------------------------------------
    # Derived paths
    # ------------------------------------------------------------------
    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir).expanduser()
        self.realtime_action = ActionKind(self.realtime_action)
        self.behavior_action = ActionKind(self.behavior_action)

    @property
    def config_path(self) -> Path:
        return self.data_dir / "config.json"

    @property
    def db_path(self) -> Path:
        """SQLite virus database."""
        return self.data_dir / "signatures.db"

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"

    @property
    def quarantine_index(self) -> Path:
        return self.quarantine_dir / "index.json"

    @property
    def log_path(self) -> Path:
        return self.data_dir / "aegis.log"

    @property
    def cache_path(self) -> Path:
        return self.data_dir / "scan_cache.json"

    @property
    def feed_state_path(self) -> Path:
        """ETag / Last-Modified bookkeeping so feeds are not re-downloaded."""
        return self.data_dir / "feed_state.json"

    @property
    def history_path(self) -> Path:
        return self.data_dir / "history.json"

    def ensure_dirs(self) -> None:
        """Create the runtime directory tree with private permissions."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        for d in (self.data_dir, self.quarantine_dir):
            try:
                d.chmod(0o700)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Self-protection
    # ------------------------------------------------------------------
    def internal_paths(self) -> list[Path]:
        """Paths the engine must never scan or watch (prevents feedback loops)."""
        return [self.data_dir.resolve()]

    def is_internal(self, path: str | os.PathLike[str]) -> bool:
        try:
            resolved = Path(path).resolve()
        except OSError:
            return False
        for internal in self.internal_paths():
            if resolved == internal or internal in resolved.parents:
                return True
        return False

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if isinstance(value, Path):
                value = str(value)
            elif isinstance(value, ActionKind):
                value = value.value
            out[f.name] = value
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        known = {f.name for f in fields(cls)}
        kwargs = {k: v for k, v in data.items() if k in known}
        return cls(**kwargs)

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> "Config":
        """Load settings, falling back to defaults on any problem."""
        cfg_path = Path(path).expanduser() if path else default_data_dir() / "config.json"
        if cfg_path.is_file():
            try:
                data = json.loads(cfg_path.read_text(encoding="utf-8"))
                cfg = cls.from_dict(data)
                if not path:
                    cfg.data_dir = cfg_path.parent
                return cfg
            except (OSError, ValueError, TypeError):
                pass
        return cls()

    def save(self, path: str | os.PathLike[str] | None = None) -> Path:
        """Atomically persist settings."""
        target = Path(path).expanduser() if path else self.config_path
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".cfg-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp, target)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return target
