"""Make the ``aegis`` package importable without installing it, plus shared fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

from aegis.config import Config  # noqa: E402
from aegis.events import EventBus  # noqa: E402

EICAR = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
).encode()


@pytest.fixture()
def bus() -> EventBus:
    return EventBus()


@pytest.fixture()
def config(tmp_path) -> Config:
    """A Config rooted in a throwaway directory - never touches the real ~/.aegis."""
    cfg = Config(data_dir=tmp_path / "aegis-data")
    cfg.realtime_paths = [str(tmp_path / "watched")]
    (tmp_path / "watched").mkdir(parents=True, exist_ok=True)
    cfg.ensure_dirs()
    return cfg


@pytest.fixture()
def eicar_bytes() -> bytes:
    return EICAR
