"""Process and socket monitoring - the actor attribution layer.

Filesystem events tell you *what* happened; this module tells you *who* did it
and *where they phoned*.  It samples the process table on an interval and turns
the differences into :class:`~aegis.models.BehaviorEvent` observations:

* ``PROCESS_START`` for a pid that appeared since the previous sample,
* ``PROCESS_STOP`` for a pid that disappeared,
* ``NET_CONNECT`` for a remote endpoint a pid had not been seen talking to.

Three backends, picked automatically:

``psutil``
    Full detail, cross-platform.  Preferred when the package is importable.
``procfs``
    Pure-stdlib ``/proc`` parsing on Linux, including socket inode to pid
    mapping through ``/proc/<pid>/fd``.
``none``
    Everything else.  The monitor degrades silently: :meth:`poll_once` returns
    an empty list and :meth:`start` logs why instead of raising.

Sampling a process table is inherently racy - processes exit while you iterate
them, and most of ``/proc`` is unreadable for processes you do not own.  Every
per-process read is therefore wrapped individually: one unreadable process must
never abort a poll.

The first poll only establishes a baseline and emits nothing, otherwise
starting the monitor would report every process on the machine as "new".
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..config import Config
from ..events import EventBus, EventType
from ..models import BehaviorEvent, BehaviorKind

if TYPE_CHECKING:  # pragma: no cover - optional sibling module
    from ..core.signatures import SignatureDB

from .behavior import BehaviorEngine

try:  # pragma: no cover - presence depends on the environment
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

__all__ = ["ProcessMonitor", "HAVE_PSUTIL"]

HAVE_PSUTIL = psutil is not None

#: TCP states in ``/proc/net/tcp`` that mean "this is an outbound connection".
_PROCFS_ACTIVE_STATES = frozenset({"01", "02"})  # ESTABLISHED, SYN_SENT

_MAX_CONN_PER_PID = 64       # remembered endpoints per process
_MAX_TRACKED_PIDS = 4096


@dataclass(slots=True)
class _ProcInfo:
    """One sampled process."""

    pid: int
    name: str = ""
    ppid: int | None = None
    exe: str = ""
    cmdline: str = ""
    create_time: float = 0.0
    endpoints: set[tuple[str, int]] = field(default_factory=set)


class ProcessMonitor:
    """Samples processes and outbound connections into a :class:`BehaviorEngine`."""

    def __init__(
        self,
        config: Config,
        bus: EventBus,
        behavior: BehaviorEngine,
        db: "SignatureDB | None" = None,
    ) -> None:
        self._config = config
        self._bus = bus
        self._behavior = behavior
        self._db = db
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._known: dict[int, _ProcInfo] = {}
        self._primed = False
        self._polls = 0
        self._events = 0
        self._errors = 0
        self._backend = self._pick_backend()

    # ------------------------------------------------------------------
    # Backend selection
    # ------------------------------------------------------------------
    @staticmethod
    def _pick_backend() -> str:
        if HAVE_PSUTIL:
            return "psutil"
        if os.path.isdir("/proc") and os.path.isdir("/proc/self"):
            return "procfs"
        return "none"

    @property
    def backend(self) -> str:
        return self._backend

    @property
    def is_running(self) -> bool:
        thread = self._thread
        return bool(thread and thread.is_alive() and not self._stop.is_set())

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "backend": self._backend,
                "running": self.is_running,
                "primed": self._primed,
                "processes": len(self._known),
                "polls": self._polls,
                "events": self._events,
                "errors": self._errors,
                "interval": float(self._config.procmon_interval_sec),
                "enabled": bool(getattr(self._config, "procmon_enabled", True)),
            }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Start the sampling thread (no-op when already running or disabled)."""
        if self.is_running:
            return
        if not getattr(self._config, "procmon_enabled", True):
            self._log("Monitor procesów wyłączony w konfiguracji.", level="info")
            return
        if self._backend == "none":
            self._log(
                "Monitor procesów nieaktywny: brak psutil i brak /proc na tym systemie.",
                level="warning",
            )
            return
        self._stop.clear()
        thread = threading.Thread(target=self._loop, name="aegis-procmon", daemon=True)
        self._thread = thread
        thread.start()
        self._log(
            f"Monitor procesów uruchomiony (backend: {self._backend}, "
            f"próbkowanie co {self._config.procmon_interval_sec:.1f} s).",
            level="success",
        )

    def stop(self, timeout: float = 5.0) -> None:
        """Ask the sampling thread to finish and wait for it."""
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=timeout)
        self._thread = None
        self._log("Monitor procesów zatrzymany.", level="info")

    def _loop(self) -> None:
        interval = max(0.2, float(self._config.procmon_interval_sec))
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as exc:  # noqa: BLE001 - the thread must survive anything
                with self._lock:
                    self._errors += 1
                self._log(f"Błąd próbkowania procesów: {exc}", level="error")
            self._stop.wait(interval)

    # ------------------------------------------------------------------
    # The poll itself
    # ------------------------------------------------------------------
    def poll_once(self) -> list[BehaviorEvent]:
        """Take one sample and feed the diff into the behaviour engine.

        Synchronous and thread-safe, so tests can drive it without a thread.
        The very first call primes the baseline and returns an empty list.
        """
        if self._backend == "none":
            return []

        snapshot = self._sample_processes()
        endpoints = self._sample_connections(snapshot)

        events: list[BehaviorEvent] = []
        with self._lock:
            self._polls += 1
            now = time.time()
            known = self._known

            if not self._primed:
                for pid, info in snapshot.items():
                    info.endpoints = set(list(endpoints.get(pid, ()))[:_MAX_CONN_PER_PID])
                self._known = snapshot
                self._primed = True
                return []

            for pid, info in snapshot.items():
                previous = known.get(pid)
                if previous is None or (
                    previous.create_time
                    and info.create_time
                    and previous.create_time != info.create_time
                ):
                    # New pid, or a recycled pid belonging to a different process.
                    events.append(
                        BehaviorEvent(
                            kind=BehaviorKind.PROCESS_START,
                            timestamp=now,
                            path=info.exe or None,
                            pid=pid,
                            ppid=info.ppid,
                            process=info.name,
                            cmdline=info.cmdline,
                            extra={
                                "parent_name": self._name_of(pid=info.ppid, snapshot=snapshot),
                                "exe": info.exe,
                                "create_time": info.create_time,
                                "backend": self._backend,
                            },
                        )
                    )
                else:
                    info.endpoints = set(previous.endpoints)

                for host, port in sorted(endpoints.get(pid, ())):
                    if (host, port) in info.endpoints:
                        continue
                    if len(info.endpoints) < _MAX_CONN_PER_PID:
                        info.endpoints.add((host, port))
                    events.append(
                        BehaviorEvent(
                            kind=BehaviorKind.NET_CONNECT,
                            timestamp=now,
                            path=info.exe or None,
                            pid=pid,
                            ppid=info.ppid,
                            process=info.name,
                            cmdline=info.cmdline,
                            remote_host=host,
                            remote_port=port,
                            extra={"backend": self._backend},
                        )
                    )

            for pid, previous in known.items():
                if pid in snapshot:
                    continue
                events.append(
                    BehaviorEvent(
                        kind=BehaviorKind.PROCESS_STOP,
                        timestamp=now,
                        path=previous.exe or None,
                        pid=pid,
                        ppid=previous.ppid,
                        process=previous.name,
                        cmdline=previous.cmdline,
                        extra={"backend": self._backend},
                    )
                )

            if len(snapshot) <= _MAX_TRACKED_PIDS:
                self._known = snapshot
            else:  # pathological fork bomb: keep a bounded slice
                self._known = dict(list(snapshot.items())[:_MAX_TRACKED_PIDS])
            self._events += len(events)

        for event in events:
            try:
                self._behavior.observe(event)
            except Exception:  # noqa: BLE001 - a rule bug must not kill monitoring
                with self._lock:
                    self._errors += 1
        return events

    @staticmethod
    def _name_of(*, pid: int | None, snapshot: dict[int, _ProcInfo]) -> str:
        if pid is None:
            return ""
        info = snapshot.get(pid)
        return info.name if info else ""

    # ------------------------------------------------------------------
    # Sampling backends
    # ------------------------------------------------------------------
    def _sample_processes(self) -> dict[int, _ProcInfo]:
        if self._backend == "psutil":
            return self._sample_processes_psutil()
        if self._backend == "procfs":
            return self._sample_processes_procfs()
        return {}

    def _sample_processes_psutil(self) -> dict[int, _ProcInfo]:
        out: dict[int, _ProcInfo] = {}
        fields = ["pid", "name", "ppid", "exe", "cmdline", "create_time"]
        try:
            iterator = psutil.process_iter(fields)
        except Exception:  # noqa: BLE001 - whole-table failure: give up this poll
            return out
        for proc in iterator:
            try:
                info = proc.info
                cmdline = info.get("cmdline") or []
                out[int(info["pid"])] = _ProcInfo(
                    pid=int(info["pid"]),
                    name=info.get("name") or "",
                    ppid=info.get("ppid"),
                    exe=info.get("exe") or "",
                    cmdline=" ".join(cmdline) if isinstance(cmdline, list) else str(cmdline),
                    create_time=float(info.get("create_time") or 0.0),
                )
            except Exception:  # noqa: BLE001 - process vanished or is unreadable
                continue
        return out

    def _sample_processes_procfs(self) -> dict[int, _ProcInfo]:
        out: dict[int, _ProcInfo] = {}
        try:
            entries = os.listdir("/proc")
        except OSError:
            return out
        for entry in entries:
            if not entry.isdigit():
                continue
            pid = int(entry)
            info = self._read_procfs_one(pid)
            if info is not None:
                out[pid] = info
        return out

    @staticmethod
    def _read_procfs_one(pid: int) -> _ProcInfo | None:
        base = f"/proc/{pid}"
        try:
            with open(f"{base}/stat", "rb") as fh:
                raw = fh.read()
        except OSError:
            return None  # exited between listdir() and open(): perfectly normal
        name = ""
        ppid: int | None = None
        create_time = 0.0
        try:
            start = raw.index(b"(")
            end = raw.rindex(b")")
            name = raw[start + 1 : end].decode("utf-8", "replace")
            tail = raw[end + 2 :].split()
            ppid = int(tail[1])
            create_time = float(tail[19])  # starttime in clock ticks
        except (ValueError, IndexError):
            pass
        cmdline = ""
        try:
            with open(f"{base}/cmdline", "rb") as fh:
                cmdline = fh.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except OSError:
            pass
        exe = ""
        try:
            exe = os.readlink(f"{base}/exe")
        except OSError:
            pass
        return _ProcInfo(
            pid=pid,
            name=name,
            ppid=ppid,
            exe=exe,
            cmdline=cmdline,
            create_time=create_time,
        )

    def _sample_connections(
        self, snapshot: dict[int, _ProcInfo]
    ) -> dict[int, set[tuple[str, int]]]:
        if self._backend == "psutil":
            return self._sample_connections_psutil(snapshot)
        if self._backend == "procfs":
            return self._sample_connections_procfs(snapshot)
        return {}

    @staticmethod
    def _sample_connections_psutil(
        snapshot: dict[int, _ProcInfo],
    ) -> dict[int, set[tuple[str, int]]]:
        out: dict[int, set[tuple[str, int]]] = {}

        def record(pid: Any, raddr: Any) -> None:
            if not pid or not raddr:
                return
            host = getattr(raddr, "ip", None)
            port = getattr(raddr, "port", None)
            if host is None and isinstance(raddr, (tuple, list)) and len(raddr) >= 2:
                host, port = raddr[0], raddr[1]
            if not host or not port:
                return
            out.setdefault(int(pid), set()).add((str(host), int(port)))

        try:
            for conn in psutil.net_connections(kind="inet"):
                record(conn.pid, conn.raddr)
            return out
        except Exception:  # noqa: BLE001 - usually AccessDenied; try per-process
            pass

        for pid in list(snapshot):
            try:
                proc = psutil.Process(pid)
                getter = getattr(proc, "net_connections", None) or getattr(
                    proc, "connections", None
                )
                if getter is None:
                    continue
                for conn in getter(kind="inet"):
                    record(pid, conn.raddr)
            except Exception:  # noqa: BLE001 - per-process failure is expected
                continue
        return out

    def _sample_connections_procfs(
        self, snapshot: dict[int, _ProcInfo]
    ) -> dict[int, set[tuple[str, int]]]:
        inode_map = self._procfs_socket_table()
        if not inode_map:
            return {}
        out: dict[int, set[tuple[str, int]]] = {}
        for pid in list(snapshot):
            fd_dir = f"/proc/{pid}/fd"
            try:
                fds = os.listdir(fd_dir)
            except OSError:
                continue  # not ours, or already gone
            for fd in fds:
                try:
                    link = os.readlink(f"{fd_dir}/{fd}")
                except OSError:
                    continue
                if not link.startswith("socket:["):
                    continue
                inode = link[8:-1]
                endpoint = inode_map.get(inode)
                if endpoint:
                    out.setdefault(pid, set()).add(endpoint)
        return out

    @classmethod
    def _procfs_socket_table(cls) -> dict[str, tuple[str, int]]:
        """Map socket inode -> remote endpoint, from ``/proc/net/tcp{,6}``."""
        table: dict[str, tuple[str, int]] = {}
        for name in ("tcp", "tcp6"):
            try:
                with open(f"/proc/net/{name}", "r", encoding="ascii", errors="replace") as fh:
                    lines = fh.readlines()[1:]
            except OSError:
                continue
            for line in lines:
                parts = line.split()
                if len(parts) < 10:
                    continue
                if parts[3] not in _PROCFS_ACTIVE_STATES:
                    continue
                endpoint = cls._parse_hex_endpoint(parts[2])
                if endpoint is None:
                    continue
                table[parts[9]] = endpoint
        return table

    @staticmethod
    def _parse_hex_endpoint(raw: str) -> tuple[str, int] | None:
        """Decode ``0100007F:1F90`` (little-endian hex) into ``("127.0.0.1", 8080)``."""
        if ":" not in raw:
            return None
        addr_hex, port_hex = raw.rsplit(":", 1)
        try:
            port = int(port_hex, 16)
        except ValueError:
            return None
        if port == 0:
            return None
        try:
            if len(addr_hex) == 8:
                octets = [int(addr_hex[i : i + 2], 16) for i in range(0, 8, 2)]
                host = ".".join(str(o) for o in reversed(octets))
            elif len(addr_hex) == 32:
                words = [addr_hex[i : i + 8] for i in range(0, 32, 8)]
                flat = b"".join(
                    bytes.fromhex(word)[::-1] for word in words
                )
                host = ":".join(flat[i : i + 2].hex() for i in range(0, 16, 2))
            else:
                return None
        except ValueError:
            return None
        return host, port

    # ------------------------------------------------------------------
    def _log(self, message: str, level: str = "info") -> None:
        if self._bus is None:
            return
        try:
            self._bus.publish(EventType.LOG, message, level=level, source="procmon")
        except Exception:  # noqa: BLE001 - best effort
            pass
