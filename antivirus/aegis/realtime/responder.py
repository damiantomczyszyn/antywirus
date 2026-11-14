"""Automated response - the part that actually does something about a threat.

Detection without response is a notification service.  This module turns a
:class:`~aegis.models.FileVerdict` or :class:`~aegis.models.ProcessVerdict`
into concrete, logged, reversible action:

* files are quarantined (reversible), deleted (not reversible, opt-in) or
  merely reported, following ``config.realtime_action``;
* processes are reported or killed together with their children, following
  ``config.behavior_action``.

Self-protection is the hard rule here.  :meth:`Responder.kill_process_tree`
refuses PID 1, its own process and **any ancestor of its own process**: an
antivirus that terminates its own shell, session or desktop is worse than no
antivirus at all.  The default configuration (``behavior_action = REPORT``)
never signals anything, and ``dry_run=True`` makes every destructive path
describe itself instead of running.
"""

from __future__ import annotations

import os
import signal
import time
from typing import TYPE_CHECKING, Any, Iterable, Sequence

from ..config import Config
from ..events import EventBus, EventType
from ..models import (
    ActionKind,
    ActionResult,
    FileVerdict,
    ProcessVerdict,
    Severity,
)
from .behavior import parse_severity, severity_at_least

if TYPE_CHECKING:  # pragma: no cover - optional sibling modules
    from ..core.quarantine import Quarantine
    from ..core.scanner import Scanner

try:  # pragma: no cover - presence depends on the environment
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

__all__ = ["Responder", "HAVE_PSUTIL"]

HAVE_PSUTIL = psutil is not None

#: Grace period between SIGTERM and SIGKILL.
DEFAULT_KILL_GRACE_SEC = 1.5

#: Processes that must never be terminated, whatever a rule says.
_PROTECTED_NAMES: frozenset[str] = frozenset(
    {
        "init", "systemd", "systemd-journald", "systemd-logind", "kthreadd",
        "launchd", "wininit", "csrss", "smss", "services", "lsass", "winlogon",
        "sshd", "login",
    }
)


class Responder:
    """Applies the configured counteraction to a verdict."""

    def __init__(
        self,
        config: Config,
        bus: EventBus,
        quarantine: "Quarantine",
        *,
        dry_run: bool = False,
        scanner: "Scanner | None" = None,
    ) -> None:
        self._config = config
        self._bus = bus
        self._quarantine = quarantine
        self._scanner = scanner
        self.dry_run = bool(dry_run)
        self._counters: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Wiring / introspection
    # ------------------------------------------------------------------
    def set_scanner(self, scanner: "Scanner | None") -> None:
        """Give the responder a scanner, so it can verify files after a kill.

        :class:`aegis.realtime.watcher.RealtimeMonitor` calls this automatically
        when it is constructed with both a scanner and a responder, which keeps
        the GUI controller free of extra wiring.
        """
        if scanner is not None:
            self._scanner = scanner

    @property
    def scanner(self) -> "Scanner | None":
        return self._scanner

    @property
    def file_min_severity(self) -> Severity:
        """Severity at or above which a file threat is acted upon."""
        return parse_severity(self._config.realtime_min_severity, Severity.MEDIUM)

    @property
    def process_min_severity(self) -> Severity:
        """Severity at or above which a process is acted upon.

        Killing a process destroys work in progress, so the floor is HIGH -
        strictly stricter than the file threshold unless the configuration asks
        for something even stricter.
        """
        configured = getattr(self._config, "behavior_min_severity", None)
        if configured is not None:
            return parse_severity(configured, Severity.HIGH)
        floor = Severity.HIGH
        wanted = parse_severity(self._config.realtime_min_severity, Severity.MEDIUM)
        return wanted if severity_at_least(wanted, floor) else floor

    def stats(self) -> dict[str, Any]:
        return dict(self._counters)

    # ------------------------------------------------------------------
    # Files
    # ------------------------------------------------------------------
    def handle_file_threat(
        self, verdict: FileVerdict, *, dry_run: bool | None = None
    ) -> list[ActionResult]:
        """Quarantine / delete / report one malicious file."""
        dry = self.dry_run if dry_run is None else bool(dry_run)
        if verdict is None or not verdict.is_threat:
            return []
        if not severity_at_least(verdict.severity, self.file_min_severity):
            result = self._report(
                verdict.path,
                f"poniżej progu reakcji ({verdict.severity.value} < "
                f"{self.file_min_severity.value}) - tylko zgłoszenie",
                threat=verdict.threat_name,
            )
            self._publish(result, verdict.threat_name, severity=verdict.severity)
            return [result]

        action = ActionKind(self._config.realtime_action)
        if self._config.is_internal(verdict.path):
            # Our own vault / cache is never a target: acting on it would make
            # the monitor chase its own tail.
            result = self._report(
                verdict.path,
                "ścieżka należy do Aegis (skarbiec/cache) - pominięto",
                threat=verdict.threat_name,
                ok=False,
            )
            self._publish(result, verdict.threat_name, severity=verdict.severity)
            return [result]

        if action in (ActionKind.QUARANTINE, ActionKind.KILL_PROCESS):
            # KILL_PROCESS makes no sense for a bare file: quarantine instead.
            result = self._quarantine_file(verdict, dry=dry)
        elif action is ActionKind.DELETE:
            result = self._delete_file(verdict, dry=dry)
        else:
            result = self._report(
                verdict.path,
                f"wykryto {verdict.threat_name} ({verdict.severity.value})",
                threat=verdict.threat_name,
            )
        self._publish(result, verdict.threat_name, severity=verdict.severity)
        return [result]

    def _quarantine_file(self, verdict: FileVerdict, *, dry: bool) -> ActionResult:
        if dry:
            return self._bump(
                ActionResult(
                    kind=ActionKind.QUARANTINE,
                    target=verdict.path,
                    ok=True,
                    detail=f"[próba] plik zostałby przeniesiony do kwarantanny "
                    f"({verdict.threat_name})",
                )
            )
        if self._quarantine is None:
            return self._bump(
                ActionResult(
                    kind=ActionKind.REPORT,
                    target=verdict.path,
                    ok=False,
                    detail="brak modułu kwarantanny - tylko zgłoszenie",
                )
            )
        try:
            result = self._quarantine.quarantine(
                verdict.path, verdict, threat_name=verdict.threat_name
            )
        except Exception as exc:  # noqa: BLE001 - a failed vault must not crash realtime
            return self._bump(
                ActionResult(
                    kind=ActionKind.QUARANTINE,
                    target=verdict.path,
                    ok=False,
                    detail=f"kwarantanna nie powiodła się: {exc}",
                )
            )
        if not isinstance(result, ActionResult):  # defensive against a sibling bug
            result = ActionResult(
                kind=ActionKind.QUARANTINE,
                target=verdict.path,
                ok=bool(result),
                detail="kwarantanna zwróciła nietypowy wynik",
            )
        return self._bump(result)

    def _delete_file(self, verdict: FileVerdict, *, dry: bool) -> ActionResult:
        if dry:
            return self._bump(
                ActionResult(
                    kind=ActionKind.DELETE,
                    target=verdict.path,
                    ok=True,
                    detail=f"[próba] plik zostałby usunięty ({verdict.threat_name})",
                )
            )
        try:
            os.remove(verdict.path)
        except FileNotFoundError:
            return self._bump(
                ActionResult(
                    kind=ActionKind.DELETE,
                    target=verdict.path,
                    ok=False,
                    detail="plik już nie istnieje",
                )
            )
        except OSError as exc:
            return self._bump(
                ActionResult(
                    kind=ActionKind.DELETE,
                    target=verdict.path,
                    ok=False,
                    detail=f"nie udało się usunąć pliku: {exc}",
                )
            )
        return self._bump(
            ActionResult(
                kind=ActionKind.DELETE,
                target=verdict.path,
                ok=True,
                detail=f"plik usunięty ({verdict.threat_name})",
            )
        )

    # ------------------------------------------------------------------
    # Processes
    # ------------------------------------------------------------------
    def handle_process_threat(
        self, verdict: ProcessVerdict, *, dry_run: bool | None = None
    ) -> list[ActionResult]:
        """Kill / report one misbehaving actor, per ``config.behavior_action``."""
        dry = self.dry_run if dry_run is None else bool(dry_run)
        if verdict is None or not verdict.is_threat:
            return []

        target = f"pid:{verdict.pid}" if verdict.pid is not None else "pid:?"
        if not severity_at_least(verdict.severity, self.process_min_severity):
            result = self._report(
                target,
                f"poniżej progu reakcji ({verdict.severity.value} < "
                f"{self.process_min_severity.value}) - tylko zgłoszenie",
                threat=verdict.threat_name,
            )
            self._publish(result, verdict.threat_name, severity=verdict.severity, pid=verdict.pid)
            return [result]

        action = ActionKind(self._config.behavior_action)
        results: list[ActionResult] = []

        if action is ActionKind.KILL_PROCESS and verdict.pid is not None:
            kill = self._kill_tree(verdict.pid, dry=dry)
            results.append(kill)
            if kill.ok:
                results.extend(self._clean_after_kill(verdict, dry=dry))
        elif action is ActionKind.KILL_PROCESS:
            results.append(
                self._report(
                    target,
                    "zdarzenia nieprzypisane do procesu - nie ma czego zatrzymać, "
                    "zgłoszenie zamiast zakończenia procesu",
                    threat=verdict.threat_name,
                    ok=False,
                )
            )
        elif action in (ActionKind.QUARANTINE, ActionKind.DELETE):
            results.extend(self._quarantine_touched(verdict, dry=dry))
            if not results:
                results.append(
                    self._report(
                        target,
                        "brak plików kwalifikujących się do kwarantanny",
                        threat=verdict.threat_name,
                    )
                )
        else:
            results.append(
                self._report(
                    target,
                    f"wykryto zachowanie {verdict.threat_name} "
                    f"({verdict.severity.value}, {verdict.score:.0f}/100)",
                    threat=verdict.threat_name,
                )
            )

        for result in results:
            self._publish(result, verdict.threat_name, severity=verdict.severity, pid=verdict.pid)
        return results

    def _clean_after_kill(self, verdict: ProcessVerdict, *, dry: bool) -> list[ActionResult]:
        """After stopping an actor, put away the files it left behind."""
        return self._quarantine_touched(verdict, dry=dry)

    def _quarantine_touched(self, verdict: ProcessVerdict, *, dry: bool) -> list[ActionResult]:
        """Quarantine the actor's touched files that still look malicious.

        "Still look malicious" means a fresh scan says so.  Without a scanner
        the responder deliberately quarantines **nothing**: the files an actor
        touched are mostly the user's own documents, and sweeping them into the
        vault on a behavioural hunch would be the worst kind of false positive.
        """
        results: list[ActionResult] = []
        if self._scanner is None:
            return results
        floor = self.file_min_severity
        for path in list(verdict.touched_paths)[:64]:
            if self._config.is_internal(path):
                continue
            try:
                if not os.path.isfile(path):
                    continue
                file_verdict = self._scanner.scan_file(path)
            except Exception:  # noqa: BLE001 - a scan failure is not fatal here
                continue
            if file_verdict is None or not file_verdict.is_threat:
                continue
            if not severity_at_least(file_verdict.severity, floor):
                continue
            results.append(self._quarantine_file(file_verdict, dry=dry))
        return results

    # ------------------------------------------------------------------
    # Process termination with self-protection
    # ------------------------------------------------------------------
    def kill_process_tree(self, pid: int, *, dry_run: bool = False) -> ActionResult:
        """Terminate *pid* and its descendants, refusing anything suicidal."""
        result = self._kill_tree(pid, dry=self.dry_run or bool(dry_run))
        self._publish(result, "")
        return result

    def _kill_tree(self, pid: int, *, dry: bool) -> ActionResult:
        """Implementation of :meth:`kill_process_tree` without publishing."""
        target = f"pid:{pid}"

        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return self._refuse(target, "nieprawidłowy identyfikator procesu")

        if pid <= 0:
            return self._refuse(
                target,
                "odmowa: PID <= 0 oznaczałby grupę procesów lub cały system",
            )
        if pid == 1:
            return self._refuse(target, "odmowa: PID 1 to proces init/systemd")
        own = os.getpid()
        if pid == own:
            return self._refuse(target, "odmowa: to własny proces Aegis")

        ancestors = self._own_ancestors()
        if pid in ancestors:
            return self._refuse(
                target,
                f"odmowa: PID {pid} jest przodkiem procesu Aegis (PID {own}) - "
                "zakończenie go zabiłoby również antywirusa",
            )

        name = self._process_name(pid)
        if name and name.lower() in _PROTECTED_NAMES:
            return self._refuse(
                target, f"odmowa: {name} jest procesem chronionym systemowo"
            )

        if not self._process_exists(pid):
            return self._refuse(target, f"proces o PID {pid} nie istnieje")

        tree = self._collect_tree(pid, forbidden=ancestors | {own, 1})
        if not tree:
            return self._refuse(target, f"proces o PID {pid} nie istnieje")

        if dry:
            listing = ", ".join(str(p) for p in tree)
            return self._bump(
                ActionResult(
                    kind=ActionKind.KILL_PROCESS,
                    target=target,
                    ok=True,
                    detail=f"[próba] zakończono by {len(tree)} procesów: {listing}",
                )
            )

        grace = float(getattr(self._config, "kill_grace_sec", DEFAULT_KILL_GRACE_SEC))
        if HAVE_PSUTIL:
            killed, survivors, denied = self._kill_psutil(tree, grace)
        else:  # pragma: no cover - exercised only without psutil
            killed, survivors, denied = self._kill_posix(tree, grace)

        if denied and not killed:
            return self._refuse(
                target, f"brak uprawnień do zakończenia procesów: {sorted(denied)}"
            )
        detail = f"zakończono {killed} z {len(tree)} procesów (drzewo PID {pid})"
        if survivors:
            detail += f"; nie udało się zakończyć: {sorted(survivors)}"
        if denied:
            detail += f"; brak uprawnień: {sorted(denied)}"
        return self._bump(
            ActionResult(
                kind=ActionKind.KILL_PROCESS,
                target=target,
                ok=killed > 0,
                detail=detail,
            )
        )

    # -- termination backends -------------------------------------------
    def _kill_psutil(
        self, tree: Sequence[int], grace: float
    ) -> tuple[int, set[int], set[int]]:
        procs = []
        denied: set[int] = set()
        for pid in tree:
            try:
                procs.append(psutil.Process(pid))
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied:
                denied.add(pid)
        for proc in procs:
            try:
                proc.terminate()
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied:
                denied.add(proc.pid)
        gone, alive = psutil.wait_procs(procs, timeout=grace)
        for proc in alive:
            try:
                proc.kill()
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied:
                denied.add(proc.pid)
        gone2, alive2 = psutil.wait_procs(alive, timeout=grace)
        killed = len(gone) + len(gone2)
        return killed, {p.pid for p in alive2}, denied

    def _kill_posix(
        self, tree: Sequence[int], grace: float
    ) -> tuple[int, set[int], set[int]]:  # pragma: no cover - psutil present here
        denied: set[int] = set()
        pending: list[int] = []
        for pid in tree:
            try:
                os.kill(pid, signal.SIGTERM)
                pending.append(pid)
            except ProcessLookupError:
                continue
            except PermissionError:
                denied.add(pid)
        deadline = time.monotonic() + max(0.0, grace)
        while pending and time.monotonic() < deadline:
            pending = [pid for pid in pending if self._process_exists(pid)]
            if pending:
                time.sleep(0.05)
        for pid in pending:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                continue
            except PermissionError:
                denied.add(pid)
        time.sleep(0.05)
        survivors = {pid for pid in tree if self._process_exists(pid)}
        killed = len([pid for pid in tree if pid not in survivors and pid not in denied])
        return killed, survivors, denied

    # -- process introspection ------------------------------------------
    def _own_ancestors(self) -> set[int]:
        """Every pid between this process and the root of the process tree."""
        own = os.getpid()
        chain: set[int] = set()
        if HAVE_PSUTIL:
            try:
                for parent in psutil.Process(own).parents():
                    chain.add(parent.pid)
                return chain
            except Exception:  # noqa: BLE001 - fall through to /proc
                chain.clear()
        pid = own
        for _ in range(64):  # the loop guard also protects against a ppid cycle
            parent = self._ppid(pid)
            if parent is None or parent <= 0 or parent in chain:
                break
            chain.add(parent)
            pid = parent
        chain.add(1)
        return chain

    @staticmethod
    def _ppid(pid: int) -> int | None:
        if HAVE_PSUTIL:
            try:
                return psutil.Process(pid).ppid()
            except Exception:  # noqa: BLE001
                return None
        try:
            with open(f"/proc/{pid}/stat", "rb") as fh:
                raw = fh.read()
        except OSError:
            return None
        try:
            tail = raw[raw.rindex(b")") + 2 :].split()
            return int(tail[1])
        except (ValueError, IndexError):
            return None

    @staticmethod
    def _process_exists(pid: int) -> bool:
        if pid <= 0:
            return False
        if HAVE_PSUTIL:
            try:
                return psutil.pid_exists(pid)
            except Exception:  # noqa: BLE001
                pass
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False
        return True

    @staticmethod
    def _process_name(pid: int) -> str:
        if HAVE_PSUTIL:
            try:
                return psutil.Process(pid).name()
            except Exception:  # noqa: BLE001
                return ""
        try:
            with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as fh:
                return fh.read().strip()
        except OSError:
            return ""

    def _collect_tree(self, pid: int, *, forbidden: Iterable[int]) -> list[int]:
        """``pid`` plus its descendants, with the protected pids removed."""
        blocked = set(forbidden)
        found: list[int] = []
        if HAVE_PSUTIL:
            try:
                proc = psutil.Process(pid)
                found = [pid] + [child.pid for child in proc.children(recursive=True)]
            except Exception:  # noqa: BLE001 - fall back to /proc
                found = []
        if not found:
            found = [pid] + self._descendants_procfs(pid)
        ordered: list[int] = []
        for candidate in found:
            if candidate in blocked or candidate in ordered or candidate <= 1:
                continue
            ordered.append(candidate)
        # Children first, so a parent cannot respawn them while we work.
        ordered.sort(key=lambda p: (p == pid, p))
        return ordered

    @staticmethod
    def _descendants_procfs(pid: int) -> list[int]:
        try:
            pids = [int(name) for name in os.listdir("/proc") if name.isdigit()]
        except OSError:
            return []
        parents: dict[int, int] = {}
        for candidate in pids:
            parent = Responder._ppid(candidate)
            if parent is not None:
                parents[candidate] = parent
        out: list[int] = []
        frontier = {pid}
        for _ in range(16):  # depth guard
            children = {c for c, p in parents.items() if p in frontier and c not in out}
            children.discard(pid)
            if not children:
                break
            out.extend(sorted(children))
            frontier = children
        return out

    # ------------------------------------------------------------------
    # Bookkeeping
    # ------------------------------------------------------------------
    def _bump(self, result: ActionResult) -> ActionResult:
        key = f"{result.kind.value}_{'ok' if result.ok else 'fail'}"
        self._counters[key] = self._counters.get(key, 0) + 1
        return result

    def _refuse(self, target: str, reason: str) -> ActionResult:
        result = ActionResult(
            kind=ActionKind.KILL_PROCESS, target=target, ok=False, detail=reason
        )
        return self._bump(result)

    def _report(
        self, target: str, detail: str, *, threat: str = "", ok: bool = True
    ) -> ActionResult:
        result = ActionResult(
            kind=ActionKind.REPORT, target=target, ok=ok, detail=detail
        )
        self._bump(result)
        return result

    def _publish(
        self,
        result: ActionResult,
        threat_name: str,
        *,
        severity: Severity | None = None,
        pid: int | None = None,
    ) -> None:
        if self._bus is None:
            return
        try:
            self._bus.publish(
                EventType.ACTION_TAKEN,
                f"{result.kind.value}: {result.target} - {result.detail}",
                level="success" if result.ok else "warning",
                action=result.kind.value,
                target=result.target,
                ok=result.ok,
                detail=result.detail,
                threat_name=threat_name,
                severity=severity.value if severity else None,
                pid=pid,
            )
        except Exception:  # noqa: BLE001 - best effort
            pass
