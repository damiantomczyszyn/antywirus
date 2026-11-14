"""Command line interface - ``python3 -m aegis <polecenie>``.

Exit codes are deliberately script friendly::

    0   wszystko czyste (lub operacja się udała)
    1   znaleziono zagrożenia
    2   błąd (zły argument, niedostępny moduł, awaria operacji)

Every user facing string is Polish; docstrings and comments stay English per
the integration contract.  ``--json`` switches the output to machine readable
JSON built from the models' own ``to_dict()`` methods.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import sys
import time
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .config import Config
from .engine.verdict import explain
from .events import Event, EventType
from .gui.controller import SEVERITY_LABELS_PL, AegisController
from .models import FileVerdict, Severity

__all__ = ["main", "build_parser"]

EXIT_CLEAN = 0
EXIT_THREATS = 1
EXIT_ERROR = 2

PROG = "python3 -m aegis"

LEVEL_MARK: dict[str, str] = {
    "info": "i",
    "success": "+",
    "warning": "!",
    "error": "x",
}

#: Events worth echoing while realtime protection runs in the foreground.
REALTIME_EVENTS: frozenset[EventType] = frozenset(
    {
        EventType.THREAT_FOUND,
        EventType.BEHAVIOR_ALERT,
        EventType.ACTION_TAKEN,
        EventType.REALTIME_STARTED,
        EventType.REALTIME_STOPPED,
        EventType.LOG,
    }
)


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------
def _out(text: str = "") -> None:
    print(text)


def _err(text: str) -> None:
    print(text, file=sys.stderr)


def _dump_json(payload: Any) -> None:
    _out(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


def _interactive() -> bool:
    try:
        return sys.stdout.isatty()
    except Exception:  # noqa: BLE001
        return False


def _table(headers: Sequence[str], rows: Sequence[Sequence[Any]], indent: str = "  ") -> str:
    """Render a fixed width table; empty input renders as a dash."""
    if not rows:
        return f"{indent}(brak)"
    cells = [[str(value) for value in row] for row in rows]
    widths = [len(str(head)) for head in headers]
    for row in cells:
        for index, value in enumerate(row):
            if index < len(widths):
                widths[index] = max(widths[index], len(value))
    lines = [indent + "  ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers)).rstrip()]
    lines.append(indent + "  ".join("-" * width for width in widths))
    for row in cells:
        lines.append(
            indent + "  ".join(value.ljust(widths[i]) for i, value in enumerate(row)).rstrip()
        )
    return "\n".join(lines)


def _fmt_time(value: float | None) -> str:
    if not value:
        return "nigdy"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(value)))
    except (OSError, OverflowError, ValueError):
        return "nieznana"


def _format_event(event: Event) -> str:
    mark = LEVEL_MARK.get(event.level, "i")
    stamp = time.strftime("%H:%M:%S", time.localtime(event.timestamp))
    return f"[{stamp}] [{mark}] {event.message or event.type.value}"


def _severity_label(value: Any) -> str:
    try:
        return SEVERITY_LABELS_PL[Severity(value)]
    except (ValueError, KeyError):
        return str(value)


def _threats_of(result: Any) -> list[FileVerdict]:
    """``ScanResult.threats`` when present, otherwise filter by hand."""
    threats = getattr(result, "threats", None)
    if isinstance(threats, list):
        return [v for v in threats if isinstance(v, FileVerdict)]
    return [
        v
        for v in (getattr(result, "verdicts", []) or [])
        if isinstance(v, FileVerdict) and v.is_threat
    ]


# --------------------------------------------------------------------------
# Argument parser
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Aegis AV — hybrydowy skaner antywirusowy (wiersz poleceń).",
        epilog="Przykład: %(prog)s scan ~/Pobrane --quarantine",
    )
    parser.add_argument(
        "--version", action="version", version=f"Aegis AV {__version__}", help="pokaż wersję i wyjdź"
    )
    parser.add_argument(
        "--data-dir",
        metavar="KATALOG",
        default=None,
        help="katalog danych programu (domyślnie ~/.aegis)",
    )
    parser.add_argument("--quiet", "-q", action="store_true", help="nie pokazuj postępu")

    sub = parser.add_subparsers(dest="command", metavar="POLECENIE")

    # -- scan ----------------------------------------------------------
    scan = sub.add_parser("scan", help="przeskanuj pliki lub katalogi")
    scan.add_argument("paths", nargs="*", metavar="ŚCIEŻKA", help="pliki i katalogi do skanowania")
    recursive = scan.add_mutually_exclusive_group()
    recursive.add_argument(
        "--recursive", dest="recursive", action="store_true", default=True,
        help="wchodź w podkatalogi (domyślnie)",
    )
    recursive.add_argument(
        "--no-recursive", dest="recursive", action="store_false", help="tylko wskazany poziom"
    )
    scan.add_argument("--quick", action="store_true", help="szybkie skanowanie katalogów użytkownika")
    scan.add_argument("--full", action="store_true", help="pełne skanowanie całego systemu")
    scan.add_argument("--json", action="store_true", help="wynik w formacie JSON")
    scan.add_argument(
        "--quarantine", action="store_true", help="przenieś wykryte zagrożenia do kwarantanny"
    )

    # -- realtime ------------------------------------------------------
    realtime = sub.add_parser(
        "realtime", help="ochrona w czasie rzeczywistym (do przerwania Ctrl+C)"
    )
    realtime.add_argument(
        "--paths", nargs="+", metavar="KATALOG", default=None, help="katalogi do pilnowania"
    )
    realtime.add_argument(
        "--duration",
        type=float,
        default=None,
        metavar="SEKUNDY",
        help="zatrzymaj się automatycznie po N sekundach",
    )
    realtime.add_argument("--json", action="store_true", help="podsumowanie w formacie JSON")

    # -- update --------------------------------------------------------
    update = sub.add_parser("update", help="zaktualizuj bazę wirusów ze źródeł threat intel")
    update.add_argument(
        "--feed", action="append", metavar="ID", default=None, help="tylko wskazane źródło (można powtórzyć)"
    )
    update.add_argument("--force", action="store_true", help="pobierz nawet jeśli nic się nie zmieniło")
    update.add_argument("--json", action="store_true", help="wynik w formacie JSON")

    # -- db ------------------------------------------------------------
    db = sub.add_parser("db", help="operacje na bazie sygnatur")
    db_sub = db.add_subparsers(dest="db_command", metavar="PODPOLECENIE")
    db_stats = db_sub.add_parser("stats", help="statystyki bazy")
    db_stats.add_argument("--json", action="store_true", help="wynik w formacie JSON")
    db_export = db_sub.add_parser("export", help="wyeksportuj wskaźniki do pliku JSON")
    db_export.add_argument("path", metavar="PLIK")
    db_export.add_argument("--json", action="store_true", help="wynik w formacie JSON")
    db_import = db_sub.add_parser("import", help="zaimportuj wskaźniki z pliku JSON")
    db_import.add_argument("path", metavar="PLIK")
    db_import.add_argument("--json", action="store_true", help="wynik w formacie JSON")

    # -- quarantine ----------------------------------------------------
    quarantine = sub.add_parser("quarantine", help="zarządzaj kwarantanną")
    q_sub = quarantine.add_subparsers(dest="quarantine_command", metavar="PODPOLECENIE")
    q_list = q_sub.add_parser("list", help="pokaż zawartość kwarantanny")
    q_list.add_argument("--json", action="store_true", help="wynik w formacie JSON")
    q_restore = q_sub.add_parser("restore", help="przywróć plik z kwarantanny")
    q_restore.add_argument("entry_id", metavar="ID")
    q_restore.add_argument("--json", action="store_true", help="wynik w formacie JSON")
    q_delete = q_sub.add_parser("delete", help="usuń trwale wpis z kwarantanny")
    q_delete.add_argument("entry_id", metavar="ID")
    q_delete.add_argument("--json", action="store_true", help="wynik w formacie JSON")
    q_purge = q_sub.add_parser("purge", help="wyczyść całą kwarantannę")
    q_purge.add_argument("--yes", "-y", action="store_true", help="nie pytaj o potwierdzenie")
    q_purge.add_argument("--json", action="store_true", help="wynik w formacie JSON")

    # -- status / gui --------------------------------------------------
    status = sub.add_parser("status", help="pokaż stan ochrony")
    status.add_argument("--json", action="store_true", help="wynik w formacie JSON")

    sub.add_parser("gui", help="uruchom okno programu (Tkinter)")

    return parser


# --------------------------------------------------------------------------
# Controller construction
# --------------------------------------------------------------------------
def _build_config(args: argparse.Namespace) -> Config:
    """Never touch the real ``~/.aegis`` when ``--data-dir`` was given."""
    if getattr(args, "data_dir", None):
        return Config(data_dir=Path(args.data_dir).expanduser())
    return Config.load()


def _report_degraded(controller: AegisController, json_mode: bool) -> None:
    if json_mode or not controller.degraded:
        return
    _err(
        "Uwaga: tryb ograniczony — niedostępne moduły: "
        + ", ".join(controller.missing_subsystems())
    )


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------
def _cmd_scan(controller: AegisController, args: argparse.Namespace) -> int:
    if args.quick:
        paths = controller.quick_scan_paths()
    elif args.full:
        paths = controller.full_scan_paths()
    else:
        paths = [str(p) for p in (args.paths or [])]
    if not paths:
        _err("Podaj przynajmniej jedną ścieżkę albo użyj --quick / --full.")
        return EXIT_ERROR

    missing = [p for p in paths if not os.path.exists(p)]
    if missing and not args.json:
        for path in missing:
            _err(f"Ostrzeżenie: ścieżka nie istnieje: {path}")

    if not args.json:
        _out("Aegis AV — skanowanie")
        _out(_table(["cel"], [[p] for p in paths]))
        _out()

    if not controller.start_scan(paths, recursive=args.recursive):
        _err("Nie udało się rozpocząć skanowania (zobacz dziennik).")
        return EXIT_ERROR

    show_progress = not args.json and not args.quiet and _interactive()
    interrupted = False
    try:
        while not controller.wait_for_scan(0.2):
            if show_progress:
                progress = controller.scan_progress()
                total = progress.get("total")
                done = progress.get("done", 0)
                counter = f"{done}/{total}" if total else str(done)
                current = os.path.basename(str(progress.get("current", "")))[:48]
                sys.stdout.write(f"\r  skanowanie {counter} — {current:<48}")
                sys.stdout.flush()
    except KeyboardInterrupt:
        interrupted = True
        controller.cancel_scan()
        controller.wait_for_scan(15.0)
    finally:
        if show_progress:
            sys.stdout.write("\r" + " " * 78 + "\r")
            sys.stdout.flush()

    result = controller.last_scan()
    if result is None:
        _err("Skanowanie nie zwróciło wyniku (zobacz dziennik).")
        return EXIT_ERROR

    threats = _threats_of(result)
    actions: list[Any] = []
    if args.quarantine and threats:
        actions = controller.handle_threats(threats)

    if args.json:
        _dump_json(
            {
                "paths": paths,
                "recursive": bool(args.recursive),
                "cancelled": bool(getattr(result, "cancelled", False)) or interrupted,
                "stats": getattr(getattr(result, "stats", None), "to_dict", dict)(),
                "threats": [v.to_dict() for v in threats],
                "verdicts": [
                    v.to_dict()
                    for v in (getattr(result, "verdicts", []) or [])
                    if isinstance(v, FileVerdict)
                ],
                "actions": [a.to_dict() for a in actions if hasattr(a, "to_dict")],
                "exit_code": EXIT_THREATS if threats else EXIT_CLEAN,
            }
        )
    else:
        if interrupted:
            _out("Przerwano skanowanie na żądanie użytkownika.")
        _print_scan_summary(result, threats, actions)

    return EXIT_THREATS if threats else EXIT_CLEAN


def _print_scan_summary(result: Any, threats: Sequence[FileVerdict], actions: Sequence[Any]) -> None:
    stats = getattr(result, "stats", None)
    _out("Podsumowanie skanowania")
    _out(
        _table(
            ["pozycja", "wartość"],
            [
                ["przeskanowane pliki", int(getattr(stats, "files_scanned", 0) or 0)],
                ["pominięte pliki", int(getattr(stats, "files_skipped", 0) or 0)],
                ["przeczytane dane", f"{int(getattr(stats, 'bytes_scanned', 0) or 0) / 1048576:.1f} MB"],
                ["wykryte zagrożenia", len(threats)],
                ["błędy", int(getattr(stats, "errors", 0) or 0)],
                ["czas", f"{float(getattr(stats, 'duration', 0.0) or 0.0):.2f} s"],
                ["przerwane", "tak" if getattr(result, "cancelled", False) else "nie"],
            ],
        )
    )
    _out()

    if not threats:
        _out("Nie znaleziono zagrożeń. Obiekty czyste.")
        return

    _out(f"Wykryte zagrożenia: {len(threats)}")
    rows = []
    for verdict in threats:
        layers = sorted({d.layer.value for d in verdict.detections})
        rows.append(
            [
                verdict.path,
                verdict.threat_name or "nieznane",
                "+".join(layers) or "-",
                f"{verdict.score:.1f}",
                _severity_label(verdict.severity),
            ]
        )
    _out(_table(["ścieżka", "zagrożenie", "warstwa", "wynik", "poziom"], rows))
    _out()

    _out("Dlaczego — rozbicie analizy hybrydowej")
    for verdict in threats:
        _out(f"  === {verdict.path} ===")
        for line in explain(verdict.detections).splitlines():
            _out(f"    {line}")
        _out()

    if actions:
        _out("Wykonane akcje")
        _out(
            _table(
                ["akcja", "obiekt", "wynik", "szczegóły"],
                [
                    [
                        str(getattr(action, "kind", "?")),
                        getattr(action, "target", ""),
                        "ok" if getattr(action, "ok", False) else "błąd",
                        getattr(action, "detail", ""),
                    ]
                    for action in actions
                ],
            )
        )


# --------------------------------------------------------------------------
# realtime
# --------------------------------------------------------------------------
def _cmd_realtime(controller: AegisController, args: argparse.Namespace) -> int:
    if args.paths:
        controller.config.realtime_paths = [str(p) for p in args.paths]

    token, events = controller.bus.listen()
    if not controller.set_realtime(True):
        controller.bus.unsubscribe(token)
        _err("Nie udało się włączyć ochrony w czasie rzeczywistym.")
        return EXIT_ERROR

    status = controller.realtime_status()
    if not args.json:
        _out("Ochrona w czasie rzeczywistym — włączona")
        _out(
            _table(
                ["pozycja", "wartość"],
                [
                    ["mechanizm", status.get("backend", "?")],
                    ["pilnowane katalogi", ", ".join(status.get("paths", [])) or "(brak)"],
                    ["akcja przy wykryciu", status.get("action_label", "?")],
                    ["analiza behawioralna", "tak" if controller.behavior_status()["available"] else "nie"],
                    ["monitor procesów", controller.procmon_status().get("backend", "?")],
                ],
            )
        )
        _out("Naciśnij Ctrl+C, aby zakończyć.")
        _out()

    threats_seen = 0
    alerts_seen = 0
    deadline = time.monotonic() + args.duration if args.duration else None
    try:
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                break
            try:
                event = events.get(timeout=0.25)
            except queue.Empty:
                continue
            if event.type is EventType.THREAT_FOUND:
                threats_seen += 1
            elif event.type is EventType.BEHAVIOR_ALERT:
                alerts_seen += 1
            if not args.json and event.type in REALTIME_EVENTS:
                _out(_format_event(event))
    except KeyboardInterrupt:
        if not args.json:
            _out()
            _out("Zatrzymywanie ochrony...")
    finally:
        controller.bus.unsubscribe(token)
        controller.set_realtime(False)

    summary = {
        "threats": threats_seen,
        "behavior_alerts": alerts_seen,
        "backend": status.get("backend", "?"),
        "paths": status.get("paths", []),
    }
    if args.json:
        _dump_json(summary)
    else:
        _out()
        _out(
            _table(
                ["pozycja", "wartość"],
                [
                    ["wykryte zagrożenia", threats_seen],
                    ["alerty behawioralne", alerts_seen],
                ],
            )
        )
    return EXIT_THREATS if threats_seen else EXIT_CLEAN


# --------------------------------------------------------------------------
# update
# --------------------------------------------------------------------------
def _cmd_update(controller: AegisController, args: argparse.Namespace) -> int:
    feeds = list(args.feed) if args.feed else None
    if not args.json:
        target = ", ".join(feeds) if feeds else "wszystkie włączone źródła"
        _out(f"Aktualizacja bazy wirusów — {target}")

    if not controller.update_database(feeds, force=bool(args.force)):
        _err("Nie udało się rozpocząć aktualizacji bazy.")
        return EXIT_ERROR

    show_progress = not args.json and not args.quiet and _interactive()
    try:
        while not controller.wait_for_update(0.5):
            if show_progress:
                sys.stdout.write(".")
                sys.stdout.flush()
    except KeyboardInterrupt:
        _out()
        _out("Przerwano — czekam na zakończenie pobierania...")
        controller.wait_for_update(30.0)
    if show_progress:
        _out()

    results = controller.last_update_results()
    stats = controller.db_stats()
    failed = [r for r in results if not getattr(r, "ok", False)]

    if args.json:
        _dump_json(
            {
                "feeds": [r.to_dict() for r in results if hasattr(r, "to_dict")],
                "db": stats,
                "ok": not failed,
            }
        )
    else:
        rows = [
            [
                getattr(r, "feed_id", "?"),
                "ok" if getattr(r, "ok", False) else "błąd",
                len(getattr(r, "indicators", []) or []),
                getattr(r, "added", 0),
                getattr(r, "updated", 0),
                "tak" if getattr(r, "skipped_unchanged", False) else "nie",
                getattr(r, "error", "") or "",
            ]
            for r in results
        ]
        _out(
            _table(
                ["źródło", "status", "wskaźniki", "nowe", "zmienione", "bez zmian", "błąd"], rows
            )
        )
        _out()
        _out(f"Baza wirusów: wersja {stats.get('version', '?')}, wskaźników {stats.get('total', 0)}.")
    return EXIT_ERROR if failed else EXIT_CLEAN


# --------------------------------------------------------------------------
# db
# --------------------------------------------------------------------------
def _cmd_db(controller: AegisController, args: argparse.Namespace) -> int:
    command = getattr(args, "db_command", None)
    if command is None:
        _err("Podaj podpolecenie: stats, export albo import.")
        return EXIT_ERROR

    if command == "stats":
        stats = controller.db_stats()
        if args.json:
            _dump_json(stats)
            return EXIT_CLEAN
        _out("Baza wirusów")
        _out(
            _table(
                ["pozycja", "wartość"],
                [
                    ["wersja", stats.get("version", "?")],
                    ["wskaźniki", stats.get("total", 0)],
                    ["ostatnia aktualizacja", _fmt_time(controller.db_last_update())],
                    ["plik", str(controller.config.db_path)],
                ],
            )
        )
        _out()
        _out("Według rodzaju")
        _out(_table(["rodzaj", "liczba"], sorted((stats.get("by_kind") or {}).items())))
        _out()
        _out("Według źródła")
        _out(_table(["źródło", "liczba"], sorted((stats.get("by_source") or {}).items())))
        return EXIT_CLEAN

    if command == "export":
        count = controller.export_database(args.path)
        if args.json:
            _dump_json({"exported": count, "path": args.path})
        else:
            _out(f"Wyeksportowano wskaźników: {count} → {args.path}")
        return EXIT_CLEAN if count or os.path.exists(args.path) else EXIT_ERROR

    if command == "import":
        if not os.path.isfile(args.path):
            _err(f"Nie ma takiego pliku: {args.path}")
            return EXIT_ERROR
        added, updated = controller.import_database(args.path)
        if args.json:
            _dump_json({"added": added, "updated": updated, "path": args.path})
        else:
            _out(f"Zaimportowano: nowych {added}, zmienionych {updated}.")
        return EXIT_CLEAN

    _err(f"Nieznane podpolecenie: {command}")
    return EXIT_ERROR


# --------------------------------------------------------------------------
# quarantine
# --------------------------------------------------------------------------
def _cmd_quarantine(controller: AegisController, args: argparse.Namespace) -> int:
    command = getattr(args, "quarantine_command", None)
    if command is None:
        _err("Podaj podpolecenie: list, restore, delete albo purge.")
        return EXIT_ERROR

    if command == "list":
        entries = controller.quarantine_items()
        if args.json:
            _dump_json([entry.to_dict() for entry in entries])
            return EXIT_CLEAN
        _out(f"Kwarantanna — wpisów: {len(entries)}")
        _out(
            _table(
                ["id", "plik", "zagrożenie", "poziom", "data"],
                [
                    [
                        entry.entry_id,
                        entry.original_path,
                        entry.threat_name or "-",
                        _severity_label(entry.severity),
                        _fmt_time(entry.quarantined_at),
                    ]
                    for entry in entries
                ],
            )
        )
        return EXIT_CLEAN

    if command in ("restore", "delete"):
        result = (
            controller.restore(args.entry_id)
            if command == "restore"
            else controller.delete(args.entry_id)
        )
        if args.json:
            _dump_json(result.to_dict())
        else:
            verb = "Przywrócono" if command == "restore" else "Usunięto"
            if result.ok:
                _out(f"{verb}: {result.target} ({result.detail})")
            else:
                _err(f"Nie udało się: {result.detail}")
        return EXIT_CLEAN if result.ok else EXIT_ERROR

    if command == "purge":
        if not args.yes and _interactive():
            answer = input("Usunąć trwale całą zawartość kwarantanny? [t/N] ").strip().lower()
            if answer not in ("t", "tak", "y", "yes"):
                _out("Anulowano.")
                return EXIT_CLEAN
        removed = controller.purge_quarantine()
        if args.json:
            _dump_json({"removed": removed})
        else:
            _out(f"Usunięto wpisów: {removed}.")
        return EXIT_CLEAN

    _err(f"Nieznane podpolecenie: {command}")
    return EXIT_ERROR


# --------------------------------------------------------------------------
# status
# --------------------------------------------------------------------------
def _cmd_status(controller: AegisController, args: argparse.Namespace) -> int:
    data = controller.dashboard()
    if args.json:
        _dump_json(data)
        return EXIT_THREATS if data["status"] == "threat" else EXIT_CLEAN

    _out(f"Stan ochrony: {data['status_label'].upper()}")
    for reason in data["status_reasons"]:
        _out(f"  • {reason}")
    _out()
    counts = data["counts"]
    _out(
        _table(
            ["pozycja", "wartość"],
            [
                ["wersja bazy", data["db_version"]],
                ["wskaźniki w bazie", data["db_indicators"]],
                ["ostatnia aktualizacja", data["db_last_update_text"]],
                ["ochrona w czasie rzeczywistym", "włączona" if data["realtime"]["running"] else "wyłączona"],
                ["mechanizm", data["realtime"].get("backend", "?")],
                ["przeskanowane pliki (sesja)", counts.get("scanned", 0)],
                ["wykryte zagrożenia (sesja)", counts.get("threats", 0)],
                ["w kwarantannie", counts.get("quarantined", 0)],
                ["alerty behawioralne", counts.get("behavior_alerts", 0)],
                ["katalog danych", data["data_dir"]],
            ],
        )
    )
    if data["degraded"]:
        _out()
        _out("Tryb ograniczony — niedostępne moduły:")
        errors = controller.subsystem_errors()
        _out(_table(["moduł", "powód"], [[key, errors.get(key, "?")] for key in data["missing"]]))
    return EXIT_THREATS if data["status"] == "threat" else EXIT_CLEAN


# --------------------------------------------------------------------------
# gui
# --------------------------------------------------------------------------
def _cmd_gui(args: argparse.Namespace) -> int:
    from .gui import run

    extra: list[str] = []
    if getattr(args, "data_dir", None):
        extra += ["--data-dir", str(args.data_dir)]
    return run(extra)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if not args.command:
        parser.print_help()
        return EXIT_ERROR

    if args.command == "gui":
        try:
            return _cmd_gui(args)
        except KeyboardInterrupt:
            return EXIT_CLEAN

    json_mode = bool(getattr(args, "json", False))
    controller: AegisController | None = None
    try:
        controller = AegisController(_build_config(args))
        _report_degraded(controller, json_mode)
        if args.command == "scan":
            return _cmd_scan(controller, args)
        if args.command == "realtime":
            return _cmd_realtime(controller, args)
        if args.command == "update":
            return _cmd_update(controller, args)
        if args.command == "db":
            return _cmd_db(controller, args)
        if args.command == "quarantine":
            return _cmd_quarantine(controller, args)
        if args.command == "status":
            return _cmd_status(controller, args)
        parser.print_help()
        return EXIT_ERROR
    except KeyboardInterrupt:
        _out()
        _out("Przerwano przez użytkownika.")
        return EXIT_CLEAN
    except Exception as exc:  # noqa: BLE001 - a CLI must not print a traceback
        _err(f"Błąd: {type(exc).__name__}: {exc}")
        return EXIT_ERROR
    finally:
        if controller is not None:
            try:
                controller.shutdown()
            except Exception:  # noqa: BLE001
                pass


if __name__ == "__main__":  # pragma: no cover - module executed via __main__.py
    sys.exit(main())
