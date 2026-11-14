"""Tkinter window for Aegis AV - widgets and wiring only.

This module is deliberately dumb.  Every decision ("is the user protected?",
"what does this verdict mean?", "is that setting valid?") lives in
:mod:`aegis.gui.controller`; here we only create widgets, push controller data
into them and forward clicks back.

Threading contract (Tk is not thread safe)
------------------------------------------
* Scans, database updates and per-row actions are started through the
  controller, which owns the worker threads.  Nothing in this file calls a
  blocking engine method - or ``time.sleep`` - on the main thread.
* Worker threads never touch a widget.  They publish :class:`aegis.events.Event`
  objects; the window drains the queue from :meth:`EventBus.listen` inside a
  ``root.after`` timer and processes at most :data:`MAX_EVENTS_PER_TICK` of
  them per tick, so an event flood degrades into a slight delay instead of a
  frozen UI.
* Closing the window cancels the timers, unsubscribes from the bus and calls
  :meth:`AegisController.shutdown`.

Tkinter itself is imported defensively: on a Linux box without ``python3-tk``
importing this module still succeeds and :func:`main` prints a Polish
explanation naming the fix instead of dumping an ``ImportError`` traceback.
"""

from __future__ import annotations

import argparse
import os
import queue
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

from ..config import Config
from ..events import Event, EventType
from .controller import AegisController

_TK_IMPORT_ERROR: Exception | None = None
try:  # pragma: no cover - exercised by whichever branch the host supports
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk
except Exception as exc:  # noqa: BLE001 - a missing Tk must not break imports
    tk = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]
    filedialog = None  # type: ignore[assignment]
    messagebox = None  # type: ignore[assignment]
    scrolledtext = None  # type: ignore[assignment]
    _TK_IMPORT_ERROR = exc

__all__ = ["AegisApp", "main", "tkinter_available", "TK_MISSING_MESSAGE"]

TK_MISSING_MESSAGE = """\
Nie można uruchomić okna programu: w tym Pythonie brakuje biblioteki Tkinter.

Tkinter jest standardową częścią Pythona, ale w niektórych systemach
Linux trzeba go doinstalować osobno:

  Debian / Ubuntu / Mint   sudo apt install python3-tk
  Fedora / RHEL / Rocky    sudo dnf install python3-tkinter
  Arch / Manjaro           sudo pacman -S tk
  openSUSE                 sudo zypper install python3-tk
  Windows / macOS          zainstaluj Pythona z python.org (Tkinter jest w zestawie)

Do tego czasu cała funkcjonalność jest dostępna z wiersza poleceń:

  python3 -m aegis status
  python3 -m aegis scan ~/Pobrane --quarantine
  python3 -m aegis update
  python3 -m aegis --help
"""

NO_DISPLAY_MESSAGE = """\
Nie można otworzyć okna: brak dostępu do serwera graficznego.

Jeśli łączysz się przez SSH, włącz przekierowanie X11 (ssh -X) albo
uruchom program lokalnie.  W środowisku bez grafiki użyj wiersza poleceń:

  python3 -m aegis status
  python3 -m aegis scan ~/Pobrane
"""

# -- timings ---------------------------------------------------------------
POLL_MS = 100            # how often the event queue is drained
REFRESH_MS = 700         # how often the dashboard labels are refreshed
MAX_EVENTS_PER_TICK = 300  # bounded batch: a flood must not freeze the UI
MAX_LOG_LINES = 2000
MAX_ALERT_ROWS = 300

# -- palette ---------------------------------------------------------------
STATUS_COLORS: dict[str, str] = {
    "protected": "#1e8e3e",
    "warning": "#c77700",
    "threat": "#c5221f",
}
SEVERITY_COLORS: dict[str, str] = {
    "clean": "#1e8e3e",
    "low": "#8a6d00",
    "medium": "#c77700",
    "high": "#c5221f",
    "critical": "#8c1411",
}
LEVEL_COLORS: dict[str, str] = {
    "info": "#263238",
    "success": "#1e8e3e",
    "warning": "#c77700",
    "error": "#c5221f",
}
LEVEL_FILTERS: list[tuple[str, str]] = [
    ("Wszystko", ""),
    ("Ostrzeżenia i błędy", "warning"),
    ("Tylko błędy", "error"),
]

if sys.platform == "win32":  # pragma: no cover - platform dependent
    FONT = "Segoe UI"
elif sys.platform == "darwin":  # pragma: no cover - platform dependent
    FONT = "Helvetica Neue"
else:
    FONT = "DejaVu Sans"

FONT_BANNER = (FONT, 26, "bold")
FONT_H1 = (FONT, 14, "bold")
FONT_H2 = (FONT, 11, "bold")
FONT_BODY = (FONT, 10)
FONT_COUNTER = (FONT, 20, "bold")
FONT_MONO = ("Courier New" if sys.platform == "win32" else "monospace", 10)


def tkinter_available() -> bool:
    """``False`` on a box where ``import tkinter`` fails."""
    return tk is not None


class AegisApp:
    """The main window: a notebook with seven tabs, in Polish."""

    def __init__(self, controller: AegisController | None = None, root: Any | None = None) -> None:
        if tk is None:  # pragma: no cover - guarded by main()
            raise RuntimeError(TK_MISSING_MESSAGE)
        self.controller = controller if controller is not None else AegisController()
        self.root = root if root is not None else tk.Tk()
        self.ui_errors: list[str] = []

        self._closing = False
        self._dashboard: dict[str, Any] = {}
        self._after_ids: list[Any] = []
        self._progress_indeterminate = False
        self._update_progress_running = False
        self._log_lines = 0
        self._choice_values: dict[str, dict[str, str]] = {}
        self._choice_labels: dict[str, dict[str, str]] = {}
        self._setting_widgets: dict[str, tuple[str, Any]] = {}

        self._event_token, self._events = self.controller.bus.listen(maxsize=8000)

        self._build_window()
        self._refresh_all()
        self._replay_history()
        self._schedule(POLL_MS, self._pump)
        self._schedule(REFRESH_MS, self._tick_refresh)

        if self.controller.config.realtime_enabled:
            self.controller.run_background(
                self.controller.set_realtime, True, label="ochrona w czasie rzeczywistym"
            )

    # ==================================================================
    # Infrastructure
    # ==================================================================
    def _schedule(self, delay: int, callback: Callable[[], None]) -> None:
        if self._closing:
            return
        try:
            self._after_ids.append(self.root.after(delay, callback))
        except Exception as exc:  # noqa: BLE001
            self._note_error("after", exc)

    def _note_error(self, where: str, exc: BaseException) -> None:
        """Record a UI level failure instead of letting Tk print a traceback."""
        message = f"{where}: {type(exc).__name__}: {exc}"
        self.ui_errors.append(message)
        try:
            self.controller.bus.publish(
                EventType.LOG, f"Błąd interfejsu ({message})", level="error"
            )
        except Exception:  # noqa: BLE001
            pass

    def _guard(self, where: str, func: Callable[..., Any], *args: Any) -> Any:
        try:
            return func(*args)
        except Exception as exc:  # noqa: BLE001 - one bad widget call must not stop the loop
            self._note_error(where, exc)
            return None

    def _status(self, text: str) -> None:
        self.var_status.set(text)

    # ==================================================================
    # Window skeleton
    # ==================================================================
    def _build_window(self) -> None:
        self.root.title("Aegis AV — ochrona hybrydowa")
        self._guard("geometry", self.root.geometry, "1180x780")
        self._guard("minsize", self.root.minsize, 980, 640)
        self._guard("protocol", self.root.protocol, "WM_DELETE_WINDOW", self.on_close)

        self.style = ttk.Style(self.root)
        for theme in ("clam", "vista", "aqua", "default"):
            try:
                self.style.theme_use(theme)
                break
            except Exception:  # noqa: BLE001 - theme availability differs per OS
                continue

        self.var_status = tk.StringVar(value="Gotowy.")
        self.status_bar = ttk.Label(
            self.root, textvariable=self.var_status, anchor="w", relief="sunken", padding=4
        )
        self.status_bar.pack(side="bottom", fill="x")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(side="top", fill="both", expand=True, padx=8, pady=8)

        self.tab_dashboard = ttk.Frame(self.notebook, padding=12)
        self.tab_scan = ttk.Frame(self.notebook, padding=12)
        self.tab_quarantine = ttk.Frame(self.notebook, padding=12)
        self.tab_realtime = ttk.Frame(self.notebook, padding=12)
        self.tab_database = ttk.Frame(self.notebook, padding=12)
        self.tab_log = ttk.Frame(self.notebook, padding=12)
        self.tab_settings = ttk.Frame(self.notebook, padding=12)

        self.notebook.add(self.tab_dashboard, text="Pulpit")
        self.notebook.add(self.tab_scan, text="Skanowanie")
        self.notebook.add(self.tab_quarantine, text="Kwarantanna")
        self.notebook.add(self.tab_realtime, text="Ochrona w czasie rzeczywistym")
        self.notebook.add(self.tab_database, text="Baza wirusów")
        self.notebook.add(self.tab_log, text="Dziennik")
        self.notebook.add(self.tab_settings, text="Ustawienia")

        self._build_dashboard_tab()
        self._build_scan_tab()
        self._build_quarantine_tab()
        self._build_realtime_tab()
        self._build_database_tab()
        self._build_log_tab()
        self._build_settings_tab()

    def _make_tree(
        self,
        parent: Any,
        columns: Sequence[str],
        headings: Sequence[str],
        widths: Sequence[int],
        *,
        height: int = 12,
        severity_tags: bool = False,
    ) -> Any:
        """A Treeview plus its scrollbar, packed into its own frame."""
        holder = ttk.Frame(parent)
        holder.pack(fill="both", expand=True)
        tree = ttk.Treeview(
            holder, columns=list(columns), show="headings", height=height, selectmode="browse"
        )
        for column, heading, width in zip(columns, headings, widths):
            tree.heading(column, text=heading)
            tree.column(column, width=width, anchor="w", stretch=True)
        bar = ttk.Scrollbar(holder, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=bar.set)
        tree.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")
        if severity_tags:
            for tag, colour in SEVERITY_COLORS.items():
                tree.tag_configure(tag, foreground=colour)
        return tree

    @staticmethod
    def _clear_tree(tree: Any) -> None:
        children = tree.get_children()
        if children:
            tree.delete(*children)

    @staticmethod
    def _selected(tree: Any) -> str | None:
        selection = tree.selection()
        if not selection:
            return None
        first = selection[0] if isinstance(selection, (list, tuple)) else selection
        return str(first)

    # ==================================================================
    # Tab 1 - Pulpit
    # ==================================================================
    def _build_dashboard_tab(self) -> None:
        parent = self.tab_dashboard

        self.banner = tk.Label(
            parent,
            text="Sprawdzanie...",
            font=FONT_BANNER,
            bg=STATUS_COLORS["warning"],
            fg="#ffffff",
            padx=20,
            pady=18,
        )
        self.banner.pack(fill="x")

        self.var_banner_detail = tk.StringVar(value="")
        self.banner_detail = ttk.Label(
            parent, textvariable=self.var_banner_detail, font=FONT_BODY, wraplength=1040,
            justify="left", anchor="w",
        )
        self.banner_detail.pack(fill="x", pady=(8, 12))

        switch_box = ttk.LabelFrame(parent, text="Ochrona w czasie rzeczywistym", padding=10)
        switch_box.pack(fill="x")
        self.var_realtime = tk.BooleanVar(value=False)
        self.chk_realtime = ttk.Checkbutton(
            switch_box,
            text="Włączona",
            variable=self.var_realtime,
            command=self.on_toggle_realtime,
        )
        self.chk_realtime.pack(side="left")
        self.var_realtime_detail = tk.StringVar(value="")
        ttk.Label(switch_box, textvariable=self.var_realtime_detail, font=FONT_BODY).pack(
            side="left", padx=16
        )

        db_box = ttk.LabelFrame(parent, text="Baza wirusów", padding=10)
        db_box.pack(fill="x", pady=12)
        self.var_db_version = tk.StringVar(value="-")
        self.var_db_count = tk.StringVar(value="-")
        self.var_db_updated = tk.StringVar(value="-")
        for column, (caption, variable) in enumerate(
            (
                ("Wersja bazy", self.var_db_version),
                ("Liczba wskaźników", self.var_db_count),
                ("Ostatnia aktualizacja", self.var_db_updated),
            )
        ):
            ttk.Label(db_box, text=caption, font=FONT_BODY).grid(
                row=0, column=column, sticky="w", padx=(0, 28)
            )
            ttk.Label(db_box, textvariable=variable, font=FONT_H2).grid(
                row=1, column=column, sticky="w", padx=(0, 28)
            )

        counters = ttk.LabelFrame(parent, text="Licznik tej sesji", padding=10)
        counters.pack(fill="x")
        self.var_count_scanned = tk.StringVar(value="0")
        self.var_count_threats = tk.StringVar(value="0")
        self.var_count_quarantined = tk.StringVar(value="0")
        for column, (caption, variable) in enumerate(
            (
                ("Przeskanowane pliki", self.var_count_scanned),
                ("Wykryte zagrożenia", self.var_count_threats),
                ("W kwarantannie", self.var_count_quarantined),
            )
        ):
            ttk.Label(counters, textvariable=variable, font=FONT_COUNTER).grid(
                row=0, column=column, sticky="w", padx=(0, 48)
            )
            ttk.Label(counters, text=caption, font=FONT_BODY).grid(
                row=1, column=column, sticky="w", padx=(0, 48)
            )

        actions = ttk.Frame(parent)
        actions.pack(fill="x", pady=(16, 0))
        self.btn_quick = ttk.Button(
            actions, text="Szybkie skanowanie", command=self.on_quick_scan, width=24
        )
        self.btn_quick.pack(side="left", padx=(0, 10))
        self.btn_full = ttk.Button(
            actions, text="Pełne skanowanie", command=self.on_full_scan, width=24
        )
        self.btn_full.pack(side="left", padx=(0, 10))
        self.btn_update = ttk.Button(
            actions, text="Aktualizuj bazę", command=self.on_update_all, width=24
        )
        self.btn_update.pack(side="left")

    # ==================================================================
    # Tab 2 - Skanowanie
    # ==================================================================
    def _build_scan_tab(self) -> None:
        parent = self.tab_scan

        bar = ttk.Frame(parent)
        bar.pack(fill="x")
        ttk.Button(bar, text="Wybierz plik...", command=self.on_scan_file).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(bar, text="Wybierz folder...", command=self.on_scan_folder).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(bar, text="Szybkie skanowanie", command=self.on_quick_scan).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(bar, text="Pełne skanowanie", command=self.on_full_scan).pack(
            side="left", padx=(0, 8)
        )
        self.btn_cancel = ttk.Button(bar, text="Anuluj", command=self.on_cancel_scan)
        self.btn_cancel.pack(side="left", padx=(16, 0))

        progress_box = ttk.LabelFrame(parent, text="Postęp", padding=10)
        progress_box.pack(fill="x", pady=12)
        self.var_progress = tk.IntVar(value=0)
        self.scan_progress = ttk.Progressbar(
            progress_box, mode="determinate", maximum=100, variable=self.var_progress
        )
        self.scan_progress.pack(fill="x")
        self.var_scan_current = tk.StringVar(value="Bezczynny.")
        ttk.Label(
            progress_box, textvariable=self.var_scan_current, font=FONT_BODY, anchor="w"
        ).pack(fill="x", pady=(6, 0))

        ttk.Label(parent, text="Wyniki", font=FONT_H2, anchor="w").pack(fill="x")
        self.scan_tree = self._make_tree(
            parent,
            ("path", "threat", "layers", "result", "severity"),
            ("Ścieżka", "Zagrożenie", "Warstwa", "Wynik", "Poziom"),
            (440, 220, 150, 130, 90),
            height=14,
            severity_tags=True,
        )
        self.scan_tree.bind("<Double-1>", self.on_scan_details)
        self.scan_tree.bind("<Return>", self.on_scan_details)

        row_actions = ttk.Frame(parent)
        row_actions.pack(fill="x", pady=(10, 0))
        ttk.Button(row_actions, text="Szczegóły", command=self.on_scan_details).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(row_actions, text="Kwarantanna", command=self.on_row_quarantine).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(row_actions, text="Usuń", command=self.on_row_delete).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(row_actions, text="Ignoruj", command=self.on_row_ignore).pack(side="left")
        ttk.Label(
            row_actions,
            text="Podwójne kliknięcie wiersza pokazuje, dlaczego plik został oznaczony.",
            font=FONT_BODY,
        ).pack(side="right")

    # ==================================================================
    # Tab 3 - Kwarantanna
    # ==================================================================
    def _build_quarantine_tab(self) -> None:
        parent = self.tab_quarantine
        ttk.Label(
            parent,
            text="Pliki w skarbcu są zaciemnione i nie mogą zostać uruchomione.",
            font=FONT_BODY,
            anchor="w",
        ).pack(fill="x", pady=(0, 10))

        self.quarantine_tree = self._make_tree(
            parent,
            ("path", "threat", "severity", "date", "size"),
            ("Plik", "Zagrożenie", "Poziom", "Data", "Rozmiar"),
            (430, 230, 100, 170, 100),
            height=16,
            severity_tags=True,
        )
        self.quarantine_tree.bind("<Double-1>", self.on_quarantine_details)

        actions = ttk.Frame(parent)
        actions.pack(fill="x", pady=(10, 0))
        ttk.Button(actions, text="Przywróć", command=self.on_quarantine_restore).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(actions, text="Usuń trwale", command=self.on_quarantine_delete).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(actions, text="Przeskanuj ponownie", command=self.on_quarantine_rescan).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(actions, text="Szczegóły", command=self.on_quarantine_details).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(actions, text="Wyczyść wszystko", command=self.on_quarantine_purge).pack(
            side="right"
        )

    # ==================================================================
    # Tab 4 - Ochrona w czasie rzeczywistym
    # ==================================================================
    def _build_realtime_tab(self) -> None:
        parent = self.tab_realtime

        top = ttk.Frame(parent)
        top.pack(fill="x")
        self.var_realtime_tab = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            top,
            text="Ochrona w czasie rzeczywistym włączona",
            variable=self.var_realtime_tab,
            command=self.on_toggle_realtime_tab,
        ).pack(side="left")
        self.var_realtime_backend = tk.StringVar(value="")
        ttk.Label(top, textvariable=self.var_realtime_backend, font=FONT_BODY).pack(
            side="left", padx=16
        )

        self.var_behavior_status = tk.StringVar(value="")
        ttk.Label(
            parent, textvariable=self.var_behavior_status, font=FONT_BODY, anchor="w",
            wraplength=1040, justify="left",
        ).pack(fill="x", pady=(8, 12))

        paths_box = ttk.LabelFrame(parent, text="Pilnowane katalogi", padding=10)
        paths_box.pack(fill="x")
        self.paths_tree = self._make_tree(
            paths_box, ("path",), ("Katalog",), (820,), height=5
        )
        path_actions = ttk.Frame(paths_box)
        path_actions.pack(fill="x", pady=(8, 0))
        ttk.Button(path_actions, text="Dodaj katalog...", command=self.on_add_path).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(path_actions, text="Usuń katalog", command=self.on_remove_path).pack(side="left")

        rules_box = ttk.LabelFrame(parent, text="Uzbrojone reguły behawioralne", padding=10)
        rules_box.pack(fill="both", expand=True, pady=12)
        self.rules_tree = self._make_tree(
            rules_box,
            ("rule", "name", "score", "description"),
            ("Reguła", "Nazwa", "Waga", "Opis"),
            (180, 220, 70, 520),
            height=6,
        )

        alerts_box = ttk.LabelFrame(parent, text="Alerty behawioralne (na żywo)", padding=10)
        alerts_box.pack(fill="both", expand=True)
        self.alerts_tree = self._make_tree(
            alerts_box,
            ("time", "process", "rule", "message"),
            ("Czas", "Proces", "Reguła", "Opis"),
            (90, 180, 160, 560),
            height=6,
        )

    # ==================================================================
    # Tab 5 - Baza wirusów
    # ==================================================================
    def _build_database_tab(self) -> None:
        parent = self.tab_database

        self.feeds_tree = self._make_tree(
            parent,
            ("enabled", "name", "source", "status", "indicators", "updated"),
            ("Włączone", "Nazwa", "Źródło", "Status", "Liczba wskaźników", "Ostatnia aktualizacja"),
            (80, 220, 320, 120, 130, 170),
            height=10,
        )
        self.feeds_tree.bind("<Button-1>", self.on_feed_click)
        self.feeds_tree.bind("<space>", self.on_feed_toggle)

        actions = ttk.Frame(parent)
        actions.pack(fill="x", pady=(10, 0))
        ttk.Button(actions, text="Włącz / wyłącz źródło", command=self.on_feed_toggle).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(actions, text="Aktualizuj wybrane", command=self.on_update_selected).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(actions, text="Aktualizuj wszystkie", command=self.on_update_all).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(actions, text="Eksport bazy...", command=self.on_export_db).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(actions, text="Import bazy...", command=self.on_import_db).pack(side="left")

        self.update_progress = ttk.Progressbar(parent, mode="determinate", maximum=100)
        self.update_progress.pack(fill="x", pady=(10, 0))
        self.var_db_summary = tk.StringVar(value="")
        ttk.Label(parent, textvariable=self.var_db_summary, font=FONT_BODY, anchor="w").pack(
            fill="x", pady=(6, 12)
        )

        stats = ttk.Frame(parent)
        stats.pack(fill="both", expand=True)
        kinds = ttk.LabelFrame(stats, text="Wskaźniki według rodzaju", padding=8)
        kinds.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.kinds_tree = self._make_tree(
            kinds, ("kind", "count"), ("Rodzaj", "Liczba"), (220, 110), height=7
        )
        sources = ttk.LabelFrame(stats, text="Wskaźniki według źródła", padding=8)
        sources.pack(side="left", fill="both", expand=True)
        self.sources_tree = self._make_tree(
            sources, ("source", "count"), ("Źródło", "Liczba"), (220, 110), height=7
        )

    # ==================================================================
    # Tab 6 - Dziennik
    # ==================================================================
    def _build_log_tab(self) -> None:
        parent = self.tab_log

        bar = ttk.Frame(parent)
        bar.pack(fill="x")
        ttk.Label(bar, text="Filtr:", font=FONT_BODY).pack(side="left", padx=(0, 6))
        self.var_log_filter = tk.StringVar(value=LEVEL_FILTERS[0][0])
        self.cmb_log_filter = ttk.Combobox(
            bar,
            textvariable=self.var_log_filter,
            values=[label for label, _ in LEVEL_FILTERS],
            state="readonly",
            width=24,
        )
        self.cmb_log_filter.pack(side="left")
        self.cmb_log_filter.bind("<<ComboboxSelected>>", self.on_log_filter)
        ttk.Button(bar, text="Zapisz do pliku...", command=self.on_save_log).pack(
            side="right", padx=(8, 0)
        )
        ttk.Button(bar, text="Wyczyść widok", command=self.on_clear_log).pack(side="right")

        self.log_text = scrolledtext.ScrolledText(parent, wrap="word", height=26, font=FONT_MONO)
        self.log_text.pack(fill="both", expand=True, pady=(10, 0))
        for level, colour in LEVEL_COLORS.items():
            self.log_text.tag_configure(level, foreground=colour)
        self.log_text.configure(state="disabled")

    # ==================================================================
    # Tab 7 - Ustawienia
    # ==================================================================
    def _build_settings_tab(self) -> None:
        parent = self.tab_settings
        ttk.Label(
            parent,
            text="Zmiany obowiązują od razu; „Zapisz” utrwala je w pliku konfiguracyjnym.",
            font=FONT_BODY,
            anchor="w",
        ).pack(fill="x", pady=(0, 10))

        grid = ttk.Frame(parent)
        grid.pack(fill="x")
        simple = [f for f in self.controller.settings_fields() if f["kind"] != "list"]
        lists = [f for f in self.controller.settings_fields() if f["kind"] == "list"]

        for index, field in enumerate(simple):
            row, column = divmod(index, 2)
            base = column * 3
            ttk.Label(grid, text=field["label"], font=FONT_BODY).grid(
                row=row, column=base, sticky="w", padx=(0, 8), pady=4
            )
            widget = self._build_setting_widget(grid, field)
            widget.grid(row=row, column=base + 1, sticky="w", padx=(0, 28), pady=4)

        for field in lists:
            box = ttk.LabelFrame(parent, text=field["label"], padding=8)
            box.pack(fill="both", expand=True, pady=10)
            text = tk.Text(box, height=5, wrap="none", font=FONT_MONO)
            text.pack(fill="both", expand=True)
            self._setting_widgets[field["key"]] = ("list", text)

        buttons = ttk.Frame(parent)
        buttons.pack(fill="x", pady=(12, 0))
        ttk.Button(buttons, text="Zapisz", command=self.on_save_settings).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(buttons, text="Przywróć domyślne", command=self.on_reset_settings).pack(
            side="left"
        )
        self.var_settings_hint = tk.StringVar(value="")
        ttk.Label(buttons, textvariable=self.var_settings_hint, font=FONT_BODY).pack(
            side="left", padx=16
        )

    def _build_setting_widget(self, parent: Any, field: dict[str, Any]) -> Any:
        key = field["key"]
        kind = field["kind"]
        if kind == "bool":
            variable = tk.BooleanVar(value=False)
            self._setting_widgets[key] = ("bool", variable)
            return ttk.Checkbutton(parent, text="tak", variable=variable)
        if kind == "choice":
            labels = {value: label for value, label in field.get("choices", ())}
            self._choice_labels[key] = labels
            self._choice_values[key] = {label: value for value, label in labels.items()}
            variable = tk.StringVar(value="")
            self._setting_widgets[key] = ("choice", variable)
            return ttk.Combobox(
                parent,
                textvariable=variable,
                values=list(labels.values()),
                state="readonly",
                width=18,
            )
        variable = tk.StringVar(value="")
        self._setting_widgets[key] = (kind, variable)
        return ttk.Entry(parent, textvariable=variable, width=20)

    # ==================================================================
    # Refresh
    # ==================================================================
    def _refresh_all(self) -> None:
        self._guard("refresh_dashboard", self._refresh_dashboard)
        self._guard("refresh_quarantine", self._refresh_quarantine)
        self._guard("refresh_realtime", self._refresh_realtime)
        self._guard("refresh_feeds", self._refresh_feeds)
        self._guard("refresh_settings", self._refresh_settings)

    def _tick_refresh(self) -> None:
        if self._closing:
            return
        self._guard("refresh_dashboard", self._refresh_dashboard)
        self._guard("refresh_progress", self._refresh_progress)
        self._schedule(REFRESH_MS, self._tick_refresh)

    def _refresh_dashboard(self) -> None:
        data = self.controller.dashboard()
        self._dashboard = data
        self.banner.configure(
            text=data["status_label"].upper(),
            bg=STATUS_COLORS.get(data["status"], STATUS_COLORS["warning"]),
        )
        self.var_banner_detail.set("\n".join(f"• {line}" for line in data["status_reasons"]))

        realtime = data["realtime"]
        self.var_realtime.set(bool(realtime["running"]))
        self.var_realtime_tab.set(bool(realtime["running"]))
        if not realtime["available"]:
            detail = "moduł niedostępny (tryb ograniczony)"
        elif realtime["running"]:
            detail = f"działa, mechanizm: {realtime.get('backend', '?')}"
        else:
            detail = "wyłączona — pliki nie są sprawdzane w tle"
        self.var_realtime_detail.set(detail)

        self.var_db_version.set(str(data["db_version"]))
        self.var_db_count.set(f"{data['db_indicators']:,}".replace(",", " "))
        self.var_db_updated.set(str(data["db_last_update_text"]))

        counts = data["counts"]
        self.var_count_scanned.set(str(counts.get("scanned", 0)))
        self.var_count_threats.set(str(counts.get("threats", 0)))
        self.var_count_quarantined.set(str(counts.get("quarantined", 0)))

        self.btn_cancel.configure(state="normal" if data["scan"]["running"] else "disabled")
        scan_state = "disabled" if data["scan"]["running"] else "normal"
        self.btn_quick.configure(state=scan_state)
        self.btn_full.configure(state=scan_state)
        self.btn_update.configure(state="disabled" if data["update_running"] else "normal")

        if data["update_running"] and not self._update_progress_running:
            self._update_progress_running = True
            self._guard("update_progress", self.update_progress.configure, {"mode": "indeterminate"})
            self._guard("update_progress_start", self.update_progress.start, 80)
        elif not data["update_running"] and self._update_progress_running:
            self._update_progress_running = False
            self._guard("update_progress_stop", self.update_progress.stop)
            self._guard("update_progress", self.update_progress.configure, {"mode": "determinate"})

        self._status(
            f"Stan: {data['status_label']} · baza {data['db_version']} "
            f"({data['db_indicators']} wskaźników) · ochrona w czasie rzeczywistym: "
            f"{'włączona' if realtime['running'] else 'wyłączona'} · "
            f"przeskanowano {counts.get('scanned', 0)}"
        )

    def _refresh_progress(self) -> None:
        progress = self.controller.scan_progress()
        if progress["running"]:
            total = progress.get("total")
            done = progress.get("done", 0)
            current = str(progress.get("current", ""))
            if total:
                self._set_progress(progress.get("percent", 0.0))
                self.var_scan_current.set(f"{done}/{total} — {current}")
            else:
                self._set_progress(None)
                self.var_scan_current.set(f"{done} plików — {current}")
        else:
            self._set_progress(progress.get("percent", 0.0) if progress.get("finished_at") else 0.0)
            if progress.get("finished_at"):
                verb = "przerwane" if progress.get("cancelled") else "zakończone"
                self.var_scan_current.set(
                    f"Skanowanie {verb}: {progress.get('done', 0)} plików, "
                    f"zagrożeń {progress.get('threats', 0)}."
                )
            else:
                self.var_scan_current.set("Bezczynny.")

    def _set_progress(self, percent: float | None) -> None:
        if percent is None:
            if not self._progress_indeterminate:
                self._progress_indeterminate = True
                self._guard("progress_mode", self.scan_progress.configure, {"mode": "indeterminate"})
                self._guard("progress_start", self.scan_progress.start, 60)
            return
        if self._progress_indeterminate:
            self._progress_indeterminate = False
            self._guard("progress_stop", self.scan_progress.stop)
            self._guard("progress_mode", self.scan_progress.configure, {"mode": "determinate"})
        self.var_progress.set(int(max(0.0, min(100.0, float(percent)))))

    def _refresh_quarantine(self) -> None:
        self._clear_tree(self.quarantine_tree)
        for row in self.controller.quarantine_rows():
            self.quarantine_tree.insert(
                "",
                "end",
                iid=row["entry_id"],
                values=(row["path"], row["threat"], row["severity_label"], row["date"], row["size_text"]),
                tags=(row["severity"],),
            )

    def _refresh_realtime(self) -> None:
        status = self.controller.realtime_status()
        self.var_realtime_tab.set(bool(status["running"]))
        procmon = self.controller.procmon_status()
        self.var_realtime_backend.set(
            f"mechanizm plików: {status.get('backend', '?')} · "
            f"monitor procesów: {procmon.get('backend', '?')}"
        )
        behavior = self.controller.behavior_status()
        self.var_behavior_status.set(
            f"Silnik behawioralny: {'aktywny' if behavior['available'] and behavior['enabled'] else 'nieaktywny'}"
            f" · reguły: {behavior['rules']}"
            f" · śledzone procesy: {behavior['tracked']}"
            f" · podejrzane: {behavior['threats']}"
            f" · alerty: {behavior['alerts']}"
            f" · okno korelacji: {behavior['window_sec']:.0f} s"
            f" · próg operacji masowych: {behavior['mass_ops_threshold']}"
            f" · próg entropii: {behavior['entropy_threshold']}"
        )

        self._clear_tree(self.paths_tree)
        for path in self.controller.config.realtime_paths or []:
            self.paths_tree.insert("", "end", iid=str(path), values=(str(path),))

        self._clear_tree(self.rules_tree)
        for rule in self.controller.behavior_rules():
            self.rules_tree.insert(
                "",
                "end",
                values=(
                    rule.get("id", "?"),
                    rule.get("name", ""),
                    rule.get("score", ""),
                    rule.get("description", ""),
                ),
            )

        self._clear_tree(self.alerts_tree)
        for alert in self.controller.recent_alerts(MAX_ALERT_ROWS):
            self._insert_alert(alert)

    def _insert_alert(self, alert: dict[str, Any]) -> None:
        process = alert.get("process") or "(nieprzypisane)"
        if alert.get("pid"):
            process = f"{process} [{alert['pid']}]"
        self.alerts_tree.insert(
            "",
            0,
            values=(alert.get("time", ""), process, alert.get("rule", ""), alert.get("message", "")),
        )
        children = self.alerts_tree.get_children()
        if len(children) > MAX_ALERT_ROWS:
            self.alerts_tree.delete(*children[MAX_ALERT_ROWS:])

    def _refresh_feeds(self) -> None:
        self._clear_tree(self.feeds_tree)
        for feed in self.controller.feeds():
            self.feeds_tree.insert(
                "",
                "end",
                iid=feed["id"],
                values=(
                    "✓" if feed["enabled"] else "—",
                    feed.get("name", feed["id"]),
                    feed.get("source", ""),
                    feed.get("status", ""),
                    feed.get("indicators", 0),
                    feed.get("last_update_text", "nigdy"),
                ),
            )
        stats = self.controller.db_stats()
        self._clear_tree(self.kinds_tree)
        for kind, count in sorted((stats.get("by_kind") or {}).items()):
            self.kinds_tree.insert("", "end", values=(kind, count))
        self._clear_tree(self.sources_tree)
        for source, count in sorted((stats.get("by_source") or {}).items()):
            self.sources_tree.insert("", "end", values=(source, count))
        self.var_db_summary.set(
            f"Wersja bazy: {stats.get('version', '?')} · wskaźników: {stats.get('total', 0)} · "
            f"plik: {self.controller.config.db_path}"
        )

    def _refresh_settings(self) -> None:
        values = self.controller.form_values()
        for key, (kind, widget) in self._setting_widgets.items():
            value = values.get(key, "")
            if kind == "bool":
                widget.set(bool(value))
            elif kind == "choice":
                widget.set(self._choice_labels.get(key, {}).get(str(value), str(value)))
            elif kind == "list":
                widget.delete("1.0", "end")
                widget.insert("1.0", str(value))
            else:
                widget.set(str(value))

    def _collect_settings(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, (kind, widget) in self._setting_widgets.items():
            if kind == "bool":
                out[key] = bool(widget.get())
            elif kind == "choice":
                label = str(widget.get())
                out[key] = self._choice_values.get(key, {}).get(label, label)
            elif kind == "list":
                out[key] = str(widget.get("1.0", "end"))
            else:
                out[key] = str(widget.get())
        return out

    # ==================================================================
    # Event pump
    # ==================================================================
    def _pump(self) -> None:
        if self._closing:
            return
        processed = 0
        while processed < MAX_EVENTS_PER_TICK:
            try:
                event = self._events.get_nowait()
            except queue.Empty:
                break
            processed += 1
            self._guard("event", self._handle_event, event)
        self._guard("rows", self._drain_rows)
        self._schedule(POLL_MS, self._pump)

    def _drain_rows(self) -> None:
        for row in self.controller.take_new_rows():
            path = row["path"]
            values = (
                path,
                row["threat"],
                row["layers"],
                f"{row['result']} ({row['score']:.0f})",
                row["severity_label"],
            )
            if self.scan_tree.exists(path):
                self.scan_tree.item(path, values=values, tags=(row["severity"],))
            else:
                self.scan_tree.insert("", "end", iid=path, values=values, tags=(row["severity"],))

    def _handle_event(self, event: Event) -> None:
        self._append_log(event)
        etype = event.type
        if etype is EventType.BEHAVIOR_ALERT:
            alerts = self.controller.recent_alerts(1)
            if alerts:
                self._insert_alert(alerts[-1])
        elif etype is EventType.QUARANTINE_CHANGED:
            self._refresh_quarantine()
        elif etype in (EventType.DB_UPDATE_FINISHED, EventType.DB_LOADED):
            self._refresh_feeds()
        elif etype in (EventType.SCAN_FINISHED, EventType.SCAN_CANCELLED):
            self._refresh_progress()
            self._refresh_dashboard()
        elif etype in (EventType.REALTIME_STARTED, EventType.REALTIME_STOPPED):
            self._refresh_realtime()

    def _append_log(self, event: Event) -> None:
        wanted = dict(LEVEL_FILTERS).get(self.var_log_filter.get(), "")
        order = {"info": 0, "success": 0, "warning": 1, "error": 2}
        if wanted and order.get(event.level, 0) < order.get(wanted, 0):
            return
        self.log_text.configure(state="normal")
        self.log_text.insert("end", self.controller.format_event(event) + "\n", event.level)
        self._log_lines += 1
        if self._log_lines > MAX_LOG_LINES:
            self.log_text.delete("1.0", "200.0")
            self._log_lines -= 199
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _replay_history(self) -> None:
        for event in self.controller.log_history(200):
            self._guard("history", self._append_log, event)

    # ==================================================================
    # Commands - dashboard / scanning
    # ==================================================================
    def on_toggle_realtime(self) -> None:
        self._toggle_realtime(bool(self.var_realtime.get()))

    def on_toggle_realtime_tab(self) -> None:
        self._toggle_realtime(bool(self.var_realtime_tab.get()))

    def _toggle_realtime(self, enabled: bool) -> None:
        self._status(
            "Włączanie ochrony w czasie rzeczywistym..."
            if enabled
            else "Wyłączanie ochrony w czasie rzeczywistym..."
        )
        # Runs off the UI thread: starting watchdog can touch the filesystem.
        self.controller.run_background(
            self.controller.set_realtime, enabled, label="przełączenie ochrony"
        )

    def on_quick_scan(self) -> None:
        self._start_scan(self.controller.quick_scan_paths())

    def on_full_scan(self) -> None:
        if not messagebox.askyesno(
            "Pełne skanowanie",
            "Pełne skanowanie obejmuje cały system i może potrwać bardzo długo.\n"
            "Rozpocząć teraz?",
        ):
            return
        self._start_scan(self.controller.full_scan_paths())

    def on_scan_file(self) -> None:
        path = filedialog.askopenfilename(title="Wybierz plik do przeskanowania")
        if path:
            self._start_scan([path])

    def on_scan_folder(self) -> None:
        path = filedialog.askdirectory(title="Wybierz folder do przeskanowania")
        if path:
            self._start_scan([path])

    def _start_scan(self, paths: Sequence[str]) -> None:
        if not paths:
            messagebox.showwarning("Skanowanie", "Nie wskazano żadnej ścieżki.")
            return
        self._clear_tree(self.scan_tree)
        if not self.controller.start_scan(list(paths)):
            messagebox.showwarning(
                "Skanowanie",
                "Nie udało się rozpocząć skanowania.\n"
                "Sprawdź zakładkę Dziennik — być może skanowanie już trwa "
                "albo skaner jest niedostępny.",
            )
            return
        self.notebook.select(self.tab_scan)
        self._status(f"Skanowanie rozpoczęte: {', '.join(paths)}")
        self._refresh_progress()

    def on_cancel_scan(self) -> None:
        self.controller.cancel_scan()
        self._status("Anulowanie skanowania...")

    # ==================================================================
    # Commands - scan result rows
    # ==================================================================
    def on_scan_details(self, event: Any = None) -> None:
        path = self._selected(self.scan_tree)
        if path is None:
            messagebox.showinfo("Szczegóły", "Zaznacz wiersz z listy wyników.")
            return
        self.show_details(
            f"Analiza: {os.path.basename(path)}", path, self.controller.explain_path(path)
        )

    def on_row_quarantine(self) -> None:
        path = self._selected(self.scan_tree)
        if path is None:
            messagebox.showinfo("Kwarantanna", "Zaznacz wiersz z listy wyników.")
            return
        self._status(f"Przenoszenie do kwarantanny: {path}")
        self.controller.run_background(self.controller.quarantine_path, path, label="kwarantanna")

    def on_row_delete(self) -> None:
        path = self._selected(self.scan_tree)
        if path is None:
            messagebox.showinfo("Usuwanie", "Zaznacz wiersz z listy wyników.")
            return
        if not messagebox.askyesno("Usuwanie", f"Usunąć trwale plik?\n\n{path}"):
            return
        self._status(f"Usuwanie pliku: {path}")
        self.controller.run_background(self.controller.delete_path, path, label="usunięcie pliku")

    def on_row_ignore(self) -> None:
        path = self._selected(self.scan_tree)
        if path is None:
            messagebox.showinfo("Ignorowanie", "Zaznacz wiersz z listy wyników.")
            return
        self.controller.ignore_path(path)
        self._status(f"Dodano do wykluczeń: {path}")

    def show_details(self, title: str, path: str, text: str) -> Any:
        """Modal-ish details window with the layer-by-layer explanation."""
        window = tk.Toplevel(self.root)
        window.title(title)
        self._guard("details_geometry", window.geometry, "860x580")
        self._guard("details_transient", window.transient, self.root)

        frame = ttk.Frame(window, padding=12)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Dlaczego to zostało oznaczone?", font=FONT_H1, anchor="w").pack(
            fill="x"
        )
        ttk.Label(
            frame,
            text="Każda warstwa analizy hybrydowej wnosi własne punkty; zgodność "
            "kilku warstw podnosi ocenę.",
            font=FONT_BODY,
            anchor="w",
            wraplength=800,
            justify="left",
        ).pack(fill="x", pady=(2, 10))

        box = scrolledtext.ScrolledText(frame, wrap="word", height=22, font=FONT_MONO)
        box.pack(fill="both", expand=True)
        box.insert("1.0", text)
        box.configure(state="disabled")

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(10, 0))
        ttk.Button(
            buttons,
            text="Kwarantanna",
            command=lambda: self.controller.run_background(
                self.controller.quarantine_path, path, label="kwarantanna"
            ),
        ).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Zamknij", command=window.destroy).pack(side="right")
        return window

    # ==================================================================
    # Commands - quarantine
    # ==================================================================
    def on_quarantine_restore(self) -> None:
        entry_id = self._selected(self.quarantine_tree)
        if entry_id is None:
            messagebox.showinfo("Kwarantanna", "Zaznacz wpis w tabeli.")
            return
        if not messagebox.askyesno(
            "Przywracanie",
            "Przywrócić plik na pierwotne miejsce?\nPlik może nadal być szkodliwy.",
        ):
            return
        self._status("Przywracanie pliku z kwarantanny...")
        self.controller.run_background(self.controller.restore, entry_id, label="przywrócenie")

    def on_quarantine_delete(self) -> None:
        entry_id = self._selected(self.quarantine_tree)
        if entry_id is None:
            messagebox.showinfo("Kwarantanna", "Zaznacz wpis w tabeli.")
            return
        if not messagebox.askyesno("Usuwanie", "Usunąć ten wpis trwale?"):
            return
        self._status("Usuwanie wpisu kwarantanny...")
        self.controller.run_background(self.controller.delete, entry_id, label="usunięcie wpisu")

    def on_quarantine_rescan(self) -> None:
        entry_id = self._selected(self.quarantine_tree)
        if entry_id is None:
            messagebox.showinfo("Kwarantanna", "Zaznacz wpis w tabeli.")
            return
        self._status("Ponowna analiza próbki z kwarantanny...")
        self.controller.run_background(
            self.controller.rescan_quarantine_entry, entry_id, label="ponowna analiza"
        )

    def on_quarantine_details(self, event: Any = None) -> None:
        entry_id = self._selected(self.quarantine_tree)
        if entry_id is None:
            messagebox.showinfo("Kwarantanna", "Zaznacz wpis w tabeli.")
            return
        entry = self.controller.quarantine_entry(entry_id)
        path = entry.original_path if entry is not None else entry_id
        self.show_details(
            "Analiza wpisu kwarantanny", path, self.controller.explain_quarantine_entry(entry_id)
        )

    def on_quarantine_purge(self) -> None:
        if not messagebox.askyesno(
            "Wyczyść kwarantannę",
            "Usunąć trwale WSZYSTKIE pliki z kwarantanny?\nTej operacji nie można cofnąć.",
        ):
            return
        self._status("Czyszczenie kwarantanny...")
        self.controller.run_background(self.controller.purge_quarantine, label="czyszczenie")

    # ==================================================================
    # Commands - realtime paths
    # ==================================================================
    def on_add_path(self) -> None:
        path = filedialog.askdirectory(title="Wybierz katalog do ochrony")
        if not path:
            return
        if self.controller.add_realtime_path(path):
            self._refresh_realtime()
        else:
            messagebox.showwarning(
                "Pilnowane katalogi", "Nie dodano katalogu (już jest na liście albo nie istnieje)."
            )

    def on_remove_path(self) -> None:
        path = self._selected(self.paths_tree)
        if path is None:
            messagebox.showinfo("Pilnowane katalogi", "Zaznacz katalog na liście.")
            return
        self.controller.remove_realtime_path(path)
        self._refresh_realtime()

    # ==================================================================
    # Commands - database
    # ==================================================================
    def on_feed_click(self, event: Any = None) -> None:
        """A click in the first column toggles that feed."""
        if event is None:
            return
        try:
            column = self.feeds_tree.identify_column(event.x)
            row = self.feeds_tree.identify_row(event.y)
        except Exception as exc:  # noqa: BLE001
            self._note_error("identify", exc)
            return
        if str(column) == "#1" and row:
            self._toggle_feed(str(row))

    def on_feed_toggle(self, event: Any = None) -> None:
        feed_id = self._selected(self.feeds_tree)
        if feed_id is None:
            messagebox.showinfo("Baza wirusów", "Zaznacz źródło w tabeli.")
            return
        self._toggle_feed(feed_id)

    def _toggle_feed(self, feed_id: str) -> None:
        current = {feed["id"]: feed["enabled"] for feed in self.controller.feeds()}
        self.controller.set_feed_enabled(feed_id, not current.get(feed_id, False))
        self._refresh_feeds()
        self._status(f"Źródło {feed_id}: {'włączone' if not current.get(feed_id, False) else 'wyłączone'}")

    def on_update_selected(self) -> None:
        feed_id = self._selected(self.feeds_tree)
        if feed_id is None:
            messagebox.showinfo("Baza wirusów", "Zaznacz źródło w tabeli.")
            return
        if not self.controller.update_database([feed_id]):
            messagebox.showwarning(
                "Baza wirusów", "Nie udało się rozpocząć aktualizacji (zobacz Dziennik)."
            )
            return
        self._status(f"Aktualizacja źródła {feed_id}...")

    def on_update_all(self) -> None:
        if not self.controller.update_database():
            messagebox.showwarning(
                "Baza wirusów", "Nie udało się rozpocząć aktualizacji (zobacz Dziennik)."
            )
            return
        self._status("Aktualizacja bazy wirusów...")

    def on_export_db(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Zapisz bazę wskaźników",
            defaultextension=".json",
            filetypes=[("Plik JSON", "*.json"), ("Wszystkie pliki", "*.*")],
        )
        if path:
            self.controller.run_background(self.controller.export_database, path, label="eksport bazy")

    def on_import_db(self) -> None:
        path = filedialog.askopenfilename(
            title="Wybierz plik ze wskaźnikami",
            filetypes=[("Plik JSON", "*.json"), ("Wszystkie pliki", "*.*")],
        )
        if path:
            self.controller.run_background(self.controller.import_database, path, label="import bazy")

    # ==================================================================
    # Commands - log / settings
    # ==================================================================
    def on_log_filter(self, event: Any = None) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self._log_lines = 0
        self._replay_history()

    def on_clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self._log_lines = 0

    def on_save_log(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Zapisz dziennik",
            defaultextension=".log",
            filetypes=[("Plik tekstowy", "*.log"), ("Wszystkie pliki", "*.*")],
        )
        if not path:
            return
        if self.controller.export_log(path):
            messagebox.showinfo("Dziennik", f"Dziennik zapisany:\n{path}")
        else:
            messagebox.showerror("Dziennik", "Nie udało się zapisać dziennika.")

    def on_save_settings(self) -> None:
        ok, errors = self.controller.apply_settings(self._collect_settings())
        if not ok:
            self.var_settings_hint.set("Popraw błędy i spróbuj ponownie.")
            messagebox.showerror("Ustawienia", "\n".join(errors))
            return
        if self.controller.save_config():
            self.var_settings_hint.set("Zapisano.")
            self._status("Ustawienia zapisane.")
        else:
            self.var_settings_hint.set("Nie udało się zapisać pliku konfiguracyjnego.")
        self._refresh_settings()

    def on_reset_settings(self) -> None:
        if not messagebox.askyesno("Ustawienia", "Przywrócić ustawienia domyślne?"):
            return
        self.controller.reset_settings()
        self._refresh_settings()
        self.var_settings_hint.set("Przywrócono domyślne (pamiętaj zapisać).")

    # ==================================================================
    # Lifecycle
    # ==================================================================
    def on_close(self) -> None:
        if self._closing:
            return
        if self.controller.scan_running and not messagebox.askyesno(
            "Aegis AV", "Trwa skanowanie. Zakończyć program?"
        ):
            return
        self._closing = True
        for after_id in self._after_ids:
            try:
                self.root.after_cancel(after_id)
            except Exception:  # noqa: BLE001 - an expired id is harmless
                pass
        self._after_ids.clear()
        try:
            self.controller.bus.unsubscribe(self._event_token)
        except Exception as exc:  # noqa: BLE001
            self._note_error("unsubscribe", exc)
        self.controller.shutdown()
        try:
            self.root.destroy()
        except Exception:  # noqa: BLE001 - already torn down
            pass

    def run(self) -> int:
        self.root.mainloop()
        return 0


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_gui.py", description="Aegis AV — okno programu", add_help=True
    )
    parser.add_argument(
        "--data-dir", metavar="KATALOG", default=None, help="katalog danych (domyślnie ~/.aegis)"
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    if not tkinter_available():
        sys.stderr.write(TK_MISSING_MESSAGE)
        if _TK_IMPORT_ERROR is not None:
            sys.stderr.write(f"\nSzczegóły techniczne: {_TK_IMPORT_ERROR}\n")
        return 2

    config = Config(data_dir=Path(args.data_dir).expanduser()) if args.data_dir else Config.load()
    controller = AegisController(config)
    try:
        app = AegisApp(controller)
    except tk.TclError as exc:  # pragma: no cover - needs a display-less Tk
        controller.shutdown()
        sys.stderr.write(NO_DISPLAY_MESSAGE)
        sys.stderr.write(f"\nSzczegóły techniczne: {exc}\n")
        return 2
    except Exception as exc:  # noqa: BLE001
        controller.shutdown()
        sys.stderr.write(f"Nie udało się zbudować okna: {type(exc).__name__}: {exc}\n")
        return 2

    try:
        return app.run()
    except KeyboardInterrupt:
        app.on_close()
        return 0
    finally:
        controller.shutdown()


if __name__ == "__main__":  # pragma: no cover - run via run_gui.py
    sys.exit(main())
