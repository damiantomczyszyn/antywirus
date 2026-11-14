"""Tests for the command line interface (``python3 -m aegis``).

``main([...])`` is called directly so exit codes and output can be asserted
without spawning a process.  Every invocation passes ``--data-dir`` into
``tmp_path``, so no test can reach the real ``~/.aegis``; no test reaches the
network either (the intel updater is monkeypatched).
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from aegis import cli
from aegis.config import Config
from aegis.models import FeedResult

ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
@pytest.fixture()
def run_cli(tmp_path, capsys):
    """Invoke ``cli.main`` and return ``(exit_code, stdout, stderr)``."""
    data_dir = tmp_path / "aegis-cli"

    def run(*args: str):
        code = cli.main(["--data-dir", str(data_dir), *args])
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    run.data_dir = data_dir  # type: ignore[attr-defined]
    run.tmp = tmp_path  # type: ignore[attr-defined]
    return run


@pytest.fixture()
def clean_dir(tmp_path) -> Path:
    target = tmp_path / "czyste"
    target.mkdir()
    (target / "notatka.txt") .write_bytes(b"nic podejrzanego\n")
    return target


@pytest.fixture()
def eicar_dir(tmp_path, eicar_bytes) -> Path:
    target = tmp_path / "zarazone"
    target.mkdir()
    (target / "eicar.com").write_bytes(eicar_bytes)
    (target / "notatka.txt").write_bytes(b"nic podejrzanego\n")
    return target


def _scanner_available() -> bool:
    try:
        from aegis.core import scanner  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


requires_scanner = pytest.mark.skipif(
    not _scanner_available(), reason="aegis.core.scanner jest niedostępny"
)


# --------------------------------------------------------------------------
# Plumbing
# --------------------------------------------------------------------------
def test_exit_codes_are_the_documented_ones():
    assert (cli.EXIT_CLEAN, cli.EXIT_THREATS, cli.EXIT_ERROR) == (0, 1, 2)


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
    assert "Aegis AV" in capsys.readouterr().out


def test_no_command_prints_help_and_fails(run_cli):
    code, out, _err = run_cli()
    assert code == cli.EXIT_ERROR
    assert "POLECENIE" in out
    assert "scan" in out and "quarantine" in out and "gui" in out


def test_help_lists_every_command(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    out = capsys.readouterr().out
    for command in ("scan", "realtime", "update", "db", "quarantine", "status", "gui"):
        assert command in out


def test_parser_builds_without_a_controller():
    parser = cli.build_parser()
    args = parser.parse_args(["scan", "/tmp", "--quick", "--json", "--quarantine"])
    assert args.command == "scan"
    assert args.recursive is True
    assert args.quick is True and args.json is True and args.quarantine is True
    args = parser.parse_args(["scan", "/tmp", "--no-recursive"])
    assert args.recursive is False


def test_data_dir_is_respected_and_home_is_untouched(run_cli):
    code, _out, _err = run_cli("status")
    assert code in (cli.EXIT_CLEAN, cli.EXIT_THREATS)
    assert run_cli.data_dir.is_dir()
    assert (run_cli.data_dir / "quarantine").is_dir()


def test_data_dir_picks_up_a_saved_config(run_cli, tmp_path):
    watched = tmp_path / "pilnowane"
    watched.mkdir()
    config = Config(data_dir=run_cli.data_dir)
    config.realtime_paths = [str(watched)]
    config.scan_threads = 3
    config.save()
    code, out, _err = run_cli("status")
    assert code in (cli.EXIT_CLEAN, cli.EXIT_THREATS)
    assert str(run_cli.data_dir) in out


# --------------------------------------------------------------------------
# status
# --------------------------------------------------------------------------
def test_status_human_output_is_polish(run_cli):
    code, out, _err = run_cli("status")
    assert code in (cli.EXIT_CLEAN, cli.EXIT_THREATS)
    assert "Stan ochrony" in out
    assert "wersja bazy" in out
    assert "ochrona w czasie rzeczywistym" in out
    assert "katalog danych" in out


def test_status_json_output(run_cli):
    code, out, _err = run_cli("status", "--json")
    assert code in (cli.EXIT_CLEAN, cli.EXIT_THREATS)
    data = json.loads(out)
    assert data["status"] in ("protected", "warning", "threat")
    assert "counts" in data and "realtime" in data and "db_version" in data


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------
def test_scan_without_paths_is_a_usage_error(run_cli):
    code, _out, err = run_cli("scan")
    assert code == cli.EXIT_ERROR
    assert "Podaj przynajmniej jedną ścieżkę" in err


@requires_scanner
def test_scan_clean_directory_exits_zero(run_cli, clean_dir):
    code, out, _err = run_cli("scan", str(clean_dir))
    assert code == cli.EXIT_CLEAN
    assert "Nie znaleziono zagrożeń" in out
    assert "Podsumowanie skanowania" in out
    assert "przeskanowane pliki" in out


@requires_scanner
def test_scan_eicar_exits_one_and_explains_why(run_cli, eicar_dir):
    code, out, _err = run_cli("scan", str(eicar_dir))
    assert code == cli.EXIT_THREATS
    assert "Wykryte zagrożenia: 1" in out
    assert "eicar.com" in out
    assert "krytyczny" in out
    # the hybrid-analysis breakdown must be visible, layer by layer
    assert "Dlaczego" in out
    assert "WYNIK:" in out
    assert "signature" in out


@requires_scanner
def test_scan_json_output_is_machine_readable(run_cli, eicar_dir):
    code, out, _err = run_cli("scan", str(eicar_dir), "--json")
    assert code == cli.EXIT_THREATS
    data = json.loads(out)
    assert data["exit_code"] == 1
    assert data["stats"]["files_scanned"] >= 2
    assert len(data["threats"]) == 1
    threat = data["threats"][0]
    assert threat["path"].endswith("eicar.com")
    assert threat["severity"] == "critical"
    assert threat["detections"], "każde zagrożenie musi nieść swoje wykrycia"
    assert data["verdicts"]


@requires_scanner
def test_scan_no_recursive_stays_on_one_level(run_cli, tmp_path, eicar_bytes):
    root = tmp_path / "zewnetrzny"
    nested = root / "wewnetrzny"
    nested.mkdir(parents=True)
    (nested / "eicar.com").write_bytes(eicar_bytes)
    code, _out, _err = run_cli("scan", str(root), "--no-recursive")
    assert code == cli.EXIT_CLEAN
    code, _out, _err = run_cli("scan", str(root), "--recursive")
    assert code == cli.EXIT_THREATS


@requires_scanner
def test_scan_quick_uses_the_configured_paths(run_cli, tmp_path, eicar_bytes):
    watched = tmp_path / "pilnowane"
    watched.mkdir()
    (watched / "eicar.com").write_bytes(eicar_bytes)
    config = Config(data_dir=run_cli.data_dir)
    config.realtime_paths = [str(watched)]
    config.save()
    code, out, _err = run_cli("scan", "--quick")
    assert code == cli.EXIT_THREATS
    assert str(watched) in out


def test_scan_warns_about_a_missing_path(run_cli, tmp_path):
    code, _out, err = run_cli("scan", str(tmp_path / "nie-ma-mnie"))
    assert "nie istnieje" in err
    assert code in (cli.EXIT_CLEAN, cli.EXIT_ERROR)


@requires_scanner
def test_scan_with_quarantine_moves_the_file(run_cli, eicar_dir):
    sample = eicar_dir / "eicar.com"
    code, out, _err = run_cli("scan", str(eicar_dir), "--quarantine")
    assert code == cli.EXIT_THREATS
    assert "Wykonane akcje" in out
    assert not sample.exists()

    code, out, _err = run_cli("quarantine", "list")
    assert code == cli.EXIT_CLEAN
    assert "eicar.com" in out
    assert "krytyczny" in out


# --------------------------------------------------------------------------
# quarantine
# --------------------------------------------------------------------------
def test_quarantine_without_subcommand_fails(run_cli):
    code, _out, err = run_cli("quarantine")
    assert code == cli.EXIT_ERROR
    assert "Podaj podpolecenie" in err


def test_quarantine_list_is_empty_at_first(run_cli):
    code, out, _err = run_cli("quarantine", "list")
    assert code == cli.EXIT_CLEAN
    assert "wpisów: 0" in out
    code, out, _err = run_cli("quarantine", "list", "--json")
    assert json.loads(out) == []


def test_quarantine_restore_of_unknown_id_fails(run_cli):
    code, _out, err = run_cli("quarantine", "restore", "brak-takiego-id")
    assert code == cli.EXIT_ERROR
    assert "Nie udało się" in err


@requires_scanner
def test_quarantine_restore_and_purge_round_trip(run_cli, eicar_dir):
    sample = eicar_dir / "eicar.com"
    run_cli("scan", str(eicar_dir), "--quarantine")

    code, out, _err = run_cli("quarantine", "list", "--json")
    entries = json.loads(out)
    assert len(entries) == 1
    entry_id = entries[0]["entry_id"]

    code, out, _err = run_cli("quarantine", "restore", entry_id)
    assert code == cli.EXIT_CLEAN
    assert "Przywrócono" in out
    assert sample.exists()

    run_cli("scan", str(eicar_dir), "--quarantine")
    code, out, _err = run_cli("quarantine", "purge", "--yes")
    assert code == cli.EXIT_CLEAN
    assert "Usunięto wpisów: 1" in out
    code, out, _err = run_cli("quarantine", "list", "--json")
    assert json.loads(out) == []


@requires_scanner
def test_quarantine_delete_removes_the_entry(run_cli, eicar_dir):
    run_cli("scan", str(eicar_dir), "--quarantine")
    _code, out, _err = run_cli("quarantine", "list", "--json")
    entry_id = json.loads(out)[0]["entry_id"]
    code, out, _err = run_cli("quarantine", "delete", entry_id, "--json")
    assert code == cli.EXIT_CLEAN
    assert json.loads(out)["ok"] is True


# --------------------------------------------------------------------------
# db
# --------------------------------------------------------------------------
def test_db_without_subcommand_fails(run_cli):
    code, _out, err = run_cli("db")
    assert code == cli.EXIT_ERROR
    assert "Podaj podpolecenie" in err


def test_db_stats_human_and_json(run_cli):
    code, out, _err = run_cli("db", "stats")
    assert code == cli.EXIT_CLEAN
    assert "Baza wirusów" in out
    assert "Według rodzaju" in out and "Według źródła" in out

    code, out, _err = run_cli("db", "stats", "--json")
    assert code == cli.EXIT_CLEAN
    data = json.loads(out)
    for key in ("total", "by_kind", "by_source", "version"):
        assert key in data


def test_db_export_then_import(run_cli, tmp_path):
    target = tmp_path / "wskazniki.json"
    code, out, _err = run_cli("db", "export", str(target))
    assert code == cli.EXIT_CLEAN
    assert target.is_file()
    assert "Wyeksportowano" in out

    code, out, _err = run_cli("db", "import", str(target), "--json")
    assert code == cli.EXIT_CLEAN
    payload = json.loads(out)
    assert payload["added"] >= 0 and payload["updated"] >= 0


def test_db_import_of_a_missing_file_fails(run_cli, tmp_path):
    code, _out, err = run_cli("db", "import", str(tmp_path / "nie-ma.json"))
    assert code == cli.EXIT_ERROR
    assert "Nie ma takiego pliku" in err


# --------------------------------------------------------------------------
# update (never over the network)
# --------------------------------------------------------------------------
@pytest.fixture()
def fake_feeds(monkeypatch):
    """Replace IntelUpdater.update so no test can reach the internet."""
    try:
        from aegis.intel import feeds
    except Exception:  # noqa: BLE001
        pytest.skip("aegis.intel.feeds jest niedostępny")

    calls: list[dict[str, object]] = []
    outcome = {"results": [FeedResult(feed_id="builtin", ok=True, added=7, updated=2)]}

    def fake_update(self, feed_ids=None, *, force=False):
        calls.append({"feed_ids": list(feed_ids) if feed_ids else None, "force": force})
        return outcome["results"]

    monkeypatch.setattr(feeds.IntelUpdater, "update", fake_update, raising=True)
    return calls, outcome


def test_update_all_feeds(run_cli, fake_feeds):
    calls, _outcome = fake_feeds
    code, out, _err = run_cli("update")
    assert code == cli.EXIT_CLEAN
    assert calls == [{"feed_ids": None, "force": False}]
    assert "źródło" in out and "builtin" in out
    assert "Baza wirusów: wersja" in out


def test_update_selected_feed_with_force(run_cli, fake_feeds):
    calls, _outcome = fake_feeds
    code, out, _err = run_cli("update", "--feed", "builtin", "--feed", "urlhaus_online", "--force")
    assert code == cli.EXIT_CLEAN
    assert calls[0]["feed_ids"] == ["builtin", "urlhaus_online"]
    assert calls[0]["force"] is True


def test_update_json_output(run_cli, fake_feeds):
    code, out, _err = run_cli("update", "--json")
    assert code == cli.EXIT_CLEAN
    data = json.loads(out)
    assert data["ok"] is True
    assert data["feeds"][0]["added"] == 7
    assert "db" in data


def test_update_reports_a_failing_feed(run_cli, fake_feeds):
    _calls, outcome = fake_feeds
    outcome["results"] = [FeedResult(feed_id="urlhaus_online", ok=False, error="brak sieci")]
    code, out, _err = run_cli("update")
    assert code == cli.EXIT_ERROR
    assert "brak sieci" in out


# --------------------------------------------------------------------------
# realtime
# --------------------------------------------------------------------------
def test_realtime_runs_for_a_bounded_time(run_cli, tmp_path):
    watched = tmp_path / "pilnowane"
    watched.mkdir()
    code, out, err = run_cli("realtime", "--paths", str(watched), "--duration", "0.3")
    if code == cli.EXIT_ERROR:
        assert "ochron" in err.lower()
        pytest.skip("monitor czasu rzeczywistego jest niedostępny")
    assert code == cli.EXIT_CLEAN
    assert "Ochrona w czasie rzeczywistym — włączona" in out
    assert "mechanizm" in out
    assert "Ctrl+C" in out
    assert "wykryte zagrożenia" in out


def test_realtime_json_summary(run_cli, tmp_path):
    watched = tmp_path / "pilnowane"
    watched.mkdir()
    code, out, _err = run_cli("realtime", "--paths", str(watched), "--duration", "0.3", "--json")
    if code == cli.EXIT_ERROR:
        pytest.skip("monitor czasu rzeczywistego jest niedostępny")
    data = json.loads(out)
    assert data["threats"] == 0
    assert data["paths"] == [str(watched)]


# --------------------------------------------------------------------------
# Interrupts and failures must never show a traceback
# --------------------------------------------------------------------------
def test_ctrl_c_exits_cleanly(run_cli, monkeypatch):
    def interrupt(controller, args):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_cmd_status", interrupt)
    code, out, _err = run_cli("status")
    assert code == cli.EXIT_CLEAN
    assert "Przerwano przez użytkownika." in out


def test_unexpected_error_becomes_exit_code_two(run_cli, monkeypatch):
    def boom(controller, args):
        raise RuntimeError("awaria testowa")

    monkeypatch.setattr(cli, "_cmd_status", boom)
    code, _out, err = run_cli("status")
    assert code == cli.EXIT_ERROR
    assert "Błąd: RuntimeError: awaria testowa" in err
    assert "Traceback" not in err


def test_controller_is_shut_down_even_on_failure(run_cli, monkeypatch):
    shutdowns: list[int] = []
    from aegis.gui.controller import AegisController

    original = AegisController.shutdown

    def counting_shutdown(self):
        shutdowns.append(1)
        original(self)

    monkeypatch.setattr(AegisController, "shutdown", counting_shutdown)
    monkeypatch.setattr(cli, "_cmd_status", lambda c, a: (_ for _ in ()).throw(RuntimeError("x")))
    run_cli("status")
    assert shutdowns, "main() musi zawsze zamknąć kontroler"


# --------------------------------------------------------------------------
# gui wiring
# --------------------------------------------------------------------------
def test_gui_command_delegates_to_the_gui_package(run_cli, monkeypatch):
    import aegis.gui as gui_pkg

    seen: list[list[str]] = []
    monkeypatch.setattr(gui_pkg, "run", lambda argv=None: seen.append(list(argv or [])) or 0)
    code, _out, _err = run_cli("gui")
    assert code == cli.EXIT_CLEAN
    assert seen and seen[0][0] == "--data-dir"


def test_app_main_explains_a_missing_tkinter(capsys):
    from aegis.gui import app

    if app.tkinter_available():
        pytest.skip("Tkinter jest dostępny - ta ścieżka dotyczy maszyn bez python3-tk")
    assert app.main([]) == 2
    err = capsys.readouterr().err
    assert "sudo apt install python3-tk" in err
    assert "python3 -m aegis" in err
    assert "Traceback" not in err


def test_tk_missing_message_names_every_platform():
    from aegis.gui import app

    for needle in ("python3-tk", "python3-tkinter", "pacman -S tk", "python.org"):
        assert needle in app.TK_MISSING_MESSAGE


# --------------------------------------------------------------------------
# Real process entry points
# --------------------------------------------------------------------------
def test_python_m_aegis_works(tmp_path):
    env = dict(os.environ, AEGIS_DATA_DIR=str(tmp_path / "aegis-env"), PYTHONIOENCODING="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "aegis", "--version"],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0
    assert "Aegis AV" in proc.stdout


def test_python_m_aegis_status_json(tmp_path):
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    proc = subprocess.run(
        [
            sys.executable, "-m", "aegis",
            "--data-dir", str(tmp_path / "aegis-sub"),
            "status", "--json",
        ],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode in (0, 1)
    assert json.loads(proc.stdout)["status"] in ("protected", "warning", "threat")


@pytest.mark.skipif(
    importlib.util.find_spec("tkinter") is not None,
    reason="z działającym Tkinterem run_gui.py otworzyłby okno i zablokował test",
)
def test_run_gui_launcher_explains_the_missing_toolkit(tmp_path):
    env = dict(os.environ, AEGIS_DATA_DIR=str(tmp_path / "aegis-gui"), PYTHONIOENCODING="utf-8")
    proc = subprocess.run(
        [sys.executable, str(ROOT / "run_gui.py")],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 2
    assert "python3-tk" in proc.stderr
    assert "Traceback" not in proc.stderr
