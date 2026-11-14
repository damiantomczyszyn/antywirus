# Kontrakt integracyjny Aegis AV

Dokument wiążący dla wszystkich równolegle pracujących modułów. Jeśli coś tutaj
koliduje z Twoim pomysłem — wygrywa ten dokument, bo cztery inne moduły już na
nim polegają.

## 1. Moduły już napisane — NIE MODYFIKOWAĆ

Te pliki są gotowe i stanowią kontrakt. Można je tylko czytać i importować:

| plik | zawartość |
|---|---|
| `antivirus/aegis/models.py` | `Severity`, `IndicatorKind`, `Indicator`, `DetectionLayer`, `Detection`, `FileVerdict`, `ScanStats`, `BehaviorKind`, `BehaviorEvent`, `ProcessVerdict`, `ActionKind`, `ActionResult`, `QuarantineEntry`, `FeedResult`, stałe punktacji |
| `antivirus/aegis/events.py` | `EventType`, `Event`, `EventBus` |
| `antivirus/aegis/config.py` | `Config` (ścieżki pochodne: `db_path`, `quarantine_dir`, `quarantine_index`, `log_path`, `cache_path`, `feed_state_path`, `history_path`) |
| `antivirus/aegis/engine/verdict.py` | `fuse()`, `apply_to_file_verdict()`, `apply_to_process_verdict()`, `explain()` |
| `antivirus/tests/conftest.py` | fixtures `bus`, `config`, `eicar_bytes` |

Jeśli naprawdę brakuje Ci pola w modelu — **nie dodawaj go**, użyj `Detection.detail`
albo `BehaviorEvent.extra` i zgłoś to w raporcie końcowym.

## 2. Podział własności plików

Każdy agent tworzy **wyłącznie** swoje pliki. Zero edycji plików innego agenta.

| agent | katalogi / pliki |
|---|---|
| A — silnik statyczny | `antivirus/aegis/core/*` + `antivirus/tests/test_core_*.py` |
| B — threat intel | `antivirus/aegis/intel/*`, `antivirus/aegis/data/*` + `antivirus/tests/test_intel_*.py` |
| C — realtime + behawior | `antivirus/aegis/realtime/*` + `antivirus/tests/test_realtime_*.py` |
| D — GUI + CLI | `antivirus/aegis/gui/*`, `antivirus/aegis/cli.py`, `antivirus/aegis/__main__.py`, `antivirus/run_gui.py` + `antivirus/tests/test_ui_*.py` |
| E — symulator | `malware-sim/**` (cały katalog) |

## 3. Wymagane publiczne API

Sygnatury są wiążące — inne moduły wołają dokładnie to.

### A. `aegis.core.hashing`
```python
@dataclass(frozen=True, slots=True)
class FileHashes:
    sha256: str; sha1: str; md5: str; size: int

def hash_file(path, chunk_size: int = 1 << 20) -> FileHashes
def hash_bytes(data: bytes) -> FileHashes
def sha256_file(path, chunk_size: int = 1 << 20) -> str
```

### A. `aegis.core.signatures`
```python
class SignatureDB:
    def __init__(self, path: Path | str | None = None, bus: EventBus | None = None) -> None
    def add(self, indicator: Indicator) -> bool                      # True == nowy
    def add_many(self, indicators: Iterable[Indicator]) -> tuple[int, int]   # (added, updated)
    def remove(self, kind: IndicatorKind, value: str) -> bool
    def lookup_hash(self, *, sha256=None, sha1=None, md5=None) -> Indicator | None
    def lookup_network(self, *, host=None, url=None, ip=None) -> Indicator | None
    def match_bytes(self, data: bytes, limit: int = 8) -> list[tuple[Indicator, int]]  # (wzorzec, offset)
    def iter_indicators(self, kind: IndicatorKind | None = None) -> Iterator[Indicator]
    def stats(self) -> dict[str, Any]        # {"total": int, "by_kind": {...}, "by_source": {...}, "version": str}
    def version(self) -> str                 # np. "2026.11.14.1532"
    def clear_source(self, source: str) -> int
    def export_json(self, path) -> int
    def import_json(self, path) -> tuple[int, int]
    def close(self) -> None
    def __len__(self) -> int
```
Magazyn: SQLite pod `config.db_path`, `PRIMARY KEY (kind, value)`, `check_same_thread=False`
+ `threading.RLock` (woła go realtime z wielu wątków). `path=None` → baza w pamięci
(`:memory:`) — tego używają testy.

`match_bytes` dopasowuje wskaźniki `IndicatorKind.PATTERN`: wartość to hex,
w którym `??` znaczy dowolny bajt (np. `4d5a????0003`). Kompiluj je raz do
`re` (bajtowo) i cache'uj; unieważnij cache po `add*`/`remove`.

### A. `aegis.core.heuristics`
```python
def shannon_entropy(data: bytes) -> float            # 0.0 .. 8.0
def detect_file_type(data: bytes) -> str             # "pe", "elf", "macho", "zip", "ole", "pdf", "script", "text", "data"
def analyze(path: str | Path | None, data: bytes, *, config: Config | None = None) -> list[Detection]
HEURISTIC_RULES: list[dict]                          # {"id","name","description","score"} dla GUI
```
Każdy zwrócony `Detection` ma `layer=DetectionLayer.HEURISTIC` i `score`
z przedziału `SCORE_HEURISTIC_WEAK`..`SCORE_HEURISTIC_STRONG`.

### A. `aegis.core.quarantine`
```python
class Quarantine:
    def __init__(self, config: Config, bus: EventBus | None = None) -> None
    def quarantine(self, path, verdict: FileVerdict | None = None, threat_name: str = "") -> ActionResult
    def restore(self, entry_id: str) -> ActionResult
    def delete(self, entry_id: str) -> ActionResult
    def purge_all(self) -> int
    def list(self) -> list[QuarantineEntry]
    def get(self, entry_id: str) -> QuarantineEntry | None
    def read_payload(self, entry_id: str) -> bytes
```
Plik w skarbcu jest **zaciemniony** (XOR strumieniem z klucza skarbca +
`entry_id`), żeby nie dał się przypadkiem uruchomić ani nie wyzwalał innego AV.
`ActionResult.target` = oryginalna ścieżka, `detail` zawiera `entry_id`.
Indeks `index.json` zapisywany atomowo (tmp + `os.replace`), prawa `0o600`.

### A. `aegis.core.scanner`
```python
class CancellationToken:
    def cancel(self) -> None
    @property
    def cancelled(self) -> bool

@dataclass(slots=True)
class ScanResult:
    verdicts: list[FileVerdict]; stats: ScanStats; cancelled: bool = False
    @property
    def threats(self) -> list[FileVerdict]

class Scanner:
    def __init__(self, db: SignatureDB, config: Config, bus: EventBus | None = None) -> None
    def scan_file(self, path, *, data: bytes | None = None) -> FileVerdict
    def scan_bytes(self, data: bytes, name: str = "<memory>") -> FileVerdict
    def iter_scan(self, paths, *, token: CancellationToken | None = None, recursive: bool = True) -> Iterator[FileVerdict]
    def scan_paths(self, paths, *, token: CancellationToken | None = None, recursive: bool = True) -> ScanResult
```
Potok dla pliku: hash → `db.lookup_hash` → `db.match_bytes` → `heuristics.analyze`
→ (archiwum: rekurencja do `config.archive_max_depth`) → `apply_to_file_verdict`.
Publikuj `SCAN_STARTED` / `SCAN_PROGRESS` / `SCAN_FILE_DONE` / `THREAT_FOUND` /
`SCAN_FINISHED` / `SCAN_CANCELLED` na `bus`. Pomijaj `config.is_internal(path)`
(inaczej AV skanuje własną kwarantannę w pętli), pliki > `config.max_file_size`
(`FileVerdict.skipped`), katalogi z `config.excluded_names`.

### B. `aegis.intel.feeds`
```python
@dataclass(frozen=True)
class FeedSpec:
    id: str; name: str; url: str; description: str
    kind: IndicatorKind; threat_prefix: str
    requires_key: bool = False; enabled_by_default: bool = True
    severity: Severity = Severity.HIGH; homepage: str = ""

def parse_feed(spec: FeedSpec, raw: bytes) -> list[Indicator]
AVAILABLE_FEEDS: dict[str, FeedSpec]

def fetch(url, *, timeout=30.0, headers=None, etag=None, last_modified=None,
          max_bytes=64 * 1024 * 1024) -> tuple[bytes | None, dict[str, str]]
# zwraca (None, meta) przy HTTP 304 — treść się nie zmieniła

class IntelUpdater:
    def __init__(self, db: SignatureDB, config: Config, bus: EventBus | None = None) -> None
    def update(self, feed_ids: Sequence[str] | None = None, *, force: bool = False) -> list[FeedResult]
    def update_feed(self, feed_id: str, *, force: bool = False) -> FeedResult
    def available(self) -> list[dict[str, Any]]      # dla tabeli w GUI
    def last_update(self) -> float | None
```

### B. `aegis.intel.baseline`
```python
def builtin_indicators() -> list[Indicator]
def ensure_baseline(db: SignatureDB) -> int          # idempotentne
```

### C. `aegis.realtime.behavior`
```python
class BehaviorEngine:
    def __init__(self, config: Config, bus: EventBus | None = None, db: SignatureDB | None = None) -> None
    def observe(self, event: BehaviorEvent) -> list[Detection]   # nowe wykrycia dla tego zdarzenia
    def verdicts(self, min_severity: Severity = Severity.LOW) -> list[ProcessVerdict]
    def verdict_for(self, pid: int | None) -> ProcessVerdict | None
    def rules(self) -> list[dict[str, Any]]
    def reset(self) -> None
BEHAVIOR_RULES: list[dict]
```
`Detection.layer = DetectionLayer.BEHAVIOR`, `score` w `SCORE_BEHAVIOR_WEAK..SCORE_BEHAVIOR_STRONG`.
Zdarzenia bez PID trafiają do koszyka `pid=None`. Każda reguła ma cooldown, żeby
nie zgłaszać tego samego 500 razy.

### C. `aegis.realtime.responder`
```python
class Responder:
    def __init__(self, config: Config, bus: EventBus, quarantine: Quarantine) -> None
    def handle_file_threat(self, verdict: FileVerdict) -> list[ActionResult]
    def handle_process_threat(self, verdict: ProcessVerdict) -> list[ActionResult]
    def kill_process_tree(self, pid: int, *, dry_run: bool = False) -> ActionResult
```
`kill_process_tree` **nigdy** nie zabija PID 1, własnego procesu ani swojego
przodka — zwraca wtedy `ActionResult(ok=False)`.

### C. `aegis.realtime.procmon`
```python
class ProcessMonitor:
    def __init__(self, config: Config, bus: EventBus, behavior: BehaviorEngine, db: SignatureDB | None = None) -> None
    def start(self) -> None
    def stop(self, timeout: float = 5.0) -> None
    @property
    def is_running(self) -> bool
    @property
    def backend(self) -> str                 # "psutil" | "procfs" | "none"
    def status(self) -> dict[str, Any]
    def poll_once(self) -> list[BehaviorEvent]   # testowalne bez wątku
```

### C. `aegis.realtime.watcher`
```python
class RealtimeMonitor:
    def __init__(self, scanner: Scanner, config: Config, bus: EventBus,
                 quarantine: Quarantine | None = None,
                 behavior: BehaviorEngine | None = None,
                 responder: Responder | None = None) -> None
    def start(self, paths: Sequence[str] | None = None) -> None
    def stop(self, timeout: float = 5.0) -> None
    @property
    def is_running(self) -> bool
    @property
    def backend(self) -> str                 # "watchdog" | "polling"
    def status(self) -> dict[str, Any]       # backend, paths, events, scanned, threats, actions
    def drain_once(self) -> int              # testowalne: przetwórz kolejkę i zwróć liczbę plików
```

### D. `aegis.gui.controller`
```python
class AegisController:     # ZERO importów tkinter — musi dać się testować headless
    def __init__(self, config: Config | None = None, bus: EventBus | None = None) -> None
    # pola: config, bus, db, scanner, quarantine, behavior, responder, monitor, updater
    def start_scan(self, paths: Sequence[str], *, recursive: bool = True) -> bool
    def cancel_scan(self) -> None
    @property
    def scan_running(self) -> bool
    def last_scan(self) -> ScanResult | None
    def set_realtime(self, enabled: bool) -> bool
    def update_database(self, feed_ids: Sequence[str] | None = None) -> bool   # w wątku
    def quarantine_items(self) -> list[QuarantineEntry]
    def restore(self, entry_id: str) -> ActionResult
    def delete(self, entry_id: str) -> ActionResult
    def dashboard(self) -> dict[str, Any]    # status, db_version, counts, last_scan, realtime
    def shutdown(self) -> None
```

## 4. Konwencje

* **Python 3.10+**, tylko biblioteka standardowa w ścieżce krytycznej.
  `watchdog` i `psutil` są opcjonalne: `try: import ... except ImportError:` i
  działający fallback. Brak zależności nie może wywalić importu modułu.
* **Nie wołaj `git`.** Commity, gałęzie i push robi integrator.
* Adnotacje typów wszędzie, `from __future__ import annotations` w każdym pliku.
* Docstringi i komentarze **po angielsku**; teksty widoczne dla użytkownika
  (GUI, CLI, komunikaty błędów, nazwy zagrożeń w raportach) **po polsku z polskimi znakami**.
* Pliki źródłowe w UTF-8.
* Nazwy zagrożeń: `Sim.<Rodzina>.<Wariant>` dla symulatora, `Heur.<Co>` dla
  heurystyk, `Behav.<Reguła>` dla behawioru, nazwa z feedu dla intelu.
* Każdy moduł musi dać się zaimportować bez efektów ubocznych (żadnego I/O,
  żadnego tworzenia katalogów na poziomie modułu).
* Testy: `pytest`, uruchamiane z katalogu `antivirus/` (`python3 -m pytest`).
  **Żaden test nie może sięgać do sieci ani do prawdziwego `~/.aegis`** — używaj
  fixture `config` (jest oparta na `tmp_path`) i mockuj HTTP.
* Nie zapisuj niczego do katalogu repozytorium w trakcie testów.

## 5. Zasady bezpieczeństwa (obowiązują wszystkich)

Symulator to **atrapa**, nie malware. Granice, których nie wolno przekroczyć:

* Żadnego kodu, który niszczy dane użytkownika, utrwala się poza piaskownicą,
  modyfikuje prawdziwy autostart/rejestr/cron/systemd, podnosi uprawnienia,
  wstrzykuje się w procesy, omija AMSI/ETW, obfuskuje się przed detekcją
  albo łączy się z jakimkolwiek zdalnym hostem.
* Wszystkie efekty symulatora muszą być **odwracalne** i zamknięte w katalogu
  piaskownicy, który symulator sam tworzy i oznacza plikiem-znacznikiem.
* Jako kanoniczna próbka sygnaturowa służy **ciąg testowy EICAR** — jest obojętny
  i rozpoznawany przez cały przemysł AV.
* Ruch sieciowy symulatora: **tylko `127.0.0.1`**, do serwera-atrapy z tego repo.
