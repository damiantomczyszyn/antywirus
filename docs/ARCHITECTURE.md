# Architektura Aegis AV

## Dlaczego hybrydowo

Każda pojedyncza warstwa detekcji ma wadę, której sama nie naprawi:

| warstwa | widzi | nie widzi |
|---|---|---|
| sygnatury (hash) | dokładnie to, co już ktoś opisał | cokolwiek nowego — zmiana jednego bajtu i hash nie pasuje |
| wzorce bajtowe | rodziny, nie konkretne pliki | kod spakowany lub zaszyfrowany |
| heurystyka statyczna | podejrzaną *budowę* pliku | nic o intencji — instalatory też są spakowane |
| threat intel (sieć) | złą infrastrukturę C2 | zły kod, który jeszcze nie zadzwonił do domu |
| behawior | świeże, nieznane malware — po tym, co **robi** | musi poczekać, aż coś się stanie |

Aegis uruchamia wszystkie pięć i **łączy ich głosy**. Decyduje o tym jedna
funkcja — `aegis/engine/verdict.py::fuse()`.

## Model punktacji

```
wkład warstwy = min(cap, najmocniejsze + 0,4 × suma pozostałych)

cap:  sygnatura 100 | behawior 85 | intel 80 | heurystyka 55

wynik = min(100, Σ wkładów warstw × (1 + 0,15 × (liczba_warstw − 1)))
                                    └── premia za zgodność warstw

0–15 czysty | 15–40 niski | 40–70 średni | 70–100 wysoki | 100 krytyczny
```

Dwie konsekwencje tego wzoru są celowe:

1. **Heurystyka sama nie wystarczy do kwarantanny.** Jej cap to 55 punktów,
   czyli maksymalnie poziom *średni*. Spakowany instalator nie wyląduje
   w kwarantannie tylko za to, że jest spakowany.
2. **Zgoda warstw jest mocniejsza niż suma części.** Plik spakowany
   (heurystyka, 30 pkt) *który dodatkowo* masowo szyfruje dokumenty
   (behawior, 55 pkt) dostaje 97,8 pkt → poziom *wysoki*, mimo że żadna
   z warstw osobno nie przekroczyłaby progu reakcji. To jest cała idea analizy
   hybrydowej zapisana w jednym mnożniku.

Dokładne wyliczenie dla każdego wykrycia pokazuje `verdict.explain()` — i ten
tekst trafia prosto do okna GUI, żeby użytkownik widział *dlaczego*, a nie samo
„wykryto zagrożenie".

## Przepływ

```
                      ┌──────────────── GUI (Tkinter) ───────────────┐
                      │  Pulpit · Skanowanie · Kwarantanna · Baza    │
                      │  Ochrona RT · Dziennik · Ustawienia          │
                      └──────────────┬────────────┬──────────────────┘
                                     │ polecenia  │ EventBus (kolejka)
                                     ▼            ▲
                            ┌──────────────────────────────┐
                            │   gui/controller.py          │
                            │   AegisController            │
                            └───┬───────┬────────┬─────────┘
          ┌─────────────────────┘       │        └──────────────────┐
          ▼                             ▼                           ▼
┌───────────────────┐        ┌────────────────────┐      ┌────────────────────┐
│  SKANOWANIE       │        │  CZAS RZECZYWISTY  │      │  THREAT INTEL      │
│  core/scanner.py  │        │ realtime/watcher   │      │  intel/feeds.py    │
│                   │        │  (watchdog/poll)   │      │                    │
│ hash → DB         │        │        │           │      │ MalwareBazaar      │
│ wzorce → DB       │        │        ├──► scan ──┤      │ URLhaus            │
│ heurystyka        │        │        │           │      │ Feodo / SSLBL      │
│ archiwa (rekur.)  │        │        ▼           │      │ ThreatFox          │
└────────┬──────────┘        │ realtime/behavior  │      │ ClamAV CVD         │
         │                   │  BehaviorEngine    │      └─────────┬──────────┘
         │                   │                    │                │
         │                   │ realtime/procmon   │                │
         │                   │  procesy + sieć    │                │
         │                   └─────────┬──────────┘                │
         │                             │                           │
         └──────────┬──────────────────┴───────────────────────────┘
                    ▼
        ┌───────────────────────────┐        ┌──────────────────────────┐
        │ engine/verdict.py::fuse() │◄───────│ core/signatures.py       │
        │ scalanie warstw → wynik   │        │ SignatureDB (SQLite)     │
        └───────────┬───────────────┘        └──────────────────────────┘
                    ▼
        ┌───────────────────────────┐
        │ realtime/responder.py     │  kwarantanna · usunięcie
        │ przeciwdziałanie          │  zabicie drzewa procesów
        └───────────┬───────────────┘
                    ▼
        ┌───────────────────────────┐
        │ core/quarantine.py        │  skarbiec: XOR + indeks 0o600
        └───────────────────────────┘
```

## Moduły

### `aegis/models.py`, `events.py`, `config.py` — kontrakt
Wspólny słownik pojęć. `Indicator` to wiersz bazy wirusów, `Detection` to jedna
przesłanka z jednej warstwy, `FileVerdict`/`ProcessVerdict` to wynik scalenia.
`EventBus` rozwiązuje problem „silnik pracuje na wątkach, a Tkinter wolno ruszać
tylko z głównego": wątki *publikują*, GUI *odsącza kolejkę* z `root.after`.
Cały stan runtime siedzi w `~/.aegis`, a `Config.is_internal()` pilnuje, żeby
skaner nigdy nie wszedł do własnej kwarantanny — bez tego kwarantanna wywołuje
skan, który wywołuje kwarantannę, i tak w kółko.

### `aegis/core/` — analiza statyczna
Potok dla pliku: `hash_file` (jeden przebieg, trzy skróty) → `lookup_hash`
→ `match_bytes` (wzorce hex z maskami `??`, skompilowane do regexów bajtowych)
→ `heuristics.analyze` → rekurencja w archiwa z limitami głębokości, liczby
składników i rozmiaru po rozpakowaniu (ochrona przed zip-bombą) → `fuse()`.
Kwarantanna zaciemnia plik XOR-em: nie po to, żeby było „bezpiecznie
kryptograficznie" (nie jest i dokumentacja modułu to mówi wprost), ale żeby
próbki nie dało się odpalić dwuklikiem i żeby nie drażniła innych skanerów.

### `aegis/intel/` — baza wirusów z internetu
Pobieranie z otwartych źródeł, z `If-None-Match`/`If-Modified-Since` (powtórna
aktualizacja kończy się na HTTP 304 i nie przepala łącza), limitem bajtów przy
strumieniowaniu, wykładniczym backoffem i obsługą `Retry-After`. Błąd sieci
nigdy nie leci wyjątkiem w górę — zamienia się w `FeedResult(ok=False)`.
Każdy wskaźnik nosi `source=<feed_id>`, więc `clear_source()` cofa jedno źródło
bez ruszania pozostałych. Z URL-i wyciągane są dodatkowo wskaźniki domenowe,
bo monitor behawioralny widzi hosty, nie pełne adresy.

### `aegis/realtime/` — co się dzieje teraz
`RealtimeMonitor` rozdziela każdą zmianę w systemie plików na **dwie** ścieżki:
skan statyczny pliku *oraz* `BehaviorEvent` do silnika behawioralnego. To ta
dwutorowość daje analizę hybrydową w czasie rzeczywistym.
`BehaviorEngine` trzyma okno czasowe zdarzeń per aktor (PID) i odpala reguły:
masowe modyfikacje, szyfrowanie w miejscu (wzrost entropii przy zachowanym
rozmiarze), masowa zmiana rozszerzenia, notki okupu, zapis do autostartu,
samo-propagacja, kasowanie kopii w tle, beaconing o regularnym interwale,
połączenie do hosta z blacklisty. Reguły mają cooldown, bo jeden przebieg
ransomware wygenerowałby setki identycznych alertów.
`Responder` przeciwdziała — i ma wbudowane bezpieczniki: nie zabije PID 1,
siebie, ani żadnego swojego przodka.

### `aegis/gui/` — okno
`controller.py` nie importuje Tkintera i dzięki temu jest testowalny headless.
`app.py` to same widgety. Skany i aktualizacje chodzą na wątkach roboczych;
główna pętla nigdy nie blokuje.

## Fałszywe alarmy

Kompilator, instalator, `git clone` i rozpakowywanie archiwum wyglądają jak
ransomware: dużo zapisów w krótkim czasie. Przeciwdziałania:

* atrybucja do konkretnego PID-u zamiast globalnego licznika,
* cap heurystyki na poziomie *średnim* — sama nie uruchomi reakcji,
* reguła `encrypt_in_place` wymaga **wzrostu entropii przy podobnym rozmiarze**,
  co odsiewa zapis nowych plików,
* `benign_control` w symulatorze: celowa seria niewinnych, szybkich zapisów,
  na której testy sprawdzają, że AV **nie** reaguje.

## Granica bezpieczeństwa symulatora

Patrz `docs/SAFETY.md`. W skrócie: symulator to atrapa, która produkuje
*sygnały*, a nie skutki. Wszystko dzieje się w katalogu-piaskownicy oznaczonym
plikiem-znacznikiem, „szyfrowanie" jest odwracalne XOR-em, autostart jest
podrobiony w piaskownicy, a ruch sieciowy nie wychodzi poza `127.0.0.1`.
