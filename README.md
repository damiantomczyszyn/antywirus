# Aegis AV

> **Ta gałąź zawiera sam symulator** — atrapę złośliwego oprogramowania,
> służącą do weryfikacji detekcji. Antywirus leży na gałęzi
> `claude/antivirus`; obie razem na `claude/keen-galileo-gkrnhj`.
>
> Zanim cokolwiek uruchomisz, przeczytaj [`docs/SAFETY.md`](docs/SAFETY.md)
> i [`malware-sim/README.md`](malware-sim/README.md).

Antywirus z analizą hybrydową plus obojętny symulator złośliwego oprogramowania,
na którym da się tę analizę zweryfikować. Projekt edukacyjny: pokazuje, jak
działa detekcja, a nie udaje produktu komercyjnego.

```
┌─ sygnatury ──┐  ┌─ heurystyka ─┐  ┌─ threat intel ┐  ┌─ behawior ───┐
│ hash + wzorce│  │ budowa pliku │  │ hosty C2      │  │ co to ROBI   │
└──────┬───────┘  └──────┬───────┘  └──────┬────────┘  └──────┬───────┘
       └─────────────────┴─────────────────┴──────────────────┘
                                 ▼
                      scalanie głosów warstw
                   (premia za zgodność warstw)
                                 ▼
              czysty / niski / średni / wysoki / krytyczny
```

Pojedyncza warstwa zawsze ma lukę: sygnatura nie zna nowego malware, heurystyka
myli spakowany instalator ze szkodnikiem, a behawior musi poczekać, aż coś się
stanie. Aegis uruchamia wszystkie i **łączy ich głosy** — szczegóły wzoru
w [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## ⚠️ Zanim uruchomisz

W repozytorium leży katalog `malware-sim/` — **atrapa** złośliwego kodu.
Generuje *sygnały* (pliki EICAR, markery, serie zapisów, beacon na `127.0.0.1`),
a nie *skutki*: nic nie niszczy, nie utrwala się w systemie, nie wychodzi do
internetu, a „szyfrowanie" jest odwracalne jedną komendą. Granice są wymuszone
w kodzie, nie w komentarzach — patrz [`docs/SAFETY.md`](docs/SAFETY.md).

Mimo to uruchamiaj to na maszynie wirtualnej albo w kontenerze, nie na
produkcji. Nie dlatego, że coś zepsuje, ale dlatego, że Twój systemowy antywirus
zacznie reagować na pliki EICAR — i słusznie.

## Struktura repozytorium i gałęzie

Praca jest rozdzielona na dwie główne gałęzie:

| gałąź | zawiera | po co |
|---|---|---|
| `claude/antivirus` | `antivirus/` + dokumentacja | sam produkt |
| `claude/malware-simulator` | `malware-sim/` + dokumentacja | cel do strzelania |
| `claude/keen-galileo-gkrnhj` | wszystko razem | integracja, testy end-to-end |

Rozdział jest celowy: antywirusa i próbki testowe trzyma się osobno, żeby
można było sklonować sam produkt bez wciągania na dysk czegokolwiek, co
wygląda jak malware.

```
antywirus/
├── antivirus/                 ← gałąź claude/antivirus
│   ├── aegis/
│   │   ├── models.py          kontrakt: Indicator, Detection, FileVerdict…
│   │   ├── events.py          EventBus (wątki ↔ GUI)
│   │   ├── config.py          konfiguracja, cały stan w ~/.aegis
│   │   ├── engine/verdict.py  scalanie warstw → jeden wynik
│   │   ├── core/              skaner, sygnatury, heurystyki, kwarantanna
│   │   ├── intel/             pobieranie bazy wirusów z internetu
│   │   ├── realtime/          ochrona RT, behawior, przeciwdziałanie
│   │   ├── gui/               okno Tkinter + kontroler (testowalny headless)
│   │   └── cli.py             interfejs tekstowy
│   ├── tests/
│   └── run_gui.py             ← uruchom to
├── malware-sim/               ← gałąź claude/malware-simulator
│   └── simulator/             piaskownica, payloady, scenariusze
└── docs/
    ├── ARCHITECTURE.md        jak to działa i dlaczego tak
    ├── SAFETY.md              granice symulatora
    └── CONTRACT.md            API między modułami
```

## Instalacja

Wymagany jest Python 3.10+. Zależności są **opcjonalne** — bez nich wszystko
działa, tylko ochrona w czasie rzeczywistym chodzi na odpytywaniu katalogów
zamiast na zdarzeniach jądra.

```bash
git clone https://github.com/damiantomczyszyn/antywirus
cd antywirus/antivirus
python3 -m pip install -r requirements.txt
```

Na Linuksie Tkinter jest osobną paczką systemową:

```bash
sudo apt install python3-tk
```

Na Windowsie i macOS Tkinter jest już w Pythonie — nic nie trzeba dograć.

## Uruchomienie

### Okno graficzne

```bash
python3 run_gui.py
```

### Wiersz poleceń

```bash
python3 -m aegis scan ~/Downloads
```

```bash
python3 -m aegis realtime
```

```bash
python3 -m aegis update
```

```bash
python3 -m aegis quarantine list
```

Kody wyjścia: `0` czysto, `1` znaleziono zagrożenia, `2` błąd — nadaje się do
skryptów i crona.

## Jak to przetestować end to end

Najpierw postaw cel w piaskownicy, potem spuść na niego antywirusa:

```bash
cd malware-sim && python3 -m simulator run full-demo --sandbox /tmp/lab --confirm
```

```bash
cd ../antivirus && python3 -m aegis scan /tmp/lab
```

Żeby zobaczyć **warstwę behawioralną** (a nie samą sygnaturę), włącz ochronę
w czasie rzeczywistym na katalogu piaskownicy i dopiero wtedy odpal scenariusz
ransomware w drugim terminalu:

```bash
python3 -m aegis realtime --paths /tmp/lab
```

```bash
cd malware-sim && python3 -m simulator run ransomware --sandbox /tmp/lab --confirm
```

Symulator nie ma żadnej sygnatury na „szyfrowanie" — zostaje wykryty po tym,
co robi: masowe modyfikacje, wzrost entropii przy zachowanym rozmiarze,
jednolita zmiana rozszerzenia, notki okupu.

Na koniec:

```bash
cd malware-sim && python3 -m simulator restore --sandbox /tmp/lab
```

```bash
cd malware-sim && python3 -m simulator clean --sandbox /tmp/lab
```

## Baza wirusów

Aegis wozi ze sobą małą bazę startową (EICAR, markery symulatora, kilka
generycznych wzorców złośliwych skryptów), więc coś wykryje od razu po
instalacji. Resztę dociąga z otwartych źródeł — m.in. MalwareBazaar, URLhaus,
Feodo Tracker i SSL Blacklist (abuse.ch) oraz opcjonalnie baza ClamAV.
Szczegóły, limity i to które źródła wymagają darmowego klucza API: zakładka
*Baza wirusów* w GUI albo `python3 -m aegis update --help`.

Aktualizacja używa `If-None-Match`/`If-Modified-Since`, więc drugie
uruchomienie pod rząd kończy się na HTTP 304 i nie przepala łącza.

## Testy

```bash
cd antivirus && python3 -m pytest
```

```bash
cd malware-sim && python3 -m pytest
```

Żaden test nie sięga do sieci ani do prawdziwego `~/.aegis`.

## Czego to nie jest

Uczciwie: **to nie zastępuje prawdziwego antywirusa.** Nie ma sterownika
jądra ani minifiltra systemu plików, więc nie zablokuje pliku *przed* jego
otwarciem — reaguje po zdarzeniu. Nie ma emulatora ani sandboxa do
rozpakowywania spakowanych próbek. Baza sygnatur to ułamek tego, co ma ClamAV
czy produkty komercyjne. Wykrywanie behawioralne działa na próbkowaniu
procesów, a nie na przechwytywaniu wywołań systemowych, więc szybkie malware
może zdążyć zrobić swoje.

Kod jest napisany tak, żeby **było widać mechanizm** — i żeby dało się na nim
nauczyć, jak detekcja działa w środku.

## Licencja

Apache-2.0 — patrz [LICENSE](LICENSE).
