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

Aegis wozi ze sobą małą bazę startową (EICAR po trzech skrótach plus wzorzec
na samą treść, markery symulatora, kilka generycznych wzorców złośliwych
skryptów), więc coś wykryje od razu po instalacji, bez sieci.

Resztę dociąga z otwartych źródeł. **Stan sprawdzony na żywo 2026-11-14**, bo
krajobraz się zmienił i warto wiedzieć, co naprawdę działa:

| źródło | domyślnie | stan |
|---|---|---|
| baza wbudowana | ✅ ON | 18 wskaźników, offline |
| `github_curated` | ✅ ON | baza startowa z tego repo przez HTTPS |
| Feodo Tracker (lista zalecana) | ✅ ON | **działa anonimowo**, 5 aktywnych C2 z nazwami rodzin (Emotet, QakBot) |
| Feodo Tracker (lista agresywna) | ⬜ OFF | działa, **7607** adresów — ale zawiera adresy offline i historyczne, a przepisany komuś innemu adres zgłosi się jako trafienie. Jeden klik w *Ustawieniach* |
| MalwareBazaar, URLhaus, ThreatFox | 🔑 klucz | abuse.ch **wycofał anonimowe eksporty masowe** (HTTP 410); zastępniki na `*-api.abuse.ch` wymagają darmowego `Auth-Key` |
| SSL Blacklist (lista IP) | ⬜ OFF | formalnie **wygaszona 2025-01-03** — odpowiada 200, ale w treści zero adresów |
| SSL Blacklist (certyfikaty) | ⬜ OFF | działa i jest świeża, ale to odciski **certyfikatów TLS**, nie plików — nigdy nie dopasują się do zawartości pliku |
| ClamAV (`daily.cvd`) | ⬜ OFF | parser napisany i przetestowany na pliku syntetycznym, **nie na prawdziwych bajtach** — Cloudflare blokuje pobranie z części sieci |

Parsery do wszystkich tych źródeł są w repo i przetestowane — wyłączone, nie
brakujące. Klucz API wkleja się w zakładce *Baza wirusów* albo przez zmienną
`AEGIS_<ID_ZRODLA>_KEY`.

Aktualizacja używa `If-None-Match`/`If-Modified-Since`, więc drugie
uruchomienie pod rząd kończy się na HTTP 304 i nie przepala łącza. Limit
bajtów jest pilnowany **w trakcie strumieniowania**, więc wrogi feed nie wypcha
pamięci ani dysku, a błąd sieci nigdy nie leci wyjątkiem w górę — zamienia się
w nieudany wynik dla tego jednego źródła.

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
