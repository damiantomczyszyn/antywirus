# Granice bezpieczeństwa

## Po co w repo z antywirusem leży „złośliwy" kod

Antywirusa nie da się sensownie rozwijać bez celu do strzelania. Cały przemysł
rozwiązuje to tak samo: **obojętna próbka testowa**. Najstarsza i najbardziej
znana to [EICAR](https://www.eicar.org/download-anti-malware-testfile/) —
68-bajtowy ciąg znaków, który każdy skaner rozpoznaje jako „zagrożenie", a który
nie robi absolutnie nic. Podobnie działa Atomic Red Team: odtwarza *technikę*,
żeby obrona dała się zweryfikować.

`malware-sim/` w tym repozytorium to dokładnie to: **generator sygnałów, nie
skutków**.

## Czego symulator NIE robi

Te ograniczenia są wymuszone strukturalnie w `malware-sim/simulator/safety.py`,
nie są kwestią dobrych intencji:

| nie robi | dlaczego to ważne |
|---|---|
| nie niszczy żadnych danych użytkownika | operuje wyłącznie na plikach-wabikach, które sam wygenerował w piaskownicy |
| nie utrwala się w systemie | „autostart" to katalog `<piaskownica>/fake-autostart/` i plik `fake-registry.json`; prawdziwy rejestr, `~/.config/autostart`, cron, systemd i LaunchAgents są nietykalne |
| nie szyfruje nieodwracalnie | „szyfrowanie" to XOR kluczem zapisanym obok danych, z komendą `restore` i testem sprawdzającym bajt-w-bajt powrót |
| nie łączy się z internetem | wyłącznie `127.0.0.1`, do serwera-atrapy z tego repo. Adres jest walidowany po rozwiązaniu nazwy, nie po napisie — **a od wersji po przeglądzie także na poziomie gniazdka**: żądania idą przez opener, który odmawia przekierowań i ignoruje `*_proxy` ze środowiska |
| nie podnosi uprawnień, nie wstrzykuje się w procesy | te techniki nie służą testowaniu detekcji, tylko jej obchodzeniu |
| nie obfuskuje się, nie omija AMSI/ETW, nie ma anty-debuga | symulator ma być **łatwy** do wykrycia — to jego zadanie |
| nie rozprzestrzenia się | „propagacja" to kopie markerów do podkatalogów piaskownicy |

## Jak wymuszona jest piaskownica

1. Piaskownica to katalog utworzony przez sam symulator, oznaczony plikiem
   `.aegis-sim-sandbox` z wygenerowanym identyfikatorem i znacznikiem czasu.
2. `require_sandbox()` odmawia działania, jeśli znacznika nie ma — oraz
   bezwarunkowo dla `/`, katalogu domowego, katalogu repozytorium i jego
   przodków, `/etc`, `/usr`, `/bin`, `/boot`, `/var`, `/sys`, `/proc`, `/dev`
   i katalogów systemowych Windows.
3. **Każdy** zapis przechodzi przez pomocnik, który ponownie sprawdza, że cel
   leży wewnątrz aktywnej piaskownicy — walidacja na wejściu nie wystarcza,
   bo ścieżka może być zbudowana później.
4. Obowiązuje limit liczby tworzonych plików i zapisanych bajtów na przebieg.
5. CLI wymaga jawnego potwierdzenia (`--confirm`), a `--dry-run` wypisuje plan
   i nie dotyka niczego.
6. `clean` odmawia usunięcia katalogu bez znacznika piaskownicy — a `create()`
   odmawia **zaadoptowania** istniejącego, niepustego katalogu bez znacznika.
   Bez tego drugiego wskazanie `--sandbox` na katalog z czyimiś plikami
   ostemplowałoby go jako piaskownicę, a późniejszy `clean` usunąłby zawartość,
   której symulator nigdy nie utworzył.
7. Żądania sieciowe nie podążają za przekierowaniami. Sama brama sprawdza cel
   *przed* otwarciem gniazdka, co jest bezwartościowe, jeśli serwer może potem
   odpowiedzieć `302` i przesłać urllib tam, gdzie brama nigdy by nie
   przepuściła. Sprawdzone doświadczalnie: domyślny opener próbował wyjść.

## Uruchamianie

Mimo powyższego: **nie uruchamiaj symulatora na maszynie produkcyjnej.**
Nie dlatego, że coś zepsuje, ale dlatego, że zainstalowany antywirus zacznie
reagować na pliki EICAR i markery — i słusznie. Właściwe miejsce to maszyna
wirtualna, kontener albo osobne konto testowe.

Jeśli Twój systemowy antywirus skasuje pliki z piaskownicy w trakcie demo —
to znaczy, że działa. Aegis ma zrobić to samo.

## Odpowiedzialność

Kod jest materiałem do nauki detekcji. Używaj go na własnym sprzęcie albo tam,
gdzie masz na to pisemną zgodę.
