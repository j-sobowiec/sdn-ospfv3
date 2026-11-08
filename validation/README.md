# Niezależna walidacja `sdn-ospfv3`

Testy przygotowane na bazie kodu `main` o commicie
`1c4b858c7f49a33ce8cb9c84e513f0f39eadfd1b`, również dla zmian
naprawczych opisanych w `FIX_README.md` (29 PASS offline po poprawkach).
Nie zmieniają kodu produkcyjnego i nie komunikują się z GitHub. Każde
ponowne uruchomienie rozpoznaje bieżący commit w katalogu źródłowym.

## 1. Mierzalne kryteria

| ID | Kryterium | Implementacja testu |
| --- | --- | --- |
| PROT-01 | Poprawne OSPFv3 Hello, DBD, LSU, LSA i sumy kontrolne | `tests/test_wire.py` |
| PROT-02 | Odrzucanie wadliwych datagramów, złych timerów i E-bit | `tests/test_receive.py` |
| PROT-03 | Obsługa DBD, retransmisji, LSAck, Dead i BadLSReq | `tests/test_receive.py` |
| INT-01 | FRR R1 widzi sąsiada `10.10.10.10` w stanie `Full` | `run_integration.py` |
| INT-02 | R2 ma prefiks LAN w RIB OSPF6 i FIB Linux | `run_integration.py` |
| INT-03 | R3 również uczy się prefiksu z OSPF6 | `run_integration.py` |
| INT-04 | R1 ma LSA kontrolera i prefiks LAN w LSDB | `run_integration.py` |
| INT-05/06 | ICMPv6 H1→H2 i H2→H1 bez utraty pakietów | `run_integration.py` |
| INT-07/08 | Wymiana danych TCP/UDP IPv6 i odpowiedzi w obie strony | `run_integration.py` |
| INT-09 | Niezerowe liczniki dwóch reguł forwardingu OVS | `run_integration.py` |
| INT-10 | Po wyłączeniu Ryu zanika `Full` i trasa OSPF | `run_integration.py` |
| INT-11 | Po restarcie Ryu wracają `Full`, trasa i pingi | `run_integration.py` |

Testy formatów porównują bajty z niezależnym dekodowaniem `struct`, obliczają
checksum IPv6 oraz weryfikują Fletcher LSA bez użycia funkcji kodu
produkcyjnego do ustalania oczekiwanego wyniku. Scapy generuje ruch wejściowy.
Maksymalnie uproszczony partner testowy nie jest zamiennikiem realnego FRR;
dlatego `INT-*` sprawdza wyniki z osobnych procesów i tablic routingu.

## 2. Instalacja (Ubuntu, kopia repozytorium)

Skopiuj katalog `validation/` do katalogu głównego *aktualnego* repozytorium
lub pozostaw go obok repozytorium i podaj `--source`.

```bash
git rev-parse HEAD
python3 -m venv --system-site-packages .venv-validation
.venv-validation/bin/python -m pip install -r validation/requirements-test.txt
.venv-validation/bin/python validation/run_offline.py --source "$PWD"
```

`--system-site-packages` pozwala osobnemu środowisku widzieć Containernet
zainstalowany systemowo. Nie instaluje ani nie aktualizuje Containernet.

Test offline nie wymaga `sudo` ani uruchamiania sieci. Tworzy *nowy* katalog
`validation/results/offline-YYYYMMDDTHHMMSSZ/` z następującymi plikami:

- `environment.json` — commit, data UTC, wersje Scapy/pytest/Python, status;
- `run.log` — pełne wyjście testów;
- `junit.xml` — surowe wyniki do CI;
- `test-results.json` — status każdego przypadku.

Gdy system blokuje odczyt interfejsów przez NETLINK, testy **offline**
wyłączają wyłącznie automatyczne wykrywanie interfejsów w Scapy. Fakt ten
zapisuje `environment.json`. Nie jest to symulacja FRR/Ryu/OVS.

## 3. Testy integracyjne — tylko odizolowany Ubuntu

Wymagane: działające Containernet/Mininet, Docker, OVS, obraz FRRouting
z `ospf6d`, `iproute2`, Python 3 dla hostów Mininet i **osobne** środowisko
Python zawierające sprawdzone Ryu, Scapy, Eventlet (np. `~/ryu-env/bin/python`).

Najpierw uruchom **bezpieczny preflight**, bez zmian sieci:

```bash
.venv-validation/bin/python validation/run_integration.py \
  --source "$PWD" \
  --controller-python "$HOME/ryu-env/bin/python"
```

Wynik preflight z błędami oznacza `BLOCKED`; usuń przyczynę przed kontynuacją.
`--controller-python` powinien wskazywać **interpreter wewnątrz ryu-env**,
np. `/home/jan/ryu-env/bin/python3` (skrypt nie rozwiązuje tego dowiązania
do systemowego Pythona).
Na dedykowanej maszynie/VM, po upewnieniu się, że nie działają inne instancje
Ryu/Containernet, uruchom:

```bash
sudo -E env PATH="$PATH" .venv-validation/bin/python \
  validation/run_integration.py --execute \
  --source "$PWD" \
  --controller-python "$HOME/ryu-env/bin/python"
```

**Uwaga:** `--execute` tworzy kontenery, przestrzenie nazw sieciowych i
przełącznik OVS `s1`, startuje własny proces Ryu, a w scenariuszu INT-10
świadomie go zatrzymuje i ponownie uruchamia. Wymaga uprawnień administratora.
Skrypt odmawia działania, jeśli port 6653, most `s1` lub kontenery `r1/r2/r3`
już istnieją. Używaj wyłącznie w środowisku testowym, ponieważ Containernet
może wpływać na sieć systemu gospodarza. W przypadku błędów `topology.main()`
ma blok `finally: net.stop()`; proces Ryu również jest zamykany.

Wyniki: `validation/results/integration-YYYYMMDDTHHMMSSZ/`:

- `summary.json` — commit, stan Git, sumy SHA-256 kodu, czasy i wyniki INT-01...INT-11;
- `evidence/*.txt` — rzeczywiste odpowiedzi `vtysh`, `ip`, `ping`, TCP/UDP,
  przepływy OVS w kolejnych punktach czasu;
- `controller-initial.log`, `controller-restart.log` — logi kontrolera;
- `component-versions.json` — Docker, OVS, FRR;
- `exception.txt` — tylko w razie problemu uruchomieniowego.

Na poprzednim commicie `1c4b858...` użytkownik potwierdził 11/11 PASS w
Containernet (po usunięciu fałszywego wyniku spowodowanego kodami terminala).
**Zmodyfikowany `peer.py` wymaga ponownego uruchomienia INT-01..11**;
wcześniejszych wyników nie wolno automatycznie przypisać nowej wersji kodu.

## 4. Interpretacja wyników

- **PASS** — konkretne kryterium spełnione przez uruchomiony test;
- **FAIL** — otrzymany wynik sprzeczny z kryterium, nie zmieniaj asercji;
- **PARTIAL** — tylko część wymagania ma dowody;
- **NOT TESTED** — test nie został wykonany;
- **BLOCKED** — niezbędny komponent/narzędzie nie jest dostępne;
- **NOT APPLICABLE** — poza zakresem z uzasadnieniem w raporcie.

Nie oceniaj jako `PASS` stanu `Peer.stage == "synchronized"`: potwierdzenie
interoperacyjności wymaga `Full` zgłoszonego **przez niezależny FRRouting**.
Sukces pingów bez trasy OSPF w RIB/FIB albo bez zaniku tej trasy po wyłączeniu
Ryu również nie dowodzi integracji protokołów.

## 5. Ograniczenia skryptów

Integracja obejmuje jeden kontroler, przełącznik, jednego sąsiada OSPFv3 i
trzy routery FRR w konfiguracji projektu. Nie jest to test multi-area,
DR/BDR, SPF w Ryu, ECMP czy dowolnych adresów MAC — te możliwości nie są
wymagane w bazowym scenariuszu pracy. Skrypt nie uruchamia destrukcyjnego
`mn -c`, nie usuwa cudzych kontenerów i nie wykonuje `git push`.

Wynik `FAIL` podczas INT wymaga sprawdzenia odpowiedniego surowego logu;
w szczególności niezgodność wersji/komendy FRR oraz błędy konfiguracji sieci
powinny być rozdzielone od wad implementacji dopiero po analizie dowodów.

### Poprawki w wersji testów z 8 listopada 2026

Mininet/Containernet może zwracać przy poleceniach także sekwencje sterujące
Bash (`ESC[?2004h`/`ESC[?2004l`), które nie są komunikatami błędu.
`run_integration.py` usuwa **tylko te sekwencje** z odpowiedzi `ifconfig`
przed interpretacją jej przez Containernet. Rzeczywisty komunikat błędu
`ifconfig` nie jest ukrywany; test regresyjny potwierdza to zachowanie.
Ten sam filtr służy do ustalania, czy wynik `ip -6 route` jest pusty.
Nie zmieniono kryteriów INT-10 ani wymagań funkcjonalnych.
