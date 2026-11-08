# Walidacja OSPFv3 — testy offline i integracyjne

Testy są oddzielone od kodu kontrolera. Raporty generowane lokalnie i
środowiska wirtualne są wykluczone z Git; **zachowaj raporty będące dowodami
do pracy inżynierskiej w osobnym archiwum**.

Historyczna dokumentacja deklarowała **29/29 PASS offline i 11/11 PASS
integracyjnie** dla commita `6c21526` (8.11.2026), lecz dowody tych
uruchomień nie znajdują się w repozytorium. Podane później **39/39 PASS**
nie było jednoznacznie przypisane do commita.

**Nowe uruchomienie offline (8.11.2026): 41/41 PASS** na kodzie commita
`ca7348384a2776cf1213a0f3d0212f0c7591bd82` (Python 3.12.14,
pytest 8.4.2, Scapy 2.6.1). Zmiany lokalne obejmowały wyłącznie Markdown
i `.gitignore`. Raport: `validation/results/offline-20261108T161712Z/`
(nieśledzony przez Git). **Nie uruchomiono integracji** dla tego commita.

## Szybki start

Na Ubuntu wymagany jest pakiet systemowy `python3-venv` do utworzenia
środowiska testowego. W katalogu głównym repozytorium:

| Polecenie | Co robi |
| --- | --- |
| `make setup-tests` | Jednorazowo tworzy `.venv-validation` i instaluje pytest/Scapy |
| `make test` | Uruchamia testy offline bez `sudo` |
| `make preflight` | Sprawdza zależności integracji **bez zmian sieci** |
| `make integration CONFIRM=YES` | Uruchamia **11 testów rzeczywistych**; wymaga `sudo` i dedykowanego Ubuntu |

Domyślny interpreter Ryu to `~/ryu-env/bin/python3`. Można go zmienić:

```bash
make preflight RYU_PYTHON=/inna/sciezka/ryu-env/bin/python3
```

Jeśli nie używasz `make`, uruchom testy offline i kontrolę wymagań:

```bash
.venv-validation/bin/python validation/run_offline.py --source "$PWD"
/usr/bin/python3 validation/run_integration.py --source "$PWD" \
  --controller-python "$HOME/ryu-env/bin/python3"
```

Bez `--execute` drugi skrypt wykonuje **tylko preflight**. Pełną
integrację uruchamiaj wyłącznie na dedykowanym Ubuntu, po świadomym
potwierdzeniu skutków sieciowych (odpowiednik `make integration CONFIRM=YES`):

```bash
sudo /usr/bin/python3 validation/run_integration.py --execute \
  --source "$PWD" --controller-python "$HOME/ryu-env/bin/python3"
```

Testy integracyjne wymagają systemowego Pythona z Containernet, Docker,
OVS, iproute2 i obrazu FRRouting z `ospf6d`. Ryu, Eventlet i Scapy
muszą działać w osobnym środowisku Ryu.

**Uwaga:** `make integration CONFIRM=YES` tworzy kontenery, interfejsy
i przełącznik OVS, uruchamia własny proces Ryu, a w INT-10 celowo go
zatrzymuje. Używaj tylko na odizolowanym hoście testowym, gdy nie działa
inna instancja Ryu ani Containernet. Bez `CONFIRM=YES` polecenie odmawia startu.

## Co sprawdzamy?

| Testy | Zakres |
| --- | --- |
| `tests/test_wire.py` | Format OSPFv3, LSA, checksum IPv6 i Fletcher |
| `tests/test_receive.py` | Hello/DBD/LSR/LSU/LSAck, E-bit, BadLSReq, retransmisje i timery |
| `tests/test_harness.py` | Zabezpieczenia przed pozornym PASS i fałszywym błędem terminala |
| `tests/test_controller_safety.py` | Odrzucanie obcego DPID bez zmian w OpenFlow |
| `INT-01`–`INT-04` | Sąsiedztwo Full, RIB/FIB i LSDB we FRRouting |
| `INT-05`–`INT-08` | ICMPv6, TCP i UDP IPv6 w obu kierunkach |
| `INT-09` | Ruch na regułach OpenFlow 1.3 |
| `INT-10`–`INT-11` | Wycofanie i powrót tras po wyłączeniu/restarcie Ryu |

Testy offline weryfikują pakiety niezależnym dekodowaniem; nie udają
rzeczywistego FRRouting. Integracja potwierdza wyniki w osobnych procesach
oraz w tablicach routingu Linux i FRR. Sam stan wewnętrzny kontrolera
nie wystarcza, aby uznać `INT-01` za PASS.

## Raporty — nie dodawaj do Git

Każdy start tworzy nowy katalog w `validation/results/` (ignorowany przez Git):

- `offline-YYYY.../`: `run.log`, `junit.xml`, `test-results.json`, `environment.json`;
- `integration-YYYY.../`: `summary.json`, `evidence/*.txt`, logi Ryu oraz wersje komponentów.

Raport integracyjny zapisuje commit, stan Git i SHA-256 kluczowych plików
źródłowych. Raport offline zapisuje commit i stan Git, ale bez sum plików;
dla jednoznacznej identyfikacji najlepiej uruchamiać testy na czystym
checkoutcie i archiwizować wyniki wraz z identyfikatorem commita.
Nie usuwaj raportów potrzebnych do pracy inżynierskiej ani audytu.

`run_offline.py` i `run_integration.py` obsługują `--results`, jeśli chcesz
zapisywać kolejne wyniki poza repozytorium. Przykład:

```bash
.venv-validation/bin/python validation/run_offline.py \
  --source "$PWD" --results "$HOME/ospfv3-offline-$(date +%Y%m%d-%H%M%S)"
```

## Ograniczenia

Testowany jest ustalony scenariusz projektu: jeden kontroler SDN, jeden
przełącznik, trzech routerów FRR i jeden sąsiad OSPFv3. To nie jest
test dowolnej topologii, wielu obszarów OSPFv3, SPF/ECMP w Ryu ani
długotrwałej odporności produkcyjnej. W razie `FAIL` analizuj surowe
dowody; nie zmieniaj kryteriów testu, by uzyskać sztuczny PASS.
