# Kontroler SDN z OSPFv3 — implementacja i weryfikacja

Projekt obejmuje kontroler **Ryu / OpenFlow 1.3** obsługujący OSPFv3 oraz stanowisko badawcze **Containernet + Open vSwitch + FRRouting**. Kontroler uruchamia własną logikę sąsiedztwa, wymiany LSA, LSDB, wyznaczania tras IPv6 i instalowania reguł OpenFlow. Biblioteka **Scapy** jest wykorzystywana w ścieżce konstruowania i dekodowania pakietów OSPFv3.

To implementacja o zakresie eksperymentalnym, **nie kompletna implementacja całego RFC OSPFv3**. Szczegóły zakresu i ograniczeń opisano w [architekturze](docs/ARCHITEKTURA.md) i [weryfikacji](docs/WERYFIKACJA.md).

## Struktura

- `ryu_sdn.py` — aplikacja Ryu: zdarzenia przełącznika i PacketIn, koordynacja kontrolera.
- `controller_openflow.py`, `dataplane.py` — OpenFlow, ruch IPv6, NDP i uczenie hostów.
- `topology.py`, `run_ryu.py` — stanowisko Containernet/FRR i uruchamianie menedżera Ryu.
- `ospfv3/` — konfiguracja, sąsiedztwo, parsery i pakiety, lokalne LSA, LSDB, SPF, moduły RX/TX, diagnostyka i timery.
- `tests/` — testy regresyjne, historyczne i referencyjne; katalog zachować w całości.

Dokładny wykaz **18 modułów produkcyjnych** znajduje się w `docs/ARCHITEKTURA.md`. Pomocnicze skrypty badawcze spoza tej listy nie są automatycznie uznawane za kod produkcyjny.

## Środowisko

W środowisku zweryfikowanym 25 października 2026 r. używano **Pythona 3.12**, **Scapy 2.7.0**, Ryu, Containernet, OVS i FRRouting. Wersje Ryu, FRRouting, OVS oraz obrazu Dockera należy przepisać z własnego środowiska i raportu `W04C_SRODOWISKO.json` — nie należy ich zgadywać. Konfiguracja `topology.py` używa zmiennej `FRR_IMAGE`, domyślnie `frrouting/frr:latest`; do późniejszego odtwarzania eksperymentu najlepiej zapisać konkretny digest obrazu.

Potrzebne są działające: Docker/Containernet, OVS z OpenFlow 1.3, pakiety Mininet/Containernet dostępne interpreterowi użytemu do topologii, środowisko `ryu-env` z zależnościami kontrolera oraz uprawnienia do budowy topologii sieciowej.

## Uruchomienie

W **pierwszym terminalu**, po aktywowaniu sprawdzonego środowiska:

```bash
cd ~/Inzynierka
source ~/ryu-env/bin/activate
python run_ryu.py ryu_sdn.py
```

`run_ryu.py` wykonuje `eventlet.monkey_patch()` przed uruchomieniem `ryu.cmd.manager`. Polecenie jest przykładem dla obecnego entrypointu; jeśli w Twoim środowisku kontroler był uruchamiany inaczej, zachowaj sprawdzoną komendę i wpisz ją do dokumentacji eksperymentu.

W **drugim terminalu** uruchom topologię z uprawnieniami i interpreterem, dla których zainstalowano Containernet, np.:

```bash
cd ~/Inzynierka
sudo python3 topology.py
```

`topology.py` łączy kontroler OpenFlow pod adresem `127.0.0.1:6653`. Nie uruchamiaj dwóch równoległych instancji kontrolera ani dwóch topologii używających tych samych interfejsów.

W konsoli `containernet>`:

```text
r1 vtysh -c 'show ipv6 ospf6 neighbor'
r1 vtysh -c 'show ipv6 ospf6 database'
r2 vtysh -c 'show ipv6 route ospf6'
r3 vtysh -c 'show ipv6 route ospf6'
h1 ping -6 -c 3 2001:db8:23::3
```

**Poczekaj na stan `Full`** przed interpretacją tras — w pierwszych sekundach sąsiedztwa mogą być przejściowo `Init` lub `Exchange`.

## Testy

```bash
cd ~/Inzynierka
source ~/ryu-env/bin/activate
export PYTHONDONTWRITEBYTECODE=1
python -m unittest discover -s tests -p 'test_*.py' -q
python -m unittest discover -s tests -p 'diagnose_*.py' -q
```

Zamknięty audyt W04c (25.10.2026): **649/649 testów OK**, **7/7 diagnostyk OK** (bez `expectedFailure`), 18 modułów produkcyjnych, **4490 PLOC / 3610 SLOC**. Są to wyniki konkretnego zweryfikowanego stanu kodu — po zmianie plików produkcyjnych należy ponowić walidację.

Dowody testów integracyjnych przechowywano poza repozytorium, w `~/Inzynierka_weryfikacja/` (W01, W03a, W03b, W04a, W04b, W04c). Szczegółowe kryteria i ograniczenia: [WERYFIKACJA.md](docs/WERYFIKACJA.md).

## Praca inżynierska / wersjonowanie

- [Architektura i przepływ danych](docs/ARCHITEKTURA.md)
- [Metodyka badań i wyniki](docs/WERYFIKACJA.md)
- [Porządkowanie plików i przygotowanie pracy](docs/PRZYGOTOWANIE_PRACY.md)
- [Przegląd komentarzy i docstringów](docs/KOMENTARZE.md)

**Status repozytorium:** po W04c audyt zakończył się PASS, ale sam audyt **nie** utworzył commita ani tagu. Przed publikacją repozytorium należy przejrzeć jego zawartość i usunąć z indeksu pliki cache; nie wykonywać bezrefleksyjnie `git add .`.
