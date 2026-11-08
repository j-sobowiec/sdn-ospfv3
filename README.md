# sdn-ospfv3 — integracja SDN i OSPFv3

Autorska aplikacja **Ryu i OpenFlow 1.3** integrująca sieć IPv6 zarządzaną
przez SDN z klasycznymi routerami FRRouting. Ryu samodzielnie uczestniczy
w OSPFv3; FRRouting działa wyłącznie w routerach R1, R2 i R3.
To demonstracja dla jednej ustalonej topologii, a nie uniwersalny router.

## Struktura

| Plik | Odpowiedzialność |
| --- | --- |
| `controller.py` | Zdarzenia Ryu, OpenFlow, NDP i brama IPv6 |
| `peer.py` | Sąsiad OSPFv3, Hello/DBD/LSR/LSU/LSAck, timery |
| `packets.py` | Kodowanie, walidacja OSPFv3 i lokalne LSA przez Scapy |
| `config.py` | Adresy IPv6, identyfikatory, porty i MAC |
| `topology.py` | Containernet: trójkąt R1–R2–R3, S1, H1, H2 |
| `run_ryu.py` | Launcher Ryu |
| `validation/` | Testy offline, 11 testów integracyjnych i raporty |
| `Makefile` | Krótkie polecenia do uruchamiania testów |

Więcej: [architektura](docs/ARCHITEKTURA.md),
[procedura testowania](docs/TESTY.md).

## Uruchomienie na Ubuntu

Wymagane: Ubuntu z Pythonem 3, środowisko Ryu z Eventlet i Scapy,
Containernet, Docker, Open vSwitch (OpenFlow 1.3) oraz obraz
`frrouting/frr` z demonem `ospf6d`. Repozytorium nie zawiera instalatora
tych komponentów ani przypiętych wersji całego środowiska; domyślnie
`topology.py` pobiera `frrouting/frr:latest` (można ustawić `FRR_IMAGE`).

Terminal 1 (z katalogu repo, w sprawdzonym środowisku Ryu):

```bash
source ~/ryu-env/bin/activate
python3 run_ryu.py --ofp-tcp-listen-port 6653 controller.py
```

Terminal 2 (z katalogu repo):

```bash
sudo python3 topology.py
```

Nie uruchamiaj drugiej instancji Ryu ani Containernet. Po zestawieniu
sąsiedztwa (czas zależy od środowiska) w konsoli `containernet>`:

```text
r1 vtysh -c 'show ipv6 ospf6 neighbor'
r1 vtysh -c 'show ipv6 ospf6 database'
r2 ip -6 route show 2001:db8:1::/64
h1 ping -6 -c 5 2001:db8:2::100
h2 ping -6 -c 5 2001:db8:1::100
```

Sprawdź `10.10.10.10 Full/PointToPoint` na R1, reklamę LAN
`2001:db8:1::/64`, dynamiczną trasę na R2 i pingi w obu kierunkach.
Instrukcja testu restartu Ryu jest w `docs/TESTY.md`.

## Testy automatyczne

Na Ubuntu, z katalogu repozytorium:

```bash
make setup-tests  # jednorazowo: pytest i Scapy w osobnym venv
make test         # testy offline, bez sudo
make preflight    # weryfikacja wymagań Containernet i Ryu
```

Pełne testy integracyjne uruchamiaj **wyłącznie na dedykowanym hoście testowym**,
bez innych uruchomionych instancji Ryu/Containernet:

```bash
make integration CONFIRM=YES
```

Na kodzie commita `ca734838` audyt z 8.11.2026 potwierdził
**41/41 PASS offline** (bez zmian w plikach Pythona); integracji tej
wersji nie uruchamiano. Wcześniejsza dokumentacja podawała **11/11 PASS
integracyjnie** dla `6c21526` — nie jest to dowód działania obecnego
`main`. Wyniki uruchomień trafiają do ignorowanego przez Git
`validation/results/`; raporty potrzebne do pracy należy archiwizować.
Pełne instrukcje, wymagania i opis kryteriów: [validation/README.md](validation/README.md).

## Sprawdzenie składni

```bash
python3 -m compileall -q controller.py peer.py packets.py config.py topology.py run_ryu.py
```

Ręczna procedura testowania jest w [docs/TESTY.md](docs/TESTY.md).

## Świadome ograniczenia

- Jeden sąsiad FRRouting na łączu point-to-point, jeden obszar OSPFv3,
  stałe porty/MAC i obsługa roli DBD Master.
- Własne Hello, DBD, LSR, LSU, LSAck, lokalne Router/Link/Prefix-LSA
  i retransmisje; brak pełnego routera, dowolnej wielosąsiedzkiej LSDB i SPF.
- OVS przekazuje IPv6 za pomocą dwóch kierunków reguł OpenFlow.
  NDP dotyczy znanych adresów bramy i tranzytu.
- Kryteria demonstracji obejmują stan Full, dynamiczną trasę OSPF do LAN,
  pingi H1↔H2 oraz odbudowanie sąsiedztwa po restarcie Ryu.
  Testy długotrwałe i awarie łączy wymagają osobnej walidacji.
