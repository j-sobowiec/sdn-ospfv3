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
| `archive/legacy-integration/` | Archiwum dotychczasowych scenariuszy integracyjnych |

Więcej: [architektura](docs/ARCHITEKTURA.md).

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
Historyczną procedurę testu restartu Ryu zachowano w [archiwum](archive/legacy-integration/TESTY.md).

## Walidacja

Poprzedni skrypt integracyjny INT-01–INT-11 przeniesiono do [archiwum](archive/legacy-integration/README.md). Nie stanowi już aktywnego zestawu testów. Zakres nowych scenariuszy dla wielu przełączników OVS, w tym testów wydajnościowych, zostanie ustalony przed ponowną walidacją. Historyczne wyniki nie potwierdzają działania przyszłej wersji projektu.

## Sprawdzenie składni

```bash
python3 -m compileall -q controller.py peer.py packets.py config.py topology.py run_ryu.py
```

## Świadome ograniczenia

- Jeden sąsiad FRRouting na łączu point-to-point, jeden obszar OSPFv3,
  stałe porty/MAC i obsługa roli DBD Master.
- Własne Hello, DBD, LSR, LSU, LSAck, lokalne Router/Link/Prefix-LSA
  i retransmisje; brak pełnego routera, dowolnej wielosąsiedzkiej LSDB i SPF.
- OVS przekazuje IPv6 za pomocą dwóch kierunków reguł OpenFlow.
  NDP dotyczy znanych adresów bramy i tranzytu.
- Dotychczasowa demonstracja obejmowała stan Full, dynamiczną trasę OSPF do LAN,
  pingi H1↔H2 oraz odbudowanie sąsiedztwa po restarcie Ryu.
  Nowa walidacja wymaga uzgodnienia scenariuszy dla rozszerzonej topologii.
