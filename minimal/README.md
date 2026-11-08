# Minimalny eksperyment OSPFv3 / SDN

To **osobna implementacja demonstracyjna** na gałęzi `minimal-ospfv3`.
Starsze `ryu_sdn.py`, `ospfv3/`, `topology.py` i `tests/` pozostają bez zmian.
Nie uruchamia się `ospf6d` wewnątrz kontrolera: Scapy dekoduje i generuje
komunikaty OSPFv3, a FRRouting działa tylko w routerach klasycznych.

## Architektura

| Moduł | Odpowiedzialność |
| --- | --- |
| `controller.py` | Ryu, PacketIn/PacketOut, reguły OpenFlow 1.3, NDP |
| `peer.py` | jeden sąsiad P2P, Hello, DBD, LSR, LSU, LSAck, timery |
| `packets.py` | Scapy, walidacja nagłówków i LSA, lokalne Router/Link/Prefix-LSA |
| `config.py` | adresacja, porty i MAC tylko dla topologii demonstracyjnej |
| `topology.py` | Containernet, OVS, trójkąt R1–R2–R3, H1 i dodatkowy H2 |

Zachowano pierwotny trójkąt: R1–R2 (`2001:db8:12::/64`), R2–R3
(`2001:db8:23::/64`) i R3–R1 (`2001:db8:31::/64`). R1 łączy się
z przełącznikiem przez `r1-eth2` (`2001:db8:10::/64`). Dodatkowy
host H2 jest podłączony do `r2-eth2` (`2001:db8:2::/64`), bez zmiany
oryginalnych połączeń router–router. Przełącznik ma dwa stałe porty:
`s1-eth1` do R1 oraz `s1-eth2` do H1.

Brama wirtualna (`02:00:00:00:00:01`) odpowiada na NDP dla
`2001:db8:1::1` i `fe80::10`. Ryu instaluje dwa kierunki przekazywania
IPv6 z dekrementacją Hop Limit i podmianą MAC. FRR sam wyznacza trasy
do podsieci klasycznej; hosty mają wyłącznie zwykłe trasy domyślne.

## Uruchomienie

Potrzebne jest działające środowisko Ryu + Scapy 2.7, Containernet,
Docker, OVS/OpenFlow 1.3 i obraz FRRouting z `ospf6d`.
Kod uruchamiamy z katalogu głównego repozytorium.

Terminal 1 — aktywuj **swoje sprawdzone środowisko Ryu**:

```bash
python run_ryu.py minimal/controller.py
```

Terminal 2 — podnieś topologię odpowiednim interpreterem Containernet:

```bash
sudo python3 -m minimal.topology
```

Nie uruchamiaj równocześnie starego kontrolera ani starej topologii.
Po około 40–60 sekundach, w konsoli `containernet>`:

```text
r1 vtysh -c 'show ipv6 ospf6 neighbor'
r1 vtysh -c 'show ipv6 ospf6 database'
r2 vtysh -c 'show ipv6 route ospf6'
r3 vtysh -c 'show ipv6 ospf6 neighbor'
r3 vtysh -c 'show ipv6 route ospf6'
r2 ip -6 route show 2001:db8:1::/64
h1 ping -6 -c 3 2001:db8:2::100
h2 ping -6 -c 3 2001:db8:1::100
h1 ping -6 -c 3 2001:db8:23::3
s1 ovs-ofctl -O OpenFlow13 dump-flows s1
```

**Kryteria zaliczenia:** sąsiad `10.10.10.10` jest `Full` po stronie `r1`,
`r2` ma trasę OSPF6 do `2001:db8:1::/64`, oba pingi działają i
po zamknięciu oraz czystym restarcie *całej* topologii wynik się powtarza.
Stan wewnętrzny `synchronized` w `peer.py` nie jest dowodem stanu `Full` FRR.

## Testy jednostkowe bez Containernet

```bash
python -m unittest minimal.tests.test_minimal minimal.tests.test_topology -v
```

Obejmują walidację pakietów, wymianę z symulowanym sąsiadem Scapy
oraz kontrolę sześciu fizycznych połączeń topologii bez Dockera.
Nie zastępują testów integracyjnych z rzeczywistym FRR.

## Świadome ograniczenia

- Dokładnie jeden sąsiad P2P; lokalny Router ID musi być większy od ID FRR,
  bo minimalna negocjacja DBD obsługuje rolę Master, nie Slave.
- Jeden host SDN i dodatkowy host testowy po stronie FRR; stałe porty/MAC,
  brak uczenia hostów w SDN, ECMP i SPF w kontrolerze.
- Bez uniwersalnej zdalnej LSDB, obsługi wszystkich typów LSA i pełnej
  odporności na restart kontrolera bez restartu routerów.
- LSR mieści się w jednym pakiecie; brak wieloczęściowej synchronizacji
  rozbudowanej domeny. Zachowane: retransmisje DBD/LSR/lokalnych LSU,
  Dead Interval i odświeżanie własnych LSA co 1800 s.
- NDP obsługuje tylko znane adresy bramy i routera; nie stanowi pełnego IPv6 ND.

**Uwaga:** status interoperacyjności trzeba ustalić na podstawie wyników
powyższych poleceń w rzeczywistym środowisku sieciowym. Same testy Scapy
i stan kontrolera nie potwierdzają zestawienia sąsiedztwa z FRR.
Wyniki przekazane 7 listopada dotyczą wcześniejszej topologii z **dwoma**
routerami FRR — po przywróceniu trójkąta należy ponowić testy.
