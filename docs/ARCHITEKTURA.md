# Architektura

1. `topology.py` tworzy trzy routery FRRouting R1–R2–R3
   połączone w trójkąt, OVS S1 oraz hosty H1 i H2.
2. `controller.py` odbiera OSPFv3 przez Ryu `PacketIn` i
   przekazuje pakiety do `Peer`.
3. `peer.py` utrzymuje jednego sąsiada OSPFv3, obsługuje
   Hello, DBD, LSR, LSU, LSAck, timery i wymianę LSA.
4. `packets.py` buduje pakiety i lokalne Router-LSA,
   Link-LSA oraz Intra-Area-Prefix-LSA przez Scapy.
5. Router R1 otrzymuje reklamę sieci LAN `2001:db8:1::/64`.
   FRRouting oblicza trasy w klasycznej domenie.
6. OVS używa reguł OpenFlow do ruchu H1→R1 i R1→H1, ze zmianą
   adresów MAC i Hop Limit. Ryu odpowiada za logiczną bramę i NDP.

## Granice projektu

To autorska aplikacja integracyjna OSPFv3/SDN dla stałej topologii.
Nie implementuje pełnego SPF w Ryu, multi-area, DR/BDR, ECMP ani
obsługi dowolnych wielu sąsiadów. Wymiana DBD zakłada rolę Master,
a LSR i zdalna LSDB są uproszczone do potrzeb demonstracji.

**Stan lokalny `synchronized` nie zastępuje dowodu `Full` z FRRouting.**
Stan protokołu i trasy weryfikuje się na R1/R2 przez `vtysh`.
