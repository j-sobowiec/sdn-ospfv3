# Architektura

## Podział odpowiedzialności

1. `topology.py` uruchamia w Containernet routery FRRouting R1–R2–R3
   połączone w trójkąt, przełącznik OVS S1 i hosty H1/H2. R1 łączy się
   z S1 przez sieć tranzytową `2001:db8:10::/64`, H1 jest w sieci SDN
   `2001:db8:1::/64`, a H2 przy R2 w `2001:db8:2::/64`.
2. `controller.py` jest aplikacją Ryu. Odbiera OSPFv3 przez OpenFlow
   `PacketIn` z portu tranzytowego S1 i przekazuje ramki do `Peer`.
   Instaluje również reguły OpenFlow 1.3 i obsługuje wybrane ICMPv6/NDP.
3. `peer.py` utrzymuje **jednego** sąsiada OSPFv3 (R1) w obszarze
   `0.0.0.0`: Hello, negocjację DBD, LSR/LSU/LSAck, Dead Interval,
   retransmisje i okresowe odświeżanie własnych LSA.
4. `packets.py` koduje i weryfikuje pakiety przy użyciu Scapy oraz
   generuje Router-LSA, Link-LSA i Intra-Area-Prefix-LSA, w tym reklamę
   `2001:db8:1::/64`. Parametry adresacji i portów są w `config.py`.
5. FRRouting (`ospf6d`) na R1, R2 i R3 obsługuje klasyczną domenę
   OSPFv3, jej LSDB i wyliczanie tras SPF. Ryu nie uruchamia FRRouting.

## Przekazywanie IPv6

S1 ma dwie statycznie dobrane reguły routingu OpenFlow (H1→R1 i
R1→H1): obniżają Hop Limit, podmieniają adresy MAC i kierują ramki
na odpowiedni port. Osobne reguły przekazują wybrany ruch i pakiety
bez dopasowania do kontrolera. Ryu odpowiada na NDP tylko dla znanych
adresów bramy LAN (`2001:db8:1::1`) i tranzytu (`fe80::10`), a na LAN
obsługuje także echo ICMPv6 skierowane do bramy.

## Granice implementacji

To demonstracja dla stałej topologii, a nie uniwersalny router OSPFv3.
Negocjacja DBD zakłada rolę Master po stronie Ryu; odbiór zdalnych LSA
służy przede wszystkim obsłudze żądań i potwierdzeń, **bez kompletnej
zdalnej LSDB i bez SPF w kontrolerze**. Nie ma obsługi wielu sąsiadów,
wielu obszarów, DR/BDR, ECMP ani dowolnego wyznaczania tras przez Ryu.

Wewnętrzny stan `synchronized` w `peer.py` nie jest równoważny
potwierdzonemu `Full` po stronie FRRouting. Sąsiedztwo, LSDB i trasy
należy sprawdzać niezależnie przez `vtysh` i tablice routingu systemu;
procedura znajduje się w [TESTY.md](TESTY.md).
