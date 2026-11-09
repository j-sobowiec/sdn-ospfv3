# Architektura

## Podział odpowiedzialności

1. `topology.py` uruchamia w Containernet routery FRRouting R1–R2–R3
   połączone w trójkąt oraz dwa OVS i hosty H1/H2/H3. S1 łączy R1 z H1,
   a S2 łączy R2 z H3. H2 pozostał przy R2. Tranzyty SDN–FRR to
   `2001:db8:10::/64` i `2001:db8:20::/64`.
2. `controller.py` to **jeden proces Ryu**, który przechowuje mapy
   `datapaths[dpid]` i `peers[dpid]`. `PacketIn` identyfikuje nadawcę przez
   DPID i port, a odpowiednie `PacketOut` oraz reguły `FlowMod` trafiają
   tylko do tego OVS. Rozłączenie S1 usuwa jedynie jego datapath;
   ponowne podłączenie zeruje tylko jego `Peer` i reinstaluje jego reguły.
3. `peer.py` utrzymuje **jednego sąsiada na instancję**, czyli dwie
   niezależne instancje dla S1–R1 i S2–R2 w obszarze `0.0.0.0`:
   Hello, DBD, LSR/LSU/LSAck, Dead Interval, retransmisje i LSA.
4. `packets.py` koduje i weryfikuje OSPFv3 przy użyciu Scapy. Każde
   wywołanie otrzymuje konfigurację swojego routera z `config.SWITCHES`,
   dzięki czemu Hello/Router-LSA/Link-LSA/Prefix-LSA używają odpowiednio
   `10.10.10.10` lub `10.10.10.11` oraz własnych Interface ID i prefiksów
   LAN `2001:db8:1::/64` lub `2001:db8:3::/64`.
5. FRRouting (`ospf6d`) na R1, R2 i R3 obsługuje klasyczną domenę
   OSPFv3, jej LSDB i wyliczanie tras SPF. Ryu nie uruchamia FRRouting.

## Przekazywanie IPv6

Każdy OVS ma dwie statycznie dobrane reguły `priority=100`:

| OVS | LAN → FRR (port 2 → 1) | FRR → LAN (port 1 → 2) |
| --- | --- | --- |
| S1 | źródło H1 `2001:db8:1::100`, MAC docelowy R1 | cel H1, MAC docelowy H1 |
| S2 | źródło H3 `2001:db8:3::100`, MAC docelowy R2 | cel H3, MAC docelowy H3 |

Obie reguły wymagają docelowego MAC bramy SDN. Akcje to `dec_ttl`
(obniżenie IPv6 Hop Limit), `set_field:eth_src` na MAC własnej bramy,
`set_field:eth_dst` na MAC next-hop/hosta oraz `output` na właściwy port.
Ruch z LAN do FRR dotyczy globalnych adresów IPv6 `2000::/3` z wyjątkiem
własnego LAN (priorytet 200 kieruje tę sieć do kontrolera). OSPFv3
z tranzytu ma osobny `PacketIn` o priorytecie 300, a NDP Neighbor Solicitation
o priorytecie 250; resztę nieobsłużonych pakietów przejmuje `table-miss`.

Ryu odpowiada na NDP dla `2001:db8:1::1` / `fe80::10` (S1) i
`2001:db8:3::1` / `fe80::11` (S2), a także na ping do własnej bramy LAN.
R1/R2/R3 uruchamiają SPF i instalują dynamiczne trasy OSPFv3, natomiast
**na OVS forwarding jest statycznie zaprogramowany przez Ryu** (next-hop
R1 dla S1 i R2 dla S2). Nie ma w Ryu dynamicznego przeliczania tras.

## Granice implementacji

To demonstracja dla stałej topologii z dwoma OVS, a nie uniwersalny router OSPFv3.
Negocjacja DBD zakłada rolę Master po stronie Ryu; odbiór zdalnych LSA
służy przede wszystkim obsłudze żądań i potwierdzeń, **bez kompletnej
zdalnej LSDB i bez SPF w kontrolerze**. Nie ma obsługi wielu sąsiadów,
wielu obszarów, DR/BDR, ECMP ani dowolnego wyznaczania tras przez Ryu.

Wewnętrzny stan `synchronized` w `peer.py` nie jest równoważny
potwierdzonemu `Full` po stronie FRRouting. Sąsiedztwo, LSDB i trasy
należy sprawdzać niezależnie przez `vtysh`, tablice routingu systemu, pingi
oraz liczniki `ovs-ofctl` (procedura: [README](../README.md#walidacja-integracyjna--sześć-osobnych-testów));
dotychczasowe scenariusze zachowano w [archiwum](../archive/legacy-integration/README.md).
