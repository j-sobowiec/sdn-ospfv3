# Architektura kontrolera SDN / OSPFv3

## 1. Cel i granice rozwiązania

Kontroler, działający jako aplikacja Ryu, utrzymuje sąsiedztwo OSPFv3 z routerem FRRouting przez sieć tranzytową i wykorzystuje otrzymane reklamy LSA do obliczania tras oraz programowania przełącznika OpenFlow 1.3. Host H1 komunikuje się przez wirtualną bramę IPv6 kontrolera. Stan protokołu OSPFv3 pozostaje we własnym kodzie projektu — Scapy obsługuje format wybranych nagłówków/komunikatów i LSA.

Nie należy utożsamiać rozdzielenia modułów z pełną niezależnością protokołu od Ryu: miksy RX/TX, timerów i diagnostyki współdzielą stan obiektu kontrolera przez `self`.

## 2. Moduły produkcyjne (18)

| Moduł | Odpowiedzialność |
|---|---|
| `ryu_sdn.py` | `OSPFv3Controller`, inicjalizacja, obsługa zdarzeń OpenFlow, odbiór PacketIn, koordynacja zmian tras |
| `controller_openflow.py` | `OpenFlowMixin`: budowa i usuwanie FlowMod, przesyłanie PacketOut, reguły IPv6 |
| `dataplane.py` | `DataPlane`: uczenie adresów hostów/transitu, Neighbor Discovery, odpowiedzi ICMPv6 |
| `topology.py` | Definicja trójkąta R1–R2–R3, OVS S1, H1, interfejsów i konfiguracji FRR |
| `run_ryu.py` | Entry point menedżera Ryu z przygotowaniem Eventlet |
| `ospfv3/__init__.py` | Definicja pakietu |
| `ospfv3/config.py` | Identyfikatory, prefiksy IPv6, metryki i timery protokołu |
| `ospfv3/controller_diagnostics.py` | `OSPFDiagnosticsMixin`: logi Hello/DBD/LSU, SPF i tras |
| `ospfv3/controller_rx.py` | `OSPFReceiveMixin`: obsługa Hello, DBD, LSR, LSU, LSAck oraz walidacja nadawcy |
| `ospfv3/controller_tx.py` | `OSPFTransmitMixin`: wysyłanie komunikatów, sekwencje DBD, retransmisje i ponowna inicjacja LSA |
| `ospfv3/controller_timers.py` | `OSPFTimerMixin`: pętle Hello, Dead, aging, retransmisji i refresh LSA |
| `ospfv3/local_lsa.py` | `LocalLSA`: generowanie Router-LSA, Intra-Area-Prefix-LSA i Link-LSA, obsługa lokalnych sekwencji |
| `ospfv3/lsa.py` | Parsowanie i porównywanie instancji LSA, checksumy, sekwencje |
| `ospfv3/lsdb.py` | `LSDB`: instalowanie LSA, odmładzanie/starszenie, usuwanie rekordów, izolacja danych wejściowych (`deepcopy`) |
| `ospfv3/neighbor.py` | `Neighbor`: dane sesji i postęp sąsiedztwa/DBD |
| `ospfv3/packet.py` | Budowa ramek/komunikatów Hello, DBD, LSR, LSU, LSAck; kodowanie przy użyciu Scapy |
| `ospfv3/parser.py` | Dekodowanie komunikatów OSPFv3 do struktur używanych przez kontroler |
| `ospfv3/routing.py` | `Routing`: budowa grafu routerów, Dijkstra SPF, next-hop, prefiksy i tabela IPv6 |

Każdy z tych plików jest częścią zestawu 18 modułów sprawdzonych w W04c. Pliki z `tests/` stanowią oddzielny zestaw testowy, ale są istotne dla odtworzenia walidacji.

## 3. Przepływ sterowania i danych

```text
                  Ryu (OSPFv3Controller)
                 ryu_sdn.py / zdarzenia Ryu
                             |
            +----------------+----------------+
            |                |                |
       OSPFv3 RX/TX       LSDB i SPF     DataPlane / OpenFlow
       parser, packet    local_lsa,lsa   NDP, IPv6, FlowMod
            |                |                |
         Scapy          Routing (SPF)       OVS S1
            |                |                |
       LSA od FRR -----> Trasy IPv6 -----> IPv6 H1 ↔ routery FRR
```

Szkic przedstawia odpowiedzialność logiczną, nie diagram wszystkich wywołań funkcji.

1. OpenFlow zgłasza `PacketIn` do aplikacji Ryu.
2. Kontroler rozpoznaje OSPFv3 (IPv6 Next Header 89) i deleguje odpowiedni typ komunikatu do miksinu RX; moduły parserów/LSA rozpoznają zawartość pakietu.
3. Odebrane reklamy są weryfikowane i instalowane w `LSDB`, a lokalne reklamy powstają w `LocalLSA`.
4. `Routing` przelicza SPF i prefiksy IPv6, a logika OpenFlow aktualizuje reguły w OVS.
5. Dla ruchu hosta kontroler obsługuje NDP oraz pierwszy pakiet ICMPv6/TCP/UDP do znanego celu przez istniejącą ścieżkę OpenFlow.
6. Pięć pętli sterowanych przez `hub.spawn` obsługuje zdarzenia okresowe, w tym Dead i odświeżanie LSA.

## 4. Topologia referencyjna

```text
R1 (1.1.1.1) ------ R2 (2.2.2.2)
  \                    /
   \                  /
    ------ R3 (3.3.3.3)
 |
 R1 -- OVS S1 -- H1 (2001:db8:1::100/64)
              brama IPv6: 2001:db8:1::1
```

Fizyczne/przestrzenne interfejsy w scenariuszu Containernet:

| Segment | Interfejsy | Sieć |
|---|---|---|
| R1–R2 | `r1-eth0`, `r2-eth0` | `2001:db8:12::/64` |
| R2–R3 | `r2-eth1`, `r3-eth0` | `2001:db8:23::/64` |
| R3–R1 | `r3-eth1`, `r1-eth1` | `2001:db8:31::/64` |
| R1–S1 | `r1-eth2` | `2001:db8:10::/64` |
| S1–H1 | brama emulowana przez Ryu | `2001:db8:1::/64` |

Ryu przedstawia się jako router OSPFv3 o Router ID `10.10.10.10` (Area `0.0.0.0`) oraz udostępnia `fe80::10` i `2001:db8:10::2` na transicie. H1 korzysta z bramy `2001:db8:1::1`.

## 5. Zasady protokołu i wprowadzone poprawki

- NDP: odrzucane są Neighbor Solicitation z nieprawidłowym Hop Limit (wymagany 255) lub ICMPv6 Code (wymagane 0). Nie wolno przy okazji uczyć nieprawidłowego nadawcy.
- LSDB: instalowana LSA jest migawką danych (`deepcopy`), więc późniejsze modyfikowanie obiektu wejściowego nie zmienia ukrycie bazy.
- SPF: dla zdalnych łączy punkt-punkt wymagane jest zwrotne wskazanie routera w Router-LSA; reprezentacja lokalnego węzła Ryu zachowuje specjalną syntetyczną krawędź. Nie jest to pełne sprawdzanie wzajemnych numerów Interface ID dla każdego łącza.
- Prefiksy z bitem `NU` (*No Unicast*) nie są instalowane jako trasy unicast.
- Pierwsza ramka IPv6 TCP/UDP/ICMPv6 do znanego celu może być przekazana przez `PacketOut` przy zachowaniu istniejących warunków instalacji przepływów i next-hop.

## 6. Parametry i ograniczenia

`ospfv3/config.py` definiuje m.in. Hello = **10 s**, Dead = **40 s**, retransmisję = **5 s**, refresh LSA = **1800 s**, MaxAge = **3600 s**, koszt łącza = **10** oraz koszt prefiksu LAN = **10**.

Zakres prac udokumentowany testami nie stanowi certyfikacji pełnej interoperacyjności ze wszystkimi implementacjami OSPFv3 ani wszystkimi typami sieci, obszarów, uwierzytelniania i LSA. Framework Ryu i jego Eventlet pozostają zależnościami projektu; ostrzeżenia deprecacyjne `cgi`/Eventlet nie były przedmiotem migracji frameworka.
