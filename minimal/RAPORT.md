# Raport refaktoryzacji — `minimal-ospfv3`

## Audyt kodu i decyzje

Przeanalizowano aktywne moduły `ryu_sdn.py`, `controller_openflow.py`,
`dataplane.py`, `ospfv3/*.py` oraz `topology.py` na podstawie kodu.
W nowej wersji pozostało pięć aktywnych modułów (`config`, `packets`,
`peer`, `controller`, `topology`). Starą implementację i jej historyczne
testy zachowano bez zmian.

| Zachowany mechanizm | Uproszczenie i uzasadnienie |
| --- | --- |
| Hello, DBD, LSR, LSU, LSAck | Stan i lista żądań tylko jednego sąsiada P2P; bez ogólnego silnika OSPF |
| Router-, Link-, Intra-Area-Prefix-LSA | Scapy generuje trzy niezbędne rekordy dla prefiksu LAN i łącza |
| Retransmisja i odświeżanie | Krótkie timery DBD/LSR/LSU, Dead Interval oraz refresh 1800 s |
| Kontrola pakietów | Weryfikacja area/instance, długości, IPv6 Hop Limit, sum OSPF i LSA; bez rozbudowanego parsera zawartości każdej LSA |
| LSDB | Zredukowana do nagłówków oczekiwanych w LSR; FRR liczy SPF, więc kontroler nie musi odtwarzać całej domeny |
| Sąsiad i Interface ID | `intid` odczytywany z Hello bez poszukiwania linku w zdalnym Router-LSA |
| OpenFlow + NDP | Stałe dwa porty, adresy MAC i host; dwie reguły routingu, wyjątek dla LAN i table-miss |
| Topologia | Zachowano pierwotny trójkąt trzech routerów FRR i interfejsy; dodano H2 za R2 do testu dwukierunkowego |

Usunięto odtwarzanie sekwencji po niezależnym restarcie, zdalną pełną LSDB,
jej aging/MaxAge, śledzenie zmian topologii, uczenie wielu hostów,
Barrier/synchronizację wielu reguł, szczegółową diagnostykę i inne
mechanizmy nieużywane przy czystym rozruchu demonstracji.

## Linie rzeczywistego kodu

Metoda: `tokenize` — liczone unikatowe linie z tokenami kodu, bez pustych
linii/komentarzy/indentacji; docstringi wykrywane przez `ast` i pomijane.
Kod testowy i dokumentacja nie wchodzą do porównania.

| Stara wersja, plik | Linie | Nowa wersja, plik | Linie |
| --- | ---: | --- | ---: |
| `ryu_sdn.py` | 171 | `minimal/controller.py` | 129 |
| `controller_openflow.py` | 132 | `minimal/peer.py` | 220 |
| `dataplane.py` | 113 | `minimal/packets.py` | 115 |
| `ospfv3/config.py` | 24 | `minimal/config.py` | 23 |
| `ospfv3/controller_rx.py` | 234 | | |
| `ospfv3/controller_tx.py` | 132 | | |
| `ospfv3/controller_timers.py` | 61 | | |
| `ospfv3/local_lsa.py` | 193 | | |
| `ospfv3/lsa.py` | 135 | | |
| `ospfv3/lsdb.py` | 82 | | |
| `ospfv3/neighbor.py` | 60 | | |
| `ospfv3/packet.py` | 76 | | |
| `ospfv3/parser.py` | 198 | | |
| **Aplikacja (łącznie)** | **1611** | **Aplikacja (łącznie)** | **487** |
| `topology.py` | 146 | `minimal/topology.py` | 118 |
| **Aplikacja + topologia** | **1757** | **Aplikacja + topologia** | **605** |

Redukcja o **1152 linie (65,6%)**. Wynik jest poniżej orientacyjnych
650–850 linii ze względu na świadomie ustalone adresy i porty oraz
ograniczenie obsługi do jednego sąsiada i jednego hosta SDN. Nie usuwano
formatowania ani nie łączono sztucznie instrukcji.

## Weryfikacja w dostępnym środowisku

Interpreter Python 3.12, zainstalowano Scapy 2.7.0 w lokalnym środowisku
testowym. Ze względu na zakaz otwierania gniazd netlink w piaskownicy,
testy wyłączają wyłącznie automatyczne wykrywanie interfejsów Scapy.

| Test | Wynik |
| --- | --- |
| `python -m unittest minimal.tests.test_minimal -v` | 7/7 OK — 5 typów pakietów, 3 LSA, sumy kontrolne, DBD/LSR/LSU/LSAck, timeout, zgodność bajtowa z poprzednimi builderami |
| `python -m unittest minimal.tests.test_topology -v` | 1/1 OK — oryginalny trójkąt, interfejsy i adresacja oraz dodatkowy H2 |
| `tests/test_lsa_scapy.py` (unittest + bootstrap Scapy) | 29/29 OK |
| `tests/test_parser_scapy.py` (unittest + bootstrap Scapy) | 20/20 OK |
| `ospfv3_independent_audit.py` (unittest + bootstrap Scapy) | 9/9 OK |
| `python -m compileall -q minimal` | OK |

Próba instalacji `ryu==4.34` do lokalnego venv nie powiodła się
z powodu niekompatybilności skryptu `setup.py` z dostępnym setuptools
i Pythonem 3.12 (`get_script_args` / `pkgutil.ImpImporter`).
W lokalnym środowisku roboczym nie ma Dockera, OVS ani Containernet;
nie można było w nim wykonać testów integracyjnych z `ospf6d`.
Poniżej zapisano wyniki dostarczone osobno z docelowego stanowiska.

## Testy integracyjne — wyniki dostarczone 7 listopada 2026 (poprzedni wariant)

Użytkownik wykonał testy w konsoli `containernet>` i przekazał ich
rzeczywiste wyjście. Nie zostały one uruchomione przez autora refaktoryzacji
w lokalnym środowisku roboczym. **Dotyczą wcześniejszej topologii z dwoma
routerami FRR**, gdzie R1 łączył się z SDN przez `r1-eth1`. W aktualnym
wariancie przywrócono trójkąt R1–R2–R3, a port SDN to `r1-eth2`.

| Kryterium z zadania | Status weryfikacji |
| --- | --- |
| Sąsiad `Full` w `show ipv6 ospf6 neighbor` | **PASS** — `10.10.10.10 Full/PointToPoint`, interfejs `r1-eth1` (także `2.2.2.2 Full` na `r1-eth0`) |
| Trasa `2001:db8:1::/64` na `r2` przez OSPF6 | **PASS** — `O>* 2001:db8:1::/64 [110/30]`, next hop `fe80::e084:7bff:fe4c:943a`, `r2-eth0` |
| Ping `h1 -> h2` | **PASS** — `3/3`, `0%` strat, RTT min/avg/max `0.166/1.987/5.616 ms` |
| Ping `h2 -> h1` | **PASS** — `3/3`, `0%` strat, RTT min/avg/max `0.171/0.189/0.206 ms` |
| Ponowny czysty start bez ręcznych tras | **DO SPRAWDZENIA** — brak wyników powtórzonego uruchomienia |

Przekazane wyniki potwierdziły cztery kryteria we wcześniejszym wariancie,
w tym interoperacyjność z `ospf6d`, instalację trasy OSPFv3 (kod `O`,
wybrana trasa `>` i zainstalowana w FIB `*`) oraz ruch IPv6 w obu kierunkach.
**Nie stanowią dowodu dla zmienionej topologii trójkątnej.** Dla obecnego
wariantu trzeba ponownie sprawdzić sąsiedztwa, trasę OSPF6, dwa pingi
oraz powtarzalność po czystym restarcie; polecenia podaje [`README.md`](README.md).

## Zgodność z pracą i ograniczenia

Wersja realizuje autorskie przetwarzanie protokołu OSPFv3 w Ryu i budowę
trzech lokalnych LSA przez Scapy. FRRouting odpowiada za sąsiedztwa
klasycznych routerów i obliczanie tras. OpenFlow przekazuje IPv6 w obu
kierunkach, co pozwala zweryfikować integrację SDN z klasycznym OSPFv3.

To **prototyp demonstracyjny**, a nie pełny router OSPFv3: bez multi-area,
multi-neighbor, DR/BDR, pełnego flooding/LSDB, arbitralnej numeracji portów,
trybu DBD Slave, restart recovery, SPF, ECMP, obsługi wszystkich typów LSA
i uogólnionej obsługi NDP. Po przywróceniu trzech routerów trzeba
ponownie wykonać komplet pięciu testów integracyjnych na docelowym stanowisku.
