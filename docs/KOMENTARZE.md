# P01 — przegląd komentarzy i docstringów

## Decyzja

**Na tym etapie nie modyfikować komentarzy w plikach `.py`.** W04c potwierdził sumy SHA-256 18 modułów produkcyjnych. Nawet zmiana samego docstringu zmieni hash i może wpłynąć na testy sprawdzające zgodność AST. Historyczne opisy są stylistycznie przestarzałe, ale nie są usterką działania.

Poniżej miejsca znalezione w rzeczywistych źródłach oraz propozycje docstringów **do ewentualnego osobnego kroku P02**, jeśli potrzebujesz wersji stricte publikacyjnej. Propozycje nie zostały automatycznie nałożone.

| Plik | Obecne odwołanie historyczne | Sens opisu docelowego |
|---|---|---|
| `controller_openflow.py` | „The seven methods below are copied without modifying their ASTs.” | Mixin reguł przepływów OpenFlow 1.3 i wysyłania ramek; korzysta ze stanu RyuApp |
| `ospfv3/controller_diagnostics.py` | „... formatting, and exceptions from V4.” | Diagnostyka zdarzeń OSPFv3 oraz obliczeń SPF i stanu tras |
| `ospfv3/controller_rx.py` | „... identical to M03 ... method ASTs are preserved” | Odbiór i obsługa Hello/DBD/LSR/LSU/LSAck, kontrole sąsiedztwa i LSDB |
| `ospfv3/controller_tx.py` | „Production method bodies are unchanged from M04.” | Generowanie i transmisja komunikatów, inicjowanie DBD, ACK i lokalnych LSA |
| `ospfv3/controller_timers.py` | „... original loop bodies. No lifecycle changes...” | Okresowe Hello, wykrywanie Dead, aging LSDB, retransmisje i refresh LSA |

## Przykładowe opisy techniczne (nie do automatycznego wklejenia)

**`controller_openflow.py`:** „Metody pomocnicze Ryu dla instalowania i usuwania reguł OpenFlow 1.3 oraz wysyłania PacketOut. Mixin korzysta ze wspólnego stanu kontrolera i nie rejestruje zdarzeń Ryu.”

**`ospfv3/controller_rx.py`:** „Obsługa odbieranych pakietów OSPFv3: Hello, DBD, LSR, LSU i LSAck. Metody korzystają ze stanu sąsiedztwa, LSDB i funkcji transmisji udostępnianych przez aplikację Ryu.”

**`ospfv3/controller_tx.py`:** „Tworzenie i transmisja komunikatów OSPFv3, zarządzanie sekwencją DBD i odświeżaniem lokalnych reklam. Stan i cykl życia należą do OSPFv3Controller.”

**`ospfv3/controller_timers.py`:** „Okresowe zadania OSPFv3: Hello, timeout sąsiada, aging LSDB, retransmisja i refresh LSA. Zadania są uruchamiane z aplikacji Ryu przez hub.spawn.”

**`ospfv3/controller_diagnostics.py`:** „Metody formatowania dzienników OSPFv3, informacji o aktualizacjach LSA, wynikach SPF i trasach IPv6. Mixin nie utrzymuje własnego stanu.”

## Co należy bezwzględnie zachować

- Komentarze o kolejności `FlowMod`, barier i `PacketOut` oraz o ścieżce NS/NDP.
- Komentarze o retransmisji, timerach, resetowaniu sąsiedztwa i aktualizowaniu LSDB.
- Komentarze o wyjątku grafu dla lokalnego routera Ryu oraz wymaganej zwrotności zdalnych Router-LSA.
- Komentarze o NU-bit i zasadzie pierwszeństwa tras bezpośrednich.
- Informacje o ograniczeniach i ryzykach zależności od Eventlet.

## Kryterium ewentualnego P02

Po zmodyfikowaniu choć jednego pliku `.py`: zachować plik referencyjny, sprawdzić `git diff --check`, przejść pełną regresję 649/649 i 7/7 diagnostyk oraz stworzyć **nowy** manifest SHA-256/audyt. Nie wolno późniejszej wersji opisywać jako bajtowo identycznej ze stanem W04c.
