# Porządkowanie repozytorium i przygotowanie pracy

## 1. Reguła nadrzędna

**Nie usuwać żadnego z 18 modułów produkcyjnych ani żadnego pliku z `tests/`**, w szczególności `tests/_*_reference.py`, bez uprzedniego sprawdzenia zależności i ponownej regresji. Zamrożony W04c stanowi referencję integralności źródeł.

## 2. Kategorie plików na podstawie `git status` z 25.10.2026

| Grupa | Zalecenie |
|---|---|
| Wszystkie 18 plików wyliczonych w `ARCHITEKTURA.md` | Zostawić w repozytorium |
| Cały katalog `tests/` (testy, diagnostyki, referencje i `b5_3_harness.py`) | Zostawić w repozytorium |
| `__pycache__/`, `*.pyc`, `*.pyo`, cache testów | Nie wersjonować; zawartość można odtworzyć |
| `ospfv3/local_lsa.py.bak`, `ospfv3/lsa.py.bak`, `ospfv3/parser.py.bak_B2b`, `ryu_sdn.py.bak_B4` | Przenieść do archiwum poza repozytorium, nie kasować jedynej kopii |
| `ryu_debug.log` | Archiwum dowodów poza repozytorium; uważaj na dane środowiskowe w logu |
| `ospfv3_baseline_tests.py`, `ospfv3_independent_audit.py` | Zachować jako narzędzia badań lub osobne `tools/`, po sprawdzeniu importów |
| `test_parser_scapy.py`, `send_lsr_test.py`, `skrypt.py` | Najpierw sprawdzić, czy są wywoływane w instrukcjach lub przez inne skrypty; potem archiwizować/porządkować |
| `topology_baseline.py` | Wersja historyczna topologii: archiwum lub `research/` po potwierdzeniu, że `topology.py` jest wersją używaną |
| `~/Inzynierka_weryfikacja/` i raporty W03/W04 | Zachować poza repozytorium jako materiał eksperymentalny |

Pierwszy krok porządkowy to **archiwizowanie**, nie destrukcyjne usuwanie. Szczególnie skryptów `skrypt.py` i `send_lsr_test.py` nie uznajemy za zbędne na podstawie samej nazwy.

## 3. Problem z plikami `.pyc` śledzonymi przez Git

W wyświetlonym `git status` część skompilowanych plików Pythona miała status `M` lub `D`, ponieważ były historycznie dodane do indeksu Git. Sam `.gitignore` **nie usuwa** już śledzonych plików z indeksu. Przy późniejszym porządkowaniu Git trzeba świadomie użyć `git rm --cached` dla konkretnych śledzonych cache i sprawdzić staged diff. Nie rób tego w etapie P01.

Proponowane przyszłe reguły `.gitignore` (najpierw przegląd istniejącego pliku):

```gitignore
__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.venv/
venv/
ryu-env/
*.log
*.bak
*.bak_*
```

Uwaga: `*.log` i kopie `.bak` nadal zachowuj w zewnętrznym archiwum, gdy są dowodami eksperymentów.

## 4. Co wpisać do pracy

- Przedmiot i zakres implementacji; wyraźnie oddziel Ryu/OpenFlow, Scapy, własne FSM/LSDB/SPF oraz FRRouting jako peer.
- Opis topologii i adresacji z `topology.py`, wraz z konfiguracją IPv6 i OpenFlow 1.3.
- Diagram architektury i opis 18 modułów; nie sugeruj, że miksy mają niezależny stan.
- Zasady przetwarzania OSPFv3 Hello, DBD, LSR, LSU i LSAck oraz mechanizmu LSA/ACK/retransmisji.
- Implementację grafu, algorytmu Dijkstry i decyzji o trasach IPv6.
- Metodologię testów jednostkowych, integracyjnych, awarii, stabilności i TCP/UDP.
- Zakres i ograniczenia testów; ważne są warunki pomiarów i liczbowe wyniki, nie tylko sam komunikat PASS.
- Zestaw dokładnych wersji i identyfikator obrazu FRR, wynik `W04C_SRODOWISKO.json`, końcowy identyfikator Git.

## 5. Po czym można uznać repozytorium za gotowe do publikacji

1. Komplet 18 modułów i `tests/` pozostaje w repozytorium.
2. Dokumenty nie zawierają danych wrażliwych, prywatnych adresów produkcyjnych ani haseł.
3. Pliki binarne `.pyc`, środowiska wirtualne, logi i kopie `.bak` nie są częścią nowego commita.
4. Polecenie `python -m unittest discover -s tests -p 'test_*.py' -q` kończy się `649 tests ... OK`; diagnostyki `7 tests ... OK`.
5. Podane ograniczenia protokołu i testów są zgodne z rzeczywistymi dowodami.
6. Gdy dokumentacja i repozytorium zostaną ostatecznie zatwierdzone: wykonaj kontrolowany commit i tag **dopiero** po przeglądzie `git diff --cached`.

P01 dodaje wyłącznie Markdown i nie modyfikuje kodu, hashy 18 modułów ani obecnej serii 649 testów.
