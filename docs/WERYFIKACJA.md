# Weryfikacja rozwiązania — wyniki do pracy inżynierskiej

## 1. Identyfikacja wydania

Stan projektu objęty audytem **W04c: PASS** z **25 października 2026 r.**:

- 18 modułów produkcyjnych, **4490 PLOC / 3610 SLOC**.
- Pełna regresja `unittest`: **649 testów, wszystkie OK**, bez pominięć w końcowym audycie.
- Siedem przypadków diagnostycznych: **7/7 OK**, bez `expectedFailure`.
- Skrypty W03a, W03b, W04a i W04b: **4/4 PASS**.
- Suma SHA-256 wszystkich modułów produkcyjnych zgodna z udanym pomiarem W04b.

W chwili audytu nie wykonano jeszcze końcowego commita ani tagu Git. Wyniki odnoszą się do plików zapisanych w raporcie `W04C_SHA256_PRODUKCJA.json`, nie do dowolnego późniejszego HEAD.

## 2. Metoda i testy automatyczne

| Etap | Zakres | Wynik |
|---|---|---|
| W01 | Architektura V5, moduły, importy, Ryu i Scapy | PASS; wówczas 575 testów |
| W02a | NDP: Hop Limit i Code | PASS; testy regresyjne |
| W02b | Izolacja zagnieżdżonych danych LSDB | PASS; testy regresyjne |
| W02c | Dwukierunkowe reklamy Router-LSA i NU-bit | PASS; testy regresyjne |
| W02d | Pierwszy pakiet TCP/UDP przez PacketIn/OpenFlow | PASS; testy regresyjne |
| W04c | Ponowna kompletna regresja i diagnostyka | **649/649 i 7/7 OK** |

Testy porównawcze z zamrożonymi implementacjami referencyjnymi służą wykrywaniu niezamierzonych zmian, ale w przypadkach świadomej naprawy błędu przyjęte oczekiwania zostały jawnie zaktualizowane. Dla W02c w historycznym D05 sprawdza się nadal wszystkie 2600 losowych topologii, przy uwzględnieniu odrzucania niepotwierdzonych krawędzi.

Uruchomienie:

```bash
cd ~/Inzynierka
source ~/ryu-env/bin/activate
export PYTHONDONTWRITEBYTECODE=1
python -m unittest discover -s tests -p 'test_*.py' -q
python -m unittest discover -s tests -p 'diagnose_*.py' -q
```

Wynik stanowi dowód poprawności w zakresie scenariuszy testowych, nie dowód kompletności normatywnej całego OSPFv3.

## 3. Interoperacyjność i łączność

Topologia obejmuje R1/R2/R3 z FRRouting, przełącznik OVS S1 oraz hosta H1. Dla poprawnej pracy oczekiwano trzech sąsiedztw z perspektywy R1, w tym Ryu o Router ID `10.10.10.10`. Obie trasy z R2 i R3 do `2001:db8:1::/64` powinny mieć koszt 30. Powtarzane serie testów ICMPv6 wykazywały **9/9** odpowiedzi.

## 4. Odporność i stabilność (dowody W03/W04)

| Etap | Metoda | Wynik |
|---|---|---|
| **W03a** | Restart procesu kontrolera bez zamykania topologii; stan przed i po | PASS: sąsiedztwa `Full`, LSDB, trasy koszt 30, 9/9 pingów, 18 niezmienionych plików |
| **W03b** | Wyłączenie R1–R3 i przywrócenie łącza | PASS: koszt R3→H1 **30 → 40 → 30**; wyjście **eth1 → eth0 → eth1**; **27/27 pingów** |
| **W04a** | Dziewięć próbek co pięć minut przez 40 min | PASS: wszystkie oczekiwane sąsiedztwa `Full`, **81/81 pingów**; Router-LSA i Prefix-LSA Ryu `0x80000001 → 0x80000002` |
| **W04b** | TCP/UDP w dwóch kierunkach H1↔R3 | PASS: **4/4 sesje**, TCP 2×128 KiB z SHA-256, UDP 2×12/12 odpowiedzi |
| **W04c** | Ponowna kontrola testów, wyników, hashy i archiwum | PASS; wszystkie cztery walidatory W03/W04 zaliczone |

W04b na początku odrzucał odpowiedź UDP z innego prawidłowego adresu interfejsu R3; problem dotyczył serwera testowego związanego z `::`. Po związaniu go z konkretnym adresem docelowym test został powtórzony i zaliczony. Pierwszą nieudaną próbę zachowano oddzielnie jako dowód diagnozy.

## 5. Ograniczenia metodologiczne

1. Próby z W03a/W03b wykorzystują ręcznie zapisane znaczniki czasu operatora. Stan routerów i tras był mierzony, ale znaczniki nie poświadczają same w sobie zdarzeń systemowych.
2. W04a próbkowano co 5 minut. Nie da się wykluczyć bardzo krótkiego zaniku sąsiedztwa i ponownego ustalenia między próbkami.
3. W04b potwierdza działanie aplikacji przez sieć, **nie** dowodzi, że każda pojedyncza ramka wywołała PacketIn; pierwszy pakiet i akcje OpenFlow sprawdzano osobno w W02d.
4. W02c sprawdza wzajemne wskazanie Router ID z Router-LSA dla zdalnych routerów; nie implementuje pełnej walidacji par Interface ID dla każdego typu połączenia.
5. Testy obejmują ustaloną topologię i wybrane awarie. Nie należy wnioskować o pełnej zgodności z RFC 5340 ani bezawaryjności wszystkich możliwych topologii.
6. Dla odtwarzalności potrzebne są dokładne wersje zależności i obrazów — wartości trzeba odczytać z rzeczywistej platformy.

## 6. Położenie dowodów

Na maszynie Ubuntu:

```text
~/Inzynierka_weryfikacja/
  W01_20261025_104815_S2EDFp/
  W03a_RESTART/
  W03b_AWARIA_LACZA/
  W04a_STABILNOSC/
  W04b_TCP_UDP/
  W04c_20261025_144317/
```

W katalogu W04c znajdują się m.in. `W04C_RAPORT.md`, `W04C_SHA256_PRODUKCJA.json`, `W04C_TEST_649.log`, `W04C_DIAGNOSTICS_7.log`, `W04C_SRODOWISKO.json` i `W04C_ZRODLA_TESTY.zip`. Dokładne nazwy zawartości sprawdź lokalnie. Katalogi dowodów **nie są częścią 18 modułów produkcyjnych** i powinny pozostać w archiwum poza Git.

Dla pracy dołącz istotne wycinki logów, konfigurację środowiska i identyfikator końcowego commita/tagu, gdy powstanie. Nie wklejaj wszystkich wielotysięcznych logów do głównego tekstu.
