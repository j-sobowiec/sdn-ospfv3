# Archiwum testów integracyjnych (INT-01–INT-11)

Zachowano tutaj poprzedni skrypt `run_integration.py` bez zmian, a także historyczną [procedurę ręczną](TESTY.md). Skrypt pochodzi z wersji `main` o commicie `95e96eacfaec8bed99ceee5e4c75300b5a6b92d1` (8 listopada 2026) i sprawdzał topologię **jednego OVS** z FRRouting.

To **archiwum, nie aktywny zestaw testów**. Scenariusze zostaną uzgodnione na nowo dla wielu routerów OSPFv3 reprezentowanych przez OVS. Archiwalny skrypt i jego wcześniejsze wyniki nie potwierdzają działania nowej architektury.

Dotychczasowe przypadki obejmowały:

- INT-01: sąsiedztwo OSPFv3 Full;
- INT-02–04: trasy RIB/FIB i LSA po stronie FRRouting;
- INT-05–06: ping IPv6 w obie strony;
- INT-07–08: komunikację TCP/UDP IPv6 w obie strony;
- INT-09: liczniki przekazywania OpenFlow 1.3;
- INT-10–11: wycofanie i ponowne pojawienie się tras po zatrzymaniu i restarcie kontrolera.

Skrypt po przeniesieniu wymaga jawnego `--source` wskazującego katalog główny projektu. **Nie uruchamiaj go z `--execute` na zwykłej stacji roboczej** — modyfikuje sieć, uruchamia Docker/Containernet/OVS i zatrzymuje własny proces Ryu; wymaga odizolowanego środowiska testowego. Raporty `validation/results/` nie były przechowywane w Git i nie zostały tutaj przeniesione.
