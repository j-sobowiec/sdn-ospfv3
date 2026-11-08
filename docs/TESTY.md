# Testy funkcjonalne i integracyjne

Uruchom Ryu i Containernet według `README.md`.
Poniższe polecenia wykonaj w CLI `containernet>`:

```text
r1 vtysh -c 'show ipv6 ospf6 neighbor'
r1 vtysh -c 'show ipv6 ospf6 database'
r1 vtysh -c 'show ipv6 ospf6 route'
r2 ip -6 route show 2001:db8:1::/64
h1 ping -6 -c 5 2001:db8:2::100
h2 ping -6 -c 5 2001:db8:1::100
h1 ping -6 -c 5 2001:db8:23::3
```

Warunki akceptacji: sąsiad Ryu `10.10.10.10` ma `Full` na R1,
lokalne LSA reklamują `2001:db8:1::/64`, R2 ma trasę `proto ospf`,
a pingi działają w obu kierunkach. Na hoście Ubuntu sprawdź liczniki:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

## Restart kontrolera

Pozostaw Containernet uruchomiony. Zatrzymaj Ryu (`Ctrl+C`),
odczekaj ponad Dead Interval (~40 s), potwierdź zanik sąsiada
na R1 i uruchom Ryu ponownie. Oczekiwane: ponowny `Full`,
odtworzona trasa OSPF, pingi w obie strony oraz odebrane
`LSAck` bez stałego retransmitowania lokalnych LSU.

## Zalecane dodatkowe próby przed obroną

- TCP i UDP w obu kierunkach wraz z weryfikacją danych.
- Awaria i przywrócenie R1–R3, rekonwergencja przez R2.
- Ponowne połączenie OVS z kontrolerem.
- Działanie przez minimum 30–40 minut (Hello, Dead i LSA refresh).
- Negatywne testy błędnych pakietów OSPFv3 oraz NDP.

Nie uznawaj tych prób za zaliczone bez zarejestrowanych wyników.

## Automatyczne

Projekt ma już [testy offline i 11 scenariuszy integracyjnych](../validation/README.md).
Z katalogu głównego repozytorium:

```bash
make setup-tests              # jednorazowo
make test                     # offline, bez uprawnień administratora
make preflight                # bez zmian sieciowych
make integration CONFIRM=YES  # wyłącznie na dedykowanym Ubuntu
```

Testy integracyjne samodzielnie uruchamiają i zatrzymują Ryu oraz Containernet;
**nie** uruchamiaj ich równolegle z topologią z sekcji powyżej.
Dowody trafiają do `validation/results/`, który jest wykluczony z Git.
