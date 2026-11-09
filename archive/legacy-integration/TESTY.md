# Archiwalna procedura testowania — topologia z jednym OVS

Ten dokument opisuje poprzedni scenariusz testowy. Nie jest aktualną procedurą walidacji rozwijanej topologii.

Uruchom Ryu i Containernet według [README projektu](../../README.md).
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

Oczekiwane wyniki (do potwierdzenia na uruchomionej wersji): sąsiad
Ryu `10.10.10.10` ma `Full` na R1, LSA reklamują `2001:db8:1::/64`,
R2 ma trasę protokołu OSPFv3 w FRRouting i w tablicy Linux
(np. `proto ospf6`), a pingi działają w obu kierunkach. Na hoście Ubuntu
sprawdź liczniki:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

## Restart kontrolera

Pozostaw Containernet uruchomiony. Zatrzymaj Ryu (`Ctrl+C`),
odczekaj ponad Dead Interval (40 s według `config.py`), potwierdź
zanik sąsiada na R1 i wycofanie trasy na R2, a następnie uruchom Ryu
ponownie. Oczekiwane: ponowny `Full`, odtworzona trasa OSPF i pingi
w obu kierunkach. Log kontrolera pozwala dodatkowo sprawdzić LSAck
i retransmisje lokalnych LSU.

## Zalecane dodatkowe próby przed obroną

- Awaria i przywrócenie R1–R3, rekonwergencja przez R2.
- Ponowne połączenie OVS z kontrolerem.
- Działanie przez minimum 30–40 minut (Hello, Dead i LSA refresh).
- Negatywne testy OSPFv3 i NDP w rzeczywistym środowisku sieciowym.

Nie uznawaj tych prób za zaliczone bez zarejestrowanych wyników.

