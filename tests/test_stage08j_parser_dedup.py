"""08J: frozen 08I parser versus optimized 08J wire/error behavior."""

import ast
import hashlib
from pathlib import Path
import random
import unittest

import test_stage06_protocol_contract as protocol


ROOT = Path(__file__).resolve().parents[1]
OLD = ROOT / "tests/_stage08j_parser_reference.py"
NEW = ROOT / "ospfv3/parser.py"
FROZEN_08J = ROOT / "tests/_stage09c_parser_reference.py"
OLD_SHA = "0d51dc103e839ccb953737a5abe057683a3885d317a5fc73441977e09e2219fc"
NEW_SHA = "8a83496abd344f888890c5f28d57fa7a63df9e4c320ff47d1c0ce711e2a8dfc9"


def load(path):
    return protocol.load_symbols(path, protocol.parser_environment,
                                 ("_LSA_BODY_PARSERS",))


OLD_PARSER = load(OLD)
NEW_PARSER = load(NEW)


def run(symbols, name, raw, length):
    return protocol.outcome(symbols[name], raw, length)


class Stage08JParserDedup(unittest.TestCase):
    def test_pins_and_line_reduction(self):
        self.assertEqual(hashlib.sha256(OLD.read_bytes()).hexdigest(), OLD_SHA)
        self.assertEqual(hashlib.sha256(NEW.read_bytes()).hexdigest(), NEW_SHA)
        self.assertEqual(hashlib.sha256(FROZEN_08J.read_bytes()).hexdigest(),
                         "36d7846c52a0e102c534a2a60d951be9ed29f17cccd5260fa8460785d6a4e155")
        self.assertGreaterEqual(len(OLD.read_text().splitlines()) -
                                len(FROZEN_08J.read_text().splitlines()), 9)

    def test_only_hello_and_lsu_changed(self):
        def functions(path):
            return {node.name: ast.dump(node, include_attributes=False)
                    for node in ast.parse(path.read_text()).body
                    if isinstance(node, ast.FunctionDef)}
        before, after = functions(OLD), functions(FROZEN_08J)
        self.assertEqual(before.keys(), after.keys())
        for name in before.keys() - {"parse_hello", "parse_lsu"}:
            with self.subTest(name=name):
                self.assertEqual(before[name], after[name])

    def test_hello_neighbors_and_truncation_randomized(self):
        randomizer = random.Random(80911)
        for index in range(300):
            count = randomizer.randrange(7)
            raw = protocol.ospf_packet(1, b"\0" * (20 + count * 4))
            decoded = protocol.FakeHello(
                intid=7, prio=1, options=0x13, hellointerval=10,
                deadinterval=40, router="0.0.0.0", backup="0.0.0.0",
                neighbors=["1.1.1.1"] * randomizer.randrange(7))
            protocol.FakeHeader.registered[raw] = decoded
            length = (len(raw) if index % 3 else randomizer.randrange(len(raw) + 8))
            with self.subTest(index=index, count=count, length=length):
                self.assertEqual(run(OLD_PARSER, "parse_hello", raw, length),
                                 run(NEW_PARSER, "parse_hello", raw, length))

    def test_lsu_count_and_boundary_randomized(self):
        randomizer = random.Random(80912)
        for index in range(300):
            items = [protocol.lsa_packet(0x200b, bytes([i]) * randomizer.randrange(7))
                     for i in range(randomizer.randrange(5))]
            count = randomizer.choice((len(items), len(items) + 1, 0, 0xffffffff))
            raw = protocol.ospf_packet(4, count.to_bytes(4, "big") + b"".join(items))
            length = (len(raw) if index % 4 else randomizer.randrange(len(raw) + 8))
            with self.subTest(index=index, declared=count, items=len(items)):
                self.assertEqual(run(OLD_PARSER, "parse_lsu", raw, length),
                                 run(NEW_PARSER, "parse_lsu", raw, length))


if __name__ == "__main__":
    unittest.main()
