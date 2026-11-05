"""C03: PacketIn byte/dispatch/state side effects vs frozen pre-C03 handler.

Comparison uses a deterministic Ryu/OpenFlow stand-in to exercise PacketIn without
spawning controller threads, plus an optional real Scapy 2.7.0 decode check.
The reference file contains the actual C01 PacketIn method, not a reimplementation.
"""
import ast
import copy
import ipaddress
from pathlib import Path
import random
import struct
import unittest
from types import SimpleNamespace as NS


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "ryu_sdn.py"
REFERENCE = Path(__file__).with_name("_c03_packet_in_reference.py")


class DummyEthernet:
    pass


class DummyIPv6:
    pass


class ScapyError(Exception):
    pass


class OSPFHeaderStub:
    def __init__(self, raw):
        (self.version, self.type, self.len, src, area, self.chksum,
         self.instance, _) = struct.unpack('!BBH4s4sHBB', raw)
        self.src = str(ipaddress.IPv4Address(src))
        self.area = str(ipaddress.IPv4Address(area))


def wire(packet_type, *, version=3, length=None, payload_length=None,
         checksum=0xBEEF, instance=0, area='0.0.0.0'):
    if payload_length is None:
        payload_length = {1: 20, 2: 12, 3: 12, 4: 4, 5: 20}.get(packet_type, 0)
    if length is None:
        length = 16 + payload_length
    return (struct.pack('!BBH4s4sHBB', version, packet_type, length,
                        ipaddress.IPv4Address('10.10.10.10').packed,
                        ipaddress.IPv4Address(area).packed,
                        checksum, instance, 0) + bytes(payload_length))


def exact_method(source):
    tree = ast.parse(source.read_text(encoding='utf-8'))
    c = next(x for x in tree.body if isinstance(x, ast.ClassDef)
             and x.name == 'OSPFv3Controller')
    meth = copy.deepcopy(next(x for x in c.body
                              if isinstance(x, ast.FunctionDef)
                              and x.name == 'packet_in_handler'))
    meth.decorator_list = []
    return compile(ast.fix_missing_locations(ast.Module(body=[meth], type_ignores=[])),
                   str(source), 'exec')


class Pkt:
    def __init__(self, payload=b'', *, ipv6_present=True, eth_present=True,
                 nxt=89, src='fe80::1', dst='ff02::5', hop_limit=1,
                 eth_dst='02:00:00:00:00:01', raw_payload=True):
        self.eth = NS(src='02:00:00:00:00:02', dst=eth_dst) if eth_present else None
        self.v6 = NS(src=src, dst=dst, hop_limit=hop_limit, nxt=nxt) if ipv6_present else None
        self.protocols = [self.eth, self.v6, payload if raw_payload else object()]

    def get_protocol(self, proto):
        if proto is DummyEthernet:
            return self.eth
        if proto is DummyIPv6:
            return self.v6
        return None


class FakeLogger:
    def __init__(self, trace):
        self.trace = trace

    def info(self, *args, **kw):
        self.trace.append(('log.info', args, kw))

    def warning(self, *args, **kw):
        self.trace.append(('log.warning', args, kw))

    def error(self, *args, **kw):
        self.trace.append(('log.error', args, kw))


class OpenFlowParser:
    def __init__(self, trace):
        self.trace = trace

    def OFPBarrierRequest(self, d):
        self.trace.append(('OFPBarrierRequest',))
        return NS(xid=0)

    def OFPActionDecNwTtl(self):
        self.trace.append(('OFPActionDecNwTtl',))
        return ('ttl',)

    def OFPActionSetField(self, **fields):
        self.trace.append(('OFPActionSetField', fields))
        return ('set', fields)

    def OFPActionOutput(self, port):
        self.trace.append(('OFPActionOutput', port))
        return ('output', port)

    def OFPPacketOut(self, **kwargs):
        self.trace.append(('OFPPacketOut', kwargs))
        return ('packetout', kwargs)


class FakeSwitch:
    def __init__(self, trace):
        self.trace = trace
        self.ofproto_parser = OpenFlowParser(trace)
        self.ofproto = NS(OFP_NO_BUFFER=0xffffffff)

    def set_xid(self, b):
        self.trace.append(('set_xid',))
        b.xid = 333

    def send_msg(self, msg):
        if isinstance(msg, NS):
            msg = ('barrier', msg.xid)
        self.trace.append(('send_msg', msg))


class FakeDataPlane:
    def __init__(self, trace, *, ndp_frame=None, echo_frame=None,
                 learn=True, transit_port=9, transit_mac='02:00:00:00:09:09'):
        self.trace = trace
        self.ndp_frame, self.echo_frame, self.learn = ndp_frame, echo_frame, learn
        self.transit_port, self.transit_router_mac = transit_port, transit_mac

    def handle_ndp(self, pkt, eth, v6, port):
        self.trace.append(('ndp', port))
        return self.ndp_frame

    def handle_echo_request(self, pkt, eth, v6, port):
        self.trace.append(('echo', port))
        return self.echo_frame

    def learn_lan_host(self, **kw):
        self.trace.append(('learn_lan_host', kw))
        return self.learn


class FakeController:
    def __init__(self, trace, *, dp, flows=True, frame_sent=True,
                 routes=(), ndp_frame=None, echo_frame=None, learn=True,
                 transit_port=9, transit_mac='02:00:00:00:09:09'):
        self.trace = trace
        self.logger = FakeLogger(trace)
        self.datapath = dp
        self.data_plane = FakeDataPlane(
            trace, ndp_frame=ndp_frame, echo_frame=echo_frame,
            learn=learn, transit_port=transit_port, transit_mac=transit_mac)
        self.pending_ndp_barriers = {}
        self.flows = flows
        self.frame_sent = frame_sent
        self.routes = routes

    def try_install_ipv6_host_flows(self):
        self.trace.append(('try_install_ipv6_host_flows',))
        return self.flows

    def send_frame(self, frame, port):
        self.trace.append(('send_frame', frame, port))
        return self.frame_sent

    def get_ospf_transit_routes(self):
        self.trace.append(('get_ospf_transit_routes',))
        return self.routes

    def __getattr__(self, name):
        if name.startswith('handle_ospf_'):
            def handler(*args):
                self.trace.append((name, args))
            return handler
        raise AttributeError(name)


class TestC03PacketInEquivalence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert SOURCE.is_file() and REFERENCE.is_file(), 'Missing C03 reference'
        cls.new = exact_method(SOURCE)
        cls.old = exact_method(REFERENCE)
        # The reference must be an independent frozen source, not the same AST.
        assert ast.dump(ast.parse(REFERENCE.read_text())) != ast.dump(ast.parse(SOURCE.read_text()))

    def execute(self, old, pkt, *, decoder=OSPFHeaderStub, flows=True,
                frame_sent=True, ndp_frame=None, echo_frame=None, learn=True,
                routes=(), transit_port=9, transit_mac='02:00:00:00:09:09',
                message_data=b'sample', in_port=7):
        trace = []
        switch = FakeSwitch(trace)
        ctrl = FakeController(trace, dp=switch, flows=flows, frame_sent=frame_sent,
                              routes=routes, ndp_frame=ndp_frame, echo_frame=echo_frame,
                              learn=learn, transit_port=transit_port,
                              transit_mac=transit_mac)

        def checksum(src, dst, payload):
            trace.append(('calculate_ospfv3_checksum', src, dst, payload))
            return 0xBEEF

        ns = {
            'packet': NS(Packet=lambda data: pkt),
            'ethernet': NS(ethernet=DummyEthernet),
            'ipv6': NS(ipv6=DummyIPv6),
            'icmpv6': NS(icmpv6=type('DummyICMP', (), {}), ND_NEIGHBOR_SOLICIT=135),
            'cfg': NS(ROUTER_MAC='02:00:00:00:00:01', AREA_ID='0.0.0.0', INSTANCE_ID=0),
            'calculate_ospfv3_checksum': checksum,
            'OSPFv3_Hdr': decoder, 'Scapy_Exception': ScapyError,
            'ipaddress': ipaddress,
        }
        exec(self.old if old else self.new, ns)
        msg = NS(match={'in_port': in_port}, data=message_data, datapath=switch)
        ev = NS(msg=msg)
        outcome = None
        try:
            result = ns['packet_in_handler'](ctrl, ev)
        except Exception as e:
            outcome = ('EXCEPTION', type(e).__name__, str(e))
        else:
            outcome = ('RETURN', result)
        return (outcome, trace, dict(ctrl.pending_ndp_barriers))

    @staticmethod
    def normalized(x):
        if isinstance(x, FakeSwitch):
            return ('datapath',)
        if isinstance(x, dict):
            return {k: TestC03PacketInEquivalence.normalized(v) for k, v in x.items()}
        if isinstance(x, (tuple, list)):
            return type(x)(TestC03PacketInEquivalence.normalized(v) for v in x)
        return x

    def compare(self, pkt, **kw):
        old = self.execute(True, pkt, **kw)
        new = self.execute(False, pkt, **kw)
        self.assertEqual(self.normalized(old), self.normalized(new))
        return new

    def test_valid_five_ospfv3_handlers(self):
        for typ in range(1, 6):
            with self.subTest(typ=typ):
                out = self.compare(Pkt(wire(typ)))
                dispatched = [x for x in out[1] if x[0].startswith('handle_ospf_')]
                self.assertEqual(len(dispatched), 1)
                self.assertEqual(dispatched[0][0],
                                 {1:'handle_ospf_hello', 2:'handle_ospf_dbd',
                                  3:'handle_ospf_lsr', 4:'handle_ospf_lsu',
                                  5:'handle_ospf_lsack'}[typ])

    def test_exact_handler_args_and_router_id(self):
        for typ, n_args in [(1,7),(2,7),(3,6),(4,6),(5,6)]:
            out = self.compare(Pkt(wire(typ)))
            handler = next(x for x in out[1] if x[0].startswith('handle_ospf_'))
            args = handler[1]
            self.assertEqual(len(args), n_args)
            self.assertEqual(args[0], 7)
            self.assertEqual(args[4] if typ == 1 else args[3], {1:36,2:28,3:28,4:20,5:36}[typ])
            if typ == 2:
                self.assertEqual(args[4], int(ipaddress.IPv4Address('10.10.10.10')))

    def test_packet_version_filter(self):
        for typ in (1,2,3,4,5,6,255):
            for version in (0,1,2,4,255):
                self.compare(Pkt(wire(typ, version=version)))

    def test_unknown_ospf_types(self):
        for typ in (0,6,7,255):
            out = self.compare(Pkt(wire(typ)))
            self.assertFalse(any(x[0].startswith('handle_ospf_') for x in out[1]))

    def test_length_boundaries_all_types(self):
        for typ, minimum in [(1,36),(2,28),(3,28),(4,20),(5,36)]:
            for len_declared in (0,15,16,minimum-1,minimum,minimum+1,100,65535):
                self.compare(Pkt(wire(typ, length=len_declared)))
            for payload_length in (0,1,3,4,8,10,12,20,36,64):
                self.compare(Pkt(wire(typ, payload_length=payload_length)))

    def test_ospf_checksum_area_and_instance(self):
        for val in (0,0xBEEE,0xFFFF):
            self.compare(Pkt(wire(4, checksum=val)))
        for area in ('0.0.0.1','2.3.4.5'):
            self.compare(Pkt(wire(4, area=area)))
        for instance in (1,3,255):
            self.compare(Pkt(wire(4, instance=instance)))

    def test_ospf_ipv6_source_destination_and_hlim(self):
        for src in ('fe80::1','2001:db8::1','bad source'):
            for dst in ('ff02::5','ff02::6','fe80::10','bad destination'):
                for hlim in (0,1,2,64,255):
                    self.compare(Pkt(wire(1), src=src,dst=dst,hop_limit=hlim))

    def test_ospf_truncated_and_non_bytes(self):
        for payload in (b'', b'\x03', b'\x03\x01', b'\x03\x01'+bytes(11), wire(1)):
            self.compare(Pkt(payload, raw_payload=False))
            self.compare(Pkt(payload))
        self.compare(Pkt(bytearray(wire(1))))

    def test_empty_and_non_ospf_ipv6(self):
        self.compare(Pkt(b'',ipv6_present=False))
        for nxt in (0,6,17,58,59,88,90,255):
            self.compare(Pkt(b'', nxt=nxt,
                             eth_dst='02:00:00:00:00:99' if nxt in (6, 17)
                             else '02:00:00:00:00:01'))

    def test_ndp_barrier_and_direct_response(self):
        for flows in (False,True):
            for frame_sent in (False,True):
                self.compare(Pkt(b'',nxt=58), ndp_frame=b'NA', flows=flows,
                             frame_sent=frame_sent)

    def test_echo_reply_returns_with_or_without_send(self):
        for frame_sent in (False,True):
            self.compare(Pkt(b'',nxt=58), echo_frame=b'ECHO',frame_sent=frame_sent)

    def test_first_icmpv6_packet_forwarding(self):
        route = {'prefix':'2001:db8:23::', 'prefix_length':64, 'next_hop':'fe80::2'}
        for learn in (False,True):
            for transit_port in (None,9):
                for transit_mac in (None,'02:00:00:00:09:09'):
                    for eth_dst in ('02:00:00:00:00:01','02:00:00:00:00:99'):
                        self.compare(Pkt(b'',nxt=58,src='2001:db8:1::100',dst='2001:db8:23::3',
                                         eth_dst=eth_dst), routes=[route], learn=learn,
                                     transit_port=transit_port,transit_mac=transit_mac)

    def test_route_preference_longest_prefix(self):
        routes = [
            {'prefix':'2001:db8::', 'prefix_length':32, 'next_hop':'fe80::1'},
            {'prefix':'2001:db8:23::', 'prefix_length':64, 'next_hop':'fe80::2'},
            {'prefix':'2001:db8:23::', 'prefix_length':64, 'next_hop':'fe80::3'},
        ]
        self.compare(Pkt(b'',nxt=58,src='2001:db8:1::100',dst='2001:db8:23::3'),routes=routes)

    def test_tcp_udp_first_packet_intentional_delta_from_frozen_c03(self):
        # Retain the frozen reference: only the new implementation forwards
        # TCP/UDP when the host, route, and next hop are available.
        route = {'prefix': '2001:db8:23::', 'prefix_length': 64,
                 'next_hop': 'fe80::2'}
        for nxt in (6, 17):
            pkt = Pkt(b'', nxt=nxt, src='2001:db8:1::100',
                      dst='2001:db8:23::3')
            prior = self.execute(True, pkt, routes=[route])
            current = self.execute(False, pkt, routes=[route])
            self.assertFalse(any(x[0] == 'OFPPacketOut' for x in prior[1]))
            self.assertEqual(sum(x[0] == 'OFPPacketOut' for x in current[1]), 1)
            self.assertEqual(sum(x[0] == 'learn_lan_host' for x in current[1]), 1)
            self.assertEqual(sum(x[0] == 'try_install_ipv6_host_flows'
                                 for x in current[1]), 1)

    def test_deterministic_random_packet_in(self):
        rng = random.Random(0xC003)
        for _ in range(1300):
            typ = rng.randrange(0,9)
            nxt = rng.choice((0,6,17,58,59,89))
            payload_length = rng.randrange(0,64)
            pkt = Pkt(wire(typ,payload_length=payload_length,
                           length=rng.choice((0,12,15,16,20,28,35,36,37,64,100,65535))),
                      nxt=nxt,hop_limit=rng.choice((0,1,2,64)),
                      src=rng.choice(('fe80::1','2001:db8::1')),
                      dst=rng.choice(('ff02::5','ff02::6','fe80::4','2001:db8::20')),
                      eth_dst='02:00:00:00:00:99' if nxt in (6, 17)
                              else '02:00:00:00:00:01')
            self.compare(pkt, flows=bool(rng.randrange(2)),
                         ndp_frame=rng.choice((None,b'NA')),
                         echo_frame=rng.choice((None,b'ECHO')))

    def test_real_scapy_decoder_if_available(self):
        try:
            from scapy.contrib.ospf import OSPFv3_Hdr
            from scapy.error import Scapy_Exception
        except ImportError:
            self.skipTest('requires real Scapy (run on Ubuntu)')
        # Match the exact Scapy exception type used by production code.
        class Adapter:
            def __init__(self, raw):
                try:
                    self.item = OSPFv3_Hdr(raw)
                except Scapy_Exception as e:
                    raise ScapyError(str(e))
            def __getattr__(self, key):
                return getattr(self.item, key)
        for typ in range(1,6):
            result = self.compare(Pkt(wire(typ)), decoder=Adapter)
            self.assertEqual(
                len([event for event in result[1] if event[0].startswith('handle_ospf_')]),
                1, f'Real Scapy must dispatch OSPFv3 type {typ}'
            )


if __name__ == '__main__':
    unittest.main()
