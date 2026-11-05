"""C01: exact FlowMod ctor arguments, instruction/actions and send order.

Uses existing B5.3 AST harness, no Ryu threads or FRR; real integration is
required on Ubuntu after patch. The reference contains verbatim old methods.
"""
import random
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import MagicMock

import b5_3_harness as h

ReferenceMethods = h.load_class(
    Path(__file__).with_name('_c01_original_flow_methods.py'),
    'OriginalFlowMethods', {**h.BASE, 'DataPlane': h.DataPlane},
)
class ReferenceController(ReferenceMethods, h.Controller):
    pass


def new_pair(*, ready=True, route=True):
    old = h.make_controller(ready=ready, route=route)
    old.__class__ = ReferenceController
    new = h.make_controller(ready=ready, route=route)
    old.logger = recording_logger()
    new.logger = recording_logger()
    return old, new


class recording_logger:
    def __init__(self):
        self.messages = []
    def info(self, *args, **kwargs):
        self.messages.append(('info', args, kwargs))
    def warning(self, *args, **kwargs):
        self.messages.append(('warning', args, kwargs))
    def error(self, *args, **kwargs):
        self.messages.append(('error', args, kwargs))
    debug = info


def canon(value):
    if value.__class__.__name__ == 'OFMsg':
        return ('OF', value.kind, tuple(canon(x) for x in value.args),
                tuple((k, canon(v)) for k, v in vars(value).items()
                      if k not in ('kind','args')))
    if value.__class__.__name__ == 'Switch':
        return 'datapath'
    if isinstance(value, dict):
        return ('dict', tuple((canon(k), canon(v)) for k, v in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(canon(x) for x in value)
    return value


def snapshot(c):
    return (
        [canon(m) for m in c.datapath.sent] if c.datapath is not None else None,
        canon(c.installed_ipv6_host_flows),
        canon(c.pending_ndp_barriers),
        canon(c.data_plane.lan_hosts),
        c.logger.messages[:],
    )


def compare(test, old, new, method, *args, **kwargs):
    old_error = new_error = None
    old_return = new_return = None
    try:
        old_return = getattr(old, method)(*args, **kwargs)
    except Exception as e:
        old_error = (type(e), str(e))
    try:
        new_return = getattr(new, method)(*args, **kwargs)
    except Exception as e:
        new_error = (type(e), str(e))
    test.assertEqual(new_error, old_error)
    test.assertEqual(new_return, old_return)
    test.assertEqual(snapshot(new), snapshot(old))
    return old_error


class TestC01FlowModEquivalence(unittest.TestCase):
    def test_one_host_three_add_flows_exact(self):
        o, n = new_pair()
        compare(self, o, n, 'try_install_ipv6_host_flows')
        self.assertEqual([x.priority for x in n.datapath.sent], [200, 110, 100])

    def test_two_hosts_order_and_actions(self):
        o, n = new_pair()
        for c in (o, n):
            c.data_plane.learn_lan_host(2, '2001:db8:1::101','02:00:00:00:01:01')
        compare(self, o, n, 'try_install_ipv6_host_flows')
        self.assertEqual([x.priority for x in n.datapath.sent], [200,110,100]*2)

    def test_no_routes_gateway_and_reverse_only(self):
        o, n = new_pair(route=False)
        compare(self, o, n, 'try_install_ipv6_host_flows')
        self.assertEqual([x.priority for x in n.datapath.sent], [200,100])

    def test_install_idempotent(self):
        o, n = new_pair()
        compare(self,o,n,'try_install_ipv6_host_flows')
        compare(self,o,n,'try_install_ipv6_host_flows')

    def test_relearn_host_mac_installs_same_messages(self):
        o,n=new_pair()
        compare(self,o,n,'try_install_ipv6_host_flows')
        compare(self,o,n,'install_ipv6_host_flows',h.LAN_IP,'02:00:00:00:01:55')

    def test_transit_mac_change(self):
        o,n=new_pair()
        compare(self,o,n,'try_install_ipv6_host_flows')
        for c in (o,n):
            c.data_plane.transit_router_mac='02:00:00:00:ee:01'
        compare(self,o,n,'try_install_ipv6_host_flows')

    def test_route_withdrawal_delete_strict_order(self):
        o,n=new_pair()
        compare(self,o,n,'try_install_ipv6_host_flows')
        for c in (o,n):
            c.ipv6_routing_table.clear()
        compare(self,o,n,'try_install_ipv6_host_flows')
        self.assertEqual([x.command for x in n.datapath.sent if hasattr(x,'command')],
                         [h.OFP.OFPFC_DELETE_STRICT])

    def test_one_route_change_next_hop(self):
        o,n=new_pair()
        compare(self,o,n,'try_install_ipv6_host_flows')
        for c in (o,n):
            for r in c.ipv6_routing_table.values():
                r['next_hop']='3.3.3.3'
        compare(self,o,n,'try_install_ipv6_host_flows')

    def test_delete_route_and_reverse(self):
        o,n=new_pair()
        compare(self,o,n,'delete_ipv6_route_flow',h.LAN_IP,'2001:db8:23::',64,2)
        compare(self,o,n,'delete_ipv6_reverse_flow',h.LAN_IP,1)
        self.assertEqual([m.priority for m in n.datapath.sent],[110,100])
        self.assertTrue(all(m.command==h.OFP.OFPFC_DELETE_STRICT
                            for m in n.datapath.sent))

    def test_delete_guard_no_dp_and_no_port(self):
        o,n=new_pair()
        compare(self,o,n,'delete_ipv6_reverse_flow',h.LAN_IP,None)
        for c in (o,n):
            c.datapath=None
        compare(self,o,n,'delete_ipv6_route_flow',h.LAN_IP,'2001:db8:23::',64,2)
        compare(self,o,n,'delete_ipv6_reverse_flow',h.LAN_IP,1)

    def test_delete_bad_prefix_errors_identical(self):
        o,n=new_pair()
        exc=compare(self,o,n,'delete_ipv6_route_flow',h.LAN_IP,'not-ipv6',64,2)
        self.assertIsNotNone(exc)

    def test_features_reset_without_recompute(self):
        o,n=new_pair()
        for c in (o,n):
            c.neighbor=NS(reset=MagicMock())
            c.lsdb=NS(clear_remote=MagicMock(return_value=False))
            c.local_lsa=[]
            c.local_lsa_ack_pending={'pending':{'sequence':1}}
            c.installed_ipv6_host_flows['old']='stale'
        self.assertIsNone(o.switch_features_handler(NS(msg=NS(datapath=o.datapath))))
        self.assertIsNone(n.switch_features_handler(NS(msg=NS(datapath=n.datapath))))
        self.assertEqual(snapshot(n), snapshot(o))

    def test_features_reset_with_recompute(self):
        o,n=new_pair()
        # We compare separate events because the datapath used by switch_features
        # must match the controller, otherwise both would share old .sent.
        for c in (o,n):
            c.neighbor=NS(reset=MagicMock())
            c.lsdb=NS(clear_remote=MagicMock(return_value=True))
            c.local_lsa=[]
            c.recompute_routing_state=MagicMock()
        old_ret=o.switch_features_handler(NS(msg=NS(datapath=o.datapath)))
        new_ret=n.switch_features_handler(NS(msg=NS(datapath=n.datapath)))
        self.assertEqual(new_ret,old_ret)
        self.assertEqual(snapshot(n),snapshot(o))
        self.assertEqual([m.command for m in n.datapath.sent if hasattr(m,'command')],
                         [h.OFP.OFPFC_DELETE])
        o.recompute_routing_state.assert_called_once()
        n.recompute_routing_state.assert_called_once()

    def test_route_change_prefix_and_more_routes(self):
        o,n=new_pair()
        for c in (o,n):
            c.ipv6_routing_table[("2001:db8:12::",64)]=dict(h.ROUTE,prefix="2001:db8:12::")
            c.ipv6_routing_table[("2001:db8:31::",64)]=dict(h.ROUTE,prefix="2001:db8:31::")
        compare(self,o,n,'try_install_ipv6_host_flows')
        self.assertEqual([m.priority for m in n.datapath.sent],[200,110,110,110,100])

    def test_randomized_install_and_withdrawal(self):
        rng=random.Random(0xC01)
        for i in range(400):
            o,n=new_pair(route=False)
            count=rng.randrange(0,5)
            disconnect = rng.randrange(0,9)==0
            for c in (o,n):
                for k in range(count):
                    prefix=f'2001:db8:{k+12:x}::'
                    c.ipv6_routing_table[(prefix,64)]=dict(h.ROUTE,prefix=prefix)
                if disconnect:
                    c.data_plane.transit_port=None
            compare(self,o,n,'try_install_ipv6_host_flows')
            for c in (o,n):
                c.ipv6_routing_table.clear()
            compare(self,o,n,'try_install_ipv6_host_flows')

    def test_constructor_trace_action_and_strict_delete(self):
        # Every built OF message must have the exact same constructor kwarg keys,
        # not only an equal OpenFlow 'meaning'. canon() preserves kwarg insertion.
        o,n=new_pair()
        compare(self,o,n,'try_install_ipv6_host_flows')
        compare(self,o,n,'delete_ipv6_route_flow',h.LAN_IP,'2001:db8:23::',64,2)
        compare(self,o,n,'delete_ipv6_reverse_flow',h.LAN_IP,1)
        old_keys=[tuple(vars(m).keys()) for m in o.datapath.sent]
        new_keys=[tuple(vars(m).keys()) for m in n.datapath.sent]
        self.assertEqual(new_keys,old_keys)

    def test_real_ryu_openflow13_bytes_if_available(self):
        """Real Ryu OF1.3 serialization, not just mocked kwargs."""
        try:
            from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
        except ImportError:
            self.skipTest('Ryu not installed in the isolated environment')

        class RealSwitch:
            def __init__(self):
                self.ofproto = ofproto_v1_3
                self.ofproto_parser = ofproto_v1_3_parser
                self.sent = []
                self.id = 1
            def send_msg(self, msg):
                msg.xid = 0xC0100000 + len(self.sent)
                msg.serialize()
                self.sent.append(bytes(msg.buf))

        o,n = new_pair()
        o.datapath = RealSwitch()
        n.datapath = RealSwitch()
        for c in (o,n):
            c.try_install_ipv6_host_flows()
            c.delete_ipv6_route_flow(h.LAN_IP,'2001:db8:23::',64,2)
            c.delete_ipv6_reverse_flow(h.LAN_IP,1)
        self.assertEqual(n.datapath.sent, o.datapath.sent)
        self.assertEqual(len(n.datapath.sent), 5)

    def test_all_parser_constructor_events_and_send_order(self):
        class TracingParser(h.OFParser):
            def __init__(self, events):
                self.events = events
            def __getattribute__(self, name):
                obj = object.__getattribute__(self, name)
                if name.startswith('OFP') and callable(obj):
                    def traced(*args, **kwargs):
                        self.events.append(('ctor', name, canon(args), canon(kwargs)))
                        return obj(*args, **kwargs)
                    return traced
                return obj
        o,n = new_pair()
        for c in (o,n):
            dp = c.datapath
            dp.events = []
            dp.ofproto_parser = TracingParser(dp.events)
            send = dp.send_msg
            def traced_send(msg, *, events=dp.events, orig=send):
                events.append(('send', canon(msg)))
                return orig(msg)
            dp.send_msg = traced_send
        compare(self,o,n,'try_install_ipv6_host_flows')
        compare(self,o,n,'delete_ipv6_route_flow',h.LAN_IP,'2001:db8:23::',64,2)
        compare(self,o,n,'delete_ipv6_reverse_flow',h.LAN_IP,1)
        self.assertEqual(n.datapath.events,o.datapath.events)



if __name__=='__main__':
    unittest.main()
