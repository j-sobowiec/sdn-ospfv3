"""Check the OpenFlow safety boundary without importing a live Ryu runtime."""

import ast
import logging
from pathlib import Path
from types import SimpleNamespace

import config as cfg


def test_unknown_switch_dpid_is_rejected_before_any_mutation():
    """An unexpected switch must not receive FlowMods or reset our peer."""
    source = Path(__file__).resolve().parents[2] / "controller.py"
    module = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    app = next(node for node in module.body if isinstance(node, ast.ClassDef)
               and node.name == "MinimalOSPFv3Controller")
    handler = next(node for node in app.body if isinstance(node, ast.FunctionDef)
                   and node.name == "switch_ready")
    # Evaluate the unmodified method body without its Ryu decorator. The
    # unknown-DPID branch must exit before using a switch's parser or flows.
    handler.decorator_list = []
    namespace = {"cfg": cfg}
    exec(compile(ast.Module(body=[handler], type_ignores=[]), str(source), "exec"),
         namespace)

    class ForbiddenPeer:
        def reset(self):
            raise AssertionError("unknown DPID reset the OSPF neighbor")

    class ForbiddenSwitch:
        id = cfg.SWITCH_DPID + 1

        @property
        def ofproto_parser(self):
            raise AssertionError("unknown DPID attempted OpenFlow programming")

    app_instance = SimpleNamespace(datapath=None, peer=ForbiddenPeer(),
                                   logger=logging.getLogger("test-openflow"))
    event = SimpleNamespace(msg=SimpleNamespace(datapath=ForbiddenSwitch()))
    namespace["switch_ready"](app_instance, event)
    assert app_instance.datapath is None
