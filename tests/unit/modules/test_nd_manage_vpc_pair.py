# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Production-wrapper tests for ``nd_manage_vpc_pair``."""

from __future__ import absolute_import, annotations, division, print_function

import json
from unittest.mock import patch

import pytest
from ansible.module_utils import basic as ansible_basic

from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (
    NDModule,
)
from ansible_collections.cisco.nd.plugins.modules import nd_manage_vpc_pair

_MISSING_CONFIG = object()


class _ModuleFailure(Exception):
    """Capture ``AnsibleModule.fail_json`` without terminating pytest."""

    def __init__(self, module, result):
        super().__init__(result.get("msg", "module failed"))
        self.module = module
        self.result = result
        self.controller_calls = []


def _module_args(config, check_mode):
    args = {
        "fabric_name": "fab1",
        "state": "overridden",
        "force": False,
        "verify": None,
        "config_actions": {"save": False, "deploy": False, "type": "switch"},
        "_ansible_check_mode": check_mode,
        "_ansible_verbosity": 0,
    }
    if config is not _MISSING_CONFIG:
        args["config"] = config
    return args


def _run_composed_vpc_pair_module(module_args):
    """Run Ansible parsing, the production service, and the real state machine."""
    raw_args = json.dumps({"ANSIBLE_MODULE_ARGS": module_args}).encode()
    captured = {}
    controller_calls = []
    deleted_switches = set()

    def exit_json(module, **kwargs):
        captured["module"] = module
        captured["result"] = kwargs

    def fail_json(module, **kwargs):
        raise _ModuleFailure(module, kwargs)

    def nd_request(_client, path, verb, data=None):
        method = verb.value
        controller_calls.append((method, path, data))
        if path == "/api/v1/manage/fabrics/fab1":
            return {"fabricType": "VXLAN"}
        if path.endswith("/vpcPairs"):
            return {
                "vpcPairs": [
                    pair
                    for pair in [
                        {
                            "switchId": "SWA",
                            "peerSwitchId": "SWB",
                            "useVirtualPeerLink": False,
                        },
                        {
                            "switchId": "SWC",
                            "peerSwitchId": "SWD",
                            "useVirtualPeerLink": False,
                        },
                    ]
                    if pair["switchId"] not in deleted_switches
                ]
            }
        if path.endswith("/switches"):
            return {
                "switches": [
                    {
                        "serialNumber": "SWA",
                        "vpcConfigured": True,
                        "vpcData": {"peerSwitchId": "SWB"},
                    },
                    {
                        "serialNumber": "SWC",
                        "vpcConfigured": True,
                        "vpcData": {"peerSwitchId": "SWD"},
                    },
                ]
            }
        if path.endswith("/switches/SWA/vpcPair"):
            if method == "PUT":
                deleted_switches.add("SWA")
                return {}
            if "SWA" in deleted_switches:
                return {}
            return {
                "switchId": "SWA",
                "peerSwitchId": "SWB",
                "useVirtualPeerLink": False,
            }
        if path.endswith("/switches/SWC/vpcPair"):
            if method == "PUT":
                deleted_switches.add("SWC")
                return {}
            if "SWC" in deleted_switches:
                return {}
            return {
                "switchId": "SWC",
                "peerSwitchId": "SWD",
                "useVirtualPeerLink": False,
            }
        if path.endswith("/vpcPairConsistency"):
            return {"type2Consistency": True}
        if "/vpcPairOverview" in path:
            return {
                "overlay": {
                    "networkCount": {"deployed": 0},
                    "vrfCount": {"deployed": 0},
                },
                "inventory": {
                    "syncStatus": {"pending": 0, "outOfSync": 0, "inProgress": 0},
                    "vpcInterfaceCount": 0,
                },
            }
        raise AssertionError((method, path, data))

    # ansible-core 2.19+ requires a serialization profile to decode _ANSIBLE_ARGS.
    with patch.object(ansible_basic, "_ANSIBLE_ARGS", raw_args), patch.object(ansible_basic, "_ANSIBLE_PROFILE", "legacy", create=True), patch.object(
        nd_manage_vpc_pair.AnsibleModule, "exit_json", exit_json
    ), patch.object(nd_manage_vpc_pair.AnsibleModule, "fail_json", fail_json), patch.object(nd_manage_vpc_pair, "setup_logging"), patch.object(
        NDModule, "request", nd_request
    ):
        try:
            nd_manage_vpc_pair.main()
        except _ModuleFailure as exc:
            exc.controller_calls = list(controller_calls)
            raise

    return {
        **captured,
        "controller_calls": controller_calls,
    }


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize(
    "config",
    [
        pytest.param(_MISSING_CONFIG, id="omitted"),
        pytest.param(None, id="null"),
    ],
)
def test_vpc_pair_wrapper_rejects_missing_config_before_service(config, check_mode):
    """Missing overridden config must fail before state-machine construction."""
    with pytest.raises(_ModuleFailure) as exc_info:
        _run_composed_vpc_pair_module(_module_args(config, check_mode))

    assert exc_info.value.module.params["config"] is None
    assert "config must be provided and cannot be null" in exc_info.value.result["msg"]
    assert exc_info.value.controller_calls == []


def test_vpc_pair_wrapper_explicit_empty_overridden_previews_existing_deletions():
    """Explicit config: [] reaches the real state machine safely in check mode."""
    run = _run_composed_vpc_pair_module(_module_args([], check_mode=True))

    assert run["module"].params["config"] == []
    assert len(run["result"]["before"]) == 2
    assert run["result"]["after"] == []
    assert run["result"]["changed"] is True
    assert len(run["result"]["deleted"]) == 2
    assert len(run["controller_calls"]) == 7
    assert all(method == "GET" for method, _path, _data in run["controller_calls"])


def test_vpc_pair_wrapper_explicit_empty_overridden_deletes_existing_pairs():
    """Explicit config: [] performs both unpair operations in normal mode."""
    run = _run_composed_vpc_pair_module(_module_args([], check_mode=False))

    assert run["module"].params["config"] == []
    assert len(run["result"]["before"]) == 2
    assert run["result"]["after"] == []
    assert run["result"]["current"] == []
    assert run["result"]["changed"] is True
    assert len(run["result"]["deleted"]) == 2

    put_calls = [(path, data) for method, path, data in run["controller_calls"] if method == "PUT"]
    assert len(put_calls) == 2
    unpair_calls = dict(put_calls)
    assert unpair_calls == {
        "/api/v1/manage/fabrics/fab1/switches/SWA/vpcPair": {
            "vpcAction": "unPair",
            "switchId": "SWA",
            "peerSwitchId": "SWB",
        },
        "/api/v1/manage/fabrics/fab1/switches/SWC/vpcPair": {
            "vpcAction": "unPair",
            "switchId": "SWC",
            "peerSwitchId": "SWD",
        },
    }
    assert all(method in {"GET", "PUT"} for method, _path, _data in run["controller_calls"])
