# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for plugins/modules/nd_manage_networks.py.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import json
from unittest.mock import patch

import pytest
from ansible.module_utils import basic as ansible_basic
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import (
    Sender,
)
from ansible_collections.cisco.nd.plugins.modules import nd_manage_networks

_MISSING_CONFIG = object()


class _ModuleFailure(Exception):
    """Capture ``AnsibleModule.fail_json`` without terminating pytest."""

    def __init__(self, module, result):
        super().__init__(result.get("msg", "module failed"))
        self.module = module
        self.result = result
        self.controller_calls = []


def _run_composed_network_module(module_args):
    """
    Run Ansible parsing, the production workflow, and the real state machine.

    Only the controller transport is replaced.
    """
    raw_args = json.dumps({"ANSIBLE_MODULE_ARGS": module_args}).encode()
    captured = {}
    controller_calls = []

    def exit_json(module, **kwargs):
        captured["module"] = module
        captured["result"] = kwargs

    def fail_json(module, **kwargs):
        raise _ModuleFailure(module, kwargs)

    def sender_commit(sender):
        path = sender.path
        verb = sender.verb.value
        controller_calls.append((verb, path, sender.payload))
        if path == "/api/v1/manage/fabrics/fab1":
            data = {"management": {"type": "vxlanIbgp"}}
        elif path == "/api/v1/manage/fabrics?category=fabricGroup&max=10000":
            data = {"fabrics": []}
        elif path == "/api/v1/manage/fabrics/fab1/networks?offset=0&max=10000":
            data = {
                "networks": [
                    {"networkName": "production"},
                    {"networkName": "storage"},
                ],
                "metadata": {"counts": {"total": 2, "remaining": 0}},
            }
        elif verb == "POST" and path == "/api/v1/manage/fabrics/fab1/networkAttachments/query?offset=0&max=10000&includeAll=true":
            data = {
                "attachments": [],
                "metadata": {"counts": {"total": 0, "remaining": 0}},
            }
        elif verb == "POST" and path in {
            "/api/v1/manage/fabrics/fab1/networkActions/deploy",
            "/api/v1/manage/fabrics/fab1/networkActions/remove",
        }:
            data = {
                "results": [
                    {"networkName": "production", "status": "success"},
                    {"networkName": "storage", "status": "success"},
                ],
            }
        else:
            raise AssertionError((verb, path, sender.payload))
        sender.response = {
            "RETURN_CODE": 200,
            "MESSAGE": "OK",
            "DATA": data,
            "REQUEST_PATH": path,
            "METHOD": verb,
        }

    # ansible-core 2.19+ requires a serialization profile to decode _ANSIBLE_ARGS.
    with patch.object(ansible_basic, "_ANSIBLE_ARGS", raw_args), patch.object(ansible_basic, "_ANSIBLE_PROFILE", "legacy", create=True), patch.object(
        nd_manage_networks.AnsibleModule, "exit_json", exit_json
    ), patch.object(nd_manage_networks.AnsibleModule, "fail_json", fail_json), patch.object(Sender, "commit", sender_commit):
        try:
            nd_manage_networks.main()
        except _ModuleFailure as exc:
            exc.controller_calls = list(controller_calls)
            raise

    return {
        **captured,
        "controller_calls": controller_calls,
    }


def test_nd_manage_networks_requires_pydantic_immediately_after_module_creation():
    """
    Verify the module wrapper checks for Pydantic before fabric resolution or
    orchestrator construction.
    """
    events = []

    class FakeAnsibleModule:
        def __init__(self, **kwargs):
            self.params = {
                "fabric_name": "fab1",
                "state": "gathered",
                "config": [],
            }
            self.kwargs = kwargs
            events.append(("AnsibleModule", self))

        def exit_json(self, **kwargs):
            events.append(("exit_json", kwargs))

        def fail_json(self, **kwargs):
            raise AssertionError(f"fail_json called unexpectedly: {kwargs}")

    class FakeCoordinator:
        def __init__(self, module):
            events.append(("NetworkWorkflowCoordinator", module))

        def run(self):
            events.append(("run",))
            return {"changed": False}

    def fake_require_pydantic(module):
        events.append(("require_pydantic", module))

    with (
        patch.object(nd_manage_networks, "AnsibleModule", FakeAnsibleModule),
        patch.object(nd_manage_networks, "require_pydantic", fake_require_pydantic),
        patch.object(nd_manage_networks, "NetworkWorkflowCoordinator", FakeCoordinator),
    ):
        nd_manage_networks.main()

    assert [event[0] for event in events] == [
        "AnsibleModule",
        "require_pydantic",
        "NetworkWorkflowCoordinator",
        "run",
        "exit_json",
    ]
    assert events[1][1] is events[2][1]
    assert events[0][1].kwargs["supports_check_mode"] is True
    assert "default" not in events[0][1].kwargs["argument_spec"]["config"]


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize(
    "config",
    [
        pytest.param(_MISSING_CONFIG, id="omitted"),
        pytest.param(None, id="null"),
    ],
)
def test_nd_manage_networks_rejects_missing_overridden_config_before_query(config, check_mode):
    """Omitted/null config must fail before production state discovery."""
    module_args = {
        "fabric_name": "fab1",
        "state": "overridden",
        "_ansible_check_mode": check_mode,
        "_ansible_verbosity": 0,
    }
    if config is not _MISSING_CONFIG:
        module_args["config"] = config

    with pytest.raises(_ModuleFailure) as exc_info:
        _run_composed_network_module(module_args)

    assert exc_info.value.module.params["config"] is None
    assert "config must be provided and cannot be null" in exc_info.value.result["msg"]
    assert exc_info.value.controller_calls == []


def test_nd_manage_networks_explicit_empty_overridden_previews_existing_deletions():
    """Explicit config: [] previews delete-all through the complete workflow."""
    run = _run_composed_network_module(
        {
            "fabric_name": "fab1",
            "state": "overridden",
            "config": [],
            "_ansible_check_mode": True,
            "_ansible_verbosity": 0,
        }
    )

    assert run["module"].params["config"] == []
    assert len(run["result"]["before"]) == 2
    assert run["result"]["after"] == []
    assert run["result"]["changed"] is True
    assert run["result"]["check_mode_deploy_payloads"] == [
        {"networkNames": ["production", "storage"]},
    ]
    assert len(run["controller_calls"]) == 3
    assert all(verb == "GET" for verb, _path, _payload in run["controller_calls"])


def test_nd_manage_networks_explicit_empty_overridden_deletes_existing_resources():
    """Explicit config: [] performs delete-all through the complete workflow."""
    run = _run_composed_network_module(
        {
            "fabric_name": "fab1",
            "state": "overridden",
            "config": [],
            "_ansible_check_mode": False,
            "_ansible_verbosity": 0,
        }
    )

    assert run["module"].params["config"] == []
    assert len(run["result"]["before"]) == 2
    assert run["result"]["after"] == []
    assert run["result"]["changed"] is True
    assert "check_mode_deploy_payloads" not in run["result"]
    mutation_calls = [
        (verb, path, payload)
        for verb, path, payload in run["controller_calls"]
        if path
        in {
            "/api/v1/manage/fabrics/fab1/networkActions/deploy",
            "/api/v1/manage/fabrics/fab1/networkActions/remove",
        }
    ]
    assert [(verb, path) for verb, path, _payload in mutation_calls] == [
        ("POST", "/api/v1/manage/fabrics/fab1/networkActions/deploy"),
        ("POST", "/api/v1/manage/fabrics/fab1/networkActions/remove"),
    ]
    for _verb, _path, payload in mutation_calls:
        assert set(payload["networkNames"]) == {
            "production",
            "storage",
        }
