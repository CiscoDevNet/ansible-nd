# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for orchestrators/manage_fabric_group_vxlan.py

Tests the fabric-group-specific ``_deploy_global`` override, which must include
member-fabric switches by setting ``inclAllFabricGroupsSwitches=true`` on the
fabric deploy request (unlike the base single-fabric deploy).
"""

# pylint: disable=protected-access

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_group_vxlan import (
    ManageFabricGroupVxlanOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def _make_rest_send(response_dicts):
    def responses():
        yield from response_dicts

    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(responses())

    rest_send = RestSend({"check_mode": False, "state": "merged"})
    rest_send.sender = sender
    rest_send.response_handler = ResponseHandler()
    rest_send.unit_test = True
    return rest_send


def _success_response(data=None):
    return {
        "RETURN_CODE": 200,
        "METHOD": "POST",
        "REQUEST_PATH": "/api/v1/stub",
        "MESSAGE": "OK",
        "DATA": data or {},
    }


def _make_results():
    r = Results()
    r.state = "merged"
    r.check_mode = False
    return r


def test_fabric_group_deploy_global_includes_member_switches():
    """
    # Summary

    Verify ManageFabricGroupVxlanOrchestrator._deploy_global sets
    ``inclAllFabricGroupsSwitches=true`` so the fabric-group global deploy reaches
    member-fabric switches.

    ## Classes and Methods

    - ManageFabricGroupVxlanOrchestrator.deploy_global()
    """
    rest_send = _make_rest_send([_success_response(data={"status": "deployed"})])
    orch = ManageFabricGroupVxlanOrchestrator(rest_send=rest_send, results=_make_results())

    orch.deploy_global("MyFabricGroup")

    assert "actions/deploy" in rest_send.path
    assert "MyFabricGroup" in rest_send.path
    assert "inclAllFabricGroupsSwitches=true" in rest_send.path
