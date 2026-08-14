# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ``ManageTorOrchestrator``.

Covers the ToR-specific behaviour that overrides ``NDBaseOrchestrator``:

- ``query_all`` issues a single fabric-wide GET (``includeCandidates=false``,
  no leaf filter) that returns every existing association across all leaves,
  with vPC pairings already collapsed to one entry by the API, and injects
  ``fabricName`` into each association.
- ``config_actions`` support via ``ConfigActionsMixin``
  (``validate_config_actions``, ``_filter_switches_needing_deploy``, and the
  ``execute_config_actions`` save + switch-deploy sequence).

The shared REST infrastructure (``_request``, verbosity tagging) is covered by
``test_base_orchestrator.py`` and is not re-exercised here.
"""

# pylint: disable=protected-access,redefined-outer-name

from __future__ import annotations

from typing import Any

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_tor import (
    ManageTorOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import (
    ResponseHandler,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import (
    MockAnsibleModule,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import (
    ResponseGenerator,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


# =============================================================================
# Test harness
# =============================================================================


def _build_rest_send(response_dicts: list[dict], params: dict[str, Any]) -> RestSend:
    """Build a real ``RestSend`` wired to a file-based ``Sender`` yielding
    ``response_dicts`` in order, with ``params`` exposed via ``rest_send.params``.
    """

    def responses():
        yield from response_dicts

    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(responses())

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    rest_send = RestSend(params)
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


def _resp(data: Any = None, *, return_code: int = 200, method: str = "GET") -> dict:
    return {
        "RETURN_CODE": return_code,
        "METHOD": method,
        "REQUEST_PATH": "/api/v1",
        "MESSAGE": "OK",
        "DATA": data if data is not None else {},
    }


def _make_results() -> Results:
    r = Results()
    r.state = "merged"
    r.check_mode = False
    return r


# =============================================================================
# query_all
# =============================================================================


def test_manage_tor_orchestrator_query_all_returns_fabric_wide():
    """query_all issues one fabric-wide GET and returns every association across
    all leaves; vPC pairings arrive already collapsed to a single entry with
    both member IDs inline, and fabricName is injected into each association."""
    responses = [
        _resp(
            {
                "associations": [
                    # single leaf <-> single tor
                    {"accessOrTorSwitchId": "T1", "aggregationOrLeafSwitchId": "L1"},
                    # vPC leaf <-> vPC tor (single self-contained entry)
                    {
                        "accessOrTorSwitchId": "T3",
                        "accessOrTorPeerSwitchId": "T4",
                        "aggregationOrLeafSwitchId": "L3",
                        "aggregationOrLeafPeerSwitchId": "L4",
                    },
                ]
            }
        ),
    ]
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send(responses, params)

    with does_not_raise():
        orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())
        result = orchestrator.query_all()

    assert len(result) == 2
    for assoc in result:
        assert assoc["fabricName"] == "fab1"
    vpc = [a for a in result if a["accessOrTorSwitchId"] == "T3"][0]
    assert vpc["accessOrTorPeerSwitchId"] == "T4"
    assert vpc["aggregationOrLeafPeerSwitchId"] == "L4"


def test_manage_tor_orchestrator_query_all_empty_fabric():
    """query_all returns an empty list when the fabric has no associations."""
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send([_resp({"associations": []})], params)
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())
    with does_not_raise():
        result = orchestrator.query_all()
    assert result == []


# =============================================================================
# config_actions
# =============================================================================


def test_manage_tor_orchestrator_validate_config_actions():
    """validate_config_actions rejects deploy-without-save and invalid type."""
    with does_not_raise():
        ManageTorOrchestrator.validate_config_actions(save=True, deploy=True, deploy_type="switch")
        ManageTorOrchestrator.validate_config_actions(save=False, deploy=False, deploy_type="global")
    with pytest.raises(ValueError, match="deploy=True requires save=True"):
        ManageTorOrchestrator.validate_config_actions(save=False, deploy=True, deploy_type="switch")
    with pytest.raises(ValueError, match="invalid type"):
        ManageTorOrchestrator.validate_config_actions(save=True, deploy=True, deploy_type="bogus")


def test_manage_tor_orchestrator_filter_switches_needing_deploy():
    """Only switches whose configSyncStatus is not inSync are selected."""
    switches = [
        {"serialNumber": "S1", "additionalData": {"configSyncStatus": "outOfSync"}},
        {"serialNumber": "S2", "additionalData": {"configSyncStatus": "inSync"}},
        {"serialNumber": "S3", "additionalData": {}},
    ]
    assert ManageTorOrchestrator._filter_switches_needing_deploy(switches) == ["S1", "S3"]


def test_manage_tor_orchestrator_execute_config_actions_save_and_switch_deploy():
    """execute_config_actions runs configSave then a switch-level deploy scoped
    to the out-of-sync switches."""
    switches = {
        "switches": [
            {"serialNumber": "S1", "additionalData": {"configSyncStatus": "outOfSync"}},
            {"serialNumber": "S2", "additionalData": {"configSyncStatus": "inSync"}},
        ]
    }
    responses = [
        _resp(switches, method="GET"),  # _get_fabric_switches
        _resp({"status": "Config save is completed"}, method="POST"),  # config_save
        _resp({"status": "success"}, return_code=207, method="POST"),  # switchActions/deploy
    ]
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send(responses, params)
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())

    with does_not_raise():
        orchestrator.execute_config_actions(fabric_names=["fab1"], save=True, deploy=True, deploy_type="switch")

    # Last request should be the switch-level deploy carrying only the
    # out-of-sync switch S1.
    assert rest_send.committed_payload == {"switchIds": ["S1"]}
