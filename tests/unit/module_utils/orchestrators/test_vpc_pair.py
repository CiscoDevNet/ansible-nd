# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for VpcPairOrchestrator.

Verifies that VpcPairOrchestrator correctly:
- declares VpcPairModel as model_class and the expected endpoints
- maps query_one 404 -> None via not_found_ok
- parses fabric-wide vpcPairs list
- runs create / update / delete via PUT vpcPair (with vpcAction = pair | unPair)
- queues both peer serials for switchActions/deploy after each mutation
- treats 207 deploy responses case-insensitively (Success / success both pass)
- raises on per-switch failure status

Uses the file-based Sender from tests/unit/module_utils/sender_file.py and the real
ResponseHandler / RestSend; fixtures in
tests/unit/module_utils/fixtures/fixture_data/test_vpc_pair_orchestrator.json.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-many-lines

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabric_switch_actions_deploy import (
    EpManageFabricSwitchActionsDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabric_switch_vpc_pair import (
    EpManageFabricSwitchVpcPairGet,
    EpManageFabricSwitchVpcPairPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabric_vpc_pairs import (
    EpManageFabricVpcPairsListGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.vpc.vpc_pair import VpcPairModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vpc_pair import VpcPairOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_vpc_pair_orch(key: str):
    """Load fixture data from test_vpc_pair_orchestrator.json."""
    return load_fixture("test_vpc_pair_orchestrator")[key]


def _build_rest_send(gen_responses: ResponseGenerator, fabric_name: str = "SITE1", config: list | None = None) -> RestSend:
    """Build a RestSend wired to the file-based Sender and the real ResponseHandler."""
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    params = {"check_mode": False, "fabric_name": fabric_name}
    if config is not None:
        params["config"] = config
    rest_send = RestSend(params)
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


def _build_orchestrator(gen_responses: ResponseGenerator, fabric_name: str = "SITE1", config: list | None = None) -> VpcPairOrchestrator:
    """Construct a VpcPairOrchestrator with the file-based RestSend injected."""
    return VpcPairOrchestrator(rest_send=_build_rest_send(gen_responses, fabric_name=fabric_name, config=config))


def _model_default() -> VpcPairModel:
    """Build a baseline VpcPairModel matching the lab SITE1 pair (S1_LE1 + S1_LE2)."""
    return VpcPairModel(
        fabric_name="SITE1",
        switch_ip="192.168.12.151",
        peer_switch_ip="192.168.12.155",
        domain_id=1,
    )


# =============================================================================
# Test: ClassVar / endpoint declarations
# =============================================================================


def test_vpc_pair_orch_00010() -> None:
    """
    # Summary

    Verify model_class points to VpcPairModel.

    ## Test

    - model_class is VpcPairModel

    ## Classes and Methods

    - VpcPairOrchestrator.model_class
    """
    assert VpcPairOrchestrator.model_class is VpcPairModel


def test_vpc_pair_orch_00020() -> None:
    """
    # Summary

    Verify endpoint class assignments map to the new vPC endpoints.

    ## Test

    - create/update/delete endpoint = EpManageFabricSwitchVpcPairPut
    - query_one endpoint = EpManageFabricSwitchVpcPairGet
    - query_all endpoint = EpManageFabricVpcPairsListGet

    ## Classes and Methods

    - VpcPairOrchestrator (instance field defaults)
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    assert orchestrator.create_endpoint is EpManageFabricSwitchVpcPairPut
    assert orchestrator.update_endpoint is EpManageFabricSwitchVpcPairPut
    assert orchestrator.delete_endpoint is EpManageFabricSwitchVpcPairPut
    assert orchestrator.query_one_endpoint is EpManageFabricSwitchVpcPairGet
    assert orchestrator.query_all_endpoint is EpManageFabricVpcPairsListGet


def test_vpc_pair_orch_00030() -> None:
    """
    # Summary

    Verify deploy_endpoint points to switchActions/deploy (NOT interfaceActions/deploy).

    ## Test

    - deploy_endpoint is EpManageFabricSwitchActionsDeployPost

    ## Classes and Methods

    - VpcPairOrchestrator.deploy_endpoint
    """
    assert VpcPairOrchestrator.deploy_endpoint is EpManageFabricSwitchActionsDeployPost


# =============================================================================
# Test: query_one — 404 returns None, 200 returns model
# =============================================================================


def test_vpc_pair_orch_00100() -> None:
    """
    # Summary

    Verify query_one returns None when the per-switch GET returns 404.

    ## Test

    - Switch list returns 2 switches (FabricContext IP -> serial)
    - Per-switch GET vpcPair returns 404
    - query_one returns None (404 mapped via not_found_ok)

    ## Classes and Methods

    - VpcPairOrchestrator.query_one()
    """

    def responses():
        yield responses_vpc_pair_orch("test_vpc_pair_orch_00100a_switches")
        yield responses_vpc_pair_orch("test_vpc_pair_orch_00100b_get_404")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)

    with does_not_raise():
        result = orchestrator.query_one(_model_default())

    assert result is None


def test_vpc_pair_orch_00110() -> None:
    """
    # Summary

    Verify query_one returns a populated VpcPairModel on 200.

    ## Test

    - Switch list returns 2 switches
    - Per-switch GET vpcPair returns lab-shaped vpcPairDetails wrapper
    - Result is a VpcPairModel populated from the wire shape (vpcPairDetails flattened)

    ## Classes and Methods

    - VpcPairOrchestrator.query_one()
    """

    def responses():
        yield responses_vpc_pair_orch("test_vpc_pair_orch_00110a_switches")
        yield responses_vpc_pair_orch("test_vpc_pair_orch_00110b_get_200")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)

    with does_not_raise():
        result = orchestrator.query_one(_model_default())

    assert isinstance(result, VpcPairModel)
    assert result.switch_id == "9ASNKH8T9DJ"
    assert result.peer_switch_id == "9SJKCSQND07"
    assert result.use_virtual_peer_link is False
    assert result.domain_id == 1
    assert result.keep_alive_vrf == "management"


# =============================================================================
# Test: query_all — empty and populated
# =============================================================================


def test_vpc_pair_orch_00200() -> None:
    """
    # Summary

    Verify query_all returns an empty list when the user's `config` is empty (no proposed peers to query).
    The fabric-wide endpoint is intentionally not hit.

    ## Test

    - config is empty
    - query_all returns []
    - No API calls are made

    ## Classes and Methods

    - VpcPairOrchestrator.query_all()
    """

    def responses():
        yield from ()  # no responses expected

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses, config=[])

    with does_not_raise():
        result = orchestrator.query_all()

    assert result == []


def test_vpc_pair_orch_00210() -> None:
    """
    # Summary

    Verify query_all walks the proposed config items, performs per-switch GET vpcPair for each unique peer
    pair, enriches the response with `fabric_name` / `switch_ip` / `peer_switch_ip`, and skips 404 entries.
    The fabric-wide vpcPairs endpoint is NOT used because it lags in practice.

    ## Test

    - config has one proposed pair
    - Switches list returns serials for IP resolution
    - Per-switch GET returns a populated pair
    - query_all returns one entry with wire shape + Ansible identifiers

    ## Classes and Methods

    - VpcPairOrchestrator.query_all()
    """

    def responses():
        yield responses_vpc_pair_orch("test_vpc_pair_orch_00110a_switches")
        yield responses_vpc_pair_orch("test_vpc_pair_orch_00110b_get_200")

    gen_responses = ResponseGenerator(responses())
    config = [{"switch_ip": "192.168.12.151", "peer_switch_ip": "192.168.12.155", "domain_id": 1}]
    orchestrator = _build_orchestrator(gen_responses, config=config)

    with does_not_raise():
        result = orchestrator.query_all()

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["switchId"] == "9ASNKH8T9DJ"
    assert result[0]["peerSwitchId"] == "9SJKCSQND07"
    assert result[0]["fabric_name"] == "SITE1"
    assert result[0]["switch_ip"] == "192.168.12.151"
    assert result[0]["peer_switch_ip"] == "192.168.12.155"


# =============================================================================
# Test: create — PUT vpcPair + queue both serials for deploy
# =============================================================================


def test_vpc_pair_orch_00300() -> None:
    """
    # Summary

    Verify create resolves both peer IPs to serials, performs the PUT vpcPair, and queues both serials for deploy.

    ## Test

    - Switch list returns 2 switches
    - PUT vpcPair returns 204
    - Both serials are queued in _pending_deploy_switch_ids
    - Model.switch_id and Model.peer_switch_id are populated post-create

    ## Classes and Methods

    - VpcPairOrchestrator.create()
    - VpcPairOrchestrator._queue_deploy_switch()
    """

    def responses():
        yield responses_vpc_pair_orch("test_vpc_pair_orch_00300a_switches")
        yield responses_vpc_pair_orch("test_vpc_pair_orch_00300b_put_204")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    model_instance = _model_default()

    with does_not_raise():
        orchestrator.create(model_instance)

    assert "9ASNKH8T9DJ" in orchestrator._pending_deploy_switch_ids
    assert "9SJKCSQND07" in orchestrator._pending_deploy_switch_ids
    assert model_instance.switch_id == "9ASNKH8T9DJ"
    assert model_instance.peer_switch_id == "9SJKCSQND07"
    assert model_instance.vpc_action == "pair"


# =============================================================================
# Test: delete — PUT vpcPair body vpcAction=unPair
# =============================================================================


def test_vpc_pair_orch_00500() -> None:
    """
    # Summary

    Verify delete sends PUT vpcPair with body `{"vpcAction": "unPair"}` and queues both serials for deploy.

    ## Test

    - Switch list returns 2 switches
    - PUT vpcPair returns 204
    - vpc_action on the model is set to "unPair" before payload generation
    - Both serials are queued for deploy

    ## Classes and Methods

    - VpcPairOrchestrator.delete()
    """

    def responses():
        yield responses_vpc_pair_orch("test_vpc_pair_orch_00500a_switches")
        yield responses_vpc_pair_orch("test_vpc_pair_orch_00500b_put_unpair_204")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    model_instance = _model_default()

    with does_not_raise():
        orchestrator.delete(model_instance)

    assert model_instance.vpc_action == "unPair"
    assert "9ASNKH8T9DJ" in orchestrator._pending_deploy_switch_ids
    assert "9SJKCSQND07" in orchestrator._pending_deploy_switch_ids


# =============================================================================
# Test: deploy_pending — 207 multi-status parsing
# =============================================================================


def test_vpc_pair_orch_00600() -> None:
    """
    # Summary

    Verify deploy_pending posts to switchActions/deploy with both serials and clears the pending queue on all-success 207.

    ## Test

    - Both serials pre-queued
    - 207 multi-status with both switches "success" (lowercase)
    - deploy_pending succeeds
    - Pending queue is cleared

    ## Classes and Methods

    - VpcPairOrchestrator.deploy_pending()
    """

    def responses():
        yield responses_vpc_pair_orch("test_vpc_pair_orch_00600a_deploy_207_all_success")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    orchestrator._pending_deploy_switch_ids = ["9ASNKH8T9DJ", "9SJKCSQND07"]

    with does_not_raise():
        orchestrator.deploy_pending()

    assert orchestrator._pending_deploy_switch_ids == []


def test_vpc_pair_orch_00610() -> None:
    """
    # Summary

    Verify deploy_pending treats per-switch status case-insensitively. Lab observation: switchActions/deploy
    returns lowercase 'success' but interfaceActions/remove returns 'Success' — orchestrator must accept both.

    ## Test

    - 207 multi-status with statuses "Success" (capital S) and "success" (lowercase) — both must pass
    - deploy_pending succeeds without raising

    ## Classes and Methods

    - VpcPairOrchestrator.deploy_pending()
    """

    def responses():
        yield responses_vpc_pair_orch("test_vpc_pair_orch_00610a_deploy_207_mixed_case")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    orchestrator._pending_deploy_switch_ids = ["9ASNKH8T9DJ", "9SJKCSQND07"]

    with does_not_raise():
        orchestrator.deploy_pending()


def test_vpc_pair_orch_00620() -> None:
    """
    # Summary

    Verify deploy_pending raises RuntimeError when any per-switch status is not "success" (case-insensitive),
    and surfaces the failure message in the exception text.

    ## Test

    - 207 multi-status with one "failed" status and a message
    - deploy_pending raises RuntimeError
    - Exception message contains the failed switch's message

    ## Classes and Methods

    - VpcPairOrchestrator.deploy_pending()
    """

    def responses():
        yield responses_vpc_pair_orch("test_vpc_pair_orch_00620a_deploy_207_one_failed")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    orchestrator._pending_deploy_switch_ids = ["9ASNKH8T9DJ", "9SJKCSQND07"]

    with pytest.raises(RuntimeError, match=r"Switch unreachable"):
        orchestrator.deploy_pending()


def test_vpc_pair_orch_00630() -> None:
    """
    # Summary

    Verify deploy_pending is a no-op when the pending queue is empty. No API call is made.

    ## Test

    - Empty pending queue
    - deploy_pending returns None and queue stays empty

    ## Classes and Methods

    - VpcPairOrchestrator.deploy_pending()
    """

    def responses():
        yield {}  # Should never be consumed

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)

    with does_not_raise():
        result = orchestrator.deploy_pending()

    assert result is None
    assert orchestrator._pending_deploy_switch_ids == []


def test_vpc_pair_orch_00640() -> None:
    """
    # Summary

    Verify _queue_deploy_switch deduplicates serial numbers (calling it twice with the same serial
    keeps the queue at length 1).

    ## Test

    - Queue same serial twice
    - Pending list contains exactly one entry

    ## Classes and Methods

    - VpcPairOrchestrator._queue_deploy_switch()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)

    orchestrator._queue_deploy_switch("9ASNKH8T9DJ")
    orchestrator._queue_deploy_switch("9ASNKH8T9DJ")
    assert orchestrator._pending_deploy_switch_ids == ["9ASNKH8T9DJ"]
