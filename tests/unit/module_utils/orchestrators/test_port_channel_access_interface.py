# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for port_channel_access_interface orchestrator.

Verifies that `PortChannelAccessInterfaceOrchestrator` correctly:
- declares the right `model_class` and `_managed_policy_types`
- inherits bulk-support flags from `PortChannelBaseOrchestrator`
- filters fabric-wide interface results to `interfaceType: "portChannel"` plus the managed
  policy types (so non-port-channel and other-flavor port-channels are excluded)
- propagates `RuntimeError` from the inherited `validate_prerequisites` path

Uses the file-based `Sender` from `tests/unit/module_utils/sender_file.py` as the
`sender` dependency injected into a real `RestSend`. Responses are read from
`tests/unit/module_utils/fixtures/fixture_data/test_port_channel_access_interface.json`.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-many-lines

from __future__ import annotations

import inspect

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_access_interface import (
    PortChannelAccessInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_access_interface import (
    PortChannelAccessInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_pc_access(key: str):
    """Load fixture data for the orchestrator's test_port_channel_access_interface.json file."""
    return load_fixture("test_port_channel_access_interface")[key]


def _build_rest_send(gen_responses: ResponseGenerator, fabric_name: str = "fabric_1") -> RestSend:
    """Build a RestSend wired to the file-based Sender and the real ResponseHandler."""
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    rest_send = RestSend({"check_mode": False, "fabric_name": fabric_name})
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


def _build_orchestrator(gen_responses: ResponseGenerator, fabric_name: str = "fabric_1") -> PortChannelAccessInterfaceOrchestrator:
    """Construct an orchestrator with the file-based RestSend injected."""
    rest_send = _build_rest_send(gen_responses, fabric_name=fabric_name)
    return PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)


# =============================================================================
# Test: ClassVar / model_class
# =============================================================================


def test_port_channel_access_orchestrator_00010() -> None:
    """
    # Summary

    Verify `model_class` points to `PortChannelAccessInterfaceModel`.

    ## Test

    - model_class is PortChannelAccessInterfaceModel

    ## Classes and Methods

    - PortChannelAccessInterfaceOrchestrator.model_class
    """
    assert PortChannelAccessInterfaceOrchestrator.model_class is PortChannelAccessInterfaceModel


def test_port_channel_access_orchestrator_00020() -> None:
    """
    # Summary

    Verify bulk-support flags inherited from `PortChannelBaseOrchestrator`.

    ## Test

    - supports_bulk_create is True
    - supports_bulk_delete is True

    ## Classes and Methods

    - PortChannelAccessInterfaceOrchestrator
    """
    assert PortChannelAccessInterfaceOrchestrator.supports_bulk_create is True
    assert PortChannelAccessInterfaceOrchestrator.supports_bulk_delete is True


# =============================================================================
# Test: _managed_policy_types
# =============================================================================


def test_port_channel_access_orchestrator_00100() -> None:
    """
    # Summary

    Verify `_managed_policy_types` returns the single `"accessPoHost"` API value.

    ## Test

    - Returned set contains exactly "accessPoHost"

    ## Classes and Methods

    - PortChannelAccessInterfaceOrchestrator._managed_policy_types()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    assert orchestrator._managed_policy_types() == {"accessPoHost"}


def test_port_channel_access_orchestrator_00110() -> None:
    """
    # Summary

    Verify `_managed_policy_types` returns a set (supports set membership for `in` checks).

    ## Test

    - Return type is set

    ## Classes and Methods

    - PortChannelAccessInterfaceOrchestrator._managed_policy_types()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    result = orchestrator._managed_policy_types()
    assert isinstance(result, set)
    assert "accessPoHost" in result


# =============================================================================
# Test: query_all — happy path with filtering
# =============================================================================


def test_port_channel_access_orchestrator_00400() -> None:
    """
    # Summary

    Verify `query_all` validates the fabric, iterates all switches, filters to interfaceType=="portChannel"
    and policyType=="accessPoHost", and injects `switchIp` onto each kept interface.

    ## Test

    - Fabric summary (validate_prerequisites) returns 200
    - Switches list returns two switches
    - Switch 1 returns: configured accessPoHost portChannel, trunkPoHost portChannel, ethernet trunkHost
    - Switch 2 returns: one configured accessPoHost portChannel
    - Result contains exactly the two accessPoHost port-channels
    - Each has switchIp injected with the fabricManagementIp

    ## Classes and Methods

    - PortChannelAccessInterfaceOrchestrator._managed_policy_types()
    - PortChannelBaseOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access("test_query_all_happy_path_00400a")
        yield responses_pc_access("test_query_all_happy_path_00400b")
        yield responses_pc_access("test_query_all_happy_path_00400c")
        yield responses_pc_access("test_query_all_happy_path_00400d")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        result = orchestrator.query_all()

    assert isinstance(result, list)
    assert len(result) == 2

    by_name = {iface["interfaceName"]: iface for iface in result}
    assert set(by_name) == {"port-channel501", "port-channel601"}

    # switchIp is injected by the base query_all
    assert by_name["port-channel501"]["switchIp"] == "192.168.1.1"
    assert by_name["port-channel601"]["switchIp"] == "192.168.1.2"

    # Filtered out: trunkPoHost (port-channel502) and ethernet trunkHost (Ethernet1/1)
    assert "port-channel502" not in by_name
    assert "Ethernet1/1" not in by_name

    # method_name is used for clearer pytest failure messages; keep as a sanity reference
    assert method_name.endswith("00400")


def test_port_channel_access_orchestrator_00410() -> None:
    """
    # Summary

    Verify `query_all` returns an empty list when no switch reports any accessPoHost port-channel.

    ## Test

    - Switch returns only non-port-channel and non-accessPoHost port-channel interfaces
    - Result is an empty list

    ## Classes and Methods

    - PortChannelAccessInterfaceOrchestrator._managed_policy_types()
    - PortChannelBaseOrchestrator.query_all()
    """

    def responses():
        yield responses_pc_access("test_query_all_no_match_00410a")
        yield responses_pc_access("test_query_all_no_match_00410b")
        yield responses_pc_access("test_query_all_no_match_00410c")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        result = orchestrator.query_all()

    assert result == []


def test_port_channel_access_orchestrator_00420() -> None:
    """
    # Summary

    Verify `query_all` raises `RuntimeError` when the fabric does not exist.

    ## Test

    - Fabric summary returns 404
    - query_all raises RuntimeError with "Query all failed" (wrapping the inner "Fabric ... not found")

    ## Classes and Methods

    - PortChannelBaseOrchestrator.query_all()
    - FabricContext.validate_for_mutation()
    """

    def responses():
        yield responses_pc_access("test_query_all_fabric_not_found_00420a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses, fabric_name="missing_fabric")

    with pytest.raises(RuntimeError, match=r"Query all failed.*missing_fabric"):
        orchestrator.query_all()


def test_port_channel_access_orchestrator_00430() -> None:
    """
    # Summary

    Verify `query_all` returns an empty list when a switch's interfaces endpoint returns no body
    (the `not_found_ok=True` branch in `PortChannelBaseOrchestrator.query_all`).

    ## Test

    - Switch's interface list returns 404 (treated as no interfaces present)
    - query_all skips the switch and yields []

    ## Classes and Methods

    - PortChannelBaseOrchestrator.query_all()
    """

    def responses():
        yield responses_pc_access("test_query_all_switch_404_00430a")
        yield responses_pc_access("test_query_all_switch_404_00430b")
        yield responses_pc_access("test_query_all_switch_404_00430c")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        result = orchestrator.query_all()

    assert result == []
