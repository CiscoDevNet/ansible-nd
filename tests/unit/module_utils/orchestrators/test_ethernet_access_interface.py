# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ethernet_access_interface orchestrator.

Verifies that `EthernetAccessInterfaceOrchestrator` correctly:
- declares the right `model_class` and `_managed_policy_types`
- inherits bulk-support flags from `EthernetBaseOrchestrator`
- filters `query_all` results down to accessHost interfaces across multiple switches
- propagates `RuntimeError` from the inherited `validate_prerequisites` path

Uses the file-based `Sender` from `tests/unit/module_utils/sender_file.py` as the
`sender` dependency injected into a real `RestSend`. Responses are read from
`tests/unit/module_utils/fixtures/fixture_data/test_ethernet_access_interface.json`.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-many-lines

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_access_interface import (
    EthernetAccessInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_access_interface import (
    EthernetAccessInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_access(key: str):
    """Load fixture data for the orchestrator's test_ethernet_access_interface.json file."""
    return load_fixture("test_ethernet_access_interface")[key]


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


def _build_orchestrator(gen_responses: ResponseGenerator, fabric_name: str = "fabric_1") -> EthernetAccessInterfaceOrchestrator:
    """Construct an orchestrator with the file-based RestSend injected."""
    rest_send = _build_rest_send(gen_responses, fabric_name=fabric_name)
    return EthernetAccessInterfaceOrchestrator(rest_send=rest_send)


# =============================================================================
# Test: ClassVar / model_class
# =============================================================================


def test_ethernet_access_orchestrator_00010() -> None:
    """
    # Summary

    Verify `model_class` points to `EthernetAccessInterfaceModel`.

    ## Test

    - model_class is EthernetAccessInterfaceModel

    ## Classes and Methods

    - EthernetAccessInterfaceOrchestrator.model_class
    """
    assert EthernetAccessInterfaceOrchestrator.model_class is EthernetAccessInterfaceModel


def test_ethernet_access_orchestrator_00020() -> None:
    """
    # Summary

    Verify bulk-support flags inherited from `EthernetBaseOrchestrator`.

    ## Test

    - supports_bulk_create is True
    - supports_bulk_delete is True

    ## Classes and Methods

    - EthernetAccessInterfaceOrchestrator
    """
    assert EthernetAccessInterfaceOrchestrator.supports_bulk_create is True
    assert EthernetAccessInterfaceOrchestrator.supports_bulk_delete is True


# =============================================================================
# Test: _managed_policy_types
# =============================================================================


def test_ethernet_access_orchestrator_00100() -> None:
    """
    # Summary

    Verify `_managed_policy_types` returns the single `"accessHost"` API value.

    ## Test

    - Returned set contains exactly "accessHost"

    ## Classes and Methods

    - EthernetAccessInterfaceOrchestrator._managed_policy_types()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    assert orchestrator._managed_policy_types() == {"accessHost"}


def test_ethernet_access_orchestrator_00110() -> None:
    """
    # Summary

    Verify `_managed_policy_types` returns a set (supports set membership for `in` checks).

    ## Test

    - Return type is set

    ## Classes and Methods

    - EthernetAccessInterfaceOrchestrator._managed_policy_types()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    result = orchestrator._managed_policy_types()
    assert isinstance(result, set)
    assert "accessHost" in result


# =============================================================================
# Test: query_all — happy path with filtering
# =============================================================================


def test_ethernet_access_orchestrator_00400() -> None:
    """
    # Summary

    Verify `query_all` validates the fabric, iterates all switches, filters to accessHost interfaces only,
    and injects `switchIp` onto each kept interface.

    ## Test

    - Fabric summary (validate_prerequisites) returns 200
    - Switches list returns two switches
    - Switch 1 returns: accessHost + trunkHost (the trunkHost should be filtered out)
    - Switch 2 returns: one accessHost
    - Result contains exactly the two accessHost interfaces
    - Each has switchIp injected with the fabricManagementIp

    ## Classes and Methods

    - EthernetAccessInterfaceOrchestrator._managed_policy_types()
    - EthernetBaseOrchestrator.query_all()
    """

    def responses():
        yield responses_access("test_query_all_happy_path_00400a")
        yield responses_access("test_query_all_happy_path_00400_freeze")
        yield responses_access("test_query_all_happy_path_00400b")
        yield responses_access("test_query_all_happy_path_00400c")
        yield responses_access("test_query_all_happy_path_00400d")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        result = orchestrator.query_all()

    assert isinstance(result, list)
    assert len(result) == 2

    by_name = {iface["interfaceName"]: iface for iface in result}
    assert set(by_name) == {"Ethernet1/1", "Ethernet2/1"}

    # switchIp is injected by the base query_all
    assert by_name["Ethernet1/1"]["switchIp"] == "192.168.1.1"
    assert by_name["Ethernet2/1"]["switchIp"] == "192.168.1.2"

    # Filtered out: the trunkHost interface on switch 1
    assert "Ethernet1/2" not in by_name


def test_ethernet_access_orchestrator_00420() -> None:
    """
    # Summary

    Verify `query_all` raises `RuntimeError` when the fabric does not exist.

    ## Test

    - Fabric summary returns 404
    - query_all raises RuntimeError with "Query all failed" (wrapping the inner "Fabric ... not found")

    ## Classes and Methods

    - EthernetBaseOrchestrator.query_all()
    - FabricContext.validate_for_mutation()
    """

    def responses():
        yield responses_access("test_query_all_fabric_not_found_00420a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses, fabric_name="missing_fabric")

    with pytest.raises(RuntimeError, match=r"Query all failed.*missing_fabric"):
        orchestrator.query_all()
