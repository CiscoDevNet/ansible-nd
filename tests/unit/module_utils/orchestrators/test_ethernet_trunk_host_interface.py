# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ethernet_trunk_host_interface orchestrator.

Verifies that `EthernetTrunkHostInterfaceOrchestrator` correctly:
- declares the right `model_class` and `_managed_policy_types`
- filters out unconfigured `int_trunk_host` defaults from `query_all` so `state: overridden`
  remains idempotent across re-runs
- propagates `RuntimeError` from the inherited `validate_prerequisites` path

Uses the file-based `Sender` from `tests/unit/module_utils/sender_file.py` as the
`sender` dependency injected into a real `RestSend`. Responses are read from
`tests/unit/module_utils/fixtures/fixture_data/test_ethernet_trunk_host_interface.json`.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-many-lines

from __future__ import annotations

import inspect

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_trunk_host_interface import (
    EthernetTrunkHostInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_trunk_host_interface import (
    EthernetTrunkHostInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_trunk_host(key: str):
    """Load fixture data for the orchestrator's test_ethernet_trunk_host_interface.json file."""
    return load_fixture("test_ethernet_trunk_host_interface")[key]


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


def _build_orchestrator(gen_responses: ResponseGenerator, fabric_name: str = "fabric_1") -> EthernetTrunkHostInterfaceOrchestrator:
    """Construct an orchestrator with the file-based RestSend injected."""
    rest_send = _build_rest_send(gen_responses, fabric_name=fabric_name)
    return EthernetTrunkHostInterfaceOrchestrator(rest_send=rest_send)


# =============================================================================
# Test: ClassVar / model_class
# =============================================================================


def test_ethernet_trunk_host_orchestrator_00010() -> None:
    """
    # Summary

    Verify `model_class` points to `EthernetTrunkHostInterfaceModel`.

    ## Test

    - model_class is EthernetTrunkHostInterfaceModel

    ## Classes and Methods

    - EthernetTrunkHostInterfaceOrchestrator.model_class
    """
    assert EthernetTrunkHostInterfaceOrchestrator.model_class is EthernetTrunkHostInterfaceModel


def test_ethernet_trunk_host_orchestrator_00020() -> None:
    """
    # Summary

    Verify bulk-support flags inherited from `EthernetBaseOrchestrator`.

    ## Test

    - supports_bulk_create is True
    - supports_bulk_delete is True

    ## Classes and Methods

    - EthernetTrunkHostInterfaceOrchestrator
    """
    assert EthernetTrunkHostInterfaceOrchestrator.supports_bulk_create is True
    assert EthernetTrunkHostInterfaceOrchestrator.supports_bulk_delete is True


# =============================================================================
# Test: _managed_policy_types
# =============================================================================


def test_ethernet_trunk_host_orchestrator_00100() -> None:
    """
    # Summary

    Verify `_managed_policy_types` returns the single `"trunkHost"` API value.

    ## Test

    - Returned set contains exactly "trunkHost"

    ## Classes and Methods

    - EthernetTrunkHostInterfaceOrchestrator._managed_policy_types()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    assert orchestrator._managed_policy_types() == {"trunkHost"}


def test_ethernet_trunk_host_orchestrator_00110() -> None:
    """
    # Summary

    Verify `_managed_policy_types` returns a set (supports set membership for `in` checks).

    ## Test

    - Return type is set

    ## Classes and Methods

    - EthernetTrunkHostInterfaceOrchestrator._managed_policy_types()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    result = orchestrator._managed_policy_types()
    assert isinstance(result, set)
    assert "trunkHost" in result


# =============================================================================
# Test: _is_unconfigured_default (static)
# =============================================================================


@pytest.mark.parametrize(
    "iface,expected",
    [
        ({}, True),
        (
            {
                "configData": {
                    "networkOS": {"policy": {"allowedVlans": "none"}},
                },
            },
            True,
        ),
        (
            {
                "configData": {
                    "networkOS": {
                        "policy": {"allowedVlans": None, "description": "", "nativeVlan": 1},
                    },
                },
            },
            True,
        ),
        (
            {
                "configData": {
                    "networkOS": {
                        "policy": {"allowedVlans": "1-100"},
                    },
                },
            },
            False,
        ),
        (
            {
                "configData": {
                    "networkOS": {
                        "policy": {"allowedVlans": "all"},
                    },
                },
            },
            False,
        ),
        (
            {
                "configData": {
                    "networkOS": {
                        "policy": {"description": "mgmt"},
                    },
                },
            },
            False,
        ),
        (
            {
                "configData": {
                    "networkOS": {
                        "policy": {"nativeVlan": 10},
                    },
                },
            },
            False,
        ),
        (
            {
                "configData": {
                    "networkOS": {
                        "policy": {
                            "allowedVlans": "1-100",
                            "description": "mgmt",
                            "nativeVlan": 10,
                        },
                    },
                },
            },
            False,
        ),
        (
            {
                "configData": {
                    "networkOS": {"policy": None},
                },
            },
            True,
        ),
    ],
    ids=[
        "empty",
        "allowed_vlans_none",
        "explicit_defaults",
        "allowed_vlans_range",
        "allowed_vlans_all",
        "description_set",
        "native_vlan_set",
        "fully_configured",
        "policy_none",
    ],
)
def test_ethernet_trunk_host_orchestrator_00200(iface, expected) -> None:
    """
    # Summary

    Exercise the truth table for `_is_unconfigured_default`. The predicate is the sole mechanism
    keeping `state: overridden` idempotent across re-runs for trunkHost — if the logic loosens,
    default-configured interfaces show up in `before` and trigger re-normalize churn.

    ## Test

    - Matrix of allowedVlans / description / nativeVlan combinations
    - Predicate returns the expected truth value

    ## Classes and Methods

    - EthernetTrunkHostInterfaceOrchestrator._is_unconfigured_default()
    """
    assert EthernetTrunkHostInterfaceOrchestrator._is_unconfigured_default(iface) is expected


# =============================================================================
# Test: query_all — happy path with filtering
# =============================================================================


def test_ethernet_trunk_host_orchestrator_00400() -> None:
    """
    # Summary

    Verify `query_all` validates the fabric, iterates all switches, filters to trunkHost interfaces,
    excludes unconfigured defaults, and injects `switchIp` onto each kept interface.

    ## Test

    - Fabric summary (validate_prerequisites) returns 200
    - Switches list returns two switches
    - Switch 1 returns: configured trunkHost, unconfigured-default trunkHost, accessHost
    - Switch 2 returns: one configured trunkHost
    - Result contains exactly the two configured trunkHost interfaces
    - Each has switchIp injected with the fabricManagementIp

    ## Classes and Methods

    - EthernetTrunkHostInterfaceOrchestrator.query_all()
    - EthernetBaseOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_trunk_host("test_query_all_happy_path_00400a")
        yield responses_trunk_host("test_query_all_happy_path_00400b")
        yield responses_trunk_host("test_query_all_happy_path_00400c")
        yield responses_trunk_host("test_query_all_happy_path_00400d")

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

    # Filtered out: unconfigured-default trunkHost (Ethernet1/2) and accessHost (Ethernet1/3)
    assert "Ethernet1/2" not in by_name
    assert "Ethernet1/3" not in by_name

    # method_name is used for clearer pytest failure messages; keep as a sanity reference
    assert method_name.endswith("00400")


def test_ethernet_trunk_host_orchestrator_00410() -> None:
    """
    # Summary

    Verify `query_all` returns an empty list when every trunkHost interface matches the
    unconfigured `int_trunk_host` default signature.

    ## Test

    - Switch returns only default-configured trunkHost interfaces
    - Result is an empty list

    ## Classes and Methods

    - EthernetTrunkHostInterfaceOrchestrator.query_all()
    - EthernetTrunkHostInterfaceOrchestrator._is_unconfigured_default()
    """

    def responses():
        yield responses_trunk_host("test_query_all_all_default_00410a")
        yield responses_trunk_host("test_query_all_all_default_00410b")
        yield responses_trunk_host("test_query_all_all_default_00410c")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        result = orchestrator.query_all()

    assert result == []


def test_ethernet_trunk_host_orchestrator_00430(monkeypatch) -> None:
    """
    # Summary

    Verify `query_all` returns the parent result unchanged when it is not a list.

    The base implementation always returns a list under normal operation, but `query_all`
    defensively guards against a non-list return value. This test patches the parent to
    return a dict and confirms it is passed through without filtering.

    ## Test

    - Parent `query_all` (monkeypatched) returns a dict
    - `EthernetTrunkHostInterfaceOrchestrator.query_all()` returns the same dict unchanged

    ## Classes and Methods

    - EthernetTrunkHostInterfaceOrchestrator.query_all()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)

    sentinel = {"not": "a list"}

    def fake_parent_query_all(self, model_instance=None, **kwargs):  # pylint: disable=unused-argument
        return sentinel

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base.EthernetBaseOrchestrator.query_all",
        fake_parent_query_all,
    )

    result = orchestrator.query_all()
    assert result is sentinel


def test_ethernet_trunk_host_orchestrator_00420() -> None:
    """
    # Summary

    Verify `query_all` raises `RuntimeError` when the fabric does not exist.

    ## Test

    - Fabric summary returns 404
    - query_all raises RuntimeError with "Query all failed" (wrapping the inner "Fabric ... not found")

    ## Classes and Methods

    - EthernetTrunkHostInterfaceOrchestrator.query_all()
    - EthernetBaseOrchestrator.query_all()
    - FabricContext.validate_for_mutation()
    """

    def responses():
        yield responses_trunk_host("test_query_all_fabric_not_found_00420a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses, fabric_name="missing_fabric")

    with pytest.raises(RuntimeError, match=r"Query all failed.*missing_fabric"):
        orchestrator.query_all()
