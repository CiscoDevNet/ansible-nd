# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for port_channel_trunk_host_interface orchestrator.

Verifies that `PortChannelTrunkHostInterfaceOrchestrator` correctly:
- declares the right `model_class` and `_managed_policy_types`
- inherits bulk-support flags from `PortChannelBaseOrchestrator`
- filters fabric-wide interface results to `interfaceType: "portChannel"` plus the managed
  policy types (so non-port-channel and accessPoHost port-channels are excluded)
- propagates `RuntimeError` from the inherited `validate_prerequisites` path

Uses the file-based `Sender` from `tests/unit/module_utils/sender_file.py` as the
`sender` dependency injected into a real `RestSend`. Responses are read from
`tests/unit/module_utils/fixtures/fixture_data/test_port_channel_trunk_host_interface.json`.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-many-lines

from __future__ import annotations

import inspect

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_trunk_host_interface import (
    PortChannelTrunkHostInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_trunk_host_interface import (
    PortChannelTrunkHostInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_pc_trunk_host(key: str):
    """Load fixture data for the orchestrator's test_port_channel_trunk_host_interface.json file."""
    return load_fixture("test_port_channel_trunk_host_interface")[key]


def _build_rest_send(
    gen_responses: ResponseGenerator,
    fabric_name: str = "fabric_1",
    state: str | None = None,
    config: list[dict] | None = None,
) -> RestSend:
    """Build a RestSend wired to the file-based Sender and the real ResponseHandler.

    `state` and `config` populate `rest_send.params` so `query_all`'s `_switches_to_query` scoping
    (fabric-wide for `overridden`, config-scoped otherwise) can be exercised.
    """
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    params: dict = {"check_mode": False, "fabric_name": fabric_name}
    if state is not None:
        params["state"] = state
    if config is not None:
        params["config"] = config

    rest_send = RestSend(params)
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


def _build_orchestrator(
    gen_responses: ResponseGenerator,
    fabric_name: str = "fabric_1",
    state: str | None = None,
    config: list[dict] | None = None,
) -> PortChannelTrunkHostInterfaceOrchestrator:
    """Construct an orchestrator with the file-based RestSend injected."""
    rest_send = _build_rest_send(gen_responses, fabric_name=fabric_name, state=state, config=config)
    return PortChannelTrunkHostInterfaceOrchestrator(rest_send=rest_send)


# =============================================================================
# Test: ClassVar / model_class
# =============================================================================


def test_port_channel_trunk_host_orchestrator_00010() -> None:
    """
    # Summary

    Verify `model_class` points to `PortChannelTrunkHostInterfaceModel`.

    ## Test

    - model_class is PortChannelTrunkHostInterfaceModel

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceOrchestrator.model_class
    """
    assert PortChannelTrunkHostInterfaceOrchestrator.model_class is PortChannelTrunkHostInterfaceModel


def test_port_channel_trunk_host_orchestrator_00020() -> None:
    """
    # Summary

    Verify bulk-support flags inherited from `PortChannelBaseOrchestrator`.

    ## Test

    - supports_bulk_create is True
    - supports_bulk_delete is True

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceOrchestrator
    """
    assert PortChannelTrunkHostInterfaceOrchestrator.supports_bulk_create is True
    assert PortChannelTrunkHostInterfaceOrchestrator.supports_bulk_delete is True


# =============================================================================
# Test: _managed_policy_types
# =============================================================================


def test_port_channel_trunk_host_orchestrator_00100() -> None:
    """
    # Summary

    Verify `_managed_policy_types` returns the single `"trunkPoHost"` API value.

    ## Test

    - Returned set contains exactly "trunkPoHost"

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceOrchestrator._managed_policy_types()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    assert orchestrator._managed_policy_types() == {"trunkPoHost"}


def test_port_channel_trunk_host_orchestrator_00110() -> None:
    """
    # Summary

    Verify `_managed_policy_types` returns a set (supports set membership for `in` checks).

    ## Test

    - Return type is set

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceOrchestrator._managed_policy_types()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    result = orchestrator._managed_policy_types()
    assert isinstance(result, set)
    assert "trunkPoHost" in result


# =============================================================================
# Test: query_all — happy path with filtering
# =============================================================================


def test_port_channel_trunk_host_orchestrator_00400() -> None:
    """
    # Summary

    Verify `query_all` validates the fabric, iterates all switches, filters to interfaceType=="portChannel"
    and policyType=="trunkPoHost", and injects `switchIp` onto each kept interface. accessPoHost
    port-channels and ethernet interfaces are excluded.

    ## Test

    - Fabric summary (validate_prerequisites) returns 200
    - Switches list returns two switches
    - Switch 1 returns: configured trunkPoHost portChannel, accessPoHost portChannel, ethernet trunkHost
    - Switch 2 returns: one configured trunkPoHost portChannel
    - Result contains exactly the two trunkPoHost port-channels
    - Each has switchIp injected with the fabricManagementIp

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceOrchestrator._managed_policy_types()
    - PortChannelBaseOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_trunk_host("test_query_all_happy_path_00400a")
        yield responses_pc_trunk_host("test_query_all_happy_path_00400b")
        yield responses_pc_trunk_host("test_query_all_happy_path_00400c")
        yield responses_pc_trunk_host("test_query_all_happy_path_00400d")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        # state=overridden keeps query_all fabric-wide so this test exercises cross-switch filtering.
        orchestrator = _build_orchestrator(gen_responses, state="overridden")
        result = orchestrator.query_all()

    assert isinstance(result, list)
    assert len(result) == 2

    by_name = {iface["interfaceName"]: iface for iface in result}
    assert set(by_name) == {"port-channel501", "port-channel601"}

    # switchIp is injected by the base query_all
    assert by_name["port-channel501"]["switchIp"] == "192.168.1.1"
    assert by_name["port-channel601"]["switchIp"] == "192.168.1.2"

    # Filtered out: accessPoHost (port-channel502) and ethernet trunkHost (Ethernet1/1)
    assert "port-channel502" not in by_name
    assert "Ethernet1/1" not in by_name

    # method_name is used for clearer pytest failure messages; keep as a sanity reference
    assert method_name.endswith("00400")


def test_port_channel_trunk_host_orchestrator_00410() -> None:
    """
    # Summary

    Verify `query_all` returns an empty list when no switch reports any trunkPoHost port-channel.

    ## Test

    - Switch returns only non-port-channel and non-trunkPoHost port-channel interfaces
    - Result is an empty list

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceOrchestrator._managed_policy_types()
    - PortChannelBaseOrchestrator.query_all()
    """

    def responses():
        yield responses_pc_trunk_host("test_query_all_no_match_00410a")
        yield responses_pc_trunk_host("test_query_all_no_match_00410b")
        yield responses_pc_trunk_host("test_query_all_no_match_00410c")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        # state=overridden keeps query_all fabric-wide so every switch is scanned for the no-match assertion.
        orchestrator = _build_orchestrator(gen_responses, state="overridden")
        result = orchestrator.query_all()

    assert result == []


def test_port_channel_trunk_host_orchestrator_00420() -> None:
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
        yield responses_pc_trunk_host("test_query_all_fabric_not_found_00420a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses, fabric_name="missing_fabric")

    with pytest.raises(RuntimeError, match=r"Query all failed.*missing_fabric"):
        orchestrator.query_all()


def test_port_channel_trunk_host_orchestrator_00430() -> None:
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
        yield responses_pc_trunk_host("test_query_all_switch_404_00430a")
        yield responses_pc_trunk_host("test_query_all_switch_404_00430b")
        yield responses_pc_trunk_host("test_query_all_switch_404_00430c")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        # state=overridden keeps query_all fabric-wide so the 404 switch is still visited and skipped.
        orchestrator = _build_orchestrator(gen_responses, state="overridden")
        result = orchestrator.query_all()

    assert result == []


def test_port_channel_trunk_host_orchestrator_00440() -> None:
    """
    # Summary

    Verify `query_all` scopes its per-switch interface-list fan-out to switches named in the user config when
    `state` is not `overridden`, rather than querying every switch in the fabric.

    ## Test

    - Fabric has two switches (192.168.1.1, 192.168.1.2), but config names only 192.168.1.1
    - state is `merged` (non-overridden), so `_switches_to_query` returns only the config switch
    - Only the config switch's interfaces are fetched; the second switch is never queried (the response
      generator yields exactly three responses — summary, switch list, switch-1 interfaces — and would raise
      if a second per-switch GET were issued)
    - Result contains only the trunkPoHost port-channel on the config switch

    ## Classes and Methods

    - PortChannelBaseOrchestrator._switches_to_query()
    - PortChannelBaseOrchestrator.query_all()
    """

    def responses():
        yield responses_pc_trunk_host("test_query_all_config_scoped_00440a")
        yield responses_pc_trunk_host("test_query_all_config_scoped_00440b")
        yield responses_pc_trunk_host("test_query_all_config_scoped_00440c")

    gen_responses = ResponseGenerator(responses())

    config = [{"switch_ip": "192.168.1.1", "interface_name": "port-channel501"}]

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses, state="merged", config=config)
        result = orchestrator.query_all()

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["interfaceName"] == "port-channel501"
    assert result[0]["switchIp"] == "192.168.1.1"
