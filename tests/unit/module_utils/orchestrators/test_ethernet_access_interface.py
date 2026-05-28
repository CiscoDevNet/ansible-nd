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
    EthernetAccessConfigDataModel,
    EthernetAccessInterfaceModel,
    EthernetAccessNetworkOSModel,
    EthernetAccessPolicyModel,
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


def _build_rest_send(gen_responses: ResponseGenerator, fabric_name: str = "fabric_1", params: dict | None = None) -> RestSend:
    """Build a RestSend wired to the file-based Sender and the real ResponseHandler.

    `params` is merged into the RestSend params so tests can supply `state` and `config`,
    which `query_all` reads via `_switches_to_query` to scope the switches it queries.
    """
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    rest_send_params = {"check_mode": False, "fabric_name": fabric_name}
    if params:
        rest_send_params.update(params)
    rest_send = RestSend(rest_send_params)
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


def _build_orchestrator(gen_responses: ResponseGenerator, fabric_name: str = "fabric_1", params: dict | None = None) -> EthernetAccessInterfaceOrchestrator:
    """Construct an orchestrator with the file-based RestSend injected."""
    rest_send = _build_rest_send(gen_responses, fabric_name=fabric_name, params=params)
    return EthernetAccessInterfaceOrchestrator(rest_send=rest_send)


def _build_access_model(policy_kwargs: dict, interface_name: str = "Ethernet1/1", switch_ip: str = "192.168.1.1") -> EthernetAccessInterfaceModel:
    """Build an `EthernetAccessInterfaceModel` whose policy carries exactly `policy_kwargs`."""
    return EthernetAccessInterfaceModel(
        switch_ip=switch_ip,
        interface_name=interface_name,
        config_data=EthernetAccessConfigDataModel(
            network_os=EthernetAccessNetworkOSModel(
                policy=EthernetAccessPolicyModel(**policy_kwargs),
            ),
        ),
    )


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

    Verify `query_all` validates the fabric, iterates the switches named in the config, filters to accessHost
    interfaces only, and injects `switchIp` onto each kept interface.

    ## Test

    - state is `merged`; config references both switches in the fabric
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
        yield responses_access("test_query_all_happy_path_00400b")
        yield responses_access("test_query_all_happy_path_00400c")
        yield responses_access("test_query_all_happy_path_00400d")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(
            gen_responses,
            params={"state": "merged", "config": [{"switch_ip": "192.168.1.1"}, {"switch_ip": "192.168.1.2"}]},
        )
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


def test_ethernet_access_orchestrator_00410() -> None:
    """
    # Summary

    Verify `query_all` skips fabric switches absent from the user config for non-overridden states, so the
    interface-list request count scales with config size, not fabric size.

    ## Test

    - state is `merged`; config references only switch 192.168.1.10
    - Fabric summary returns 200; switches list returns two switches (192.168.1.10 and 192.168.1.11)
    - Only switch 192.168.1.10 is queried for interfaces; 192.168.1.11 is never requested
    - Result contains only the accessHost interface on 192.168.1.10

    ## Classes and Methods

    - EthernetBaseOrchestrator._switches_to_query()
    - EthernetBaseOrchestrator.query_all()
    """

    def responses():
        yield responses_access("test_query_all_config_scoped_00410a")
        yield responses_access("test_query_all_config_scoped_00410b")
        yield responses_access("test_query_all_config_scoped_00410c")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(
            gen_responses,
            params={"state": "merged", "config": [{"switch_ip": "192.168.1.10"}]},
        )
        result = orchestrator.query_all()

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["interfaceName"] == "Ethernet1/1"
    assert result[0]["switchIp"] == "192.168.1.10"


def test_ethernet_access_orchestrator_00415() -> None:
    """
    # Summary

    Verify `query_all` stays fabric-wide for `state: overridden`: every switch in the fabric is queried even
    when the user config is empty.

    ## Test

    - state is `overridden`; config is empty
    - Fabric summary returns 200; switches list returns two switches
    - Both switches are queried for interfaces despite the empty config
    - Result contains the accessHost interface from each switch

    ## Classes and Methods

    - EthernetBaseOrchestrator._switches_to_query()
    - EthernetBaseOrchestrator.query_all()
    """

    def responses():
        yield responses_access("test_query_all_overridden_fabric_wide_00415a")
        yield responses_access("test_query_all_overridden_fabric_wide_00415b")
        yield responses_access("test_query_all_overridden_fabric_wide_00415c")
        yield responses_access("test_query_all_overridden_fabric_wide_00415d")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(
            gen_responses,
            params={"state": "overridden", "config": []},
        )
        result = orchestrator.query_all()

    assert isinstance(result, list)
    assert len(result) == 2
    assert {iface["interfaceName"] for iface in result} == {"Ethernet1/1", "Ethernet2/1"}


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


# =============================================================================
# Test: port-channel membership enforcement (create / update / create_bulk)
# =============================================================================


def test_ethernet_access_orchestrator_00500() -> None:
    """
    # Summary

    Verify `create` raises `RuntimeError` when the target interface is an existing port-channel member and a
    non-whitelisted policy field is being changed.

    ## Test

    - switches-list resolves 192.168.1.1 -> FDO11111AAA
    - interfaceList reports Ethernet1/1 as a member of port-channel 10
    - The model changes `access_vlan`, which is not in `PORT_CHANNEL_MODIFIABLE_FIELDS`
    - `create` raises `RuntimeError` naming the port-channel and the rejected field
    - No deploy is queued (the check raises before the POST)

    ## Classes and Methods

    - EthernetBaseOrchestrator.create()
    - EthernetBaseOrchestrator._existing_interface()
    - EthernetBaseOrchestrator._check_port_channel_restrictions()
    """

    def responses():
        yield responses_access("test_create_pc_member_blocked_00500a")
        yield responses_access("test_create_pc_member_blocked_00500b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = EthernetAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_access_model({"access_vlan": 100})

    with pytest.raises(RuntimeError, match=r"Create failed for.*member of port-channel 10.*access_vlan"):
        instance.create(model)

    assert instance._pending_deploys == []


def test_ethernet_access_orchestrator_00510() -> None:
    """
    # Summary

    Verify `create` succeeds on a port-channel member when only whitelisted policy fields are being changed.

    ## Test

    - switches-list resolves 192.168.1.1 -> FDO11111AAA
    - interfaceList reports Ethernet1/1 as a member of port-channel 10
    - The model changes only `description`, which is in `PORT_CHANNEL_MODIFIABLE_FIELDS`
    - `create` does not raise; the POST is issued and a deploy is queued

    ## Classes and Methods

    - EthernetBaseOrchestrator.create()
    - EthernetBaseOrchestrator._check_port_channel_restrictions()
    """

    def responses():
        yield responses_access("test_create_pc_member_whitelisted_00510a")
        yield responses_access("test_create_pc_member_whitelisted_00510b")
        yield responses_access("test_create_pc_member_whitelisted_00510c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = EthernetAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_access_model({"description": "uplink to host"})

    with does_not_raise():
        instance.create(model)

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces"
    assert instance._pending_deploys == [("Ethernet1/1", "FDO11111AAA")]


def test_ethernet_access_orchestrator_00520() -> None:
    """
    # Summary

    Verify `create` succeeds when the target interface is not a port-channel member, even when a
    non-whitelisted policy field is being changed.

    ## Test

    - switches-list resolves 192.168.1.1 -> FDO11111AAA
    - interfaceList reports Ethernet1/1 with no `portChannelId` (not a port-channel member)
    - The model changes `access_vlan` (non-whitelisted), which is allowed because there is no membership
    - `create` does not raise; the POST is issued and a deploy is queued

    ## Classes and Methods

    - EthernetBaseOrchestrator.create()
    - EthernetBaseOrchestrator._check_port_channel_restrictions()
    """

    def responses():
        yield responses_access("test_create_not_pc_member_00520a")
        yield responses_access("test_create_not_pc_member_00520b")
        yield responses_access("test_create_not_pc_member_00520c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = EthernetAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_access_model({"access_vlan": 100})

    with does_not_raise():
        instance.create(model)

    assert instance._pending_deploys == [("Ethernet1/1", "FDO11111AAA")]


def test_ethernet_access_orchestrator_00530() -> None:
    """
    # Summary

    Verify `update` enforces port-channel membership restrictions, raising `RuntimeError` when a
    non-whitelisted policy field is changed on an existing port-channel member.

    ## Test

    - switches-list resolves 192.168.1.1 -> FDO11111AAA
    - interfaceList reports Ethernet1/1 as a member of port-channel 10
    - The model changes `access_vlan` (non-whitelisted)
    - `update` raises `RuntimeError`; no deploy is queued

    ## Classes and Methods

    - EthernetBaseOrchestrator.update()
    - EthernetBaseOrchestrator._existing_interface()
    - EthernetBaseOrchestrator._check_port_channel_restrictions()
    """

    def responses():
        yield responses_access("test_update_pc_member_blocked_00530a")
        yield responses_access("test_update_pc_member_blocked_00530b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = EthernetAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_access_model({"access_vlan": 100})

    with pytest.raises(RuntimeError, match=r"Update failed for.*member of port-channel 10.*access_vlan"):
        instance.update(model)

    assert instance._pending_deploys == []


def test_ethernet_access_orchestrator_00540() -> None:
    """
    # Summary

    Verify `create_bulk` enforces port-channel membership restrictions, raising `RuntimeError` when a
    non-whitelisted policy field is changed on an existing port-channel member.

    ## Test

    - switches-list resolves 192.168.1.1 -> FDO11111AAA
    - interfaceList reports Ethernet1/1 as a member of port-channel 10
    - The single bulk model changes `access_vlan` (non-whitelisted)
    - `create_bulk` raises `RuntimeError`; no deploy is queued

    ## Classes and Methods

    - EthernetBaseOrchestrator.create_bulk()
    - EthernetBaseOrchestrator._existing_interface()
    - EthernetBaseOrchestrator._check_port_channel_restrictions()
    """

    def responses():
        yield responses_access("test_create_bulk_pc_member_blocked_00540a")
        yield responses_access("test_create_bulk_pc_member_blocked_00540b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = EthernetAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_access_model({"access_vlan": 100})

    with pytest.raises(RuntimeError, match=r"Bulk create failed.*member of port-channel 10.*access_vlan"):
        instance.create_bulk([model])

    assert instance._pending_deploys == []


def test_ethernet_access_orchestrator_00550() -> None:
    """
    # Summary

    Verify `update` succeeds on a port-channel member when the post-merge model carries non-whitelisted
    wire-side values (e.g. `access_vlan`, `mtu`) that the user did NOT change. Regression test for the
    state:merged path where the state machine merges the existing model into the proposed one before
    calling `update`.

    ## Test

    - switches-list resolves 192.168.1.1 -> FDO11111AAA
    - interfaceList reports Ethernet1/1 as a member of port-channel 10 with `accessVlan=10`, `mtu=jumbo`
    - The model passed to `update` carries `description='new'` (the user-set field) AND the existing
      `access_vlan=10` / `mtu=jumbo` carried over by the state machine's merge step
    - Only `description` differs from the wire; `access_vlan` / `mtu` match -> no flag -> `update` succeeds

    ## Classes and Methods

    - EthernetBaseOrchestrator.update()
    - EthernetBaseOrchestrator._check_port_channel_restrictions()
    """

    def responses():
        yield responses_access("test_update_pc_member_merged_whitelisted_00550a")
        yield responses_access("test_update_pc_member_merged_whitelisted_00550b")
        yield responses_access("test_update_pc_member_merged_whitelisted_00550c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = EthernetAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_access_model({"description": "new", "access_vlan": 10, "mtu": "jumbo"})

    with does_not_raise():
        instance.update(model)

    assert instance._pending_deploys == [("Ethernet1/1", "FDO11111AAA")]


def test_ethernet_access_orchestrator_00560() -> None:
    """
    # Summary

    Verify `update` still raises on a port-channel member when the post-merge model genuinely changes a
    non-whitelisted field (different value from the wire). Confirms the merge-aware check did not
    over-loosen the guard.

    ## Test

    - switches-list resolves 192.168.1.1 -> FDO11111AAA
    - interfaceList reports Ethernet1/1 as a port-channel member with `accessVlan=10`
    - The model carries `access_vlan=100` (different from wire) -> flagged as a real change
    - `update` raises `RuntimeError` naming `access_vlan`; no deploy is queued

    ## Classes and Methods

    - EthernetBaseOrchestrator.update()
    - EthernetBaseOrchestrator._check_port_channel_restrictions()
    """

    def responses():
        yield responses_access("test_update_pc_member_merged_unwhitelisted_00560a")
        yield responses_access("test_update_pc_member_merged_unwhitelisted_00560b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = EthernetAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_access_model({"access_vlan": 100})

    with pytest.raises(RuntimeError, match=r"Update failed for.*member of port-channel 10.*access_vlan"):
        instance.update(model)

    assert instance._pending_deploys == []


def test_ethernet_access_orchestrator_00570() -> None:
    """
    # Summary

    Verify `delete` refuses to normalize a port-channel member: normalizing would strip the channel-group
    membership and silently detach the interface from its port-channel.

    ## Test

    - switches-list resolves 192.168.1.1 -> FDO11111AAA
    - interfaceList reports Ethernet1/1 as a member of port-channel 10
    - `delete` raises `RuntimeError` naming the port-channel; no normalize or deploy is queued

    ## Classes and Methods

    - EthernetBaseOrchestrator.delete()
    - EthernetBaseOrchestrator._check_port_channel_delete_restriction()
    """

    def responses():
        yield responses_access("test_delete_pc_member_blocked_00570a")
        yield responses_access("test_delete_pc_member_blocked_00570b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = EthernetAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_access_model({})

    with pytest.raises(RuntimeError, match=r"Delete failed for.*member of port-channel 10.*Refusing to normalize"):
        instance.delete(model)

    assert instance._pending_normalizes == []
    assert instance._pending_deploys == []


def test_ethernet_access_orchestrator_00580() -> None:
    """
    # Summary

    Verify `delete_bulk` refuses when any interface in the batch is a port-channel member, failing fast on
    the first offender so the caller does not silently detach interfaces from their port-channels.

    ## Test

    - switches-list resolves 192.168.1.1 -> FDO11111AAA
    - interfaceList reports Ethernet1/1 as a member of port-channel 10
    - `delete_bulk` raises `RuntimeError`; no normalize or deploy is queued

    ## Classes and Methods

    - EthernetBaseOrchestrator.delete_bulk()
    - EthernetBaseOrchestrator._check_port_channel_delete_restriction()
    """

    def responses():
        yield responses_access("test_delete_bulk_pc_member_blocked_00580a")
        yield responses_access("test_delete_bulk_pc_member_blocked_00580b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = EthernetAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_access_model({})

    with pytest.raises(RuntimeError, match=r"member of port-channel 10.*Refusing to normalize"):
        instance.delete_bulk([model])

    assert instance._pending_normalizes == []
    assert instance._pending_deploys == []


def test_ethernet_access_orchestrator_00590() -> None:
    """
    # Summary

    Verify `delete` proceeds normally when the target interface is not a port-channel member, queuing both
    a normalize and a deploy for later bulk execution.

    ## Test

    - switches-list resolves 192.168.1.1 -> FDO11111AAA
    - interfaceList reports Ethernet1/1 with no `portChannelId`
    - `delete` does not raise; `_pending_normalizes` and `_pending_deploys` each contain the pair

    ## Classes and Methods

    - EthernetBaseOrchestrator.delete()
    - EthernetBaseOrchestrator._check_port_channel_delete_restriction()
    """

    def responses():
        yield responses_access("test_delete_not_pc_member_00590a")
        yield responses_access("test_delete_not_pc_member_00590b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = EthernetAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_access_model({})

    with does_not_raise():
        instance.delete(model)

    assert instance._pending_normalizes == [("Ethernet1/1", "FDO11111AAA")]
    assert instance._pending_deploys == [("Ethernet1/1", "FDO11111AAA")]


def test_ethernet_access_orchestrator_00600() -> None:
    """
    # Summary

    Verify `delete_bulk` silently skips port-channel members when `state == "overridden"` so fabric-wide
    convergence does not detach interfaces from their port-channels. Non-member interfaces in the same batch
    are still queued for normalize / deploy.

    ## Test

    - state is "overridden"
    - switches-list resolves 192.168.1.1 -> FDO11111AAA and 192.168.1.2 -> FDO22222BBB
    - Ethernet1/1 on FDO11111AAA is a PC 10 member -> skipped
    - Ethernet1/2 on FDO22222BBB is not a PC member -> queued
    - `delete_bulk` does not raise; only the non-member ends up in `_pending_normalizes` / `_pending_deploys`

    ## Classes and Methods

    - EthernetBaseOrchestrator.delete_bulk()
    - EthernetBaseOrchestrator._existing_port_channel_id()
    """

    def responses():
        yield responses_access("test_delete_bulk_overridden_skips_pc_00600a")
        yield responses_access("test_delete_bulk_overridden_skips_pc_00600b")
        yield responses_access("test_delete_bulk_overridden_skips_pc_00600c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, params={"state": "overridden"})
    instance = EthernetAccessInterfaceOrchestrator(rest_send=rest_send)
    pc_member = _build_access_model({}, interface_name="Ethernet1/1", switch_ip="192.168.1.1")
    non_member = _build_access_model({}, interface_name="Ethernet1/2", switch_ip="192.168.1.2")

    with does_not_raise():
        instance.delete_bulk([pc_member, non_member])

    assert instance._pending_normalizes == [("Ethernet1/2", "FDO22222BBB")]
    assert instance._pending_deploys == [("Ethernet1/2", "FDO22222BBB")]


def test_ethernet_access_orchestrator_00610() -> None:
    """
    # Summary

    Verify `delete_bulk` still raises on a port-channel member when `state == "deleted"` (the user named the
    interface explicitly), so the user is told loudly rather than having their PC silently broken.

    ## Test

    - state is "deleted"
    - switches-list resolves 192.168.1.1 -> FDO11111AAA
    - Ethernet1/1 is a PC 10 member, user named it
    - `delete_bulk` raises `RuntimeError`; nothing is queued

    ## Classes and Methods

    - EthernetBaseOrchestrator.delete_bulk()
    - EthernetBaseOrchestrator._check_port_channel_delete_restriction()
    """

    def responses():
        yield responses_access("test_delete_bulk_deleted_raises_pc_00610a")
        yield responses_access("test_delete_bulk_deleted_raises_pc_00610b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, params={"state": "deleted"})
    instance = EthernetAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_access_model({})

    with pytest.raises(RuntimeError, match=r"member of port-channel 10.*Refusing to normalize"):
        instance.delete_bulk([model])

    assert instance._pending_normalizes == []
    assert instance._pending_deploys == []
