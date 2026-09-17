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
    EthernetTrunkHostConfigDataModel,
    EthernetTrunkHostInterfaceModel,
    XeEthernetTrunkHostNetworkOSModel,
    XeEthernetTrunkHostPolicyModel,
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


def _build_orchestrator(gen_responses: ResponseGenerator, fabric_name: str = "fabric_1", params: dict | None = None) -> EthernetTrunkHostInterfaceOrchestrator:
    """Construct an orchestrator with the file-based RestSend injected."""
    rest_send = _build_rest_send(gen_responses, fabric_name=fabric_name, params=params)
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
    assert orchestrator._managed_policy_types() == {"trunkHost", "iosXeTrunkHost"}


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
        (
            {
                "configData": {
                    "networkOS": {"policy": {"bandwidth": 1500000}},
                },
            },
            False,
        ),
        (
            {
                "configData": {
                    "networkOS": {"policy": {"debounceLinkupTimer": 5000}},
                },
            },
            False,
        ),
        (
            {
                "configData": {
                    "networkOS": {"policy": {"inheritBandwidth": 2000000}},
                },
            },
            False,
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
        "class_c_bandwidth",
        "class_c_debounce_linkup",
        "class_c_inherit_bandwidth",
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

    Verify `query_all` validates the fabric, iterates the switches named in the config, filters to
    trunkHost interfaces, excludes unconfigured defaults, and injects `switchIp` onto each kept interface.

    ## Test

    - state is `merged`; config references both switches in the fabric
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

    # Filtered out: unconfigured-default trunkHost (Ethernet1/2) and accessHost (Ethernet1/3)
    assert "Ethernet1/2" not in by_name
    assert "Ethernet1/3" not in by_name

    # method_name is used for clearer pytest failure messages; keep as a sanity reference
    assert method_name.endswith("00400")


def test_ethernet_trunk_host_orchestrator_00410(monkeypatch) -> None:
    """
    # Summary

    Verify `query_all` returns an empty list specifically because the
    `_is_unconfigured_default` filter dropped every trunkHost interface returned by the
    switch — not because no switches were scanned.

    ## Test

    - state is `merged`; config references the one switch returned by the fabric, so
      `_switches_to_query` selects it and the per-switch interfaces GET is actually issued
    - Switch returns two default-configured trunkHost interfaces
    - `_is_unconfigured_default` is called once per interface (proves the filter ran)
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

    filtered: list[dict] = []
    original_filter = EthernetTrunkHostInterfaceOrchestrator._is_unconfigured_default

    def spy(iface: dict) -> bool:
        filtered.append(iface)
        return original_filter(iface)

    monkeypatch.setattr(EthernetTrunkHostInterfaceOrchestrator, "_is_unconfigured_default", staticmethod(spy))

    with does_not_raise():
        orchestrator = _build_orchestrator(
            gen_responses,
            params={"state": "merged", "config": [{"switch_ip": "192.168.1.1"}]},
        )
        result = orchestrator.query_all()

    assert result == []
    assert [iface["interfaceName"] for iface in filtered] == ["Ethernet1/1", "Ethernet1/2"]


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


# =============================================================================
# Test: IOS-XE branch (issue #535)
# =============================================================================


def test_ethernet_trunk_host_orchestrator_00120() -> None:
    """
    # Summary

    Verify `_managed_policy_types` is exactly the union of the NX-OS and IOS-XE trunk-host policy types, so `query_all` keeps
    Catalyst `iosXeTrunkHost` interfaces in scope alongside NX-OS `trunkHost`.

    ## Test

    - Result == {"trunkHost", "iosXeTrunkHost"}

    ## Classes and Methods

    - EthernetTrunkHostInterfaceOrchestrator._managed_policy_types()
    """

    def responses():
        yield {}

    orchestrator = _build_orchestrator(ResponseGenerator(responses()))
    assert orchestrator._managed_policy_types() == {"trunkHost", "iosXeTrunkHost"}


XE_TRUNK_DEFAULTS_ONLY_POLICY = {
    "policyType": "iosXeTrunkHost",
    "adminState": True,
    "allowedVlans": "none",
    "bpduGuard": "default",
    "mtu": 1500,
    "speed": "auto",
}


@pytest.mark.parametrize(
    "policy_overrides,expected",
    [
        ({}, True),
        ({"description": ""}, True),
        ({"allowedVlans": "10"}, False),
        ({"allowedVlans": "all"}, False),
        ({"description": "cat trunk"}, False),
        ({"mtu": 9000}, False),
        ({"speed": "1Gb"}, False),
        ({"bpduGuard": "enable"}, False),
        ({"adminState": False}, False),
        ({"extraConfig": "spanning-tree portfast trunk"}, False),
        ({"deviceTrackingPolicy": "IPDT_POLICY"}, False),
    ],
    ids=[
        "xe_defaults_only",
        "xe_empty_description",
        "xe_allowed_vlans_set",
        "xe_allowed_vlans_all",
        "xe_description_set",
        "xe_mtu_nondefault",
        "xe_speed_nondefault",
        "xe_bpdu_guard_nondefault",
        "xe_admin_down",
        "xe_extra_config_set",
        "xe_431_only_field_set",
    ],
)
def test_ethernet_trunk_host_orchestrator_00210(policy_overrides, expected) -> None:
    """
    # Summary

    Exercise the IOS-XE truth table for `_is_unconfigured_default`: a Catalyst port reset by the XE reset PUT reads back as a
    defaults-only `iosXeTrunkHost` (ND injects the `iosXeIntTrunkHostTemplate` defaults on the echo), and it must leave this
    module's scope so `state: overridden` and repeat `deleted` runs stay idempotent. Any configured field (including a 4.3.1-only
    field the model does not declare) or any non-default value keeps the interface in scope.

    ## Test

    - XE defaults-only (and an empty `description`) -> True; every override -> False

    ## Classes and Methods

    - EthernetTrunkHostInterfaceOrchestrator._is_unconfigured_default()
    """
    policy = {**XE_TRUNK_DEFAULTS_ONLY_POLICY, **policy_overrides}
    iface = {"configData": {"mode": "trunk", "networkOS": {"networkOSType": "ios-xe", "policy": policy}}}
    assert EthernetTrunkHostInterfaceOrchestrator._is_unconfigured_default(iface) is expected


def test_ethernet_trunk_host_orchestrator_00440() -> None:
    """
    # Summary

    Verify an explicitly named IOS-XE trunk interface under `state: deleted` is queued for the XE reset path with the shared
    defaults-only `iosXeTrunkHost` reset body (never the NX-OS normalize queue), and is queued for deploy.

    ## Test

    - state is `deleted`; delete_bulk receives one IOS-XE model (the links GET lists no fabric link, so it is not fabric-owned)
    - XE pair in `_pending_xe_resets`, not in `_pending_normalizes`; pair in `_pending_deploys`
    - `_xe_reset_payload` policy is exactly {policyType: iosXeTrunkHost, adminState: true} in `trunk` mode

    ## Classes and Methods

    - EthernetBaseOrchestrator.delete_bulk()
    - EthernetBaseOrchestrator._xe_reset_payload()
    """

    def responses():
        yield responses_trunk_host("test_xe_reset_payload_00440a")
        yield responses_trunk_host("test_xe_reset_payload_00440b")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()), params={"state": "deleted"})
    xe = EthernetTrunkHostInterfaceModel(
        switch_ip="192.168.2.1",
        interface_name="GigabitEthernet1/0/1",
        config_data=EthernetTrunkHostConfigDataModel(
            network_os=XeEthernetTrunkHostNetworkOSModel(
                network_os_type="ios-xe",
                policy=XeEthernetTrunkHostPolicyModel(policy_type="iosXeTrunkHost", allowed_vlans="10"),
            ),
        ),
    )
    with does_not_raise():
        orchestrator.delete_bulk([xe], existing_data={"interfaceName": "probe", "operData": {"portChannelId": -1}})
    assert orchestrator._pending_xe_resets == [("GigabitEthernet1/0/1", "FDO22222BBB")]
    assert orchestrator._pending_normalizes == []
    assert orchestrator._pending_deploys == [("GigabitEthernet1/0/1", "FDO22222BBB")]
    payload = EthernetTrunkHostInterfaceOrchestrator._xe_reset_payload("GigabitEthernet1/0/1", "FDO22222BBB")
    assert payload["configData"]["mode"] == "trunk"
    assert payload["configData"]["networkOS"] == {"networkOSType": "ios-xe", "policy": {"policyType": "iosXeTrunkHost", "adminState": True}}


# =============================================================================
# Test: fabric-ownership guard on the IOS-XE branch (PR #558 review, mikewiebe)
# =============================================================================


def _build_xe_trunk_model(
    policy_kwargs: dict, interface_name: str = "GigabitEthernet1/0/1", switch_ip: str = "192.168.2.1"
) -> EthernetTrunkHostInterfaceModel:
    """Build an IOS-XE `EthernetTrunkHostInterfaceModel` whose policy carries exactly `policy_kwargs`."""
    return EthernetTrunkHostInterfaceModel(
        switch_ip=switch_ip,
        interface_name=interface_name,
        config_data=EthernetTrunkHostConfigDataModel(
            network_os=XeEthernetTrunkHostNetworkOSModel(
                network_os_type="ios-xe",
                policy=XeEthernetTrunkHostPolicyModel(policy_type="iosXeTrunkHost", **policy_kwargs),
            ),
        ),
    )


def _xe_routed_wire(interface_name: str) -> dict:
    """Build the wire-state dict of a defaults-only IOS-XE `iosXeRoutedHost` interface — the shape a fabric-link endpoint reads as."""
    return {
        "interfaceName": interface_name,
        "interfaceType": "ethernet",
        "operData": {"portChannelId": -1},
        "configData": {
            "mode": "routed",
            "networkOS": {"networkOSType": "ios-xe", "policy": {"policyType": "iosXeRoutedHost", "adminState": True, "mtu": 1500, "speed": "auto"}},
        },
    }


def test_ethernet_trunk_host_orchestrator_00800() -> None:
    """
    # Summary

    Verify `create_bulk` refuses an IOS-XE target that is an endpoint of a fabric link carrying an ND link policy even though its own
    wire record is a plain defaults-only `iosXeRoutedHost`, which the policy-type guard alone would let an `iosXeTrunkHost` overwrite
    (PR #558 review). Policy type cannot express IOS-XE fabric ownership, so the fabric links are consulted before any write.

    ## Test

    - Existing wire state for GigabitEthernet1/0/48 is a defaults-only `iosXeRoutedHost` (passes the policy-type guard)
    - The links GET lists GigabitEthernet1/0/48 as the src endpoint of a link carrying a link policy
    - `create_bulk` raises `RuntimeError` naming the link before any POST; nothing is queued for deploy

    ## Classes and Methods

    - EthernetBaseOrchestrator._check_fabric_ownership()
    - EthernetBaseOrchestrator._check_xe_fabric_link()
    - EthernetBaseOrchestrator._fabric_link_endpoints()
    """

    def responses():
        yield responses_trunk_host("test_xe_ownership_00800a")
        yield responses_trunk_host("test_xe_ownership_00800b")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()), params={"state": "merged"})
    model = _build_xe_trunk_model({"allowed_vlans": "10"}, interface_name="GigabitEthernet1/0/48")

    with pytest.raises(
        RuntimeError,
        match=r"Bulk create failed: Interface GigabitEthernet1/0/48 on switch 192\.168\.2\.1 is an endpoint of fabric link LINK-UUID-1 "
        r"\(numbered: C1_LE1 GigabitEthernet1/0/48 -> C1_CORE1 GigabitEthernet1/0/1\)\. Refusing to overwrite fabric-owned intent with policy 'iosXeTrunkHost'",
    ):
        orchestrator.create_bulk([model], existing_data=_xe_routed_wire("GigabitEthernet1/0/48"))
    assert orchestrator._pending_deploys == []
    assert len(orchestrator.rest_send.responses) == 2


def test_ethernet_trunk_host_orchestrator_00810() -> None:
    """
    # Summary

    Verify `preflight` runs the IOS-XE fabric-link check against the per-switch inventory, so a `--check` run naming a fabric-link
    endpoint fails exactly like a normal run would inside `create_bulk` instead of reporting a planned change.

    ## Test

    - interfaceList reports GigabitEthernet1/0/48 as a defaults-only `iosXeRoutedHost`
    - The links GET lists GigabitEthernet1/0/48 as the src endpoint of a link carrying a link policy
    - `preflight` raises `RuntimeError` naming the link

    ## Classes and Methods

    - EthernetBaseOrchestrator.preflight()
    - EthernetBaseOrchestrator._check_xe_fabric_link()
    """

    def responses():
        yield responses_trunk_host("test_xe_ownership_preflight_00810a")
        yield responses_trunk_host("test_xe_ownership_preflight_00810b")
        yield responses_trunk_host("test_xe_ownership_preflight_00810c")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()), params={"state": "merged", "check_mode": True})
    model = _build_xe_trunk_model({"allowed_vlans": "10"}, interface_name="GigabitEthernet1/0/48")

    with pytest.raises(RuntimeError, match=r"Interface GigabitEthernet1/0/48 on switch 192\.168\.2\.1 is an endpoint of fabric link LINK-UUID-1"):
        orchestrator.preflight([model])


def test_ethernet_trunk_host_orchestrator_00820() -> None:
    """
    # Summary

    Verify `preflight_delete` refuses an explicitly named IOS-XE fabric-link endpoint, so a `--check` `state: deleted` run fails like
    a normal run's `delete_bulk` would. The XE reset PUT would otherwise rewrite the endpoint's record underneath the link.

    ## Test

    - interfaceList reports GigabitEthernet1/0/48 as a defaults-only `iosXeRoutedHost` (not a port-channel member)
    - The links GET lists GigabitEthernet1/0/48 as the src endpoint of a link carrying a link policy
    - `preflight_delete` raises `RuntimeError` naming the link

    ## Classes and Methods

    - EthernetBaseOrchestrator.preflight_delete()
    - EthernetBaseOrchestrator._check_xe_fabric_link()
    """

    def responses():
        yield responses_trunk_host("test_xe_ownership_preflight_delete_00820a")
        yield responses_trunk_host("test_xe_ownership_preflight_delete_00820b")
        yield responses_trunk_host("test_xe_ownership_preflight_delete_00820c")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()), params={"state": "deleted", "check_mode": True})
    model = _build_xe_trunk_model({"allowed_vlans": "10"}, interface_name="GigabitEthernet1/0/48")

    with pytest.raises(RuntimeError, match=r"Interface GigabitEthernet1/0/48 on switch 192\.168\.2\.1 is an endpoint of fabric link LINK-UUID-1"):
        orchestrator.preflight_delete([model])


def test_ethernet_trunk_host_orchestrator_00830() -> None:
    """
    # Summary

    Verify `delete_bulk` under `state: deleted` refuses an IOS-XE fabric-link endpoint before queueing anything: neither the XE reset
    nor its deploy is queued, so `remove_pending` / `deploy_pending` have nothing to ship for it.

    ## Test

    - The links GET lists GigabitEthernet1/0/48 as the src endpoint of a link carrying a link policy
    - `delete_bulk` raises `RuntimeError` naming the link
    - The XE reset queue and the deploy queue are both empty

    ## Classes and Methods

    - EthernetBaseOrchestrator.delete_bulk()
    - EthernetBaseOrchestrator._check_xe_fabric_link()
    """

    def responses():
        yield responses_trunk_host("test_xe_ownership_delete_bulk_00830a")
        yield responses_trunk_host("test_xe_ownership_delete_bulk_00830b")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()), params={"state": "deleted"})
    model = _build_xe_trunk_model({"allowed_vlans": "10"}, interface_name="GigabitEthernet1/0/48")

    with pytest.raises(RuntimeError, match=r"GigabitEthernet1/0/48 on switch 192\.168\.2\.1 is an endpoint of fabric link LINK-UUID-1"):
        orchestrator.delete_bulk([model], existing_data={"interfaceName": "probe", "operData": {"portChannelId": -1}})
    assert orchestrator._pending_xe_resets == []
    assert orchestrator._pending_deploys == []


def test_ethernet_trunk_host_orchestrator_00840() -> None:
    """
    # Summary

    Verify a bulk batch is refused as a whole when any IOS-XE item is a fabric-link endpoint: every guard runs before the first POST,
    so a discovered-only neighbor (policy-less link, allowed) in the same batch is not written either, and the links are fetched once.

    ## Test

    - Two IOS-XE models on the same switch: GigabitEthernet1/0/47 (policy-less link, allowed) and GigabitEthernet1/0/48 (fabric link)
    - `create_bulk` raises `RuntimeError` naming GigabitEthernet1/0/48's link
    - Exactly two responses were consumed (switch map + one links GET): no POST was sent; nothing is queued for deploy

    ## Classes and Methods

    - EthernetBaseOrchestrator.create_bulk()
    - EthernetBaseOrchestrator._group_by_switch_and_policy_type()
    - EthernetBaseOrchestrator._check_xe_fabric_link()
    """

    def responses():
        yield responses_trunk_host("test_xe_ownership_bulk_00840a")
        yield responses_trunk_host("test_xe_ownership_bulk_00840b")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()), params={"state": "merged"})
    allowed = _build_xe_trunk_model({"allowed_vlans": "10"}, interface_name="GigabitEthernet1/0/47")
    owned = _build_xe_trunk_model({"allowed_vlans": "10"}, interface_name="GigabitEthernet1/0/48")

    with pytest.raises(RuntimeError, match=r"GigabitEthernet1/0/48 on switch 192\.168\.2\.1 is an endpoint of fabric link LINK-UUID-1"):
        orchestrator.create_bulk([allowed, owned], existing_data=_xe_routed_wire("GigabitEthernet1/0/48"))
    assert orchestrator._pending_deploys == []
    assert len(orchestrator.rest_send.responses) == 2
    assert set(orchestrator._fabric_link_endpoints()) == {("FDO22222BBB", "gigabitethernet1/0/48"), ("FDO33333CCC", "gigabitethernet1/0/1")}


# =============================================================================
# Test: platform / network_os_type preflight (PR #558 review)
# =============================================================================


def test_ethernet_trunk_host_orchestrator_00900() -> None:
    """
    # Summary

    Verify `preflight` refuses an IOS-XE (`iosXeTrunkHost`) target whose switch reports `platformType` `nx-os`, so a `--check` run
    fails with the same module-level error a normal run raises instead of reporting the change as viable (PR #558 review). The check
    runs off the switch inventory already fetched for `switch_ip` resolution: no interfaceList or links GET is issued.

    ## Test

    - Switches GET reports 192.168.2.1 as `nx-os`
    - `preflight` (check mode) raises `RuntimeError` naming the switch, the reported platform, and the requested OS
    - Exactly one response (the switch-inventory GET) was issued

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.preflight()
    - NDBaseInterfaceOrchestrator._check_platform_match()
    """

    def responses():
        yield responses_trunk_host("test_platform_mismatch_00900a")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()), params={"state": "merged", "check_mode": True})
    model = _build_xe_trunk_model({"allowed_vlans": "10"})

    with pytest.raises(
        RuntimeError,
        match=r"Switch 192\.168\.2\.1 reports platformType 'nx-os', but the requested network_os_type is 'ios-xe' \(GigabitEthernet1/0/1\)\. No changes were made\.",
    ):
        orchestrator.preflight([model])
    assert len(orchestrator.rest_send.responses) == 1


def test_ethernet_trunk_host_orchestrator_00910() -> None:
    """
    # Summary

    Verify the platform check refuses the opposite direction too: an NX-OS (`trunkHost`) target whose switch reports `platformType`
    `ios-xe`.

    ## Test

    - Switches GET reports 192.168.1.1 as `ios-xe`
    - `preflight` raises `RuntimeError` naming the switch, `ios-xe`, and the requested `nx-os`
    - Exactly one response (the switch-inventory GET) was issued

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.preflight()
    - NDBaseInterfaceOrchestrator._check_platform_match()
    """

    def responses():
        yield responses_trunk_host("test_platform_mismatch_00910a")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()), params={"state": "merged"})
    model = EthernetTrunkHostInterfaceModel(
        switch_ip="192.168.1.1", interface_name="Ethernet1/1", config_data={"network_os": {"policy": {"allowed_vlans": "10"}}}
    )
    assert model.config_data.network_os.network_os_type == "nx-os"

    with pytest.raises(
        RuntimeError, match=r"Switch 192\.168\.1\.1 reports platformType 'ios-xe', but the requested network_os_type is 'nx-os' \(Ethernet1/1\)"
    ):
        orchestrator.preflight([model])
    assert len(orchestrator.rest_send.responses) == 1


def test_ethernet_trunk_host_orchestrator_00920() -> None:
    """
    # Summary

    Verify the platform check adds no requests at scale: four IOS-XE targets across two switches reuse the single switch-inventory
    GET issued for `switch_ip` resolution, and a switch that reports no recognizable `platformType` is skipped rather than refused.

    ## Test

    - Switches GET reports 192.168.2.1 as `ios-xe` and 192.168.2.2 with no `additionalData`
    - Two `iosXeTrunkHost` targets per switch
    - `preflight` does not raise
    - Responses: exactly one switch-inventory GET, one interfaceList GET per switch, one links GET (four total)

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator._check_platform_match()
    - EthernetBaseOrchestrator.preflight()
    """

    def responses():
        yield responses_trunk_host("test_platform_mismatch_00920a")
        yield responses_trunk_host("test_platform_mismatch_00920b")
        yield responses_trunk_host("test_platform_mismatch_00920c")
        yield responses_trunk_host("test_platform_mismatch_00920d")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()), params={"state": "merged"})
    models = [
        _build_xe_trunk_model({"allowed_vlans": "10"}, interface_name="GigabitEthernet1/0/1", switch_ip="192.168.2.1"),
        _build_xe_trunk_model({"allowed_vlans": "10"}, interface_name="GigabitEthernet1/0/2", switch_ip="192.168.2.1"),
        _build_xe_trunk_model({"allowed_vlans": "10"}, interface_name="GigabitEthernet1/0/1", switch_ip="192.168.2.2"),
        _build_xe_trunk_model({"allowed_vlans": "10"}, interface_name="GigabitEthernet1/0/2", switch_ip="192.168.2.2"),
    ]

    with does_not_raise():
        orchestrator.preflight(models)
    paths = [response.get("REQUEST_PATH", "") for response in orchestrator.rest_send.responses]
    assert len(paths) == 4
    assert sum(1 for path in paths if path.endswith("/switches")) == 1
