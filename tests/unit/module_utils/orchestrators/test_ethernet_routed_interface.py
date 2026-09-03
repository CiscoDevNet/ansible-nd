# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ethernet_routed_interface orchestrator (issue #447).

Verifies that `EthernetRoutedInterfaceOrchestrator` correctly:
- declares the right `model_class` and `_managed_policy_types`
- opts OUT of the `capableSwitches` capability preflight (the endpoint returns an empty set for every
  ethernet mode on a VXLAN fabric even though writes succeed; vault: capable-switches-empty-for-ethernet-on-vxlan)
- filters `query_all` to the managed policy types only, excluding system routed policy types
  (`numbered`, `multiSiteLinkMember`, `vrfLiteLinkMember`, `csrMultisiteIfcMember`) whose intent
  `state: overridden` must never touch (underlay safety)

Uses the file-based `Sender` from `tests/unit/module_utils/sender_file.py` as the
`sender` dependency injected into a real `RestSend`. Responses are read from
`tests/unit/module_utils/fixtures/fixture_data/test_ethernet_routed_interface.json`.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_routed_interface import (
    EthernetRoutedConfigDataModel,
    EthernetRoutedInterfaceModel,
    NexusEthernetRoutedNetworkOSModel,
    NexusEthernetRoutedPolicyModel,
    XeEthernetRoutedPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_routed_interface import (
    EthernetRoutedInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_ethernet_routed(key: str):
    """Load fixture data for the orchestrator's test_ethernet_routed_interface.json file."""
    return load_fixture("test_ethernet_routed_interface")[key]


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


def _build_orchestrator(gen_responses: ResponseGenerator, fabric_name: str = "fabric_1", params: dict | None = None) -> EthernetRoutedInterfaceOrchestrator:
    """Construct an orchestrator with the file-based RestSend injected."""
    rest_send = _build_rest_send(gen_responses, fabric_name=fabric_name, params=params)
    return EthernetRoutedInterfaceOrchestrator(rest_send=rest_send)


# =============================================================================
# Test: ClassVar / model_class
# =============================================================================


def test_ethernet_routed_orchestrator_00010() -> None:
    """
    # Summary

    Verify `model_class` points to `EthernetRoutedInterfaceModel`.

    ## Test

    - model_class is EthernetRoutedInterfaceModel

    ## Classes and Methods

    - EthernetRoutedInterfaceOrchestrator.model_class
    """
    assert EthernetRoutedInterfaceOrchestrator.model_class is EthernetRoutedInterfaceModel


def test_ethernet_routed_orchestrator_00020() -> None:
    """
    # Summary

    Verify bulk-support flags inherited from `EthernetBaseOrchestrator`.

    ## Test

    - supports_bulk_create is True
    - supports_bulk_delete is True

    ## Classes and Methods

    - EthernetRoutedInterfaceOrchestrator
    """
    assert EthernetRoutedInterfaceOrchestrator.supports_bulk_create is True
    assert EthernetRoutedInterfaceOrchestrator.supports_bulk_delete is True


def test_ethernet_routed_orchestrator_00030() -> None:
    """
    # Summary

    Verify the orchestrator opts OUT of the `capableSwitches` capability preflight: the endpoint returns an empty
    `switches[]` for every ethernet mode on a VXLAN fabric (lab-verified 2026-07-27) even though the write paths
    succeed, so adopting it would veto every switch. `validate_switches_capable` must no-op without any API call.

    ## Test

    - `interface_type` and `interface_mode` ClassVars are both "" (the opt-out signal)
    - `validate_switches_capable` returns without consuming any response from an EMPTY response generator
      (any API attempt would raise)

    ## Classes and Methods

    - EthernetRoutedInterfaceOrchestrator.interface_type
    - EthernetRoutedInterfaceOrchestrator.interface_mode
    - NDBaseInterfaceOrchestrator.validate_switches_capable()
    """
    assert EthernetRoutedInterfaceOrchestrator.interface_type == ""
    assert EthernetRoutedInterfaceOrchestrator.interface_mode == ""

    def responses():
        yield from ()

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    model = EthernetRoutedInterfaceModel(switch_ip="192.168.1.1", interface_name="Ethernet1/7")
    with does_not_raise():
        orchestrator.validate_switches_capable([model])


# =============================================================================
# Test: _managed_policy_types
# =============================================================================


def test_ethernet_routed_orchestrator_00100() -> None:
    """
    # Summary

    Verify `_managed_policy_types` returns exactly the union of the NX-OS and IOS-XE managed routed policy types.

    ## Test

    - Returned set is exactly {"routedHost", "iosXeRoutedHost"}

    ## Classes and Methods

    - EthernetRoutedInterfaceOrchestrator._managed_policy_types()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    assert orchestrator._managed_policy_types() == {"routedHost", "iosXeRoutedHost"}


# =============================================================================
# Test: _is_unconfigured_default (static)
# =============================================================================


NX_DEFAULTS_ONLY_POLICY = {
    "policyType": "routedHost",
    "adminState": True,
    "fec": "auto",
    "ipRedirects": False,
    "mtu": 9216,
    "netflow": False,
    "pfc": False,
    "pimDrPriority": 1,
    "pimSparse": False,
    "ptp": False,
    "qos": False,
    "speed": "auto",
}


@pytest.mark.parametrize(
    "policy_overrides,expected",
    [
        ({}, True),
        ({"policyType": "iosXeRoutedHost", "mtu": 1500}, True),
        ({"ip": "10.99.31.1"}, False),
        ({"prefix": 30}, False),
        ({"description": "routed uplink"}, False),
        ({"routingTag": "54321"}, False),
        ({"vrfInterface": "blue"}, False),
        ({"extraConfig": "no ip redirects"}, False),
        ({"adminState": False}, False),
        ({"mtu": 1500}, False),
        ({"speed": "100Gb"}, False),
        ({"pimSparse": True}, False),
        ({"pimDrPriority": 100}, False),
        ({"netflow": True}, False),
        ({"qos": True}, False),
        ({"fec": "off"}, False),
        ({"ipRedirects": True}, False),
    ],
    ids=[
        "nx_defaults_only",
        "xe_defaults_only",
        "ip_set",
        "prefix_set",
        "description_set",
        "routing_tag_set",
        "vrf_set",
        "extra_config_set",
        "admin_down",
        "mtu_nondefault",
        "speed_nondefault",
        "pim_sparse_on",
        "pim_dr_priority_set",
        "netflow_on",
        "qos_on",
        "fec_nondefault",
        "ip_redirects_on",
    ],
)
def test_ethernet_routed_orchestrator_00200(policy_overrides, expected) -> None:
    """
    # Summary

    Exercise the truth table for `_is_unconfigured_default`. On switches whose fabric default interface policy is
    routed (lab-verified 2026-07-27: EVERY unused port on a borderGateway defaults to a defaults-only `routedHost`;
    core-router IOS-XE ports default to `iosXeRoutedHost`), this predicate is the only thing keeping those ports out
    of `before[]` - without it, `state: overridden` would normalize every unused port on the switch. Treat any
    loosening as review-blocking. The ND-injected `ptp` key counts as default; the XE variant's `mtu` default is
    1500 (per-policy-type defaults).

    ## Test

    - Matrix over the NX defaults-only signature with single-field overrides
    - Defaults-only (NX and XE) -> True; any configured field or non-default value -> False

    ## Classes and Methods

    - EthernetRoutedInterfaceOrchestrator._is_unconfigured_default()
    """
    policy = dict(NX_DEFAULTS_ONLY_POLICY)
    if policy_overrides.get("policyType") == "iosXeRoutedHost":
        policy = {"policyType": "iosXeRoutedHost", "adminState": True, "speed": "auto"}
    policy.update(policy_overrides)
    iface = {"configData": {"mode": "routed", "networkOS": {"policy": policy}}}
    assert EthernetRoutedInterfaceOrchestrator._is_unconfigured_default(iface) is expected


# =============================================================================
# Test: delete_bulk — IOS-XE interfaces are merge-only under state:overridden
# =============================================================================


def _nx_model(interface_name: str = "Ethernet1/31") -> EthernetRoutedInterfaceModel:
    """Build a configured NX-OS routed model as it would come from before[]."""
    return EthernetRoutedInterfaceModel.from_response(
        {
            "switchIp": "192.168.1.1",
            "interfaceName": interface_name,
            "interfaceType": "ethernet",
            "configData": {
                "mode": "routed",
                "networkOS": {"networkOSType": "nx-os", "policy": {"policyType": "routedHost", "ip": "10.99.31.1", "prefix": 30}},
            },
        }
    )


def _xe_model(interface_name: str = "GigabitEthernet2") -> EthernetRoutedInterfaceModel:
    """Build a configured IOS-XE routed model as it would come from before[]."""
    return EthernetRoutedInterfaceModel.from_response(
        {
            "switchIp": "192.168.1.2",
            "interfaceName": interface_name,
            "interfaceType": "ethernet",
            "configData": {
                "mode": "routed",
                "networkOS": {"networkOSType": "ios-xe", "policy": {"policyType": "iosXeRoutedHost", "ip": "10.10.1.1", "prefix": 30}},
            },
        }
    )


def test_ethernet_routed_orchestrator_00300() -> None:
    """
    # Summary

    Verify `state: overridden` never queues an IOS-XE interface for reset (XE merge-only). IOS-XE fabric links can carry
    plain configured `iosXeRoutedHost` with no intent-side ownership marker (lab-verified 2026-07-27: WAN1's multisite
    link GigabitEthernet2), so a fabric-wide overridden delete set computed from policy-type scope would strip real
    fabric links. Treat any loosening as review-blocking.

    ## Test

    - state is `overridden`; delete_bulk receives one NX-OS model and one IOS-XE model
    - Only the NX-OS interface is queued for normalize; the IOS-XE interface is skipped

    ## Classes and Methods

    - EthernetRoutedInterfaceOrchestrator.delete_bulk()
    """

    def responses():
        yield responses_ethernet_routed("test_delete_bulk_00300a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses, params={"state": "overridden"})
    with does_not_raise():
        orchestrator.delete_bulk([_nx_model(), _xe_model()], existing_data={"interfaceName": "probe"})
    assert ("Ethernet1/31", "FDO11111AAA") in orchestrator._pending_normalizes
    assert all("GigabitEthernet2" not in pair for pair in orchestrator._pending_normalizes)


def test_ethernet_routed_orchestrator_00310() -> None:
    """
    # Summary

    Verify an explicitly named IOS-XE interface under `state: deleted` IS queued for reset — via the XE reset queue,
    never the normalize queue: `interfaceActions/normalize` is structurally unusable for IOS-XE (its body requires
    `mtu`, which C8000V rejects per-port; vault: c8000v-rejects-per-port-mtu). NX-OS interfaces keep the family
    normalize path. The merge-only skip applies only to the fabric-wide `overridden` delete set, not to interfaces
    the user asked for by name.

    ## Test

    - state is `deleted`; delete_bulk receives one NX-OS model and one IOS-XE model
    - The NX-OS interface is queued for normalize; the IOS-XE interface is queued for XE reset (and NOT normalize)
    - Both are queued for deploy

    ## Classes and Methods

    - EthernetRoutedInterfaceOrchestrator.delete_bulk()
    """

    def responses():
        yield responses_ethernet_routed("test_delete_bulk_00310a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses, params={"state": "deleted"})
    with does_not_raise():
        orchestrator.delete_bulk([_nx_model(), _xe_model()], existing_data={"interfaceName": "probe"})
    assert ("Ethernet1/31", "FDO11111AAA") in orchestrator._pending_normalizes
    assert ("GigabitEthernet2", "FDO22222BBB") in orchestrator._pending_xe_resets
    assert all("GigabitEthernet2" not in pair for pair in orchestrator._pending_normalizes)
    assert ("GigabitEthernet2", "FDO22222BBB") in orchestrator._pending_deploys


def test_ethernet_routed_orchestrator_00315() -> None:
    """
    # Summary

    Verify the XE reset payload is the lab-verified C8000V-safe body: a defaults-only `iosXeRoutedHost` policy with NO
    `mtu` key anywhere (probe 2026-07-27: the mtu-less PUT returns 204 and ND injects the schema defaults, landing the
    interface on the unconfigured-default signature so it leaves managed scope).

    ## Test

    - Payload carries interfaceName/interfaceType/switchId and mode "routed" / networkOSType "ios-xe"
    - Policy is exactly {policyType: iosXeRoutedHost, adminState: true}
    - No "mtu" key appears anywhere in the payload

    ## Classes and Methods

    - EthernetRoutedInterfaceOrchestrator._xe_reset_payload()
    """
    payload = EthernetRoutedInterfaceOrchestrator._xe_reset_payload("GigabitEthernet2", "FDO22222BBB")
    assert payload["interfaceName"] == "GigabitEthernet2"
    assert payload["interfaceType"] == "ethernet"
    assert payload["switchId"] == "FDO22222BBB"
    assert payload["configData"]["mode"] == "routed"
    assert payload["configData"]["networkOS"]["networkOSType"] == "ios-xe"
    assert payload["configData"]["networkOS"]["policy"] == {"policyType": "iosXeRoutedHost", "adminState": True}
    assert "mtu" not in str(payload)


def test_ethernet_routed_orchestrator_00320() -> None:
    """
    # Summary

    Verify `remove_pending` flushes the XE reset queue via per-interface PUT and empties it. The single fixture
    response covers the one PUT; any additional request would exhaust the generator and fail.

    ## Test

    - state is `deleted`; delete_bulk queues one IOS-XE interface
    - `remove_pending` consumes exactly one PUT response and clears the XE reset queue

    ## Classes and Methods

    - EthernetRoutedInterfaceOrchestrator.remove_pending()
    """

    def responses():
        yield responses_ethernet_routed("test_remove_pending_00320a")
        yield responses_ethernet_routed("test_remove_pending_00320b")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses, params={"state": "deleted"})
    with does_not_raise():
        orchestrator.delete_bulk([_xe_model()], existing_data={"interfaceName": "probe"})
        orchestrator.remove_pending()
    assert orchestrator._pending_xe_resets == []


# =============================================================================
# Test: query_all — managed-set filter is the underlay-safety boundary
# =============================================================================


def test_ethernet_routed_orchestrator_00400() -> None:
    """
    # Summary

    Verify `query_all` keeps ONLY managed routed policy types and excludes system routed policy types. This is the
    underlay-safety boundary: `numbered` (fabric links), `multiSiteLinkMember`, `vrfLiteLinkMember`, and
    `csrMultisiteIfcMember` all carry `configData.mode: "routed"` on the wire, so filtering by mode alone would put
    fabric underlay intent in `before[]` and let `state: overridden` bulldoze it. Treat any loosening of this filter
    as review-blocking.

    ## Test

    - state is `merged`; config references both switches in the fabric
    - Switch 1 (NX-OS) returns: managed routedHost, trunkHost (other module), numbered, multiSiteLinkMember,
      vrfLiteLinkMember (all three system types with mode "routed")
    - Switch 2 (IOS-XE) returns: managed iosXeRoutedHost, csrMultisiteIfcMember (mode "routed"), and a loopback
    - Result contains exactly the two managed interfaces, each with `switchIp` injected

    ## Classes and Methods

    - EthernetRoutedInterfaceOrchestrator.query_all()
    - EthernetBaseOrchestrator.query_all()
    """

    def responses():
        yield responses_ethernet_routed("test_query_all_routed_00400a")
        yield responses_ethernet_routed("test_query_all_routed_00400b")
        yield responses_ethernet_routed("test_query_all_routed_00400c")
        yield responses_ethernet_routed("test_query_all_routed_00400d")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(
            gen_responses,
            params={"state": "merged", "config": [{"switch_ip": "192.168.1.1"}, {"switch_ip": "192.168.1.2"}]},
        )
        result = orchestrator.query_all()

    assert isinstance(result, list)
    kept = {(iface["interfaceName"], iface["configData"]["networkOS"]["policy"]["policyType"]) for iface in result}
    assert kept == {("Ethernet1/7", "routedHost"), ("GigabitEthernet3", "iosXeRoutedHost")}
    switch_ips = {iface["interfaceName"]: iface["switchIp"] for iface in result}
    assert switch_ips == {"Ethernet1/7": "192.168.1.1", "GigabitEthernet3": "192.168.1.2"}


def test_ethernet_routed_orchestrator_00410() -> None:
    """
    # Summary

    Verify `state: overridden` scope excludes IOS-XE interfaces that are NOT named in the task config (XE merge-only):
    they must be invisible to `before[]`, not merely skipped at delete time, so the module's changed/diff reporting
    stays truthful — a delete-time-only skip would report the interface as removed while leaving it untouched.
    A configured NX-OS interface stays in scope regardless, and a NAMED IOS-XE interface stays in scope (here the
    config names GigabitEthernet3 in abbreviated lowercase to prove config names are canonicalized before matching).

    ## Test

    - state is `overridden`; config names Ethernet1/7 (NX) and gi3 (XE, abbreviated)
    - The unnamed configured XE interface set (none in this fixture beyond GigabitEthernet3) plus the named one
      resolve correctly: GigabitEthernet3 is retained because it is named
    - Re-run with config naming ONLY Ethernet1/7: GigabitEthernet3 is excluded from the result

    ## Classes and Methods

    - EthernetRoutedInterfaceOrchestrator.query_all()
    """

    def responses():
        yield responses_ethernet_routed("test_query_all_overridden_00410a")
        yield responses_ethernet_routed("test_query_all_overridden_00410b")
        yield responses_ethernet_routed("test_query_all_overridden_00410c")
        yield responses_ethernet_routed("test_query_all_overridden_00410d")

    gen_responses = ResponseGenerator(responses())
    with does_not_raise():
        orchestrator = _build_orchestrator(
            gen_responses,
            params={
                "state": "overridden",
                "config": [
                    {"switch_ip": "192.168.1.1", "interface_name": "Ethernet1/7"},
                    {"switch_ip": "192.168.1.2", "interface_name": "gi3"},
                ],
            },
        )
        result = orchestrator.query_all()
    kept = {iface["interfaceName"] for iface in result}
    assert kept == {"Ethernet1/7", "GigabitEthernet3"}

    def responses_nx_only():
        yield responses_ethernet_routed("test_query_all_overridden_00410a")
        yield responses_ethernet_routed("test_query_all_overridden_00410b")
        yield responses_ethernet_routed("test_query_all_overridden_00410c")
        yield responses_ethernet_routed("test_query_all_overridden_00410d")

    gen_responses_nx_only = ResponseGenerator(responses_nx_only())
    with does_not_raise():
        orchestrator = _build_orchestrator(
            gen_responses_nx_only,
            params={"state": "overridden", "config": [{"switch_ip": "192.168.1.1", "interface_name": "Ethernet1/7"}]},
        )
        result = orchestrator.query_all()
    kept = {iface["interfaceName"] for iface in result}
    assert kept == {"Ethernet1/7"}


# =============================================================================
# Test: unconfigured-default signature is derived from the models' reverse_diff_defaults
# =============================================================================


@pytest.mark.parametrize(
    "policy_type,policy_cls,injected",
    [
        ("routedHost", NexusEthernetRoutedPolicyModel, {"ptp": False}),
        ("iosXeRoutedHost", XeEthernetRoutedPolicyModel, {}),
    ],
    ids=["routedHost", "iosXeRoutedHost"],
)
def test_ethernet_routed_orchestrator_00210(policy_type, policy_cls, injected) -> None:
    """
    # Summary

    The orchestrator's unconfigured-default signature for each managed policy type is the policy model's
    `reverse_diff_defaults` table plus the ND-injected read keys the model never declares (`ptp` on `routedHost`),
    so the query-scope filter and the replaced/overridden reverse pass can never drift apart.

    ## Test

    - `_unconfigured_default_signature(policy_type)` equals `policy_cls.reverse_diff_defaults` merged with the injected keys
    - The model table is non-empty (a missing table would silently collapse the signature to `ptp` alone)

    ## Classes and Methods

    - EthernetRoutedInterfaceOrchestrator._unconfigured_default_signature()
    - InterfacePolicyStrictBase.reverse_diff_defaults
    """
    assert policy_cls.reverse_diff_defaults
    expected = {**policy_cls.reverse_diff_defaults, **injected}
    assert EthernetRoutedInterfaceOrchestrator._unconfigured_default_signature(policy_type) == expected


# =============================================================================
# Test: query_all — a named defaults-only interface is retained (PR #550 review)
# =============================================================================


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
def test_ethernet_routed_orchestrator_00420(state) -> None:
    """
    # Summary

    Verify `query_all` retains a defaults-only routed interface when the task names it, under every create/update state, while
    still dropping unnamed defaults-only interfaces. Without this, an explicit "make Ethernet1/20 routed with all defaults"
    task never converges: the second run filters the (now defaults-only) interface out of `before[]`, classifies it as a
    create, and reports `changed: true` forever. The config names the interface in lowercase to prove canonicalization.

    ## Test

    - Switch FDO11111AAA returns Ethernet1/7 (configured routedHost), Ethernet1/20 and Ethernet1/21 (both defaults-only)
    - Config names `ethernet1/20` only
    - Result keeps Ethernet1/7 (configured) and Ethernet1/20 (named default); Ethernet1/21 (unnamed default) is dropped

    ## Classes and Methods

    - EthernetRoutedInterfaceOrchestrator.query_all()
    - EthernetRoutedInterfaceOrchestrator._named_interfaces()
    - EthernetRoutedInterfaceOrchestrator._is_unconfigured_default()
    """

    def responses():
        yield responses_ethernet_routed("test_query_all_named_default_00420a")
        yield responses_ethernet_routed("test_query_all_named_default_00420b")
        yield responses_ethernet_routed("test_query_all_named_default_00420c")

    gen_responses = ResponseGenerator(responses())
    with does_not_raise():
        orchestrator = _build_orchestrator(
            gen_responses,
            params={"state": state, "config": [{"switch_ip": "192.168.1.1", "interface_name": "ethernet1/20"}]},
        )
        result = orchestrator.query_all()
    kept = {iface["interfaceName"] for iface in result}
    assert kept == {"Ethernet1/7", "Ethernet1/20"}


# =============================================================================
# Test: port-channel member guard is state-aware under replaced/overridden (PR #550 review)
# =============================================================================


def _user_nx_model(policy_kwargs: dict, interface_name: str = "Ethernet1/7", switch_ip: str = "192.168.1.1") -> EthernetRoutedInterfaceModel:
    """Build a user-side NX-OS routed model whose policy carries exactly `policy_kwargs` (omitted fields stay None)."""
    return EthernetRoutedInterfaceModel(
        switch_ip=switch_ip,
        interface_name=interface_name,
        config_data=EthernetRoutedConfigDataModel(
            network_os=NexusEthernetRoutedNetworkOSModel(
                network_os_type="nx-os",
                policy=NexusEthernetRoutedPolicyModel(policy_type="routedHost", **policy_kwargs),
            ),
        ),
    )


def _pc_member_wire(policy: dict, interface_name: str = "Ethernet1/7", port_channel_id: int = 10) -> dict:
    """Build the wire-state dict of a routed port-channel member carrying `policy` (policyType added)."""
    return {
        "interfaceName": interface_name,
        "interfaceType": "ethernet",
        "operData": {"portChannelId": port_channel_id},
        "configData": {"mode": "routed", "networkOS": {"networkOSType": "nx-os", "policy": {"policyType": "routedHost", **policy}}},
    }


def test_ethernet_routed_orchestrator_00600() -> None:
    """
    # Summary

    Verify `update` under `state: replaced` refuses a description-only replacement of a port-channel member that carries
    `ip`, `prefix`, and a non-default `mtu`: the omitted fields are removals the PUT would apply, and none of them is in the
    member allowlist. Before the state-aware guard, the `None` proposed values were skipped and the PUT cleared them.

    ## Test

    - state is `replaced`; existing wire state is a member of port-channel 10 with ip/prefix/mtu 9000/description
    - Proposed model carries only a new description
    - `update` raises `RuntimeError` naming the port-channel and the removed fields ip, mtu, prefix; no PUT, no deploy

    ## Classes and Methods

    - EthernetBaseOrchestrator.update()
    - EthernetBaseOrchestrator._check_port_channel_restrictions()
    """

    def responses():
        yield responses_ethernet_routed("test_update_pc_member_replaced_00600a")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()), params={"state": "replaced"})
    existing = _pc_member_wire({"adminState": True, "description": "Old description", "ip": "10.10.10.1", "prefix": 30, "mtu": 9000})
    model = _user_nx_model({"description": "New description"})

    with pytest.raises(RuntimeError, match=r"Update failed for.*member of port-channel 10.*\['ip', 'mtu', 'prefix'\]"):
        orchestrator.update(model, existing_data=existing)
    assert orchestrator._pending_deploys == []


def test_ethernet_routed_orchestrator_00610() -> None:
    """
    # Summary

    Verify `update` under `state: replaced` allows a replacement of a port-channel member when every omitted field already sits
    at its template default (clearing a default is a no-op, mirroring the reverse-diff scrub in `get_diff`) and the carried
    fields are unchanged or whitelisted.

    ## Test

    - state is `replaced`; existing member carries ip/prefix, default mtu 9216, and an old description
    - Proposed model carries the same ip/prefix and a new description (mtu omitted)
    - `update` does not raise; the PUT is issued and a deploy is queued

    ## Classes and Methods

    - EthernetBaseOrchestrator.update()
    - EthernetBaseOrchestrator._check_port_channel_restrictions()
    """

    def responses():
        yield responses_ethernet_routed("test_update_pc_member_replaced_00610a")
        yield responses_ethernet_routed("test_update_pc_member_replaced_00610b")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()), params={"state": "replaced"})
    existing = _pc_member_wire({"adminState": True, "description": "Old description", "ip": "10.10.10.1", "prefix": 30, "mtu": 9216})
    model = _user_nx_model({"description": "New description", "ip": "10.10.10.1", "prefix": 30})

    with does_not_raise():
        orchestrator.update(model, existing_data=existing)
    assert orchestrator.rest_send.verb == HttpVerbEnum.PUT.value
    assert orchestrator._pending_deploys == [("Ethernet1/7", "FDO11111AAA")]


def test_ethernet_routed_orchestrator_00620() -> None:
    """
    # Summary

    Verify the removal-aware check does NOT apply under `state: merged`: an omitted field is not a removal there (the state
    machine merges it from existing state), so a description-only merge on a member carrying ip/prefix/mtu is allowed.

    ## Test

    - state is `merged`; existing member carries ip/prefix/mtu 9000
    - Proposed model carries only a new description
    - `update` does not raise; the PUT is issued and a deploy is queued

    ## Classes and Methods

    - EthernetBaseOrchestrator.update()
    - EthernetBaseOrchestrator._check_port_channel_restrictions()
    """

    def responses():
        yield responses_ethernet_routed("test_update_pc_member_merged_00620a")
        yield responses_ethernet_routed("test_update_pc_member_merged_00620b")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()), params={"state": "merged"})
    existing = _pc_member_wire({"adminState": True, "description": "Old description", "ip": "10.10.10.1", "prefix": 30, "mtu": 9000})
    model = _user_nx_model({"description": "New description"})

    with does_not_raise():
        orchestrator.update(model, existing_data=existing)
    assert orchestrator._pending_deploys == [("Ethernet1/7", "FDO11111AAA")]


# =============================================================================
# Test: preflight / preflight_delete validate in check mode too (PR #550 review)
# =============================================================================


def test_ethernet_routed_orchestrator_00700() -> None:
    """
    # Summary

    Verify `preflight` resolves every target switch even though this orchestrator opts out of the capability preflight, so a
    `--check` run fails on an unknown `switch_ip` exactly like a normal run would inside `create_bulk`.

    ## Test

    - Switch list contains only 192.168.1.1
    - `preflight` receives a model targeting 10.1.1.99
    - `RuntimeError` names the unresolvable IP; no capability GET is attempted (single fixture)

    ## Classes and Methods

    - EthernetBaseOrchestrator.preflight()
    - NDBaseInterfaceOrchestrator._require_resolvable_switches()
    """

    def responses():
        yield responses_ethernet_routed("test_preflight_00700a")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()), params={"state": "merged"})
    model = _user_nx_model({"ip": "10.10.10.1", "prefix": 30}, switch_ip="10.1.1.99")

    with pytest.raises(RuntimeError, match=r"Cannot resolve switch_ip to switchId in fabric 'fabric_1' for: 10\.1\.1\.99\."):
        orchestrator.preflight([model])


def test_ethernet_routed_orchestrator_00710() -> None:
    """
    # Summary

    Verify `preflight` runs the port-channel member guard, so a `--check` run rejects a prohibited change to a member instead
    of reporting a planned change that normal execution would refuse.

    ## Test

    - interfaceList reports Ethernet1/7 as a member of port-channel 10 with ip/prefix
    - Proposed model changes `mtu` (not whitelisted) under `merged`
    - `preflight` raises `RuntimeError` naming the port-channel and `mtu`

    ## Classes and Methods

    - EthernetBaseOrchestrator.preflight()
    - EthernetBaseOrchestrator._check_port_channel_restrictions()
    """

    def responses():
        yield responses_ethernet_routed("test_preflight_00710a")
        yield responses_ethernet_routed("test_preflight_00710b")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()), params={"state": "merged"})
    model = _user_nx_model({"mtu": 9000})

    with pytest.raises(RuntimeError, match=r"member of port-channel 10.*\['mtu'\]"):
        orchestrator.preflight([model])


def test_ethernet_routed_orchestrator_00720() -> None:
    """
    # Summary

    Verify `preflight_delete` refuses an explicitly named port-channel member, so a `--check` `state: deleted` run fails the
    same way the normal run's `delete_bulk` would.

    ## Test

    - interfaceList reports Ethernet1/7 as a member of port-channel 10
    - `preflight_delete` receives the existing model for Ethernet1/7
    - `RuntimeError` refuses to normalize the member

    ## Classes and Methods

    - EthernetBaseOrchestrator.preflight_delete()
    - EthernetBaseOrchestrator._check_port_channel_delete_restriction()
    """

    def responses():
        yield responses_ethernet_routed("test_preflight_delete_00720a")
        yield responses_ethernet_routed("test_preflight_delete_00720b")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()), params={"state": "deleted"})

    with pytest.raises(RuntimeError, match=r"member of port-channel 10. Refusing to normalize a port-channel member"):
        orchestrator.preflight_delete([_nx_model("Ethernet1/7")])


def test_ethernet_routed_orchestrator_00730() -> None:
    """
    # Summary

    Verify `preflight_delete` fails on an unresolvable `switch_ip` before touching any interface state.

    ## Test

    - Switch list contains only 192.168.1.1
    - `preflight_delete` receives a model targeting 10.1.1.99
    - `RuntimeError` names the unresolvable IP (single fixture: no interfaceList GET is attempted)

    ## Classes and Methods

    - EthernetBaseOrchestrator.preflight_delete()
    - NDBaseInterfaceOrchestrator._require_resolvable_switches()
    """

    def responses():
        yield responses_ethernet_routed("test_preflight_delete_00730a")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()), params={"state": "deleted"})
    model = _user_nx_model({}, switch_ip="10.1.1.99")

    with pytest.raises(RuntimeError, match=r"Cannot resolve switch_ip to switchId in fabric 'fabric_1' for: 10\.1\.1\.99\."):
        orchestrator.preflight_delete([model])


# =============================================================================
# Test: mixed 207 bulk response — accepted members are still deployed (PR #550 review)
# =============================================================================


def test_ethernet_routed_orchestrator_00800() -> None:
    """
    # Summary

    Verify a per-switch bulk create that fails with a mixed HTTP 207 still queues the exact-success member for deploy, and the
    failure-path finalizer then ships it. Without this, the accepted interface stays staged: a retry reads it as already
    matching, never re-queues it, and can succeed while the switch running state stays divergent.

    ## Test

    - One switch; Ethernet1/7 and Ethernet1/8 are non-member trunk ports on the wire
    - The bulk POST returns 207: Ethernet1/7 `success`, Ethernet1/8 `failed`
    - `create_bulk` raises `RuntimeError` naming the accepted subset; `_pending_deploys` holds only Ethernet1/7
    - `deploy_accepted_mutations` deploys exactly Ethernet1/7 and drains the queue

    ## Classes and Methods

    - EthernetBaseOrchestrator.create_bulk()
    - EthernetBaseOrchestrator._queue_accepted_bulk_items()
    - NDBaseInterfaceOrchestrator._accepted_multistatus_names()
    - NDBaseInterfaceOrchestrator.deploy_accepted_mutations()
    """

    def responses():
        yield responses_ethernet_routed("test_create_bulk_207_00800a")
        yield responses_ethernet_routed("test_create_bulk_207_00800b")
        yield responses_ethernet_routed("test_create_bulk_207_00800c")
        yield responses_ethernet_routed("test_create_bulk_207_00800d")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()), params={"state": "merged"})
    orchestrator.deploy = True
    models = [
        _user_nx_model({"ip": "10.10.7.1", "prefix": 30}, interface_name="Ethernet1/7"),
        _user_nx_model({"ip": "10.10.8.1", "prefix": 30}, interface_name="Ethernet1/8"),
    ]

    with pytest.raises(RuntimeError, match=r"Bulk create failed: .*The controller accepted \['Ethernet1/7'\] from the same request"):
        orchestrator.create_bulk(models)
    assert orchestrator._pending_deploys == [("Ethernet1/7", "FDO11111AAA")]

    with does_not_raise():
        deployed = orchestrator.deploy_accepted_mutations()
    assert deployed == [("Ethernet1/7", "FDO11111AAA")]
    assert orchestrator.rest_send.committed_payload == {"interfaces": [{"interfaceName": "Ethernet1/7", "switchId": "FDO11111AAA"}]}
    assert orchestrator._pending_deploys == []


def test_ethernet_routed_orchestrator_00430() -> None:
    """
    # Summary

    Verify the `state: deleted` scope for named defaults-only interfaces is per-OS: a named defaults-only NX-OS `routedHost` stays
    in scope (its reset target is the `trunkHost` template, a real mode flip), while a named defaults-only IOS-XE `iosXeRoutedHost`
    is dropped because the XE reset lands exactly on that signature — keeping it would re-reset it and report a change on every
    `deleted` run (found by the SITE1/ISN lab run of the XE delete-idempotency scenario).

    ## Test

    - state is `deleted`; config names Ethernet1/20 (NX, defaults-only) and GigabitEthernet4 (XE, defaults-only)
    - Switch 1 (NX) returns configured Ethernet1/7 and defaults-only Ethernet1/20; switch 2 (XE) returns configured
      GigabitEthernet3 and defaults-only GigabitEthernet4
    - Result keeps Ethernet1/7, Ethernet1/20 and GigabitEthernet3; GigabitEthernet4 is dropped

    ## Classes and Methods

    - EthernetRoutedInterfaceOrchestrator.query_all()
    - EthernetRoutedInterfaceOrchestrator._is_ios_xe()
    """

    def responses():
        yield responses_ethernet_routed("test_query_all_deleted_default_00430a")
        yield responses_ethernet_routed("test_query_all_deleted_default_00430b")
        yield responses_ethernet_routed("test_query_all_deleted_default_00430c")
        yield responses_ethernet_routed("test_query_all_deleted_default_00430d")

    gen_responses = ResponseGenerator(responses())
    with does_not_raise():
        orchestrator = _build_orchestrator(
            gen_responses,
            params={
                "state": "deleted",
                "config": [
                    {"switch_ip": "192.168.1.1", "interface_name": "Ethernet1/20"},
                    {"switch_ip": "192.168.1.2", "interface_name": "GigabitEthernet4"},
                ],
            },
        )
        result = orchestrator.query_all()
    kept = {iface["interfaceName"] for iface in result}
    assert kept == {"Ethernet1/7", "Ethernet1/20", "GigabitEthernet3"}
