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
    EthernetRoutedInterfaceModel,
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

    Verify an explicitly named IOS-XE interface under `state: deleted` IS queued for reset — the merge-only skip applies
    only to the fabric-wide `overridden` delete set, not to interfaces the user asked for by name.

    ## Test

    - state is `deleted`; delete_bulk receives one NX-OS model and one IOS-XE model
    - Both interfaces are queued for normalize

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
    assert ("GigabitEthernet2", "FDO22222BBB") in orchestrator._pending_normalizes


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
