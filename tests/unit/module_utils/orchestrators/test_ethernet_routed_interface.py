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
