# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for the routed (L3) port-channel interface orchestrator (issue #549).

`PortChannelRoutedInterfaceOrchestrator` inherits every CRUD, queue and preflight method from `PortChannelBaseOrchestrator`, whose
behaviour is covered by `test_port_channel_access_interface.py` and `test_port_channel_trunk_host_interface.py`. These tests cover
what the routed subclass adds: its managed policy types (the `query_all` ownership filter), the `iosXeL3PortChannel` row of the
IOS-XE member-mode preflight, and the routed wire shape through the inherited bulk create and delete paths.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name

from __future__ import annotations

import inspect

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_routed_interface import (
    PortChannelRoutedInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_routed_interface import (
    PortChannelRoutedInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

SWITCH_ID = "FDO11111AAA"


def responses_pc_routed(key: str):
    """Load fixture data for the orchestrator's test_port_channel_routed_interface.json file."""
    return load_fixture("test_port_channel_routed_interface")[key]


def _build_rest_send(gen_responses: ResponseGenerator, state: str | None = None, check_mode: bool = False) -> RestSend:
    """Build a RestSend wired to the file-based Sender and the real ResponseHandler. `state` populates `rest_send.params` for `query_all` scoping."""
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    params: dict = {"check_mode": check_mode, "fabric_name": "fabric_1"}
    if state is not None:
        params["state"] = state

    rest_send = RestSend(params)
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


def _build_nx_model(interface_name: str = "port-channel20", ports: list[str] | None = None, switch_ip: str = "192.168.1.1") -> PortChannelRoutedInterfaceModel:
    """Build an NX-OS `l3Po` model (members default to `["Ethernet1/10"]`)."""
    return PortChannelRoutedInterfaceModel.from_config(
        {
            "switch_ip": switch_ip,
            "interface_name": interface_name,
            "config_data": {
                "network_os": {
                    "network_os_type": "nx-os",
                    "policy": {"ip": "10.1.1.1", "prefix": 30, "ports": ports if ports is not None else ["Ethernet1/10"]},
                }
            },
        }
    )


def _build_xe_model(
    interface_name: str = "port-channel120", ports: list[str] | None = None, switch_ip: str = "192.168.1.1"
) -> PortChannelRoutedInterfaceModel:
    """Build an IOS-XE `iosXeL3PortChannel` model (members default to `["GigabitEthernet1/0/3"]`)."""
    return PortChannelRoutedInterfaceModel.from_config(
        {
            "switch_ip": switch_ip,
            "interface_name": interface_name,
            "config_data": {
                "network_os": {
                    "network_os_type": "ios-xe",
                    "policy": {"ip": "10.49.0.1", "prefix": 30, "ports": ports if ports is not None else ["GigabitEthernet1/0/3"]},
                }
            },
        }
    )


# =============================================================================
# Test: ClassVar / managed policy types
# =============================================================================


def test_port_channel_routed_orchestrator_00010() -> None:
    """
    # Summary

    Verify the orchestrator binds the routed model and manages exactly the NX-OS `l3Po` and IOS-XE `iosXeL3PortChannel` policy types.

    ## Test

    - `model_class is PortChannelRoutedInterfaceModel`
    - `_managed_policy_types() == {"l3Po", "iosXeL3PortChannel"}`
    - bulk create and bulk delete are inherited as supported

    ## Classes and Methods

    - PortChannelRoutedInterfaceOrchestrator._managed_policy_types()
    """
    instance = PortChannelRoutedInterfaceOrchestrator(rest_send=_build_rest_send(ResponseGenerator(iter(()))))
    assert instance.model_class is PortChannelRoutedInterfaceModel
    assert instance._managed_policy_types() == {"l3Po", "iosXeL3PortChannel"}
    assert instance.supports_bulk_create is True
    assert instance.supports_bulk_delete is True


# =============================================================================
# Test: query_all ownership filter
# =============================================================================


def test_port_channel_routed_orchestrator_00100() -> None:
    """
    # Summary

    Verify `query_all` returns only the routed port-channels this module owns, so `overridden` can never remove a system-provisioned
    routed port-channel (`l3PoInternal`, `mplsUplinkPo`), a `userDefined` one, or another module's access port-channel.

    ## Test

    - Responses: fabric summary, switches list, interfaces list
    - Result names are exactly `port-channel20` (`l3Po`) and `port-channel120` (`iosXeL3PortChannel`), each with `switchIp` injected
    - Every returned item parses through the model

    ## Classes and Methods

    - PortChannelRoutedInterfaceOrchestrator._managed_policy_types()
    - PortChannelBaseOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_routed(f"{method_name}a")
        yield responses_pc_routed(f"{method_name}b")
        yield responses_pc_routed(f"{method_name}c")

    # state=overridden keeps query_all fabric-wide.
    instance = PortChannelRoutedInterfaceOrchestrator(rest_send=_build_rest_send(ResponseGenerator(responses()), state="overridden"))
    with does_not_raise():
        result = instance.query_all()
        models = [PortChannelRoutedInterfaceModel.from_response(item) for item in result]
    assert {item["interfaceName"] for item in result} == {"port-channel20", "port-channel120"}
    assert {item["switchIp"] for item in result} == {"192.168.1.1"}
    assert {model.policy_type for model in models} == {"l3Po", "iosXeL3PortChannel"}


# =============================================================================
# Test: preflight -- IOS-XE member-mode rule for iosXeL3PortChannel
#
# Shared inventory (see the 00200b fixture TEST_NOTES): GigabitEthernet1/0/2 is the fabric-default iosXeTrunkHost,
# GigabitEthernet1/0/3 is a free iosXeRoutedHost, GigabitEthernet1/0/4 is an iosXeL3PoMember of Port-channel120,
# GigabitEthernet1/0/5 is an iosXeL3PoMember of Port-channel121. GigabitEthernet1/0/9 does not exist on the switch.
# =============================================================================


@pytest.mark.parametrize(
    "ports, match",
    [
        (["GigabitEthernet1/0/2"], r"member=GigabitEthernet1/0/2, current policy=iosXeTrunkHost, required=iosXeRoutedHost.*nd_interface_ethernet_routed"),
        (["GigabitEthernet1/0/9"], r"member=GigabitEthernet1/0/9, current policy=absent from the switch inventory"),
    ],
    ids=["trunk_host_member", "absent_member"],
)
def test_port_channel_routed_orchestrator_00200(ports, match) -> None:
    """
    # Summary

    Verify the IOS-XE member-mode preflight refuses an `iosXeL3PortChannel` whose member is still a trunk host (ND would reject the
    create: flat HTTP 500 on 4.2.1, 207 failed item on 4.3.1; lab-verified 2026-09-18) or is absent from the inventory, before any
    write and in check mode, naming the module that converts the member.

    # workaround: xe-port-channel-member-mode-mismatch

    ## Test

    - Responses: switches list, interfaces list for the switch
    - `preflight` raises `RuntimeError` matching `match`; no write was sent (`len(rest_send.responses) == 2`)

    ## Classes and Methods

    - PortChannelBaseOrchestrator.XE_MEMBER_HOST_POLICY
    - PortChannelBaseOrchestrator._validate_xe_member_modes()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_routed(f"{method_name}a")
        yield responses_pc_routed("test_port_channel_routed_orchestrator_capable_switches_shared")
        yield responses_pc_routed(f"{method_name}b")

    rest_send = _build_rest_send(ResponseGenerator(responses()), check_mode=True)
    instance = PortChannelRoutedInterfaceOrchestrator(rest_send=rest_send)
    with pytest.raises(RuntimeError, match=match):
        instance.preflight([_build_xe_model(ports=ports)])
    assert len(rest_send.responses) == 3


def test_port_channel_routed_orchestrator_00210() -> None:
    """
    # Summary

    Verify the preflight accepts a free `iosXeRoutedHost` member and an `iosXeL3PoMember` already owned by the same port-channel
    (idempotent re-apply), and skips NX-OS models, whose members ND re-homes itself.

    ## Test

    - `port-channel120` with members Gi1/0/3 (iosXeRoutedHost) and Gi1/0/4 (member of Port-channel120) passes
    - An NX-OS `l3Po` naming Ethernet1/10 (a trunkHost) passes without consulting member policy types

    ## Classes and Methods

    - PortChannelBaseOrchestrator._validate_xe_member_modes()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_routed(f"{method_name}a")
        yield responses_pc_routed("test_port_channel_routed_orchestrator_capable_switches_shared")
        yield responses_pc_routed(f"{method_name}b")

    instance = PortChannelRoutedInterfaceOrchestrator(rest_send=_build_rest_send(ResponseGenerator(responses())))
    with does_not_raise():
        instance.preflight([_build_xe_model(ports=["GigabitEthernet1/0/3", "GigabitEthernet1/0/4"]), _build_nx_model(ports=["Ethernet1/10"])])


def test_port_channel_routed_orchestrator_00220() -> None:
    """
    # Summary

    Verify a member owned by ANOTHER routed port-channel is reported by the member-availability preflight (its message names the
    current owner), so the mode preflight never masks the ownership conflict.

    ## Test

    - `port-channel120` naming Gi1/0/5 (member of port-channel121) raises `already in use ... current owner=port-channel121`

    ## Classes and Methods

    - PortChannelBaseOrchestrator._validate_members_available()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_routed(f"{method_name}a")
        yield responses_pc_routed("test_port_channel_routed_orchestrator_capable_switches_shared")
        yield responses_pc_routed(f"{method_name}b")

    instance = PortChannelRoutedInterfaceOrchestrator(rest_send=_build_rest_send(ResponseGenerator(responses())))
    with pytest.raises(RuntimeError, match=r"already in use.*current owner=port-channel121"):
        instance.preflight([_build_xe_model(ports=["GigabitEthernet1/0/5"])])


# =============================================================================
# Test: routed wire shape through the inherited bulk paths
# =============================================================================


def test_port_channel_routed_orchestrator_00300() -> None:
    """
    # Summary

    Verify a mixed-OS bulk create sends one homogeneous POST per `(switch, policyType)` group with the routed wire shape, the IOS-XE
    group under the canonical `Port-channel<N>` create name, and queues each accepted item for deploy under its lowercase identifier.

    ## Test

    - Responses: switches list, POST 207 (NX-OS group), POST 207 (IOS-XE group)
    - The last committed body is the IOS-XE group: `interfaceName == "Port-channel120"`, `mode == "routed"`, `policyType == "iosXeL3PortChannel"`
    - `_pending_deploys` holds both port-channels

    ## Classes and Methods

    - PortChannelBaseOrchestrator.create_bulk()
    - NDBaseInterfaceOrchestrator.bulk_create_groups()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_routed(f"{method_name}a")
        yield responses_pc_routed("test_port_channel_routed_orchestrator_capable_switches_shared")
        yield responses_pc_routed(f"{method_name}b")
        yield responses_pc_routed(f"{method_name}c")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = PortChannelRoutedInterfaceOrchestrator(rest_send=rest_send)
    with does_not_raise():
        instance.create_bulk([_build_nx_model(), _build_xe_model()])
    assert len(rest_send.responses) == 3
    body = rest_send.committed_payload
    assert [item["interfaceName"] for item in body["interfaces"]] == ["Port-channel120"]
    assert body["interfaces"][0]["switchId"] == SWITCH_ID
    assert body["interfaces"][0]["configData"]["mode"] == "routed"
    assert body["interfaces"][0]["configData"]["networkOS"]["policy"]["policyType"] == "iosXeL3PortChannel"
    assert instance._pending_deploys == [("port-channel20", SWITCH_ID), ("port-channel120", SWITCH_ID)]


def test_port_channel_routed_orchestrator_00310() -> None:
    """
    # Summary

    Verify the delete side queues an IOS-XE routed port-channel under its switch-canonical `Port-channel<N>` name in BOTH the remove
    and deploy queues (pair identity for the failure-path finalizer), and an NX-OS one under its lowercase name. No request is sent.

    # workaround: xe-port-channel-remove-leaves-switch-interface

    ## Test

    - Responses: switches list only
    - `_pending_removes == _pending_deploys == [("port-channel20", sw), ("Port-channel120", sw)]`

    ## Classes and Methods

    - PortChannelBaseOrchestrator.delete_bulk()
    - PortChannelBaseOrchestrator._delete_side_name()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_routed(f"{method_name}a")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = PortChannelRoutedInterfaceOrchestrator(rest_send=rest_send)
    with does_not_raise():
        instance.delete_bulk([_build_nx_model(), _build_xe_model()])
    expected = [("port-channel20", SWITCH_ID), ("Port-channel120", SWITCH_ID)]
    assert instance._pending_removes == expected
    assert instance._pending_deploys == expected
    assert len(rest_send.responses) == 1


# =============================================================================
# Test: capability preflight opt-in (PR #577 review)
# =============================================================================


def test_port_channel_routed_orchestrator_00390() -> None:
    """
    # Summary

    Verify the orchestrator opts in to the shared capability preflight as `portChannel` / `routed`.

    ## Test

    - `interface_type == "portChannel"` and `interface_mode == "routed"`

    ## Classes and Methods

    - PortChannelRoutedInterfaceOrchestrator.interface_type
    - PortChannelRoutedInterfaceOrchestrator.interface_mode
    """
    assert PortChannelRoutedInterfaceOrchestrator.interface_type == "portChannel"
    assert PortChannelRoutedInterfaceOrchestrator.interface_mode == "routed"


@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check_mode"])
def test_port_channel_routed_orchestrator_00400(check_mode: bool) -> None:
    """
    # Summary

    Verify `preflight` validates every target switch against the cached `capableSwitches` answer for `portChannel` / `routed`, at
    scale: four routed port-channels on two switches cost exactly one switches GET and one `capableSwitches` GET (then one
    interface-list GET per switch for the member checks), in normal and check mode.

    ## Test

    - Two NX-OS and two IOS-XE routed port-channels on two capable switches
    - `preflight` does not raise
    - The first two responses are the switches list and the `capableSwitches` GET; four in all

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.preflight()
    - NDBaseInterfaceOrchestrator.validate_switches_capable()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        for key in "abcd":
            yield responses_pc_routed(f"{method_name}{key}")

    rest_send = _build_rest_send(ResponseGenerator(responses()), check_mode=check_mode)
    instance = PortChannelRoutedInterfaceOrchestrator(rest_send=rest_send)
    models = [
        _build_nx_model(interface_name="port-channel20", ports=["Ethernet1/10"]),
        _build_nx_model(interface_name="port-channel21", ports=["Ethernet1/11"]),
        _build_xe_model(interface_name="port-channel120", ports=["GigabitEthernet1/0/3"], switch_ip="192.168.12.181"),
        _build_xe_model(interface_name="port-channel121", ports=["GigabitEthernet1/0/4"], switch_ip="192.168.12.181"),
    ]

    with does_not_raise():
        instance.preflight(models)

    paths = [response.get("REQUEST_PATH") for response in rest_send.responses]
    assert paths[:2] == ["/api/v1/manage/fabrics/fabric_1/switches", "/api/v1/manage/fabrics/fabric_1/capableSwitches?interfaceType=portChannel&mode=routed"]
    assert len(rest_send.responses) == 4


def test_port_channel_routed_orchestrator_00410() -> None:
    """
    # Summary

    Verify `preflight` refuses a routed port-channel on a switch the controller does not list as capable of `portChannel` / `routed`,
    outside check mode, naming the switch.

    ## Test

    - `capableSwitches` lists switch A only; the Catalyst is the target
    - `preflight` raises `RuntimeError` naming the Catalyst's switch id and the mode

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.preflight()
    - NDBaseInterfaceOrchestrator.validate_switches_capable()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_routed(f"{method_name}a")
        yield responses_pc_routed(f"{method_name}b")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = PortChannelRoutedInterfaceOrchestrator(rest_send=rest_send)
    model = _build_xe_model(interface_name="port-channel120", ports=["GigabitEthernet1/0/3"], switch_ip="192.168.12.181")

    with pytest.raises(RuntimeError, match=r"not capable of hosting interface_type='portChannel' mode='routed'.*CAT9KV1701"):
        instance.preflight([model])
