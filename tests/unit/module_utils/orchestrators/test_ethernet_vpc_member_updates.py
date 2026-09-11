# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pair-aware regression tests for safe updates to authentic vPC members."""

# pylint: disable=protected-access

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from types import MethodType
from typing import Any

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
    NDStateMachineError,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
    NDStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_access_interface import (
    EthernetAccessInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_trunk_host_interface import (
    EthernetTrunkHostInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import (
    ResponseHandler,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import (
    MockAnsibleModule,
)

LOCAL_IP = "192.168.1.1"
PEER_IP = "192.168.1.2"
LOCAL_SERIAL = "FDO11111AAA"
PEER_SERIAL = "FDO22222BBB"
VPC_NAME = "vpc100"


@dataclass(frozen=True)
class _VpcCase:
    name: str
    orchestrator_class: type
    member_policy_type: str
    parent_policy_type: str
    mode: str
    unsafe_field: tuple[str, object]


VPC_CASES = (
    _VpcCase(
        name="trunk_vpc",
        orchestrator_class=EthernetTrunkHostInterfaceOrchestrator,
        member_policy_type="vpcMember",
        parent_policy_type="trunkVpcHost",
        mode="trunk",
        unsafe_field=("allowed_vlans", "200-300"),
    ),
    _VpcCase(
        name="access_vpc",
        orchestrator_class=EthernetAccessInterfaceOrchestrator,
        member_policy_type="accessVpcPoMember",
        parent_policy_type="accessVpcHost",
        mode="access",
        unsafe_field=("access_vlan", 200),
    ),
)


def _case_id(case: _VpcCase) -> str:
    return case.name


def _member(
    case: _VpcCase,
    switch_id: str,
    interface_name: str,
    port_channel_id: int,
) -> dict[str, Any]:
    return {
        "interfaceName": interface_name,
        "interfaceType": "ethernet",
        "switchId": switch_id,
        "configData": {
            "mode": case.mode,
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {
                    "policyType": case.member_policy_type,
                    "portChannelId": f"Port-channel{port_channel_id}",
                    "portChannelMode": "active",
                    "primaryInterface": VPC_NAME,
                    "adminState": True,
                    "description": "existing vPC member",
                    "extraConfig": "logging event link-status",
                    "cdp": False,
                    "debounceTimer": 250,
                    "debounceLinkupTimer": 2000,
                    "fec": "rsFec",
                    "lacpPortPriority": 4096,
                    "lacpRate": "fast",
                    "ptp": False,
                },
            },
        },
        "operData": {
            "portChannelId": port_channel_id,
            "interfaceStatus": "connected",
        },
    }


def _parent(
    case: _VpcCase,
    switch_id: str,
    peer_switch_id: str,
    local_members: list[str],
    peer_members: list[str],
    local_port_channel_id: int,
    peer_port_channel_id: int,
) -> dict[str, Any]:
    return {
        "interfaceName": VPC_NAME,
        "interfaceType": "vpc",
        "switchId": switch_id,
        "configData": {
            "mode": case.mode,
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {
                    "policyType": case.parent_policy_type,
                    "peerSwitchId": peer_switch_id,
                    "peer1PortChannelId": local_port_channel_id,
                    "peer2PortChannelId": peer_port_channel_id,
                    "peer1MemberPorts": local_members,
                    "peer2MemberPorts": peer_members,
                },
            },
        },
    }


def _parent_side_port_channel(case: _VpcCase, switch_id: str, port_channel_id: int) -> dict[str, Any]:
    policy_type = "accessVpcMember" if case.mode == "access" else "trunkVpcMember"
    return {
        "interfaceName": f"port-channel{port_channel_id}",
        "interfaceType": "portChannel",
        "switchId": switch_id,
        "configData": {
            "mode": case.mode,
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {
                    "policyType": policy_type,
                    "portChannelId": f"port-channel{port_channel_id}",
                    "primaryInterface": VPC_NAME,
                },
            },
        },
        "operData": {"portChannelId": -1},
    }


def _inventories(
    case: _VpcCase,
    *,
    local_names: tuple[str, ...] = ("Ethernet1/24",),
    peer_names: tuple[str, ...] = ("Ethernet1/25",),
) -> dict[str, list[dict[str, Any]]]:
    local_members = [_member(case, LOCAL_SERIAL, name, 20) for name in local_names]
    peer_members = [_member(case, PEER_SERIAL, name, 30) for name in peer_names]
    local_parent = _parent(
        case,
        LOCAL_SERIAL,
        PEER_SERIAL,
        list(local_names),
        list(peer_names),
        20,
        30,
    )
    peer_parent = _parent(
        case,
        PEER_SERIAL,
        LOCAL_SERIAL,
        list(local_names),
        list(peer_names),
        20,
        30,
    )
    return {
        LOCAL_SERIAL: [local_parent, _parent_side_port_channel(case, LOCAL_SERIAL, 20), *local_members],
        PEER_SERIAL: [peer_parent, _parent_side_port_channel(case, PEER_SERIAL, 30), *peer_members],
    }


@dataclass
class _Controller:
    inventories: dict[str, list[dict[str, Any]]]
    pair_records: dict[str, dict[str, Any]] = field(default_factory=dict)
    calls: list[dict[str, Any]] = field(default_factory=list)

    def request(
        self,
        _orchestrator,
        path: str,
        verb: HttpVerbEnum,
        data: dict[str, Any] | None = None,
        not_found_ok: bool = False,
        operation_type=None,
    ) -> dict[str, Any]:
        del not_found_ok, operation_type
        verb_value = verb.value if isinstance(verb, HttpVerbEnum) else str(verb)
        self.calls.append({"path": path, "verb": verb_value, "data": deepcopy(data)})
        if verb_value == HttpVerbEnum.GET.value:
            for switch_id, records in self.inventories.items():
                if path.endswith(f"/switches/{switch_id}/interfaces"):
                    return {"interfaces": deepcopy(records)}
            if path.endswith("/vpcPair"):
                for switch_id, record in self.pair_records.items():
                    if path.endswith(f"/switches/{switch_id}/vpcPair"):
                        return deepcopy(record)
                return {}
            if "/api/v1/manage/links" in path:
                return {"links": []}
        if verb_value == HttpVerbEnum.PUT.value and "/interfaces/Ethernet1%2F" in path:
            return {}
        raise AssertionError(f"Unexpected controller request: {verb_value} {path}; data={data}")


class _FabricContext:
    switch_map = {LOCAL_IP: LOCAL_SERIAL, PEER_IP: PEER_SERIAL}

    @staticmethod
    def validate_for_mutation() -> None:
        pass

    @staticmethod
    def get_switch_id(switch_ip: str) -> str:
        try:
            return _FabricContext.switch_map[switch_ip]
        except KeyError as exc:
            raise RuntimeError(f"Unknown switch {switch_ip!r}") from exc


def _state_machine(
    case: _VpcCase,
    *,
    state: str = "merged",
    requested_policy: dict[str, Any] | None = None,
    inventories: dict[str, list[dict[str, Any]]] | None = None,
    local_names: tuple[str, ...] = ("Ethernet1/24",),
    pair_records: dict[str, dict[str, Any]] | None = None,
) -> tuple[NDStateMachine, _Controller]:
    if state == "deleted":
        config = [{"switch_ip": LOCAL_IP, "interface_name": name} for name in local_names]
    else:
        config = [
            {
                "switch_ip": LOCAL_IP,
                "interface_name": name,
                "config_data": {"network_os": {"policy": requested_policy or {}}},
            }
            for name in local_names
        ]
    params = {
        "state": state,
        "config": config,
        "output_level": "normal",
        "ignore_errors": False,
        "fabric_name": "fabric_1",
        "config_actions": {"deploy": False},
    }
    orchestrator = case.orchestrator_class(rest_send=_rest_send(params))
    controller = _Controller(
        inventories or _inventories(case, local_names=local_names),
        pair_records=pair_records or {},
    )
    object.__setattr__(orchestrator, "_fabric_context", _FabricContext())
    object.__setattr__(orchestrator, "_request", MethodType(controller.request, orchestrator))
    module = MockAnsibleModule()
    module.params = params
    module.check_mode = False
    module.no_log_values = set()
    return NDStateMachine(module=module, model_orchestrator=orchestrator), controller


def _rest_send(params: dict[str, Any]) -> RestSend:
    rest_send = RestSend({**params, "check_mode": False})
    rest_send.response_handler = ResponseHandler()
    return rest_send


def _writes(controller: _Controller) -> list[dict[str, Any]]:
    return [call for call in controller.calls if call["verb"] != HttpVerbEnum.GET.value]


def _inventory_gets(controller: _Controller, switch_id: str) -> list[dict[str, Any]]:
    return [call for call in controller.calls if call["verb"] == HttpVerbEnum.GET.value and call["path"].endswith(f"/switches/{switch_id}/interfaces")]


def _pair_gets(controller: _Controller) -> list[dict[str, Any]]:
    return [call for call in controller.calls if call["verb"] == HttpVerbEnum.GET.value and call["path"].endswith("/vpcPair")]


@pytest.mark.parametrize("case", VPC_CASES, ids=_case_id)
def test_pair_aware_safe_merge_preserves_authentic_member_payload(
    case: _VpcCase,
) -> None:
    state_machine, controller = _state_machine(
        case,
        requested_policy={
            "admin_state": False,
            "description": "updated pair-aware member",
            "extra_config": "logging event trunk-status",
        },
    )

    state_machine.manage_state()

    assert len(_inventory_gets(controller, LOCAL_SERIAL)) == 1
    assert len(_inventory_gets(controller, PEER_SERIAL)) == 1
    assert _pair_gets(controller) == []
    writes = _writes(controller)
    assert len(writes) == 1
    assert writes[0]["verb"] == HttpVerbEnum.PUT.value
    assert writes[0]["path"].endswith("/interfaces/Ethernet1%2F24")
    payload = writes[0]["data"]
    policy = payload["configData"]["networkOS"]["policy"]
    assert payload["interfaceName"] == "Ethernet1/24"
    assert payload["interfaceType"] == "ethernet"
    assert payload["switchId"] == LOCAL_SERIAL
    assert payload["configData"]["mode"] == case.mode
    assert policy["policyType"] == case.member_policy_type
    assert policy["portChannelId"] == "Port-channel20"
    assert policy["portChannelMode"] == "active"
    assert policy["primaryInterface"] == VPC_NAME
    assert policy["adminState"] is False
    assert policy["description"] == "updated pair-aware member"
    assert policy["extraConfig"] == "logging event trunk-status"
    for key, value in {
        "cdp": False,
        "debounceTimer": 250,
        "debounceLinkupTimer": 2000,
        "fec": "rsFec",
        "lacpPortPriority": 4096,
        "lacpRate": "fast",
    }.items():
        assert policy[key] == value
    assert "ptp" not in policy
    assert "operData" not in payload
    assert not any(call["verb"] == HttpVerbEnum.POST.value for call in controller.calls)


@pytest.mark.parametrize("case", VPC_CASES, ids=_case_id)
def test_two_vpc_members_share_one_local_and_one_peer_inventory_get(
    case: _VpcCase,
) -> None:
    local_names = ("Ethernet1/24", "Ethernet1/26")
    peer_names = ("Ethernet1/25", "Ethernet1/27")
    state_machine, controller = _state_machine(
        case,
        requested_policy={"description": "same safe overlay"},
        inventories=_inventories(case, local_names=local_names, peer_names=peer_names),
        local_names=local_names,
    )

    state_machine.manage_state()

    assert len(_inventory_gets(controller, LOCAL_SERIAL)) == 1
    assert len(_inventory_gets(controller, PEER_SERIAL)) == 1
    writes = _writes(controller)
    assert len(writes) == 2
    assert {call["verb"] for call in writes} == {HttpVerbEnum.PUT.value}
    assert not any(call["verb"] == HttpVerbEnum.POST.value for call in controller.calls)


@pytest.mark.parametrize("case", VPC_CASES, ids=_case_id)
@pytest.mark.parametrize("peer_failure", ("missing", "inconsistent"))
def test_missing_or_inconsistent_peer_evidence_rejects_before_write(case: _VpcCase, peer_failure: str) -> None:
    inventories = _inventories(case)
    if peer_failure == "missing":
        inventories[PEER_SERIAL] = []
        error = r"(?i)peer.*does not contain.*parent"
    else:
        peer_parent = inventories[PEER_SERIAL][0]
        peer_parent["configData"]["networkOS"]["policy"]["peer2MemberPorts"] = ["Ethernet1/99"]
        error = r"(?i)inconsistent literal configured data"
    state_machine, controller = _state_machine(
        case,
        requested_policy={"description": "must not write"},
        inventories=inventories,
    )

    with pytest.raises(NDStateMachineError, match=error):
        state_machine.manage_state()

    assert len(_inventory_gets(controller, LOCAL_SERIAL)) == 1
    assert len(_inventory_gets(controller, PEER_SERIAL)) == 1
    assert _writes(controller) == []


@pytest.mark.parametrize("case", VPC_CASES, ids=_case_id)
@pytest.mark.parametrize("state", ("replaced", "overridden"))
def test_vpc_member_rejects_replacement_states_before_peer_fetch(case: _VpcCase, state: str) -> None:
    state_machine, controller = _state_machine(
        case,
        state=state,
        requested_policy={"description": "must not replace"},
    )

    with pytest.raises(NDStateMachineError, match=r"(?i)member.*merged"):
        state_machine.manage_state()

    assert len(_inventory_gets(controller, LOCAL_SERIAL)) == 1
    # overridden is intentionally fabric-wide and therefore discovers both peers
    # up front; replaced remains scoped to the explicitly named local switch.
    assert len(_inventory_gets(controller, PEER_SERIAL)) == (1 if state == "overridden" else 0)
    assert _writes(controller) == []


@pytest.mark.parametrize("case", VPC_CASES, ids=_case_id)
def test_explicit_vpc_member_delete_rejects_without_peer_fetch(
    case: _VpcCase,
) -> None:
    state_machine, controller = _state_machine(case, state="deleted")

    with pytest.raises(NDStateMachineError, match=r"(?i)member.*(normalize|parent)"):
        state_machine.manage_state()

    assert len(_inventory_gets(controller, LOCAL_SERIAL)) == 1
    assert len(_inventory_gets(controller, PEER_SERIAL)) == 0
    assert _writes(controller) == []


@pytest.mark.parametrize("case", VPC_CASES, ids=_case_id)
def test_unsafe_vpc_member_field_rejects_without_peer_fetch(case: _VpcCase) -> None:
    field_name, value = case.unsafe_field
    state_machine, controller = _state_machine(
        case,
        requested_policy={"description": "must be atomic", field_name: value},
    )

    with pytest.raises(NDStateMachineError, match=r"(?i)member.*only"):
        state_machine.manage_state()

    assert len(_inventory_gets(controller, LOCAL_SERIAL)) == 1
    assert len(_inventory_gets(controller, PEER_SERIAL)) == 0
    assert _writes(controller) == []


@pytest.mark.parametrize("case", VPC_CASES, ids=_case_id)
def test_missing_parent_peer_ids_use_one_cached_pair_and_peer_get(
    case: _VpcCase,
) -> None:
    inventories = _inventories(case)
    for records in inventories.values():
        parent = next(item for item in records if item["interfaceType"] == "vpc")
        parent["configData"]["networkOS"]["policy"].pop("peerSwitchId")
    state_machine, controller = _state_machine(
        case,
        requested_policy={"description": "resolved through pair evidence"},
        inventories=inventories,
        pair_records={
            LOCAL_SERIAL: {
                "switchId": LOCAL_SERIAL,
                "peerSwitchId": PEER_SERIAL,
            }
        },
    )

    state_machine.manage_state()

    assert len(_pair_gets(controller)) == 1
    assert len(_inventory_gets(controller, LOCAL_SERIAL)) == 1
    assert len(_inventory_gets(controller, PEER_SERIAL)) == 1
    assert [call["verb"] for call in _writes(controller)] == [HttpVerbEnum.PUT.value]


@pytest.mark.parametrize("case", VPC_CASES, ids=_case_id)
def test_two_members_with_missing_peer_ids_share_pair_and_inventory_gets(
    case: _VpcCase,
) -> None:
    local_names = ("Ethernet1/24", "Ethernet1/26")
    peer_names = ("Ethernet1/25", "Ethernet1/27")
    inventories = _inventories(case, local_names=local_names, peer_names=peer_names)
    for records in inventories.values():
        parent = next(item for item in records if item["interfaceType"] == "vpc")
        parent["configData"]["networkOS"]["policy"].pop("peerSwitchId")
    state_machine, controller = _state_machine(
        case,
        requested_policy={"description": "shared fallback"},
        inventories=inventories,
        local_names=local_names,
        pair_records={LOCAL_SERIAL: {"peerSwitchId": PEER_SERIAL}},
    )

    state_machine.manage_state()

    assert len(_pair_gets(controller)) == 1
    assert len(_inventory_gets(controller, LOCAL_SERIAL)) == 1
    assert len(_inventory_gets(controller, PEER_SERIAL)) == 1
    assert len(_writes(controller)) == 2


@pytest.mark.parametrize("case", VPC_CASES, ids=_case_id)
def test_missing_parent_peer_id_without_pair_evidence_fails_before_peer_get(
    case: _VpcCase,
) -> None:
    inventories = _inventories(case)
    local_parent = next(item for item in inventories[LOCAL_SERIAL] if item["interfaceType"] == "vpc")
    local_parent["configData"]["networkOS"]["policy"].pop("peerSwitchId")
    state_machine, controller = _state_machine(
        case,
        requested_policy={"description": "must not write"},
        inventories=inventories,
    )

    with pytest.raises(NDStateMachineError, match=r"(?i)vpcPair.*no pair evidence"):
        state_machine.manage_state()

    assert len(_pair_gets(controller)) == 1
    assert len(_inventory_gets(controller, LOCAL_SERIAL)) == 1
    assert len(_inventory_gets(controller, PEER_SERIAL)) == 0
    assert _writes(controller) == []
