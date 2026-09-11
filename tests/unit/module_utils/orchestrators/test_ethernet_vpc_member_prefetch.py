# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Scale regressions for pair-aware Ethernet member inventory prefetch."""

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
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators import (
    ethernet_base,
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


@dataclass
class _Topology:
    switch_map: dict[str, str]
    inventories: dict[str, list[dict[str, Any]]]
    config: list[dict[str, Any]]
    local_serials: list[str]
    peer_serials: list[str]
    pair_records: dict[str, dict[str, Any]]


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
        if verb_value == HttpVerbEnum.PUT.value and "/interfaces/" in path:
            return {}
        raise AssertionError(f"Unexpected controller request: {verb_value} {path}; data={data}")


class _FabricContext:
    def __init__(self, switch_map: dict[str, str]) -> None:
        self.switch_map = switch_map

    @staticmethod
    def validate_for_mutation() -> None:
        pass

    def get_switch_id(self, switch_ip: str) -> str:
        try:
            return self.switch_map[switch_ip]
        except KeyError as exc:
            raise RuntimeError(f"Unknown switch {switch_ip!r}") from exc


def _member(
    switch_id: str,
    interface_name: str,
    parent_name: str,
    port_channel_id: int,
) -> dict[str, Any]:
    return {
        "interfaceName": interface_name,
        "interfaceType": "ethernet",
        "switchId": switch_id,
        "configData": {
            "mode": "trunk",
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {
                    "policyType": "vpcMember",
                    "portChannelId": f"Port-channel{port_channel_id}",
                    "portChannelMode": "active",
                    "primaryInterface": parent_name,
                    "adminState": True,
                    "description": "existing vPC member",
                    "extraConfig": "logging event link-status",
                },
            },
        },
        "operData": {
            "portChannelId": port_channel_id,
            "interfaceStatus": "connected",
        },
    }


def _parent(
    switch_id: str,
    peer_switch_id: object,
    parent_name: str,
    local_port_channel_id: int,
    peer_port_channel_id: int,
    local_members: list[str],
    peer_members: list[str],
) -> dict[str, Any]:
    return {
        "interfaceName": parent_name,
        "interfaceType": "vpc",
        "switchId": switch_id,
        "configData": {
            "mode": "trunk",
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {
                    "policyType": "trunkVpcHost",
                    "peerSwitchId": peer_switch_id,
                    "peer1PortChannelId": local_port_channel_id,
                    "peer2PortChannelId": peer_port_channel_id,
                    "peer1MemberPorts": local_members,
                    "peer2MemberPorts": peer_members,
                },
            },
        },
    }


def _topology(
    pair_count: int,
    *,
    members_per_pair: int = 1,
    parent_peer_value: str = "declared",
) -> _Topology:
    switch_map: dict[str, str] = {}
    inventories: dict[str, list[dict[str, Any]]] = {}
    config: list[dict[str, Any]] = []
    local_serials: list[str] = []
    peer_serials: list[str] = []
    pair_records: dict[str, dict[str, Any]] = {}

    for pair_index in range(pair_count):
        local_ip = f"192.0.2.{pair_index + 1}"
        peer_ip = f"198.51.100.{pair_index + 1}"
        local_serial = f"LOCAL-{pair_index:03d}"
        peer_serial = f"PEER-{pair_index:03d}"
        parent_name = f"vpc{pair_index + 100}"
        local_id = pair_index + 100
        peer_id = pair_index + 200
        name_offset = pair_index * members_per_pair
        local_names = [f"Ethernet1/{name_offset + member_index + 1}" for member_index in range(members_per_pair)]
        peer_names = [f"Ethernet1/{name_offset + member_index + 21}" for member_index in range(members_per_pair)]

        if parent_peer_value == "declared":
            local_parent_peer: object = peer_serial
            peer_parent_peer: object = local_serial
        elif parent_peer_value == "empty":
            local_parent_peer = ""
            peer_parent_peer = ""
        else:
            raise ValueError(f"Unsupported parent_peer_value {parent_peer_value!r}")

        local_parent = _parent(
            local_serial,
            local_parent_peer,
            parent_name,
            local_id,
            peer_id,
            local_names,
            peer_names,
        )
        peer_parent = _parent(
            peer_serial,
            peer_parent_peer,
            parent_name,
            local_id,
            peer_id,
            local_names,
            peer_names,
        )
        inventories[local_serial] = [
            local_parent,
            *[_member(local_serial, name, parent_name, local_id) for name in local_names],
        ]
        inventories[peer_serial] = [
            peer_parent,
            *[_member(peer_serial, name, parent_name, peer_id) for name in peer_names],
        ]
        switch_map[local_ip] = local_serial
        switch_map[peer_ip] = peer_serial
        config.extend(
            {
                "switch_ip": local_ip,
                "interface_name": name,
                "config_data": {
                    "network_os": {
                        "policy": {
                            "description": f"updated pair {pair_index}",
                        }
                    }
                },
            }
            for name in local_names
        )
        local_serials.append(local_serial)
        peer_serials.append(peer_serial)
        pair_records[local_serial] = {
            "switchId": local_serial,
            "peerSwitchId": peer_serial,
        }

    return _Topology(
        switch_map=switch_map,
        inventories=inventories,
        config=config,
        local_serials=local_serials,
        peer_serials=peer_serials,
        pair_records=pair_records,
    )


def _rest_send(params: dict[str, Any]) -> RestSend:
    rest_send = RestSend({**params, "check_mode": False})
    rest_send.response_handler = ResponseHandler()
    return rest_send


def _state_machine(
    topology: _Topology,
) -> tuple[NDStateMachine, _Controller]:
    params = {
        "state": "merged",
        "config": topology.config,
        "output_level": "normal",
        "ignore_errors": False,
        "fabric_name": "fabric_1",
        "config_actions": {"deploy": False},
    }
    orchestrator = EthernetTrunkHostInterfaceOrchestrator(rest_send=_rest_send(params))
    controller = _Controller(topology.inventories, topology.pair_records)
    object.__setattr__(orchestrator, "_fabric_context", _FabricContext(topology.switch_map))
    object.__setattr__(orchestrator, "_request", MethodType(controller.request, orchestrator))
    module = MockAnsibleModule()
    module.params = params
    module.check_mode = False
    module.no_log_values = set()
    return NDStateMachine(module=module, model_orchestrator=orchestrator), controller


def _inventory_gets(controller: _Controller) -> list[dict[str, Any]]:
    return [call for call in controller.calls if call["verb"] == HttpVerbEnum.GET.value and call["path"].endswith("/interfaces")]


def _pair_gets(controller: _Controller) -> list[dict[str, Any]]:
    return [call for call in controller.calls if call["verb"] == HttpVerbEnum.GET.value and call["path"].endswith("/vpcPair")]


def _writes(controller: _Controller) -> list[dict[str, Any]]:
    return [call for call in controller.calls if call["verb"] != HttpVerbEnum.GET.value]


def _install_counting_index(monkeypatch):
    real_index = ethernet_base.EthernetMembershipIndex

    class CountingMembershipIndex(real_index):
        builds = 0
        instances = []

        def __init__(self, *args, **kwargs) -> None:
            type(self).builds += 1
            super().__init__(*args, **kwargs)
            type(self).instances.append(self)

    monkeypatch.setattr(ethernet_base, "EthernetMembershipIndex", CountingMembershipIndex)
    return CountingMembershipIndex


def test_many_distinct_pairs_build_one_index_and_retain_it_across_puts(monkeypatch) -> None:
    topology = _topology(8)
    state_machine, controller = _state_machine(topology)
    counting_index = _install_counting_index(monkeypatch)

    state_machine.manage_state()

    assert counting_index.builds == 1
    assert len(_inventory_gets(controller)) == 16
    assert _pair_gets(controller) == []
    assert len(_writes(controller)) == 8
    assert state_machine.model_orchestrator._membership_index_cache is counting_index.instances[0]
    assert len(state_machine.model_orchestrator._validated_member_ownership) == 8


def test_direct_updates_rebuild_only_when_a_new_switch_inventory_is_loaded(monkeypatch) -> None:
    topology = _topology(2)
    params = {
        "state": "merged",
        "config": topology.config,
        "fabric_name": "fabric_1",
        "config_actions": {"deploy": False},
    }
    orchestrator = EthernetTrunkHostInterfaceOrchestrator(rest_send=_rest_send(params))
    controller = _Controller(topology.inventories, topology.pair_records)
    object.__setattr__(orchestrator, "_fabric_context", _FabricContext(topology.switch_map))
    object.__setattr__(orchestrator, "_request", MethodType(controller.request, orchestrator))
    counting_index = _install_counting_index(monkeypatch)
    models = [orchestrator.model_class.from_config(item, context={"state": "merged"}) for item in topology.config]

    orchestrator.update(models[0])
    first_index = orchestrator._membership_index_cache
    orchestrator.update(models[1])

    assert counting_index.builds == 2
    assert first_index is not orchestrator._membership_index_cache
    assert len(_inventory_gets(controller)) == 4
    assert _pair_gets(controller) == []
    assert len(_writes(controller)) == 2


def test_same_pair_members_share_empty_peer_fallback_inventory_and_index(monkeypatch) -> None:
    topology = _topology(1, members_per_pair=6, parent_peer_value="empty")
    state_machine, controller = _state_machine(topology)
    counting_index = _install_counting_index(monkeypatch)

    state_machine.manage_state()

    assert counting_index.builds == 1
    assert len(_inventory_gets(controller)) == 2
    assert len(_pair_gets(controller)) == 1
    assert len(_writes(controller)) == 6
    assert state_machine.model_orchestrator._membership_index_cache is counting_index.instances[0]


def test_pair_endpoint_is_used_only_for_parent_that_omits_peer(monkeypatch) -> None:
    topology = _topology(2)
    omitted_local = topology.local_serials[1]
    omitted_peer = topology.peer_serials[1]
    topology.inventories[omitted_local][0]["configData"]["networkOS"]["policy"]["peerSwitchId"] = ""
    topology.inventories[omitted_peer][0]["configData"]["networkOS"]["policy"]["peerSwitchId"] = ""
    counting_index = _install_counting_index(monkeypatch)
    state_machine, controller = _state_machine(topology)

    state_machine.manage_state()

    assert counting_index.builds == 1
    assert len(_pair_gets(controller)) == 1
    assert _pair_gets(controller)[0]["path"].endswith(f"/switches/{omitted_local}/vpcPair")
    assert len(_inventory_gets(controller)) == 4
    assert len(_writes(controller)) == 2


def test_conflicting_parent_pair_ids_fail_before_peer_get_index_or_write(monkeypatch) -> None:
    topology = _topology(2)
    shared_local = topology.local_serials[0]
    second_local = topology.local_serials[1]
    second_local_ip = next(switch_ip for switch_ip, switch_id in topology.switch_map.items() if switch_id == second_local)
    first_local_ip = next(switch_ip for switch_ip, switch_id in topology.switch_map.items() if switch_id == shared_local)
    second_records = topology.inventories.pop(second_local)
    for record in second_records:
        record["switchId"] = shared_local
    topology.inventories[shared_local].extend(second_records)
    topology.switch_map.pop(second_local_ip)
    for item in topology.config:
        if item["switch_ip"] == second_local_ip:
            item["switch_ip"] = first_local_ip
    counting_index = _install_counting_index(monkeypatch)
    state_machine, controller = _state_machine(topology)

    with pytest.raises(NDStateMachineError, match=r"(?i)conflicting vPC pair evidence"):
        state_machine.manage_state()

    assert counting_index.builds == 0
    assert len(_inventory_gets(controller)) == 1
    assert _pair_gets(controller) == []
    assert _writes(controller) == []


@pytest.mark.parametrize("invalid_peer", (42, "LOCAL-000"))
def test_invalid_parent_peer_id_fails_before_peer_get_index_or_write(
    invalid_peer: object,
    monkeypatch,
) -> None:
    topology = _topology(1)
    topology.inventories[topology.local_serials[0]][0]["configData"]["networkOS"]["policy"]["peerSwitchId"] = invalid_peer
    counting_index = _install_counting_index(monkeypatch)
    state_machine, controller = _state_machine(topology)

    with pytest.raises(NDStateMachineError, match=r"(?i)(valid peerSwitchId|points to itself)"):
        state_machine.manage_state()

    assert counting_index.builds == 0
    assert len(_inventory_gets(controller)) == 1
    assert _pair_gets(controller) == []
    assert _writes(controller) == []
