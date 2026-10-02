# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for interface-family adapters and aggregate read-only planning."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import PlatformType
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.interface_family_adapters import (
    IMPLICIT_TRANSITION_STATES,
    INTERFACE_FAMILY_ADAPTERS,
    InterfaceDeleteStrategy,
    InterfaceTransitionStrategy,
    InterfaceWorkflowValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import InterfaceStateSnapshot
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_executor import InterfaceWorkflowExecutor
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import (
    InterfaceWorkflowConflictError,
    InterfaceWorkflowPlanner,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_access_interface import EthernetAccessInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import EthernetBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_routed_interface import EthernetRoutedInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


class _RequestRecorder:
    """Route queued inventory and per-switch summary bodies and record every request."""

    def __init__(
        self,
        responses: list[dict[str, Any]],
        summary_responses: Mapping[str, dict[str, Any] | list[dict[str, Any]]] | None = None,
    ) -> None:
        self._responses: Iterator[dict[str, Any]] = iter(responses)
        self._summary_responses = {switch_id: iter(value if isinstance(value, list) else [value]) for switch_id, value in (summary_responses or {}).items()}
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        path = str(kwargs.get("path") or "")
        if "/interfacesSummary" in path:
            switch_ids = parse_qs(urlsplit(path).query).get("switchId", [])
            if len(switch_ids) != 1 or switch_ids[0] not in self._summary_responses:
                raise AssertionError(f"Unexpected interface-summary request: {path}")
            return next(self._summary_responses[switch_ids[0]])
        return next(self._responses)


def _planner(
    *,
    switches: Mapping[str, str] | None = None,
    responses: list[dict[str, Any]] | None = None,
    summary_responses: Mapping[str, dict[str, Any] | list[dict[str, Any]]] | None = None,
    vpc_pairs: Mapping[str, str | tuple[str, str]] | None = None,
) -> tuple[InterfaceWorkflowPlanner, _RequestRecorder]:
    switch_map = dict(switches or {"192.0.2.1": "SERIAL1", "192.0.2.2": "SERIAL2"})
    recorder = _RequestRecorder(
        responses or [{"interfaces": []} for _switch in switch_map],
        summary_responses=summary_responses,
    )
    rest_send = RestSend({"fabric_name": "fabric_1", "check_mode": True})
    context = FabricContext(rest_send=rest_send, fabric_name="fabric_1")
    context._fabric_summary = {"local": True, "fabricStatus": "default"}
    context._switch_map = switch_map
    context._switch_map_by_id = {switch_id: switch_ip for switch_ip, switch_id in switch_map.items()}
    snapshot = InterfaceStateSnapshot(fabric_name="fabric_1", fabric_context=context, request=recorder)
    return InterfaceWorkflowPlanner(snapshot=snapshot, vpc_pair_by_switch_ip=vpc_pairs), recorder


def _loopback(
    switch_ip: str,
    name: str = "loopback10",
    *,
    network_os_type: str = "nx-os",
    policy_type: str = "loopback",
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "switch_ip": switch_ip,
        "interface_name": name,
        "config_data": {
            "network_os": {
                "network_os_type": network_os_type,
                "policy": {
                    "policy_type": policy_type,
                    **(policy or {"ip": "198.51.100.10/32"}),
                },
            }
        },
    }


def _wire_loopback(
    name: str,
    policy_type: str,
    *,
    network_os_type: str = "nx-os",
    **policy: Any,
) -> dict[str, Any]:
    return {
        "interfaceName": name,
        "interfaceType": "loopback",
        "configData": {
            "mode": "managed",
            "networkOS": {
                "networkOSType": network_os_type,
                "policy": {"policyType": policy_type, **policy},
            },
        },
    }


def _ethernet(switch_ip: str, name: str = "Ethernet1/1", *, trunk: bool = False) -> dict[str, Any]:
    policy = {"allowed_vlans": "10-20"} if trunk else {"access_vlan": 10}
    return {
        "switch_ip": switch_ip,
        "interface_names": [name],
        "config_data": {"network_os": {"policy": policy}},
    }


def _port_channel(switch_ip: str, name: str = "port-channel10", members: list[str] | None = None) -> dict[str, Any]:
    return {
        "switch_ip": switch_ip,
        "interface_name": name,
        "config_data": {"network_os": {"policy": {"ports": members or ["Ethernet1/1"], "port_channel_mode": "active"}}},
    }


def _vpc(
    switch_ip: str,
    name: str = "vpc10",
    *,
    trunk: bool = False,
    peer1_members: list[str] | None = None,
    peer2_members: list[str] | None = None,
) -> dict[str, Any]:
    policy: dict[str, Any] = {"allowed_vlans": "10-20"} if trunk else {"access_vlan": 10}
    if peer1_members is not None:
        policy["peer1_member_ports"] = peer1_members
    if peer2_members is not None:
        policy["peer2_member_ports"] = peer2_members
    return {
        "switch_ip": switch_ip,
        "interface_name": name,
        "config_data": {"network_os": {"policy": policy}},
    }


def _wire_interface(
    name: str,
    interface_type: str,
    policy_type: str,
    *,
    network_os_type: str = "nx-os",
    mode: str = "access",
    **policy: Any,
) -> dict[str, Any]:
    return {
        "interfaceName": name,
        "interfaceType": interface_type,
        "configData": {
            "mode": mode,
            "networkOS": {
                "networkOSType": network_os_type,
                "policy": {"policyType": policy_type, **policy},
            },
        },
    }


def _summary_row(
    current: Mapping[str, Any],
    switch_id: str,
    **overrides: Any,
) -> dict[str, Any]:
    """Return one controller-eligible summary row matching a raw record."""
    row = {
        "interfaceName": current["interfaceName"],
        "interfaceType": current["interfaceType"],
        "policyType": InterfaceStateSnapshot.policy_type(dict(current)),
        "switchId": switch_id,
        "editAllowed": True,
        "rbacAccessible": True,
        "blockConfig": False,
        "markDeleted": False,
        "hasDeletedOverlay": False,
        "policyChangeSupported": True,
        "deletable": True,
    }
    row.update(overrides)
    return row


def test_registry_is_the_exact_twelve_family_scope_and_delegates_model_ownership() -> None:
    """The authoritative registry excludes flow-rules and derives every model from its orchestrator."""
    assert set(INTERFACE_FAMILY_ADAPTERS) == {
        "ethernet_access",
        "ethernet_routed",
        "ethernet_trunk_host",
        "loopback",
        "port_channel_access",
        "port_channel_routed",
        "port_channel_trunk_host",
        "subinterface_managed",
        "subinterface_unmanaged",
        "svi",
        "vpc_access",
        "vpc_trunk_host",
    }
    assert "flow_rules" not in INTERFACE_FAMILY_ADAPTERS
    assert all(adapter.model_class is adapter.orchestrator_class.model_class for adapter in INTERFACE_FAMILY_ADAPTERS.values())
    assert all(adapter.supported_states == frozenset({"merged", "replaced", "overridden", "deleted"}) for adapter in INTERFACE_FAMILY_ADAPTERS.values())
    assert INTERFACE_FAMILY_ADAPTERS["ethernet_access"].policy_types == frozenset({"accessHost", "iosXeAccess"})
    assert INTERFACE_FAMILY_ADAPTERS["ethernet_trunk_host"].policy_types == frozenset({"trunkHost", "iosXeTrunkHost"})
    assert INTERFACE_FAMILY_ADAPTERS["port_channel_access"].policy_types == frozenset({"accessPoHost", "iosXeAccessPoHost"})
    assert INTERFACE_FAMILY_ADAPTERS["port_channel_trunk_host"].policy_types == frozenset({"trunkPoHost", "iosXeTrunkPoHost"})
    assert INTERFACE_FAMILY_ADAPTERS["port_channel_routed"].policy_types == frozenset({"l3Po", "iosXeL3PortChannel"})
    assert INTERFACE_FAMILY_ADAPTERS["subinterface_managed"].policy_types == frozenset({"subinterface", "iosXeSubinterface", "iosXeSubinterfaceShutNoshut"})
    assert INTERFACE_FAMILY_ADAPTERS["svi"].policy_types == frozenset({"svi", "iosXeSvi", "iosXeSviShutNoShut"})


def test_adapter_policy_sets_match_standalone_orchestrator_contracts() -> None:
    """Adapters with a managed-policy API cannot drift from their standalone orchestrator."""
    checked = set()
    for resource_type, adapter in INTERFACE_FAMILY_ADAPTERS.items():
        if not hasattr(adapter.orchestrator_class, "_managed_policy_types"):
            continue
        orchestrator = adapter.orchestrator_class.__new__(adapter.orchestrator_class)
        assert adapter.policy_types == frozenset(orchestrator._managed_policy_types())
        checked.add(resource_type)

    assert checked == {
        "ethernet_access",
        "ethernet_routed",
        "ethernet_trunk_host",
        "port_channel_access",
        "port_channel_routed",
        "port_channel_trunk_host",
        "subinterface_managed",
        "svi",
        "vpc_access",
        "vpc_trunk_host",
    }


@pytest.mark.parametrize(
    ("resource_type", "expected_mode", "expected_policy_type"),
    [
        ("ethernet_access", "trunk", "iosXeTrunkHost"),
        ("ethernet_trunk_host", "trunk", "iosXeTrunkHost"),
        ("ethernet_routed", "routed", "iosXeRoutedHost"),
    ],
)
def test_ethernet_adapters_retain_family_correct_ios_xe_reset_profiles(
    resource_type: str,
    expected_mode: str,
    expected_policy_type: str,
) -> None:
    """The aggregate registry points at the standalone class that owns each reset payload."""
    payload = INTERFACE_FAMILY_ADAPTERS[resource_type].orchestrator_class._xe_reset_payload("GigabitEthernet3", "SERIAL1")

    assert payload["configData"]["mode"] == expected_mode
    assert payload["configData"]["networkOS"]["policy"]["policyType"] == expected_policy_type
    assert payload["configData"]["networkOS"]["policy"]["adminState"] is True


def test_registry_declares_generic_transition_delete_and_structural_safety_metadata() -> None:
    """Every adapter advertises its mutation strategy and structural dependency guards."""
    expected = {
        "ethernet_access": (InterfaceDeleteStrategy.NORMALIZE, False, False, True),
        "ethernet_routed": (InterfaceDeleteStrategy.NORMALIZE, False, False, True),
        "ethernet_trunk_host": (InterfaceDeleteStrategy.NORMALIZE, False, False, True),
        "loopback": (InterfaceDeleteStrategy.REMOVE, False, False, False),
        "port_channel_access": (InterfaceDeleteStrategy.REMOVE, False, True, True),
        "port_channel_routed": (InterfaceDeleteStrategy.REMOVE, False, True, True),
        "port_channel_trunk_host": (InterfaceDeleteStrategy.REMOVE, False, True, True),
        "subinterface_managed": (InterfaceDeleteStrategy.REMOVE, False, False, False),
        "subinterface_unmanaged": (InterfaceDeleteStrategy.REMOVE, False, False, False),
        "svi": (InterfaceDeleteStrategy.REMOVE, False, False, False),
        "vpc_access": (InterfaceDeleteStrategy.DELETE, True, True, False),
        "vpc_trunk_host": (InterfaceDeleteStrategy.DELETE, True, True, False),
    }

    for resource_type, adapter in INTERFACE_FAMILY_ADAPTERS.items():
        delete_strategy, pair_consistency, owns_members, child_guard = expected[resource_type]
        assert adapter.transition_strategy is InterfaceTransitionStrategy.UPDATE
        assert adapter.transition_states == IMPLICIT_TRANSITION_STATES
        assert adapter.delete_strategy is delete_strategy
        assert adapter.safety.requires_pair_consistency is pair_consistency
        assert adapter.safety.owns_physical_members is owns_members
        assert adapter.safety.guards_child_subinterfaces is child_guard
        assert adapter.supports_intra_family_policy_transitions is (resource_type in {"ethernet_routed", "loopback", "subinterface_managed", "svi"})
        assert not hasattr(adapter, "policy_transition_sources")

    assert IMPLICIT_TRANSITION_STATES == frozenset({"merged", "replaced"})
    assert {adapter.delete_strategy for adapter in INTERFACE_FAMILY_ADAPTERS.values()} == {
        InterfaceDeleteStrategy.NORMALIZE,
        InterfaceDeleteStrategy.REMOVE,
        InterfaceDeleteStrategy.DELETE,
    }


def test_ethernet_adapter_accepts_the_grouped_standalone_input_contract() -> None:
    """The adapter expands interface_names before invoking the existing concrete model."""
    adapter = INTERFACE_FAMILY_ADAPTERS["ethernet_access"]

    proposed = adapter.validate_config(
        [
            {
                "switch_ip": "192.0.2.1",
                "interface_names": ["e1/1", "ETHERNET1/2"],
                "config_data": {"network_os": {"policy": {"access_vlan": 10}}},
            }
        ],
        "merged",
        3,
    )

    assert proposed.keys() == [("192.0.2.1", "Ethernet1/1"), ("192.0.2.1", "Ethernet1/2")]


def test_ethernet_trunk_vlan_mapping_plan_retains_entries() -> None:
    """The aggregate path inherits the standalone atomic VLAN-mapping merge."""
    current = _wire_interface(
        "Ethernet1/44",
        "ethernet",
        "trunkHost",
        mode="trunk",
        vlanMapping=False,
    )
    planner, recorder = _planner(responses=[{"interfaces": [current]}])
    config = {
        "switch_ip": "192.0.2.1",
        "interface_names": ["Ethernet1/44"],
        "config_data": {
            "network_os": {
                "policy": {
                    "vlan_mapping": True,
                    "vlan_mapping_entries": [
                        {
                            "customer_inner_vlan_id": 3121,
                            "customer_vlan_id": ["3122-3123"],
                            "dot1q_tunnel": True,
                            "provider_vlan_id": 3120,
                        }
                    ],
                }
            }
        },
    }

    plan = planner.plan([{"type": "ethernet_trunk_host", "state": "merged", "config": [config]}])

    assert plan.changed is True
    assert plan.mutation_count == 1
    policy = plan.to_dict()["resources"][0]["after"][0]["config_data"]["network_os"]["policy"]
    assert policy["vlan_mapping"] is True
    assert policy["vlan_mapping_entries"] == [
        {
            "customer_inner_vlan_id": 3121,
            "customer_vlan_id": ["3122-3123"],
            "dot1q_tunnel": True,
            "provider_vlan_id": 3120,
        }
    ]
    assert {getattr(call["verb"], "value", call["verb"]) for call in recorder.calls} == {"GET"}


def test_check_mode_planning_rejects_platform_mismatch_before_any_write() -> None:
    """The read-only planner applies develop's platform guard to every planned aggregate write."""
    planner, recorder = _planner(responses=[{"interfaces": []}])
    planner.fabric_context._platform_map = {"192.0.2.1": PlatformType.IOS_XE, "192.0.2.2": PlatformType.IOS_XE}

    with pytest.raises(InterfaceWorkflowValidationError, match=r"reports platformType 'ios-xe'.*network_os_type is 'nx-os'"):
        planner.plan([{"type": "ethernet_access", "state": "merged", "config": [_ethernet("192.0.2.1")]}])

    assert len(recorder.calls) == 1
    assert {getattr(call["verb"], "value", call["verb"]) for call in recorder.calls} == {"GET"}


def test_normal_execution_rechecks_platform_match_immediately_before_writes() -> None:
    """A platform change after planning fails before the executor can send a mutation."""
    planner, _recorder = _planner(responses=[{"interfaces": []}])
    planner.fabric_context._platform_map = {"192.0.2.1": PlatformType.NX_OS, "192.0.2.2": PlatformType.NX_OS}
    plan = planner.plan([{"type": "ethernet_access", "state": "merged", "config": [_ethernet("192.0.2.1")]}])
    planner.fabric_context._platform_map["192.0.2.1"] = PlatformType.IOS_XE

    execution = InterfaceWorkflowExecutor(snapshot=planner.snapshot).execute(plan)

    assert execution.failed is True
    assert execution.changed is False
    assert execution.mutation_requests == 0
    assert execution.deploy_requests == 0
    assert "reports platformType 'ios-xe'" in execution.message


@pytest.mark.parametrize(
    ("resource_type", "config"),
    [
        (
            "ethernet_access",
            {
                "switch_ip": "192.0.2.1",
                "interface_names": ["GigabitEthernet3"],
                "config_data": {"network_os": {"network_os_type": "ios-xe", "policy": {"access_vlan": 10}}},
            },
        ),
        (
            "ethernet_trunk_host",
            {
                "switch_ip": "192.0.2.1",
                "interface_names": ["GigabitEthernet3"],
                "config_data": {"network_os": {"network_os_type": "ios-xe", "policy": {"allowed_vlans": "10-20"}}},
            },
        ),
        (
            "ethernet_routed",
            {
                "switch_ip": "192.0.2.1",
                "interface_name": "GigabitEthernet3",
                "config_data": {"network_os": {"network_os_type": "ios-xe", "policy": {"ip": "198.51.100.5", "prefix": 30}}},
            },
        ),
    ],
)
def test_all_ethernet_families_reject_ios_xe_fabric_link_writes(
    monkeypatch: pytest.MonkeyPatch,
    resource_type: str,
    config: dict[str, Any],
) -> None:
    """Access, trunk, and routed aggregate writes all consume the shared fabric-link guard."""
    current = _wire_interface(
        "GigabitEthernet3",
        "ethernet",
        "iosXeRoutedHost",
        adminState=True,
        description="fabric endpoint",
        ip="198.51.100.1",
        prefix=30,
    )
    current["configData"]["mode"] = "routed"
    current["configData"]["networkOS"]["networkOSType"] = "ios-xe"
    planner, _recorder = _planner(
        responses=[{"interfaces": [current]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1")]}},
    )
    planner.fabric_context._platform_map = {"192.0.2.1": PlatformType.IOS_XE, "192.0.2.2": PlatformType.IOS_XE}
    link = {
        "linkId": "LINK-UUID-1",
        "configData": {"policyType": "ebgpVrfLite"},
        "srcSwitchName": "WAN1",
        "srcInterfaceName": "GigabitEthernet3",
        "dstSwitchName": "BORDER1",
        "dstInterfaceName": "Ethernet1/3",
    }
    monkeypatch.setattr(EthernetBaseOrchestrator, "_fabric_link_endpoints", lambda _self: {("SERIAL1", "gigabitethernet3"): link})

    with pytest.raises(InterfaceWorkflowValidationError, match=r"endpoint of fabric link LINK-UUID-1"):
        planner.plan([{"type": resource_type, "state": "merged", "config": [config]}])


def test_adapter_validation_error_names_index_type_and_standalone_module() -> None:
    """Workflow validation keeps the authoritative standalone contract discoverable."""
    adapter = INTERFACE_FAMILY_ADAPTERS["loopback"]

    with pytest.raises(InterfaceWorkflowValidationError) as exc_info:
        adapter.validate_config([{"switch_ip": "192.0.2.1"}], "merged", 4)

    message = str(exc_info.value)
    assert "resources[4]" in message
    assert "loopback" in message
    assert "cisco.nd.nd_interface_loopback" in message


def test_two_family_plan_uses_one_inventory_get_per_union_switch() -> None:
    """Two families over two switches plan fully with exactly two interface GETs."""
    planner, recorder = _planner()

    plan = planner.plan(
        [
            {"type": "loopback", "state": "merged", "config": [_loopback("192.0.2.1")]},
            {"type": "ethernet_access", "state": "merged", "config": [_ethernet("192.0.2.2")]},
        ]
    )

    assert plan.changed is True
    assert plan.mutation_count == 2
    assert plan.target_switch_ids == ("SERIAL1", "SERIAL2")
    assert plan.request_stats["interface_inventory_gets"] == 2
    assert len(recorder.calls) == 2
    assert [resource.operations.mutation_count for resource in plan.resources] == [1, 1]


def test_any_overridden_group_expands_initial_scope_to_the_full_fabric() -> None:
    """Override preloads all fabric switches even when config names one switch."""
    switches = {"192.0.2.1": "SERIAL1", "192.0.2.2": "SERIAL2", "192.0.2.3": "SERIAL3"}
    planner, recorder = _planner(switches=switches)

    plan = planner.plan([{"type": "loopback", "state": "overridden", "config": [_loopback("192.0.2.1")]}])

    assert plan.target_switch_ids == ("SERIAL1", "SERIAL2", "SERIAL3")
    assert plan.request_stats["interface_inventory_gets"] == 3
    assert len(recorder.calls) == 3


def test_sibling_families_cannot_claim_the_same_switch_interface() -> None:
    """Access and trunk claims for one physical identity fail before writes."""
    planner, _recorder = _planner(responses=[{"interfaces": []}, {"interfaces": []}])

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan(
            [
                {"type": "ethernet_access", "state": "merged", "config": [_ethernet("192.0.2.1")]},
                {"type": "ethernet_trunk_host", "state": "merged", "config": [_ethernet("192.0.2.1", trunk=True)]},
            ]
        )

    assert "duplicate_ownership" in {conflict.code for conflict in exc_info.value.conflicts}
    assert exc_info.value.conflicts[0].resource_indices == (0, 1)


@pytest.mark.parametrize("state", ["merged", "replaced"])
def test_implicit_ethernet_transition_supports_merged_and_replaced(state: str) -> None:
    """A convertible host policy is implicitly replaced for both write states."""
    current = _wire_interface("Ethernet1/1", "ethernet", "trunkHost", description="configured trunk")
    planner, _recorder = _planner(
        responses=[{"interfaces": [current]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1")]}},
    )

    plan = planner.plan([{"type": "ethernet_access", "state": state, "config": [_ethernet("192.0.2.1")]}])

    resource = plan.resources[0]
    assert resource.operations.creates == ()
    assert resource.operations.updates == ()
    assert resource.operations.deletes == ()
    assert len(resource.transitions) == 1
    assert resource.transitions[0].from_policy_type == "trunkHost"
    assert resource.transitions[0].to_policy_type == "accessHost"
    assert plan.request_stats["interface_summary_gets"] == 1


def test_legacy_allow_policy_transition_key_is_rejected_before_inventory() -> None:
    """The removed opt-in key cannot silently survive through direct planner calls."""
    planner, recorder = _planner()

    with pytest.raises(InterfaceWorkflowValidationError, match=r"unsupported keys: allow_policy_transition"):
        planner.plan(
            [
                {
                    "type": "ethernet_access",
                    "state": "merged",
                    "allow_policy_transition": True,
                    "config": [_ethernet("192.0.2.1")],
                }
            ]
        )

    assert recorder.calls == []


@pytest.mark.parametrize(
    ("resource_type", "config", "interface_name", "interface_type"),
    [
        ("ethernet_access", _ethernet("192.0.2.1", "Ethernet1/10"), "Ethernet1/10", "ethernet"),
        ("ethernet_trunk_host", _ethernet("192.0.2.1", "Ethernet1/11", trunk=True), "Ethernet1/11", "ethernet"),
        ("loopback", _loopback("192.0.2.1", "loopback10"), "loopback10", "loopback"),
        ("port_channel_access", _port_channel("192.0.2.1", "port-channel10"), "port-channel10", "portChannel"),
        ("port_channel_trunk_host", _port_channel("192.0.2.1", "port-channel11"), "port-channel11", "portChannel"),
        (
            "subinterface_managed",
            {
                "switch_ip": "192.0.2.1",
                "interface_name": "Ethernet1/3.10",
                "config_data": {"network_os": {"policy": {"vlan_id": 10}}},
            },
            "Ethernet1/3.10",
            "subInterface",
        ),
        (
            "subinterface_unmanaged",
            {
                "switch_ip": "192.0.2.1",
                "interface_name": "Ethernet1/4.20",
                "config_data": {"network_os": {"policy": {}}},
            },
            "Ethernet1/4.20",
            "subInterface",
        ),
        (
            "svi",
            {
                "switch_ip": "192.0.2.1",
                "interface_name": "vlan100",
                "config_data": {"network_os": {"policy": {}}},
            },
            "vlan100",
            "svi",
        ),
    ],
)
def test_implicit_transition_is_generic_across_non_vpc_adapters(
    resource_type: str,
    config: dict[str, Any],
    interface_name: str,
    interface_type: str,
) -> None:
    """Every non-vPC adapter can replace an arbitrary same-structure policy."""
    current_policy_type = {
        "ethernet_access": "trunkHost",
        "ethernet_trunk_host": "accessHost",
    }.get(resource_type, f"foreign-{resource_type}")
    current = _wire_interface(
        interface_name,
        interface_type,
        current_policy_type,
        **({"description": "configured trunk"} if resource_type == "ethernet_access" else {}),
    )
    inventory = [current]
    if resource_type.startswith("subinterface_"):
        parent_name = interface_name.rsplit(".", 1)[0]
        inventory.append(_wire_interface(parent_name, "ethernet", "routedHost", mode="routed"))
    planner, _recorder = _planner(
        responses=[{"interfaces": inventory}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1")]}},
    )

    plan = planner.plan([{"type": resource_type, "state": "merged", "config": [config]}])

    resource = plan.resources[0]
    assert len(resource.transitions) == 1
    assert resource.operations.creates == ()
    assert resource.transitions[0].to_policy_type in resource.adapter.policy_types


def test_svi_transition_accepts_switch_virtual_interface_summary_alias() -> None:
    """The interfacesSummary SVI spelling is canonicalized to the raw-record structure."""
    current = _wire_interface("vlan100", "switchVirtualInterface", "foreignSviPolicy")
    planner, _recorder = _planner(
        responses=[{"interfaces": [current]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1", interfaceType="switchVirtualInterface")]}},
    )
    config = {
        "switch_ip": "192.0.2.1",
        "interface_name": "vlan100",
        "config_data": {"network_os": {"policy": {}}},
    }

    plan = planner.plan([{"type": "svi", "state": "merged", "config": [config]}])

    assert len(plan.resources[0].transitions) == 1
    assert plan.request_stats["interface_summary_gets"] == 1


@pytest.mark.parametrize(
    ("current_policy_type", "current_policy", "desired_policy_type", "desired_policy"),
    [
        (
            "iosXeSvi",
            {"adminState": True, "ip": "198.51.100.1", "prefix": 24},
            "iosXeSviShutNoShut",
            {"admin_state": False},
        ),
        (
            "iosXeSviShutNoShut",
            {"adminState": False},
            "iosXeSvi",
            {"admin_state": True, "ip": "198.51.100.1", "prefix": 24},
        ),
    ],
)
def test_ios_xe_svi_full_and_admin_variants_transition_in_both_directions(
    current_policy_type: str,
    current_policy: dict[str, Any],
    desired_policy_type: str,
    desired_policy: dict[str, Any],
) -> None:
    """The final IOS-XE SVI union is executable, not merely listed in the registry."""
    current = _wire_interface(
        "vlan100",
        "svi",
        current_policy_type,
        network_os_type="ios-xe",
        mode="managed",
        **current_policy,
    )
    planner, _recorder = _planner(
        switches={"192.0.2.1": "SERIAL1"},
        responses=[{"interfaces": [current]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1")]}},
    )
    planner.fabric_context._platform_map = {"192.0.2.1": PlatformType.IOS_XE}
    desired = {
        "switch_ip": "192.0.2.1",
        "interface_name": "vlan100",
        "config_data": {
            "network_os": {
                "network_os_type": "ios-xe",
                "policy": {"policy_type": desired_policy_type, **desired_policy},
            }
        },
    }

    plan = planner.plan([{"type": "svi", "state": "merged", "config": [desired]}])

    transition = plan.resources[0].transitions[0]
    assert transition.from_policy_type == current_policy_type
    assert transition.to_policy_type == desired_policy_type


@pytest.mark.parametrize(
    ("current_policy_type", "current_policy", "desired_policy_type", "desired_policy"),
    [
        (
            "iosXeSubinterface",
            {"adminState": True, "vlanId": 10, "ip": "198.51.100.5", "prefix": 30},
            "iosXeSubinterfaceShutNoshut",
            {"admin_state": False},
        ),
        (
            "iosXeSubinterfaceShutNoshut",
            {"adminState": False},
            "iosXeSubinterface",
            {"admin_state": True, "vlan_id": 10, "ip": "198.51.100.5", "prefix": 30},
        ),
    ],
)
def test_ios_xe_managed_subinterface_full_and_admin_variants_transition_in_both_directions(
    current_policy_type: str,
    current_policy: dict[str, Any],
    desired_policy_type: str,
    desired_policy: dict[str, Any],
) -> None:
    """Both final IOS-XE managed-subinterface policies honor the routed-parent contract."""
    parent = _wire_interface(
        "GigabitEthernet3",
        "ethernet",
        "iosXeRoutedHost",
        network_os_type="ios-xe",
        mode="routed",
    )
    current = _wire_interface(
        "GigabitEthernet3.10",
        "subInterface",
        current_policy_type,
        network_os_type="ios-xe",
        mode="managed",
        **current_policy,
    )
    planner, _recorder = _planner(
        switches={"192.0.2.1": "SERIAL1"},
        responses=[{"interfaces": [parent, current]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1")]}},
    )
    planner.fabric_context._platform_map = {"192.0.2.1": PlatformType.IOS_XE}
    desired = {
        "switch_ip": "192.0.2.1",
        "interface_name": "GigabitEthernet3.10",
        "config_data": {
            "network_os": {
                "network_os_type": "ios-xe",
                "policy": {"policy_type": desired_policy_type, **desired_policy},
            }
        },
    }

    plan = planner.plan([{"type": "subinterface_managed", "state": "merged", "config": [desired]}])

    transition = plan.resources[0].transitions[0]
    assert transition.from_policy_type == current_policy_type
    assert transition.to_policy_type == desired_policy_type


@pytest.mark.parametrize(("resource_type", "trunk"), [("vpc_access", False), ("vpc_trunk_host", True)])
def test_implicit_transition_requires_and_accepts_a_consistent_vpc_pair(resource_type: str, trunk: bool) -> None:
    """Both vPC adapters transition only after equivalent records and safety rows exist on both peers."""
    primary = _wire_interface("vpc10", "vpc", "foreignVpcPolicy")
    peer = _wire_interface("vpc10", "vpc", "foreignVpcPolicy")
    pairs = {"192.0.2.1": ("192.0.2.1", "192.0.2.2")}
    planner, _recorder = _planner(
        responses=[{"interfaces": [primary]}, {"interfaces": [peer]}],
        summary_responses={
            "SERIAL1": {"interfaces": [_summary_row(primary, "SERIAL1")]},
            "SERIAL2": {"interfaces": [_summary_row(peer, "SERIAL2")]},
        },
        vpc_pairs=pairs,
    )

    plan = planner.plan([{"type": resource_type, "state": "merged", "config": [_vpc("192.0.2.1", trunk=trunk)]}])

    transition = plan.resources[0].transitions[0]
    assert len(transition.current_records) == 2
    assert plan.request_stats["interface_summary_gets"] == 2


def test_vpc_pair_fingerprint_accepts_identical_asymmetric_peer_fields() -> None:
    """ND's two echoes preserve peer1/peer2 meaning while peerSwitchId swaps."""
    primary = _wire_interface(
        "vpc10",
        "vpc",
        "foreignVpcPolicy",
        peerSwitchId="SERIAL2",
        peer1MemberPorts=["Ethernet1/1", "Ethernet1/3"],
        peer2MemberPorts=["Ethernet1/2", "Ethernet1/4"],
    )
    peer = _wire_interface(
        "vpc10",
        "vpc",
        "foreignVpcPolicy",
        peerSwitchId="SERIAL1",
        peer1MemberPorts=["ethernet1/3", "ETHERNET1/1"],
        peer2MemberPorts=["ethernet1/4", "ETHERNET1/2"],
    )
    planner, _recorder = _planner(
        responses=[{"interfaces": [primary]}, {"interfaces": [peer]}],
        summary_responses={
            "SERIAL1": {"interfaces": [_summary_row(primary, "SERIAL1")]},
            "SERIAL2": {"interfaces": [_summary_row(peer, "SERIAL2")]},
        },
        vpc_pairs={"192.0.2.1": ("192.0.2.1", "192.0.2.2")},
    )

    plan = planner.plan(
        [
            {
                "type": "vpc_access",
                "state": "merged",
                "config": [
                    _vpc(
                        "192.0.2.1",
                        peer1_members=["Ethernet1/1", "Ethernet1/3"],
                        peer2_members=["Ethernet1/2", "Ethernet1/4"],
                    )
                ],
            }
        ]
    )

    assert len(plan.resources[0].transitions) == 1


def test_summary_inventory_is_lazy_and_shared_for_two_transitions_on_one_switch() -> None:
    """Two foreign policies on one switch add one summary GET, never one per interface."""
    first = _wire_interface("Ethernet1/10", "ethernet", "routedHost")
    second = _wire_interface("Ethernet1/11", "ethernet", "dot1qTunnelHost")
    planner, recorder = _planner(
        responses=[{"interfaces": [first, second]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(first, "SERIAL1"), _summary_row(second, "SERIAL1")]}},
    )
    config = {
        "switch_ip": "192.0.2.1",
        "interface_names": ["Ethernet1/10", "Ethernet1/11"],
        "config_data": {"network_os": {"policy": {"access_vlan": 10}}},
    }

    plan = planner.plan([{"type": "ethernet_access", "state": "merged", "config": [config]}])

    assert len(plan.resources[0].transitions) == 2
    assert plan.request_stats["interface_inventory_gets"] == 1
    assert plan.request_stats["interface_summary_gets"] == 1
    assert len(recorder.calls) == 2


def test_default_trunk_host_keeps_bulk_create_path_without_summary_get() -> None:
    """An unconfigured physical default remains an ordinary batched create candidate."""
    current = _wire_interface("Ethernet1/1", "ethernet", "trunkHost")
    planner, recorder = _planner(responses=[{"interfaces": [current]}])

    plan = planner.plan([{"type": "ethernet_access", "state": "merged", "config": [_ethernet("192.0.2.1")]}])

    resource = plan.resources[0]
    assert resource.transitions == ()
    assert len(resource.operations.creates) == 1
    assert plan.request_stats["interface_summary_gets"] == 0
    assert len(recorder.calls) == 1


def test_same_name_different_interface_type_is_a_structural_collision() -> None:
    """A same-name object of another structural kind is never treated as create or transition."""
    current = _wire_interface("Ethernet1/1", "svi", "svi")
    planner, recorder = _planner(responses=[{"interfaces": [current]}])

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan([{"type": "ethernet_access", "state": "merged", "config": [_ethernet("192.0.2.1")]}])

    assert {conflict.code for conflict in exc_info.value.conflicts} == {"structural_type_collision"}
    assert len(recorder.calls) == 1


@pytest.mark.parametrize(
    ("resource_type", "config", "interface_name", "interface_type", "current_policy_type"),
    [
        (
            "ethernet_access",
            {"switch_ip": "192.0.2.1", "interface_names": ["Ethernet1/1"]},
            "Ethernet1/1",
            "ethernet",
            "dot1qTunnelHost",
        ),
        (
            "ethernet_routed",
            {"switch_ip": "192.0.2.1", "interface_name": "Ethernet1/3"},
            "Ethernet1/3",
            "ethernet",
            "accessHost",
        ),
        (
            "ethernet_trunk_host",
            {"switch_ip": "192.0.2.1", "interface_names": ["Ethernet1/2"]},
            "Ethernet1/2",
            "ethernet",
            "dot1qTunnelHost",
        ),
        (
            "loopback",
            {"switch_ip": "192.0.2.1", "interface_name": "loopback10"},
            "loopback10",
            "loopback",
            "foreignDeletablePolicy",
        ),
        (
            "port_channel_access",
            {"switch_ip": "192.0.2.1", "interface_name": "port-channel10"},
            "port-channel10",
            "portChannel",
            "foreignDeletablePolicy",
        ),
        (
            "port_channel_trunk_host",
            {"switch_ip": "192.0.2.1", "interface_name": "port-channel11"},
            "port-channel11",
            "portChannel",
            "foreignDeletablePolicy",
        ),
        (
            "subinterface_managed",
            {
                "switch_ip": "192.0.2.1",
                "interface_name": "Ethernet1/3.10",
            },
            "Ethernet1/3.10",
            "subInterface",
            "foreignDeletablePolicy",
        ),
        (
            "subinterface_unmanaged",
            {
                "switch_ip": "192.0.2.1",
                "interface_name": "Ethernet1/4.20",
            },
            "Ethernet1/4.20",
            "subInterface",
            "foreignDeletablePolicy",
        ),
        (
            "svi",
            {
                "switch_ip": "192.0.2.1",
                "interface_name": "vlan100",
            },
            "vlan100",
            "svi",
            "foreignDeletablePolicy",
        ),
    ],
)
def test_deleted_is_policy_independent_within_the_selected_structure(
    resource_type: str,
    config: dict[str, Any],
    interface_name: str,
    interface_type: str,
    current_policy_type: str,
) -> None:
    """Explicit deleted targets a safe cross-family policy and uses the destination adapter's delete path."""
    current = _wire_interface(interface_name, interface_type, current_policy_type)
    planner, _recorder = _planner(
        responses=[{"interfaces": [current]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1")]}},
    )

    plan = planner.plan([{"type": resource_type, "state": "deleted", "config": [config]}])

    resource = plan.resources[0]
    assert resource.transitions == ()
    assert len(resource.operations.deletes) == 1
    assert resource.mutation_count == 1


def test_deleted_rejects_fabric_owned_ethernet_policy_before_writes() -> None:
    """Explicit physical delete cannot normalize a fabric link carrying a system-owned policy."""
    current = _wire_interface("Ethernet1/1", "ethernet", "numbered", ip="198.51.100.1", prefix=30)
    planner, recorder = _planner(
        responses=[{"interfaces": [current]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1")]}},
    )

    with pytest.raises(InterfaceWorkflowValidationError, match=r"system policy 'numbered'"):
        planner.plan([{"type": "ethernet_access", "state": "deleted", "config": [_ethernet("192.0.2.1")]}])

    assert len(recorder.calls) == 2


@pytest.mark.parametrize(
    "inventory",
    [
        [],
        [_wire_interface("Ethernet1/1", "ethernet", "trunkHost")],
    ],
)
def test_deleted_absent_or_default_ethernet_is_idempotent_without_summary(inventory: list[dict[str, Any]]) -> None:
    """Deleting an absent or already-normalized physical interface is a no-op."""
    planner, recorder = _planner(responses=[{"interfaces": inventory}])

    plan = planner.plan([{"type": "ethernet_access", "state": "deleted", "config": [_ethernet("192.0.2.1")]}])

    assert plan.changed is False
    assert plan.mutation_count == 0
    assert plan.request_stats["interface_summary_gets"] == 0
    assert len(recorder.calls) == 1


@pytest.mark.parametrize(
    ("policy_type", "mode"),
    [("iosXeRoutedHost", "routed"), ("iosXeTrunkHost", "trunk")],
)
def test_deleted_ios_xe_default_is_idempotent_without_platform_reset_or_summary(policy_type: str, mode: str) -> None:
    """A defaults-only IOS-XE physical port is already at its platform reset target."""
    current = _wire_interface("GigabitEthernet3", "ethernet", policy_type, adminState=True, speed="auto")
    current["configData"]["mode"] = mode
    current["configData"]["networkOS"]["networkOSType"] = "ios-xe"
    planner, recorder = _planner(responses=[{"interfaces": [current]}])
    config = {"switch_ip": "192.0.2.1", "interface_names": ["GigabitEthernet3"]}

    plan = planner.plan([{"type": "ethernet_access", "state": "deleted", "config": [config]}])

    assert plan.changed is False
    assert plan.mutation_count == 0
    assert plan.auxiliary_orchestrators == ()
    assert plan.request_stats["interface_summary_gets"] == 0
    assert len(recorder.calls) == 1


def test_deleted_ios_xe_configured_port_uses_same_family_platform_reset_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """A cross-policy IOS-XE delete keeps one logical item and selects the requested family's reset implementation."""
    current = _wire_interface(
        "GigabitEthernet3",
        "ethernet",
        "iosXeRoutedHost",
        adminState=True,
        ip="198.51.100.1",
        prefix=30,
    )
    current["configData"]["mode"] = "routed"
    current["configData"]["networkOS"]["networkOSType"] = "ios-xe"
    planner, recorder = _planner(
        responses=[{"interfaces": [current]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1")]}},
    )
    monkeypatch.setattr(EthernetAccessInterfaceOrchestrator, "_fabric_link_endpoints", lambda _self: {})
    config = {"switch_ip": "192.0.2.1", "interface_names": ["GigabitEthernet3"]}

    plan = planner.plan([{"type": "ethernet_access", "state": "deleted", "config": [config]}])

    resource = plan.resources[0]
    assert len(resource.operations.deletes) == 1
    assert len(resource.platform_deletes) == 1
    proxy = resource.platform_deletes[0]
    assert proxy.get_identifier_value() == ("192.0.2.1", "GigabitEthernet3")
    assert proxy.config_data.network_os.network_os_type == "ios-xe"
    assert proxy.config_data.mode == "access"
    assert isinstance(resource.orchestrator, EthernetAccessInterfaceOrchestrator)
    assert plan.auxiliary_orchestrators == ()
    assert plan.request_stats["interface_inventory_gets"] == 1
    assert plan.request_stats["interface_summary_gets"] == 1
    assert len(recorder.calls) == 2


def test_direct_routed_ios_xe_delete_refuses_a_fabric_link_endpoint_during_planning(monkeypatch: pytest.MonkeyPatch) -> None:
    """A direct routed delete fails closed on an IOS-XE fabric-link endpoint before any mutation can run."""
    current = _wire_interface(
        "GigabitEthernet3",
        "ethernet",
        "iosXeRoutedHost",
        adminState=True,
        description="fabric-owned endpoint",
        ip="198.51.100.1",
        prefix=30,
    )
    current["configData"]["mode"] = "routed"
    current["configData"]["networkOS"]["networkOSType"] = "ios-xe"
    planner, recorder = _planner(
        switches={"192.0.2.1": "SERIAL1"},
        responses=[{"interfaces": [current]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1")]}},
    )
    link_calls: list[tuple[str, str]] = []

    def links_request(_orchestrator, *, path, verb, **_kwargs):
        link_calls.append((getattr(verb, "value", verb), path))
        return {
            "links": [
                {
                    "linkId": "LINK-UUID-1",
                    "configData": {"policyType": "ebgpVrfLite"},
                    "srcSwitchName": "WAN1",
                    "srcSwitchId": "SERIAL1",
                    "srcInterfaceName": "GigabitEthernet3",
                    "dstSwitchName": "BORDER1",
                    "dstSwitchId": "SERIAL9",
                    "dstInterfaceName": "Ethernet1/3",
                }
            ],
            "meta": {"counts": {"remaining": 0}},
        }

    monkeypatch.setattr(EthernetRoutedInterfaceOrchestrator, "_request", links_request)
    resources = [
        {
            "type": "ethernet_routed",
            "state": "deleted",
            "config": [{"switch_ip": "192.0.2.1", "interface_name": "GigabitEthernet3"}],
        }
    ]

    with pytest.raises(
        InterfaceWorkflowValidationError,
        match=r"resources\[0\] type 'ethernet_routed' preflight failed: Interface GigabitEthernet3 .* endpoint of fabric link LINK-UUID-1",
    ):
        planner.plan(resources)

    assert link_calls == [("GET", "/api/v1/manage/links?fabricName=fabric_1")]
    assert planner.snapshot.request_stats["interface_inventory_gets"] == 1
    assert planner.snapshot.request_stats["interface_summary_gets"] == 0
    assert len(recorder.calls) == 1
    assert {getattr(call["verb"], "value", call["verb"]) for call in recorder.calls} == {"GET"}


def test_first_of_two_direct_routed_ios_xe_deletes_refuses_a_fabric_link_endpoint_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two direct routed groups load their inventories, then the first link-owned target stops planning after one links GET."""
    first = _wire_interface(
        "GigabitEthernet3",
        "ethernet",
        "iosXeRoutedHost",
        adminState=True,
        description="fabric-owned endpoint",
        ip="198.51.100.1",
        prefix=30,
    )
    second = _wire_interface(
        "GigabitEthernet4",
        "ethernet",
        "iosXeRoutedHost",
        adminState=True,
        description="ordinary routed interface",
        ip="198.51.100.5",
        prefix=30,
    )
    for current in (first, second):
        current["configData"]["mode"] = "routed"
        current["configData"]["networkOS"]["networkOSType"] = "ios-xe"
    planner, recorder = _planner(
        responses=[{"interfaces": [first]}, {"interfaces": [second]}],
        summary_responses={
            "SERIAL1": {"interfaces": [_summary_row(first, "SERIAL1")]},
            "SERIAL2": {"interfaces": [_summary_row(second, "SERIAL2")]},
        },
    )
    link_calls: list[tuple[str, str]] = []

    def links_request(_orchestrator, *, path, verb, **_kwargs):
        link_calls.append((getattr(verb, "value", verb), path))
        return {
            "links": [
                {
                    "linkId": "LINK-UUID-1",
                    "configData": {"policyType": "ebgpVrfLite"},
                    "srcSwitchName": "WAN1",
                    "srcSwitchId": "SERIAL1",
                    "srcInterfaceName": "GigabitEthernet3",
                    "dstSwitchName": "BORDER1",
                    "dstSwitchId": "SERIAL9",
                    "dstInterfaceName": "Ethernet1/3",
                }
            ],
            "meta": {"counts": {"remaining": 0}},
        }

    monkeypatch.setattr(EthernetRoutedInterfaceOrchestrator, "_request", links_request)
    resources = [
        {
            "type": "ethernet_routed",
            "state": "deleted",
            "config": [{"switch_ip": "192.0.2.1", "interface_name": "GigabitEthernet3"}],
        },
        {
            "type": "ethernet_routed",
            "state": "deleted",
            "config": [{"switch_ip": "192.0.2.2", "interface_name": "GigabitEthernet4"}],
        },
    ]

    with pytest.raises(
        InterfaceWorkflowValidationError,
        match=r"resources\[0\] type 'ethernet_routed' preflight failed: Interface GigabitEthernet3 .* endpoint of fabric link LINK-UUID-1",
    ):
        planner.plan(resources)

    assert link_calls == [("GET", "/api/v1/manage/links?fabricName=fabric_1")]
    assert planner.snapshot.request_stats["interface_inventory_gets"] == 2
    assert planner.snapshot.request_stats["interface_summary_gets"] == 0
    assert len(recorder.calls) == 2
    assert {getattr(call["verb"], "value", call["verb"]) for call in recorder.calls} == {"GET"}


def test_multiple_routed_ios_xe_deletes_share_one_link_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    """Direct routed delete groups reuse one lazy link query while retaining their own reset queues."""
    first = _wire_interface(
        "GigabitEthernet3",
        "ethernet",
        "iosXeRoutedHost",
        adminState=True,
        ip="198.51.100.1",
        prefix=30,
    )
    second = _wire_interface(
        "GigabitEthernet4",
        "ethernet",
        "iosXeRoutedHost",
        adminState=True,
        ip="198.51.100.5",
        prefix=30,
    )
    for current in (first, second):
        current["configData"]["mode"] = "routed"
        current["configData"]["networkOS"]["networkOSType"] = "ios-xe"
    planner, recorder = _planner(
        responses=[{"interfaces": [first]}, {"interfaces": [second]}],
        summary_responses={
            "SERIAL1": {"interfaces": [_summary_row(first, "SERIAL1")]},
            "SERIAL2": {"interfaces": [_summary_row(second, "SERIAL2")]},
        },
    )
    link_calls = []

    def links_request(orchestrator, *, path, verb, **_kwargs):
        link_calls.append((id(orchestrator), path))
        response = {
            "RETURN_CODE": 200,
            "METHOD": getattr(verb, "value", verb),
            "REQUEST_PATH": path,
            "DATA": {"links": []},
        }
        orchestrator.rest_send._response.append(response)
        orchestrator.rest_send._result.append({"success": True, "changed": False})
        return {"links": []}

    monkeypatch.setattr(EthernetRoutedInterfaceOrchestrator, "_request", links_request)
    resources = [
        {
            "type": "ethernet_routed",
            "state": "deleted",
            "config": [{"switch_ip": "192.0.2.1", "interface_name": "GigabitEthernet3"}],
        },
        {
            "type": "ethernet_routed",
            "state": "deleted",
            "config": [{"switch_ip": "192.0.2.2", "interface_name": "GigabitEthernet4"}],
        },
    ]

    plan = planner.plan(resources)

    assert len(link_calls) == 1
    assert plan.request_stats["fabric_link_gets"] == 1
    assert plan.auxiliary_orchestrators == ()
    assert plan.resources[1].orchestrator._fabric_link_cache_provider is plan.resources[0].orchestrator
    assert all(len(resource.platform_deletes) == 1 for resource in plan.resources)
    assert len(recorder.calls) == 2


@pytest.mark.parametrize("resource_type", ["vpc_access", "vpc_trunk_host"])
def test_vpc_deleted_is_policy_independent_and_pair_consistent(resource_type: str) -> None:
    """vPC deleted accepts a foreign policy only when both peers agree and are deletable."""
    primary = _wire_interface("vpc10", "vpc", "foreignVpcPolicy")
    peer = _wire_interface("vpc10", "vpc", "foreignVpcPolicy")
    planner, _recorder = _planner(
        responses=[{"interfaces": [primary]}, {"interfaces": [peer]}],
        summary_responses={
            "SERIAL1": {"interfaces": [_summary_row(primary, "SERIAL1")]},
            "SERIAL2": {"interfaces": [_summary_row(peer, "SERIAL2")]},
        },
        vpc_pairs={"192.0.2.1": ("192.0.2.1", "192.0.2.2")},
    )

    plan = planner.plan(
        [
            {
                "type": resource_type,
                "state": "deleted",
                "config": [{"switch_ip": "192.0.2.1", "interface_name": "vpc10"}],
            }
        ]
    )

    assert len(plan.resources[0].operations.deletes) == 1
    assert plan.request_stats["interface_summary_gets"] == 2


def test_vpc_transition_rejects_a_record_missing_on_one_peer() -> None:
    """A one-sided vPC record fails before summary lookup or mutation planning."""
    current = _wire_interface("vpc10", "vpc", "foreignVpcPolicy")
    planner, recorder = _planner(
        responses=[{"interfaces": [current]}, {"interfaces": []}],
        vpc_pairs={"192.0.2.1": ("192.0.2.1", "192.0.2.2")},
    )

    with pytest.raises(InterfaceWorkflowValidationError, match="missing on peer"):
        planner.plan([{"type": "vpc_access", "state": "merged", "config": [_vpc("192.0.2.1")]}])

    assert len(recorder.calls) == 2


def test_vpc_transition_rejects_mismatched_peer_policy_data() -> None:
    """Pair records with different policy data fail closed before summary lookup."""
    primary = _wire_interface("vpc10", "vpc", "foreignVpcPolicy", peer1MemberPorts=["Ethernet1/1"])
    peer = _wire_interface("vpc10", "vpc", "foreignVpcPolicy", peer1MemberPorts=["Ethernet1/2"])
    planner, recorder = _planner(
        responses=[{"interfaces": [primary]}, {"interfaces": [peer]}],
        vpc_pairs={"192.0.2.1": ("192.0.2.1", "192.0.2.2")},
    )

    with pytest.raises(InterfaceWorkflowValidationError, match="inconsistent vPC pair records"):
        planner.plan([{"type": "vpc_access", "state": "merged", "config": [_vpc("192.0.2.1")]}])

    assert len(recorder.calls) == 2


def test_vpc_transition_rejects_peer_switch_id_outside_authoritative_pair() -> None:
    """A reciprocal-looking row cannot point outside the configured pair."""
    primary = _wire_interface(
        "vpc10",
        "vpc",
        "foreignVpcPolicy",
        peerSwitchId="SERIAL3",
    )
    peer = _wire_interface("vpc10", "vpc", "foreignVpcPolicy", peerSwitchId="SERIAL1")
    planner, recorder = _planner(
        responses=[{"interfaces": [primary]}, {"interfaces": [peer]}],
        vpc_pairs={"192.0.2.1": ("192.0.2.1", "192.0.2.2")},
    )

    with pytest.raises(InterfaceWorkflowValidationError, match="expected 'SERIAL2'"):
        planner.plan([{"type": "vpc_access", "state": "merged", "config": [_vpc("192.0.2.1")]}])

    assert len(recorder.calls) == 2


def test_vpc_overridden_delete_rejects_a_record_missing_on_one_peer() -> None:
    """An overridden cleanup cannot delete a one-sided vPC record."""
    current = _wire_interface("vpc10", "vpc", "accessVpcHost", accessVlan=10)
    planner, recorder = _planner(
        responses=[{"interfaces": [current]}, {"interfaces": []}],
        vpc_pairs={"192.0.2.1": ("192.0.2.1", "192.0.2.2")},
    )

    with pytest.raises(InterfaceWorkflowValidationError, match="missing on peer"):
        planner.plan([{"type": "vpc_access", "state": "overridden", "config": []}])

    assert len(recorder.calls) == 2


def test_transition_rejects_ethernet_port_channel_member_before_summary() -> None:
    """A physical member cannot be reset or policy-transitioned independently."""
    current = _wire_interface("Ethernet1/1", "ethernet", "routedHost")
    current["operData"] = {"portChannelId": 10}
    planner, recorder = _planner(responses=[{"interfaces": [current]}])

    with pytest.raises(InterfaceWorkflowValidationError, match="member of port-channel 10"):
        planner.plan([{"type": "ethernet_access", "state": "merged", "config": [_ethernet("192.0.2.1")]}])

    assert len(recorder.calls) == 1


def test_same_family_ethernet_member_update_is_preflighted_before_execution() -> None:
    """A prohibited member update fails during planning, before delete-side writes could run."""
    current = _wire_interface("Ethernet1/1", "ethernet", "accessHost", accessVlan=10)
    current["operData"] = {"portChannelId": 20}
    desired = _ethernet("192.0.2.1")
    desired["config_data"]["network_os"]["policy"]["access_vlan"] = 20
    planner, recorder = _planner(responses=[{"interfaces": [current]}])

    with pytest.raises(InterfaceWorkflowValidationError, match="operational port-channel membership 20.*configured policy.*accessHost"):
        planner.plan([{"type": "ethernet_access", "state": "merged", "config": [desired]}])

    assert len(recorder.calls) == 1


def test_same_family_ethernet_member_update_preserves_standalone_whitelist() -> None:
    """Description-only member changes remain allowed by the standalone whitelist."""
    parent = _wire_interface("port-channel20", "portChannel", "accessPoHost", ports=["Ethernet1/1"])
    current = _wire_interface(
        "Ethernet1/1",
        "ethernet",
        "accessPoMember",
        portChannelId="port-channel20",
        description="old",
    )
    current["operData"] = {"portChannelId": 20}
    desired = {
        "switch_ip": "192.0.2.1",
        "interface_names": ["Ethernet1/1"],
        "config_data": {"network_os": {"policy": {"description": "new"}}},
    }
    planner, _recorder = _planner(responses=[{"interfaces": [parent, current]}])

    plan = planner.plan([{"type": "ethernet_access", "state": "merged", "config": [desired]}])

    assert len(plan.resources[0].operations.updates) == 1


@pytest.mark.parametrize(
    ("resource_type", "parent", "interface_type", "policy_type"),
    [
        ("ethernet_access", "Ethernet1/1", "ethernet", "accessHost"),
        ("port_channel_access", "port-channel10", "portChannel", "accessPoHost"),
    ],
)
def test_overridden_parent_delete_rejects_existing_child_subinterface(
    resource_type: str,
    parent: str,
    interface_type: str,
    policy_type: str,
) -> None:
    """Override-generated parent cleanup cannot bypass existing-child protection."""
    current = _wire_interface(parent, interface_type, policy_type)
    child = _wire_interface(f"{parent}.10", "subInterface", "subinterface")
    planner, recorder = _planner(responses=[{"interfaces": [current, child]}, {"interfaces": []}])

    with pytest.raises(InterfaceWorkflowValidationError, match="child subinterfaces exist"):
        planner.plan([{"type": resource_type, "state": "overridden", "config": []}])

    assert len(recorder.calls) == 2


@pytest.mark.parametrize(
    ("resource_type", "config", "parent", "interface_type"),
    [
        ("ethernet_access", _ethernet("192.0.2.1"), "Ethernet1/1", "ethernet"),
        ("port_channel_access", _port_channel("192.0.2.1"), "port-channel10", "portChannel"),
    ],
)
def test_parent_transition_rejects_existing_child_subinterfaces(
    resource_type: str,
    config: dict[str, Any],
    parent: str,
    interface_type: str,
) -> None:
    """Ethernet and port-channel parents both protect existing child subinterfaces."""
    current = _wire_interface(parent, interface_type, "foreignParentPolicy")
    child = _wire_interface(f"{parent}.10", "subInterface", "subinterface")
    planner, recorder = _planner(responses=[{"interfaces": [current, child]}])

    with pytest.raises(InterfaceWorkflowValidationError, match="child subinterfaces exist"):
        planner.plan([{"type": resource_type, "state": "merged", "config": [config]}])

    assert len(recorder.calls) == 1


def test_parent_transition_conflicts_with_planned_child_create() -> None:
    """A planned child operation cannot race its parent policy replacement."""
    current = _wire_interface("Ethernet1/1", "ethernet", "routedHost")
    planner, _recorder = _planner(
        responses=[{"interfaces": [current]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1")]}},
    )
    child = {
        "switch_ip": "192.0.2.1",
        "interface_name": "Ethernet1/1.10",
        "config_data": {"network_os": {"policy": {"vlan_id": 10}}},
    }

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan(
            [
                {"type": "ethernet_access", "state": "merged", "config": [_ethernet("192.0.2.1")]},
                {"type": "subinterface_managed", "state": "merged", "config": [child]},
            ]
        )

    assert "subinterface_parent_prerequisite" in {conflict.code for conflict in exc_info.value.conflicts}


@pytest.mark.parametrize(
    ("resource_type", "parent", "interface_type", "policy_type", "config"),
    [
        (
            "ethernet_access",
            "Ethernet1/1",
            "ethernet",
            "accessHost",
            _ethernet("192.0.2.1"),
        ),
        (
            "port_channel_access",
            "port-channel10",
            "portChannel",
            "accessPoHost",
            _port_channel("192.0.2.1"),
        ),
    ],
)
def test_same_family_parent_update_rejects_existing_child_subinterface(
    resource_type: str,
    parent: str,
    interface_type: str,
    policy_type: str,
    config: dict[str, Any],
) -> None:
    """Ordinary same-family parent updates cannot bypass current-child protection."""
    current = _wire_interface(parent, interface_type, policy_type, accessVlan=10)
    child = _wire_interface(f"{parent}.10", "subInterface", "subinterface")
    config["config_data"]["network_os"]["policy"]["access_vlan"] = 20
    planner, recorder = _planner(responses=[{"interfaces": [current, child]}])

    with pytest.raises(InterfaceWorkflowValidationError, match="child subinterfaces exist"):
        planner.plan([{"type": resource_type, "state": "merged", "config": [config]}])

    assert len(recorder.calls) == 1


@pytest.mark.parametrize(
    ("parent_resource", "parent_config", "child_name", "inventory"),
    [
        (
            "ethernet_access",
            _ethernet("192.0.2.1"),
            "Ethernet1/1.10",
            [_wire_interface("Ethernet1/1", "ethernet", "trunkHost")],
        ),
        (
            "port_channel_access",
            _port_channel("192.0.2.1"),
            "port-channel10.10",
            [],
        ),
    ],
)
def test_parent_create_conflicts_with_planned_child_create(
    parent_resource: str,
    parent_config: dict[str, Any],
    child_name: str,
    inventory: list[dict[str, Any]],
) -> None:
    """Default-Ethernet bulk create and new port-channel create both protect children."""
    planner, _recorder = _planner(responses=[{"interfaces": inventory}])
    child = {
        "switch_ip": "192.0.2.1",
        "interface_name": child_name,
        "config_data": {"network_os": {"policy": {"vlan_id": 10}}},
    }

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan(
            [
                {"type": parent_resource, "state": "merged", "config": [parent_config]},
                {"type": "subinterface_managed", "state": "merged", "config": [child]},
            ]
        )

    assert "subinterface_parent_prerequisite" in {conflict.code for conflict in exc_info.value.conflicts}


@pytest.mark.parametrize(
    ("parent", "expected_reason"),
    [
        (None, "does not exist"),
        (
            _wire_interface("Ethernet1/1", "ethernet", "accessHost", accessVlan=10),
            "expected one of.*routedHost",
        ),
    ],
)
def test_subinterface_write_requires_existing_routed_parent(
    parent: dict[str, Any] | None,
    expected_reason: str,
) -> None:
    """Subinterface writes fail locally when the external routed-parent prerequisite is unmet."""
    inventory = [] if parent is None else [parent]
    planner, _recorder = _planner(responses=[{"interfaces": inventory}])
    child = {
        "switch_ip": "192.0.2.1",
        "interface_name": "Ethernet1/1.10",
        "config_data": {"network_os": {"policy": {"vlan_id": 10}}},
    }

    with pytest.raises(InterfaceWorkflowConflictError, match=expected_reason) as exc_info:
        planner.plan([{"type": "subinterface_managed", "state": "merged", "config": [child]}])

    assert "subinterface_parent_prerequisite" in {conflict.code for conflict in exc_info.value.conflicts}


@pytest.mark.parametrize(
    ("resource_type", "policy"),
    [
        ("subinterface_managed", {"vlan_id": 10}),
        ("subinterface_unmanaged", {}),
    ],
)
def test_subinterface_write_accepts_existing_routed_port_channel_parent(
    resource_type: str,
    policy: dict[str, Any],
) -> None:
    """Both subinterface families accept the routed NX-OS port-channel parent."""
    parent = _wire_interface("port-channel10", "portChannel", "l3Po", mode="routed")
    planner, _recorder = _planner(responses=[{"interfaces": [parent]}])
    child = {
        "switch_ip": "192.0.2.1",
        "interface_name": "port-channel10.10",
        "config_data": {"network_os": {"policy": policy}},
    }

    plan = planner.plan([{"type": resource_type, "state": "merged", "config": [child]}])

    assert len(plan.resources[0].operations.creates) == 1


@pytest.mark.parametrize(
    ("parent_name", "interface_type", "policy_type"),
    [
        ("GigabitEthernet3", "ethernet", "iosXeRoutedHost"),
        ("Port-channel120", "portChannel", "iosXeL3PortChannel"),
    ],
)
def test_ios_xe_subinterface_write_accepts_matching_routed_parent_contract(
    parent_name: str,
    interface_type: str,
    policy_type: str,
) -> None:
    """Final IOS-XE routed Ethernet and port-channel parent policies both satisfy the child contract."""
    parent = _wire_interface(
        parent_name,
        interface_type,
        policy_type,
        network_os_type="ios-xe",
        mode="routed",
    )
    planner, _recorder = _planner(responses=[{"interfaces": [parent]}])
    planner.fabric_context._platform_map = {"192.0.2.1": PlatformType.IOS_XE, "192.0.2.2": PlatformType.IOS_XE}
    child = {
        "switch_ip": "192.0.2.1",
        "interface_name": f"{parent_name}.10",
        "config_data": {
            "network_os": {
                "network_os_type": "ios-xe",
                "policy": {"vlan_id": 10, "ip": "198.51.100.5", "prefix": 30},
            }
        },
    }

    plan = planner.plan([{"type": "subinterface_managed", "state": "merged", "config": [child]}])

    assert len(plan.resources[0].operations.creates) == 1


@pytest.mark.parametrize(
    ("mode", "network_os_type", "expected_reason"),
    [
        ("access", "nx-os", "parent mode is 'access'.*expected 'routed'"),
        ("routed", None, "requires networkOSType 'nx-os'.*reports None"),
    ],
)
def test_subinterface_write_rejects_incomplete_routed_parent_envelope(
    mode: str,
    network_os_type: str | None,
    expected_reason: str,
) -> None:
    """A routed policy name alone cannot authorize a structurally invalid parent."""
    parent = _wire_interface("port-channel10", "portChannel", "l3Po", mode=mode)
    if network_os_type is None:
        parent["configData"]["networkOS"].pop("networkOSType")
    else:
        parent["configData"]["networkOS"]["networkOSType"] = network_os_type
    planner, _recorder = _planner(responses=[{"interfaces": [parent]}])
    child = {
        "switch_ip": "192.0.2.1",
        "interface_name": "port-channel10.10",
        "config_data": {"network_os": {"policy": {"vlan_id": 10}}},
    }

    with pytest.raises(InterfaceWorkflowConflictError, match=expected_reason):
        planner.plan([{"type": "subinterface_managed", "state": "merged", "config": [child]}])


@pytest.mark.parametrize(
    ("parent_network_os", "child_network_os", "expected_reason"),
    [
        ("nx-os", "ios-xe", "requires networkOSType 'ios-xe'.*reports 'nx-os'"),
        ("ios-xe", "nx-os", "child network_os_type is 'nx-os'.*requires 'ios-xe'"),
    ],
)
def test_subinterface_write_rejects_ios_xe_parent_or_child_platform_mismatch(
    parent_network_os: str,
    child_network_os: str,
    expected_reason: str,
) -> None:
    """Policy, parent network OS, and child network OS must describe one platform contract."""
    parent = _wire_interface(
        "GigabitEthernet3",
        "ethernet",
        "iosXeRoutedHost",
        network_os_type=parent_network_os,
        mode="routed",
    )
    planner, _recorder = _planner(responses=[{"interfaces": [parent]}])
    child = {
        "switch_ip": "192.0.2.1",
        "interface_name": "GigabitEthernet3.10",
        "config_data": {
            "network_os": {
                "network_os_type": child_network_os,
                "policy": {"vlan_id": 10},
            }
        },
    }

    with pytest.raises(InterfaceWorkflowConflictError, match=expected_reason) as exc_info:
        planner.plan([{"type": "subinterface_managed", "state": "merged", "config": [child]}])

    assert "subinterface_parent_prerequisite" in {conflict.code for conflict in exc_info.value.conflicts}


def test_routed_parent_create_is_scheduled_before_subinterface_create() -> None:
    """One workflow can create a routed parent and then its managed child."""
    current_parent = _wire_interface("Ethernet1/1", "ethernet", "trunkHost")
    planner, _recorder = _planner(responses=[{"interfaces": [current_parent]}])
    parent = {
        "switch_ip": "192.0.2.1",
        "interface_name": "Ethernet1/1",
        "config_data": {
            "network_os": {
                "network_os_type": "nx-os",
                "policy": {"ip": "198.51.100.1", "prefix": 30},
            }
        },
    }
    child = {
        "switch_ip": "192.0.2.1",
        "interface_name": "Ethernet1/1.10",
        "config_data": {"network_os": {"policy": {"vlan_id": 10}}},
    }

    plan = planner.plan(
        [
            {"type": "subinterface_managed", "state": "merged", "config": [child]},
            {"type": "ethernet_routed", "state": "merged", "config": [parent]},
        ]
    )

    assert [[operation.interface_name for operation in layer] for layer in plan.execution_layers] == [
        ["Ethernet1/1"],
        ["Ethernet1/1.10"],
    ]


def test_subinterface_delete_is_scheduled_before_parent_policy_transition() -> None:
    """Deleting the final child unlocks and precedes its parent's routed transition."""
    current_parent = _wire_interface("Ethernet1/1", "ethernet", "accessHost", accessVlan=10)
    current_child = _wire_interface("Ethernet1/1.10", "subInterface", "subinterface", vlanId=10)
    current_child["configData"]["mode"] = "managed"
    planner, _recorder = _planner(
        responses=[{"interfaces": [current_parent, current_child]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(current_parent, "SERIAL1")]}},
    )
    parent = {
        "switch_ip": "192.0.2.1",
        "interface_name": "Ethernet1/1",
        "config_data": {
            "network_os": {
                "network_os_type": "nx-os",
                "policy": {"ip": "198.51.100.1", "prefix": 30},
            }
        },
    }
    child = {"switch_ip": "192.0.2.1", "interface_name": "Ethernet1/1.10"}

    plan = planner.plan(
        [
            {"type": "ethernet_routed", "state": "merged", "config": [parent]},
            {"type": "subinterface_managed", "state": "deleted", "config": [child]},
        ]
    )

    assert [(layer[0].action, layer[0].interface_name) for layer in plan.execution_layers] == [
        ("delete", "Ethernet1/1.10"),
        ("transition", "Ethernet1/1"),
    ]


def test_policy_independent_subinterface_delete_unblocks_parent_policy_transition() -> None:
    """A foreign-family explicit child delete is classified before parent guards run."""
    current_parent = _wire_interface("Ethernet1/1", "ethernet", "accessHost", accessVlan=10)
    current_child = _wire_interface("Ethernet1/1.10", "subInterface", "subinterface", vlanId=10)
    current_child["configData"]["mode"] = "managed"
    planner, _recorder = _planner(
        responses=[{"interfaces": [current_parent, current_child]}],
        summary_responses={
            "SERIAL1": {
                "interfaces": [
                    _summary_row(current_parent, "SERIAL1"),
                    _summary_row(current_child, "SERIAL1"),
                ]
            }
        },
    )
    parent = {
        "switch_ip": "192.0.2.1",
        "interface_name": "Ethernet1/1",
        "config_data": {
            "network_os": {
                "network_os_type": "nx-os",
                "policy": {"ip": "198.51.100.1", "prefix": 30},
            }
        },
    }
    child = {"switch_ip": "192.0.2.1", "interface_name": "Ethernet1/1.10"}

    plan = planner.plan(
        [
            {"type": "ethernet_routed", "state": "merged", "config": [parent]},
            {"type": "subinterface_unmanaged", "state": "deleted", "config": [child]},
        ]
    )

    assert [(layer[0].action, layer[0].interface_name) for layer in plan.execution_layers] == [
        ("delete", "Ethernet1/1.10"),
        ("transition", "Ethernet1/1"),
    ]


@pytest.mark.parametrize(
    ("resource_type", "config"),
    [
        ("port_channel_access", _port_channel("192.0.2.1", members=["Ethernet1/1", "ethernet1/1"])),
        ("vpc_access", _vpc("192.0.2.1", peer1_members=["Ethernet1/1", "ethernet1/1"])),
    ],
)
def test_duplicate_members_within_one_aggregate_are_rejected(
    resource_type: str,
    config: dict[str, Any],
) -> None:
    """Canonical duplicate members cannot be hidden by conflict-set deduplication."""
    pairs = {"192.0.2.1": ("192.0.2.1", "192.0.2.2")} if resource_type.startswith("vpc_") else None
    planner, _recorder = _planner(vpc_pairs=pairs)

    with pytest.raises(InterfaceWorkflowValidationError, match="contains duplicate"):
        planner.plan([{"type": resource_type, "state": "merged", "config": [config]}])


@pytest.mark.parametrize("current_member", [False, True])
def test_port_channel_current_and_final_members_conflict_with_ethernet_mutation(current_member: bool) -> None:
    """Both current and final port-channel members are protected from Ethernet actions."""
    current = _wire_interface("port-channel10", "portChannel", "foreignPoPolicy", ports=["Ethernet1/1"])
    responses = [{"interfaces": [current]}] if current_member else [{"interfaces": []}]
    summaries = {"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1")]}} if current_member else None
    final_members = ["Ethernet1/2"] if current_member else ["Ethernet1/1"]
    planner, _recorder = _planner(responses=responses, summary_responses=summaries)

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan(
            [
                {
                    "type": "port_channel_access",
                    "state": "merged",
                    "config": [_port_channel("192.0.2.1", members=final_members)],
                },
                {"type": "ethernet_access", "state": "merged", "config": [_ethernet("192.0.2.1")]},
            ]
        )

    assert "ethernet_member_collision" in {conflict.code for conflict in exc_info.value.conflicts}


@pytest.mark.parametrize("current_member", [False, True])
def test_vpc_current_and_final_members_conflict_with_ethernet_mutation(current_member: bool) -> None:
    """Both current and final per-peer vPC members are protected from Ethernet actions."""
    primary = _wire_interface("vpc10", "vpc", "foreignVpcPolicy", peerSwitchId="SERIAL2", peer1MemberPorts=["Ethernet1/1"])
    peer = _wire_interface("vpc10", "vpc", "foreignVpcPolicy", peerSwitchId="SERIAL1", peer1MemberPorts=["Ethernet1/1"])
    responses = [{"interfaces": [primary]}, {"interfaces": [peer]}] if current_member else [{"interfaces": []}, {"interfaces": []}]
    summaries = (
        {
            "SERIAL1": {"interfaces": [_summary_row(primary, "SERIAL1")]},
            "SERIAL2": {"interfaces": [_summary_row(peer, "SERIAL2")]},
        }
        if current_member
        else None
    )
    final_members = ["Ethernet1/2"] if current_member else ["Ethernet1/1"]
    planner, _recorder = _planner(
        responses=responses,
        summary_responses=summaries,
        vpc_pairs={"192.0.2.1": ("192.0.2.1", "192.0.2.2")},
    )

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan(
            [
                {
                    "type": "vpc_access",
                    "state": "merged",
                    "config": [_vpc("192.0.2.1", peer1_members=final_members)],
                },
                {"type": "ethernet_access", "state": "merged", "config": [_ethernet("192.0.2.1")]},
            ]
        )

    assert "ethernet_member_collision" in {conflict.code for conflict in exc_info.value.conflicts}


def test_new_port_channel_cannot_claim_member_of_untouched_existing_port_channel() -> None:
    """Raw aggregate inventory protects members even when their current owner has no planned action."""
    current_owner = _wire_interface(
        "port-channel20",
        "portChannel",
        "accessPoHost",
        ports=["Ethernet1/1"],
    )
    planner, _recorder = _planner(responses=[{"interfaces": [current_owner]}])

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan(
            [
                {
                    "type": "port_channel_access",
                    "state": "merged",
                    "config": [_port_channel("192.0.2.1", "port-channel10", ["Ethernet1/1"])],
                }
            ]
        )

    assert "existing_member_ownership" in {conflict.code for conflict in exc_info.value.conflicts}


def test_existing_port_channel_can_retain_its_operational_member() -> None:
    """The operational backstop allows a member when raw inventory proves the same owner."""
    current_owner = _wire_interface(
        "port-channel10",
        "portChannel",
        "accessPoHost",
        ports=["Ethernet1/1"],
        portChannelMode="active",
        accessVlan=10,
    )
    ethernet = _wire_interface("Ethernet1/1", "ethernet", "trunkHost")
    ethernet["operData"] = {"portChannelId": 10}
    desired = _port_channel("192.0.2.1", "port-channel10", ["Ethernet1/1"])
    desired["config_data"]["network_os"]["policy"]["access_vlan"] = 20
    planner, _recorder = _planner(responses=[{"interfaces": [current_owner, ethernet]}])

    plan = planner.plan([{"type": "port_channel_access", "state": "merged", "config": [desired]}])

    assert len(plan.resources[0].operations.updates) == 1


def test_new_vpc_cannot_claim_member_of_untouched_existing_vpc() -> None:
    """Pair-scoped raw vPC owners protect their physical members without extra GETs."""
    primary = _wire_interface(
        "vpc20",
        "vpc",
        "accessVpcHost",
        peerSwitchId="SERIAL2",
        peer1MemberPorts=["Ethernet1/1"],
    )
    peer = _wire_interface(
        "vpc20",
        "vpc",
        "accessVpcHost",
        peerSwitchId="SERIAL1",
        peer1MemberPorts=["Ethernet1/1"],
    )
    planner, _recorder = _planner(
        responses=[{"interfaces": [primary]}, {"interfaces": [peer]}],
        vpc_pairs={"192.0.2.1": ("192.0.2.1", "192.0.2.2")},
    )

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan(
            [
                {
                    "type": "vpc_access",
                    "state": "merged",
                    "config": [_vpc("192.0.2.1", "vpc10", peer1_members=["Ethernet1/1"])],
                }
            ]
        )

    assert "existing_member_ownership" in {conflict.code for conflict in exc_info.value.conflicts}


def test_new_vpc_cannot_claim_peer2_member_of_untouched_existing_vpc() -> None:
    """Current-owner indexing maps peer2 members onto the resolved peer switch."""
    primary = _wire_interface(
        "vpc20",
        "vpc",
        "accessVpcHost",
        peerSwitchId="SERIAL2",
        peer1MemberPorts=["Ethernet1/1"],
        peer2MemberPorts=["Ethernet1/2"],
    )
    peer = _wire_interface(
        "vpc20",
        "vpc",
        "accessVpcHost",
        peerSwitchId="SERIAL1",
        peer1MemberPorts=["Ethernet1/2"],
        peer2MemberPorts=["Ethernet1/1"],
    )
    planner, _recorder = _planner(
        responses=[{"interfaces": [primary]}, {"interfaces": [peer]}],
        vpc_pairs={"192.0.2.1": ("192.0.2.1", "192.0.2.2")},
    )

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan(
            [
                {
                    "type": "vpc_access",
                    "state": "merged",
                    "config": [_vpc("192.0.2.1", "vpc10", peer2_members=["Ethernet1/2"])],
                }
            ]
        )

    assert "existing_member_ownership" in {conflict.code for conflict in exc_info.value.conflicts}


def test_operational_membership_is_a_fail_closed_backstop() -> None:
    """A positive operational port-channel ID blocks a claim when no owner record proves equivalence."""
    ethernet = _wire_interface("Ethernet1/1", "ethernet", "trunkHost")
    ethernet["operData"] = {"portChannelId": 20}
    planner, _recorder = _planner(responses=[{"interfaces": [ethernet]}])

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan(
            [
                {
                    "type": "port_channel_access",
                    "state": "merged",
                    "config": [_port_channel("192.0.2.1", "port-channel10", ["Ethernet1/1"])],
                }
            ]
        )

    assert "operational_member_ownership" in {conflict.code for conflict in exc_info.value.conflicts}


@pytest.mark.parametrize(
    ("state", "policy_type"),
    [
        ("merged", "routedHost"),
        ("deleted", "accessHost"),
    ],
)
def test_ethernet_only_action_cannot_mutate_untouched_port_channel_member(
    state: str,
    policy_type: str,
) -> None:
    """A parent-owned member is protected even when operational membership is stale."""
    parent = _wire_interface(
        "port-channel10",
        "portChannel",
        "accessPoHost",
        ports=["Ethernet1/1"],
    )
    ethernet = _wire_interface("Ethernet1/1", "ethernet", policy_type, accessVlan=10)
    ethernet["operData"] = {"portChannelId": -1}
    summaries = {"SERIAL1": {"interfaces": [_summary_row(ethernet, "SERIAL1")]}} if state == "merged" else None
    planner, _recorder = _planner(
        responses=[{"interfaces": [parent, ethernet]}],
        summary_responses=summaries,
    )

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan([{"type": "ethernet_access", "state": state, "config": [_ethernet("192.0.2.1")]}])

    assert "ethernet_member_collision" in {conflict.code for conflict in exc_info.value.conflicts}


def test_ethernet_only_action_cannot_mutate_untouched_vpc_member() -> None:
    """A row-local vPC owner protects its member without a vPC resource action."""
    parent = _wire_interface(
        "vpc10",
        "vpc",
        "accessVpcHost",
        peerSwitchId="SERIAL2",
        peer1MemberPorts=["Ethernet1/1"],
        peer1PortChannelId="port-channel10",
    )
    ethernet = _wire_interface("Ethernet1/1", "ethernet", "accessHost", accessVlan=10)
    ethernet["operData"] = {"portChannelId": -1}
    planner, _recorder = _planner(
        responses=[{"interfaces": [parent, ethernet]}],
        vpc_pairs={"192.0.2.1": ("192.0.2.1", "192.0.2.2")},
    )

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan([{"type": "ethernet_access", "state": "deleted", "config": [_ethernet("192.0.2.1")]}])

    assert "ethernet_member_collision" in {conflict.code for conflict in exc_info.value.conflicts}


@pytest.mark.parametrize("state", ["merged", "deleted"])
def test_configured_member_policy_is_a_fail_closed_backstop(state: str) -> None:
    """Configured PoMember state protects a member when parent and operational data are stale."""
    ethernet = _wire_interface(
        "Ethernet1/1",
        "ethernet",
        "accessPoMember",
        portChannelId="port-channel901",
    )
    ethernet["operData"] = {"portChannelId": -1}
    planner, recorder = _planner(responses=[{"interfaces": [ethernet]}])

    desired = {
        "switch_ip": "192.0.2.1",
        "interface_names": ["Ethernet1/1"],
        "config_data": {"network_os": {"policy": {"description": "new"}}},
    }
    with pytest.raises(InterfaceWorkflowValidationError, match="orphaned|member of port-channel 901"):
        planner.plan([{"type": "ethernet_access", "state": state, "config": [desired]}])

    assert len(recorder.calls) == 1


def test_untouched_owner_preserves_whitelisted_ethernet_member_update() -> None:
    """Description-only updates remain valid for a member whose parent is untouched."""
    parent = _wire_interface(
        "port-channel10",
        "portChannel",
        "accessPoHost",
        ports=["Ethernet1/1"],
    )
    ethernet = _wire_interface(
        "Ethernet1/1",
        "ethernet",
        "accessPoMember",
        portChannelId="port-channel10",
        description="old",
    )
    ethernet["operData"] = {"portChannelId": -1}
    desired = {
        "switch_ip": "192.0.2.1",
        "interface_names": ["Ethernet1/1"],
        "config_data": {"network_os": {"policy": {"description": "new"}}},
    }
    planner, _recorder = _planner(responses=[{"interfaces": [parent, ethernet]}])

    plan = planner.plan([{"type": "ethernet_access", "state": "merged", "config": [desired]}])

    assert len(plan.resources[0].operations.updates) == 1


def test_retained_parent_update_precedes_safe_member_update() -> None:
    """A retained parent mutation is ordered before PR #561's safe member PUT."""
    parent = _wire_interface(
        "port-channel10",
        "portChannel",
        "accessPoHost",
        ports=["Ethernet1/1"],
        portChannelMode="active",
        accessVlan=10,
    )
    member = _wire_interface(
        "Ethernet1/1",
        "ethernet",
        "accessPoMember",
        portChannelId="port-channel10",
        description="old",
    )
    member["operData"] = {"portChannelId": -1}
    desired_parent = _port_channel("192.0.2.1", "port-channel10", ["Ethernet1/1"])
    desired_parent["config_data"]["network_os"]["policy"]["access_vlan"] = 20
    desired_member = {
        "switch_ip": "192.0.2.1",
        "interface_names": ["Ethernet1/1"],
        "config_data": {"network_os": {"policy": {"description": "new"}}},
    }
    planner, _recorder = _planner(responses=[{"interfaces": [parent, member]}])

    plan = planner.plan(
        [
            {"type": "ethernet_access", "state": "merged", "config": [desired_member]},
            {"type": "port_channel_access", "state": "merged", "config": [desired_parent]},
        ]
    )

    assert [(layer[0].resource_type, layer[0].interface_name) for layer in plan.execution_layers] == [
        ("port_channel_access", "port-channel10"),
        ("ethernet_access", "Ethernet1/1"),
    ]
    assert plan.execution_layers[1][0].refresh_before is True


def test_parent_policy_transition_rejects_member_update_from_former_family() -> None:
    """A member update cannot follow its owner into an incompatible final policy family."""
    parent = _wire_interface(
        "port-channel10",
        "portChannel",
        "accessPoHost",
        ports=["Ethernet1/1"],
        portChannelMode="active",
        accessVlan=10,
    )
    member = _wire_interface(
        "Ethernet1/1",
        "ethernet",
        "accessPoMember",
        portChannelId="port-channel10",
        description="old",
    )
    member["operData"] = {"portChannelId": -1}
    desired_parent = _port_channel("192.0.2.1", "port-channel10", ["Ethernet1/1"])
    desired_parent["config_data"]["network_os"]["policy"]["allowed_vlans"] = "10-20"
    desired_member = {
        "switch_ip": "192.0.2.1",
        "interface_names": ["Ethernet1/1"],
        "config_data": {"network_os": {"policy": {"description": "new"}}},
    }
    planner, _recorder = _planner(
        responses=[{"interfaces": [parent, member]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(parent, "SERIAL1")]}},
    )

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan(
            [
                {"type": "ethernet_access", "state": "merged", "config": [desired_member]},
                {"type": "port_channel_trunk_host", "state": "merged", "config": [desired_parent]},
            ]
        )

    assert "ethernet_member_collision" in {conflict.code for conflict in exc_info.value.conflicts}


def test_aggregate_update_uses_authoritative_member_registry_for_configured_operational_mismatch() -> None:
    """A matching operational owner cannot hide a contradictory configured member ID."""
    parent = _wire_interface(
        "port-channel10",
        "portChannel",
        "accessPoHost",
        ports=["Ethernet1/1"],
        portChannelMode="active",
        accessVlan=10,
    )
    member = _wire_interface(
        "Ethernet1/1",
        "ethernet",
        "accessPoMember",
        portChannelId="port-channel20",
        portChannelMode="active",
    )
    member["operData"] = {"portChannelId": 10}
    desired = _port_channel("192.0.2.1", "port-channel10", ["Ethernet1/1"])
    desired["config_data"]["network_os"]["policy"]["access_vlan"] = 20
    planner, _recorder = _planner(responses=[{"interfaces": [parent, member]}])

    with pytest.raises(InterfaceWorkflowConflictError, match="configured port-channel ID 20 but operational ID 10") as exc_info:
        planner.plan([{"type": "port_channel_access", "state": "merged", "config": [desired]}])

    assert "member_ownership_validation" in {conflict.code for conflict in exc_info.value.conflicts}


def test_ios_xe_host_conversion_precedes_port_channel_attach(monkeypatch) -> None:
    """The registry-required IOS-XE host policy transition runs before parent creation."""
    monkeypatch.setattr(EthernetBaseOrchestrator, "_fabric_link_endpoints", lambda self: {})
    member = _wire_interface("GigabitEthernet1/0/2", "ethernet", "iosXeTrunkHost")
    member["configData"]["networkOS"]["networkOSType"] = "ios-xe"
    member["operData"] = {"portChannelId": -1}
    planner, _recorder = _planner(
        responses=[{"interfaces": [member]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(member, "SERIAL1")]}},
    )
    desired_member = {
        "switch_ip": "192.0.2.1",
        "interface_names": ["GigabitEthernet1/0/2"],
        "config_data": {
            "network_os": {
                "network_os_type": "ios-xe",
                "policy": {"access_vlan": 100},
            }
        },
    }
    desired_parent = {
        "switch_ip": "192.0.2.1",
        "interface_name": "port-channel101",
        "config_data": {
            "network_os": {
                "network_os_type": "ios-xe",
                "policy": {"access_vlan": 100, "ports": ["GigabitEthernet1/0/2"]},
            }
        },
    }

    plan = planner.plan(
        [
            {"type": "port_channel_access", "state": "merged", "config": [desired_parent]},
            {"type": "ethernet_access", "state": "merged", "config": [desired_member]},
        ]
    )

    assert [(layer[0].action, layer[0].resource_type) for layer in plan.execution_layers] == [
        ("create", "ethernet_access"),
        ("create", "port_channel_access"),
    ]


def test_ios_xe_routed_host_conversion_precedes_routed_port_channel_attach(monkeypatch) -> None:
    """The final routed registry row drives IOS-XE l3 port-channel dependency ordering."""
    monkeypatch.setattr(EthernetBaseOrchestrator, "_fabric_link_endpoints", lambda self: {})
    member = _wire_interface(
        "GigabitEthernet1/0/3",
        "ethernet",
        "iosXeTrunkHost",
        network_os_type="ios-xe",
        mode="trunk",
    )
    member["operData"] = {"portChannelId": -1}
    planner, _recorder = _planner(
        switches={"192.0.2.1": "SERIAL1"},
        responses=[{"interfaces": [member]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(member, "SERIAL1")]}},
    )
    planner.fabric_context._platform_map = {"192.0.2.1": PlatformType.IOS_XE}
    desired_member = {
        "switch_ip": "192.0.2.1",
        "interface_name": "GigabitEthernet1/0/3",
        "config_data": {
            "network_os": {
                "network_os_type": "ios-xe",
                "policy": {},
            }
        },
    }
    desired_parent = {
        "switch_ip": "192.0.2.1",
        "interface_name": "port-channel103",
        "config_data": {
            "network_os": {
                "network_os_type": "ios-xe",
                "policy": {
                    "ip": "198.51.100.1",
                    "prefix": 30,
                    "ports": ["GigabitEthernet1/0/3"],
                },
            }
        },
    }

    plan = planner.plan(
        [
            {"type": "port_channel_routed", "state": "merged", "config": [desired_parent]},
            {"type": "ethernet_routed", "state": "merged", "config": [desired_member]},
        ]
    )

    assert [(layer[0].action, layer[0].resource_type) for layer in plan.execution_layers] == [
        ("create", "ethernet_routed"),
        ("create", "port_channel_routed"),
    ]
    parent_policy = plan.execution_layers[1][0].model.config_data.network_os.policy
    assert parent_policy.policy_type == "iosXeL3PortChannel"


def test_untouched_owner_rejects_non_whitelisted_ethernet_member_update() -> None:
    """A stale operational ID cannot hide a VLAN change to an aggregate member."""
    parent = _wire_interface(
        "port-channel10",
        "portChannel",
        "accessPoHost",
        ports=["Ethernet1/1"],
    )
    ethernet = _wire_interface("Ethernet1/1", "ethernet", "accessHost", accessVlan=10)
    ethernet["operData"] = {"portChannelId": -1}
    desired = _ethernet("192.0.2.1")
    desired["config_data"]["network_os"]["policy"]["access_vlan"] = 20
    planner, _recorder = _planner(responses=[{"interfaces": [parent, ethernet]}])

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan([{"type": "ethernet_access", "state": "merged", "config": [desired]}])

    assert "ethernet_member_collision" in {conflict.code for conflict in exc_info.value.conflicts}


def test_operational_member_id_must_match_the_retained_owner() -> None:
    """A positive operational ID cannot be reconciled to a different retained parent."""
    parent = _wire_interface(
        "port-channel10",
        "portChannel",
        "accessPoHost",
        ports=["Ethernet1/1"],
        portChannelMode="active",
        accessVlan=10,
    )
    ethernet = _wire_interface("Ethernet1/1", "ethernet", "trunkHost")
    ethernet["operData"] = {"portChannelId": 20}
    desired = _port_channel("192.0.2.1", "port-channel10", ["Ethernet1/1"])
    desired["config_data"]["network_os"]["policy"]["access_vlan"] = 20
    planner, _recorder = _planner(responses=[{"interfaces": [parent, ethernet]}])

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan([{"type": "port_channel_access", "state": "merged", "config": [desired]}])

    assert "operational_member_mismatch" in {conflict.code for conflict in exc_info.value.conflicts}


def test_matching_destination_policy_is_idempotent_without_summary() -> None:
    """A converged destination-family interface neither transitions nor fetches safety metadata."""
    current = _wire_interface("Ethernet1/1", "ethernet", "accessHost", accessVlan=10)
    planner, recorder = _planner(responses=[{"interfaces": [current]}])

    plan = planner.plan([{"type": "ethernet_access", "state": "merged", "config": [_ethernet("192.0.2.1")]}])

    assert plan.changed is False
    assert plan.resources[0].transitions == ()
    assert plan.request_stats["interface_summary_gets"] == 0
    assert len(recorder.calls) == 1


def test_override_delete_conflicts_with_another_group_desiring_the_identity() -> None:
    """An override cannot remove an identity retained by a sibling group in the same task."""
    current = _wire_interface("Ethernet1/1", "ethernet", "accessHost", accessVlan=10)
    planner, _recorder = _planner(
        responses=[{"interfaces": [current]}, {"interfaces": []}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1")]}},
    )

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan(
            [
                {"type": "ethernet_access", "state": "overridden", "config": []},
                {"type": "ethernet_trunk_host", "state": "merged", "config": [_ethernet("192.0.2.1", trunk=True)]},
            ]
        )

    codes = {conflict.code for conflict in exc_info.value.conflicts}
    assert "delete_write_collision" in codes
    assert "overridden_ownership" in codes


def test_ethernet_mutation_cannot_race_a_new_port_channel_membership() -> None:
    """A physical port cannot be changed independently while a port-channel claims it."""
    planner, _recorder = _planner()

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan(
            [
                {"type": "ethernet_access", "state": "merged", "config": [_ethernet("192.0.2.1")]},
                {"type": "port_channel_access", "state": "merged", "config": [_port_channel("192.0.2.1")]},
            ]
        )

    assert "ethernet_member_collision" in {conflict.code for conflict in exc_info.value.conflicts}


def test_same_vpc_name_on_different_pairs_is_not_a_global_identity_conflict() -> None:
    """Pair-aware keys preserve equal vPC names on independent pairs."""
    switches = {
        "192.0.2.1": "SERIAL1",
        "192.0.2.2": "SERIAL2",
        "192.0.2.3": "SERIAL3",
        "192.0.2.4": "SERIAL4",
    }
    pairs = {
        "192.0.2.1": ("192.0.2.1", "192.0.2.2"),
        "192.0.2.3": ("192.0.2.3", "192.0.2.4"),
    }
    planner, recorder = _planner(switches=switches, vpc_pairs=pairs)

    plan = planner.plan(
        [
            {"type": "vpc_access", "state": "merged", "config": [_vpc("192.0.2.1")]},
            {"type": "vpc_access", "state": "merged", "config": [_vpc("192.0.2.3")]},
        ]
    )

    assert plan.mutation_count == 2
    assert plan.target_switch_ids == ("SERIAL1", "SERIAL2", "SERIAL3", "SERIAL4")
    assert len(recorder.calls) == 4


def test_overridden_preserves_same_vpc_name_as_two_pair_scoped_records() -> None:
    """Fabric-wide discovery does not collapse equal vPC names on independent pairs."""
    switches = {
        "192.0.2.1": "SERIAL1",
        "192.0.2.2": "SERIAL2",
        "192.0.2.3": "SERIAL3",
        "192.0.2.4": "SERIAL4",
    }
    pairs = {
        "192.0.2.1": ("192.0.2.1", "192.0.2.2"),
        "192.0.2.3": ("192.0.2.3", "192.0.2.4"),
    }
    records = [
        _wire_interface(
            "vpc10",
            "vpc",
            "accessVpcHost",
            accessVlan=10,
            peerSwitchId=peer_id,
        )
        for peer_id in ("SERIAL2", "SERIAL1", "SERIAL4", "SERIAL3")
    ]
    planner, recorder = _planner(
        switches=switches,
        responses=[
            {"interfaces": [records[0]]},
            {"interfaces": [records[1]]},
            {"interfaces": [records[2]]},
            {"interfaces": [records[3]]},
        ],
        vpc_pairs=pairs,
    )

    plan = planner.plan(
        [
            {
                "type": "vpc_access",
                "state": "overridden",
                "config": [],
            }
        ]
    )

    resource = plan.resources[0]
    assert len(resource.before) == 2
    assert len(resource.operations.deletes) == 2
    assert {(item.switch_ip, item.interface_name) for item in resource.operations.deletes} == {
        ("192.0.2.1", "vpc10"),
        ("192.0.2.3", "vpc10"),
    }
    assert len(recorder.calls) == 4


def test_opposite_primaries_on_the_same_vpc_pair_share_one_identity() -> None:
    """The unordered pair discriminator detects same-pair duplicate declarations."""
    pairs = {
        "192.0.2.1": ("192.0.2.1", "192.0.2.2"),
        "192.0.2.2": ("192.0.2.1", "192.0.2.2"),
    }
    planner, _recorder = _planner(vpc_pairs=pairs)

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan(
            [
                {"type": "vpc_access", "state": "merged", "config": [_vpc("192.0.2.1")]},
                {"type": "vpc_access", "state": "merged", "config": [_vpc("192.0.2.2")]},
            ]
        )

    assert "duplicate_ownership" in {conflict.code for conflict in exc_info.value.conflicts}


def test_twelve_family_plan_shares_one_inventory_fetch_per_switch() -> None:
    """The actual workflow path reduces twelve family inventories over two switches to two GETs."""

    def config(switch_ip: str, interface_name: str, policy: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "switch_ip": switch_ip,
            "interface_name": interface_name,
            "config_data": {"network_os": {"policy": policy or {}}},
        }

    planner, recorder = _planner(
        responses=[
            {
                "interfaces": [
                    _wire_interface("Ethernet1/3", "ethernet", "routedHost", mode="routed"),
                ]
            },
            {
                "interfaces": [
                    _wire_interface("Ethernet1/4", "ethernet", "routedHost", mode="routed"),
                ]
            },
        ],
        vpc_pairs={"192.0.2.1": "192.0.2.2"},
    )
    resources = [
        {
            "type": "ethernet_access",
            "state": "merged",
            "config": [_ethernet("192.0.2.1", "Ethernet1/1")],
        },
        {
            "type": "ethernet_routed",
            "state": "merged",
            "config": [
                {
                    "switch_ip": "192.0.2.1",
                    "interface_name": "Ethernet1/5",
                    "config_data": {
                        "network_os": {
                            "network_os_type": "nx-os",
                            "policy": {"ip": "198.51.100.1", "prefix": 30},
                        }
                    },
                }
            ],
        },
        {
            "type": "ethernet_trunk_host",
            "state": "merged",
            "config": [_ethernet("192.0.2.2", "Ethernet1/2", trunk=True)],
        },
        {
            "type": "loopback",
            "state": "merged",
            "config": [_loopback("192.0.2.1", "loopback10")],
        },
        {
            "type": "port_channel_access",
            "state": "merged",
            "config": [config("192.0.2.1", "port-channel10", {"port_channel_mode": "active"})],
        },
        {
            "type": "port_channel_trunk_host",
            "state": "merged",
            "config": [config("192.0.2.2", "port-channel11", {"port_channel_mode": "active"})],
        },
        {
            "type": "port_channel_routed",
            "state": "merged",
            "config": [
                {
                    "switch_ip": "192.0.2.1",
                    "interface_name": "port-channel12",
                    "config_data": {
                        "network_os": {
                            "network_os_type": "nx-os",
                            "policy": {"port_channel_mode": "active"},
                        }
                    },
                }
            ],
        },
        {
            "type": "subinterface_managed",
            "state": "merged",
            "config": [config("192.0.2.1", "Ethernet1/3.10", {"vlan_id": 10})],
        },
        {
            "type": "subinterface_unmanaged",
            "state": "merged",
            "config": [config("192.0.2.2", "Ethernet1/4.20")],
        },
        {
            "type": "svi",
            "state": "merged",
            "config": [config("192.0.2.1", "vlan100")],
        },
        {
            "type": "vpc_access",
            "state": "merged",
            "config": [_vpc("192.0.2.1", "vpc10")],
        },
        {
            "type": "vpc_trunk_host",
            "state": "merged",
            "config": [config("192.0.2.1", "vpc11")],
        },
    ]

    plan = planner.plan(resources)

    assert len(plan.resources) == 12
    assert plan.mutation_count == 12
    assert plan.target_switch_ids == ("SERIAL1", "SERIAL2")
    assert plan.request_stats["interface_inventory_gets"] == 2
    assert len(recorder.calls) == 2


def test_overridden_still_rejects_an_unknown_configured_switch_before_inventory() -> None:
    """Fabric-wide scope cannot hide an invalid switch_ip in desired config."""
    planner, recorder = _planner()

    with pytest.raises(InterfaceWorkflowValidationError, match=r"resources\[0\].*192\.0\.2\.99"):
        planner.plan([{"type": "loopback", "state": "overridden", "config": [_loopback("192.0.2.99")]}])

    assert recorder.calls == []
