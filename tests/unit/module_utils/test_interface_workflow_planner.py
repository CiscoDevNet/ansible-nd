# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for interface-family adapters and aggregate read-only planning."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.interface_family_adapters import (
    INTERFACE_FAMILY_ADAPTERS,
    InterfaceWorkflowValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import InterfaceStateSnapshot
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import (
    InterfaceWorkflowConflictError,
    InterfaceWorkflowPlanner,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


class _RequestRecorder:
    """Return queued interface-list bodies and record every inventory request."""

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self._responses: Iterator[dict[str, Any]] = iter(responses)
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return next(self._responses)


def _planner(
    *,
    switches: Mapping[str, str] | None = None,
    responses: list[dict[str, Any]] | None = None,
    vpc_pairs: Mapping[str, str | tuple[str, str]] | None = None,
) -> tuple[InterfaceWorkflowPlanner, _RequestRecorder]:
    switch_map = dict(switches or {"192.0.2.1": "SERIAL1", "192.0.2.2": "SERIAL2"})
    recorder = _RequestRecorder(responses or [{"interfaces": []} for _switch in switch_map])
    rest_send = RestSend({"fabric_name": "fabric_1", "check_mode": True})
    context = FabricContext(rest_send=rest_send, fabric_name="fabric_1")
    context._fabric_summary = {"local": True, "fabricStatus": "default"}
    context._switch_map = switch_map
    context._switch_map_by_id = {switch_id: switch_ip for switch_ip, switch_id in switch_map.items()}
    snapshot = InterfaceStateSnapshot(fabric_name="fabric_1", fabric_context=context, request=recorder)
    return InterfaceWorkflowPlanner(snapshot=snapshot, vpc_pair_by_switch_ip=vpc_pairs), recorder


def _loopback(switch_ip: str, name: str = "loopback10") -> dict[str, Any]:
    return {
        "switch_ip": switch_ip,
        "interface_name": name,
        "config_data": {"network_os": {"policy": {"ip": "198.51.100.10/32"}}},
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


def _vpc(switch_ip: str, name: str = "vpc10") -> dict[str, Any]:
    return {
        "switch_ip": switch_ip,
        "interface_name": name,
        "config_data": {"network_os": {"policy": {"access_vlan": 10}}},
    }


def _wire_interface(name: str, interface_type: str, policy_type: str, **policy: Any) -> dict[str, Any]:
    return {
        "interfaceName": name,
        "interfaceType": interface_type,
        "configData": {
            "mode": "access",
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {"policyType": policy_type, **policy},
            },
        },
    }


def test_registry_is_the_exact_ten_family_scope_and_delegates_model_ownership() -> None:
    """The authoritative registry excludes flow-rules and derives every model from its orchestrator."""
    assert set(INTERFACE_FAMILY_ADAPTERS) == {
        "ethernet_access",
        "ethernet_trunk_host",
        "loopback",
        "port_channel_access",
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


def test_create_over_a_current_sibling_policy_requires_an_explicit_transition() -> None:
    """A family-filtered create cannot silently collide with existing sibling ownership."""
    current = _wire_interface("Ethernet1/1", "ethernet", "accessHost", accessVlan=10)
    planner, _recorder = _planner(responses=[{"interfaces": [current]}])

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan([{"type": "ethernet_trunk_host", "state": "merged", "config": [_ethernet("192.0.2.1", trunk=True)]}])

    assert "existing_policy_ownership" in {conflict.code for conflict in exc_info.value.conflicts}


def test_override_delete_conflicts_with_another_group_desiring_the_identity() -> None:
    """An override cannot remove an identity retained by a sibling group in the same task."""
    current = _wire_interface("Ethernet1/1", "ethernet", "accessHost", accessVlan=10)
    planner, _recorder = _planner(responses=[{"interfaces": [current]}, {"interfaces": []}])

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


def test_ten_family_plan_shares_one_inventory_fetch_per_switch() -> None:
    """The actual workflow path reduces ten family inventories over two switches to two GETs."""

    def config(switch_ip: str, interface_name: str, policy: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "switch_ip": switch_ip,
            "interface_name": interface_name,
            "config_data": {"network_os": {"policy": policy or {}}},
        }

    planner, recorder = _planner(vpc_pairs={"192.0.2.1": "192.0.2.2"})
    resources = [
        {
            "type": "ethernet_access",
            "state": "merged",
            "config": [_ethernet("192.0.2.1", "Ethernet1/1")],
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

    assert len(plan.resources) == 10
    assert plan.mutation_count == 10
    assert plan.target_switch_ids == ("SERIAL1", "SERIAL2")
    assert plan.request_stats["interface_inventory_gets"] == 2
    assert len(recorder.calls) == 2


def test_overridden_still_rejects_an_unknown_configured_switch_before_inventory() -> None:
    """Fabric-wide scope cannot hide an invalid switch_ip in desired config."""
    planner, recorder = _planner()

    with pytest.raises(InterfaceWorkflowValidationError, match=r"resources\[0\].*192\.0\.2\.99"):
        planner.plan([{"type": "loopback", "state": "overridden", "config": [_loopback("192.0.2.99")]}])

    assert recorder.calls == []


def test_vpc_create_detects_a_sibling_policy_observed_only_on_the_peer() -> None:
    """Pair-scoped current-policy checks inspect both preloaded peer inventories."""
    peer_current = _wire_interface("vpc10", "vpc", "trunkVpcHost")
    pairs = {"192.0.2.1": ("192.0.2.1", "192.0.2.2")}
    planner, _recorder = _planner(
        responses=[{"interfaces": []}, {"interfaces": [peer_current]}],
        vpc_pairs=pairs,
    )

    with pytest.raises(InterfaceWorkflowConflictError) as exc_info:
        planner.plan([{"type": "vpc_access", "state": "merged", "config": [_vpc("192.0.2.1")]}])

    assert "existing_policy_ownership" in {conflict.code for conflict in exc_info.value.conflicts}
