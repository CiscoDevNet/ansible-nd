# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for interface-family adapters and aggregate read-only planning."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.interface_family_adapters import (
    IMPLICIT_TRANSITION_STATES,
    INTERFACE_FAMILY_ADAPTERS,
    InterfaceDeleteStrategy,
    InterfaceTransitionStrategy,
    InterfaceWorkflowValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import InterfaceStateSnapshot
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import (
    InterfaceWorkflowConflictError,
    InterfaceWorkflowPlanner,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


class _RequestRecorder:
    """Route queued inventory and per-switch summary bodies and record every request."""

    def __init__(
        self,
        responses: list[dict[str, Any]],
        summary_responses: Mapping[str, dict[str, Any] | list[dict[str, Any]]] | None = None,
    ) -> None:
        self._responses: Iterator[dict[str, Any]] = iter(responses)
        self._summary_responses = {
            switch_id: iter(value if isinstance(value, list) else [value])
            for switch_id, value in (summary_responses or {}).items()
        }
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


def test_registry_declares_generic_transition_delete_and_structural_safety_metadata() -> None:
    """Every adapter advertises its mutation strategy and structural dependency guards."""
    expected = {
        "ethernet_access": (InterfaceDeleteStrategy.NORMALIZE, False, False, True),
        "ethernet_trunk_host": (InterfaceDeleteStrategy.NORMALIZE, False, False, True),
        "loopback": (InterfaceDeleteStrategy.REMOVE, False, False, False),
        "port_channel_access": (InterfaceDeleteStrategy.REMOVE, False, True, True),
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
        assert adapter.supports_intra_family_policy_transitions is (resource_type == "loopback")
        assert not hasattr(adapter, "policy_transition_sources")

    assert IMPLICIT_TRANSITION_STATES == frozenset({"merged", "replaced"})
    assert {
        adapter.delete_strategy for adapter in INTERFACE_FAMILY_ADAPTERS.values()
    } == {
        InterfaceDeleteStrategy.NORMALIZE,
        InterfaceDeleteStrategy.REMOVE,
        InterfaceDeleteStrategy.DELETE,
    }


def test_loopback_adapter_tracks_the_complete_standalone_policy_union() -> None:
    """The workflow owns every policy discriminator now managed by nd_interface_loopback."""
    adapter = INTERFACE_FAMILY_ADAPTERS["loopback"]

    assert adapter.policy_types == frozenset(
        {
            "loopback",
            "ipfmLoopback",
            "mplsLoopback",
            "iosXeLoopback",
            "iosXeLoopbackShutNoshut",
            "iosXeUnderlayLoopback",
            "iosXeInternalLoopback",
            "csrLoopback",
            "csr1kvLoopback",
        }
    )
    assert adapter.supports_intra_family_policy_transitions is True


@pytest.mark.parametrize(
    ("network_os_type", "policy_type"),
    [
        ("nx-os", "loopback"),
        ("nx-os", "ipfmLoopback"),
        ("nx-os", "mplsLoopback"),
        ("ios-xe", "iosXeLoopback"),
        ("ios-xe", "iosXeLoopbackShutNoshut"),
        ("ios-xe", "iosXeUnderlayLoopback"),
        ("ios-xe", "iosXeInternalLoopback"),
        ("ios-xe", "csrLoopback"),
        ("ios-xe", "csr1kvLoopback"),
    ],
)
def test_loopback_adapter_validates_every_policy_union_branch(network_os_type: str, policy_type: str) -> None:
    """Adapter validation delegates all nine branches to the standalone discriminated union."""
    adapter = INTERFACE_FAMILY_ADAPTERS["loopback"]
    proposed = adapter.validate_config(
        [
            _loopback(
                "192.0.2.1",
                network_os_type=network_os_type,
                policy_type=policy_type,
                policy={"admin_state": True},
            )
        ],
        "merged",
        0,
    )

    assert len(proposed) == 1
    assert next(iter(proposed)).policy_type == policy_type


@pytest.mark.parametrize(
    "config_data",
    [
        {"network_os": {"policy": {"policy_type": "loopback", "ip": "198.51.100.10"}}},
        {"network_os": {"network_os_type": "nx-os", "policy": {"ip": "198.51.100.10"}}},
    ],
)
def test_loopback_adapter_does_not_invent_required_discriminators(
    config_data: dict[str, Any],
) -> None:
    """Configured loopbacks missing either discriminator fail exactly as they do in the standalone module."""
    adapter = INTERFACE_FAMILY_ADAPTERS["loopback"]
    config = [
        {
            "switch_ip": "192.0.2.1",
            "interface_name": "loopback10",
            "config_data": config_data,
        }
    ]

    with pytest.raises(InterfaceWorkflowValidationError, match="discriminator"):
        adapter.validate_config(config, "merged", 0)


def test_loopback_identifier_only_delete_remains_valid_without_discriminators() -> None:
    """Deleted state retains the standalone identifier-only input contract."""
    adapter = INTERFACE_FAMILY_ADAPTERS["loopback"]

    proposed = adapter.validate_config(
        [{"switch_ip": "192.0.2.1", "interface_name": "loopback10"}],
        "deleted",
        0,
    )

    assert next(iter(proposed)).config_data is None


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


@pytest.mark.parametrize("state", ["merged", "replaced"])
def test_implicit_ethernet_transition_supports_merged_and_replaced(state: str) -> None:
    """A foreign Ethernet policy is implicitly replaced for both write states."""
    current = _wire_interface("Ethernet1/1", "ethernet", "futureArbitraryPolicy")
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
    assert resource.transitions[0].from_policy_type == "futureArbitraryPolicy"
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
    current = _wire_interface(interface_name, interface_type, f"foreign-{resource_type}")
    inventory = [current]
    if resource_type.startswith("subinterface_"):
        parent_name = interface_name.rsplit(".", 1)[0]
        inventory.append(_wire_interface(parent_name, "ethernet", "routedHost"))
    planner, _recorder = _planner(
        responses=[{"interfaces": inventory}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1")]}},
    )

    plan = planner.plan([{"type": resource_type, "state": "merged", "config": [config]}])

    resource = plan.resources[0]
    assert len(resource.transitions) == 1
    assert resource.operations.creates == ()
    assert resource.transitions[0].to_policy_type in resource.adapter.policy_types


@pytest.mark.parametrize("state", ["merged", "replaced"])
def test_loopback_policy_union_change_is_an_explicit_transition(state: str) -> None:
    """A same-identity NX-OS policy branch change uses one safety-checked replacement PUT plan."""
    current = _wire_loopback("loopback10", "ipfmLoopback", ip="198.51.100.10")
    desired = _loopback(
        "192.0.2.1",
        policy_type="mplsLoopback",
        policy={"ip": "198.51.100.10", "dci_routing_protocol": "isis"},
    )
    planner, recorder = _planner(
        responses=[{"interfaces": [current]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1")]}},
    )

    plan = planner.plan([{"type": "loopback", "state": state, "config": [desired]}])

    resource = plan.resources[0]
    assert len(resource.before) == 1
    assert resource.operations.creates == ()
    assert resource.operations.updates == ()
    assert resource.operations.deletes == ()
    assert len(resource.transitions) == 1
    assert resource.transitions[0].from_policy_type == "ipfmLoopback"
    assert resource.transitions[0].to_policy_type == "mplsLoopback"
    assert next(iter(resource.operations.after)).policy_type == "mplsLoopback"
    assert plan.request_stats["interface_inventory_gets"] == 1
    assert plan.request_stats["interface_summary_gets"] == 1
    assert len(recorder.calls) == 2


def test_same_loopback_policy_branch_remains_an_ordinary_merged_update() -> None:
    """A field change within one union branch keeps merge semantics and needs no safety-summary read."""
    current = _wire_loopback("loopback10", "loopback", ip="198.51.100.10", description="old")
    desired = _loopback(
        "192.0.2.1",
        policy={"ip": "198.51.100.10", "description": "new"},
    )
    planner, recorder = _planner(responses=[{"interfaces": [current]}])

    plan = planner.plan([{"type": "loopback", "state": "merged", "config": [desired]}])

    resource = plan.resources[0]
    assert resource.transitions == ()
    assert len(resource.operations.updates) == 1
    assert plan.request_stats["interface_inventory_gets"] == 1
    assert plan.request_stats["interface_summary_gets"] == 0
    assert len(recorder.calls) == 1


def test_loopback_transition_rejects_a_network_os_discriminator_change() -> None:
    """A policy transition cannot silently turn one physical switch from NX-OS into IOS-XE."""
    current = _wire_loopback("loopback10", "loopback", ip="198.51.100.10")
    desired = _loopback(
        "192.0.2.1",
        network_os_type="ios-xe",
        policy_type="iosXeLoopback",
        policy={"ip": "198.51.100.10"},
    )
    planner, recorder = _planner(
        responses=[{"interfaces": [current]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1")]}},
    )

    with pytest.raises(
        InterfaceWorkflowValidationError,
        match=r"networkOSType .*nx-os.*incompatible with destination .*ios-xe",
    ):
        planner.plan([{"type": "loopback", "state": "merged", "config": [desired]}])

    assert len(recorder.calls) == 2


def test_loopback_transitions_share_one_summary_read_per_switch() -> None:
    """Multiple loopback branch changes reuse the shared inventory and summary snapshots."""
    first = _wire_loopback("loopback10", "ipfmLoopback", ip="198.51.100.10")
    second = _wire_loopback("loopback11", "mplsLoopback", ip="198.51.100.11")
    planner, recorder = _planner(
        responses=[{"interfaces": [first, second]}],
        summary_responses={
            "SERIAL1": {
                "interfaces": [
                    _summary_row(first, "SERIAL1"),
                    _summary_row(second, "SERIAL1"),
                ]
            }
        },
    )
    config = [
        _loopback("192.0.2.1", "loopback10", policy={"ip": "198.51.100.10"}),
        _loopback("192.0.2.1", "loopback11", policy={"ip": "198.51.100.11"}),
    ]

    plan = planner.plan([{"type": "loopback", "state": "merged", "config": config}])

    assert len(plan.resources[0].transitions) == 2
    assert plan.request_stats["interface_inventory_gets"] == 1
    assert plan.request_stats["interface_summary_gets"] == 1
    assert len(recorder.calls) == 2


def test_svi_transition_accepts_switch_virtual_interface_summary_alias() -> None:
    """The interfacesSummary SVI spelling is canonicalized to the raw-record structure."""
    current = _wire_interface("vlan100", "switchVirtualInterface", "foreignSviPolicy")
    planner, _recorder = _planner(
        responses=[{"interfaces": [current]}],
        summary_responses={
            "SERIAL1": {
                "interfaces": [
                    _summary_row(current, "SERIAL1", interfaceType="switchVirtualInterface")
                ]
            }
        },
    )
    config = {
        "switch_ip": "192.0.2.1",
        "interface_name": "vlan100",
        "config_data": {"network_os": {"policy": {}}},
    }

    plan = planner.plan([{"type": "svi", "state": "merged", "config": [config]}])

    assert len(plan.resources[0].transitions) == 1
    assert plan.request_stats["interface_summary_gets"] == 1


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

    plan = planner.plan(
        [{"type": resource_type, "state": "merged", "config": [_vpc("192.0.2.1", trunk=trunk)]}]
    )

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
        summary_responses={
            "SERIAL1": {"interfaces": [_summary_row(first, "SERIAL1"), _summary_row(second, "SERIAL1")]}
        },
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
    ("resource_type", "config", "interface_name", "interface_type"),
    [
        (
            "ethernet_access",
            {"switch_ip": "192.0.2.1", "interface_names": ["Ethernet1/1"]},
            "Ethernet1/1",
            "ethernet",
        ),
        (
            "ethernet_trunk_host",
            {"switch_ip": "192.0.2.1", "interface_names": ["Ethernet1/2"]},
            "Ethernet1/2",
            "ethernet",
        ),
        ("loopback", {"switch_ip": "192.0.2.1", "interface_name": "loopback10"}, "loopback10", "loopback"),
        (
            "port_channel_access",
            {"switch_ip": "192.0.2.1", "interface_name": "port-channel10"},
            "port-channel10",
            "portChannel",
        ),
        (
            "port_channel_trunk_host",
            {"switch_ip": "192.0.2.1", "interface_name": "port-channel11"},
            "port-channel11",
            "portChannel",
        ),
        (
            "subinterface_managed",
            {
                "switch_ip": "192.0.2.1",
                "interface_name": "Ethernet1/3.10",
            },
            "Ethernet1/3.10",
            "subInterface",
        ),
        (
            "subinterface_unmanaged",
            {
                "switch_ip": "192.0.2.1",
                "interface_name": "Ethernet1/4.20",
            },
            "Ethernet1/4.20",
            "subInterface",
        ),
        (
            "svi",
            {
                "switch_ip": "192.0.2.1",
                "interface_name": "vlan100",
            },
            "vlan100",
            "svi",
        ),
    ],
)
def test_deleted_is_policy_independent_within_the_selected_structure(
    resource_type: str,
    config: dict[str, Any],
    interface_name: str,
    interface_type: str,
) -> None:
    """Explicit deleted targets a foreign policy and uses the destination adapter's delete path."""
    current = _wire_interface(interface_name, interface_type, "foreignDeletablePolicy")
    planner, _recorder = _planner(
        responses=[{"interfaces": [current]}],
        summary_responses={"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1")]}},
    )

    plan = planner.plan([{"type": resource_type, "state": "deleted", "config": [config]}])

    resource = plan.resources[0]
    assert resource.transitions == ()
    assert len(resource.operations.deletes) == 1
    assert resource.mutation_count == 1


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

    with pytest.raises(InterfaceWorkflowValidationError, match="cannot update.*member of port-channel 20"):
        planner.plan([{"type": "ethernet_access", "state": "merged", "config": [desired]}])

    assert len(recorder.calls) == 1


def test_same_family_ethernet_member_update_preserves_standalone_whitelist() -> None:
    """Description-only member changes remain allowed by the standalone whitelist."""
    current = _wire_interface("Ethernet1/1", "ethernet", "accessHost", accessVlan=10, description="old")
    current["operData"] = {"portChannelId": 20}
    desired = _ethernet("192.0.2.1")
    desired["config_data"]["network_os"]["policy"]["description"] = "new"
    planner, _recorder = _planner(responses=[{"interfaces": [current]}])

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

    assert "parent_subinterface_collision" in {conflict.code for conflict in exc_info.value.conflicts}


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

    assert "parent_subinterface_collision" in {conflict.code for conflict in exc_info.value.conflicts}


@pytest.mark.parametrize(
    ("parent", "expected_reason"),
    [
        (None, "does not exist"),
        (
            _wire_interface("Ethernet1/1", "ethernet", "accessHost", accessVlan=10),
            "expected routed policy 'routedHost'",
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

    assert "subinterface_parent_prerequisite" in {
        conflict.code
        for conflict in exc_info.value.conflicts
    }


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
    """Both subinterface families accept the documented l3PortChannel parent."""
    parent = _wire_interface("port-channel10", "portChannel", "l3PortChannel")
    planner, _recorder = _planner(responses=[{"interfaces": [parent]}])
    child = {
        "switch_ip": "192.0.2.1",
        "interface_name": "port-channel10.10",
        "config_data": {"network_os": {"policy": policy}},
    }

    plan = planner.plan([{"type": resource_type, "state": "merged", "config": [child]}])

    assert len(plan.resources[0].operations.creates) == 1


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
    summaries = (
        {"SERIAL1": {"interfaces": [_summary_row(current, "SERIAL1")]}}
        if current_member
        else None
    )
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
    primary = _wire_interface(
        "vpc10", "vpc", "foreignVpcPolicy", peerSwitchId="SERIAL2", peer1MemberPorts=["Ethernet1/1"]
    )
    peer = _wire_interface(
        "vpc10", "vpc", "foreignVpcPolicy", peerSwitchId="SERIAL1", peer1MemberPorts=["Ethernet1/1"]
    )
    responses = (
        [{"interfaces": [primary]}, {"interfaces": [peer]}]
        if current_member
        else [{"interfaces": []}, {"interfaces": []}]
    )
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
    summaries = (
        {"SERIAL1": {"interfaces": [_summary_row(ethernet, "SERIAL1")]}}
        if state == "merged"
        else None
    )
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
        planner.plan(
            [{"type": "ethernet_access", "state": "deleted", "config": [_ethernet("192.0.2.1")]}]
        )

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

    with pytest.raises(InterfaceWorkflowValidationError, match="member of port-channel 901"):
        planner.plan([{"type": "ethernet_access", "state": state, "config": [_ethernet("192.0.2.1")]}])

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
        "accessHost",
        accessVlan=10,
        description="old",
    )
    ethernet["operData"] = {"portChannelId": -1}
    desired = _ethernet("192.0.2.1")
    desired["config_data"]["network_os"]["policy"]["description"] = "new"
    planner, _recorder = _planner(responses=[{"interfaces": [parent, ethernet]}])

    plan = planner.plan([{"type": "ethernet_access", "state": "merged", "config": [desired]}])

    assert len(plan.resources[0].operations.updates) == 1


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
    assert {
        (item.switch_ip, item.interface_name)
        for item in resource.operations.deletes
    } == {
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


def test_ten_family_plan_shares_one_inventory_fetch_per_switch() -> None:
    """The actual workflow path reduces ten family inventories over two switches to two GETs."""

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
                    _wire_interface("Ethernet1/3", "ethernet", "routedHost"),
                ]
            },
            {
                "interfaces": [
                    _wire_interface("Ethernet1/4", "ethernet", "routedHost"),
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
