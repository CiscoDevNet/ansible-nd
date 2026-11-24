# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Fresh absence and exact owner proof for explicit missing-member preparation."""

from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils import (
    interface_missing_member_preparation as helper,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_family_adapters import (
    INTERFACE_FAMILY_ADAPTERS,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import EthernetBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import InterfaceResourcePlan
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_plan import NDStatePlan
from ansible_collections.cisco.nd.tests.unit.module_utils import test_interface_workflow_planner as planner_fakes


def _wire(name, policy, *, kind="ethernet", mode="trunk", **values):
    if policy == "trunkHost":
        values = {"allowedVlans": "none", **values}
    return {
        "interfaceName": name,
        "interfaceType": kind,
        "switchId": "S1",
        "configData": {
            "mode": mode,
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {"policyType": policy, **values},
            },
        },
        "operData": {"portChannelId": -1},
    }


class Snapshot:
    """Explicit complete inventory fake whose refresh can expose new records."""

    def __init__(self, records=(), next_records=None):
        self.clean_interfaces_by_switch = {"S1": {row["interfaceName"].lower(): deepcopy(row) for row in records}}
        self.next_records = next_records
        self.fabric_name = "fab"
        self.invalidations = 0
        self.refreshes = []
        self.context = SimpleNamespace(
            fabric_name="fab",
            switch_map_by_id={"S1": "192.0.2.1"},
            validate_for_mutation=lambda: None,
            switches=[
                {
                    "switchId": "S1",
                    "fabricName": "fab",
                    "additionalData": {"platformType": "nx-os", "systemMode": "normal"},
                }
            ],
        )

    def invalidate_topology_evidence(self):
        self.invalidations += 1

    def topology_context(self, _factory):
        return self.context

    def refresh(self, ids):
        self.refreshes.append(ids)
        if self.next_records is not None:
            self.clean_interfaces_by_switch["S1"] = {row["interfaceName"].lower(): deepcopy(row) for row in self.next_records}

    def has_switch(self, switch_id):
        return switch_id in self.clean_interfaces_by_switch

    def cached_interface(self, switch_id, name):
        return self.clean_interfaces_by_switch.get(switch_id, {}).get(name.lower())


def _receipt(**overrides):
    orchestrator = SimpleNamespace(
        deploy=False,
        rest_send=SimpleNamespace(),
        _member_peer_serial_cache={},
        _load_staged_detachment_peer=lambda *_args, **_kwargs: None,
        _fabric_link_endpoints=lambda: {},
    )
    model = INTERFACE_FAMILY_ADAPTERS["ethernet_trunk_host"].model_class.from_config(
        {
            "switch_ip": "192.0.2.1",
            "interface_name": "Ethernet1/10",
            "config_data": {"network_os": {"policy": {}}},
        },
        context={"state": "merged"},
    )
    fields = dict(
        model=model,
        resource_index=0,
        resource_type="ethernet_trunk_host",
        parent_resource_index=1,
        parent_switch_id="S1",
        kind="missing_inventory",
        orchestrator=orchestrator,
        switch_id="S1",
        interface_name="Ethernet1/10",
        to_policy_type="trunkHost",
        parent_name="port-channel10",
        parent_policy_type="trunkPoHost",
        expected_member_policy="poMember",
        parent_port_channel_id=10,
    )
    fields.update(overrides)
    return SimpleNamespace(**fields)


def test_fresh_absence_accepts_explicit_normal_mode_nxos_identity():
    snapshot = Snapshot()
    helper.refresh_missing_preparations([_receipt()], snapshot)
    assert snapshot.invalidations == 1
    assert snapshot.refreshes == [["S1"]]


def test_absence_is_rechecked_after_planning():
    snapshot = Snapshot(next_records=[_wire("Ethernet1/10", "trunkHost")])
    with pytest.raises(RuntimeError, match="appeared after planning"):
        helper.refresh_missing_preparations([_receipt()], snapshot)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda context: context.switches[0].update(fabricName="other"),
        lambda context: context.switches[0]["additionalData"].update(platformType="ios-xe"),
        lambda context: context.switches.append(deepcopy(context.switches[0])),
    ],
)
def test_preparation_requires_positive_exact_fabric_nxos_identity(mutate):
    snapshot = Snapshot()
    mutate(snapshot.context)
    with pytest.raises(RuntimeError):
        helper.refresh_missing_preparations([_receipt()], snapshot)


@pytest.mark.parametrize(
    "record",
    [
        _wire("Ethernet1/10.100", "subinterface", kind="subInterface"),
        _wire("port-channel11", "trunkPoHost", kind="portChannel", ports=["Ethernet1/10"]),
        _wire(
            "port-channel11",
            "trunkPoHost",
            kind="portChannel",
            ports={"malformed": True},
        ),
    ],
)
def test_absence_refuses_children_and_parent_claims(record):
    with pytest.raises((RuntimeError, ValueError)):
        helper.refresh_missing_preparations([_receipt()], Snapshot([record]))


def test_absence_refuses_fabric_link_intent():
    receipt = _receipt()
    receipt.orchestrator._fabric_link_endpoints = lambda: {("S1", "ethernet1/10"): {}}
    with pytest.raises(RuntimeError, match="fabric-link"):
        helper.refresh_missing_preparations([receipt], Snapshot())


def test_prepared_phase_requires_expected_policy_and_wire_mode():
    helper.refresh_missing_preparations([_receipt()], Snapshot([_wire("Ethernet1/10", "trunkHost")]), phase="prepared")
    with pytest.raises(RuntimeError, match="unexpected identity, host policy or mode"):
        helper.refresh_missing_preparations(
            [_receipt()],
            Snapshot([_wire("Ethernet1/10", "trunkHost", mode="access")]),
            phase="prepared",
        )


@pytest.mark.parametrize("oper_id", [10, True, "-1"])
def test_prepared_phase_refuses_positive_or_ambiguous_operational_membership(oper_id):
    record = _wire("Ethernet1/10", "trunkHost")
    record["operData"]["portChannelId"] = oper_id
    with pytest.raises(RuntimeError, match="operational membership"):
        helper.refresh_missing_preparations([_receipt()], Snapshot([record]), phase="prepared")


def test_member_phase_proves_exact_real_policy_parent_and_parent_id():
    member = _wire("Ethernet1/10", "poMember", portChannelId="10")
    parent = _wire("port-channel10", "trunkPoHost", kind="portChannel", ports=["Ethernet1/10"])
    snapshot = Snapshot([member, parent])
    helper.refresh_missing_preparations([_receipt()], snapshot, phase="member")
    with pytest.raises(RuntimeError, match="unexpected member policy or aggregate ownership"):
        helper.refresh_missing_preparations([_receipt(parent_port_channel_id=11)], snapshot, phase="member")


def _resource(planner, index, family, policy_type, *, switch_ip="192.0.2.1", name=None, values=None, noop=False):
    """Use real family models and resource plans without controller transports."""
    adapter = INTERFACE_FAMILY_ADAPTERS[family]
    name = name or ("Ethernet1/10" if adapter.ownership_domain == "ethernet" else "port-channel10")
    model = adapter.model_class.from_config(
        {
            "switch_ip": switch_ip,
            "interface_name": name,
            "config_data": {"network_os": {"network_os_type": "nx-os", "policy": {"policy_type": policy_type, **(values or {})}}},
        },
        context={"state": "merged"},
    )
    proposed = NDConfigCollection(adapter.model_class, [model])
    before = proposed.copy() if noop else NDConfigCollection(adapter.model_class)
    operations = NDStatePlan(state="merged", before=before, proposed=proposed, after=proposed.copy(), creates=() if noop else (model,))
    orchestrator = adapter.build_orchestrator(
        rest_send=RestSend(
            {"fabric_name": "fabric_1", "state": "merged", "config": proposed.to_ansible_config(), "check_mode": True, "config_actions": {"deploy": False}}
        ),
        snapshot=planner.snapshot,
    )
    if adapter.ownership_domain == "ethernet":
        planner._register_ethernet_orchestrator(orchestrator)
    return InterfaceResourcePlan(index, adapter, "merged", proposed, before, operations, orchestrator)


def _explicit_resources(*, family="trunk", host_values=None, noop=False, records=None, parent_name="port-channel10"):
    planner, _recorder = planner_fakes._planner(switches={"192.0.2.1": "S1"}, responses=[{"interfaces": records or []}])
    planner.snapshot.load_switch("S1")
    planner_fakes._set_non_vpc_topology(planner)
    ethernet_type, parent_type, host_policy, parent_policy, _member = {
        "access": ("ethernet_access", "port_channel_access", "accessHost", "accessPoHost", "accessPoMember"),
        "trunk": ("ethernet_trunk_host", "port_channel_trunk_host", "trunkHost", "trunkPoHost", "poMember"),
        "routed": ("ethernet_routed", "port_channel_routed", "routedHost", "l3Po", "l3PoMember"),
    }[family]
    ethernet = _resource(planner, 0, ethernet_type, host_policy, values=host_values, noop=noop)
    parent = _resource(planner, 1, parent_type, parent_policy, name=parent_name, values={"ports": ["Ethernet1/10"]}, noop=noop)
    return planner, [ethernet, parent]


@pytest.mark.parametrize(
    "family,expected_host,expected_member",
    [("access", "accessHost", "accessPoMember"), ("trunk", "trunkHost", "poMember"), ("routed", "routedHost", "l3PoMember")],
)
def test_planning_uses_explicit_minimum_family_models(monkeypatch, family, expected_host, expected_member):
    planner, resources = _explicit_resources(family=family)
    calls = []
    monkeypatch.setattr(helper, "refresh_missing_preparations", lambda preparations, _snapshot, **kwargs: calls.append((preparations, kwargs)))
    rewritten, preparations = helper.plan_missing_members(planner, resources)
    assert len(preparations) == 1
    receipt = preparations[0]
    assert receipt.to_policy_type == expected_host
    assert receipt.expected_member_policy == expected_member
    assert receipt.parent_port_channel_id == 10
    assert receipt.kind == "missing_inventory" and receipt.requires_member_update is False
    assert receipt.resource_index == 0 and receipt.parent_resource_index == 1
    assert receipt.model is next(iter(resources[0].proposed))
    assert receipt.orchestrator is resources[0].orchestrator
    assert receipt.model.config_data.network_os.policy.model_fields_set == {"policy_type"}
    assert not rewritten[0].operations.creates and not rewritten[0].operations.updates
    assert rewritten[1] is resources[1]
    assert calls[0][1] == {"phase": "absent"}


def test_parent_only_request_does_not_infer_missing_ethernet_creates(monkeypatch):
    planner, resources = _explicit_resources()
    observed = []
    monkeypatch.setattr(helper, "refresh_missing_preparations", lambda preparations, *_args, **_kwargs: observed.extend(preparations))
    rewritten, preparations = helper.plan_missing_members(planner, [resources[1]])
    assert rewritten == [resources[1]] and preparations == () and observed == []
    assert helper.explicit_member_expectations(planner, [resources[1]]) == ()


@pytest.mark.parametrize("safe_values", [{"description": "Server member"}, {"admin_state": True}])
def test_safe_explicit_fields_receive_post_parent_update(monkeypatch, safe_values):
    planner, resources = _explicit_resources(host_values=safe_values)
    monkeypatch.setattr(helper, "refresh_missing_preparations", lambda *_args, **_kwargs: ())
    rewritten, preparations = helper.plan_missing_members(planner, resources)
    assert preparations[0].requires_member_update is True
    assert rewritten[0].operations.updates == (next(iter(resources[0].proposed)),)
    assert not rewritten[0].operations.creates


@pytest.mark.parametrize("unsafe", [{"allowed_vlans": "100-200"}, {"native_vlan": 100}])
def test_aggregate_owned_ethernet_fields_are_rejected(monkeypatch, unsafe):
    planner, resources = _explicit_resources(host_values=unsafe)

    def refresh(preparations, *_args, **_kwargs):
        assert preparations == []

    monkeypatch.setattr(helper, "refresh_missing_preparations", refresh)
    rewritten, preparations = helper.plan_missing_members(planner, resources)
    assert rewritten == resources and preparations == ()
    assert "ethernet_member_collision" in {row.code for row in planner._find_conflicts(rewritten)}


def test_duplicate_final_claims_fail_before_fresh_reads_or_writes(monkeypatch):
    planner, resources = _explicit_resources()
    second_parent = _resource(planner, 2, "port_channel_trunk_host", "trunkPoHost", name="port-channel11", values={"ports": ["Ethernet1/10"]})
    monkeypatch.setattr(helper, "refresh_missing_preparations", lambda *_args, **_kwargs: pytest.fail("Duplicate intent must fail before reads"))
    with pytest.raises(ValueError, match="duplicate Ethernet or final parent claims"):
        helper.plan_missing_members(planner, [*resources, second_parent])


def test_existing_claim_with_missing_inventory_is_not_silently_repaired():
    current_parent = _wire("port-channel10", "trunkPoHost", kind="portChannel", ports=["Ethernet1/10"])
    planner, resources = _explicit_resources(records=[current_parent])
    with pytest.raises(ValueError, match="already-claimed member missing"):
        helper.plan_missing_members(planner, resources)


@pytest.mark.parametrize("target,expected", [("S1", 10), ("S2", 20)])
def test_vpc_parent_id_uses_actual_member_switch_slot(target, expected):
    parent = SimpleNamespace(switch_ip="192.0.2.1")
    policy = SimpleNamespace(peer1_port_channel_id=10, peer2_port_channel_id=20)
    planner = SimpleNamespace(
        fabric_context=SimpleNamespace(get_switch_id=lambda _ip: "S1"),
        _desired_policy_type=lambda _parent: "trunkVpcHost",
        _policy=lambda _parent: policy,
    )
    claim = SimpleNamespace(parent=parent, member_identity=SimpleNamespace(scope=(target,)))
    assert helper._parent_id(planner, claim) == expected


def test_explicit_vpc_preparation_preserves_both_switch_slots(monkeypatch):
    planner, _recorder = planner_fakes._planner(switches={"192.0.2.1": "S1", "192.0.2.2": "S2"}, vpc_pairs={"192.0.2.1": ("192.0.2.1", "192.0.2.2")})
    for switch_id in ("S1", "S2"):
        planner.snapshot.load_switch(switch_id)
    ethernet1 = _resource(planner, 0, "ethernet_trunk_host", "trunkHost")
    ethernet2 = _resource(planner, 1, "ethernet_trunk_host", "trunkHost", switch_ip="192.0.2.2")
    parent = _resource(
        planner,
        2,
        "vpc_trunk_host",
        "trunkVpcHost",
        name="vpc10",
        values={"peer1_member_ports": ["Ethernet1/10"], "peer2_member_ports": ["Ethernet1/10"], "peer1_port_channel_id": 10, "peer2_port_channel_id": 20},
    )
    monkeypatch.setattr(helper, "refresh_missing_preparations", lambda *_args, **_kwargs: ())
    _rewritten, preparations = helper.plan_missing_members(planner, [ethernet1, ethernet2, parent])
    assert [(row.switch_id, row.parent_port_channel_id, row.parent_resource_index) for row in preparations] == [("S1", 10, 2), ("S2", 20, 2)]
    assert all(row.parent_switch_id == "S1" for row in preparations)


@pytest.mark.parametrize("noop", [False, True])
def test_explicit_expectations_survive_retained_hosts_and_noop_parents(noop):
    planner, resources = _explicit_resources(noop=noop)
    expectations = helper.explicit_member_expectations(planner, resources)
    assert len(expectations) == 1
    receipt = expectations[0]
    assert receipt.expected_member_policy == "poMember" and receipt.parent_port_channel_id == 10
    assert receipt.parent_action == ("noop" if noop else "create")
    assert receipt.resource_index == 0 and receipt.parent_resource_index == 1
    # A retained standalone host is not proof of aggregate membership.
    guarded = replace(receipt, orchestrator=_receipt().orchestrator)
    with pytest.raises(ValueError, match="not an indexed ethernet member"):
        helper.refresh_missing_preparations([guarded], Snapshot([_wire("Ethernet1/10", "trunkHost")]), phase="member")
    member = _wire("Ethernet1/10", "poMember", portChannelId="10")
    parent = _wire("port-channel10", "trunkPoHost", kind="portChannel", ports=["Ethernet1/10"])
    rows = helper.refresh_missing_preparations([guarded], Snapshot([member, parent]), phase="member")
    assert rows[0]["resource_index"] == 0 and rows[0]["parent_resource_index"] == 1
    assert rows[0]["owner_switch_id"] == "S1" and rows[0]["policy_type"] == "poMember"


def test_noop_parent_with_missing_member_fails_final_readback():
    planner, resources = _explicit_resources(noop=True)
    expectations = helper.explicit_member_expectations(planner, resources)
    guarded = replace(expectations[0], orchestrator=_receipt().orchestrator)
    with pytest.raises(ValueError):
        helper.refresh_missing_preparations([guarded], Snapshot(), phase="member")


def test_prepared_readback_must_preserve_minimum_trunk_default():
    with pytest.raises(RuntimeError, match="minimum host field 'allowedVlans'"):
        helper.refresh_missing_preparations(
            [_receipt()],
            Snapshot([_wire("Ethernet1/10", "trunkHost", allowedVlans="all")]),
            phase="prepared",
        )


@pytest.mark.parametrize("source_policy,source_mode", [("accessHost", "access"), ("routedHost", "routed")])
def test_policy_only_existing_host_conversion_precedes_parent_in_real_planner(monkeypatch, source_policy, source_mode):
    source = planner_fakes._wire_interface("Ethernet1/10", "ethernet", source_policy, mode=source_mode)
    source["operData"] = {"portChannelId": -1}
    planner, _recorder = planner_fakes._planner(
        switches={"192.0.2.1": "S1"},
        responses=[{"interfaces": [source]}],
        summary_responses={"S1": {"interfaces": [planner_fakes._summary_row(source, "S1")]}},
    )
    planner_fakes._set_non_vpc_topology(planner)
    monkeypatch.setattr(EthernetBaseOrchestrator, "_fabric_link_endpoints", lambda self: {})
    observations = []
    monkeypatch.setattr(helper, "refresh_missing_preparations", lambda rows, _snapshot, **kwargs: observations.append((rows, kwargs)))
    resources = [
        {
            "type": "ethernet_trunk_host",
            "state": "merged",
            "config": [
                {
                    "switch_ip": "192.0.2.1",
                    "interface_names": ["Ethernet1/10"],
                    "config_data": {"network_os": {"network_os_type": "nx-os", "policy": {"policy_type": "trunkHost"}}},
                }
            ],
        },
        {
            "type": "port_channel_trunk_host",
            "state": "merged",
            "config": [
                {
                    "switch_ip": "192.0.2.1",
                    "interface_name": "port-channel10",
                    "config_data": {"network_os": {"network_os_type": "nx-os", "policy": {"policy_type": "trunkPoHost", "ports": ["Ethernet1/10"]}}},
                }
            ],
        },
    ]

    plan = planner.plan(resources)

    assert len(plan.member_preparations) == 1
    receipt = plan.member_preparations[0]
    assert receipt.kind == "explicit_host_conversion"
    assert receipt.source_action == "transition" and receipt.from_policy_type == source_policy
    assert receipt.to_policy_type == "trunkHost" and receipt.current["configData"] == source["configData"]
    assert receipt.model.config_data.network_os.policy.model_fields_set == {"policy_type"}
    assert receipt.requires_member_update is False
    assert receipt.resource_index == 0 and receipt.parent_resource_index == 1
    assert not plan.resources[0].transitions and not plan.resources[0].operations.creates and not plan.resources[0].operations.updates
    assert [[(item.resource_index, item.action) for item in layer] for layer in plan.execution_layers] == [[(0, "prepare_member")], [(1, "create")]]
    assert observations[0][1] == {"phase": "absent"}
    assert plan.missing_member_verifications[0].parent_policy_type == "trunkPoHost"


def _existing_host_receipt():
    source = _wire("Ethernet1/10", "accessHost", mode="access", accessVlan=10)
    return _receipt(kind="explicit_host_conversion", from_policy_type="accessHost", current=deepcopy(source)), source


def test_existing_host_conversion_rechecks_unchanged_source_before_writing():
    receipt, source = _existing_host_receipt()
    snapshot = Snapshot([source])
    assert helper.refresh_missing_preparations([receipt], snapshot, phase="absent") == ()
    changed = deepcopy(source)
    changed["configData"]["networkOS"]["policy"]["accessVlan"] = 20
    snapshot.next_records = [changed]
    with pytest.raises(RuntimeError, match="source changed"):
        helper.refresh_missing_preparations([receipt], snapshot, phase="absent")
    assert snapshot.refreshes == [["S1"], ["S1"]]


@pytest.mark.parametrize("oper_id", [44, True, "-1"])
def test_existing_host_conversion_refuses_positive_or_ambiguous_membership(oper_id):
    receipt, source = _existing_host_receipt()
    source["operData"]["portChannelId"] = oper_id
    with pytest.raises(RuntimeError, match="positive or ambiguous operational membership"):
        helper.refresh_missing_preparations([receipt], Snapshot([source]), phase="absent")


def test_existing_host_conversion_refuses_foreign_parent_claim():
    receipt, source = _existing_host_receipt()
    parent = _wire("port-channel11", "trunkPoHost", kind="portChannel", ports=["Ethernet1/10"])
    with pytest.raises(RuntimeError, match="existing aggregate ownership"):
        helper.refresh_missing_preparations([receipt], Snapshot([source, parent]), phase="absent")


@pytest.mark.parametrize("noop", [False, True])
def test_safe_explicit_members_keep_preparation_observation_expectations(noop):
    """Safe member settings must remain provable after conversion and on replay."""
    planner, resources = _explicit_resources(host_values={"description": "Server member", "admin_state": True}, noop=noop)
    expectations = helper.explicit_member_expectations(planner, resources)
    assert len(expectations) == 1
    assert expectations[0].resource_index == 0 and expectations[0].parent_resource_index == 1
    assert expectations[0].requires_member_update is True


def test_legacy_physical_conversion_keeps_explicit_member_observation(monkeypatch):
    current = _wire("Ethernet1/10", "accessHost", mode="access")
    planner, resources = _explicit_resources(host_values={"description": "Server member"}, records=[current])
    from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import EthernetBaseOrchestrator

    monkeypatch.setattr(EthernetBaseOrchestrator, "_fabric_link_endpoints", lambda self: {})
    rewritten = planner._split_member_preparations(resources)
    assert len(planner._member_preparations) == 1
    assert planner._member_preparations[0].kind == "existing_host_conversion"
    expectations = helper.explicit_member_expectations(planner, rewritten)
    assert len(expectations) == 1
    assert expectations[0].parent_policy_type == "trunkPoHost"
