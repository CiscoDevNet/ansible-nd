# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# SPDX-License-Identifier: GPL-3.0-or-later

"""Actual L2 preparation evidence, scope and no-transport safety."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.interface_family_adapters import (
    INTERFACE_FAMILY_ADAPTERS,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_actual_noop_upserts import actual_noop_upserts
from ansible_collections.cisco.nd.plugins.module_utils.interface_preparation_observation import (
    preparation_observation,
    validate_preparation_plan,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_contract import (
    request_sha256,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import (
    InterfaceWorkflowValidationError,
)

PARAMS = {
    "config_actions": {"deploy": False},
    "verify": {"enabled": True},
    "execution_options": {"preparation_only": True},
}


class Snapshot:
    def __init__(self, inventory):
        self._interfaces_by_switch = inventory
        self.original = deepcopy(inventory)
        self._overlay_baselines_by_switch = {}
        self.dirty = set()
        self.fabric_context = SimpleNamespace(get_switch_id=lambda ip: {"10.0.0.1": "S1", "10.0.0.2": "S2"}[ip])

    def has_switch(self, serial):
        return serial in self._interfaces_by_switch and serial not in self.dirty

    def cached_interface(self, serial, name, *, original=False):
        return deepcopy((self.original if original else self._interfaces_by_switch).get(serial, {}).get(name.casefold()))

    @staticmethod
    def switch_revision(_serial):
        return 3

    @staticmethod
    def refresh(*_args):
        pytest.fail("Readiness proof cannot fetch inventory")


def fixture(family="ethernet_access", *, changed=False, members=False):
    adapter = INTERFACE_FAMILY_ADAPTERS[family]
    domain = adapter.ownership_domain
    name = "Ethernet1/1" if domain == "ethernet" else "port-channel10" if domain == "port_channel" else "vpc10"
    policy = {"policy_type": next(p for p in adapter.policy_types if not p.startswith("iosXe"))}
    if family.endswith("access"):
        policy["access_vlan"] = 100
    else:
        policy["allowed_vlans"] = "100-200"
    if members and domain == "port_channel":
        policy["ports"] = ["Ethernet1/1"]
    if domain == "vpc":
        policy.update(peer1_port_channel_id=10, peer2_port_channel_id=20)
        if members:
            policy.update(peer1_member_ports=["Ethernet1/1"], peer2_member_ports=["Ethernet1/2"])
    config = {
        "switch_ip": "10.0.0.1",
        "config_data": {"network_os": {"network_os_type": "nx-os", "policy": policy}},
    }
    config["interface_names" if domain == "ethernet" else "interface_name"] = [name] if domain == "ethernet" else name
    proposed = adapter.validate_config([config], "replaced", 0)
    desired = next(iter(proposed))
    raw = desired.to_payload()
    raw["switchId"] = "S1"
    raw_policy = raw["configData"]["networkOS"]["policy"]
    if domain == "vpc":
        raw_policy["peerSwitchId"] = "S2"
        if "peer1AllowedVlans" in raw_policy:
            raw_policy["allowedVlans"] = raw_policy.pop("peer1AllowedVlans")
            raw_policy.pop("peer2AllowedVlans")
        if "peer1AccessVlan" in raw_policy:
            raw_policy["accessVlan"] = raw_policy.pop("peer1AccessVlan")
            raw_policy.pop("peer2AccessVlan")
    inventory = {"S1": {name.casefold(): raw}}
    peers = {}
    if domain == "vpc":
        secondary = deepcopy(raw)
        secondary["switchId"] = "S2"
        secondary["configData"]["networkOS"]["policy"]["peerSwitchId"] = "S1"
        inventory["S2"] = {name.casefold(): secondary}
        peers = {"S1": "S2", "S2": "S1"}
    if members:
        member_policy = {
            "port_channel_access": "accessPoMember",
            "port_channel_trunk_host": "poMember",
            "vpc_access": "accessVpcPoMember",
            "vpc_trunk_host": "vpcMember",
        }[family]
        for serial, member_name, po_id in [
            ("S1", "Ethernet1/1", 10),
            *(([("S2", "Ethernet1/2", 20)]) if domain == "vpc" else []),
        ]:
            inventory[serial][member_name.casefold()] = {
                "switchId": serial,
                "interfaceName": member_name,
                "interfaceType": "ethernet",
                "configData": {
                    "mode": raw["configData"]["mode"],
                    "networkOS": {
                        "networkOSType": "nx-os",
                        "policy": {
                            "policyType": member_policy,
                            "portChannelId": str(po_id),
                        },
                    },
                },
                "operData": {"portChannelId": -1, "operationalStatus": "down"},
            }
            if domain == "vpc":
                inventory[serial][member_name.casefold()]["configData"]["networkOS"]["policy"]["primaryInterface"] = name
    snapshot = Snapshot(inventory)
    resource = SimpleNamespace(
        resource_index=0,
        resource_type=family,
        adapter=adapter,
        state="replaced",
        proposed=proposed,
        orchestrator=SimpleNamespace(_peer_serial_cache=peers),
        operations=SimpleNamespace(creates=(desired,) if changed else (), updates=(), deletes=()),
        transitions=(),
        platform_deletes=(),
    )
    plan = SimpleNamespace(resources=(resource,), target_switch_ids=tuple(inventory), changed=changed)
    return plan, snapshot


def observe(plan, snapshot, **kwargs):
    return preparation_observation(params=PARAMS, plan=plan, snapshot=snapshot, request_sha256=request_sha256(PARAMS), **kwargs)


@pytest.mark.parametrize(
    "family",
    [
        "ethernet_access",
        "ethernet_trunk_host",
        "port_channel_access",
        "port_channel_trunk_host",
        "vpc_access",
        "vpc_trunk_host",
    ],
)
def test_ready_l2_configurations_use_only_actual_cached_rows(family):
    plan, snapshot = fixture(family)
    before = deepcopy(snapshot._interfaces_by_switch)
    result = observe(plan, snapshot)
    assert result["observed"] and result["complete"] and result["all_satisfied"], result
    assert result["request_sha256"] == request_sha256(PARAMS)
    assert snapshot._interfaces_by_switch == before


@pytest.mark.parametrize(
    "family",
    ["port_channel_access", "port_channel_trunk_host", "vpc_access", "vpc_trunk_host"],
)
def test_configured_members_are_ready_without_operational_lacp(family):
    plan, snapshot = fixture(family, members=True)
    result = observe(plan, snapshot)
    assert result["complete"] and result["all_satisfied"], result
    details = result["resources"][0]["targets"][0]["member_policies"]
    assert len(details) == (2 if family.startswith("vpc_") else 1)


def test_typed_view_cannot_hide_routed_raw_residue():
    plan, snapshot = fixture("ethernet_trunk_host")
    snapshot._interfaces_by_switch["S1"]["ethernet1/1"]["configData"]["networkOS"]["policy"]["ip"] = "192.0.2.1"
    result = observe(plan, snapshot)
    assert result["complete"] and not result["all_satisfied"]
    assert result["resources"][0]["targets"][0]["reason"] == "conflicting_routed_policy_fields"


def test_wrong_member_policy_does_not_certify_parent_readiness():
    plan, snapshot = fixture("port_channel_trunk_host", members=True)
    snapshot._interfaces_by_switch["S1"]["ethernet1/1"]["configData"]["networkOS"]["policy"]["policyType"] = "trunkHost"
    result = observe(plan, snapshot)
    assert not result["complete"] and not result["all_satisfied"]


@pytest.mark.parametrize("fault", ["missing_peer", "changed_peer", "dirty_peer", "one_sided_pair", "wrong_peer_record"])
def test_pair_aware_proof_rejects_incomplete_or_conflicting_peer(fault):
    plan, snapshot = fixture("vpc_trunk_host")
    if fault == "missing_peer":
        snapshot._interfaces_by_switch["S2"].clear()
    elif fault == "changed_peer":
        snapshot._interfaces_by_switch["S2"]["vpc10"]["configData"]["networkOS"]["policy"]["allowedVlans"] = "200"
    elif fault == "dirty_peer":
        snapshot.dirty.add("S2")
    elif fault == "wrong_peer_record":
        snapshot._interfaces_by_switch["S2"]["vpc10"]["configData"]["networkOS"]["policy"]["peerSwitchId"] = "OTHER"
    else:
        plan.resources[0].orchestrator._peer_serial_cache.pop("S2")
    result = observe(plan, snapshot)
    assert not result["all_satisfied"], result


def test_projected_or_unverified_mutations_cannot_certify_readiness():
    plan, snapshot = fixture(changed=True)
    for kwargs in [{"check_mode": True}, {"verified": False}]:
        result = observe(plan, snapshot, **kwargs)
        assert not result["observed"] and not result["complete"]
    assert observe(plan, snapshot, verified=True)["all_satisfied"]
    snapshot._overlay_baselines_by_switch["S1"] = {}
    assert not observe(plan, snapshot, verified=True)["complete"]


def test_unrelated_fabric_peer_metadata_does_not_expand_readiness_scope():
    plan, snapshot = fixture("vpc_trunk_host")
    plan.resources[0].orchestrator._peer_serial_cache.update({"UNRELATED1": "UNRELATED2", "UNRELATED2": "UNRELATED1"})
    assert observe(plan, snapshot)["all_satisfied"]


@pytest.mark.parametrize("trunk", [False, True])
@pytest.mark.parametrize("missing_vpc_peer", [False, True])
def test_real_snapshot_local_parent_does_not_require_unrelated_switch_peer_inventory(trunk, missing_vpc_peer):
    """Leaf1 local Po plus leaf3/4 vPC needs three inventories, never leaf2."""
    from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import InterfaceStateSnapshot

    local_plan, local = fixture("port_channel_trunk_host" if trunk else "port_channel_access", members=True)
    paired_plan, paired = fixture("vpc_trunk_host" if trunk else "vpc_access", members=True)
    parent = paired_plan.resources[0]
    config = next(iter(parent.proposed)).to_config()
    config["switch_ip"] = "10.0.0.3"
    parent.proposed = parent.adapter.validate_config([config], "replaced", 1)
    parent.resource_index = 1
    mapping = {"S1": "S3", "S2": "S4"}
    inventories = {"S1": local._interfaces_by_switch["S1"]}
    for serial, rows in paired._interfaces_by_switch.items():
        inventories[mapping[serial]] = deepcopy(rows)
        for raw in inventories[mapping[serial]].values():
            raw["switchId"] = mapping[serial]
            policy = raw["configData"]["networkOS"]["policy"]
            if policy.get("peerSwitchId") in mapping:
                policy["peerSwitchId"] = mapping[policy["peerSwitchId"]]
    peers = {"S1": "S2", "S2": "S1", "S3": "S4", "S4": "S3"}
    local_plan.resources[0].orchestrator._peer_serial_cache = peers
    parent.orchestrator._peer_serial_cache = peers
    addresses = {"10.0.0.%s" % number: "S%s" % number for number in range(1, 5)}
    context = SimpleNamespace(fabric_name="FABRIC", get_switch_id=addresses.__getitem__, switch_map_by_id={serial: ip for ip, serial in addresses.items()})
    requests = []

    def request(*, path, **_kwargs):
        requests.append(path)
        serial = path.split("/switches/")[1].split("/")[0]
        assert serial != "S2", "Ordinary local Po must not fetch its fabric vPC peer"
        rows = list(inventories[serial].values())
        return {"interfaces": rows, "meta": {"counts": {"total": len(rows), "remaining": 0}}}

    snapshot = InterfaceStateSnapshot(fabric_name="FABRIC", fabric_context=context, request=request)
    snapshot.load_switches(("S1", "S3", "S4"))
    assert snapshot.has_switch("S2") is False
    if missing_vpc_peer:
        snapshot.invalidate("S4")
    plan = SimpleNamespace(resources=(*local_plan.resources, parent), target_switch_ids=("S1", "S3", "S4"), changed=False)

    result = observe(plan, snapshot)

    assert len(requests) == 3, "Readiness must reuse already complete cached inventories"
    if missing_vpc_peer:
        assert result["complete"] is False and result["all_satisfied"] is False
        assert result["reason"] == "incomplete_clean_switch_observation"
    else:
        assert result["observed"] is True and result["complete"] is True and result["all_satisfied"] is True, result


def test_missing_target_and_actual_configuration_difference_fail_readiness():
    plan, snapshot = fixture()
    snapshot._interfaces_by_switch["S1"]["ethernet1/1"]["configData"]["networkOS"]["policy"]["accessVlan"] = 200
    assert not observe(plan, snapshot)["all_satisfied"]
    snapshot._interfaces_by_switch["S1"].clear()
    assert not observe(plan, snapshot)["all_satisfied"]


def test_preparation_preflight_rejects_implicit_member_retirement():
    plan, snapshot = fixture("port_channel_trunk_host", changed=True, members=True)
    snapshot.original["S1"]["port-channel10"]["configData"]["networkOS"]["policy"]["ports"].append("Ethernet1/2")
    with pytest.raises(InterfaceWorkflowValidationError, match="retire aggregate members"):
        validate_preparation_plan(params=PARAMS, plan=plan, snapshot=snapshot)


def test_preparation_preflight_allows_addition_without_retirement():
    plan, snapshot = fixture("port_channel_trunk_host", changed=True, members=True)
    snapshot.original["S1"]["port-channel10"]["configData"]["networkOS"]["policy"]["ports"] = []
    validate_preparation_plan(params=PARAMS, plan=plan, snapshot=snapshot)


@pytest.mark.parametrize("fault", ["deploy", "unverified", "delete", "override"])
def test_preparation_preflight_rejects_incompatible_execution_or_scope(fault):
    plan, snapshot = fixture()
    params = deepcopy(PARAMS)
    if fault == "deploy":
        params["config_actions"]["deploy"] = True
    elif fault == "unverified":
        params["verify"]["enabled"] = False
    else:
        plan.resources[0].state = "deleted" if fault == "delete" else "overridden"
    with pytest.raises(InterfaceWorkflowValidationError):
        validate_preparation_plan(params=params, plan=plan, snapshot=snapshot)


def test_disabled_preparation_preserves_ordinary_request_binding():
    normal = {"fabric_name": "FABRIC", "resources": [], "verify": {"enabled": True}, "config_actions": {"deploy": False}}
    disabled = dict(normal, execution_options={"preparation_only": False})
    enabled = dict(normal, execution_options={"preparation_only": True})
    assert request_sha256(normal) == request_sha256(disabled)
    assert request_sha256(normal) != request_sha256(enabled)


def _actual_noop_fixture(family="vpc_access"):
    plan, snapshot = fixture(family, members=True)
    plan.mutation_count = 0
    policy = snapshot._interfaces_by_switch["S1"]["vpc10"]["configData"]["networkOS"]["policy"]
    for serial, number in (("S1", 10), ("S2", 20)):
        generated = {
            "policyType": "accessVpcMember" if family.endswith("access") else "trunkVpcMember",
            "primaryInterface": "vpc10",
            "portChannelId": f"port-channel{number}",
        }
        generated.update({key: policy[key] for key in ("accessVlan", "allowedVlans", "nativeVlan") if key in policy})
        snapshot._interfaces_by_switch[serial][f"port-channel{number}"] = {
            "switchId": serial,
            "interfaceName": f"port-channel{number}",
            "interfaceType": "portChannel",
            "configData": {"mode": "access" if family.endswith("access") else "trunk", "networkOS": {"networkOSType": "nx-os", "policy": generated}},
            "operData": {"portChannelId": -1, "operationalStatus": "down"},
        }
    return plan, snapshot


def _actual_noop(plan, snapshot, params=None):
    return actual_noop_upserts(params=params or PARAMS, plan=plan, snapshot=snapshot, request_sha256="a" * 64, desired_digest="b" * 64)


@pytest.mark.parametrize("family", ["vpc_access", "vpc_trunk_host"])
def test_actual_noop_proves_generated_pair_without_reads_copies_or_replanning(family, monkeypatch):
    plan, snapshot = _actual_noop_fixture(family)
    before = deepcopy(snapshot._interfaces_by_switch)
    snapshot.cached_interface = lambda *_args, **_kwargs: pytest.fail("Proof must borrow cached raw rows without copying")
    from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import InterfaceWorkflowPlanner

    monkeypatch.setattr(InterfaceWorkflowPlanner, "plan", lambda *_args, **_kwargs: pytest.fail("Proof must not replan"))

    proof = _actual_noop(plan, snapshot)

    assert proof["complete"] is True and proof["all_satisfied"] is True and proof["observed"] is True
    assert proof["source"] == "native_actual_noop_upserts_v1"
    generated = proof["resources"][0]["targets"][0]["vpc"]["generated_aggregates"]
    assert [(item["switch_id"], item["interface_name"]) for item in generated] == [("S1", "port-channel10"), ("S2", "port-channel20")]
    assert snapshot._interfaces_by_switch == before


def test_actual_noop_keeps_all_ordinary_targets_and_original_resource_indices():
    plan, snapshot = _actual_noop_fixture()
    ethernet, _unused = fixture("ethernet_trunk_host")
    ordinary = ethernet.resources[0]
    ordinary.resource_index = 1
    ordinary.proposed = ordinary.adapter.validate_config(
        [
            {
                "switch_ip": "10.0.0.1",
                "interface_names": ["Ethernet1/3"],
                "config_data": {"network_os": {"policy": {"allowed_vlans": "100-200"}}},
            }
        ],
        "replaced",
        1,
    )
    desired = next(iter(ordinary.proposed))
    snapshot._interfaces_by_switch["S1"]["ethernet1/3"] = dict(desired.to_payload(), switchId="S1")
    plan.resources = (*plan.resources, ordinary)

    proof = _actual_noop(plan, snapshot)

    assert proof["all_satisfied"] is True
    assert [(group["resource_index"], group["type"]) for group in proof["resources"]] == [(0, "vpc_access"), (1, "ethernet_trunk_host")]
    assert proof["resources"][1]["targets"][0]["interface_name"] == "Ethernet1/3"


@pytest.mark.parametrize(
    "fault",
    [
        "changed",
        "count",
        "deleted",
        "overridden",
        "dirty_peer",
        "missing_parent",
        "wrong_owner",
        "wrong_id",
        "wrong_vlan",
        "wrong_member",
        "deploy",
        "unverified",
    ],
)
def test_actual_noop_declines_mutation_removal_or_incomplete_generated_footprint(fault):
    plan, snapshot = _actual_noop_fixture()
    params = deepcopy(PARAMS)
    local = snapshot._interfaces_by_switch["S2"]["port-channel20"]["configData"]["networkOS"]["policy"]
    if fault == "changed":
        plan.changed = True
    elif fault == "count":
        plan.mutation_count = 1
    elif fault in {"deleted", "overridden"}:
        plan.resources[0].state = fault
    elif fault == "dirty_peer":
        snapshot.dirty.add("S2")
    elif fault == "missing_parent":
        del snapshot._interfaces_by_switch["S2"]["port-channel20"]
    elif fault == "wrong_owner":
        local["primaryInterface"] = "vpc11"
    elif fault == "wrong_id":
        local["portChannelId"] = 99
    elif fault == "wrong_vlan":
        local["accessVlan"] = 101
    elif fault == "wrong_member":
        snapshot._interfaces_by_switch["S2"]["ethernet1/2"]["configData"]["networkOS"]["policy"]["policyType"] = "poMember"
    elif fault == "deploy":
        params["config_actions"]["deploy"] = True
    else:
        params["verify"]["enabled"] = False
    proof = _actual_noop(plan, snapshot, params)
    assert proof["complete"] is False and proof["all_satisfied"] is False


def _deferred_fixture(family="port_channel_trunk_host"):
    from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
    from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import (
        InterfaceResourcePlan,
        InterfaceWorkflowPlan,
        InterfaceWorkflowOperation,
    )

    original, snapshot = fixture(family, members=True)
    snapshot.request_stats = {}
    adapter = original.resources[0].adapter
    raw = snapshot._interfaces_by_switch["S1"]["port-channel10"]
    raw["configData"]["networkOS"]["policy"]["ports"] = ["Ethernet1/1", "Ethernet1/2"]
    second = deepcopy(snapshot._interfaces_by_switch["S1"]["ethernet1/1"])
    second["interfaceName"] = "Ethernet1/2"
    snapshot._interfaces_by_switch["S1"]["ethernet1/2"] = second
    snapshot.original = deepcopy(snapshot._interfaces_by_switch)
    current = adapter.model_class.from_response(dict(raw, switchIp="10.0.0.1"))
    config = next(iter(original.resources[0].proposed)).to_config()
    config["config_data"]["network_os"]["policy"]["ports"] = ["Ethernet1/1", "Ethernet1/3"]
    proposed = adapter.validate_config([config], "replaced", 0)
    before = NDConfigCollection(adapter.model_class, [current])
    operations = adapter.plan(before=before, proposed=proposed, state="replaced")
    owner = SimpleNamespace(_peer_serial_cache={}, fabric_context=snapshot.fabric_context)
    resource = InterfaceResourcePlan(0, adapter, "replaced", proposed, before, operations, owner)
    operation = InterfaceWorkflowOperation(0, family, "update", "S1", "port-channel10", operations.updates[0])
    plan = InterfaceWorkflowPlan("FABRIC", ("S1",), (resource,), {}, execution_layers=((operation,),))
    params = deepcopy(PARAMS)
    params["execution_options"].update(desired_equality=True, defer_ready_membership=True)
    params.update(fabric_name="FABRIC", resources=[{"type": family, "state": "replaced", "config": [config]}])
    return plan, snapshot, params


@pytest.mark.parametrize("family", ["port_channel_access", "port_channel_trunk_host"])
def test_deferred_membership_is_actual_ready_but_not_future_desired_equality(family, monkeypatch):
    from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_coordinator import InterfaceWorkflowCoordinator

    plan, snapshot, params = _deferred_fixture(family)
    before = deepcopy(snapshot._interfaces_by_switch)
    module = SimpleNamespace(params=params, check_mode=False)
    coordinator = InterfaceWorkflowCoordinator(module)
    coordinator._snapshot = snapshot
    monkeypatch.setattr(coordinator, "_build_plan", lambda: plan)
    coordinator.executor_factory = lambda **_kwargs: pytest.fail("Deferred-only preparation must perform no writes")

    result = coordinator.run()

    proof = result["preparation_observation"]
    target = proof["resources"][0]["targets"][0]
    assert proof["all_ready"] is True and proof["all_satisfied"] is False
    assert target["satisfied"] is False and target["ready"] is True and target["non_membership_satisfied"] is True
    assert target["disposition"] == "deferred_membership"
    assert target["members"] == ["Ethernet1/1", "Ethernet1/2"]
    assert target["desired_members"] == ["Ethernet1/1", "Ethernet1/3"]
    assert result["resources"][0]["operations"] == [] and result["resources"][0]["after_verified"] is True
    assert result["resources"][0]["after"][0]["config_data"]["network_os"]["policy"]["ports"] == ["Ethernet1/1", "Ethernet1/2"]
    assert result["write_receipt"]["no_mutation_attempted"] is True
    assert "desired_equality" not in result
    assert snapshot._interfaces_by_switch == before
    assert list(plan.resources[0].proposed)[0].config_data.network_os.policy.ports == ["Ethernet1/1", "Ethernet1/3"]
    assert plan.mutation_count == 1  # Original desired plan is untouched.


@pytest.mark.parametrize("fault", ["vlan", "description", "wrong_current_member", "no_opt_in"])
def test_membership_retirement_without_exact_current_readiness_still_rejects(fault, monkeypatch):
    from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_coordinator import InterfaceWorkflowCoordinator

    plan, snapshot, params = _deferred_fixture()
    if fault in {"vlan", "description"}:
        policy = plan.resources[0].operations.updates[0].config_data.network_os.policy
        setattr(policy, "allowed_vlans" if fault == "vlan" else "description", "200" if fault == "vlan" else "changed")
    elif fault == "wrong_current_member":
        snapshot._interfaces_by_switch["S1"]["ethernet1/2"]["configData"]["networkOS"]["policy"]["policyType"] = "trunkHost"
    else:
        params["execution_options"].pop("defer_ready_membership")
    coordinator = InterfaceWorkflowCoordinator(SimpleNamespace(params=params, check_mode=False))
    coordinator._snapshot = snapshot
    monkeypatch.setattr(coordinator, "_build_plan", lambda: plan)
    coordinator.executor_factory = lambda **_kwargs: pytest.fail("Unsafe preparation must not write")
    with pytest.raises(InterfaceWorkflowValidationError):
        coordinator.run()
