import copy
import json
import pathlib
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from nd_prerequisite_orchestrator import (
    SWITCH_TOPOLOGY_MUTATION_PROFILES,
    ApiErrorTracker,
    OrchestrationError,
    build_phase_schedule,
    build_snapshot,
    evaluate_restore,
    main,
    plan_topology_delta,
    quarantine,
    resolve_execution,
    runtime_vars_for_execution,
    snapshot_path,
    validate_api_status,
    validate_snapshot_lineage,
    write_restricted_json,
    write_restricted_yaml,
)
from validate_nd_prerequisites import load_registry


@pytest.fixture
def registry():
    return load_registry(ROOT / "tests/nd_prerequisite_profiles.yaml")


@pytest.fixture
def valid_state():
    return yaml.safe_load((ROOT / "tests/fixtures/nd_prerequisite/valid_state.yaml").read_text())


def confirm(registry, profile_id):
    result = copy.deepcopy(registry)
    result["profiles"][profile_id]["confirmation"] = {
        "status": "confirmed", "owner": "fixture-owner", "evidence": "fixture-contract", "reasons": [],
    }
    return result


def confirm_vpc_executions(registry):
    result = confirm(registry, "integration.nd_vpc_pair")
    executions = result["profile_executions"]["integration.nd_vpc_pair"]
    executions[0].update(pair_mode="virtual", physical_peer_links=[])
    executions[1].update(
        switch_refs=["external_edge_1", "external_edge_2"],
        desired_roles=["edge_router", "edge_router"],
        pair_mode="virtual",
        physical_peer_links=[],
    )
    for execution in executions:
        execution["confirmation"] = {
            "status": "confirmed", "owner": "fixture-owner", "evidence": "fixture-contract", "reasons": [],
        }
    return result


def test_pending_profile_and_implicit_multi_execution_are_rejected(registry):
    with pytest.raises(OrchestrationError, match="owner confirmation is pending"):
        resolve_execution(registry, "integration.nd_manage_policy")
    confirmed = confirm_vpc_executions(registry)
    with pytest.raises(OrchestrationError, match="explicit execution ID"):
        resolve_execution(confirmed, "integration.nd_vpc_pair")


def test_allow_auto_confirm_resolves_concrete_pending_execution(registry):
    resolved = resolve_execution(registry, "integration.nd_manage_policy", allow_auto_confirm=True)
    assert resolved["profile_id"] == "integration.nd_manage_policy"

    advanced = resolve_execution(registry, "integration.nd_vpc_pair.advanced", allow_auto_confirm=True)
    assert advanced["execution_id"] == "integration.nd_vpc_pair.advanced"
    assert advanced["execution"]["pair_mode"] == "virtual"

    with pytest.raises(OrchestrationError, match="pair_mode is unresolved"):
        resolve_execution(registry, "integration.nd_vpc_pair.external", allow_auto_confirm=True)

    schedule = build_phase_schedule(
        registry,
        ["integration.nd_manage_policy", "integration.nd_vpc_pair.advanced"],
        allow_auto_confirm=True,
    )
    assert [phase["phase_id"] for phase in schedule] == ["advanced_leaf", "vpc_pair_isolated"]


def test_phase_schedule_is_registry_ordered_and_expands_vpc(registry):
    confirmed = confirm_vpc_executions(registry)
    for profile_id in (
        "smoke.nd_manage_prefix_list",
        "integration.nd_manage_policy",
        "integration.nd_manage_switches",
    ):
        confirmed = confirm(confirmed, profile_id)
    schedule = build_phase_schedule(
        confirmed,
        [
            "integration.nd_manage_switches",
            "integration.nd_vpc_pair",
            "integration.nd_manage_policy",
            "smoke.nd_manage_prefix_list",
        ],
    )
    assert [phase["phase_id"] for phase in schedule] == [
        "retained_no_switch", "advanced_leaf", "vpc_pair_isolated",
    ]
    vpc_ids = next(item["execution_ids"] for item in schedule if item["phase_id"] == "vpc_pair_isolated")
    assert vpc_ids == ["integration.nd_vpc_pair.advanced", "integration.nd_vpc_pair.external"]


def test_ordinary_profiles_refuse_switch_topology_mutation(registry, valid_state):
    policy_registry = confirm(registry, "integration.nd_manage_policy")
    drifted = copy.deepcopy(valid_state)
    drifted["switches"]["vxlan_leaf_1"]["role"] = "border"
    policy = resolve_execution(policy_registry, "integration.nd_manage_policy")
    with pytest.raises(OrchestrationError, match="verify-only.*refusing role change"):
        plan_topology_delta(policy_registry, policy, drifted)

    moved = copy.deepcopy(valid_state)
    moved["switches"]["vxlan_leaf_1"]["fabric_ref"] = "external"
    with pytest.raises(OrchestrationError, match="verify-only.*refusing membership change"):
        plan_topology_delta(policy_registry, policy, moved)

    missing = copy.deepcopy(valid_state)
    missing["switches"].pop("vxlan_leaf_1")
    assert plan_topology_delta(policy_registry, policy, missing) == [{
        "operation": "ensure_switch_membership",
        "switch_ref": "vxlan_leaf_1",
        "serial": "SERIAL00001",
        "fabric_ref": "advanced",
        "desired_role": "leaf",
    }]


def test_switch_topology_mutation_allowlist_is_integration_only():
    assert SWITCH_TOPOLOGY_MUTATION_PROFILES == {
        "integration.nd_manage_fabric",
        "integration.nd_manage_switches",
        "integration.nd_resource_manager",
    }
    assert all(profile_id.startswith("integration.") for profile_id in SWITCH_TOPOLOGY_MUTATION_PROFILES)


def test_smoke_profiles_refuse_switch_topology_mutation(registry, valid_state):
    resource_registry = confirm(registry, "smoke.nd_manage_resource_manager")
    resource = resolve_execution(resource_registry, "smoke.nd_manage_resource_manager")
    drifted = copy.deepcopy(valid_state)
    drifted["switches"]["vxlan_leaf_1"]["role"] = "border"
    with pytest.raises(OrchestrationError, match="verify-only.*refusing role change"):
        plan_topology_delta(resource_registry, resource, drifted)


def test_permitted_switch_profile_can_reconcile_role_drift(registry, valid_state):
    switch_registry = confirm(registry, "integration.nd_manage_switches")
    drifted = copy.deepcopy(valid_state)
    drifted["switches"]["vxlan_spine_1"]["role"] = "leaf"
    resolved = resolve_execution(switch_registry, "integration.nd_manage_switches")
    operations = plan_topology_delta(switch_registry, resolved, drifted)
    assert operations == [{
        "operation": "change_role",
        "switch_ref": "vxlan_spine_1",
        "serial": "SERIAL00003",
        "fabric_ref": "advanced",
        "current_role": "leaf",
        "desired_role": "spine",
    }]


def test_non_topology_prerequisites_remain_available(registry, valid_state):

    group_registry = confirm(registry, "integration.nd_manage_policy_group")
    group = resolve_execution(group_registry, "integration.nd_manage_policy_group")
    operations = plan_topology_delta(group_registry, group, valid_state)
    assert operations == []

    bfd_missing = copy.deepcopy(valid_state)
    bfd_missing["fabrics"]["advanced"]["bfd_enabled"] = False
    l3out_registry = confirm(registry, "integration.nd_manage_l3out")
    l3out = resolve_execution(l3out_registry, "integration.nd_manage_l3out")
    assert plan_topology_delta(l3out_registry, l3out, bfd_missing) == [
        {"operation": "ensure_bfd", "fabric_ref": "advanced"},
    ]


def test_delta_creates_only_namespaced_disposable_fabric(registry, valid_state):
    confirmed = confirm(registry, "smoke.nd_manage_fabric_ibgp_vxlan")
    state = copy.deepcopy(valid_state)
    state["fabrics"].pop("disposable_ibgp", None)
    resolved = resolve_execution(confirmed, "smoke.nd_manage_fabric_ibgp_vxlan")
    assert plan_topology_delta(confirmed, resolved, state) == [{
        "operation": "create_disposable_fabric",
        "fabric_ref": "disposable_ibgp",
        "name": "ANSIBLE_NIGHTLY_IBGP",
        "fabric_type": "vxlanIbgp",
    }]

    retained_missing = copy.deepcopy(valid_state)
    retained_missing["fabrics"].pop("advanced")
    policy_registry = confirm(registry, "integration.nd_manage_policy")
    with pytest.raises(OrchestrationError, match="retained fabric advanced is missing"):
        plan_topology_delta(
            policy_registry,
            resolve_execution(policy_registry, "integration.nd_manage_policy"),
            retained_missing,
        )


def test_delta_enforces_link_allowlist_virtual_vpc_and_resources(registry, valid_state):
    confirmed = confirm(registry, "integration.nd_interface_vpc_access")
    state = copy.deepcopy(valid_state)
    state["interfaces"]["vxlan_leaf_1"]["Ethernet1/3"]["admin_state"] = False
    state["vpc_pairs"] = []
    resolved = resolve_execution(confirmed, "integration.nd_interface_vpc_access")
    operations = plan_topology_delta(confirmed, resolved, state)
    assert any(item["operation"] == "ensure_interface" and item["switch_ref"] == "vxlan_leaf_1" for item in operations)
    vpc = [item for item in operations if item["operation"] == "ensure_virtual_vpc"]
    assert vpc == [{
        "operation": "ensure_virtual_vpc", "fabric_ref": "advanced",
        "peer_refs": ["vxlan_leaf_1", "vxlan_leaf_2"], "physical_peer_links": [],
    }]

    broken = copy.deepcopy(state)
    broken["interfaces"]["vxlan_leaf_1"].pop("Ethernet1/3")
    with pytest.raises(OrchestrationError, match="required physical interface is missing"):
        plan_topology_delta(confirmed, resolved, broken)

    resource_registry = confirm(registry, "smoke.nd_manage_resource_manager")
    resource = resolve_execution(resource_registry, "smoke.nd_manage_resource_manager")
    resource_ops = plan_topology_delta(resource_registry, resource, valid_state)
    assert resource_ops == [{
        "operation": "verify_resource",
        "resource": {"kind": "pool", "name": "L3_VNI", "type": "ID", "state": "existing"},
    }]

    entity_registry = confirm(registry, "integration.nd_resource_manager")
    entity_resource = resolve_execution(entity_registry, "integration.nd_resource_manager")
    entity_ops = plan_topology_delta(entity_registry, entity_resource, valid_state)
    assert not any(item["operation"] == "verify_resource" for item in entity_ops)

    fabric_registry = confirm(registry, "integration.nd_manage_fabric")
    fabric_profile = resolve_execution(fabric_registry, "integration.nd_manage_fabric")
    assert plan_topology_delta(fabric_registry, fabric_profile, valid_state) == []

    missing_pair_state = copy.deepcopy(valid_state)
    missing_pair_state["vpc_pairs"] = []
    with pytest.raises(OrchestrationError, match="profile forbids creation"):
        plan_topology_delta(entity_registry, entity_resource, missing_pair_state)


def test_snapshots_have_strict_lineage_and_restricted_writes(tmp_path, valid_state):
    l0 = build_snapshot("L0", "run-1", valid_state)
    l1 = build_snapshot(
        "L1", "run-1", valid_state, phase_id="advanced_leaf", parent_snapshot_id=l0["snapshot_id"],
    )
    l2 = build_snapshot(
        "L2", "run-1", valid_state, phase_id="advanced_leaf",
        profile_id="integration.nd_manage_policy", execution_id="integration.nd_manage_policy",
        parent_snapshot_id=l1["snapshot_id"],
    )
    assert validate_snapshot_lineage(l0, l1, l2) == []
    stale = copy.deepcopy(l2)
    stale["parent_snapshot_id"] = "wrong"
    assert "L2 parent does not match L1" in validate_snapshot_lineage(l0, l1, stale)

    state_dir = tmp_path / ".nd-prerequisite-recovery" / "run-1"
    yaml_path = snapshot_path(state_dir, "L0")
    json_path = snapshot_path(state_dir, "L1", phase_id="advanced_leaf").with_suffix(".json")
    assert yaml_path == state_dir / "L0" / "job.yaml"
    assert snapshot_path(
        state_dir, "L2", phase_id="advanced_leaf", execution_id="integration.nd_manage_policy",
    ) == state_dir / "L2" / "advanced_leaf" / "integration.nd_manage_policy.yaml"
    write_restricted_yaml(yaml_path, l0)
    write_restricted_json(json_path, l1)
    assert state_dir.stat().st_mode & 0o777 == 0o700
    assert yaml_path.stat().st_mode & 0o777 == 0o600
    assert json_path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(OrchestrationError, match="already exists"):
        write_restricted_yaml(yaml_path, l0)


def test_runtime_vars_are_fresh_and_execution_specific(registry):
    confirmed = confirm(registry, "integration.nd_manage_policy")
    resolved = resolve_execution(confirmed, "integration.nd_manage_policy")
    runtime = runtime_vars_for_execution(resolved, "run-22", "phase-baseline-3")
    assert runtime["fabric_name"] == "VXLAN_EVPN_Fabric"
    assert [item["name"] for item in runtime["nd_test_fabric_switches"]["VXLAN_EVPN_Fabric"]] == [
        "vxlan_leaf_1", "vxlan_leaf_2", "vxlan_spine_1", "vxlan_border_1",
    ]
    assert [item["name"] for item in runtime["nd_test_fabric_switches"]["External_Connectivity_Fabric"]] == [
        "external_edge_1", "external_edge_2",
    ]
    assert runtime["nd_prerequisite_prepared"] is True
    assert runtime["nd_prerequisite_run_id"] == "run-22"
    assert runtime["nd_prerequisite_profile"] == "integration.nd_manage_policy"
    assert runtime["nd_prerequisite_execution_id"] == "integration.nd_manage_policy"
    assert runtime["nd_prerequisite_phase_baseline_id"] == "phase-baseline-3"

    vpc_registry = confirm_vpc_executions(registry)
    vpc = resolve_execution(vpc_registry, "integration.nd_vpc_pair.advanced")
    vpc_runtime = runtime_vars_for_execution(vpc, "run-23", "phase-baseline-4")
    assert vpc_runtime["fabric_name"] == "VXLAN_EVPN_Fabric"
    assert vpc_runtime["fabric_type"] == "vxlanIbgp"
    assert vpc_runtime["switch1_serial"] == "SERIAL00001"
    assert vpc_runtime["switch2_serial"] == "SERIAL00002"

    resolved["profile"]["runtime_vars"]["nd_test_fabric_switches"] = {}
    with pytest.raises(OrchestrationError, match="collide with canonical topology"):
        runtime_vars_for_execution(resolved, "run-24", "phase-baseline-5")


def test_snapshot_and_quarantine_reject_credentials_and_symlinked_state(tmp_path, valid_state):
    secret_state = copy.deepcopy(valid_state)
    secret_state["switch_password"] = "must-not-serialize"
    with pytest.raises(OrchestrationError, match="credential-like"):
        build_snapshot("L0", "run-1", secret_state)

    real = tmp_path / ".nd-prerequisite-recovery" / "real"
    real.mkdir(parents=True)
    linked = tmp_path / ".nd-prerequisite-recovery" / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(OrchestrationError, match="symlink"):
        quarantine(linked, "run-1", "integration.nd_manage_policy", ["switches"])


def test_http_207_and_three_consecutive_api_errors_fail_closed():
    with pytest.raises(OrchestrationError, match="HTTP 207"):
        validate_api_status(207, [{"switchId": "x", "message": "partial"}])
    tracker = ApiErrorTracker(max_consecutive_errors=3)
    assert tracker.observe(success=False) == 1
    assert tracker.observe(success=False) == 2
    with pytest.raises(OrchestrationError, match="3 consecutive API errors"):
        tracker.observe(success=False)
    assert tracker.observe(success=True) == 0


def test_restore_mismatch_quarantines_and_keeps_recovery_material(tmp_path, valid_state):
    after = copy.deepcopy(valid_state)
    after["switches"]["vxlan_leaf_1"]["role"] = "border"
    mismatches = evaluate_restore(valid_state, after, ["switches", "fabrics"])
    assert mismatches == ["switches"]
    state_dir = tmp_path / ".nd-prerequisite-recovery" / "run-1"
    state_dir.mkdir(parents=True)
    marker = quarantine(state_dir, "run-1", "integration.nd_manage_policy", mismatches)
    assert marker.name == "QUARANTINED"
    assert marker.stat().st_mode & 0o777 == 0o600
    report = json.loads((state_dir / "recovery-report.json").read_text())
    assert report["mismatched_domains"] == ["switches"]


def test_cli_plan_and_schedule_emit_json(capsys):
    registry_path = ROOT / "tests/nd_prerequisite_profiles.yaml"
    state_path = ROOT / "tests/fixtures/nd_prerequisite/valid_state.yaml"
    assert main([
        "plan", "--registry", str(registry_path),
        "--execution-id", "integration.nd_manage_policy",
        "--state", str(state_path), "--allow-auto-confirm",
        "--run-id", "run-9", "--phase-baseline-id", "phase-9",
    ]) == 0
    plan_output = json.loads(capsys.readouterr().out)
    assert plan_output["resolved"]["execution_id"] == "integration.nd_manage_policy"
    assert isinstance(plan_output["operations"], list)
    assert plan_output["runtime_vars"]["nd_prerequisite_run_id"] == "run-9"

    assert main([
        "schedule", "--registry", str(registry_path),
        "--selected", "integration.nd_manage_policy,integration.nd_vpc_pair.advanced",
        "--allow-auto-confirm",
    ]) == 0
    schedule_output = json.loads(capsys.readouterr().out)
    assert [phase["phase_id"] for phase in schedule_output] == ["advanced_leaf", "vpc_pair_isolated"]

    assert main([
        "plan", "--registry", str(registry_path),
        "--execution-id", "integration.nd_vpc_pair.external", "--allow-auto-confirm",
    ]) == 1
