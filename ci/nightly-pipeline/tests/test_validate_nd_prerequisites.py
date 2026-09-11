import copy
import json
import pathlib
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from validate_nd_prerequisites import (
    expand_profile_executions,
    jenkins_targets,
    load_registry,
    normalized_equal,
    sanitize_interface_payload,
    validate_fabric_delete_guards,
    validate_playbook_profile_coverage,
    validate_registry,
    validate_runtime_markers,
    validate_selected_profiles,
    validate_tree,
    write_checkpoint,
)


EXPECTED_INTEGRATION = {
    "nd_manage_policy", "nd_manage_policy_group", "nd_manage_vrfs", "nd_manage_networks",
    "nd_manage_route_map", "nd_manage_acl", "nd_manage_l3out", "nd_interface_vpc_access",
    "nd_interface_vpc_trunk_host", "nd_manage_switches", "nd_manage_fabric", "nd_resource_manager", "nd_vpc_pair",
}
EXPECTED_SMOKE = {
    "nd_manage_acl", "nd_manage_prefix_list", "nd_manage_route_map", "nd_manage_vrfs", "nd_manage_networks",
    "nd_manage_policy", "nd_manage_policy_group", "nd_manage_switches", "nd_manage_vpc_pair", "nd_interface_vpc_access",
    "nd_interface_vpc_trunk_host", "nd_manage_vrf_lite", "nd_manage_l3out", "nd_manage_resource_manager",
    "nd_manage_fabric_ibgp_vxlan", "nd_manage_fabric_ebgp_vxlan", "nd_manage_fabric_ai_ibgp_vxlan",
    "nd_manage_fabric_ai_ebgp_vxlan", "nd_manage_fabric_external",
}


@pytest.fixture
def registry():
    return load_registry(ROOT / "tests/nd_prerequisite_profiles.yaml")


def test_registry_has_every_profile_and_distinct_lab_switches(registry):
    assert set(registry["lab"]["switches"]) == {"vxlan_leaf_1", "vxlan_leaf_2", "vxlan_spine_1", "vxlan_border_1", "external_edge_1", "external_edge_2"}
    serials = [value["serial"] for value in registry["lab"]["switches"].values()]
    assert len(serials) == len(set(serials)) == 6
    ids = set(registry["profiles"])
    assert {f"integration.{name}" for name in EXPECTED_INTEGRATION} <= ids
    assert {f"smoke.{name}" for name in EXPECTED_SMOKE} == {name for name in ids if name.startswith("smoke.")}


def test_retained_fabrics_cannot_be_declared_disposable(registry):
    for profile in registry["profiles"].values():
        for fabric in profile["fabrics"]:
            if fabric["name"] in {"VXLAN_EVPN_Fabric", "External_Connectivity_Fabric"}:
                assert fabric["lifecycle"] == "retained"


def test_validator_rejects_bad_registry_shape(registry):
    bad = dict(registry)
    bad["schema_version"] = 3
    assert "schema_version must equal 2" in validate_registry(bad)


REQUIRED_PROFILE_FIELDS = {
    "profile_id", "phase", "execution_style", "fabrics", "switches",
    "links", "vpc_pairs", "resources", "managed_domains", "runtime_vars",
    "timeouts", "restore", "confirmation",
}

EXPECTED_PHASE_ORDER = [
    "controller_disposable",
    "retained_no_switch",
    "advanced_leaf",
    "vpc_pair_isolated",
    "advanced_virtual_vpc",
    "border_external",
    "borrowed_switch",
    "terminal_switch",
    "final_restore",
]


def test_registry_uses_phase_and_confirmation_schema(registry):
    assert registry["schema_version"] == 2
    assert registry["phase_order"] == EXPECTED_PHASE_ORDER
    assert set(registry["phases"]) == set(EXPECTED_PHASE_ORDER)
    assert validate_registry(registry) == []

    for profile_id, profile in registry["profiles"].items():
        assert set(profile) >= REQUIRED_PROFILE_FIELDS, profile_id
        assert profile["profile_id"] == profile_id
        assert profile["phase"] in EXPECTED_PHASE_ORDER[:-1]
        assert profile["timeouts"]["poll_seconds"] == 15
        assert profile["restore"] == {
            "target": "verified_phase_snapshot",
            "job": "verified_job_snapshot",
        }
        assert profile["confirmation"]["status"] in {"confirmed", "pending", "rejected"}


def test_profile_topology_references_are_registered_and_allowlisted(registry):
    fabric_refs = set(registry["lab"]["fabrics"])
    switch_refs = set(registry["lab"]["switches"])
    allowlist = registry["lab"]["interface_allowlist"]

    for profile_id, profile in registry["profiles"].items():
        assert {item["ref"] for item in profile["fabrics"]} <= fabric_refs, profile_id
        members = profile["switches"]["members"]
        assert profile["switches"]["required_count"] == len(members), profile_id
        assert {item["ref"] for item in members} <= switch_refs, profile_id
        for link in profile["links"]:
            assert link["switch_ref"] in switch_refs, profile_id
            assert set(link["interfaces"]) <= set(allowlist[link["switch_ref"]]), profile_id
            assert link["admin_state"] is True
            assert link["operational_state"] == "when_reported_up"


ROLE_NOT_ASSERTED = {"preserve"}


def test_profile_switch_members_match_canonical_role_and_fabric(registry):
    """Every required switch member in every profile must match the canonical lab
    baseline for both fabric and role (unless it deliberately preserves the current
    role). This is the CI signal for "required roles/fabric changed": edit a
    topology_template to demand a role/fabric the lab switch does not have and this
    fails loudly, naming the profile and switch."""
    lab_switches = registry["lab"]["switches"]
    for profile_id, profile in registry["profiles"].items():
        for member in profile["switches"]["members"]:
            baseline = lab_switches[member["ref"]]
            assert member["desired_fabric_ref"] == baseline["baseline_fabric_ref"], (
                f"{profile_id}: {member['ref']} desired_fabric_ref="
                f"{member['desired_fabric_ref']} != canonical {baseline['baseline_fabric_ref']}"
            )
            if member["desired_role"] not in ROLE_NOT_ASSERTED:
                assert member["desired_role"] == baseline["baseline_role"], (
                    f"{profile_id}: {member['ref']} desired_role={member['desired_role']} "
                    f"!= canonical {baseline['baseline_role']}"
                )


def test_profile_execution_roles_match_canonical_baseline(registry):
    """Every profile_executions switch/role pair must match the canonical baseline
    role, so a drifted desired_roles list (e.g. a vPC pair retagged) is caught in CI."""
    lab_switches = registry["lab"]["switches"]
    for profile_id, executions in registry.get("profile_executions", {}).items():
        for execution in executions:
            for ref, role in zip(execution["switch_refs"], execution["desired_roles"]):
                assert role == lab_switches[ref]["baseline_role"], (
                    f"{profile_id}/{execution['execution_id']}: {ref} desired_role={role} "
                    f"!= canonical {lab_switches[ref]['baseline_role']}"
                )


def test_integration_vpc_pair_expands_to_two_blocked_executions(registry):
    executions = expand_profile_executions(registry, "integration.nd_vpc_pair")
    assert [item["execution_id"] for item in executions] == [
        "integration.nd_vpc_pair.advanced",
        "integration.nd_vpc_pair.external",
    ]
    assert [item["fabric_ref"] for item in executions] == ["advanced", "external"]
    assert all(item["confirmation"]["status"] == "pending" for item in executions)
    assert executions[0]["pair_mode"] == "virtual"
    assert executions[1]["pair_mode"] is None


def test_selected_pending_profile_is_an_execution_blocker(registry):
    errors = validate_selected_profiles(registry, ["integration.nd_manage_policy"])
    assert errors == ["integration.nd_manage_policy: owner confirmation is pending"]

    confirmed = copy.deepcopy(registry)
    confirmed["profiles"]["integration.nd_manage_policy"]["confirmation"] = {
        "status": "confirmed",
        "owner": "module-owner",
        "evidence": "owner-ticket-123",
        "reasons": [],
    }
    assert validate_selected_profiles(confirmed, ["integration.nd_manage_policy"]) == []


def test_allow_auto_confirm_runs_concrete_pending_but_blocks_unresolved_and_rejected(registry):
    assert validate_selected_profiles(registry, ["integration.nd_manage_policy"]) == [
        "integration.nd_manage_policy: owner confirmation is pending",
    ]
    assert validate_selected_profiles(
        registry, ["integration.nd_manage_policy"], allow_auto_confirm=True
    ) == []

    assert validate_selected_profiles(
        registry, ["integration.nd_vpc_pair.advanced"], allow_auto_confirm=True
    ) == []
    external = validate_selected_profiles(
        registry, ["integration.nd_vpc_pair.external"], allow_auto_confirm=True
    )
    assert any("pair_mode is unresolved" in error for error in external)

    rejected = copy.deepcopy(registry)
    rejected["profiles"]["integration.nd_manage_policy"]["confirmation"] = {
        "status": "rejected", "owner": "", "evidence": "", "reasons": ["blocked"],
    }
    assert validate_selected_profiles(
        rejected, ["integration.nd_manage_policy"], allow_auto_confirm=True
    ) == ["integration.nd_manage_policy: owner confirmation is rejected"]


def test_logical_multi_execution_selection_requires_every_child(registry):
    candidate = copy.deepcopy(registry)
    candidate["profiles"]["integration.nd_vpc_pair"]["confirmation"] = {
        "status": "confirmed", "owner": "owner", "evidence": "ticket", "reasons": [],
    }
    errors = validate_selected_profiles(candidate, ["integration.nd_vpc_pair"])
    assert errors == [
        "integration.nd_vpc_pair.advanced: owner confirmation is pending",
        "integration.nd_vpc_pair.external: owner confirmation is pending",
    ]

    for execution in candidate["profile_executions"]["integration.nd_vpc_pair"]:
        execution["confirmation"] = {
            "status": "confirmed", "owner": "owner", "evidence": "ticket", "reasons": [],
        }
    assert any("pair_mode is unresolved" in error for error in validate_registry(candidate))


def test_pending_values_are_reasons_not_executable_placeholders(registry):
    serialized = repr(registry)
    assert "??" not in serialized
    for profile in registry["profiles"].values():
        if profile["confirmation"]["status"] == "pending":
            assert profile["confirmation"]["reasons"]


def test_jenkins_target_parser_ignores_commented_entries():
    jenkins_text = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    targets = jenkins_targets(jenkins_text)
    assert targets["PLAYBOOK_FILES"] == []
    assert "nd_manage_policy" in targets["INTEGRATION_MODULES"]
    assert targets["STANDALONE_INTEGRATION_MODULES"] == []


def test_jenkins_derives_every_switch_alias_from_canonical_names(registry):
    jenkins_text = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    # The generated inventory passes the full canonical roster through as
    # nd_switches and builds a by_name lookup keyed on switch name; every
    # positional alias below is derived from that lookup so a topology edit can
    # never leave a stale serial/IP behind (root cause of the #35/#36 fabric-add
    # failure). The nd_test_fabric_switches map itself lives in
    # integration_config.yml (see test_integration_config_declares_complete_
    # canonical_fabric_membership), not the Jenkins-generated inventory.
    assert 'by_name = {switch["name"]: switch for switch in switches}' in jenkins_text
    assert '"nd_switches": switches,' in jenkins_text
    alias_sources = {
        "ansible_switch1": ("vxlan_leaf_1", "ip"),
        "ansible_switch2": ("vxlan_leaf_2", "ip"),
        "ansible_sno_1": ("vxlan_leaf_1", "serial"),
        "ansible_sno_2": ("vxlan_leaf_2", "serial"),
        "switch_serial_1": ("vxlan_leaf_1", "serial"),
        "switch_serial_2": ("vxlan_leaf_2", "serial"),
        "switch_serial_3": ("vxlan_spine_1", "serial"),
        "nd_test_switch1_id": ("vxlan_border_1", "serial"),
        "nd_test_switch2_id": ("external_edge_1", "serial"),
        "nd_test_switch1_mgmt_ip": ("vxlan_border_1", "ip"),
        "nd_test_switch2_mgmt_ip": ("external_edge_1", "ip"),
    }
    for alias, (name, field) in alias_sources.items():
        assert f'"{alias}": by_name["{name}"]["{field}"]' in jenkins_text, alias

    switches = registry["lab"]["switches"]
    for alias, name in (
        ("switch_serial_1", "vxlan_leaf_1"),
        ("switch_serial_2", "vxlan_leaf_2"),
        ("switch_serial_3", "vxlan_spine_1"),
    ):
        assert f"{alias}: {switches[name]['serial']}" in jenkins_text, alias


def test_integration_config_declares_complete_canonical_fabric_membership():
    config = yaml.safe_load((ROOT / "tests/integration_config.yml").read_text())
    fabrics = config["nd_test_fabric_switches"]
    assert [item["name"] for item in fabrics["VXLAN_EVPN_Fabric"]] == [
        "vxlan_leaf_1", "vxlan_leaf_2", "vxlan_spine_1", "vxlan_border_1",
    ]
    assert [item["name"] for item in fabrics["External_Connectivity_Fabric"]] == [
        "external_edge_1", "external_edge_2",
    ]
    # nd_manage_switches upstream (targets/nd_manage_switches/tasks/base_tasks.yaml) reads exactly
    # THREE positional seed IPs: ansible_switch1->leaf, ansible_switch2->spine, ansible_switch3->border.
    # No ansible_switch4 exists, so this is a deliberate leaf/spine/border 3-of-4 subset; vxlan_leaf_2
    # is carried by the full nd_test_fabric_switches roster above + the prerequisite reconcile step.
    vxlan_seed_ip = {item["name"]: item["seed_ip"] for item in fabrics["VXLAN_EVPN_Fabric"]}
    assert config["nd_manage_switches_test_projection"] == {
        "ansible_switch1": vxlan_seed_ip["vxlan_leaf_1"],    # role leaf
        "ansible_switch2": vxlan_seed_ip["vxlan_spine_1"],   # role spine
        "ansible_switch3": vxlan_seed_ip["vxlan_border_1"],  # role border
    }

    registry = load_registry(ROOT / "tests/nd_prerequisite_profiles.yaml")
    inventory = yaml.safe_load((ROOT / "consul/inventory.yaml").read_text())
    assert registry["runtime_defaults"]["nd_test_fabric_switches"] == fabrics
    assert inventory["all"]["vars"]["nd_test_fabric_switches"] == fabrics


def test_border_and_external_edge_counts_match_canonical_lab(registry):
    topology = registry["topology_templates"]["border_edges"]
    assert topology["required_count"] == 3
    # Assert every member's fabric + role, so the border (advanced/border) is verified
    # symmetrically with the two edges (external/edge_router), not just its name.
    assert [
        (item["ref"], item["desired_fabric_ref"], item["desired_role"])
        for item in topology["members"]
    ] == [
        ("vxlan_border_1", "advanced", "border"),
        ("external_edge_1", "external", "edge_router"),
        ("external_edge_2", "external", "edge_router"),
    ]

    external = registry["profile_executions"]["integration.nd_vpc_pair"][1]
    assert external["switch_refs"] == ["external_edge_1", "external_edge_2"]
    assert external["desired_roles"] == ["edge_router", "edge_router"]


def test_fabric_delete_guard_rejects_retained_and_unguarded_delete(tmp_path):
    retained = tmp_path / "retained.yaml"
    retained.write_text("""---
- hosts: nd
  tasks:
    - cisco.nd.nd_manage_fabric_external:
        state: deleted
        config: [{fabric_name: External_Connectivity_Fabric}]
""")
    errors = validate_fabric_delete_guards([retained])
    assert any("retained fabric" in error for error in errors)
    assert any("lacks namespace/retained guard" in error for error in errors)

    bypass = tmp_path / "bypass.yaml"
    bypass.write_text("""---
- hosts: nd
  tasks:
    - ansible.builtin.debug:
        msg: "ANSIBLE_NIGHTLY_ VXLAN_EVPN_Fabric External_Connectivity_Fabric"
    - cisco.nd.nd_manage_fabric_ibgp_vxlan:
        state: deleted
        config: [{fabric_name: "{{ fabric_name }}"}]
""")
    assert any("lacks namespace/retained guard" in error for error in validate_fabric_delete_guards([bypass]))

    deceptive_assert = tmp_path / "deceptive-assert.yaml"
    deceptive_assert.write_text("""---
- hosts: nd
  tasks:
    - ansible.builtin.assert:
        that:
          - fabric_name == fabric_name
          - "'^ANSIBLE_NIGHTLY_'"
          - "'VXLAN_EVPN_Fabric External_Connectivity_Fabric'"
    - cisco.nd.nd_manage_fabric_ibgp_vxlan:
        state: deleted
        config: [{fabric_name: "{{ fabric_name }}"}]
""")
    assert any("lacks namespace/retained guard" in error for error in validate_fabric_delete_guards([deceptive_assert]))

    static_safe = tmp_path / "static-safe.yaml"
    static_safe.write_text("""---
- hosts: nd
  tasks:
    - cisco.nd.nd_manage_fabric_ibgp_vxlan:
        state: deleted
        config: [{fabric_name: ANSIBLE_NIGHTLY_IBGP}]
""")
    assert validate_fabric_delete_guards([static_safe]) == []

    templated_prefix = tmp_path / "templated-prefix.yaml"
    templated_prefix.write_text("""---
- hosts: nd
  tasks:
    - cisco.nd.nd_manage_fabric_ibgp_vxlan:
        state: deleted
        config: [{fabric_name: "ANSIBLE_NIGHTLY_{{ unsafe_value }}"}]
""")
    assert any("lacks namespace/retained guard" in error for error in validate_fabric_delete_guards([templated_prefix]))

    asserted_safe = tmp_path / "asserted-safe.yaml"
    asserted_safe.write_text("""---
- hosts: nd
  tasks:
    - ansible.builtin.assert:
        that:
          - fabric_name is match('^ANSIBLE_NIGHTLY_')
          - fabric_name not in ['VXLAN_EVPN_Fabric', 'External_Connectivity_Fabric']
    - cisco.nd.nd_manage_fabric_ibgp_vxlan:
        state: deleted
        config: [{fabric_name: "{{ fabric_name }}"}]
""")
    assert validate_fabric_delete_guards([asserted_safe]) == []


def test_interface_sanitizer_is_recursive_allowlisted_and_normalization_is_strict(registry):
    payload = {
        "current": {
            "interfaceName": "Ethernet1/3",
            "configData": {"networkOS": {"policy": {
                "adminState": False,
                "nested": {"metadata": "remove", "value": 7},
            }}},
        }
    }
    sanitized = sanitize_interface_payload(payload, "SERIAL00001", True, registry)
    policy = sanitized["configData"]["networkOS"]["policy"]
    assert policy == {"adminState": True, "nested": {"value": 7}}
    assert normalized_equal("switches", [{"uuid": "a", "id": 1}], [{"uuid": "b", "id": 1}])
    with pytest.raises(ValueError, match="unsupported normalized domain"):
        normalized_equal("unknown", [], [])
    payload["current"]["interfaceName"] = "Ethernet99/99"
    with pytest.raises(ValueError, match="allowlisted"):
        sanitize_interface_payload(payload, "SERIAL00001", True, registry)
    tampered = copy.deepcopy(registry)
    tampered["lab"]["interface_allowlist"]["vxlan_leaf_1"].append("Ethernet99/99")
    with pytest.raises(ValueError, match="registry failed validation"):
        sanitize_interface_payload(payload, "SERIAL00001", True, tampered)


def test_registry_requires_exact_switches_and_canonical_profile_fabrics(registry):
    wrong_switch = copy.deepcopy(registry)
    wrong_switch["lab"]["switches"]["vxlan_leaf_1"]["serial"] = "WRONG"
    assert any("exact canonical mapping" in error for error in validate_registry(wrong_switch))

    wrong_fabric = copy.deepcopy(registry)
    wrong_fabric["profiles"]["smoke.nd_manage_acl"]["fabrics"][0]["type"] = "vxlanEbgp"
    assert any("canonical fabric" in error for error in validate_registry(wrong_fabric))


def test_runtime_markers_and_bidirectional_playbook_coverage(registry, tmp_path):
    valid = {
        "nd_prerequisite_prepared": True,
        "nd_prerequisite_run_id": "run-1",
        "nd_prerequisite_profile": "smoke.nd_manage_acl",
        "nd_prerequisite_execution_id": "smoke.nd_manage_acl",
        "nd_prerequisite_phase_baseline_id": "phase-2",
    }
    assert validate_runtime_markers(valid, "smoke.nd_manage_acl", "smoke.nd_manage_acl", "run-1") == []
    stale = dict(valid, nd_prerequisite_run_id="old")
    assert validate_runtime_markers(stale, "smoke.nd_manage_acl", "smoke.nd_manage_acl", "run-1")

    runtime_file = tmp_path / "runtime-vars.yaml"
    runtime_file.write_text("\n".join(f"{key}: {str(value).lower() if isinstance(value, bool) else value}" for key, value in stale.items()) + "\n")
    runtime_file.chmod(0o600)
    tree_errors = validate_tree(
        ROOT,
        ROOT / "Jenkinsfile_nd_jenkins_script",
        allow_pending=True,
        runtime_marker_file=runtime_file,
        expected_profile="smoke.nd_manage_acl",
        expected_execution="smoke.nd_manage_acl",
        expected_run_id="run-1",
    )
    assert "runtime marker nd_prerequisite_run_id mismatch" in tree_errors
    required_errors = validate_tree(
        ROOT, ROOT / "Jenkinsfile_nd_jenkins_script", allow_pending=True,
    )
    assert "runtime marker file is required unless static_only is true" in required_errors

    only_acl = tmp_path / "nd_manage_acl.yaml"
    only_acl.write_text("---\n[]\n")
    errors = validate_playbook_profile_coverage([only_acl], registry["profiles"])
    assert "smoke.nd_manage_prefix_list: smoke profile has no playbook" in errors


def test_checkpoint_includes_jenkins_and_design_docs(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o755)
    output = private / "checkpoint.json"
    write_checkpoint(ROOT, "task-1", output)
    report = json.loads(output.read_text())
    assert "Jenkinsfile_nd_jenkins_script" in report["files"]
    assert any(path.startswith("docs/superpowers/") for path in report["files"])
    assert private.stat().st_mode & 0o777 == 0o700
    assert output.stat().st_mode & 0o777 == 0o600

    link = tmp_path / "linked"
    link.symlink_to(private, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        write_checkpoint(ROOT, "task-1", link / "other.json")
    nested = link / "nested" / "checkpoint.json"
    with pytest.raises(ValueError, match="symlink"):
        write_checkpoint(ROOT, "task-1", nested)
