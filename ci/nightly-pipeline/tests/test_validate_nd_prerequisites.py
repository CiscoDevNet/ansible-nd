import copy
import json
import os
import pathlib
import re
import subprocess
import sys

import pytest
import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from validate_nd_prerequisites import (
    expand_profile_executions,
    jenkins_targets,
    load_registry,
    main,
    normalized_equal,
    sanitize_interface_payload,
    validate_effective_module_profile_coverage,
    validate_fabric_delete_guards,
    validate_playbook_profile_coverage,
    validate_registry,
    validate_runtime_markers,
    validate_selected_profiles,
    validate_tree,
    write_checkpoint,
)


def walk_tasks(tasks):
    for task in tasks or []:
        yield task
        for field in ("block", "rescue", "always"):
            yield from walk_tasks(task.get(field, []))


@pytest.mark.parametrize("action,outcome", [
    ("routed", "success"), ("admin_up", "success"), ("delete", "success"),
    ("routed", "write_failure"), ("routed", "unverified"), ("delete", "stale_plan"),
])
def test_baseline_interface_repair_executes_with_mock_controller(tmp_path, action, outcome):
    module_dir = tmp_path / "collections/ansible_collections/cisco/nd/plugins/modules"
    module_dir.mkdir(parents=True)
    module_dir.joinpath("nd_rest.py").write_text('''
import json
import os
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule

module = AnsibleModule(argument_spec={"path": {"type": "str"}, "method": {"type": "str"}, "content": {"type": "raw"}})
state_path = Path(os.environ["REPAIR_TEST_STATE"])
state = json.loads(state_path.read_text())
path, method = module.params["path"], module.params["method"]
if method != "get":
    if not Path(os.environ["REPAIR_TEST_JOURNAL"]).exists():
        module.fail_json(msg="mutation before journal")
    state["writes"].append(method + " " + path)
    state_path.write_text(json.dumps(state))
    if state["outcome"] == "write_failure" and method == "put":
        module.fail_json(msg="injected update refusal")
    if method == "put" and state["outcome"] != "unverified":
        state["current"]["configData"] = module.params["content"]["configData"]
        state["current"]["operData"]["mode"] = "routed"
    if method == "delete":
        state["deleted"] = True
    state_path.write_text(json.dumps(state))
    module.exit_json(changed=True, current={})
if path.endswith("/switches"):
    module.exit_json(current={"switches": [{"switchId": "SERIAL00001", "fabricManagementIp": "192.0.2.10"}]})
if "/interface?" in path:
    policy = "unexpected" if state["outcome"] == "stale_plan" else "int_trunk_host"
    module.exit_json(current=[] if state["deleted"] else [{"policy": policy, "interfaces": [{"nvPairs": {"ADMIN_STATE": "false"}}]}])
module.exit_json(current=state["current"])
''')
    interface = "Ethernet1/1.100" if action == "delete" else "Ethernet1/1"
    current = {"interfaceName": interface, "interfaceType": "ethernet",
               "configData": {"mode": "trunk", "networkOS": {"networkOSType": "nx-os",
                              "policy": {"policyType": "trunkHost", "adminState": False, "allowedVlans": "100"}}},
               "operData": {"mode": "trunk"}}
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"current": current, "deleted": False, "writes": [], "outcome": outcome}))
    helper = yaml.safe_load((ROOT / "playbooks/nd_prerequisite/apply_repair_interface.yaml").read_text())

    def fast_tasks(tasks):
        for task in tasks:
            if "retries" in task:
                task.update(retries=1, delay=0)
            task.pop("no_log", None)
            fast_tasks(task.get("block", []))

    fast_tasks(helper)
    operation = {"operation": "repair_interface", "action": action, "switch_ref": "leaf",
                 "serial": "SERIAL00001", "switch_ip": "192.0.2.10", "fabric_name": "TEST",
                 "interface": interface, "expected_policy": "int_trunk_host",
                 "expected_nv_pairs": {"ADMIN_STATE": "false"}}
    play = [{"hosts": "localhost", "connection": "local", "gather_facts": False,
             "vars": {"ansible_python_interpreter": sys.executable, "_ndp_repair_operation": operation,
                      "_ndp_registry": {"lab": {"switches": {"leaf": {"serial": "SERIAL00001"}}}},
                      "_ndp_baseline_repair_journal": [], "_ndp_state_dir": str(tmp_path),
                      "_ndp_run_id": "mock", "_ndp_execution_id": "mock"}, "tasks": helper}]
    playbook = tmp_path / "play.yaml"
    playbook.write_text(yaml.safe_dump(play, sort_keys=False))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\nretry_files_enabled = False\n")
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_COLLECTIONS_PATH=str(tmp_path / "collections"),
                       REPAIR_TEST_STATE=str(state_file), REPAIR_TEST_JOURNAL=str(tmp_path / "baseline-repair-journal.yaml"))
    result = subprocess.run([sys.executable, "-m", "ansible.cli.playbook", "-i", "localhost,", str(playbook)],
                            env=environment, text=True, capture_output=True, timeout=60)
    assert (result.returncode == 0) == (outcome == "success"), result.stdout + result.stderr
    state = json.loads(state_file.read_text())
    if outcome == "stale_plan":
        assert state["writes"] == []
    elif outcome == "write_failure":
        assert len(state["writes"]) == 1
        assert not any("deploy" in write for write in state["writes"])
    else:
        journal = tmp_path / "baseline-repair-journal.yaml"
        assert yaml.safe_load(journal.read_text())["operations"][0]["before"] == current
        assert journal.stat().st_mode & 0o777 == 0o600
        if action == "admin_up":
            assert state["current"]["configData"]["networkOS"]["policy"]["allowedVlans"] == "100"


@pytest.mark.parametrize("mode,occupied,target_failure", [
    ("live", False, False), ("live", True, False), ("live", False, True),
    ("audit", False, False), ("check", False, False), ("fixture", False, False),
    ("disabled", False, False), ("apply_false", False, False),
])
def test_baseline_repair_lock_and_readonly_modes(tmp_path, mode, occupied, target_failure):
    wrapper = yaml.safe_load((ROOT / "playbooks/nd_prerequisite/nd_prerequisite_wrapper.yaml").read_text())
    lock = next(task for task in wrapper if task["name"].startswith("Hold the exclusive baseline"))
    repair_tasks = [copy.deepcopy(task) for task in wrapper if "ansible.builtin.include_tasks" in task
                    and task["ansible.builtin.include_tasks"] == "repair_baseline.yaml"]
    for task in repair_tasks:
        del task["ansible.builtin.include_tasks"]
        task["ansible.builtin.debug"] = {"msg": "REPAIR_ENABLED"}
    restore = yaml.safe_load((ROOT / "playbooks/nd_prerequisite/nd_prerequisite_restore.yaml").read_text())
    release = [task for task in restore if "baseline repair lock" in task["name"]]
    release_file = tmp_path / "release.yaml"
    release_file.write_text(yaml.safe_dump(release, sort_keys=False))
    lock_dir = tmp_path / "nd-prerequisite-baseline.lock"
    if occupied:
        lock_dir.mkdir()
        (lock_dir / "owner.json").write_text('{"run_id": "another-run"}')
    variables = {"ansible_python_interpreter": sys.executable, "nd_prerequisite_mode": "fixture" if mode == "fixture" else "live",
                 "nd_prerequisite_apply": mode != "apply_false", "nd_prerequisite_only": mode == "audit",
                 "nd_prerequisite_repair_baseline": mode != "disabled", "test_module": "mock",
                 "_ndp_profile": {"switches": {"members": ["leaf"]}}, "_ndp_run_id": "mock-run",
                 "_ndp_execution_id": "mock", "nd_prerequisite_repair_lock_dir": str(lock_dir)}
    tasks = [lock] + repair_tasks
    if target_failure:
        tasks.append({"name": "Injected target failure", "ansible.builtin.fail": {"msg": "target failed"}})
    play = [{"hosts": "localhost", "connection": "local", "gather_facts": False, "force_handlers": True,
             "vars": variables, "tasks": tasks,
             "handlers": [{"name": "Restore prerequisite interface changes", "ansible.builtin.include_tasks": str(release_file)}]}]
    playbook = tmp_path / "lock.yaml"
    playbook.write_text(yaml.safe_dump(play, sort_keys=False))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\nretry_files_enabled = False\n")
    command = [sys.executable, "-m", "ansible.cli.playbook", "-i", "localhost,", str(playbook)]
    if mode == "check":
        command.append("--check")
    result = subprocess.run(command, env=dict(os.environ, ANSIBLE_CONFIG=str(config)), text=True,
                            capture_output=True, timeout=60)
    assert (result.returncode == 0) == (not occupied and not target_failure), result.stdout + result.stderr
    assert lock_dir.exists() == occupied, result.stdout
    assert ('"msg": "REPAIR_ENABLED"' in result.stdout) == (mode == "live" and not occupied), result.stdout
    if occupied:
        assert json.loads((lock_dir / "owner.json").read_text())["run_id"] == "another-run"


EXPECTED_INTEGRATION = {
    "nd_manage_policy", "nd_manage_policy_group", "nd_manage_vrfs", "nd_manage_networks",
    "nd_manage_route_map", "nd_manage_acl", "nd_manage_l3out", "nd_interface_vpc_access",
    "nd_interface_vpc_trunk_host", "nd_manage_switches", "nd_manage_fabric", "nd_resource_manager", "nd_vpc_pair",
    "nd_interface_ethernet_routed", "nd_manage_links", "nd_manage_fabric_group_vxlan",
    "nd_manage_fabric_group_members", "nd_manage_tor",
    "nd_local_user", "nd_maintenance_mode", "nd_fabric_update_group", "nd_interface_port_channel_routed",
    "nd_interface_loopback", "nd_interface_svi", "nd_interface_ethernet_access",
    "nd_interface_ethernet_trunk_host", "nd_interface_port_channel_access",
    "nd_interface_port_channel_trunk_host", "nd_interface_subinterface_managed",
    "nd_interface_subinterface_unmanaged", "nd_manage_community_list", "nd_manage_extended_community_list",
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
    assert set(registry["lab"]["switches"]) == {
        "vxlan_leaf_1", "vxlan_leaf_2", "vxlan_spine_1", "vxlan_border_1", "vxlan_leaf_3", "vxlan_leaf_4",
        "external_edge_1", "external_edge_2",
    }
    serials = [value["serial"] for value in registry["lab"]["switches"].values()]
    assert len(serials) == len(set(serials)) == 8
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
    # Both pairs are physical (virtual peering is unsupported on these switches) and blocked until
    # the lab owner cables and records the peer-links.
    assert all(item["pair_mode"] == "physical" for item in executions)
    assert all(item["physical_peer_links"] == [] for item in executions)
    advanced_reason = " ".join(executions[0]["confirmation"]["reasons"])
    external_reason = " ".join(executions[1]["confirmation"]["reasons"])
    assert "leaf_1 Ethernet1/2 <-> leaf_2 Ethernet1/1" in advanced_reason
    assert "never repurpose leaf_1 Ethernet1/3" in advanced_reason
    assert "edge_1 Ethernet1/5 <-> edge_2 Ethernet1/6" in external_reason
    assert "edge_1 Ethernet1/7 <-> edge_2 Ethernet1/8" in external_reason
    assert "never repurpose edge_1 Ethernet1/2 or Ethernet1/3" in external_reason


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

    # Physical pairs with no cabled peer-links stay blocked even under auto-confirm (fail-closed).
    assert validate_selected_profiles(
        registry, ["integration.nd_vpc_pair.advanced"], allow_auto_confirm=True
    ) == ["integration.nd_vpc_pair.advanced: physical pair requires peer-link interfaces"]
    external = validate_selected_profiles(
        registry, ["integration.nd_vpc_pair.external"], allow_auto_confirm=True
    )
    assert any("physical pair requires peer-link interfaces" in error for error in external)

    rejected = copy.deepcopy(registry)
    rejected["profiles"]["integration.nd_manage_policy"]["confirmation"] = {
        "status": "rejected", "owner": "", "evidence": "", "reasons": ["blocked"],
    }
    assert validate_selected_profiles(
        rejected, ["integration.nd_manage_policy"], allow_auto_confirm=True
    ) == ["integration.nd_manage_policy: owner confirmation is rejected"]


def test_new_controller_only_fabric_group_profiles_are_self_contained(registry):
    for profile_id in (
        "integration.nd_manage_fabric_group_vxlan",
        "integration.nd_manage_fabric_group_members",
    ):
        profile = registry["profiles"][profile_id]
        assert profile["phase"] == "controller_disposable"
        assert profile["fabrics"] == []
        assert profile["switches"] == {"required_count": 0, "members": []}
        assert profile["resources"][0]["requirement_status"] == "ready"
        assert validate_selected_profiles(
            registry, [profile_id], allow_auto_confirm=True
        ) == []


def test_routed_ethernet_profile_reserves_leaf1_interfaces(registry):
    profile = registry["profiles"]["integration.nd_interface_ethernet_routed"]
    assert [member["ref"] for member in profile["switches"]["members"]] == [
        "vxlan_leaf_1"
    ]
    assert profile["runtime_vars"] == {
        "nd_test_fabric_name": "VXLAN_EVPN_Fabric",
        "nd_test_switch_ip": "192.0.2.195",
    }
    resource = profile["resources"][0]
    assert resource["kind"] == "verify_free_interfaces"
    assert resource["requirement_status"] == "ready"
    assert resource["interfaces"] == [
        "Ethernet1/31", "Ethernet1/32", "Ethernet1/33", "Ethernet1/34",
    ]


def test_interface_profiles_declare_typed_checks_and_reversible_parents(registry):
    expected_namespaces = {
        "integration.nd_interface_loopback": {
            "loopback200", "loopback201", "loopback202", "loopback203",
            "loopback204", "loopback205", "loopback206", "loopback299",
        },
        "integration.nd_interface_svi": {
            "vlan333", "vlan334", "vlan335", "vlan336",
            "vlan337", "vlan338", "vlan500", "vlan501",
        },
    }
    for profile_id, interfaces in expected_namespaces.items():
        resource = registry["profiles"][profile_id]["resources"][0]
        assert resource["kind"] == "verify_logical_interface_namespace"
        assert set(resource["interfaces"]) == interfaces
        assert resource["expected_state"] == "absent"

    for profile_id, interfaces in {
        "integration.nd_interface_ethernet_access": {f"Ethernet1/{port}" for port in range(41, 51)},
        "integration.nd_interface_ethernet_trunk_host": {f"Ethernet1/{port}" for port in range(41, 49)},
        "integration.nd_interface_port_channel_access": {f"Ethernet1/{port}" for port in range(10, 14)},
        "integration.nd_interface_port_channel_trunk_host": {f"Ethernet1/{port}" for port in range(14, 18)},
        "integration.nd_interface_port_channel_routed": {f"Ethernet1/{port}" for port in range(18, 22)},
    }.items():
        resource = registry["profiles"][profile_id]["resources"][0]
        assert resource["kind"] == "verify_free_interfaces"
        assert set(resource["interfaces"]) == interfaces
        assert set(resource["constraints"]) == {
            "exists", "not_port_channel_member", "not_fabric_link",
        }

    for profile_id in (
        "integration.nd_interface_subinterface_managed",
        "integration.nd_interface_subinterface_unmanaged",
    ):
        resources = registry["profiles"][profile_id]["resources"]
        parent = next(item for item in resources if item["kind"] == "ensure_routed_parent")
        port_channel = next(
            item for item in resources if item["kind"] == "ensure_routed_port_channel"
        )
        assert (parent["interface"], parent["desired_policy"]) == (
            "Ethernet1/1", "routedHost",
        )
        assert parent["existing_link"] == {
            "peer_switch_ref": "external_edge_1", "peer_interface": "Ethernet1/1",
        }
        assert (port_channel["interface"], port_channel["desired_policy"]) == (
            "Port-channel10", "int_l3_port_channel",
        )
        assert port_channel["member_interfaces"] == []


def test_existing_link_parent_must_join_two_registered_fabrics(registry):
    profile_id = "integration.nd_interface_subinterface_managed"
    for peer, interface, expected in (
        ("vxlan_leaf_2", "Ethernet1/1", "existing link must join two different fabrics"),
        ("missing_switch", "Ethernet1/1", "existing link uses unknown peer switch"),
        ("external_edge_1", "eth1", "existing link peer interface is invalid"),
    ):
        candidate = copy.deepcopy(registry)
        parent = next(
            item for item in candidate["profiles"][profile_id]["resources"] if item["kind"] == "ensure_routed_parent"
        )
        parent["existing_link"] = {"peer_switch_ref": peer, "peer_interface": interface}
        assert any(expected in error for error in validate_registry(candidate)), peer


def test_nd_manage_links_and_nd_manage_tor_profiles_are_ready(registry):
    # nd_manage_links targets live-verified free ports on the shared fabric; nd_manage_tor runs a reduced single-association
    # test on vxlan_leaf_3/vxlan_leaf_4, so neither declares an unavailable substrate any more.
    assert validate_selected_profiles(
        registry, ["integration.nd_manage_links"], allow_auto_confirm=True
    ) == []
    assert validate_selected_profiles(
        registry, ["integration.nd_manage_tor"], allow_auto_confirm=True
    ) == []


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
    # A confirmed physical execution with no recorded peer-links is caught by full-registry validation.
    assert any(
        "physical pair requires peer-link interfaces" in error
        for error in validate_registry(candidate)
    )


def test_pending_values_are_reasons_not_executable_placeholders(registry):
    serialized = repr(registry)
    assert "??" not in serialized
    for profile in registry["profiles"].values():
        if profile["confirmation"]["status"] == "pending":
            assert profile["confirmation"]["reasons"]


def test_jenkins_target_parser_ignores_commented_entries():
    source = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    expected = jenkins_targets(source)
    commented = source
    for name in ("PLAYBOOK_FILES", "INTEGRATION_MODULES", "INTERFACE_INTEGRATION_MODULES"):
        marker = "def " + name + " = ["
        assert marker in commented
        commented = commented.replace(marker, marker + "\n    // 'disabled_line',", 1)
    assert jenkins_targets(commented) == expected
    assert "nd_manage_policy" in expected["INTEGRATION_MODULES"]
    assert expected["STANDALONE_INTEGRATION_MODULES"] == ["nd_vpc_pair"]
    assert set(expected["INTEGRATION_MODULES"] + expected["INTERFACE_INTEGRATION_MODULES"]) <= set(expected["EFFECTIVE_INTEGRATION_MODULES"])


def test_jenkins_runs_vpc_pairs_immediately_after_policy_groups():
    jenkins_text = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    ordering = jenkins_text.split("def orderedIntegrationTargets = []", 1)[1].split("def integrationForShell", 1)[0]
    assert "effectiveIntegrationModules.each { moduleName ->" in ordering
    assert ordering.index("orderedIntegrationTargets.add(moduleName)") < ordering.index("orderedIntegrationTargets.addAll(standaloneTargets)")
    assert "moduleName == 'nd_manage_policy_group' && env.ND_PREREQUISITE_ONLY_EFFECTIVE != 'true'" in ordering
    assert "ORDERED_INTEGRATION_LIST=${orderedIntegrationTargets.join(' ')}" in jenkins_text
    assert 'for m in ${ORDERED_INTEGRATION_LIST}; do' in jenkins_text
    assert 'run_standalone_integration "${m}"' in jenkins_text
    assert 'for m in ${STANDALONE_INTEGRATION_LIST}; do' not in jenkins_text
    assert 'def plannedResultTargets = orderedIntegrationTargets.collect' in jenkins_text
    assert 'registerStructuredExecutions(ndfcConfig, plannedResultTargets' in jenkins_text
    assert "standaloneTargets.each { m -> resultTargets.add([m, 'integration']) }" not in jenkins_text


def test_jenkins_exposes_only_debug_and_git_branch_parameters():
    jenkins_text = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    block = re.search(r"\n    parameters \{(.*?)\n    \}", jenkins_text, re.S).group(1)
    assert re.findall(r"(?:booleanParam|string|choice|text|password)\(name: '([A-Za-z0-9_]+)'", block) == ["DEBUG", "DEBUG_MODULES", "ND_GIT_BRANCH"]
    # Topology and coverage remain fixed; only branch/debug parameters are read.
    assert set(re.findall(r"\bparams\.([A-Za-z0-9_]+)", jenkins_text)) == {"DEBUG", "DEBUG_MODULES", "ND_GIT_BRANCH"}
    for removed in ("RUN_ND_MANAGE_LINKS", "RUN_ND_VPC_PAIR", "RUN_ND_MANAGE_TOR", "ND_LINKS_FABRIC", "ND_SUBIF_ETHERNET_PARENT", "ND_INTERFACE_TEST_SWITCH_IP"):
        assert removed not in jenkins_text, removed


def test_jenkins_always_runs_nd_vpc_pair_and_never_skips_it():
    jenkins_text = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    standalone = jenkins_text.split("Running Standalone Integration Modules")[1].split("Running Integration Modules")[0]
    # A missing peer-link is logged and the module still runs; nothing may turn it back into a SKIP.
    assert "NDP_MODULE_SKIPPED" not in standalone
    assert "running the module anyway" in standalone
    assert '"${TARGET_PLAYBOOK}"' in standalone


@pytest.mark.parametrize("links, expected", [
    ([], "ABSENT"),
    ([{"srcSwitchId": "peer1", "dstSwitchId": "peer2", "linkPresent": False}], "ABSENT"),
    ([{"srcSwitchId": "peer1", "dstSwitchId": "peer2"}], "ABSENT"),
    ([{"srcSwitchId": "peer1", "dstSwitchId": "other", "linkPresent": True}], "ABSENT"),
    ([{"srcSwitchId": "peer1", "dstSwitchId": "peer2", "linkPresent": True}], "PRESENT"),
    ([{"srcSwitchId": "peer2", "dstSwitchId": "peer1", "linkPresent": True}], "PRESENT"),
])
def test_jenkins_vpc_peerlink_probe_requires_a_present_link(links, expected):
    from jinja2 import Environment

    jenkins_text = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    probe_text = jenkins_text.split("<<'PEERLINK_PROBE_EOF'\n", 1)[1].split("\nPEERLINK_PROBE_EOF", 1)[0]
    probe = yaml.safe_load(probe_text)[0]
    message = probe["tasks"][-1]["ansible.builtin.debug"]["msg"]
    result = Environment().from_string(message).render(
        _probe_links={"current": {"links": links}}, probe_s1="peer1", probe_s2="peer2",
    )
    assert result == f"NDP_VPC_PEERLINK_{expected}"


@pytest.mark.parametrize("status, expected_returncode", [(200, 0), (500, 2)])
def test_generated_peerlink_probe_runs_with_mock_api_data(tmp_path, status, expected_returncode):
    executable = pathlib.Path(sys.executable).with_name("ansible-playbook")
    if not executable.exists():
        pytest.skip("ansible-playbook is not installed in the test interpreter environment")
    source = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    probe_text = source.split("<<'PEERLINK_PROBE_EOF'\n", 1)[1].split("\nPEERLINK_PROBE_EOF", 1)[0]
    play = yaml.safe_load(probe_text)[0]
    assert play["hosts"] == "nd_controller"
    assert play["gather_facts"] is False
    assert len(play["tasks"]) == 4
    assert play["tasks"][1]["cisco.nd.nd_rest"]["method"] == "get"
    assert all(set(endpoint) == {"fabric", "serial", "ifname", "label"}
               for endpoint in play["tasks"][0]["loop"])
    play["hosts"] = "localhost"
    play["vars"] = {"probe_fabric": "TEST", "probe_s1": "peer1", "probe_s2": "peer2",
                    "probe_prepare_peerlink": False}
    play["tasks"][1] = {"name": "Provide mock link API response", "ansible.builtin.set_fact": {
        "_probe_links": {"status": status, "current": {"links": [
            {"srcSwitchId": "peer1", "dstSwitchId": "peer2", "linkPresent": True},
        ]}},
    }}
    playbook = tmp_path / "peerlink-probe.yaml"
    playbook.write_text(yaml.safe_dump([play], sort_keys=False))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n")
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_HOME=str(tmp_path / "ansible-home"),
                       ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible-tmp"), ANSIBLE_STDOUT_CALLBACK="default",
                       ANSIBLE_NOCOLOR="1", ANSIBLE_FORCE_COLOR="0")
    environment.pop("ANSIBLE_CALLBACKS_ENABLED", None)
    result = subprocess.run([sys.executable, str(executable), "-i", "localhost,", "-c", "local", str(playbook)],
                            env=environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == expected_returncode, result.stdout + result.stderr
    assert ("NDP_VPC_PEERLINK_PRESENT" in result.stdout) == (expected_returncode == 0)
    if expected_returncode:
        assert "NDP_VPC_PEERLINK_PROBE_FAILED" in result.stdout


def test_jenkins_vpc_peerlink_prepares_only_known_leaf_ports_and_reports_probe_errors():
    jenkins_text = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    probe_text = jenkins_text.split("<<'PEERLINK_PROBE_EOF'\n", 1)[1].split("\nPEERLINK_PROBE_EOF", 1)[0]
    prepare = yaml.safe_load(probe_text)[0]["tasks"][0]
    assert prepare["ansible.builtin.include_tasks"].endswith("/nd_prerequisite/admin_up_interface.yaml")
    assert [port["ifname"] for port in prepare["loop"]] == ["Ethernet1/2", "Ethernet1/1"]
    assert prepare["when"] == "probe_prepare_peerlink | default(false) | bool"
    assert '"${VPC_RUN_ID}" = "advanced"' in jenkins_text
    # The advanced pair is the round's primary-fabric pair (iBGP in round 1, eBGP in round 2), never a hard-coded name.
    assert '"${VPC_FABRIC}" = "${FABRIC_NAME}"' in jenkins_text
    assert '"${VPC_FABRIC}" = "VXLAN_EVPN_Fabric"' not in jenkins_text
    assert 'PREPARE_PEERLINK=false' in jenkins_text
    assert '|| PEERLINK_STATUS=$?' in jenkins_text
    assert 'NDP_VPC_PEERLINK_PROBE_FAILED [${m}]' in jenkins_text


def test_jenkins_switch_guard_allows_greenfield_reload_time():
    jenkins_text = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    assert 'SWITCH_GUARD_TIMEOUT="${ND_SWITCH_GUARD_TIMEOUT:-1800}"' in jenkins_text


def test_runner_keeps_community_list_develop_defaults_unchanged():
    runner = (ROOT / "tests/run_integration_module.yaml").read_text()
    assert "drop the unsupported timeout module default from the target" not in runner
    for module in ("nd_manage_community_list", "nd_manage_extended_community_list"):
        assert f"integration.{module}" in (ROOT / "tests/nd_prerequisite_profiles.yaml").read_text()


def test_vpc_interface_targets_use_the_runner_formed_physical_pair(registry):
    runner = (ROOT / "tests/run_integration_module.yaml").read_text()
    # The targets' own setup builds a virtual-peer-link pair that ND 4.3 rejects on this fabric, so the runner forms the
    # physical pair first, hands it over as pre-existing substrate and removes only a pair that it created itself.
    assert runner.count("test_module in ['nd_interface_vpc_access', 'nd_interface_vpc_trunk_host']") >= 2
    assert "use_virtual_peer_link: false" in runner
    assert "nd_test_manage_vpc_pairs: false" not in runner
    assert "_ndp_vpcif_pair_preexisting is defined" in runner
    allowlist = registry["lab"]["interface_allowlist"]
    for module in ("nd_interface_vpc_access", "nd_interface_vpc_trunk_host"):
        profile = registry["profiles"][f"integration.{module}"]
        # Pair 1 (leaf_1/leaf_2) is what the target works on; pair 2 (leaf_3/leaf_4) is the pre-existing second pair its
        # multi-pair scenario asserts, so the runner forms both and the profile declares both peer-links.
        pair1, pair2 = profile["vpc_pairs"]
        assert pair1["peer_refs"] == ["vxlan_leaf_1", "vxlan_leaf_2"]
        assert pair2["peer_refs"] == ["vxlan_leaf_3", "vxlan_leaf_4"]
        for pair in (pair1, pair2):
            assert pair["mode"] == "physical"
            assert pair["required_path"] == "module_creates_pair"
            assert pair["physical_peer_links"]
        assert len(pair1["physical_peer_links"]) == 1
        assert [
            (link["src"]["interface"], link["dst"]["interface"]) for link in pair2["physical_peer_links"]
        ] == [("Ethernet1/1", "Ethernet1/1"), ("Ethernet1/2", "Ethernet1/2")]
        assert "nd_test_manage_vpc_pairs" not in profile["runtime_vars"]
        # The target resolves the second pair through these two management IPs, so they must be the leaf_3/leaf_4 seed IPs.
        assert (
            profile["runtime_vars"]["nd_test_vpc_pair2_peer1_ip"],
            profile["runtime_vars"]["nd_test_vpc_pair2_peer2_ip"],
        ) == (
            registry["lab"]["switches"]["vxlan_leaf_3"]["seed_ip"],
            registry["lab"]["switches"]["vxlan_leaf_4"]["seed_ip"],
        )
        # Member ports are verified free on ALL FOUR leaves, and every reserved port is on the lab allowlist.
        reserved = {
            resource["switch_ref"]: set(resource["interfaces"])
            for resource in profile["resources"]
            if resource["kind"] == "verify_free_interfaces"
        }
        assert set(reserved) == {"vxlan_leaf_1", "vxlan_leaf_2", "vxlan_leaf_3", "vxlan_leaf_4"}
        assert len({frozenset(interfaces) for interfaces in reserved.values()}) == 1
        for switch_ref, interfaces in reserved.items():
            assert interfaces <= set(allowlist[switch_ref])
        # Every declared peer-link port is on the allowlist and admin-up readiness is requested for it.
        link_ports = {(link["switch_ref"], interface) for link in profile["links"] for interface in link["interfaces"]}
        for pair in (pair1, pair2):
            for peer_link in pair["physical_peer_links"]:
                for side in ("src", "dst"):
                    endpoint = peer_link[side]
                    assert endpoint["interface"] in allowlist[endpoint["switch_ref"]]
                    assert (endpoint["switch_ref"], endpoint["interface"]) in link_ports


def test_effective_module_profile_coverage_reports_all_missing_profiles_once():
    profiles = {"integration.present": {}}
    assert validate_effective_module_profile_coverage(["present"], profiles) == []
    assert validate_effective_module_profile_coverage(
        ["present", "missing_one", "missing_two", "missing_one"],
        profiles,
    ) == [
        "integration.missing_one: effective Jenkins module has no profile",
        "integration.missing_two: effective Jenkins module has no profile",
    ]
    assert validate_effective_module_profile_coverage([], profiles) == [
        "effective Jenkins module list is empty"
    ]


def test_profile_coverage_command_passes_and_fails_closed(capsys):
    registry_path = str(ROOT / "tests/nd_prerequisite_profiles.yaml")
    assert main([
        "coverage",
        "--registry",
        registry_path,
        "--modules",
        "nd_manage_policy,nd_interface_ethernet_routed,nd_manage_switches",
    ]) == 0
    assert "NDP_PROFILE_COVERAGE_OK: 3 effective module(s) have profiles" in capsys.readouterr().out

    assert main([
        "coverage",
        "--registry",
        registry_path,
        "--modules",
        "nd_manage_policy,missing_profile_fixture",
    ]) == 1
    assert (
        "integration.missing_profile_fixture: effective Jenkins module has no profile"
        in capsys.readouterr().err
    )


def test_jenkins_runs_profile_coverage_gate_before_the_module_loop():
    source = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    coverage_call = 'python "${PROFILE_VALIDATOR}" coverage'
    module_loop = 'for m in ${ORDERED_INTEGRATION_LIST}; do'
    assert '"NDP_EFFECTIVE_MODULES=${profileCoverageForShell}"' in source
    assert source.index(coverage_call) < source.index(module_loop)
    assert '--modules "${NDP_EFFECTIVE_MODULES}"' in source


def test_live_link_capture_uses_an_ansible_loop_not_a_python_comprehension():
    capture_text = (
        ROOT / "playbooks/nd_prerequisite/nd_prerequisite_capture.yaml"
    ).read_text()
    task_text = capture_text.split(
        "- name: Normalize captured inter-fabric links for the planner", 1
    )[1].split("- name: Persist normalized live prerequisite state for planning", 1)[0]

    assert "for _ndp_link in" not in task_text
    assert "| subelements('current.links', skip_missing=True)" in task_text
    assert "loop_var: _ndp_link_item" in task_text
    assert "'links': _ndp_live_state.links + [{" in task_text
    assert "_ndp_link_item.1.srcSwitchId" in task_text


def test_subinterface_parent_lifecycle_is_owned_by_typed_prerequisites():
    runner_text = (ROOT / "tests/run_integration_module.yaml").read_text()
    jenkins_text = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()

    assert "SUBIF SETUP - provision routed parent" not in runner_text
    assert "_subif_parent_is_underlay" not in runner_text
    assert "force_handlers: true" in runner_text
    assert "restore any prerequisite interfaces after preparation failure" in runner_text
    assert "notify: Restore prerequisite interface changes" in runner_text
    assert "nd_prerequisite_restore.yaml" in runner_text

    for filename in (
        "apply_verify_free_interfaces.yaml",
        "apply_verify_logical_interface_namespace.yaml",
        "apply_ensure_routed_parent.yaml",
        "apply_ensure_routed_port_channel.yaml",
        "nd_prerequisite_restore.yaml",
        "restore_interface_operation.yaml",
    ):
        assert f"nd_prerequisite/{filename}" in jenkins_text


def test_runner_maps_numbered_links_without_replacing_the_develop_tor_suite():
    runner_text = (ROOT / "tests/run_integration_module.yaml").read_text()
    for token in (
        "ND_LINKS_FABRIC",
        "ND_LINKS_SWITCH_A",
        "ND_LINKS_SWITCH_B",
    ):
        assert token in runner_text
    # nd_manage_links no longer demands a dedicated fabric: its inputs must be roster members and, with
    # prerequisites enabled, equal to what the planner verified live (profile runtime_vars).
    assert "validate dedicated numbered-link topology" not in runner_text
    assert "_ndp_result.runtime_vars.nd_test_switch_a" in runner_text
    assert "nd_test_fabric_numbered in nd_test_fabric_switches" in runner_text
    # nd_manage_tor no longer needs a dedicated seven-switch fabric or seven Jenkins-supplied serials.
    assert "validate dedicated seven-switch ToR topology" not in runner_text
    assert "validate the reduced ToR roster" not in runner_text
    for removed in ("ND_TOR_FABRIC", "ND_TOR_SWITCH_SERIAL", "ND_VPC_TOR_PEER_SERIAL", "ND_TOR2_SWITCH_SERIAL", "test_tor_fabric_name"):
        assert removed not in runner_text


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
        "nd_test_vpc_pair2_peer1_ip": ("vxlan_leaf_3", "ip"),
        "nd_test_vpc_pair2_peer2_ip": ("vxlan_leaf_4", "ip"),
    }
    for alias, (name, field) in alias_sources.items():
        assert f'"{alias}": by_name["{name}"]["{field}"]' in jenkins_text, alias

    # The removed embedded runner no longer injects literal serial aliases.


def test_runner_rejects_cross_fabric_positional_switch_mapping():
    runner_text = (ROOT / "tests/run_integration_module.yaml").read_text()
    jenkins_text = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()

    # The old Build 30 failure passed external_edge_1 as switch_serial_3 to a
    # primary-fabric module. Keep the runtime assertion and Jenkins guard in
    # place so a stale Consul copy cannot silently repeat that mismatch.
    assert "NDP_SWITCH_MAPPING_FAIL" in runner_text
    assert "switch_serial_3 in (nd_test_fabric_switches.VXLAN_EVPN_Fabric" in runner_text
    assert "switch_serial_3 not in (nd_test_fabric_switches.External_Connectivity_Fabric" in runner_text
    assert "refusing to run the module" in jenkins_text
    assert "canonical switch pre-flight is unavailable; refusing to run" in jenkins_text


def test_l3out_runner_verifies_required_vrfs_before_running_role():
    runner_text = (ROOT / "tests/run_integration_module.yaml").read_text()

    # Build 30 continued into nd_manage_l3out after the raw VRF create had
    # failed. A duplicate POST is acceptable only when the follow-up GET proves
    # that both role-required VRFs are present on their declared fabrics.
    assert "SETUP - verify L3Out VRF on fabric1" in runner_text
    assert "SETUP - verify L3Out VRF on fabric2" in runner_text
    assert "NDP_L3OUT_VRF_PREREQUISITE_FAIL" in runner_text
    assert "NDP_L3OUT_VRF_PREREQUISITE_OK" in runner_text
    assert "vrfType: vxlanIbgp" in runner_text
    assert "vrfType: externalConnectivity" in runner_text
    assert runner_text.count("failed_when: false") >= 2
    assert "ignore_errors so an already-present VRF" not in runner_text


def test_selected_branch_acl_and_ibgp_payloads_are_not_rewritten():
    source = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    assert "item8: nd_manage_acl" not in source
    assert "item9: nd_manage_fabric" not in source
    assert "item10: nd_manage_fabric" not in source
    assert "prepareSwitchIntegrationBaseline" not in source
    assert 'nd_verify_develop_sources.py' in source
    runner = yaml.safe_load((ROOT / "tests/run_integration_module.yaml").read_text())[0]
    tasks = list(walk_tasks(runner["pre_tasks"] + runner["tasks"]))
    assert not any("ansible.builtin.replace" in task for task in tasks)


def test_collection_modules_are_verified_without_runtime_patches():
    source = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    for removed_patch in ("ND_REST_MODULE=", "NETWORK_VALIDATE=", "VRFS_ORCHESTRATOR=", "patch_nd_switch_removal.py"):
        assert removed_patch not in source
    assert '--expected-commit' in source
    assert '--expected-branch "${ND_GIT_BRANCH}"' in source
    assert '"${BASE_DIRECTORY}/venv/bin/python" "${COLLECTIONS_DIRECTORY}/nd_verify_develop_sources.py"' in source


def test_policy_suites_keep_authored_failure_and_setup_semantics():
    source = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    assert "item14 policy repeat-delete no-op" not in source
    assert "item15 policy-group baseline no deploy" not in source
    assert "POLICY_GROUP_SPECIAL_TEST" not in source
    runner = yaml.safe_load((ROOT / "tests/run_integration_module.yaml").read_text())[0]
    calls = [task for task in walk_tasks(runner["tasks"]) if task.get("ansible.builtin.include_role", {}).get("name") == "{{ test_module }}" and not task["ansible.builtin.include_role"].get("tasks_from")]
    assert calls
    assert all(not task.get("ignore_errors") for task in calls)
    assert any(not task["ansible.builtin.include_role"].get("tasks_from") for task in calls)


def test_local_runner_l3out_projection_uses_border_and_external_edge():
    runner_text = (ROOT / "run_all_integ.sh").read_text()

    # Keep the local runner aligned with the confirmed L3Out profile and the
    # Jenkins runner: border_1 is the VXLAN endpoint, edge_1 is the external endpoint.
    assert "nd_test_switch1_id=SERIAL00004" in runner_text
    assert "nd_test_switch1_mgmt_ip=192.0.2.88" in runner_text
    assert "nd_test_switch2_id=SERIAL00005" in runner_text
    assert "nd_test_switch2_mgmt_ip=192.0.2.89" in runner_text
    assert "nd_test_switch1_id=SERIAL00001 -e nd_test_switch1_mgmt_ip=192.0.2.195" not in runner_text


def test_webex_results_table_uses_markdown_and_separate_artifact_links():
    source = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    assert "def headers = ['Status', 'Module', 'Fabric']" in source
    assert "headers.addAll(['Passed', 'Failed', 'Skipped', 'Duration'])" in source
    assert "def formatModuleActivityTable(results, buildNumber)" in source
    assert "'Base', 'Cleanup', 'Skipped', 'Result / failure'" in source
    assert "**Artifact links:**" in source
    assert "def formatArtifactLinks(rawArtifacts)" in source
    assert "def splitWebexMessage" in source
    assert "sendWebexNotificationMessages(notificationMessages)" in source
    assert "buildWebexAdaptiveCard" not in source


def test_switch_credentials_are_separate_and_runtime_bound():
    jenkins_text = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    runner_text = (ROOT / "tests/run_integration_module.yaml").read_text()
    ensure_text = (ROOT / "playbooks/nd_ensure_switches.yaml").read_text()
    fallback_inventory = (ROOT / "consul/inventory.yaml").read_text()

    # Controller credentials must not be silently reused for switch onboarding;
    # both the module runner and membership guard read a separately bound Jenkins
    # username/password credential at execution time.
    assert "def SWITCH_CREDENTIALS_ID = 'SWITCH_CREDENTIALS'" in jenkins_text
    assert "credentialsId: SWITCH_CREDENTIALS_ID" in jenkins_text
    assert "usernameVariable: 'ANSIBLE_NXOS_SWITCH_USERNAME'" in jenkins_text
    assert "passwordVariable: 'ANSIBLE_NXOS_SWITCH_PASSWORD'" in jenkins_text
    assert "lookup('env', 'ANSIBLE_NXOS_SWITCH_USERNAME')" in runner_text
    assert "lookup('env', 'ANSIBLE_NXOS_SWITCH_PASSWORD')" in runner_text
    assert "lookup('env', 'ANSIBLE_NXOS_SWITCH_USERNAME')" in ensure_text
    assert "lookup('env', 'ANSIBLE_NXOS_SWITCH_PASSWORD')" in ensure_text
    assert "lookup('env', 'NDFC_USER')" in fallback_inventory
    assert "lookup('env', 'NDFC_PASSWORD')" in fallback_inventory
    assert "lookup('env', 'ANSIBLE_NXOS_SWITCH_USERNAME')" in fallback_inventory
    assert "lookup('env', 'ANSIBLE_NXOS_SWITCH_PASSWORD')" in fallback_inventory


def test_pipeline_switch_payloads_explicitly_disable_preservation_for_every_fabric():
    text = (ROOT / "playbooks/nd_ensure_switches.yaml").read_text()
    play = yaml.safe_load(text)[0]
    # User-selected pipeline policy is explicit false even for External. The
    # collection's capability validation is unchanged and can reject that input.
    assert play["vars"]["nd_switch_preserve_config"] is False
    assert "'preserve_config': false" in text
    assert "nd_fabric_type_probe" not in text
    assert "nd_preserve_override" not in text
    onboard = next(task for task in play["tasks"] if task.get("name", "").startswith("Onboard the missing switches"))
    adds = [task for task in walk_tasks(onboard["block"]) if "cisco.nd.nd_manage_switches" in task]
    assert len(adds) == 1
    assert adds[0]["loop"] == "{{ nd_add_requests | dict2items }}"
    assert adds[0]["cisco.nd.nd_manage_switches"]["config"] == "{{ _req.value }}"
    assert 'preserve_config: "{{ nd_switch_preserve_config | bool }}"' not in text
    # Existing in-place role correction is a direct REST operation, not an
    # onboarding payload. Do not inject an unrelated preserve_config API field.
    confirm = next(task for task in play["tasks"] if task.get("name", "").startswith("Confirm the full canonical roster"))
    role_heal = next(task for task in confirm["block"] if task.get("name", "").startswith("Correct role drift"))
    assert role_heal["cisco.nd.nd_rest"]["path"].endswith("/switchActions/changeRoles")
    assert set(role_heal["cisco.nd.nd_rest"]["content"]["switchRoles"][0]) == {"switchId", "role"}
    for name in ("apply_ensure_switch_membership.yaml", "apply_membership_move.yaml", "apply_repair_switch.yaml"):
        prerequisite = yaml.safe_load((ROOT / "playbooks/nd_prerequisite" / name).read_text())
        onboards = [task["cisco.nd.nd_manage_switches"] for task in prerequisite
                    if task.get("cisco.nd.nd_manage_switches", {}).get("state") == "merged"]
        assert len(onboards) == 1
        assert onboards[0]["config"][0]["preserve_config"] is False


@pytest.mark.parametrize("environment_value, expected", [("", "inventory"), ("bound", "bound")])
def test_switch_onboarding_credentials_resolve_inventory_fallback(environment_value, expected):
    play = yaml.safe_load((ROOT / "playbooks/nd_ensure_switches.yaml").read_text())[0]
    environment = NativeEnvironment(undefined=StrictUndefined)
    environment.globals["lookup"] = lambda *args, **kwargs: environment_value
    context = {"switch_username": "inventory", "switch_password": "inventory"}
    for name in ("nd_switch_username", "nd_switch_password"):
        assert environment.from_string(play["vars"][name]).render(**context) == expected


def test_switch_removal_uses_verified_collection_sources_without_a_patch():
    source = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    assert "patch_nd_switch_removal.py" not in source
    assert "def CONSUL_PREFLIGHT_FILES = ['nd_ensure_switches.yaml', 'action_plugins/nd_switch_discovery.py']" in source
    block = source.split("def runNDFCVersionTests(", 1)[1].split("def runSwitchPreflight(", 1)[0]
    gate = '"${BASE_DIRECTORY}/venv/bin/python" "${COLLECTIONS_DIRECTORY}/nd_verify_develop_sources.py"'
    assert block.index(gate) < block.index("applyFabricRound(ndfcConfig)")


def test_source_patch_archive_is_not_an_active_runtime_input():
    source = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    runner = (ROOT / "tests/run_integration_module.yaml").read_text()
    for text in (source, runner):
        assert "patch.git.diff" not in text
        assert "patch_nd_switch_removal.py" not in text
        assert "git apply" not in text


def test_switch_move_checks_credentials_before_removing_any_switch():
    play = yaml.safe_load((ROOT / "playbooks/nd_ensure_switches.yaml").read_text())[0]
    names = [task["name"] for task in play["tasks"]]
    prerequisite = next(index for index, task in enumerate(play["tasks"])
                        if task["name"] == "Require switch discovery credentials before onboarding")
    removal = next(index for index, name in enumerate(names) if name.startswith("Move the roster switches out"))
    onboard = next(index for index, name in enumerate(names) if name.startswith("Onboard the missing switches"))
    assert prerequisite < removal < onboard
    task = play["tasks"][prerequisite]
    assert "nd_switch_apply | bool" in task["when"]
    assert "nd_missing_switches | length > 0" in task["when"]


def test_switch_removal_requires_scoped_acceptance_before_source_absence():
    play = yaml.safe_load((ROOT / "playbooks/nd_ensure_switches.yaml").read_text())[0]
    tasks = list(walk_tasks(play["tasks"]))
    removal = next(task for task in tasks if task.get("name") == "Remove each switch from the fabric it is leaving")
    classification = next(task for task in tasks if task.get("name", "").startswith("Classify the immediate normal removal response"))
    assert removal["cisco.nd.nd_rest"]["method"] == "post"
    assert removal["cisco.nd.nd_rest"]["path"].endswith("/switchActions/remove")
    assert "map(attribute='serial')" in removal["cisco.nd.nd_rest"]["content"]["switchIds"]
    assert removal["register"] == "nd_rehome_removed"
    assert removal["failed_when"] is False and removal["no_log"] is True
    assert classification["loop"] == "{{ nd_rehome_removed.results }}"
    assert classification["no_log"] is True
    report = classification["vars"]["_remove_report"]
    assert "'classification': 'refused' if ns.refused" in report
    assert "'accepted' if http in [200, 201, 202, 204, 207]" in report
    assert "'items': ns.details[:8]" in report
    # HTTP acceptance is required before the separate source-absence proof.
    assert any("accepted" in str(task.get("ansible.builtin.assert", {})) for task in tasks)


@pytest.mark.parametrize("name", ["apply_ensure_switch_membership.yaml", "apply_membership_move.yaml"])
def test_prerequisite_switch_onboarding_validates_credentials_before_mutation(name):
    tasks = yaml.safe_load((ROOT / "playbooks/nd_prerequisite" / name).read_text())
    assertion = tasks[0]["ansible.builtin.assert"]
    environment = NativeEnvironment(undefined=StrictUndefined)
    context = {"nd_switch_username": "", "nd_switch_password": "", "switch_username": "inventory", "switch_password": "inventory"}
    assert all(environment.compile_expression(condition)(**context) for condition in assertion["that"])
    assert not all(environment.compile_expression(condition)(**(context | {"switch_password": ""})) for condition in assertion["that"])
    add = next(task["cisco.nd.nd_manage_switches"] for task in tasks
               if task.get("cisco.nd.nd_manage_switches", {}).get("state") == "merged")
    for field in ("username", "password"):
        assert environment.from_string(add["config"][0][field]).render(**context) == "inventory"


def test_integration_config_declares_complete_canonical_fabric_membership():
    config = yaml.safe_load((ROOT / "tests/integration_config.yml").read_text())
    fabrics = config["nd_test_fabric_switches"]
    assert [item["name"] for item in fabrics["VXLAN_EVPN_Fabric"]] == [
        "vxlan_leaf_1", "vxlan_leaf_2", "vxlan_spine_1", "vxlan_border_1", "vxlan_leaf_3", "vxlan_leaf_4",
    ]
    assert [item["name"] for item in fabrics["External_Connectivity_Fabric"]] == [
        "external_edge_1", "external_edge_2",
    ]
    # nd_manage_switches upstream (targets/nd_manage_switches/tasks/base_tasks.yaml) reads exactly
    # THREE positional seed IPs: ansible_switch1->leaf, ansible_switch2->spine, ansible_switch3->border.
    # No ansible_switch4 exists, so this is a deliberate leaf/spine/border 3-of-8 subset; vxlan_leaf_2, vxlan_leaf_3
    # and vxlan_leaf_4 are carried by the full nd_test_fabric_switches roster above + the prerequisite reconcile step.
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


LAB_SWITCH_IDENTITIES = {
    "vxlan_leaf_1": ("192.0.2.195", "SERIAL00001"),
    "vxlan_leaf_2": ("192.0.2.196", "SERIAL00002"),
    "vxlan_spine_1": ("192.0.2.194", "SERIAL00003"),
    "vxlan_border_1": ("192.0.2.88", "SERIAL00004"),
    "vxlan_leaf_3": ("192.0.2.85", "SERIAL00008"),
    "vxlan_leaf_4": ("192.0.2.86", "SERIAL00009"),
    "external_edge_1": ("192.0.2.89", "SERIAL00005"),
    "external_edge_2": ("192.0.2.90", "SERIAL00006"),
}


def test_runtime_roster_and_defaults_match_confirmed_switch_identities():
    jenkins = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    rows = re.findall(
        r"\[name: '([^']+)', ip: '([^']+)', serial: '([^']+)', fabric: '([^']+)', role: '([^']+)'\]",
        jenkins,
    )
    assert len(rows) == len(LAB_SWITCH_IDENTITIES)
    assert {name: (ip, serial) for name, ip, serial, fabric, role in rows} == LAB_SWITCH_IDENTITIES
    for name, ip, serial, fabric, role in rows:
        external = name.startswith("external_")
        assert fabric == ("External_Connectivity_Fabric" if external else "VXLAN_EVPN_Fabric")
        assert role == ("edge_router" if external else name.split("_")[1])

    defaults = yaml.safe_load((ROOT / "tests/run_integration_module.yaml").read_text())[0]["vars"]
    for alias, name in {
        "switch_serial_1": "vxlan_leaf_1",
        "switch_serial_2": "vxlan_leaf_2",
        "switch_serial_3": "vxlan_spine_1",
        "ansible_sno_1": "vxlan_leaf_1",
        "ansible_sno_2": "vxlan_leaf_2",
        "nd_test_switch1_id": "vxlan_border_1",
        "nd_test_switch2_id": "external_edge_1",
    }.items():
        assert defaults[alias] == LAB_SWITCH_IDENTITIES[name][1], alias
    registry = load_registry(ROOT / "tests/nd_prerequisite_profiles.yaml")
    assert {name: (row["seed_ip"], row["serial"]) for name, row in registry["lab"]["switches"].items()} == LAB_SWITCH_IDENTITIES
    for position, name in ((1, "vxlan_leaf_1"), (2, "vxlan_leaf_2")):
        serial = LAB_SWITCH_IDENTITIES[name][1]
        assert f"vpc_pair_switch{position}_serial: '{serial}'" in jenkins
    for position, name in ((1, "vxlan_border_1"), (2, "external_edge_1")):
        ip, serial = LAB_SWITCH_IDENTITIES[name]
        assert f"nd_test_switch{position}_id={serial} -e nd_test_switch{position}_mgmt_ip={ip}" in jenkins


def test_every_roster_file_carries_all_eight_lab_switches(registry):
    # One entry per file that enumerates the lab: a switch missing from any of them is how a stale roster slips in.
    assert {
        name: (switch["seed_ip"], switch["serial"]) for name, switch in registry["lab"]["switches"].items()
    } == LAB_SWITCH_IDENTITIES
    roster_files = (
        "tests/integration_config.yml",
        "tests/nd_prerequisite_profiles.yaml",
        "tests/validate_nd_prerequisites.py",
        "tests/fixtures/nd_prerequisite/valid_state.yaml",
        "consul/inventory.yaml",
        "consul/reset_fabric.yaml",
        "playbooks/nd_prerequisite/nd_prerequisite_reconcile.yaml",
        "Jenkinsfile_nd_jenkins_script",
    )
    for relative in roster_files:
        text = (ROOT / relative).read_text()
        for name, (seed_ip, serial) in LAB_SWITCH_IDENTITIES.items():
            assert serial in text, f"{relative} is missing the serial of {name}"
            assert seed_ip in text, f"{relative} is missing the IP of {name}"


def serial_check_context(live_switches):
    play = yaml.safe_load((ROOT / "playbooks/nd_ensure_switches.yaml").read_text())[0]
    guard = next(task for task in play["tasks"] if task["name"].startswith("Verify live switch serials"))
    compare = next(task for task in guard["block"] if task["name"].startswith("Compare each roster IP"))
    roster = yaml.safe_load((ROOT / "tests/integration_config.yml").read_text())["nd_test_fabric_switches"]
    environment = NativeEnvironment(undefined=StrictUndefined)
    context = {"nd_switch_identity_inventory": {"current": {"switches": live_switches}}, "nd_switch_serial_rows": []}
    for fabric, switches in roster.items():
        for switch in switches:
            row_context = dict(context, _identity=({"key": fabric}, switch))
            for name, value in compare["vars"].items():
                if isinstance(value, dict):
                    row_context[name] = {key: environment.from_string(item).render(**row_context) for key, item in value.items()}
                else:
                    row_context[name] = environment.from_string(value).render(**row_context)
            context["nd_switch_serial_rows"] = environment.from_string(
                compare["ansible.builtin.set_fact"]["nd_switch_serial_rows"]
            ).render(**row_context)
    assertion = guard["block"][-1]["ansible.builtin.assert"]
    passed = environment.compile_expression(assertion["that"][0])(**context)
    report = environment.from_string(assertion["fail_msg"]).render(**context)
    return passed, context["nd_switch_serial_rows"], report


@pytest.mark.parametrize("change, expected_status", [
    ({"serialNumber": "STALE_SERIAL", "switchId": "STALE_SERIAL"}, "DRIFT"),
    ({"serialNumber": "", "switchId": ""}, "UNVERIFIED"),
    ({"serialNumber": "SERIAL00001", "switchId": "OTHER_SERIAL"}, "UNVERIFIED"),
])
def test_switch_serial_drift_fails_with_an_ip_to_serial_table(change, expected_status):
    live = [{"fabricManagementIp": ip, "serialNumber": serial, "switchId": serial} for ip, serial in LAB_SWITCH_IDENTITIES.values()]
    leaf = next(switch for switch in live if switch["fabricManagementIp"] == "192.0.2.195")
    leaf.update(change)
    passed, rows, report = serial_check_context(live)
    assert not passed
    assert next(row for row in rows if row["name"] == "vxlan_leaf_1")["status"] == expected_status
    assert "NDP_SWITCH_SERIAL_DRIFT" in report
    assert "192.0.2.195 | vxlan_leaf_1 | VXLAN_EVPN_Fabric | SERIAL00001 |" in report
    assert len(rows) == 8


def test_switch_serial_check_accepts_matching_identities_in_either_round_fabric():
    live = [{"fabricManagementIp": ip, "switchId": serial, "fabricName": "VXLAN_EVPN_Fabric_eBGP"}
            for ip, serial in LAB_SWITCH_IDENTITIES.values()]
    live.append({"fabricManagementIp": "192.0.2.181", "serialNumber": "UNRELATED_SWITCH"})
    passed, rows, _ = serial_check_context(live)
    assert passed
    assert all(row["status"] == "MATCH" for row in rows)


def test_switch_serial_check_leaves_absent_ips_eligible_for_onboarding():
    passed, rows, _ = serial_check_context([])
    assert passed
    assert len(rows) == 8
    assert all(row["status"] == "MISSING" for row in rows)


def test_switch_serial_check_rejects_ambiguous_ip_identity():
    passed, rows, _ = serial_check_context([
        {"fabricManagementIp": "192.0.2.195", "serialNumber": "SERIAL00001"},
        {"fabricManagementIp": "192.0.2.195", "serialNumber": "OTHER_SERIAL"},
    ])
    assert not passed
    assert next(row for row in rows if row["name"] == "vxlan_leaf_1")["status"] == "AMBIGUOUS"


def test_switch_serial_check_precedes_mutation_and_has_no_polling():
    play = yaml.safe_load((ROOT / "playbooks/nd_ensure_switches.yaml").read_text())[0]
    names = [task["name"] for task in play["tasks"]]
    index = next(index for index, name in enumerate(names) if name.startswith("Verify live switch serials"))
    assert index < names.index("Gather current inventory for each fabric in the roster")
    guard = play["tasks"][index]["block"]
    read = guard[0]
    assert read["cisco.nd.nd_rest"]["method"] == "get"
    assert read["cisco.nd.nd_rest"]["path"].startswith("/api/v1/manage/inventory/switches")
    assert read["check_mode"] is False
    for task in guard:
        assert not {"retries", "delay", "until", "ignore_errors", "failed_when", "when"} & set(task)
    assertion = guard[1]["ansible.builtin.assert"]
    environment = NativeEnvironment(undefined=StrictUndefined)
    for current in ({}, {"switches": None}, {"switches": "not-a-list"}, {"switches": {}}):
        assert not all(environment.compile_expression(condition)(nd_switch_identity_inventory={"current": current})
                       for condition in assertion["that"])


@pytest.mark.parametrize("live_serial, expected_returncode", [("SERIAL00001", 0), ("STALE_SERIAL", 2)])
def test_switch_serial_gate_aborts_ansible_before_followup_tasks(tmp_path, live_serial, expected_returncode):
    executable = pathlib.Path(sys.executable).with_name("ansible-playbook")
    if not executable.exists():
        pytest.skip("ansible-playbook is not installed in the test interpreter environment")
    play = yaml.safe_load((ROOT / "playbooks/nd_ensure_switches.yaml").read_text())[0]
    guard = next(task for task in play["tasks"] if task["name"].startswith("Verify live switch serials"))
    guard["block"][0] = {
        "name": "Provide read-only mock inventory",
        "ansible.builtin.set_fact": {"nd_switch_identity_inventory": {"current": {"switches": [
            {"fabricManagementIp": "192.0.2.195", "serialNumber": live_serial, "switchId": live_serial},
        ]}}},
    }
    roster = yaml.safe_load((ROOT / "tests/integration_config.yml").read_text())["nd_test_fabric_switches"]
    playbook = tmp_path / "serial-check.yaml"
    playbook.write_text(yaml.safe_dump([{
        "name": "Verify the serial gate without ND mutation", "hosts": "localhost", "gather_facts": False,
        "vars": {"nd_test_fabric_switches": roster},
        "tasks": [guard, {"name": "Followup", "ansible.builtin.debug": {"msg": "SERIAL_GATE_FOLLOWUP_REACHED"}}],
    }], sort_keys=False))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n")
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_HOME=str(tmp_path / "ansible-home"),
                       ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible-tmp"), ANSIBLE_STDOUT_CALLBACK="default",
                       ANSIBLE_NOCOLOR="1", ANSIBLE_FORCE_COLOR="0")
    environment.pop("ANSIBLE_CALLBACKS_ENABLED", None)
    result = subprocess.run([sys.executable, str(executable), "-i", "localhost,", "-c", "local", str(playbook)],
                            env=environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == expected_returncode, result.stdout + result.stderr
    assert ("SERIAL_GATE_FOLLOWUP_REACHED" in result.stdout) == (expected_returncode == 0)
    if expected_returncode:
        assert "NDP_SWITCH_SERIAL_DRIFT" in result.stdout
        assert "192.0.2.195 | vxlan_leaf_1 | VXLAN_EVPN_Fabric | SERIAL00001 | STALE_SERIAL | DRIFT" in result.stdout


def test_vpc_interface_runner_forms_and_removes_the_second_leaf_pair():
    runner = (ROOT / "tests/run_integration_module.yaml").read_text()
    ensure_text = (ROOT / "playbooks/nd_ensure_switches.yaml").read_text()
    # The multi-pair scenario never creates its second pair, so the runner forms leaf_3/leaf_4 like the first pair and
    # looks the pair up in the roster by the same management IPs the target reads.
    assert "nd_test_vpc_pair2_peer1_ip: 192.0.2.85" in runner
    assert "nd_test_vpc_pair2_peer2_ip: 192.0.2.86" in runner
    assert "selectattr('seed_ip', 'equalto', nd_test_vpc_pair2_peer1_ip)" in runner
    assert "selectattr('seed_ip', 'equalto', nd_test_vpc_pair2_peer2_ip)" in runner
    assert "SETUP - create the second physical vPC pair" in runner
    assert runner.count("use_virtual_peer_link: false") >= 2
    assert "CLEANUP - unpair the second vPC pair the runner formed for the vPC interface target" in runner
    assert "_ndp_vpcif2_pair_preexisting is defined" in runner
    # The read-only heal removes the second pair as well, so a stuck leaf_3/leaf_4 cannot block a Recalculate & Deploy.
    assert "Unpair the second vPC leaf pair on each fabric with a read-only leaf" in ensure_text


def test_border_and_external_edge_counts_match_canonical_lab(registry):
    topology = registry["topology_templates"]["border_edges"]
    assert topology["required_count"] == 3
    # vxlan_border_1 (baseline role 'border') hosts the L3Out: it is now cabled to external_edge_1
    # (border_1 Eth1/1 routed <-> edge_1 Eth1/3, probe-confirmed up/up) for the ext_l3_dci_link.
    # desired_role 'border' == its baseline role, so nd_manage_l3out (verify-only for switch
    # topology) requests no role change. vxlan_leaf_1 stays a plain leaf and is not in the L3Out.
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


def test_external_fabric_smoke_is_disposable_idempotent_and_always_cleans_up():
    path = ROOT / "playbooks/nd_manage_fabric_external.yaml"
    play = yaml.safe_load(path.read_text())[0]
    assert play["vars"]["nd_ext_fabric_name"] == "ANSIBLE_NIGHTLY_EXTERNAL"
    assert play["vars"]["nd_prerequisite"]["switch_count"] == 0
    management = play["vars"]["nd_ext_management"]
    assert management["day0_bootstrap"] is False
    assert management["local_dhcp_server"] is False
    assert management["scheduled_backup"] is False
    assert management["scheduled_backup_time"] == "00:00"
    assert all(management[field] for field in ("dhcp_start_address", "dhcp_end_address", "management_gateway"))
    lifecycle = next(task for task in play["tasks"] if "block" in task)
    module = "cisco.nd.nd_manage_fabric_external"
    assert [task[module]["state"] for task in lifecycle["block"] if module in task] == ["deleted", "merged", "merged"]
    repeat = next(task for task in lifecycle["block"] if task.get("register") == "nd_ext_repeat")
    assert repeat[module]["config"][0]["fabric_name"] == "{{ nd_ext_fabric_name }}"
    assert lifecycle["always"][0]["ansible.builtin.assert"]["that"][0] == "nd_ext_fabric_name is match('^ANSIBLE_NIGHTLY_')"
    assert lifecycle["always"][-1][module]["state"] == "deleted"
    assert not any(task.get("ignore_errors") for task in lifecycle["block"] + lifecycle["always"])
    assert validate_fabric_delete_guards([path]) == []


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


def test_checkpoint_covers_published_runtime_with_private_permissions(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o755)
    output = private / "checkpoint.json"
    write_checkpoint(ROOT, "task-1", output)
    report = json.loads(output.read_text())
    assert "Jenkinsfile_nd_jenkins_script" in report["files"]
    for relative in ("tests/run_integration_module.yaml", "tests/nd_prerequisite_profiles.yaml", "playbooks/nd_ensure_switches.yaml"):
        import hashlib
        assert report["files"][relative] == hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    assert private.stat().st_mode & 0o777 == 0o700
    assert output.stat().st_mode & 0o777 == 0o600

    link = tmp_path / "linked"
    link.symlink_to(private, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        write_checkpoint(ROOT, "task-1", link / "other.json")
    nested = link / "nested" / "checkpoint.json"
    with pytest.raises(ValueError, match="symlink"):
        write_checkpoint(ROOT, "task-1", nested)
