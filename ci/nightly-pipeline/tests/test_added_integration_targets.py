"""Four upstream integration targets added to the nightly: nd_interface_port_channel_routed, nd_local_user, nd_maintenance_mode
and nd_fabric_update_group.

The routed port-channel target is an ordinary interface target on vxlan_leaf_1. The other three change ND-side state that can
reach beyond the test objects, so the runner guards them:

* nd_local_user ends with a state: overridden step that deletes every controller local user it does not list, so it only starts
  while admin is the sole local user (plus leftovers of its own three logins).
* nd_fabric_update_group has overridden and auto-assign steps that act on every update group of the fabric, so it only starts
  while the fabric holds no group besides ND's built-in default group literally named "None" (plus its own two groups).
* nd_maintenance_mode only toggles the intended system mode, so it needs no skip guard; the runner proves both switches are
  present and not migrating, and verifies normal mode and configuration sync again afterwards.

These tests pin the registry, the Jenkins wiring and the runner, and evaluate the runner's own Jinja against ND response shapes
captured from the live lab, so every guard is proven offline.
"""
import pathlib
import re
import sys

import pytest
import yaml
from jinja2 import Environment
from jinja2.nativetypes import NativeEnvironment

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from validate_nd_prerequisites import jenkins_targets, load_registry, validate_selected_profiles  # noqa: E402

RUNNER_PATH = ROOT / "tests/run_integration_module.yaml"
JENKINS_PATH = ROOT / "Jenkinsfile_nd_jenkins_script"
FABRIC = "VXLAN_EVPN_Fabric"
NEW_MODULES = ("nd_interface_port_channel_routed", "nd_local_user", "nd_maintenance_mode", "nd_fabric_update_group")
LEAF3_IP, LEAF4_IP, SPINE_IP = "192.0.2.85", "192.0.2.86", "192.0.2.194"
OWN_LOGINS = ["ansible_local_user", "ansible_local_user_2", "ansible_local_user_3"]


# --- helpers --------------------------------------------------------------------------------------------------------

def runner_play():
    return yaml.safe_load(RUNNER_PATH.read_text(encoding="utf-8"))[0]


def walk(tasks):
    for task_ in tasks or []:
        yield task_
        for key in ("block", "rescue", "always"):
            yield from walk(task_.get(key))


def all_tasks():
    play = runner_play()
    return list(walk(play["pre_tasks"] + play["tasks"]))


def task(fragment):
    matches = [item for item in all_tasks() if fragment in str(item.get("name", ""))]
    assert len(matches) == 1, f"{fragment!r} matched {len(matches)} tasks"
    return matches[0]


def environment(env_class=Environment):
    """Plain Jinja plus the one Ansible filter the runner conditions use."""
    env = env_class()
    env.filters["bool"] = lambda value: str(value).lower() in ("true", "1", "yes", "on")
    return env


def render_facts(set_fact_task, context):
    env = environment(NativeEnvironment)
    return {key: env.from_string(value).render(**context) for key, value in set_fact_task["ansible.builtin.set_fact"].items()}


def render_text(text, context):
    return environment().from_string(text).render(**context)


def holds(condition, context):
    return bool(environment().compile_expression(condition)(**context))


def conditions(task_):
    when = task_.get("when", [])
    return [when] if isinstance(when, str) else list(when)


def runs(task_, context):
    """True when every `when` condition of the task holds, short-circuiting like Ansible does."""
    return all(holds(condition, context) for condition in conditions(task_))


def switch(ip, serial, mode="normal", intended=None, sync="inSync", role="leaf"):
    return {
        "fabricManagementIp": ip, "switchId": serial, "serialNumber": serial, "switchRole": role,
        "additionalData": {"systemMode": mode, "intendedSystemMode": intended or mode, "configSyncStatus": sync},
    }


def jenkins_skip_note(test_output):
    """Extract a bounded skip marker from the synthetic debug-output fixtures."""
    idx = test_output.find("NDP_MODULE_SKIPPED")
    assert idx >= 0
    tail = test_output[idx: idx + 420].replace("\r", " ").replace("\n", " ")
    tail = re.sub(r"\s+", " ", tail)
    cut = len(tail)
    for token in ("'", " Read `", " TASK [", " PLAY ["):
        position = tail.find(token, 20)
        if 0 < position < cut:
            cut = position
    note = tail[:cut].replace("|", "/").strip()
    return note[:200]


def ansible_debug_output(task_name, message, following="TASK [[x] SETUP - end the play cleanly]"):
    return f'TASK [{task_name}] ***\nok: [nd_controller] => {{\n    "msg": "{message}"\n}}\n\n{following} ***\n'


@pytest.fixture
def registry():
    return load_registry(ROOT / "tests/nd_prerequisite_profiles.yaml")


@pytest.fixture
def roster():
    return yaml.safe_load((ROOT / "tests/integration_config.yml").read_text(encoding="utf-8"))["nd_test_fabric_switches"][FABRIC]


# --- registry -------------------------------------------------------------------------------------------------------

def test_every_new_module_has_a_valid_profile(registry):
    for module in NEW_MODULES:
        assert validate_selected_profiles(registry, [f"integration.{module}"], allow_auto_confirm=True) == [], module


def test_routed_port_channel_profile_reserves_leaf1_members_and_its_own_namespace(registry):
    profile = registry["profiles"]["integration.nd_interface_port_channel_routed"]
    assert [member["ref"] for member in profile["switches"]["members"]] == ["vxlan_leaf_1"]
    free, port_channels, subinterfaces = profile["resources"]
    assert free["kind"] == "verify_free_interfaces"
    assert free["interfaces"] == [f"Ethernet1/{port}" for port in range(18, 22)]
    assert set(free["constraints"]) == {"exists", "not_port_channel_member", "not_fabric_link"}
    assert (port_channels["kind"], port_channels["interface_type"]) == ("verify_logical_interface_namespace", "port_channel")
    assert port_channels["interfaces"] == [f"Port-channel{number}" for number in range(520, 524)]
    assert (subinterfaces["interface_type"], subinterfaces["interfaces"]) == ("subinterface", ["Port-channel523.5"])
    assert all(item["expected_state"] == "absent" and item["requirement_status"] == "ready" for item in (port_channels, subinterfaces))
    assert profile["runtime_vars"] == {
        "nd_test_fabric_name": FABRIC, "nd_test_switch_ip": "192.0.2.195",
        "nd_test_pc_member_a": "Ethernet1/18", "nd_test_pc_member_b": "Ethernet1/19",
        "nd_test_pc_member_c": "Ethernet1/20", "nd_test_pc_member_d": "Ethernet1/21",
    }


def test_routed_port_channel_ids_do_not_collide_with_the_other_port_channel_targets(registry):
    def namespaces(module):
        resources = registry["profiles"][f"integration.{module}"]["resources"]
        return {
            name.lower()
            for item in resources if item["kind"] == "verify_logical_interface_namespace" and item["interface_type"] == "port_channel"
            for name in item["interfaces"]
        }
    routed = namespaces("nd_interface_port_channel_routed")
    for other in ("nd_interface_port_channel_access", "nd_interface_port_channel_trunk_host"):
        assert routed.isdisjoint(namespaces(other)), other
    # The subinterface targets use Port-channel10 as their routed parent.
    assert "port-channel10" not in routed


def test_the_three_port_channel_targets_reserve_disjoint_member_pools(registry):
    # Option A de-confliction: each port-channel target owns its own 4-port pool on vxlan_leaf_1, so a member left
    # stuck by one target's failed teardown cannot starve the free-interface gate of the next target.
    allowlist = set(registry["lab"]["interface_allowlist"]["vxlan_leaf_1"])
    pools = {}
    for module, expected in (
        ("nd_interface_port_channel_access", [f"Ethernet1/{port}" for port in range(10, 14)]),
        ("nd_interface_port_channel_trunk_host", [f"Ethernet1/{port}" for port in range(14, 18)]),
        ("nd_interface_port_channel_routed", [f"Ethernet1/{port}" for port in range(18, 22)]),
    ):
        profile = registry["profiles"][f"integration.{module}"]
        free = profile["resources"][0]
        assert free["kind"] == "verify_free_interfaces"
        assert free["interfaces"] == expected, module
        assert [profile["runtime_vars"][f"nd_test_pc_member_{letter}"] for letter in "abcd"] == expected, module
        assert set(expected) <= allowlist, module
        pools[module] = set(expected)
    modules = list(pools)
    for index, left in enumerate(modules):
        for right in modules[index + 1:]:
            assert pools[left].isdisjoint(pools[right]), (left, right)


def test_local_user_profile_is_controller_level_without_fabric_or_switch(registry):
    profile = registry["profiles"]["integration.nd_local_user"]
    assert profile["phase"] == "controller_disposable"
    assert profile["fabrics"] == []
    assert profile["switches"] == {"required_count": 0, "members": []}
    assert profile["resources"] == [] and profile["runtime_vars"] == {}
    assert "admin" in " ".join(profile["confirmation"]["reasons"])


def test_the_two_switch_profiles_are_verify_only_and_agree_with_the_roster(registry, roster):
    seed = {entry["name"]: entry["seed_ip"] for entry in roster}
    for module, members, keys in (
        ("nd_maintenance_mode", ["vxlan_leaf_3", "vxlan_leaf_4"],
         ["nd_test_maintenance_mode_switch_ip_a", "nd_test_maintenance_mode_switch_ip_b"]),
        ("nd_fabric_update_group", ["vxlan_leaf_3", "vxlan_leaf_4", "vxlan_spine_1"],
         ["nd_test_update_switch_a", "nd_test_update_switch_b", "nd_test_update_switch_c"]),
    ):
        profile = registry["profiles"][f"integration.{module}"]
        assert [member["ref"] for member in profile["switches"]["members"]] == members
        assert profile["switches"]["required_count"] == len(members)
        for member in profile["switches"]["members"]:
            # Verify-only for switch topology: the planner must see each switch in its baseline role.
            assert member["desired_role"] == registry["lab"]["switches"][member["ref"]]["baseline_role"]
            assert member["desired_fabric_ref"] == "advanced"
        # The management IPs the target runs on are those of the verified members, in order.
        assert [profile["runtime_vars"][key] for key in keys] == [seed[name] for name in members]
        assert len(set(profile["runtime_vars"][key] for key in keys)) == len(keys)


def test_runner_play_vars_equal_the_registry_runtime_vars(registry):
    play_vars = runner_play()["vars"]
    for module in ("nd_maintenance_mode", "nd_fabric_update_group"):
        for key, value in registry["profiles"][f"integration.{module}"]["runtime_vars"].items():
            if key in ("nd_test_fabric_name", "nd_test_maintenance_mode_fabric_name"):
                continue  # fabric names follow the round (-e fabric_name); render-round swaps the registry literal
            assert play_vars[key] == value, key
    assert play_vars["nd_test_maintenance_mode_fabric_name"] == "{{ fabric_name }}"
    assert play_vars["nd_test_fabric_name"] == "{{ fabric_name }}"


def test_the_new_registry_and_runner_text_survive_the_fabric_round_rendering():
    """render-round swaps whole fabric names and requires exactly one `vrfType: vxlanIbgp` in the runner."""
    runner = RUNNER_PATH.read_text(encoding="utf-8")
    assert runner.count("vrfType: vxlanIbgp") == 1
    block = runner.split("# SETUP (nd_local_user only, read-only)", 1)[1].split("# SETUP: run the target's own setup/prepare file FIRST", 1)[0]
    # The guards use the play's variables, never a literal fabric name, so both rounds run them on their own fabric.
    for literal in ("VXLAN_EVPN_Fabric", "External_Connectivity_Fabric"):
        assert literal not in block


# --- Jenkins --------------------------------------------------------------------------------------------------------

def test_jenkins_wires_every_new_module_in_a_safe_order():
    text = JENKINS_PATH.read_text(encoding="utf-8")
    targets = jenkins_targets(text)
    integration, interface, effective = targets["INTEGRATION_MODULES"], targets["INTERFACE_INTEGRATION_MODULES"], targets["EFFECTIVE_INTEGRATION_MODULES"]
    for module in NEW_MODULES:
        assert module in effective, module
        assert module not in targets["STANDALONE_INTEGRATION_MODULES"], module
    assert interface.index("nd_interface_port_channel_trunk_host") + 1 == interface.index("nd_interface_port_channel_routed")
    assert interface.index("nd_interface_port_channel_routed") < interface.index("nd_interface_subinterface_managed")
    assert integration.index("nd_local_user") > integration.index("nd_manage_fabric_group_members")
    assert integration.index("nd_maintenance_mode") > integration.index("nd_manage_tor")
    assert integration.index("nd_fabric_update_group") > integration.index("nd_maintenance_mode")
    # The user excludes the switch lifecycle; all other baseline targets stay selected.
    assert "nd_manage_switches" not in effective
    destructive = [effective.index(name) for name in ("nd_resource_manager", "nd_manage_fabric", "nd_manage_links")]
    assert all(effective.index(module) < min(destructive) for module in NEW_MODULES)


def test_jenkins_gives_each_port_channel_target_its_own_disjoint_member_ports():
    text = JENKINS_PATH.read_text(encoding="utf-8")
    for module, base in (
        ("nd_interface_port_channel_access", 10),
        ("nd_interface_port_channel_trunk_host", 14),
        ("nd_interface_port_channel_routed", 18),
    ):
        assert f"{module})" in text, module
        case = text.split(f"{module})", 1)[1].split(";;", 1)[0]
        for index, port in enumerate("abcd"):
            assert f"-e nd_test_pc_member_{port}=Ethernet1/{base + index}" in case, module
    # The optional IOS-XE scenario of the routed target stays off: nothing may ever supply nd_test_xe_switch_ip.
    for source in (text, RUNNER_PATH.read_text(encoding="utf-8"), (ROOT / "run_all_integ.sh").read_text(encoding="utf-8")):
        assert re.search(r"nd_test_xe_switch_ip\s*[=:]", source) is None


def test_the_manual_runner_script_mirrors_the_nightly():
    script = (ROOT / "run_all_integ.sh").read_text(encoding="utf-8")
    for module in NEW_MODULES:
        assert re.search(rf"^\s+{module}$", script, re.M), module
    for module, base in (
        ("nd_interface_port_channel_access", 10),
        ("nd_interface_port_channel_trunk_host", 14),
        ("nd_interface_port_channel_routed", 18),
    ):
        assert f"{module})" in script, module
        case = script.split(f"{module})", 1)[1].split(";;", 1)[0]
        for index, port in enumerate("abcd"):
            assert f"-e nd_test_pc_member_{port}=Ethernet1/{base + index}" in case, module


def test_the_runner_runs_the_upstream_target_for_every_new_module():
    include = task("include collection target (all configured cases)")
    for module in NEW_MODULES:
        assert module not in include["when"], module
        assert runs(include, {"test_module": module})
    assert runs(include, {"test_module": "nd_manage_tor"})


# --- nd_local_user guard --------------------------------------------------------------------------------------------

def local_user_context(logins):
    users = [{"loginID": login, "accountStatus": "Active"} for login in logins]
    context = {"test_module": "nd_local_user", "nd_prerequisite_only": False, "_ndp_lu_live": {"current": {"localusers": users}}}
    for fragment in ("SETUP - read the controller local users",):
        assert runs(task(fragment), context)
    context.update(render_facts(task("SETUP - find the logins this test does not own"), context))
    return context


@pytest.mark.parametrize("logins, expected_foreign, skips", [
    (["admin"], [], False),
    (["admin", *OWN_LOGINS], [], False),
    (["admin", "ansible_local_user_2"], [], False),
    (["admin", "bob"], ["bob"], True),
    (["admin", "ansible_local_user", "ops_team", "bob"], ["ops_team", "bob"], True),
    ([], [], True),
    (["bob"], ["bob"], True),
])
def test_the_local_user_guard_starts_only_when_admin_is_the_sole_foreign_free_account(logins, expected_foreign, skips):
    context = local_user_context(logins)
    assert context["_ndp_lu_foreign"] == expected_foreign
    assert runs(task("SETUP - end the play cleanly before any local user is touched"), context) is skips
    assert runs(task("SETUP - report nd_local_user as skipped when other local users exist"), context) is skips


def test_the_local_user_guard_reads_before_it_decides_and_fails_closed_on_api_errors():
    read = task("SETUP - read the controller local users")
    assert read["cisco.nd.nd_rest"] == {"method": "get", "path": "/api/v1/infra/aaa/localUsers"}
    # No failed_when/ignore_errors: a controller that cannot be read must fail the module, never run the destructive target.
    assert "failed_when" not in read and "ignore_errors" not in read
    assert read["no_log"] is True and read["check_mode"] is False


def test_the_local_user_guard_does_nothing_for_other_modules_and_in_audit_mode():
    for context in (
        {"test_module": "nd_manage_tor", "nd_prerequisite_only": False},
        {"test_module": "nd_local_user", "nd_prerequisite_only": True},
    ):
        for fragment in (
            "SETUP - read the controller local users", "SETUP - find the logins this test does not own",
            "SETUP - report nd_local_user as skipped when other local users exist",
            "SETUP - end the play cleanly before any local user is touched",
        ):
            assert not runs(task(fragment), context), (context, fragment)


def test_the_local_user_skip_message_is_greppable_and_yields_a_clean_jenkins_note():
    report = task("SETUP - report nd_local_user as skipped when other local users exist")
    context = local_user_context(["admin", "bob", "ops_team"])
    message = render_text(report["ansible.builtin.debug"]["msg"], context)
    assert message.startswith("NDP_MODULE_SKIPPED [integration.nd_local_user]: ")
    assert "bob, ops_team" in message
    # The Jenkins skip-note parser cuts at the first apostrophe, so none may precede the Read pointer.
    assert "'" not in message.split(" Read `", 1)[0]
    note = jenkins_skip_note(ansible_debug_output(report["name"], message))
    assert note == (
        "NDP_MODULE_SKIPPED [integration.nd_local_user]: local users besides admin exist (bob, ops_team); "
        "the overridden step of the target would delete them."
    )
    assert len(note) < 200 and "\"" not in note and "}" not in note

    no_admin = local_user_context(["ops"])
    no_admin["_ndp_lu_foreign"] = []
    assert "no local user named admin" in render_text(report["ansible.builtin.debug"]["msg"], no_admin)


def test_the_skip_ends_the_play_before_any_target_task_so_no_account_is_touched():
    play = runner_play()
    names = [str(item.get("name", "")) for item in play["tasks"]]
    skip = next(index for index, name in enumerate(names) if "end the play cleanly before any local user is touched" in name)
    update_groups = next(index for index, name in enumerate(names) if "precheck the update-group topology" in name)
    setup = next(index for index, name in enumerate(names) if "run target setup/prepare first" in name)
    run_block = next(index for index, name in enumerate(names) if "RUN full integration suite" in name)
    assert skip < setup < run_block
    assert update_groups < setup
    assert play["tasks"][skip]["ansible.builtin.meta"] == "end_play"
    inner = task("SETUP - end the play cleanly before any update group is touched")
    assert inner["ansible.builtin.meta"] == "end_play"


def test_the_local_user_cleanup_deletes_only_the_three_test_logins_and_only_after_a_passed_guard():
    cleanup = task("CLEANUP - delete the test local users this run may have left")
    module = cleanup["cisco.nd.nd_local_user"]
    assert module["state"] == "deleted"
    assert [item["login_id"] for item in module["config"]] == OWN_LOGINS
    assert "admin" not in str(module)
    assert cleanup["ignore_errors"] is True
    base = {"test_module": "nd_local_user", "nd_prerequisite_only": False}
    assert not runs(cleanup, base)                                          # guard never ran
    assert not runs(cleanup, base | {"_ndp_lu_foreign": ["bob"]})           # guard said skip
    assert runs(cleanup, base | {"_ndp_lu_foreign": []})
    assert not runs(cleanup, base | {"test_module": "nd_manage_tor", "_ndp_lu_foreign": []})


# --- nd_maintenance_mode guard --------------------------------------------------------------------------------------

def maintenance_context(switches):
    context = {
        "test_module": "nd_maintenance_mode",
        "nd_prerequisite_only": False,
        "nd_test_maintenance_mode_fabric_name": FABRIC,
        "nd_test_maintenance_mode_switch_ip_a": LEAF3_IP,
        "nd_test_maintenance_mode_switch_ip_b": LEAF4_IP,
        "_ndp_mm_live": {"current": {"switches": switches}},
    }
    context.update(render_facts(task("SETUP - select the two switches by management IP"), context))
    return context


def maintenance_passes(context):
    assertion = task("SETUP - require both switches present and not migrating")["ansible.builtin.assert"]
    return all(holds(condition, context) for condition in assertion["that"])


LEAF1 = switch("192.0.2.195", "AAA")


@pytest.mark.parametrize("switches, passes", [
    ([LEAF1, switch(LEAF3_IP, "S3"), switch(LEAF4_IP, "S4")], True),
    # a leftover maintenance mode is forced back to normal by the target's own setup, so it must not block the run
    ([switch(LEAF3_IP, "S3", mode="maintenance"), switch(LEAF4_IP, "S4", mode="maintenance")], True),
    ([switch(LEAF3_IP, "S3", mode="inconsistent", intended="normal"), switch(LEAF4_IP, "S4")], True),
    ([switch(LEAF3_IP, "S3")], False),
    ([LEAF1], False),
    ([], False),
    ([switch(LEAF3_IP, "S3", mode="migration"), switch(LEAF4_IP, "S4")], False),
    ([switch(LEAF3_IP, "S3"), switch(LEAF4_IP, "S4", mode="normal", intended="migration")], False),
])
def test_the_maintenance_precheck_requires_both_switches_present_and_not_migrating(switches, passes):
    assert maintenance_passes(maintenance_context(switches)) is passes


def test_the_maintenance_precheck_selects_by_management_ip_and_keeps_the_serials_for_the_cleanup():
    context = maintenance_context([LEAF1, switch(LEAF3_IP, "S3"), switch(LEAF4_IP, "S4")])
    assert [item["fabricManagementIp"] for item in context["_ndp_mm_switches"]] == [LEAF3_IP, LEAF4_IP]
    deploy = task("CLEANUP - push the pending maintenance-mode switch state")
    ids = NativeEnvironment().from_string(deploy["cisco.nd.nd_rest"]["content"]["switchIds"]).render(**context)
    assert ids == ["S3", "S4"]


def test_the_maintenance_precheck_is_a_read_only_block_that_fails_closed():
    block = task("SETUP - precheck the maintenance-mode switches")
    assert not runs(block, {"test_module": "nd_manage_tor", "nd_prerequisite_only": False})
    assert not runs(block, {"test_module": "nd_maintenance_mode", "nd_prerequisite_only": True})
    for inner in block["block"]:
        for module_name, arguments in inner.items():
            if module_name == "cisco.nd.nd_rest":
                assert arguments["method"] == "get"
        assert "ignore_errors" not in inner and "failed_when" not in inner


def sync_context(sync, modes=("normal", "normal"), intended=("normal", "normal")):
    context = maintenance_context([
        switch(LEAF3_IP, "S3", mode=modes[0], intended=intended[0], sync=sync[0]),
        switch(LEAF4_IP, "S4", mode=modes[1], intended=intended[1], sync=sync[1]),
    ])
    context["_ndp_mm_restored"] = context["_ndp_mm_live"]
    context.update(render_facts(task("CLEANUP - record the configuration sync state after the mode restore"), context))
    return context


def test_the_maintenance_cleanup_recalculates_and_deploys_only_when_a_switch_is_not_in_sync():
    names = ("CLEANUP - save the fabric configuration", "CLEANUP - push the pending maintenance-mode switch state",
             "CLEANUP - wait for both maintenance-mode switches to report in sync")
    synced = sync_context(("inSync", "inSync"))
    pending = sync_context(("pending", "inSync"))
    for fragment in names:
        assert not runs(task(fragment), synced), fragment
        assert runs(task(fragment), pending), fragment
        assert not runs(task(fragment), pending | {"test_module": "nd_manage_tor"}), fragment


def test_the_maintenance_cleanup_runs_only_after_the_precheck_recorded_the_switches():
    for fragment in ("CLEANUP - read both switches back after the mode restore", "CLEANUP - report the mode restore"):
        step = task(fragment)
        assert not runs(step, {"test_module": "nd_maintenance_mode", "nd_prerequisite_only": False})
        assert runs(step, {"test_module": "nd_maintenance_mode", "nd_prerequisite_only": False, "_ndp_mm_switches": []})
        assert not runs(step, {"test_module": "nd_maintenance_mode", "nd_prerequisite_only": True, "_ndp_mm_switches": []})


@pytest.mark.parametrize("modes, intended, ok", [
    (("normal", "normal"), ("normal", "normal"), True),
    (("maintenance", "normal"), ("normal", "normal"), False),
    (("normal", "normal"), ("normal", "maintenance"), False),
    (("inconsistent", "normal"), ("normal", "normal"), False),
])
def test_the_restore_report_requires_normal_system_and_intended_modes(modes, intended, ok):
    context = sync_context(("inSync", "inSync"), modes, intended)
    assertion = task("CLEANUP - report the mode restore")["ansible.builtin.assert"]
    assert all(holds(condition, context) for condition in assertion["that"]) is ok


def test_the_maintenance_teardown_gets_its_nd_info_before_it_runs_stand_alone():
    """Live 2026-10-13/16: the stand-alone pre-clean/teardown reads nd_info, so the runner now defines it for EVERY
    module (nd_maintenance_mode, nd_manage_prefix_list, nd_manage_community_list ...) before that step, skipping only
    prerequisite-only runs."""
    names = [str(item.get("name", "")) for item in runner_play()["tasks"]]
    define = next(index for index, name in enumerate(names) if "SETUP - define nd_info for the stand-alone pre-clean/teardown" in name)
    pre_clean = next(index for index, name in enumerate(names) if "SETUP - pre-clean stale objects" in name)
    assert define < pre_clean
    step = task("SETUP - define nd_info for the stand-alone pre-clean/teardown")
    assert step["ansible.builtin.set_fact"]["nd_info"] == {"output_level": '{{ api_key_output_level | default("debug") }}'}
    assert runs(step, {"test_module": "nd_maintenance_mode", "nd_prerequisite_only": False})
    assert runs(step, {"test_module": "nd_manage_tor", "nd_prerequisite_only": False})
    assert not runs(step, {"test_module": "nd_maintenance_mode", "nd_prerequisite_only": True})


def test_the_maintenance_cleanup_steps_run_in_the_order_that_makes_sense():
    run_block = next(item for item in runner_play()["tasks"] if "RUN full integration suite" in str(item.get("name", "")))
    names = [str(item.get("name", "")) for item in run_block["always"]]
    order = [
        "CLEANUP - post-clean (required)",          # the target's own teardown restores normal mode first
        "CLEANUP - read both switches back after the mode restore",
        "CLEANUP - record the configuration sync state after the mode restore",
        "CLEANUP - save the fabric configuration",
        "CLEANUP - push the pending maintenance-mode switch state",
        "CLEANUP - wait for both maintenance-mode switches to report in sync",
        "CLEANUP - report the mode restore",
    ]
    positions = [next(index for index, name in enumerate(names) if fragment in name) for fragment in order]
    assert positions == sorted(positions)


# --- nd_fabric_update_group guard -----------------------------------------------------------------------------------

DEFAULT_GROUP = {"updateGroupName": "None", "updateGroupSwitches": ["S1", "S2", "S3", "S4", "S5", "S6"], "execution": "parallel"}


def update_group_context(groups, present=(LEAF3_IP, LEAF4_IP, SPINE_IP)):
    live = [switch(ip, f"S{index}") for index, ip in enumerate(present)] + [switch("192.0.2.195", "AAA")]
    context = {
        "test_module": "nd_fabric_update_group",
        "nd_prerequisite_only": False,
        "nd_test_fabric_name": FABRIC,
        "nd_test_update_switch_a": LEAF3_IP,
        "nd_test_update_switch_b": LEAF4_IP,
        "nd_test_update_switch_c": SPINE_IP,
        "_ndp_ug_live": {"current": {"switches": live}},
        "_ndp_ug_groups": {"current": {"updateGroups": groups}},
    }
    context.update(render_facts(task("SETUP - find the test switches and the groups this test does not own"), context))
    return context


@pytest.mark.parametrize("groups, foreign, skips", [
    ([DEFAULT_GROUP], [], False),                                    # the live lab today: only ND's built-in default group
    ([], [], False),
    ([DEFAULT_GROUP, {"updateGroupName": "ansible_leaf_group"}, {"updateGroupName": "ansible_spine_group"}], [], False),
    ([DEFAULT_GROUP, {"updateGroupName": "release_wave_1"}], ["release_wave_1"], True),
    ([DEFAULT_GROUP, {"updateGroupName": "ansible_leaf_group"}, {"updateGroupName": "leaf"}, {"updateGroupName": "spine"}], ["leaf", "spine"], True),
    ([DEFAULT_GROUP, {"updateGroupSwitches": ["S1"]}], [], False),    # an entry without a name is not a group anyone owns
])
def test_the_update_group_guard_starts_only_without_foreign_groups(groups, foreign, skips):
    context = update_group_context(groups)
    assert context["_ndp_ug_foreign"] == foreign
    assert runs(task("SETUP - end the play cleanly before any update group is touched"), context) is skips
    assert runs(task("SETUP - report nd_fabric_update_group as skipped when other update groups exist"), context) is skips


def test_the_update_group_guard_requires_all_three_switches_in_the_fabric():
    assertion = task("SETUP - require the three test switches in the fabric")["ansible.builtin.assert"]
    assert all(holds(condition, update_group_context([DEFAULT_GROUP])) for condition in assertion["that"])
    assert not all(holds(condition, update_group_context([DEFAULT_GROUP], present=(LEAF3_IP, LEAF4_IP))) for condition in assertion["that"])
    assert "NDP_UPDATE_GROUP_PRECHECK_FAIL" in assertion["fail_msg"]


def test_the_update_group_skip_message_yields_a_clean_jenkins_note():
    report = task("SETUP - report nd_fabric_update_group as skipped when other update groups exist")
    context = update_group_context([DEFAULT_GROUP, {"updateGroupName": "release_wave_1"}])
    message = render_text(report["ansible.builtin.debug"]["msg"], context)
    assert message.startswith("NDP_MODULE_SKIPPED [integration.nd_fabric_update_group]: ")
    assert "'" not in message.split(" Read `", 1)[0]
    note = jenkins_skip_note(ansible_debug_output(report["name"], message))
    assert note == (
        "NDP_MODULE_SKIPPED [integration.nd_fabric_update_group]: update groups besides the default one exist (release_wave_1); "
        "the overridden and auto-assign steps of the target would delete or regroup them."
    )
    assert len(note) < 200


def test_the_update_group_guard_is_read_only_and_ordered_before_any_target_task():
    block = task("SETUP - precheck the update-group topology")
    assert not runs(block, {"test_module": "nd_manage_tor", "nd_prerequisite_only": False})
    assert not runs(block, {"test_module": "nd_fabric_update_group", "nd_prerequisite_only": True})
    for inner in block["block"]:
        arguments = inner.get("cisco.nd.nd_rest")
        if arguments:
            assert arguments["method"] == "get" and arguments["path"].startswith("/api/v1/manage/fabrics/")
            assert "failed_when" not in inner and "ignore_errors" not in inner
    names = [str(item.get("name", "")) for item in runner_play()["tasks"]]
    assert names.index("[{{ test_module }}] SETUP - precheck the update-group topology") < next(
        index for index, name in enumerate(names) if "RUN full integration suite" in name
    )


def test_the_update_group_cleanup_deletes_only_what_this_run_created():
    read = task("CLEANUP - read the update groups left in the fabric")
    delete = task("CLEANUP - delete every update group this run created")
    base = {"test_module": "nd_fabric_update_group", "nd_prerequisite_only": False, "nd_test_fabric_name": FABRIC}
    leftovers = {"current": {"updateGroups": [DEFAULT_GROUP, {"updateGroupName": "ansible_leaf_group"}, {"updateGroupName": "roleBased_leaf"}]}}
    for step in (read, delete):
        assert not runs(step, base)                                       # the guard never ran
        assert not runs(step, base | {"_ndp_ug_foreign": ["release_wave_1"]})  # the guard said skip
        assert not runs(step, base | {"_ndp_ug_foreign": [], "test_module": "nd_manage_tor"})
    assert runs(read, base | {"_ndp_ug_foreign": []})
    assert not runs(delete, base | {"_ndp_ug_foreign": [], "_ndp_ug_after": {"current": {"updateGroups": [DEFAULT_GROUP]}}})
    context = base | {"_ndp_ug_foreign": [], "_ndp_ug_after": leftovers}
    assert runs(delete, context)
    names = NativeEnvironment().from_string(delete["vars"]["_ndp_ug_leftover"]).render(**context)
    assert names == ["ansible_leaf_group", "roleBased_leaf"]               # never ND's default group named None
    assert delete["cisco.nd.nd_fabric_update_group"]["state"] == "deleted"
    assert delete["ignore_errors"] is True


# --- shared topology facts ------------------------------------------------------------------------------------------

def test_the_required_topology_facts_reject_missing_or_duplicate_test_switches():
    assertion = task("validate required topology facts")["ansible.builtin.assert"]["that"]
    maintenance = next(item for item in assertion if "nd_maintenance_mode" in item)
    update_group = next(item for item in assertion if "nd_fabric_update_group" in item)
    play_vars = runner_play()["vars"]
    good = {
        "test_module": "nd_maintenance_mode", "nd_test_maintenance_mode_fabric_name": FABRIC,
        "nd_test_maintenance_mode_switch_ip_a": play_vars["nd_test_maintenance_mode_switch_ip_a"],
        "nd_test_maintenance_mode_switch_ip_b": play_vars["nd_test_maintenance_mode_switch_ip_b"],
    }
    assert holds(maintenance, good)
    assert not holds(maintenance, good | {"nd_test_maintenance_mode_switch_ip_b": good["nd_test_maintenance_mode_switch_ip_a"]})
    assert not holds(maintenance, good | {"nd_test_maintenance_mode_switch_ip_b": ""})
    assert not holds(maintenance, good | {"nd_test_maintenance_mode_fabric_name": ""})
    assert holds(maintenance, good | {"test_module": "nd_manage_tor", "nd_test_maintenance_mode_switch_ip_b": ""})

    good = {
        "test_module": "nd_fabric_update_group", "nd_test_fabric_name": FABRIC,
        "nd_test_update_switch_a": LEAF3_IP, "nd_test_update_switch_b": LEAF4_IP, "nd_test_update_switch_c": SPINE_IP,
    }
    assert holds(update_group, good)
    assert not holds(update_group, good | {"nd_test_update_switch_c": LEAF3_IP})
    assert not holds(update_group, good | {"nd_test_update_switch_c": ""})
    assert holds(update_group, good | {"test_module": "nd_manage_tor", "nd_test_update_switch_c": LEAF3_IP})


def test_no_new_task_name_collides_with_the_tor_cleanup_ordering_keys():
    # test_tor_pairing pins the ToR cleanup order by name fragments; the new maintenance-mode cleanup must not match them.
    tor_keys = ("remove the ToR association", "roster role back", "read the role back", "recalculate", "deploy the two", "wait until both", "report the restore")
    for item in all_tasks():
        name = str(item.get("name", ""))
        if any(word in name for word in ("maintenance-mode", "mode restore", "update group", "local users", "local user")):
            assert not any(key in name for key in tor_keys), name
