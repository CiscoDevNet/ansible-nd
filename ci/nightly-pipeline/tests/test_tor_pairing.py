"""nd_manage_tor runs a pipeline-owned reduced ToR test instead of the upstream target.

The upstream target needs six or seven switches in one fabric (three ToR-role, three leaf-role) and two vPC pairs, which
the lab cannot provide. The runner pairs vxlan_leaf_3 (ToR role for the test only) with vxlan_leaf_4 (leaf). ND 4.3 records
that association intent without cabling, save or deploy (live probe 2026-10-13), so the single 1:1 topology is enough.
These tests pin the registry, the Jenkins wiring and the runner structure, and evaluate the runner's own Jinja against
sample ND data so the precheck, the resolution by management IP and the restore verification are proven offline.
"""
import copy
import pathlib
import sys

import pytest
import yaml
from jinja2 import Environment
from jinja2.nativetypes import NativeEnvironment

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from validate_nd_prerequisites import jenkins_targets, load_registry, validate_selected_profiles  # noqa: E402

RUNNER_PATH = ROOT / "tests/run_integration_module.yaml"
FABRIC = "VXLAN_EVPN_Fabric"
TOR_IP, LEAF_IP = "192.0.2.85", "192.0.2.86"
TOR_SERIAL, LEAF_SERIAL = "SERIAL00008", "SERIAL00009"

ROSTER = {
    FABRIC: [
        {"name": "vxlan_leaf_1", "seed_ip": "192.0.2.195", "serial": "SERIAL00001", "role": "leaf"},
        {"name": "vxlan_leaf_2", "seed_ip": "192.0.2.196", "serial": "SERIAL00002", "role": "leaf"},
        {"name": "vxlan_spine_1", "seed_ip": "192.0.2.194", "serial": "SERIAL00003", "role": "spine"},
        {"name": "vxlan_border_1", "seed_ip": "192.0.2.88", "serial": "SERIAL00004", "role": "border"},
        {"name": "vxlan_leaf_3", "seed_ip": TOR_IP, "serial": TOR_SERIAL, "role": "leaf"},
        {"name": "vxlan_leaf_4", "seed_ip": LEAF_IP, "serial": LEAF_SERIAL, "role": "leaf"},
    ]
}


def runner_play():
    return yaml.safe_load(RUNNER_PATH.read_text(encoding="utf-8"))[0]


def walk(tasks):
    for task in tasks or []:
        yield task
        for key in ("block", "rescue", "always"):
            yield from walk(task.get(key))


def all_tasks():
    play = runner_play()
    return list(walk(play["pre_tasks"] + play["tasks"]))


def task(fragment):
    matches = [item for item in all_tasks() if fragment in str(item.get("name", ""))]
    assert len(matches) == 1, f"{fragment!r} matched {len(matches)} tasks"
    return matches[0]


def render_facts(set_fact_task, context):
    env = NativeEnvironment()
    return {key: env.from_string(value).render(**context) for key, value in set_fact_task["ansible.builtin.set_fact"].items()}


def holds(condition, context):
    return bool(Environment().compile_expression(condition)(**context))


def switch(ip, serial, role="leaf", mode="normal", sync="inSync"):
    return {
        "fabricManagementIp": ip, "serialNumber": serial, "switchRole": role,
        "additionalData": {"systemMode": mode, "configSyncStatus": sync},
    }


def base_context(tor=None, leaf=None, pairs=None):
    live = [
        switch("192.0.2.195", "SERIAL00001"),
        tor or switch(TOR_IP, TOR_SERIAL),
        leaf or switch(LEAF_IP, LEAF_SERIAL),
    ]
    return {
        "nd_test_fabric_switches": ROSTER,
        "ansible_it_fabric": FABRIC,
        "nd_tor_switch_name": "vxlan_leaf_3",
        "nd_tor_leaf_name": "vxlan_leaf_4",
        "_ndp_tor_live": {"current": {"switches": live}},
        "_ndp_tor_pairs": {"current": {"vpcPairs": pairs or []}},
    }


def resolved_context(**kwargs):
    """Run the runner's three set_fact tasks in order, exactly as the play does."""
    context = base_context(**kwargs)
    for fragment in (
        "SETUP - resolve the ToR and leaf management IPs from the roster",
        "SETUP - resolve the live ToR and leaf switches by management IP",
        "SETUP - record serials, roles and modes",
    ):
        context.update(render_facts(task(fragment), context))
    return context


# --- registry -------------------------------------------------------------------------------------------------------

@pytest.fixture
def registry():
    return load_registry(ROOT / "tests/nd_prerequisite_profiles.yaml")


def test_the_profile_is_a_ready_verify_only_requirement_on_the_two_leaves(registry):
    profile = registry["profiles"]["integration.nd_manage_tor"]
    assert [member["ref"] for member in profile["switches"]["members"]] == ["vxlan_leaf_3", "vxlan_leaf_4"]
    for member in profile["switches"]["members"]:
        # Verify-only: the runner flips the role for the test, so the planner must see the canonical role.
        assert member["desired_role"] == registry["lab"]["switches"][member["ref"]]["baseline_role"] == "leaf"
        assert member["desired_fabric_ref"] == "advanced"
    assert profile["switches"]["required_count"] == 2
    assert [fabric["ref"] for fabric in profile["fabrics"]] == ["advanced"]
    assert profile["resources"] == []
    assert profile["managed_domains"] == ["vpc_pairs"]
    assert "dedicated_tor_topology" not in yaml.safe_dump(profile)
    assert validate_selected_profiles(registry, ["integration.nd_manage_tor"], allow_auto_confirm=True) == []


# --- Jenkins --------------------------------------------------------------------------------------------------------

def test_jenkins_always_runs_nd_manage_tor_without_a_dedicated_fabric_or_serials():
    text = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text(encoding="utf-8")
    targets = jenkins_targets(text)
    assert "nd_manage_tor" in targets["INTEGRATION_MODULES"]
    assert "nd_manage_tor" in targets["EFFECTIVE_INTEGRATION_MODULES"]
    for removed in (
        "ND_TOR_ENABLED", "ND_TOR_FABRIC", "ND_TOR_SWITCH_SERIAL", "ND_LEAF_SWITCH_SERIAL", "ND_VPC_TOR_SWITCH_SERIAL",
        "ND_VPC_TOR_PEER_SERIAL", "ND_VPC_LEAF_SWITCH_SERIAL", "ND_VPC_LEAF_PEER_SERIAL", "ND_TOR2_SWITCH_SERIAL",
        "torFabricName", "torSwitchSerials", "on hold",
    ):
        assert removed not in text, removed
    assert "def effectiveIntegrationModules = INTEGRATION_MODULES + INTERFACE_INTEGRATION_MODULES" in text


# --- runner structure -----------------------------------------------------------------------------------------------

def test_the_upstream_target_is_not_included_for_nd_manage_tor():
    include = task("include collection target (all configured cases)")
    assert "nd_manage_tor" in include["when"]
    network_vrf = task("include selected network/VRF groups")
    assert "nd_manage_tor" not in network_vrf["when"]


def test_the_role_change_is_recorded_before_it_is_attempted_and_restored_in_the_always_cleanup():
    play = runner_play()
    run_block = next(item for item in play["tasks"] if "RUN full integration suite" in str(item.get("name", "")))
    reduced = next(item for item in run_block["block"] if "reduced ToR pairing test" in str(item.get("name", "")))
    names = [str(item.get("name", "")) for item in reduced["block"]]
    record = next(index for index, name in enumerate(names) if "record the role change attempt" in name)
    change = next(index for index, name in enumerate(names) if "to the tor role" in name)
    assert record < change
    # Every case runs after the role is confirmed.
    confirmed = next(index for index, name in enumerate(names) if "require the tor role" in name)
    cases = [index for index, name in enumerate(names) if " TC" in name]
    assert cases and min(cases) > confirmed
    assert [name.split(" - ")[0].split("] ")[-1] for name in names if " TC" in name][0] == "TC0"
    assert {name.split(" - ")[0].split("] ")[-1] for name in names if " TC" in name} == {f"TC{n}" for n in range(9)}

    cleanup = [str(item.get("name", "")) for item in run_block["always"] if "nd_manage_tor" not in str(item.get("name", ""))]
    ordered = [name for name in cleanup if "CLEANUP - " in name and any(
        key in name for key in ("remove the ToR association", "roster role back", "read the role back", "recalculate", "deploy the two", "wait until both", "report the restore")
    )]
    assert [next(key for key in ("remove the ToR association", "roster role back", "read the role back", "recalculate", "deploy the two", "wait until both", "report the restore") if key in name) for name in ordered] == [
        "remove the ToR association", "roster role back", "read the role back", "recalculate", "deploy the two", "wait until both", "report the restore",
    ]


def test_the_cleanup_only_touches_the_two_test_switches_and_the_fabric_the_round_runs_on():
    text = RUNNER_PATH.read_text(encoding="utf-8")
    block = text.split("# nd_manage_tor: undo what the reduced test changed.", 1)[1].split("  handlers:", 1)[0]
    assert "switchActions/changeRoles" in block and "actions/configSave" in block and "switchActions/deploy" in block
    assert block.count("{{ ansible_it_fabric }}") >= 6
    for literal in ("VXLAN_EVPN_Fabric", "External_Connectivity_Fabric", "nac-msd"):
        assert literal not in block
    # The deploy to the two switches only runs after the role is back, so no ToR-role configuration is ever pushed.
    assert block.index("give {{ nd_tor_switch_name }} its roster role back") < block.index("deploy the two switches")


def test_no_case_deploys_while_the_switch_holds_the_tor_role():
    text = RUNNER_PATH.read_text(encoding="utf-8")
    body = text.split("- name: \"[{{ test_module }}] reduced ToR pairing test\"", 1)[1].split("TC8 - gathered asserts", 1)[0]
    # Only the negative config_actions case names deploy, and it runs in check mode and must fail validation.
    assert body.count("deploy: true") == 1
    assert body.count("save: false") == 1
    negative = body.split("TC3 - deploy without save is rejected", 1)[1].split("TC3 - config_actions asserts", 1)[0]
    assert "check_mode: true" in negative and "deploy: true" in negative


def test_the_overridden_case_is_skipped_when_the_fabric_holds_associations_this_test_does_not_own():
    case = task("TC6 - omit the port channels (overridden, reverse-diff regression)")
    assert case["when"] == "(_ndp_tor_foreign_count | default(1) | int) == 0"
    # An unreadable foreign count (undefined) takes the safe default of 1, which skips the destructive state.
    assert not holds(case["when"], {})


# --- precheck logic evaluated against sample ND data ----------------------------------------------------------------

PRECHECK_TASK = "SETUP - require both switches present, normal and in the expected roles"


def precheck_holds(context):
    return all(holds(condition, context) for condition in task(PRECHECK_TASK)["ansible.builtin.assert"]["that"])


def test_the_switches_are_resolved_live_by_management_ip_not_from_the_roster_serials():
    # A rebuilt ToR switch reports a new serial: it is still found by IP and its live serial is used.
    context = resolved_context(tor=switch(TOR_IP, "MOCKSERIAL1"))
    assert context["_ndp_tor_serial"] == "MOCKSERIAL1"
    assert context["_ndp_leaf_serial"] == LEAF_SERIAL
    assert (context["_ndp_tor_ip"], context["_ndp_leaf_ip"]) == (TOR_IP, LEAF_IP)
    assert context["_ndp_tor_role_restore"] == "leaf"
    assert (context["_ndp_tor_role_before"], context["_ndp_leaf_role_before"]) == ("leaf", "leaf")
    assert (context["_ndp_tor_mode"], context["_ndp_leaf_mode"]) == ("normal", "normal")
    assert precheck_holds(context)


def test_the_precheck_accepts_a_tor_role_left_over_from_an_earlier_failed_run():
    assert precheck_holds(resolved_context(tor=switch(TOR_IP, TOR_SERIAL, role="tor")))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"tor": switch(TOR_IP, TOR_SERIAL, role="spine")},
        {"tor": switch(TOR_IP, TOR_SERIAL, mode="migration")},
        {"leaf": switch(LEAF_IP, LEAF_SERIAL, role="tor")},
        {"leaf": switch(LEAF_IP, LEAF_SERIAL, mode="maintenance")},
        {"leaf": switch(LEAF_IP, TOR_SERIAL)},
    ],
    ids=["tor-is-spine", "tor-in-migration", "leaf-is-tor", "leaf-in-maintenance", "same-serial"],
)
def test_the_precheck_refuses_a_switch_in_the_wrong_role_or_mode(kwargs):
    assert not precheck_holds(resolved_context(**kwargs))


def test_the_precheck_refuses_a_switch_that_is_missing_from_the_fabric():
    context = resolved_context()
    context["_ndp_tor_live"]["current"]["switches"] = [item for item in context["_ndp_tor_live"]["current"]["switches"] if item["fabricManagementIp"] != LEAF_IP]
    context.update(render_facts(task("SETUP - resolve the live ToR and leaf switches by management IP"), context))
    context.update(render_facts(task("SETUP - record serials, roles and modes"), context))
    assert context["_ndp_leaf_serial"] == ""
    assert not precheck_holds(context)


def test_the_precheck_refuses_a_vpc_paired_switch():
    conditions = task("SETUP - require neither switch to be vPC paired")["ansible.builtin.assert"]["that"]
    clean = resolved_context()
    assert all(holds(condition, clean) for condition in conditions)
    for pair in (
        {"switchId": TOR_SERIAL, "peerSwitchId": LEAF_SERIAL},
        {"switchId": "SERIAL00001", "peerSwitchId": LEAF_SERIAL},
        {"switchId": TOR_SERIAL, "peerSwitchId": "SERIAL00001"},
    ):
        paired = resolved_context(pairs=[pair])
        assert not all(holds(condition, paired) for condition in conditions), pair
    unrelated = resolved_context(pairs=[{"switchId": "SERIAL00001", "peerSwitchId": "SERIAL00002"}])
    assert all(holds(condition, unrelated) for condition in conditions)


def test_only_associations_involving_neither_switch_count_as_foreign():
    count = task("SETUP - count the associations this test does not own")
    context = resolved_context()
    ours = {"access_or_tor_switch_id": TOR_SERIAL, "aggregation_or_leaf_switch_id": LEAF_SERIAL}
    other_tor = {"access_or_tor_switch_id": TOR_SERIAL, "aggregation_or_leaf_switch_id": "SERIAL00001"}
    foreign = {"access_or_tor_switch_id": "MOCKSERIALX", "aggregation_or_leaf_switch_id": "SERIAL00001"}
    for existing, expected in (([], 0), ([ours], 0), ([ours, other_tor], 0), ([foreign], 1), ([ours, foreign], 1)):
        probe = copy.deepcopy(context)
        probe["_ndp_tor_assoc_before"] = {"after": existing}
        assert render_facts(count, probe)["_ndp_tor_foreign_count"] == expected, existing


# --- restore verification evaluated against sample ND data ----------------------------------------------------------

def restored_context(role, sync_tor="inSync", sync_leaf="inSync"):
    context = resolved_context()
    context["_ndp_tor_role_restore"] = "leaf"
    context["_ndp_tor_restored"] = {"current": {"switches": [switch(TOR_IP, TOR_SERIAL, role=role), switch(LEAF_IP, LEAF_SERIAL)]}}
    context["_ndp_tor_synced"] = {"current": {"switches": [switch(TOR_IP, TOR_SERIAL, sync=sync_tor), switch(LEAF_IP, LEAF_SERIAL, sync=sync_leaf)]}}
    return context


def test_the_restore_is_verified_by_reading_the_role_back():
    read_back = task("CLEANUP - read the role back")
    assert holds(read_back["until"], restored_context("leaf"))
    assert holds(read_back["until"], restored_context("Leaf"))
    assert not holds(read_back["until"], restored_context("tor"))
    report = task("CLEANUP - report the restore")["ansible.builtin.assert"]["that"][0]
    assert holds(report, restored_context("leaf"))
    assert not holds(report, restored_context("tor"))


def test_the_cleanup_waits_for_both_switches_to_report_in_sync():
    wait = task("CLEANUP - wait until both switches report in sync")
    assert holds(wait["until"], restored_context("leaf"))
    assert not holds(wait["until"], restored_context("leaf", sync_tor="pending"))
    assert not holds(wait["until"], restored_context("leaf", sync_leaf="outOfSync"))


def test_the_role_flip_is_confirmed_before_the_cases_run():
    flip_read = task("RUN - read the role back")
    context = base_context()
    context["_ndp_tor_ip"] = TOR_IP
    context["_ndp_tor_after_flip"] = {"current": {"switches": [switch(TOR_IP, TOR_SERIAL, role="tor")]}}
    assert holds(flip_read["until"], context)
    context["_ndp_tor_after_flip"] = {"current": {"switches": [switch(TOR_IP, TOR_SERIAL, role="leaf")]}}
    assert not holds(flip_read["until"], context)
