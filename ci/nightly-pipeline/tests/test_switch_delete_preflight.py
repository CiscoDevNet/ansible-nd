"""Exercise switch-delete admission checks; baseline writes have separate tests."""
import copy
from pathlib import Path

from ansible.parsing.dataloader import DataLoader
from ansible.playbook.conditional import Conditional
from ansible.template import Templar
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def guard():
    play = yaml.safe_load((ROOT / "tests/run_integration_module.yaml").read_text())[0]
    return next(task for task in play["tasks"] if "require safe fabric-wide switch deletion" in task.get("name", ""))


def permitted(conditions, variables):
    loader = DataLoader()
    conditional = Conditional(loader=loader)
    conditional.when = [conditions] if isinstance(conditions, str) else conditions
    return conditional.evaluate_conditional(Templar(loader=loader, variables=variables), variables)


def fixture():
    return {
        "test_module": "nd_manage_switches", "ansible_check_mode": False,
        "fabric_name": "fixture", "ansible_it_fabric": "fixture",
        "nd_test_fabric2_name": "fixtureExternal",
        "nd_pipeline_switches_topology": [
            {"serial": "FIXTURE1", "role": "leaf"}, {"serial": "FIXTURE2", "role": "spine"},
        ],
        "_ndp_delete_inventory": {"status": 200, "current": {"switches": [
            {"switchId": "FIXTURE1", "switchRole": "leaf"},
            {"switchId": "FIXTURE2", "switchRole": "spine"},
        ]}},
        "_ndp_delete_tor": {"changed": False, "before": [], "after": []},
        "_ndp_delete_anomalies": {"status": 200, "current": {"anomalies": []}},
        "_ndp_delete_global_inventory": {"status": 200, "current": {
            "switches": [{"switchId": "FIXTURE1"}, {"switchId": "FIXTURE2"}],
            "meta": {"counts": {"remaining": 0, "total": 2}},
        }},
    }


def execute(guard, values):
    values = copy.deepcopy(values)
    calls = []
    if not permitted(guard["when"], values):
        return calls
    for task in guard["block"]:
        items = Templar(loader=DataLoader(), variables=values).template(task["loop"]) if "loop" in task else [None]
        for item in items:
            scoped = dict(values, item=item)
            for key, value in task.get("vars", {}).items():
                scoped[key] = Templar(loader=DataLoader(), variables=scoped).template(value)
            if "ansible.builtin.set_fact" in task:
                for key, value in task["ansible.builtin.set_fact"].items():
                    values[key] = Templar(loader=DataLoader(), variables=scoped).template(value)
            elif "ansible.builtin.assert" in task:
                assertion = task["ansible.builtin.assert"]
                assert permitted(assertion["that"], scoped), assertion["fail_msg"]
            elif "register" in task:
                module = next(key for key in task if key.startswith("cisco.nd."))
                args = Templar(loader=DataLoader(), variables=scoped).template(task[module])
                calls.append((module, args))
    return calls


@pytest.mark.parametrize("reply,expected", [
    ({"status": 200, "current": {"anomalies": [
        {"fabricName": "fixture", "cleared": False, "anomalyString": "Leaf-ToR unpairing PRIVATE"},
        {"fabricName": "other", "cleared": False, "anomalyString": "Leaf-ToR unpairing PRIVATE"},
        {"fabricName": "fixture", "cleared": True, "anomalyString": "Leaf-ToR unpairing PRIVATE"},
    ]}}, "active_leaf_tor=1"),
    ({"status": 200, "current": {"anomalies": [None]}}, "unavailable: incomplete or failed anomaly read"),
    ({"status": 500}, "unavailable: incomplete or failed anomaly read"),
])
def test_post_switch_snapshot_projects_only_counts_and_keeps_recovery(reply, expected):
    play = yaml.safe_load((ROOT / "tests/run_integration_module.yaml").read_text())[0]
    target = next(task for task in play["tasks"] if "RUN full integration suite" in task.get("name", ""))
    snapshot = next(task for task in target["always"] if "snapshot Leaf-ToR warnings" in task.get("name", ""))
    values = dict(fixture(), _ndp_post_delete_anomalies=reply)
    assert permitted(snapshot["when"], values)
    assert not permitted(snapshot["when"], dict(values, test_module="nd_manage_tor"))
    assert not permitted(snapshot["when"], dict(values, ansible_check_mode=True))
    read, report = snapshot["block"]
    assert read["cisco.nd.nd_rest"]["method"] == "get"
    assert read["no_log"] and read["timeout"] == 20
    for key, value in report["vars"].items():
        values[key] = Templar(loader=DataLoader(), variables=values).template(value)
    message = Templar(loader=DataLoader(), variables=values).template(report["ansible.builtin.debug"]["msg"])
    assert message == "NDP_SWITCH_DELETE_CONTROLLER_SNAPSHOT " + expected
    assert "ansible.builtin.debug" in snapshot["rescue"][0]
    assert "rescue" not in target


def test_switch_delete_readiness_uses_only_read_operations(guard):
    calls = execute(guard, fixture())
    assert len(calls) == 4
    assert all(args.get("method") == "get" or args.get("state") == "gathered" for _, args in calls)
    assert all("force" not in str(args) for _, args in calls)


@pytest.mark.parametrize("reason", ["association", "role", "extra-switch", "missing-switch", "duplicate-switch", "fabric"])
def test_switch_delete_blocks_unsafe_topology(guard, reason):
    values = fixture()
    rows = values["_ndp_delete_inventory"]["current"]["switches"]
    if reason == "association":
        values["_ndp_delete_tor"]["before"] = values["_ndp_delete_tor"]["after"] = [{"access_or_tor_switch_id": "FIXTURE1"}]
    elif reason == "role":
        rows[0]["switchRole"] = "tor"
    elif reason == "extra-switch":
        rows.append({"switchId": "FOREIGN", "switchRole": "leaf"})
    elif reason == "missing-switch":
        rows.pop()
    elif reason == "duplicate-switch":
        rows[1] = rows[0]
    else:
        values["ansible_it_fabric"] = "another"
    with pytest.raises(AssertionError, match="PREFLIGHT_BLOCKED"):
        execute(guard, values)


@pytest.mark.parametrize("cleared", [False, True])
def test_switch_delete_does_not_confuse_acknowledged_with_cleared(guard, cleared):
    values = fixture()
    values["_ndp_delete_anomalies"]["current"]["anomalies"] = [{
        "fabricName": "fixture", "cleared": cleared, "acknowledged": True,
        "anomalyString": "Please perform Recalculate and Deploy to complete Leaf-ToR unpairing before deleting the leaf switch",
    }]
    if cleared:
        execute(guard, values)
    else:
        with pytest.raises(AssertionError, match="PREFLIGHT_BLOCKED"):
            execute(guard, values)


def retained_pair_fixture():
    values = fixture()
    values["nd_pipeline_switches_topology"] = [
        {"name": "vxlan_leaf_1", "serial": "FIXTURE1", "role": "leaf"},
        {"name": "vxlan_leaf_3", "serial": "TOR3", "role": "leaf"},
        {"name": "vxlan_leaf_4", "serial": "LEAF4", "role": "leaf"},
    ]
    values["_ndp_delete_inventory"]["current"]["switches"] = [
        {"switchId": serial, "switchRole": "leaf"} for serial in ("FIXTURE1", "TOR3", "LEAF4")
    ]
    return values


def leaf_tor_warning(identity):
    return {
        "fabricName": "fixture", "cleared": False, "acknowledged": True,
        "anomalyString": f"Please perform Recalculate and Deploy to complete Leaf-ToR unpairing before deleting the leaf switch {identity}",
    }


def test_switch_delete_tolerates_only_retained_test_pair_warnings(guard):
    values = retained_pair_fixture()
    values["_ndp_delete_anomalies"]["current"]["anomalies"] = [
        leaf_tor_warning("leaf3[tor3]"), leaf_tor_warning("[leaf-4/LEAF4]"),
        {"fabricName": "other", "cleared": False, "anomalyString": leaf_tor_warning("[FIXTURE1]")["anomalyString"]},
    ]
    execute(guard, values)


@pytest.mark.parametrize("identity", ["[FIXTURE1]", "leaf[TOR3] and leaf[FIXTURE1]",
                                      "leaf[TOR3] and leaf[UNKNOWN]", "without identity", "[UNKNOWN]"])
def test_switch_delete_blocks_leaf_tor_warnings_outside_retained_pair(guard, identity):
    values = retained_pair_fixture()
    values["_ndp_delete_anomalies"]["current"]["anomalies"] = [leaf_tor_warning(identity)]
    with pytest.raises(AssertionError, match="PREFLIGHT_BLOCKED"):
        execute(guard, values)


def retired_warning(guard):
    classifier = next(task for task in guard["block"] if "classify uncleared" in task.get("name", ""))
    retired = {"vxlan_leaf_3": "OLDTOR3", "vxlan_leaf_4": "OLDLEAF4"}
    classifier.setdefault("vars", {})["_ndp_retired_leaf_tor_identities"] = retired
    return leaf_tor_warning(f"[vxlan_leaf_3/{retired['vxlan_leaf_3']}]")


def test_switch_delete_tolerates_verified_absent_historical_pair_identity(guard):
    values = retained_pair_fixture()
    values["_ndp_delete_anomalies"]["current"]["anomalies"] = [
        leaf_tor_warning("[TOR3]"), retired_warning(guard),
    ]
    execute(guard, values)


def test_switch_delete_classifies_current_and_retired_pair_warnings_separately(guard):
    values = retained_pair_fixture()
    retired_warning(guard)
    classifier = next(task for task in guard["block"] if "classify uncleared" in task.get("name", ""))
    retired = classifier["vars"]["_ndp_retired_leaf_tor_identities"]
    values["_ndp_delete_anomalies"]["current"]["anomalies"] = [
        leaf_tor_warning("[vxlan_leaf_3/TOR3]"),
        leaf_tor_warning("[vxlan_leaf_4/LEAF4]"),
        *[leaf_tor_warning(f"[{name}/{serial}]") for name, serial in retired.items()],
    ]
    execute(guard, values)
    templar = Templar(loader=DataLoader(), variables={**values, **classifier["vars"]})
    result = templar.template(classifier["ansible.builtin.set_fact"]["_ndp_delete_leaf_tor"])
    assert result == {"known": 2, "retired": 2, "unknown": 0, "malformed": 0}


@pytest.mark.parametrize("reason", [
    "present", "http", "missing-meta", "remaining", "wrong-total", "malformed-switch",
    "wrong-name", "serial-only", "mixed-unknown", "embedded-error", "invalid-counts",
])
def test_switch_delete_blocks_unverified_historical_identity(guard, reason):
    values = retained_pair_fixture()
    warning = retired_warning(guard)
    reply = values["_ndp_delete_global_inventory"]
    old_serial = warning["anomalyString"].split("/")[-1].rstrip("]")
    if reason == "present":
        reply["current"]["switches"][0]["switchId"] = old_serial
    elif reason == "http":
        reply["status"] = 500
    elif reason == "missing-meta":
        reply["current"].pop("meta")
    elif reason == "remaining":
        reply["current"]["meta"]["counts"]["remaining"] = 1
    elif reason == "wrong-total":
        reply["current"]["meta"]["counts"]["total"] = 3
    elif reason == "malformed-switch":
        reply["current"]["switches"][0] = {}
    elif reason == "invalid-counts":
        reply["current"]["switches"] = []
        reply["current"]["meta"]["counts"] = {"remaining": "invalid", "total": "invalid"}
    elif reason == "wrong-name":
        warning["anomalyString"] = warning["anomalyString"].replace("vxlan_leaf_3/", "another_leaf/")
    elif reason == "serial-only":
        warning["anomalyString"] = warning["anomalyString"].replace("vxlan_leaf_3/", "")
    elif reason == "mixed-unknown":
        warning["anomalyString"] += " [UNKNOWN]"
    else:
        reply["current"]["errors"] = ["read failed"]
    values["_ndp_delete_anomalies"]["current"]["anomalies"] = [warning]
    with pytest.raises(AssertionError, match="PREFLIGHT_BLOCKED"):
        execute(guard, values)


def test_switch_delete_requires_both_retained_pair_members_declared(guard):
    values = retained_pair_fixture()
    values["nd_pipeline_switches_topology"] = values["nd_pipeline_switches_topology"][:2]
    values["_ndp_delete_inventory"]["current"]["switches"] = values["_ndp_delete_inventory"]["current"]["switches"][:2]
    values["_ndp_delete_anomalies"]["current"]["anomalies"] = [leaf_tor_warning("[TOR3]")]
    with pytest.raises(AssertionError, match="PREFLIGHT_BLOCKED"):
        execute(guard, values)


@pytest.mark.parametrize("reason", ["http", "missing-switches", "missing-associations", "missing-anomalies", "truncated", "malformed-row", "embedded-error"])
def test_switch_delete_fails_closed_for_incomplete_reads(guard, reason):
    values = fixture()
    if reason == "http":
        values["_ndp_delete_inventory"]["status"] = 503
    elif reason == "missing-switches":
        values["_ndp_delete_inventory"]["current"] = {}
    elif reason == "missing-associations":
        values["_ndp_delete_tor"] = {"msg": "failed"}
    elif reason == "missing-anomalies":
        values["_ndp_delete_anomalies"]["current"] = {}
    elif reason == "truncated":
        values["_ndp_delete_anomalies"]["current"]["anomalies"] = [{}] * 200
    elif reason == "embedded-error":
        values["_ndp_delete_inventory"]["current"]["error"] = "unverified"
    else:
        values["_ndp_delete_anomalies"]["current"]["anomalies"] = [{}]
    with pytest.raises(AssertionError, match="PREFLIGHT_"):
        execute(guard, values)


@pytest.mark.parametrize("mode", ["prerequisite-only", "check", "other-module"])
def test_switch_delete_guard_does_not_touch_other_modes(guard, mode):
    values = fixture()
    if mode == "prerequisite-only":
        values["nd_prerequisite_only"] = True
    elif mode == "check":
        values["ansible_check_mode"] = True
    else:
        values["test_module"] = "nd_manage_tor"
    assert execute(guard, values) == []


def test_switch_delete_guard_precedes_authored_lifecycle_and_does_not_continue(guard):
    play = yaml.safe_load((ROOT / "tests/run_integration_module.yaml").read_text())[0]
    names = [task.get("name", "") for task in play["tasks"]]
    assert names.index(guard["name"]) < next(i for i, name in enumerate(names) if "discover optional setup/cleanup" in name)
    assert len(guard["rescue"]) == 1
    assert "ansible.builtin.fail" in guard["rescue"][0]


@pytest.fixture(params=["nd_manage_switches", "nd_manage_tor"])
def tor_cleanup(request):
    play = yaml.safe_load((ROOT / "tests/run_integration_module.yaml").read_text())[0]
    tasks = play["tasks"]
    if request.param == "nd_manage_switches":
        index = next(i for i, task in enumerate(tasks) if "association before switch deletion" in task["name"])
        assert "require safe fabric-wide switch deletion" in tasks[index + 1]["name"]
        return request.param, tasks[index]
    target = next(task for task in tasks if "RUN full integration suite" in task["name"])
    return request.param, next(task for task in target["always"] if "association after execution" in task["name"])


def exercise_tor_cleanup(hook, scenario):
    module, block = hook
    fabric = "VXLAN_EVPN_Fabric_eBGP" if module == "nd_manage_switches" else "VXLAN_EVPN_Fabric"
    values = {
        "test_module": module, "ansible_check_mode": scenario == "check",
        "nd_prerequisite_only": scenario == "prerequisite-only",
        "fabric_name": fabric, "ansible_it_fabric": fabric,
        "nd_pipeline_switches_topology": [
            {"name": "vxlan_leaf_3", "serial": "TOR3"},
            {"name": "vxlan_leaf_4", "serial": "LEAF4"},
        ],
    }
    pair = {"fabric_name": fabric, "access_or_tor_switch_id": "TOR3", "aggregation_or_leaf_switch_id": "LEAF4"}
    foreign = dict(pair, aggregation_or_leaf_switch_id="OTHER")
    rows = [foreign] if scenario == "foreign-only" else [foreign, pair]
    if scenario == "vpc":
        pair["access_or_tor_peer_switch_id"] = "PEER"
    if scenario == "duplicate":
        rows.append(pair)
    if scenario == "wrong-fabric":
        pair["fabric_name"] = "another-fabric"
    calls = []

    def run(task, inherited):
        scoped = dict(inherited, **values)
        for key, expression in task.get("vars", {}).items():
            scoped[key] = Templar(loader=DataLoader(), variables=scoped).template(expression)
        if not permitted(task.get("when", []), scoped):
            return
        if "block" in task:
            for child in task["block"]:
                run(child, scoped)
        elif "ansible.builtin.assert" in task:
            assertion = task["ansible.builtin.assert"]
            assert permitted(assertion["that"], scoped), assertion["fail_msg"]
        elif "cisco.nd.nd_manage_tor" in task:
            args = Templar(loader=DataLoader(), variables=scoped).template(task["cisco.nd.nd_manage_tor"])
            calls.append(args)
            if args["state"] == "deleted":
                result = {"changed": scenario != "delete-noop"}
            else:
                returned = rows if len(calls) == 1 or scenario == "still-present" else [foreign]
                result = {"changed": False, "before": returned, "after": returned}
            values[task["register"]] = result
            if "until" in task:
                assert permitted(task["until"], dict(scoped, **values)), "readback did not confirm absence"

    run(block, {})
    return calls


def test_tor_cleanup_removes_and_deploys_only_the_known_pair(tor_cleanup):
    read, delete, verify = exercise_tor_cleanup(tor_cleanup, "leftover")
    assert read == verify
    assert read["state"] == "gathered"
    assert delete == {
        "fabric_name": read["fabric_name"],
        "state": "deleted",
        "config": [{"access_or_tor_switch": "TOR3", "aggregation_or_leaf_switch": "LEAF4"}],
        "config_actions": {"save": True, "deploy": True, "type": "switch"},
    }


@pytest.mark.parametrize("scenario", ["foreign-only", "check", "prerequisite-only"])
def test_tor_cleanup_never_changes_unrelated_associations_or_read_only_runs(tor_cleanup, scenario):
    calls = exercise_tor_cleanup(tor_cleanup, scenario)
    assert [args["state"] for args in calls] == (["gathered"] if scenario == "foreign-only" else [])


@pytest.mark.parametrize(("scenario", "error"), [
    ("vpc", "duplicated or belongs to a vPC"),
    ("duplicate", "duplicated or belongs to a vPC"),
    ("wrong-fabric", "verifiable fabric associations"),
    ("delete-noop", "Recalculate and Deploy are unconfirmed"),
    ("still-present", "readback did not confirm absence"),
])
def test_tor_cleanup_fails_when_scope_or_outcome_is_unverified(tor_cleanup, scenario, error):
    with pytest.raises(AssertionError, match=error):
        exercise_tor_cleanup(tor_cleanup, scenario)
