"""Exercise staged-fixture cleanup templates without controller or device access."""
import copy
from pathlib import Path

from ansible.parsing.dataloader import DataLoader
from ansible.playbook.conditional import Conditional
from ansible.template import Templar
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def cleanup():
    play = yaml.safe_load((ROOT / "tests/run_integration_module.yaml").read_text())[0]
    target = next(task for task in play["tasks"] if "RUN full integration suite" in task.get("name", ""))
    return next(task for task in target["always"] if "remove this target's staged overlay fixtures" in task.get("name", ""))


def permitted(conditions, variables):
    loader = DataLoader()
    conditional = Conditional(loader=loader)
    conditional.when = [conditions] if isinstance(conditions, str) else conditions
    return conditional.evaluate_conditional(Templar(loader=loader, variables=variables), variables)


def render(value, variables):
    return Templar(loader=DataLoader(), variables=variables).template(value)


def execute(cleanup, variables, remaining=None, incomplete=False):
    """Run production guards/facts/assertions; replace only ND module calls."""
    variables = copy.deepcopy(variables)
    calls = []
    if not permitted(cleanup["when"], variables):
        return calls
    for key, value in cleanup["vars"].items():
        variables[key] = render(value, variables)
    for task in cleanup["block"]:
        if not permitted(task.get("when", []), variables):
            continue
        if "loop" in task:
            items = render(task["loop"], variables)
        else:
            items = [None]
        for item in items:
            if "loop" in task:
                variables[task["loop_control"]["loop_var"]] = item
            scoped = dict(variables)
            for key, value in task.get("vars", {}).items():
                scoped[key] = render(value, scoped)
            if "ansible.builtin.set_fact" in task:
                variables.update(render(task["ansible.builtin.set_fact"], scoped))
            elif "ansible.builtin.assert" in task:
                assertion = task["ansible.builtin.assert"]
                assert permitted(assertion["that"], scoped), assertion["fail_msg"]
            else:
                module = next(key for key in task if key.startswith("cisco.nd."))
                arguments = render(task[module], scoped)
                calls.append((module, arguments))
                if "register" in task:
                    variables[task["register"]] = {} if incomplete else {"gathered": remaining or []}
    return calls


def fixture(module):
    network = module == "nd_manage_networks"
    prefix = "ndnetstg" if network else "ndvrfstg"
    identity = "network_name" if network else "vrf_name"
    kind = "network" if network else "vrf"
    return {
        "test_module": module, "fabric_name": "fixture", "target_fabric": "fixture",
        "ansible_check_mode": False, "staged_create_result": {"changed": True},
        f"nd_{kind}_staged_seed": [{identity: prefix + suffix, "deploy": False, "attach": [{"ip_address": "192.0.2.1"}]}
                                    for suffix in ("add", "remove", "detach", "omit")],
        f"nd_{kind}_staged_create_config": [{identity: prefix + "create", "deploy": True}],
    }


@pytest.mark.parametrize("module", ["nd_manage_networks", "nd_manage_vrfs"])
def test_staged_cleanup_detaches_deploys_only_named_fixtures_and_reads_back(cleanup, module):
    values = fixture(module)
    calls = execute(cleanup, values)
    assert len(calls) == 2
    assert all(name == "cisco.nd." + module for name, _ in calls)
    deletion, readback = [arguments for _, arguments in calls]
    assert deletion["state"] == "deleted"
    assert readback["state"] == "gathered"
    assert deletion["fabric_name"] == readback["fabric_name"] == "fixture"
    selectors = deletion["config"]
    identity = "network_name" if module == "nd_manage_networks" else "vrf_name"
    prefix = "ndnetstg" if module == "nd_manage_networks" else "ndvrfstg"
    assert {row[identity] for row in selectors} == {prefix + suffix for suffix in ("add", "remove", "detach", "omit", "create")}
    assert all(row["deploy"] is True and "attach" not in row for row in selectors)
    assert readback["config"] == selectors


@pytest.mark.parametrize("change", ["not-started", "skipped", "check", "prerequisite-only", "other-target"])
def test_staged_cleanup_never_runs_without_an_executed_staged_target(cleanup, change):
    values = fixture("nd_manage_networks")
    if change == "not-started":
        del values["staged_create_result"]
    elif change == "skipped":
        values["staged_create_result"] = {"skipped": True}
    elif change == "check":
        values["ansible_check_mode"] = True
    elif change == "prerequisite-only":
        values["nd_prerequisite_only"] = True
    else:
        values["test_module"] = "nd_interface_vpc_access"
    assert execute(cleanup, values) == []


@pytest.mark.parametrize("change", ["fabric", "empty", "unowned-name", "missing-name"])
def test_staged_cleanup_refuses_unsafe_or_empty_selectors(cleanup, change):
    values = fixture("nd_manage_networks")
    if change == "fabric":
        values["target_fabric"] = "other-fabric"
    elif change == "empty":
        values["nd_network_staged_seed"] = []
        values["nd_network_staged_create_config"] = []
    elif change == "unowned-name":
        values["nd_network_staged_seed"][0]["network_name"] = "production"
    else:
        del values["nd_network_staged_seed"][0]["network_name"]
    with pytest.raises(AssertionError, match="NDP_STAGED_CLEANUP_REFUSED"):
        execute(cleanup, values)


@pytest.mark.parametrize("incomplete", [False, True])
def test_staged_cleanup_does_not_report_success_for_residue_or_incomplete_readback(cleanup, incomplete):
    with pytest.raises(AssertionError, match="NDP_STAGED_CLEANUP_FAILED"):
        execute(cleanup, fixture("nd_manage_vrfs"), remaining=[{"vrf_name": "ndvrfstgcreate"}], incomplete=incomplete)


@pytest.mark.parametrize("module,identity", [("nd_manage_networks", "network_name"), ("nd_manage_vrfs", "vrf_name")])
def test_staged_cleanup_leaves_unrelated_overlays_alone(cleanup, module, identity):
    calls = execute(cleanup, fixture(module), remaining=[{identity: "unrelated-overlay"}])
    assert len(calls) == 2
    assert all(row[identity] != "unrelated-overlay" for _, arguments in calls for row in arguments["config"])


def test_staged_cleanup_rejects_unidentifiable_readback_rows(cleanup):
    with pytest.raises(AssertionError, match="NDP_STAGED_CLEANUP_FAILED"):
        execute(cleanup, fixture("nd_manage_networks"), remaining=[{"unexpected_field": "ndnetstgcreate"}])
