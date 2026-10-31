"""Execute production runner gates against fake local ND modules only."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tests/run_integration_module.yaml"
ANSIBLE_PYTHON = os.environ.get("ND_RUNNER_ANSIBLE_PYTHON", sys.executable)
FAKE = r'''
import json, os
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule
m = AnsibleModule(argument_spec={
    'output_level': {'type':'str'}, 'fabric_name': {'type':'str'},
    'config': {'type':'raw'}, 'state': {'type':'str'},
    'path': {'type':'str'}, 'method': {'type':'str'}})
p = Path(os.environ['INTERFACE_RUNNER_LEDGER'])
rows = json.loads(p.read_text()); rows.append(m.params); p.write_text(json.dumps(rows))
m.exit_json(changed=True, status=200, current={})
'''


def named(tasks, text):
    return copy.deepcopy(next(task for task in tasks if text in task.get("name", "")))


def descendants(tasks):
    for task in tasks:
        yield task
        for key in ("block", "rescue", "always"):
            yield from descendants(task.get(key, []))


def registry(module, ip="192.0.2.10", changed=False, parent=None):
    runtime = {"nd_test_switch_ip": ip, "nd_test_fabric_name": "fixture-fabric"}
    if parent:
        runtime["nd_test_ethernet_parent"] = parent
    profile = {"switches": {"required_count": 1, "members": [
        {"ref": "leaf", "desired_fabric_ref": "primary", "desired_role": "leaf"}]},
        "runtime_vars": runtime, "interface_selection_changed": changed}
    return {"lab": {"switches": {"leaf": {"seed_ip": ip}},
                    "fabrics": {"primary": {"name": "fixture-fabric"}}},
            "profiles": {"integration." + module: profile}}


def execute(tmp_path, module="nd_interface_port_channel_access", *, selected=False,
            changed=False, baseline=False, input_ip=None, input_fabric="fixture-fabric",
            marker=None, parent=None, input_parent=None, missing=False):
    pre = yaml.safe_load(RUNNER.read_text())[0]["pre_tasks"]
    tasks = [named(pre, name) for name in (
        "load registry contract", "resolve required + present", "validate interface inputs before preparation",
        "release reserved port-channel members before the gate")]
    default = registry(module)
    (tmp_path / "nd_prerequisite_profiles.yaml").write_text(yaml.safe_dump(default))
    chosen = registry(module, ip="192.0.2.20" if changed else "192.0.2.10", changed=changed, parent=parent)
    selected_path = tmp_path / "selected-registry.json"
    if not missing:
        selected_path.write_text(json.dumps(chosen))
    ledger = tmp_path / "ledger.json"
    ledger.write_text("[]")
    modules = tmp_path / "collections/ansible_collections/cisco/nd/plugins/modules"
    modules.mkdir(parents=True)
    for name in ("nd_interface_port_channel_access", "nd_rest"):
        (modules / (name + ".py")).write_text(FAKE)
    values = {
        "ansible_python_interpreter": ANSIBLE_PYTHON,
        "test_module": module, "nd_test_fabric_name": input_fabric,
        "nd_prerequisite_enable": True, "nd_prerequisite_mode": "live",
        "nd_prerequisite_apply": True, "nd_prerequisite_repair_baseline": baseline,
        "ansible_switch1": "192.0.2.99", "ansible_it_fabric": "legacy-fabric",
        "nd_test_fabric_switches": {"VXLAN_EVPN_Fabric": [{"name": "leaf", "role": "leaf"}],
                                    "External_Connectivity_Fabric": []},
    }
    if selected:
        values["nd_prerequisite_registry"] = str(selected_path)
    if input_ip is not None:
        values["nd_test_switch_ip"] = input_ip
    if marker is not None:
        values["nd_interface_selection_changed"] = marker
    if input_parent is not None:
        values["nd_test_ethernet_parent"] = input_parent
    result_path = tmp_path / "facts.json"
    tasks.append({"name": "Retain selected source identity", "ansible.builtin.copy": {
        "dest": str(result_path), "content": "{{ _ndp_selected_profile.runtime_vars | to_json }}"}})
    return run(tmp_path, tasks, values, ledger, result_path)


def run(tmp_path, tasks, values, ledger, result_path=None):
    play = tmp_path / "play.yaml"
    play.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local", "gather_facts": False,
                                    "vars": values, "tasks": tasks}], sort_keys=False))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n")
    env = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_STDOUT_CALLBACK="default",
               ANSIBLE_COLLECTIONS_PATH=str(tmp_path / "collections"), ANSIBLE_COLLECTIONS_SCAN_SYS_PATH="False",
               ANSIBLE_LOCAL_TEMP=str(tmp_path / "local"), ANSIBLE_LOCAL_TMP=str(tmp_path / "local"),
               ANSIBLE_REMOTE_TEMP=str(tmp_path / "remote"), INTERFACE_RUNNER_LEDGER=str(ledger),
               OBJC_DISABLE_INITIALIZE_FORK_SAFETY="YES", ANSIBLE_NOCOLOR="1")
    completed = subprocess.run([str(Path(ANSIBLE_PYTHON).with_name("ansible-playbook")), "-i", "localhost,", str(play)],
                               text=True, capture_output=True, env=env, timeout=45)
    facts = json.loads(result_path.read_text()) if result_path and result_path.exists() else None
    return completed, json.loads(ledger.read_text()), facts


@pytest.mark.parametrize("selected", [False, True])
@pytest.mark.parametrize("module", ["nd_interface_port_channel_access", "nd_interface_port_channel_trunk_host"])
def test_default_cleanup_uses_verified_profile_target_and_fabric(tmp_path, selected, module):
    result, writes, facts = execute(tmp_path, selected=selected, module=module, input_ip="192.0.2.10")
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(writes) == 3
    assert writes[0]["fabric_name"] == "fixture-fabric"
    assert {item["switch_ip"] for item in writes[0]["config"]} == {"192.0.2.10"}
    assert {item["interface_name"] for item in writes[0]["config"]} == {"port-channel501", "port-channel502", "port-channel503"}
    assert all("legacy-fabric" not in (item["path"] or "") for item in writes)
    assert facts["nd_test_switch_ip"] == "192.0.2.10"


@pytest.mark.parametrize("marker", [None, True])
def test_custom_selection_never_runs_legacy_namespace_deletion(tmp_path, marker):
    result, writes, facts = execute(tmp_path, selected=True, changed=True, marker=marker,
                                    input_ip="192.0.2.20", baseline=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert writes == [] and facts["nd_test_switch_ip"] == "192.0.2.20"


@pytest.mark.parametrize("options", [
    {"changed": True, "baseline": True}, {"changed": True, "marker": False},
    {"changed": False, "marker": True}, {"input_ip": "192.0.2.99"},
    {"input_fabric": "wrong-fabric"}, {"missing": True},
    {"module": "nd_interface_subinterface_managed", "parent": "Ethernet1/35", "input_parent": "Ethernet1/3"},
])
def test_stale_input_marker_or_baseline_cannot_mutate_any_switch(tmp_path, options):
    result, writes, _ = execute(tmp_path, selected=True, **options)
    assert result.returncode != 0, result.stdout + result.stderr
    assert writes == []


def test_routed_target_does_not_delete_unrelated_501_namespace(tmp_path):
    result, writes, _ = execute(tmp_path, module="nd_interface_port_channel_routed", input_ip="192.0.2.10")
    assert result.returncode == 0, result.stdout + result.stderr
    assert writes == []


@pytest.mark.parametrize("ip,fabric,passed", [("192.0.2.20", "fixture-fabric", True),
                                             ("192.0.2.10", "fixture-fabric", False),
                                             ("192.0.2.20", "wrong-fabric", False)])
def test_execution_cannot_depart_from_the_planned_interface_target(tmp_path, ip, fabric, passed):
    play = yaml.safe_load(RUNNER.read_text())[0]
    tasks = descendants(play.get("pre_tasks", []) + play.get("tasks", []))
    gate = next(task["ansible.builtin.assert"] for task in tasks if "ansible.builtin.assert" in task
                and any("_ndp_result.runtime_vars.nd_test_switch_ip" in str(value)
                        for value in task["ansible.builtin.assert"].get("that", [])))
    condition = next(value for value in gate["that"] if "_ndp_result.runtime_vars.nd_test_switch_ip" in str(value))
    ledger = tmp_path / "ledger.json"
    ledger.write_text("[]")
    values = {"test_module": "nd_interface_loopback", "nd_test_switch_ip": ip, "nd_test_fabric_name": fabric,
              "_ndp_result": {"runtime_vars": {"nd_test_switch_ip": "192.0.2.20", "nd_test_fabric_name": "fixture-fabric"}}}
    result, writes, _ = run(tmp_path, [{"ansible.builtin.assert": {"that": [condition]}}], values, ledger)
    assert (result.returncode == 0) == passed, result.stdout + result.stderr
    assert writes == []
