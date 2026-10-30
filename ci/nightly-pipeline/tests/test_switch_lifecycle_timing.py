"""Exercise production timing/budget gates with local fake ND modules only."""

import copy
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "playbooks/nd_ensure_switches.yaml"
PHASES = ("deploy-settle", "delete", "source-absence", "discovery", "add", "convergence")
FAKE = r'''
import json, os
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule
m = AnsibleModule(argument_spec={'path':{'type':'str'},'method':{'type':'str'},'content':{'type':'raw'},
 'fabric':{'type':'str'},'state':{'type':'str'},'config':{'type':'raw'},'config_actions':{'type':'raw'}})
p = Path(os.environ['TIMING_FIXTURE_LEDGER']); ledger = json.loads(p.read_text()); a=m.params
ledger['calls'].append(a['path'] or a['state'])
if a['state']=='merged': ledger['adds'].append(a['config'])
p.write_text(json.dumps(ledger))
if a['content'] and a['content'].get('fail'):
 m.fail_json(msg='PRIMARY_API_ERROR',status=207)
if a['path'] and 'shallowDiscovery' in a['path']:
 m.exit_json(changed=False,status=200,current={'switches':[{'ip':'192.0.2.10','serialNumber':'FIXTURE0','status':'manageable'}]})
m.exit_json(changed=a['method']=='post' or a['state']=='merged',status=200,current={})
'''


def source():
    return yaml.safe_load(GUARD.read_text())[0]


def walk(tasks):
    for task in tasks:
        yield task
        for branch in ("block", "rescue", "always"):
            yield from walk(task.get(branch, []))


def named(tasks, prefix):
    return next(task for task in walk(tasks) if task.get("name", "").startswith(prefix))


def phase_wrapper(phase):
    prefix = "Confirm the full canonical roster" if phase == "convergence" else "Measure switch lifecycle " + phase
    return copy.deepcopy(named(source()["tasks"], prefix))


def operation(fail=False):
    return {"name": "Synthetic ND operation", "cisco.nd.nd_rest": {
        "path": "/fixture/operation", "method": "post", "content": {"fail": fail}}}


def run(tmp_path, tasks, values=None):
    modules = tmp_path / "collections/ansible_collections/cisco/nd/plugins/modules"
    modules.mkdir(parents=True)
    for name in ("nd_rest", "nd_manage_switches"):
        (modules / (name + ".py")).write_text(FAKE)
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps({"calls": [], "adds": []}))
    play = tmp_path / "play.yaml"
    play.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local", "gather_facts": False,
        "vars": {"ansible_python_interpreter": sys.executable, "nd_switch_apply": True, "nd_switch_predelete_deploy": True,
                 "_nd_switch_clock": source()["vars"]["_nd_switch_clock"],
                 **{key: value for key, value in source()["vars"].items()
                    if key.startswith("nd_switch_predelete_") or key.startswith("_nd_predelete_")},
                 **(values or {})},
        "tasks": tasks}], sort_keys=False))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\nretry_files_enabled=False\nhost_key_checking=False\n")
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_COLLECTIONS_PATH=str(tmp_path / "collections"),
        ANSIBLE_COLLECTIONS_SCAN_SYS_PATH="False", ANSIBLE_STDOUT_CALLBACK="default",
        ANSIBLE_CALLBACK_PLUGINS=str(tmp_path / "callbacks"),
        ANSIBLE_ACTION_PLUGINS=str(ROOT / "playbooks/action_plugins"), TIMING_FIXTURE_LEDGER=str(ledger),
        ANSIBLE_LOCAL_TEMP=str(tmp_path / "local"), ANSIBLE_LOCAL_TMP=str(tmp_path / "local"),
        ANSIBLE_REMOTE_TEMP=str(tmp_path / "remote"), OBJC_DISABLE_INITIALIZE_FORK_SAFETY="YES")
    completed = subprocess.run([str(Path(sys.executable).with_name("ansible-playbook")), "-i", "localhost,", str(play)],
                              env=environment, capture_output=True, text=True, timeout=30)
    return completed, json.loads(ledger.read_text())


@pytest.mark.parametrize("phase", PHASES)
@pytest.mark.parametrize("failed", (False, True))
def test_each_actual_phase_wrapper_reports_success_and_api_failure(tmp_path, phase, failed):
    wrapper = phase_wrapper(phase)
    # Retain the actual start/complete/always tasks. The underlying phase work is
    # independently covered by the deletion/onboarding/convergence suites.
    wrapper["block"] = [wrapper["block"][0], operation(failed), wrapper["block"][-1]]
    completed, ledger = run(tmp_path, [wrapper])
    assert (completed.returncode != 0) is failed, completed.stdout + completed.stderr
    matches = re.findall(r"NDP_SWITCH_PHASE: " + re.escape(phase) + r"\s+([0-9.]+)\s+status=(success|failed)", completed.stdout)
    assert len(matches) == 1, completed.stdout
    assert float(matches[0][0]) >= 0
    assert matches[0][1] == ("failed" if failed else "success")
    assert ledger["calls"] == ["/fixture/operation"]
    if failed:
        assert "PRIMARY_API_ERROR" in completed.stdout


@pytest.mark.parametrize("elapsed", (30, 31))
def test_exhausted_guard_minus_reserve_stops_before_discovery_and_add(tmp_path, elapsed):
    onboarding = copy.deepcopy(named(source()["tasks"], "Onboard the missing switches"))
    completed, ledger = run(tmp_path, [onboarding], {
        "_nd_switch_clock": 100, "_nd_switch_guard_started": 100 - elapsed,
        "nd_switch_guard_timeout_seconds": 60, "nd_switch_discovery_timeout": 900,
        "nd_missing_switches": [{"seed_ip": "192.0.2.10", "serial": "FIXTURE0", "name": "fixture", "fabric": "fixture-fabric", "role": "leaf"}],
        "nd_switch_rediscover_enabled": True, "nd_switch_rediscover_protocols": ["md5", "sha"],
        "nd_switch_discovery_call_timeout": 2, "nd_switch_rediscover_delay": 0,
        "nd_switch_rediscover_retries": 0, "nd_switch_expected_serial_supported": False,
        "nd_switch_username": "fixture-user", "nd_switch_password": "fixture-password",
        "nd_switch_deploy": True, "nd_switch_deploy_scope": "global",
        "nd_switch_onboard_initial_wait": 0, "nd_switch_onboard_retries": 0, "nd_switch_onboard_delay": 0})
    assert completed.returncode != 0, completed.stdout + completed.stderr
    assert "GUARD_BUDGET_EXHAUSTED" in completed.stdout
    assert ledger == {"calls": [], "adds": []}
    assert "NDP_SWITCH_PHASE: discovery 0.0 status=failed" in completed.stdout
    assert "NDP_SWITCH_PHASE: add" not in completed.stdout


def test_force_compatibility_flag_is_rejected_before_any_controller_call(tmp_path):
    tasks = source()["tasks"]
    policy = next(index for index, task in enumerate(tasks) if task.get("name", "").startswith("Require a bounded non-force"))
    assert not any(any(key.startswith("cisco.nd.") for key in task) for task in walk(tasks[:policy + 1]))
    completed, ledger = run(tmp_path, copy.deepcopy(tasks[:policy + 1]) + [operation()], {
        "nd_switch_guard_timeout_seconds": 3600, "nd_switch_rehome_force_delete": True})
    assert completed.returncode != 0
    assert "NDP_SWITCH_LIFECYCLE_POLICY" in completed.stdout
    assert ledger == {"calls": [], "adds": []}


@pytest.mark.parametrize("failed", (False, True))
def test_timing_report_failure_preserves_the_operation_result(tmp_path, failed):
    wrapper = phase_wrapper("delete")
    wrapper["block"] = [wrapper["block"][0], operation(failed), wrapper["block"][-1]]
    clock = tmp_path / "clock.py"
    clock.write_text("import json,pathlib,sys\np=pathlib.Path(" + repr(str(tmp_path / "ledger.json")) + ")\n"
                     "if json.loads(p.read_text())['calls']: print('TIMING_REPORT_FAILURE',file=sys.stderr);sys.exit(7)\nprint(100)\n")
    command = shlex.join([sys.executable, str(clock)])
    tasks = [{"block": [wrapper], "rescue": [
        {"name": "Verify the original API error remains authoritative", "ansible.builtin.assert": {
            "that": "ansible_failed_result.msg == 'PRIMARY_API_ERROR'", "fail_msg": "Timing replaced the primary API failure"}},
        {"name": "Preserve the original failed result", "ansible.builtin.fail": {"msg": "PRESERVED_PRIMARY_API_ERROR"}},
    ]}]
    completed, ledger = run(tmp_path, tasks, {
        "_nd_switch_clock": "{{ lookup('ansible.builtin.pipe', " + json.dumps(command) + ") }}"})
    assert (completed.returncode != 0) is failed, completed.stdout + completed.stderr
    assert ledger["calls"] == ["/fixture/operation"]
    assert "TIMING_REPORT_FAILURE" in completed.stdout + completed.stderr
    if failed:
        assert "PRESERVED_PRIMARY_API_ERROR" in completed.stdout
        assert "Timing replaced the primary API failure" not in completed.stdout
