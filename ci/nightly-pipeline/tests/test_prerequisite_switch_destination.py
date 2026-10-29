"""Run actual prerequisite tasks with fake local modules; no ND calls."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ("apply_ensure_switch_membership.yaml", "apply_membership_move.yaml", "apply_repair_switch.yaml")

FAKE = r'''
import json, os
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule
m = AnsibleModule(argument_spec={'fabric':{'type':'str'},'state':{'type':'str'},'config':{'type':'raw'},
 'config_actions':{'type':'raw'},'method':{'type':'str','default':'get'},'path':{'type':'str'},'content':{'type':'raw'}})
p=Path(os.environ['PREREQUISITE_FIXTURE_STATE']); s=json.loads(p.read_text()); a=m.params
def done(**result):
 p.write_text(json.dumps(s)); m.exit_json(**result)
if a['path']:
 if a['method']=='get':
  if a['path'].endswith('/switches'):
   done(changed=False,status=200,current={'switches':[{'switchId':'FIXTURE0001','fabricManagementIp':'192.0.2.10','switchRole':s['role']}]})
  s['reads']+=1
  current={'management':{'type':s['fabric_type']}}
  if s['scenario']=='malformed': current=None
  done(changed=False,status=500 if s['scenario']=='http_error' else 200,current=current)
 s['writes'].append('REST '+a['path']); done(changed=True,status=200,current={})
s['writes'].append(a['state'])
if a['state']=='merged': s['preservation_values'].extend(row.get('preserve_config','MISSING') for row in a['config'])
done(changed=True)
'''


def reveal(value):
    if isinstance(value, dict):
        if "no_log" in value:
            value["no_log"] = False
        for child in value.values():
            reveal(child)
    elif isinstance(value, list):
        for child in value:
            reveal(child)


def execute(tmp_path, helper, scenario="success", fabric_type="vxlanEbgp", inplace=False, reonboard_role=False):
    modules = tmp_path / "collections/ansible_collections/cisco/nd/plugins/modules"
    modules.mkdir(parents=True)
    for name in ("nd_rest", "nd_manage_switches"):
        (modules / (name + ".py")).write_text(FAKE)
    role = "edge_router" if inplace else "border" if reonboard_role else "leaf"
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"scenario": scenario, "fabric_type": fabric_type, "role": "edgeRouter" if inplace else role,
                                 "reads": 0, "writes": [], "preservation_values": []}))
    repair = {"operation": "repair_switch", "action": "role" if inplace or reonboard_role else "move",
              "switch_ref": "fixture-switch", "serial": "FIXTURE0001", "switch_ip": "192.0.2.10",
              "fabric_ref": "destination", "fabric_name": "fixture-destination", "fabric_type": fabric_type,
              "source_fabric_name": "fixture-source", "desired_role": role,
              "before": {"role": "spine" if reonboard_role else "leaf"}}
    values = {"ansible_python_interpreter": sys.executable,
              "nd_switch_username": "fixture-user", "nd_switch_password": "fixture-password",
              "_ndp_operation": {"switch_ref": "fixture-switch", "fabric_ref": "destination",
                                  "source_fabric_ref": "source", "destination_fabric_ref": "destination", "desired_role": role},
              "_ndp_fabric_name_by_ref": {"source": "fixture-source", "destination": "fixture-destination"},
              "_ndp_switch_seed_ip": {"fixture-switch": "192.0.2.10"}, "_ndp_repair_operation": repair,
              "_ndp_registry": {"lab": {"switches": {"fixture-switch": {"serial": "FIXTURE0001", "seed_ip": "192.0.2.10"}}}},
              "_ndp_baseline_repair_journal": [], "_ndp_state_dir": str(tmp_path), "_ndp_run_id": "fixture-run",
              "_ndp_execution_id": "fixture-execution"}
    tasks = yaml.safe_load((ROOT / "playbooks/nd_prerequisite" / helper).read_text())
    reveal(tasks)  # Synthetic fixture inputs only; production no_log is unchanged.
    shutil.copy2(ROOT / "playbooks/nd_prerequisite/apply_change_role.yaml", tmp_path / "apply_change_role.yaml")
    play = tmp_path / "play.yaml"
    play.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local", "gather_facts": False,
                                    "vars": values, "tasks": tasks}], sort_keys=False))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\nretry_files_enabled=False\nhost_key_checking=False\n")
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_COLLECTIONS_PATH=str(tmp_path / "collections"),
                       ANSIBLE_COLLECTIONS_SCAN_SYS_PATH="False", ANSIBLE_STDOUT_CALLBACK="default",
                       ANSIBLE_CALLBACK_PLUGINS=str(tmp_path / "callbacks"), PREREQUISITE_FIXTURE_STATE=str(state),
                       ANSIBLE_LOCAL_TEMP=str(tmp_path / "local-tmp"), ANSIBLE_LOCAL_TMP=str(tmp_path / "local-tmp"),
                       ANSIBLE_REMOTE_TEMP=str(tmp_path / "remote-tmp"), OBJC_DISABLE_INITIALIZE_FORK_SAFETY="YES")
    command = [str(Path(sys.executable).with_name("ansible-playbook")), "-i", "localhost,", str(play)]
    completed = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=60)
    return completed, json.loads(state.read_text())


@pytest.mark.parametrize("helper", HELPERS)
@pytest.mark.parametrize("scenario,fabric_type", (
    ("success", "externalConnectivity"), ("success", "vxlanCampus"), ("http_error", "vxlanEbgp"), ("malformed", "vxlanIbgp"),
))
def test_incompatible_or_unreadable_destination_blocks_before_switch_mutation(tmp_path, helper, scenario, fabric_type):
    completed, state = execute(tmp_path, helper, scenario, fabric_type)
    assert completed.returncode != 0, completed.stdout + completed.stderr
    assert "NDP_SWITCH_DESTINATION_BLOCKED" in completed.stdout
    assert state["reads"] == 1
    assert state["writes"] == []
    assert not (tmp_path / "baseline-repair-journal.yaml").exists()


@pytest.mark.parametrize("helper", HELPERS)
def test_supported_destination_is_read_before_add_and_preservation_stays_false(tmp_path, helper):
    completed, state = execute(tmp_path, helper)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert state["reads"] == 1
    assert state["preservation_values"] == [False]
    assert state["writes"] == (["merged"] if helper == HELPERS[0] else ["deleted", "merged"])


def test_external_in_place_role_repair_does_not_apply_onboarding_restriction(tmp_path):
    completed, state = execute(tmp_path, "apply_repair_switch.yaml", fabric_type="externalConnectivity", inplace=True)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert state["reads"] == 0
    assert not state["preservation_values"]
    assert state["writes"] and all(value.startswith("REST ") for value in state["writes"])


def test_external_role_transition_requiring_reonboarding_is_blocked_before_remove(tmp_path):
    completed, state = execute(tmp_path, "apply_repair_switch.yaml", fabric_type="externalConnectivity", reonboard_role=True)
    assert completed.returncode != 0
    assert "NDP_SWITCH_DESTINATION_BLOCKED" in completed.stdout
    assert state["writes"] == []
