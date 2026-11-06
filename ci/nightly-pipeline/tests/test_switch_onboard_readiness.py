"""Execute the actual onboarding block with local fake ND modules; no controller calls."""
import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "playbooks/nd_ensure_switches.yaml"

FAKE_MODULE = r'''
import json, os
import time
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule
m = AnsibleModule(argument_spec={
 'fabric': {'type': 'str'}, 'state': {'type': 'str'}, 'config': {'type': 'raw'},
 'config_actions': {'type': 'raw'}, 'path': {'type': 'str'},
 'method': {'type': 'str'}, 'content': {'type': 'raw'}})
p = Path(os.environ['ONBOARD_FIXTURE_STATE']); s = json.loads(p.read_text()); a = m.params
def finish(failed=False, **result):
 p.write_text(json.dumps(s))
 if failed: m.fail_json(msg='Synthetic discovery failure', **result)
 m.exit_json(**result)
if a['state']:
 if s['scenario'] in ('sha_only', 'mixed'):
  for row in a['config']:
   expected = 'SHA' if s['scenario'] == 'sha_only' or row['seed_ip'].endswith('.10') else 'MD5'
   if row.get('auth_proto') != expected: finish(failed=True, changed=False)
 s['adds'].append(a['config']); finish(changed=True)
seeds = a['content']['seedIpCollection']
if a['content']['username'] != 'fixture-user' or a['content']['password'] != 'fixture-password':
 finish(failed=True, changed=False, status=400)
protocol = a['content']['snmpV3AuthProtocol']
s['batches'].append({'seeds': seeds, 'protocol': protocol})
scenario = s['scenario']
if scenario == 'slow_api': time.sleep(1)
rows = []
for seed in seeds:
 s['polls'][seed] = s['polls'].get(seed, 0) + 1
 s['protocols'].setdefault(seed, []).append(protocol)
 row = {'ip': seed, 'serialNumber': s['serials'][seed], 'status': s['status']}
 if scenario in ('sha_only', 'mixed') and protocol == 'md5' and (scenario == 'sha_only' or seed.endswith('.10')):
  row['status'] = 'notAuthorized'
 if scenario == 'missing_serial' or (scenario == 'later' and s['polls'][seed] < s['ready_after']): row['serialNumber'] = ''
 if scenario == 'second_missing' and seed.endswith('.11'): row['serialNumber'] = ''
 if scenario == 'permanent_mixed' and seed.endswith('.11'): row['status'] = 'notManageable'
 if scenario in ('wrong_serial', 'wrong_serial_elsewhere'): row['serialNumber'] = 'OTHER_SERIAL'
 if scenario == 'wrong_seed': row['ip'] = '192.0.2.99'
 if scenario == 'missing_status': row.pop('status')
 if scenario == 'conflicting_ips': row['seedIp'] = '192.0.2.99'
 rows.append(row)
 if scenario == 'duplicate': rows.append(dict(row))
 if scenario in ('extra_unrelated', 'conflicting_serial'):
  rows.append({'ip': '192.0.2.99', 'serialNumber': row['serialNumber'] if scenario == 'conflicting_serial' else 'UNRELATED', 'status': 'ok'})
 if scenario == 'wrong_serial_elsewhere':
  rows.append({'ip': '192.0.2.99', 'serialNumber': s['serials'][seed], 'status': 'ok'})
 if scenario == 'duplicate_wrong': rows.append(dict(row, serialNumber='OTHER_SERIAL'))
 if scenario == 'malformed_row': rows.append('invalid row')
body = {'switches': rows}
if scenario == 'malformed_switches': body['switches'] = {'unexpected': rows}
if scenario == 'malformed_current': body = None
finish(failed=scenario == 'module_failure', changed=False,
       status=503 if scenario == 'http_error' else 429 if scenario == 'transient_429' and max(s['polls'].values()) == 1 else 200, current=body)
'''


def execute(tmp_path, scenario="ready", status="manageable", rediscover=True, switch_count=1,
            retries=1, ready_after=2, protocols=None, credential_lookup=False,
            discovery_timeout=5, call_timeout=2, adjacent_action=False):
    source = yaml.safe_load(GUARD.read_text())[0]
    onboarding = next(task for task in source["tasks"]
                      if task.get("name", "").startswith("Onboard the missing switches"))
    switches = [{"seed_ip": "192.0.2." + str(10 + index), "serial": "FIXTURE" + str(index),
                 "name": "fixture-" + str(index), "fabric": "fixture-fabric", "role": "leaf"}
                for index in range(switch_count)]
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"scenario": scenario, "status": status,
                                     "serials": {row["seed_ip"]: row["serial"] for row in switches},
                                     "polls": {}, "protocols": {}, "batches": [], "adds": [], "ready_after": ready_after}))
    modules = tmp_path / "collections/ansible_collections/cisco/nd/plugins/modules"
    modules.mkdir(parents=True)
    for name in ("nd_rest", "nd_manage_switches"):
        (modules / (name + ".py")).write_text(FAKE_MODULE)
    if adjacent_action:
        (tmp_path / 'action_plugins').mkdir()
        shutil.copy2(ROOT / 'playbooks/action_plugins/nd_switch_discovery.py',
                     tmp_path / 'action_plugins/nd_switch_discovery.py')
    values = {"ansible_python_interpreter": sys.executable, "nd_switch_apply": True,
              "nd_missing_switches": switches, "nd_switch_expected_serial_supported": False,
              "nd_switch_username": "fixture-user", "nd_switch_password": "fixture-password",
              "nd_switch_deploy": True, "nd_switch_deploy_scope": "global",
              "nd_switch_rediscover_enabled": rediscover,
              "nd_switch_rediscover_protocols": protocols if protocols is not None else ["md5", "sha"],
              "nd_switch_rediscover_retries": source["vars"]["nd_switch_rediscover_retries"],
              "nd_switch_rediscover_delay": 0,
              "nd_switch_discovery_timeout": discovery_timeout, "nd_switch_discovery_call_timeout": call_timeout,
              "nd_switch_onboard_initial_wait": 1,
              "nd_switch_onboard_retries": 0, "nd_switch_onboard_delay": 0}
    values.update(nd_switch_guard_timeout_seconds=3600, _nd_switch_guard_started=time.monotonic())
    if '_nd_switch_clock' in source['vars']:
        values['_nd_switch_clock'] = source['vars']['_nd_switch_clock']
    if credential_lookup:
        values['nd_switch_username'] = "{{ lookup('env', 'NDP_FIXTURE_USERNAME') }}"
        values['nd_switch_password'] = "{{ lookup('env', 'NDP_FIXTURE_PASSWORD') }}"
    play = tmp_path / "play.yaml"
    play.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local", "gather_facts": False,
                                    "vars": values, "tasks": [
                                        {"ansible.builtin.debug": {"msg": "FIXTURE_DISCOVERY_RETRIES={{ nd_switch_rediscover_retries }}"}},
                                        copy.deepcopy(onboarding)]}], sort_keys=False))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\nretry_files_enabled=False\ndisplay_skipped_hosts=True\n")
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config),
                       ANSIBLE_COLLECTIONS_PATH=str(tmp_path / "collections"),
                       ANSIBLE_COLLECTIONS_SCAN_SYS_PATH="False", ANSIBLE_STDOUT_CALLBACK="default",
                       ANSIBLE_CALLBACK_PLUGINS=str(tmp_path / "callbacks"),
                       ANSIBLE_ACTION_PLUGINS=str(ROOT / "playbooks/action_plugins"),
                       ONBOARD_FIXTURE_STATE=str(state_file),
                       ANSIBLE_LOCAL_TEMP=str(tmp_path / "local-tmp"),
                       ANSIBLE_LOCAL_TMP=str(tmp_path / "local-tmp"),
                       ANSIBLE_REMOTE_TEMP=str(tmp_path / "remote-tmp"),
                       OBJC_DISABLE_INITIALIZE_FORK_SAFETY="YES")
    environment.update(NDP_FIXTURE_USERNAME='fixture-user', NDP_FIXTURE_PASSWORD='fixture-password')
    if adjacent_action:
        environment.pop('ANSIBLE_ACTION_PLUGINS', None)
    if retries is None:
        environment.pop("ND_SWITCH_REDISCOVER_RETRIES", None)
    else:
        environment["ND_SWITCH_REDISCOVER_RETRIES"] = str(retries)
    completed = subprocess.run([str(Path(sys.executable).with_name("ansible-playbook")),
                                "-i", "localhost,", str(play)], env=environment,
                               capture_output=True, text=True, timeout=30)
    return completed, json.loads(state_file.read_text())


@pytest.mark.parametrize("status", ["manageable", "ok", "alreadyManaged"])
def test_ready_expected_identity_skips_fixed_wait_and_adds_all_switches(tmp_path, status):
    result, state = execute(tmp_path, status=status, switch_count=2)
    assert result.returncode == 0, result.stdout + result.stderr
    assert list(state["polls"].values()) == [1, 1]
    assert len(state["adds"]) == 1 and len(state["adds"][0]) == 2
    assert all(row["preserve_config"] is False for row in state["adds"][0])
    assert all(row["auth_proto"] == 'MD5' for row in state["adds"][0])
    assert "NDP_SWITCH_REDISCOVER_READY" in result.stdout
    assert re.search(r'NDP_SWITCH_PHASE: discovery [0-9.]+ status=success', result.stdout)
    assert re.search(r'NDP_SWITCH_PHASE: add [0-9.]+ status=success', result.stdout)
    wait_output = result.stdout.split("TASK [Wait for late/rebooting switches", 1)[1].split("TASK [", 1)[0]
    assert "skipping: [localhost]" in wait_output


@pytest.mark.parametrize("scenario,status", [
    ("missing_serial", "ok"), ("wrong_serial", "ok"), ("wrong_seed", "ok"),
    ("ready", "notAuthorized"), ("ready", "notReachable"), ("ready", "notManageable"),
    ("missing_status", "ok"), ("ready", "unknown"), ("http_error", "ok"),
    ("module_failure", "ok"), ("malformed_switches", "ok"), ("malformed_current", "ok"),
    ("duplicate", "ok"), ("second_missing", "ok"), ("duplicate_wrong", "ok"),
    ("conflicting_serial", "ok"), ("malformed_row", "ok"), ("conflicting_ips", "ok"),
    ("wrong_serial_elsewhere", "ok"),
])
def test_failed_or_ambiguous_identity_stops_before_any_add(tmp_path, scenario, status):
    result, state = execute(tmp_path, scenario, status, switch_count=2 if scenario == "second_missing" else 1)
    assert result.returncode != 0, result.stdout + result.stderr
    assert state["adds"] == []
    assert 1 <= max(state["polls"].values()) <= 4
    assert "NDP_SWITCH_REDISCOVER_READY" not in result.stdout
    assert re.search(r'NDP_SWITCH_PHASE: discovery [0-9.]+ status=failed', result.stdout)
    assert 'NDP_SWITCH_PHASE: add ' not in result.stdout


def test_bounded_discovery_retries_until_expected_identity_is_ready(tmp_path):
    result, state = execute(tmp_path, "later")
    assert result.returncode == 0, result.stdout + result.stderr
    assert list(state["polls"].values()) == [2]
    assert len(state["adds"]) == 1


def test_default_polling_uses_the_deadline_without_a_retry_count_cap(tmp_path):
    result, state = execute(tmp_path, retries=None)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "FIXTURE_DISCOVERY_RETRIES=" in result.stdout
    assert list(state["polls"].values()) == [1]


def test_explicit_retry_override_allows_multiple_transient_discoveries(tmp_path):
    result, state = execute(tmp_path, "later", retries=3, ready_after=4)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "FIXTURE_DISCOVERY_RETRIES=3" in result.stdout
    assert list(state["polls"].values()) == [4] and len(state["adds"]) == 1


def test_zero_retry_override_is_not_replaced_by_the_default_budget(tmp_path):
    result, state = execute(tmp_path, "missing_serial", retries=0)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "FIXTURE_DISCOVERY_RETRIES=0" in result.stdout
    assert list(state["polls"].values()) == [2] and state["adds"] == []


def test_zero_retry_override_accepts_a_positive_first_discovery(tmp_path):
    result, state = execute(tmp_path, retries=0)
    assert result.returncode == 0, result.stdout + result.stderr
    assert list(state["polls"].values()) == [1] and len(state["adds"]) == 1


@pytest.mark.parametrize("scenario,count", [('sha_only', 1), ('mixed', 2)])
def test_sha_fallback_propagates_the_confirmed_protocol_without_leaking_between_seeds(tmp_path, scenario, count):
    result, state = execute(tmp_path, scenario, switch_count=count)
    assert result.returncode == 0, result.stdout + result.stderr
    assert state['protocols']['192.0.2.10'] == ['md5', 'sha']
    assert state['adds'][0][0]['auth_proto'] == 'SHA'
    if count == 2:
        assert state['protocols']['192.0.2.11'] == ['md5']
        assert state['adds'][0][1]['auth_proto'] == 'MD5'


def test_unrelated_discovery_rows_do_not_hide_one_valid_requested_identity(tmp_path):
    result, state = execute(tmp_path, 'extra_unrelated')
    assert result.returncode == 0, result.stdout + result.stderr
    assert list(state['polls'].values()) == [1] and len(state['adds']) == 1


def test_another_expected_seed_in_a_response_does_not_skip_its_own_probe(tmp_path):
    result, state = execute(tmp_path, 'other_expected_ready', switch_count=2)
    assert result.returncode == 0, result.stdout + result.stderr
    assert state['polls'] == {'192.0.2.10': 1, '192.0.2.11': 1}
    assert state['batches'] == [{'seeds': ['192.0.2.10', '192.0.2.11'], 'protocol': 'md5'}]


def test_legacy_retry_override_caps_complete_batched_cycles(tmp_path):
    result, state = execute(tmp_path, 'missing_serial', retries=3)
    assert result.returncode != 0, result.stdout + result.stderr
    assert state['protocols']['192.0.2.10'] == ['md5', 'sha'] * 4
    assert state['adds'] == []


def test_success_skips_all_remaining_protocols_before_the_next_seed(tmp_path):
    result, state = execute(tmp_path, switch_count=2, protocols=['md5', 'sha', 'sha-256'])
    assert result.returncode == 0, result.stdout + result.stderr
    assert state['protocols'] == {'192.0.2.10': ['md5'], '192.0.2.11': ['md5']}


def test_confirmed_protocol_uses_the_original_collection_config_field(tmp_path):
    collection = tmp_path / 'ansible_collections/cisco'
    collection.mkdir(parents=True)
    (collection / 'nd').symlink_to(ROOT.parents[1])
    code = '''
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.config_models import SwitchConfigModel
config = SwitchConfigModel.model_validate({'seed_ip': '192.0.2.10', 'role': 'leaf', 'auth_proto': 'SHA'})
assert config.auth_proto == 'sha'
'''
    result = subprocess.run([sys.executable, '-B', '-c', code],
                            env=dict(os.environ, PYTHONPATH=str(tmp_path)), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_explicitly_disabled_rediscovery_retains_the_fallback_wait(tmp_path):
    result, state = execute(tmp_path, rediscover=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert state["polls"] == {} and len(state["adds"]) == 1
    assert "NDP_SWITCH_REDISCOVER_READY" not in result.stdout
    wait_output = result.stdout.split("TASK [Wait for late/rebooting switches", 1)[1].split("TASK [", 1)[0]
    assert "ok: [localhost]" in wait_output and "skipping:" not in wait_output


def test_action_renders_existing_env_lookup_credentials_before_calling_nd_rest(tmp_path):
    result, state = execute(tmp_path, credential_lookup=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(state['adds']) == 1


def test_actual_nd_rest_call_is_bounded_before_the_outer_module_timeout(tmp_path):
    result, state = execute(tmp_path, 'slow_api', retries=None,
                            discovery_timeout=0.2, call_timeout=0.1)
    assert result.returncode != 0, result.stdout + result.stderr
    assert 'NDP_SWITCH_REDISCOVER_UNREADY' in result.stdout
    assert 'DEADLINE_EXCEEDED' in result.stdout
    assert state['adds'] == []


def test_action_plugin_loads_beside_the_guard_in_the_installed_layout(tmp_path):
    result, state = execute(tmp_path, adjacent_action=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(state['adds']) == 1


def test_one_permanently_unready_switch_blocks_the_entire_add_phase(tmp_path):
    result, state = execute(tmp_path, 'permanent_mixed', switch_count=2, retries=None)
    assert result.returncode != 0, result.stdout + result.stderr
    assert 'PERMANENT_DISCOVERY_FAILURE' in result.stdout
    assert state['protocols'] == {'192.0.2.10': ['md5'], '192.0.2.11': ['md5', 'sha']}
    assert state['adds'] == []


def test_actual_nd_rest_transient_429_can_recover_in_the_same_batched_cycle(tmp_path):
    result, state = execute(tmp_path, 'transient_429', retries=0)
    assert result.returncode == 0, result.stdout + result.stderr
    assert state['protocols'] == {'192.0.2.10': ['md5', 'sha']}
    assert state['adds'][0][0]['auth_proto'] == 'SHA'
