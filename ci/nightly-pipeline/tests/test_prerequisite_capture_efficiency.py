"""Execute production prerequisite task gates with local fake modules; no ND calls."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PREREQUISITES = ROOT / "playbooks/nd_prerequisite"
FAKE_MODULE = r'''
import json, os
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule
module = AnsibleModule(argument_spec={'path': {'type': 'str', 'required': True}, 'method': {'type': 'str', 'default': 'get'}})
p = Path(os.environ['NDP_CAPTURE_FIXTURE_LEDGER']); state = json.loads(p.read_text())
path = module.params['path']; method = module.params['method']
if method == 'get':
 state['reads'].append(path)
 if path == '/fixture/state': current = {'write_count': len(state['writes'])}
 elif path in state['responses']: current = state['responses'][path]
 else:
  p.write_text(json.dumps(state)); module.fail_json(msg='Unexpected fixture-only read: ' + path)
else:
 state['writes'].append(path); current = {}
p.write_text(json.dumps(state)); module.exit_json(changed=method != 'get', status=200, current=current)
'''

FAKE_VPC_MODULE = r'''
import json, os
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule
module = AnsibleModule(argument_spec={
    'fabric_name': {'type': 'str', 'required': True},
    'state': {'type': 'str', 'choices': ['gathered'], 'required': True},
    'config': {'type': 'list', 'elements': 'dict', 'required': True}})
ledger = Path(os.environ['NDP_CAPTURE_FIXTURE_LEDGER'])
state = json.loads(ledger.read_text())
state['reads'].append('vpc:' + module.params['fabric_name'])
ledger.write_text(json.dumps(state))
module.exit_json(changed=False, gathered=state['responses']['vpc'])
'''

FAKE_PORT_CHANNEL_MODULE = r'''
from ansible.module_utils.basic import AnsibleModule
module = AnsibleModule(argument_spec={
    'fabric_name': {'type': 'str'}, 'config': {'type': 'list'},
    'config_actions': {'type': 'dict'}, 'state': {'type': 'str'}, 'output_level': {'type': 'str'}})
module.exit_json(changed=False, before=[], after=[])
'''


def tasks(filename):
    return yaml.safe_load((PREREQUISITES / filename).read_text())


def flat(items):
    for item in items:
        yield item
        for section in ("block", "rescue", "always"):
            yield from flat(item.get(section, []))


def named(items, name):
    return copy.deepcopy(next(item for item in flat(items) if item.get("name", "").startswith(name)))


def reveal(value):
    if isinstance(value, dict):
        if "no_log" in value:
            value["no_log"] = False
        for child in value.values():
            reveal(child)
    elif isinstance(value, list):
        for child in value:
            reveal(child)


def run(tmp_path, selected, values, responses=None, replan_operations=None):
    modules = tmp_path / "collections/ansible_collections/cisco/nd/plugins/modules"
    modules.mkdir(parents=True)
    (modules / "nd_rest.py").write_text(FAKE_MODULE)
    (modules / "nd_manage_vpc_pair.py").write_text(FAKE_VPC_MODULE)
    for module_name in ("nd_interface_port_channel_access", "nd_interface_port_channel_trunk_host",
                        "nd_interface_port_channel_routed"):
        (modules / (module_name + ".py")).write_text(FAKE_PORT_CHANNEL_MODULE)
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps({"responses": responses or {}, "reads": [], "writes": [], "plans": 0,
                                  "replan_operations": replan_operations or []}))
    planner = tmp_path / "planner.py"
    planner.write_text("""import json, os, sys
from pathlib import Path
p=Path(os.environ['NDP_CAPTURE_FIXTURE_LEDGER']); s=json.loads(p.read_text()); s['plans']+=1
operations = s['replan_operations']
if '--repair-stage' in sys.argv:
    stage = sys.argv[sys.argv.index('--repair-stage') + 1]
    operations = operations.get(stage, []) if isinstance(operations, dict) else operations
else:
    assert '/fixture/state' in s['reads'], 'Replan must use a fresh capture'
p.write_text(json.dumps(s)); print(json.dumps({'operations':operations}))
""")
    values = {**values, "ansible_python_interpreter": sys.executable, "_ndp_argv": [sys.executable, str(planner)]}
    result_path = tmp_path / "result.json"
    selected += [{"name": "Save synthetic observed facts", "ansible.builtin.copy": {
        "dest": str(result_path), "content": "{{ {'state': _ndp_live_state | default({}), 'done': _ndp_baseline_repair_interfaces_done | default(none), 'refresh': _ndp_reconcile_requires_refresh | default(none), 'fresh_write_count': _fixture_fresh_snapshot | default(none), 'passes': _fixture_passes | default([])} | to_json }}"}}]
    reveal(selected)  # Synthetic data only; production no_log remains unchanged.
    play = tmp_path / "play.yaml"
    play.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local", "gather_facts": False,
                                    "vars": values, "tasks": selected}], sort_keys=False))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\nretry_files_enabled=False\n")
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_COLLECTIONS_PATH=str(tmp_path / "collections"),
                       ANSIBLE_COLLECTIONS_SCAN_SYS_PATH="False", ANSIBLE_STDOUT_CALLBACK="default",
                       ANSIBLE_CALLBACK_PLUGINS=str(tmp_path / "callbacks"), NDP_CAPTURE_FIXTURE_LEDGER=str(ledger),
                       ANSIBLE_LOCAL_TEMP=str(tmp_path / "local-tmp"), ANSIBLE_LOCAL_TMP=str(tmp_path / "local-tmp"),
                       ANSIBLE_REMOTE_TEMP=str(tmp_path / "remote-tmp"), OBJC_DISABLE_INITIALIZE_FORK_SAFETY="YES")
    completed = subprocess.run([str(Path(sys.executable).with_name("ansible-playbook")), "-i", "localhost,", str(play)],
                               text=True, capture_output=True, env=environment, timeout=60)
    return completed, json.loads(ledger.read_text()), json.loads(result_path.read_text()) if result_path.exists() else None


def capture_stub(tmp_path):
    (tmp_path / "nd_prerequisite_capture.yaml").write_text(yaml.safe_dump([
        {"name": "Capture actual synthetic post-apply state", "cisco.nd.nd_rest": {"path": "/fixture/state"},
         "register": "_fixture_capture"},
        {"name": "Retain fresh synthetic snapshot", "ansible.builtin.set_fact": {
            "_fixture_fresh_snapshot": "{{ _fixture_capture.current.write_count }}"}},
    ], sort_keys=False))


def mutation_stub(tmp_path, operation, journaled=False):
    change = {"name": "Apply declared synthetic change", "cisco.nd.nd_rest": {"path": "/fixture/change", "method": "post"}}
    if journaled:
        # Production repair files journal the before-image only when they will mutate.
        change = {"name": "Journal and apply declared synthetic change", "when": "_ndp_repair_operation.mutates",
                  "block": [{"name": "Journal synthetic before-image", "ansible.builtin.set_fact": {
                      "_ndp_baseline_repair_journal": "{{ _ndp_baseline_repair_journal + [_ndp_repair_operation] }}"}},
                      change]}
    (tmp_path / ("apply_" + operation + ".yaml")).write_text(yaml.safe_dump([change], sort_keys=False))


@pytest.mark.parametrize("placement", ("same_fabric", "split_fabrics", "missing", "zero_members"))
def test_membership_reads_once_per_fabric_and_normalizes_all_members(tmp_path, placement):
    source = tasks("nd_prerequisite_capture.yaml")
    selected = [named(source, prefix) for prefix in ("Discover required switch memberships", "Normalize each discovered switch membership", "Validate each required switch was discovered")]
    switches = {"one": {"serial": "FIXTURE0001"}, "two": {"serial": "FIXTURE0002"}, "three": {"serial": "FIXTURE0003"}}
    members = [{"ref": ref} for ref in switches] if placement != "zero_members" else []
    fabrics = [{"ref": "primary", "name": "fixture-primary"}]
    if placement in {"split_fabrics", "zero_members"}:
        fabrics.append({"ref": "external", "name": "fixture-external"})
    records = [{"switchId": sw["serial"], "fabricManagementIp": "192.0.2." + str(index),
                "switchRole": "edgeRouter" if ref == "three" else "leaf",
                "additionalData": {"intendedSystemMode": "normal", "configSyncStatus": "inSync"}}
               for index, (ref, sw) in enumerate(switches.items(), 1)]
    responses = {"/api/v1/manage/fabrics/fixture-primary/switches": {"switches": records[:2] if placement in {"split_fabrics", "missing"} else records}}
    if placement == "split_fabrics":
        responses["/api/v1/manage/fabrics/fixture-external/switches"] = {"switches": records[2:]}
    completed, ledger, facts = run(tmp_path, selected, {"nd_prerequisite_mode": "live", "_ndp_profile": {"fabrics": fabrics, "switches": {"members": members}},
                                                        "_ndp_registry": {"lab": {"switches": switches}}, "_ndp_live_state": {"switches": {}}}, responses)
    assert (completed.returncode == 0) is (placement != "missing"), completed.stdout + completed.stderr
    assert len(ledger["reads"]) == (0 if placement == "zero_members" else len(fabrics))
    assert len(ledger["reads"]) == len(set(ledger["reads"]))
    assert not ledger["writes"]
    if facts:
        captured = facts["state"]["switches"]
        assert set(captured) == set(switches if members else {})
        if members:
            assert captured["three"]["fabric_ref"] == ("external" if placement == "split_fabrics" else "primary")
            assert captured["three"]["seed_ip"] == "192.0.2.3"
            assert captured["three"]["role"] == "edge_router"
            assert captured["three"]["serial"] == "FIXTURE0003"
            assert captured["one"]["sync_status"] == "inSync"


@pytest.mark.parametrize("stage,action,mutates,expected_capture,done", (
    ("interfaces", None, True, 0, True), ("interfaces", "admin_up", False, 0, True),
    ("interfaces", "admin_up", True, 1, True), ("interfaces", "delete_pc", True, 1, False),
    ("switches", "move", True, 0, None),
), ids=("no_ops", "enabled_admin_up", "disabled_admin_up", "delete_pc", "switch_stage"))
def test_empty_interface_repairs_reuse_capture_but_real_repairs_refresh(tmp_path, stage, action, mutates,
                                                                        expected_capture, done):
    source = tasks("repair_baseline.yaml")
    selected = [named(source, prefix) for prefix in ("Mark the repair journal", "Apply and verify each declared baseline repair",
                                                     "Recapture actual controller state", "Stop repair passes")]
    capture_stub(tmp_path)
    operation = "repair_interface" if stage == "interfaces" else "repair_switch"
    mutation_stub(tmp_path, operation, journaled=True)
    changes = [{"operation": operation, "action": action, "switch_ref": "fixture-switch", "mutates": mutates}] if action else []
    completed, ledger, facts = run(tmp_path, selected, {"_ndp_repair_stage": stage, "_ndp_baseline_repair_journal": [{}],
                                                       "_ndp_repair_plan": {"stdout": json.dumps({"operations": changes})}})
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert ledger["reads"].count("/fixture/state") == expected_capture
    assert len(ledger["writes"]) == bool(changes and mutates)
    assert facts["done"] is done
    if expected_capture:
        assert int(facts["fresh_write_count"]) == 1


@pytest.mark.parametrize("initially_done,clean_after,expected", (
    (False, 1, ["switches", "interfaces"]),
    (False, 2, ["switches", "interfaces", "interfaces"]),
    (False, 9, ["switches"] + ["interfaces"] * 4),
    (True, 1, ["switches"]),
), ids=("clean_first_pass", "clean_second_pass", "never_clean", "already_done"))
def test_interface_repair_passes_stop_after_the_first_clean_pass(tmp_path, initially_done, clean_after, expected):
    # Real wrapper includes and real pass guard; only the pass body is synthetic.
    guard = copy.deepcopy(tasks("repair_baseline.yaml")[0])
    assert "_ndp_baseline_repair_interfaces_done" in guard["when"]
    guard["block"] = [
        {"name": "Count the synthetic repair pass", "ansible.builtin.set_fact": {
            "_fixture_passes": "{{ _fixture_passes | default([]) + [_ndp_repair_stage] }}"}},
        {"name": "Finish after the configured clean pass", "when": "_ndp_repair_stage == 'interfaces'",
         "ansible.builtin.set_fact": {"_ndp_baseline_repair_interfaces_done": (
             "{{ _fixture_passes | select('equalto', 'interfaces') | list | length >= " + str(clean_after) + " }}")}},
    ]
    (tmp_path / "repair_baseline.yaml").write_text(yaml.safe_dump([guard], sort_keys=False))
    wrapper = tasks("nd_prerequisite_wrapper.yaml")
    selected = [named(wrapper, prefix) for prefix in ("Repair declared switch baseline before requiring full capture",
                                                      "Repair and recapture the declared interface baseline")]
    completed, _, facts = run(tmp_path, selected, {
        "nd_prerequisite_mode": "live", "nd_prerequisite_apply": True, "nd_prerequisite_repair_baseline": True,
        "_ndp_profile": {"switches": {"members": [{"ref": "fixture-switch"}]}},
        "_ndp_baseline_repair_interfaces_done": initially_done})
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert facts["passes"] == expected


@pytest.mark.parametrize("switch_ops,interface_ops,expected_reads", (
    ([], [], 1),
    ([{"operation": "repair_switch", "action": "move", "switch_ref": "fixture-switch", "mutates": True}], [], 2),
    ([], [{"operation": "repair_interface", "action": "delete", "switch_ref": "fixture-switch",
           "interface": "Port-channel9", "mutates": True}], 4),
), ids=("unchanged_switch_pass_reused", "switch_repair_rereads", "later_interface_passes_reread"))
def test_interface_pass_zero_reuses_only_an_unchanged_switch_pass_snapshot(tmp_path, switch_ops, interface_ops,
                                                                         expected_reads):
    # Real wrapper includes and the real repair pass; only planner, capture and apply bodies are synthetic.
    shutil.copy(PREREQUISITES / "repair_baseline.yaml", tmp_path / "repair_baseline.yaml")
    capture_stub(tmp_path)
    mutation_stub(tmp_path, "repair_switch", journaled=True)
    mutation_stub(tmp_path, "repair_interface", journaled=True)
    wrapper = tasks("nd_prerequisite_wrapper.yaml")
    selected = [named(wrapper, prefix) for prefix in ("Repair declared switch baseline before requiring full capture",
                                                      "Capture the current prerequisite state before planning",
                                                      "Repair and recapture the declared interface baseline")]
    fabric = "/api/v1/manage/fabrics/fixture-primary"
    completed, ledger, _ = run(tmp_path, selected, {
        "nd_prerequisite_mode": "live", "nd_prerequisite_apply": True, "nd_prerequisite_repair_baseline": True,
        "_ndp_baseline_repair_lock_acquired": True, "_ndp_profile": {"switches": {"members": [{"ref": "fixture-switch"}]}},
        "_ndp_registry": {"lab": {"fabrics": {"primary": {"name": "fixture-primary", "type": "vxlanIbgp",
                                                          "lifecycle": "retained"}}}},
        "_ndp_state_dir": str(tmp_path / "state"), "_ndp_state_file": str(tmp_path / "state/state.yaml"),
        "_ndp_baseline_repair_journal": [], "_ndp_run_id": "fixture", "_ndp_execution_id": "fixture"},
        {fabric: {"management": {"type": "vxlanIbgp"}}, fabric + "/switches": {"switches": []}},
        {"switches": switch_ops, "interfaces": interface_ops})
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert ledger["reads"].count(fabric) == expected_reads
    assert ledger["reads"].count(fabric + "/switches") == expected_reads
    assert ledger["plans"] == 1 + (4 if interface_ops else 1)
    assert ("reusing the switch-pass fabric types" in completed.stdout) is (not switch_ops)
    assert yaml.safe_load((tmp_path / "state/repair-inventory.yaml").read_text()) == {
        "inventory": [{"fabric_ref": "primary", "switches": []}]}


def wrapper_tail():
    source = tasks("nd_prerequisite_wrapper.yaml")
    start = next(index for index, task in enumerate(source) if task.get("name", "").startswith("Decide whether prerequisite operations"))
    end = next(index for index, task in enumerate(source) if task.get("name", "").startswith("Publish verified ND prerequisite"))
    return copy.deepcopy(source[start:end])


def verification_operations():
    return [
        {"operation": "verify_resource", "resource": {"name": "fixture-resource"}},
        {"operation": "verify_free_interfaces", "switch_ref": "fixture-switch", "serial": "FIXTURE0001", "interfaces": ["Ethernet1/41"],
         "constraints": ["exists", "not_fabric_link", "not_port_channel_member"]},
        {"operation": "verify_logical_interface_namespace", "switch_ref": "fixture-switch", "expected_state": "absent",
         "interface_type": "loopback", "interfaces": ["Loopback601"]},
    ]


@pytest.mark.parametrize("scenario", ("empty", "resource", "free", "logical", "all_readonly", "mutating", "mixed", "future", "remaining_delta"))
def test_readonly_verification_keeps_checks_without_redundant_capture_or_replan(tmp_path, scenario):
    readonly = verification_operations()
    operations = {"empty": [], "resource": readonly[:1], "free": readonly[1:2], "logical": readonly[2:],
                  "all_readonly": readonly, "mutating": [{"operation": "ensure_interface"}],
                  "mixed": readonly + [{"operation": "ensure_interface"}],
                  "future": [{"operation": "future_operation"}],
                  "remaining_delta": [{"operation": "ensure_interface"}]}[scenario]
    # The original reconcile loop and original read-only helpers still execute.
    reconcile = [named(tasks("nd_prerequisite_reconcile.yaml"), "Apply each confirmed ND prerequisite operation")]
    (tmp_path / "nd_prerequisite_reconcile.yaml").write_text(yaml.safe_dump(reconcile, sort_keys=False))
    for name in ("verify_resource", "verify_free_interfaces", "verify_logical_interface_namespace"):
        shutil.copy2(PREREQUISITES / ("apply_" + name + ".yaml"), tmp_path)
    for name in ("ensure_interface", "future_operation"):
        mutation_stub(tmp_path, name)
    (tmp_path / "nd_prerequisite_wait.yaml").write_text("- name: Synthetic no-vPC wait path\n  ansible.builtin.debug:\n    msg: No vPC operations require convergence\n")
    capture_stub(tmp_path)
    remaining = [{"operation": "ensure_switch_membership"}] if scenario == "remaining_delta" else []
    values = {"nd_prerequisite_mode": "live", "nd_prerequisite_apply": True,
              "_ndp_execution_id": "fixture-profile", "_ndp_result": {"operations": operations},
              "_ndp_registry": {"lab": {"interface_allowlist": {"fixture-switch": ["Ethernet1/41"]}}}}
    responses = {}
    if any(operation.get("operation") == "verify_free_interfaces" for operation in operations):
        serial = "FIXTURE0001"
        values["_ndp_restore_file"] = str(tmp_path / "restore.yaml")
        values["_ndp_run_id"] = "capture-test"
        values["_ndp_registry"]["lab"].update({
            "switches": {"fixture-switch": {"serial": serial, "seed_ip": "192.0.2.41", "baseline_fabric_ref": "primary"}},
            "fabrics": {"primary": {"name": "fixture-primary"}},
        })
        responses["/api/v1/manage/fabrics/fixture-primary/switches/FIXTURE0001/interfaces/Ethernet1%2F41"] = {
            "switchId": serial, "interfaceName": "Ethernet1/41", "interfaceType": "ethernet",
            "configData": {"mode": "trunk", "networkOS": {"networkOSType": "nx-os", "policy": {
                "adminState": False, "policyType": "trunkHost"}}},
        }
    completed, ledger, facts = run(tmp_path, wrapper_tail(), values, responses=responses,
                                  replan_operations=remaining)
    needs_refresh = scenario in {"mutating", "mixed", "future", "remaining_delta"}
    assert (completed.returncode == 0) is (scenario != "remaining_delta"), completed.stdout + completed.stderr
    assert ledger["reads"].count("/fixture/state") == int(needs_refresh)
    assert ledger["plans"] == int(needs_refresh)
    assert len(ledger["writes"]) == int(needs_refresh)
    if facts:
        assert facts["refresh"] is needs_refresh
        if needs_refresh:
            assert int(facts["fresh_write_count"]) == 1
    if scenario in {"resource", "all_readonly", "mixed"}:
        assert "Verify resource contract is satisfied" in completed.stdout
    if scenario in {"free", "all_readonly", "mixed"}:
        assert "Reserved interfaces are present" in completed.stdout
    if scenario in {"logical", "all_readonly", "mixed"}:
        assert "namespace is unused" in completed.stdout


@pytest.mark.parametrize("scenario", ("ready", "missing_pair", "peer_out_of_sync", "missing_peer"))
def test_vpc_wait_uses_gathered_contract_and_requires_both_peers_in_sync(tmp_path, scenario):
    peers = [{"switchId": "FIXTURE0001", "additionalData": {"configSyncStatus": "inSync"}},
             {"switchId": "FIXTURE0002", "additionalData": {"configSyncStatus": "inSync"}}]
    if scenario == "peer_out_of_sync":
        peers[1]["additionalData"]["configSyncStatus"] = "outOfSync"
    if scenario == "missing_peer":
        peers.pop()
    pairs = [] if scenario == "missing_pair" else [{"switchId": "FIXTURE0001", "peerSwitchId": "FIXTURE0002"}]
    values = {"nd_prerequisite_mode": "live", "nd_prerequisite_apply": True,
              "_ndp_fabric_name_by_ref": {"primary": "fixture-primary"},
              "_ndp_switch_serial": {"one": "FIXTURE0001", "two": "FIXTURE0002"},
              "_ndp_result": {"operations": [{"operation": "ensure_virtual_vpc", "fabric_ref": "primary",
                                               "peer_refs": ["one", "two"]}]},
              "_ndp_profile": {"timeouts": {"retries": 1, "poll_seconds": 0}}}
    responses = {"vpc": {"vpc_pairs": pairs},
                 "/api/v1/manage/fabrics/fixture-primary/switches": {"switches": peers}}
    completed, ledger, _ = run(tmp_path, tasks("nd_prerequisite_wait.yaml"), values, responses)
    assert (completed.returncode == 0) is (scenario == "ready"), completed.stdout + completed.stderr
    assert ledger["reads"].count("vpc:fixture-primary") == (2 if scenario == "missing_pair" else 1)
    assert not ledger["writes"]
    expected_peer_reads = 0 if scenario == "missing_pair" else 1 if scenario == "ready" else 2
    assert ledger["reads"].count("/api/v1/manage/fabrics/fixture-primary/switches") == expected_peer_reads


def test_unknown_operation_still_fails_the_original_contract_before_execution(tmp_path):
    contract = named(tasks("nd_prerequisite_wrapper.yaml"), "Confirm the prepared topology before invoking")
    completed, ledger, _ = run(tmp_path, [contract], {
        "_ndp_execution_id": "fixture-profile",
        "_ndp_result": {"resolved": {"execution_id": "fixture-profile"}, "operations": [{"operation": "future_operation"}]},
    })
    assert completed.returncode != 0
    assert "plans an unsupported operation" in completed.stdout
    assert not ledger["reads"] and not ledger["writes"] and not ledger["plans"]
