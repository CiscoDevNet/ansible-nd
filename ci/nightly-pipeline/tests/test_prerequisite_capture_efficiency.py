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


def tasks(filename):
    return yaml.safe_load((PREREQUISITES / filename).read_text())


def named(items, name):
    return copy.deepcopy(next(item for item in items if item.get("name", "").startswith(name)))


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
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps({"responses": responses or {}, "reads": [], "writes": [], "plans": 0,
                                  "replan_operations": replan_operations or []}))
    planner = tmp_path / "planner.py"
    planner.write_text("""import json, os
from pathlib import Path
p=Path(os.environ['NDP_CAPTURE_FIXTURE_LEDGER']); s=json.loads(p.read_text()); s['plans']+=1
assert '/fixture/state' in s['reads'], 'Replan must use a fresh capture'
p.write_text(json.dumps(s)); print(json.dumps({'operations':s['replan_operations']}))
""")
    values = {**values, "ansible_python_interpreter": sys.executable, "_ndp_argv": [sys.executable, str(planner)]}
    result_path = tmp_path / "result.json"
    selected += [{"name": "Save synthetic observed facts", "ansible.builtin.copy": {
        "dest": str(result_path), "content": "{{ {'state': _ndp_live_state | default({}), 'done': _ndp_baseline_repair_interfaces_done | default(none), 'refresh': _ndp_reconcile_requires_refresh | default(none), 'fresh_write_count': _fixture_fresh_snapshot | default(none)} | to_json }}"}}]
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


def mutation_stub(tmp_path, operation):
    (tmp_path / ("apply_" + operation + ".yaml")).write_text(yaml.safe_dump([
        {"name": "Apply declared synthetic change", "cisco.nd.nd_rest": {"path": "/fixture/change", "method": "post"}}
    ], sort_keys=False))


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


@pytest.mark.parametrize("stage,action,expected_capture,done", (
    ("interfaces", None, 0, True), ("interfaces", "admin_up", 1, True),
    ("interfaces", "delete_pc", 1, False), ("switches", "move", 0, None),
))
def test_empty_interface_repairs_reuse_capture_but_real_repairs_refresh(tmp_path, stage, action, expected_capture, done):
    source = tasks("repair_baseline.yaml")
    selected = [named(source, prefix) for prefix in ("Apply and verify each declared baseline repair", "Recapture actual controller state", "Stop repair passes")]
    capture_stub(tmp_path)
    operation = "repair_interface" if stage == "interfaces" else "repair_switch"
    mutation_stub(tmp_path, operation)
    changes = [{"operation": operation, "action": action, "switch_ref": "fixture-switch"}] if action else []
    completed, ledger, facts = run(tmp_path, selected, {"_ndp_repair_stage": stage,
                                                       "_ndp_repair_plan": {"stdout": json.dumps({"operations": changes})}})
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert ledger["reads"].count("/fixture/state") == expected_capture
    assert len(ledger["writes"]) == bool(changes)
    assert facts["done"] is done
    if expected_capture:
        assert int(facts["fresh_write_count"]) == 1


def wrapper_tail():
    source = tasks("nd_prerequisite_wrapper.yaml")
    start = next(index for index, task in enumerate(source) if task.get("name", "").startswith("Decide whether prerequisite operations"))
    end = next(index for index, task in enumerate(source) if task.get("name", "").startswith("Publish verified ND prerequisite"))
    return copy.deepcopy(source[start:end])


def verification_operations():
    return [
        {"operation": "verify_resource", "resource": {"name": "fixture-resource"}},
        {"operation": "verify_free_interfaces", "switch_ref": "fixture-switch", "interfaces": ["Ethernet1/41"],
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
    completed, ledger, facts = run(tmp_path, wrapper_tail(), {"nd_prerequisite_mode": "live", "nd_prerequisite_apply": True,
                                                           "_ndp_execution_id": "fixture-profile", "_ndp_result": {"operations": operations},
                                                           "_ndp_registry": {"lab": {"interface_allowlist": {"fixture-switch": ["Ethernet1/41"]}}}},
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


def test_unknown_operation_still_fails_the_original_contract_before_execution(tmp_path):
    contract = named(tasks("nd_prerequisite_wrapper.yaml"), "Confirm the prepared topology before invoking")
    completed, ledger, _ = run(tmp_path, [contract], {
        "_ndp_execution_id": "fixture-profile",
        "_ndp_result": {"resolved": {"execution_id": "fixture-profile"}, "operations": [{"operation": "future_operation"}]},
    })
    assert completed.returncode != 0
    assert "plans an unsupported operation" in completed.stdout
    assert not ledger["reads"] and not ledger["writes"] and not ledger["plans"]
