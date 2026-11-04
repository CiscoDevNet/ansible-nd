import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


PLUGIN = Path(__file__).resolve().parents[1] / "playbooks/action_plugins/nd_interface_baseline.py"


@pytest.fixture
def baseline():
    specification = importlib.util.spec_from_file_location("nd_interface_baseline", PLUGIN)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def unused_evidence():
    return {
        "serial": "SERIAL00001", "interface": "Ethernet1/63",
        "identity_verified": True, "ready": True, "admin_up": True,
        "oper_down": True, "default_host_policy": True, "default_config": True,
        "no_neighbors": True, "no_attachments": True, "no_logical_children": True,
    }


def test_only_positive_unused_evidence_allows_shutdown(baseline):
    evidence = unused_evidence()
    before = copy.deepcopy(evidence)
    assert baseline.shutdown_decision(evidence, {}) == "VERIFIED_UNUSED"
    assert evidence == before


def test_registry_reservations_cover_all_profiles_and_logical_parents(baseline):
    registry = {
        "lab": {"switches": {"leaf": {"serial": "SERIAL00001"}, "spine": {"serial": "SERIAL00002"}},
                "interface_allowlist": {"leaf": ["Ethernet1/1"], "spine": []}},
        "profiles": {"unused_target": {"switches": {"members": [{"ref": "leaf"}]},
                                      "resources": [{"switch_ref": "leaf", "interface": "Ethernet1/63.42"}],
                                      "runtime_vars": {"member_ports": ["Ethernet1/10", "Ethernet1/11"]}}}}
    before = copy.deepcopy(registry)
    protected = baseline.registry_reservations(registry)
    assert set(protected["SERIAL00001"]) == {"Ethernet1/1", "Ethernet1/63", "Ethernet1/10", "Ethernet1/11"}
    assert protected["SERIAL00002"] == []
    assert registry == before


@pytest.mark.parametrize("problem", ["missing_allowlist", "missing_profiles", "duplicate_serial", "unknown_switch"])
def test_invalid_reservation_registry_blocks_planning(baseline, problem):
    registry = {"lab": {"switches": {"leaf": {"serial": "SERIAL00001"}},
                        "interface_allowlist": {"leaf": []}}, "profiles": {}}
    if problem == "missing_allowlist":
        registry["lab"].pop("interface_allowlist")
    elif problem == "missing_profiles":
        registry.pop("profiles")
    elif problem == "duplicate_serial":
        registry["lab"]["switches"]["other"] = {"serial": "SERIAL00001"}
    else:
        registry["profiles"]["bad"] = {"resources": [{"switch_ref": "foreign", "interface": "Ethernet1/63"}]}
    with pytest.raises(ValueError):
        baseline.registry_reservations(registry)


@pytest.mark.parametrize("field", [
    "identity_verified", "ready", "admin_up", "oper_down", "default_host_policy",
    "default_config", "no_neighbors", "no_attachments", "no_logical_children",
])
@pytest.mark.parametrize("value", [False, None, "true", 1])
def test_missing_or_untyped_safety_evidence_never_allows_shutdown(baseline, field, value):
    evidence = unused_evidence()
    evidence[field] = value
    assert baseline.shutdown_decision(evidence, {}) != "VERIFIED_UNUSED"


@pytest.mark.parametrize("interface", ["Ethernet1/63", "ethernet1/63", "Eth1/63.42"])
def test_reserved_ports_and_logical_parents_are_never_shutdown(baseline, interface):
    evidence = unused_evidence()
    protected = {"SERIAL00001": [interface]}
    assert baseline.shutdown_decision(evidence, protected) == "PROTECTED_INTERFACE"


def test_reservations_are_scoped_to_the_switch_identity(baseline):
    assert baseline.shutdown_decision(unused_evidence(), {"OTHER_SERIAL": ["Ethernet1/63"]}) == "VERIFIED_UNUSED"


@pytest.mark.parametrize("interface", ["mgmt0", "Vlan100", "Port-channel10", "Ethernet1/63.2", "Ethernet1/63;shutdown"])
def test_nonphysical_or_ambiguous_names_are_never_shutdown(baseline, interface):
    evidence = unused_evidence()
    evidence["interface"] = interface
    assert baseline.shutdown_decision(evidence, {}) != "VERIFIED_UNUSED"


def controller_fixture(problem=None):
    registry = {"lab": {"switches": {"leaf": {"serial": "SERIAL00001", "seed_ip": "192.0.2.10", "baseline_role": "leaf"}},
                        "interface_allowlist": {"leaf": ["Ethernet1/1"]}}, "profiles": {}}
    policy = {"adminState": True, "allowedVlans": "none", "bpduGuard": "default", "mtu": "jumbo",
              "netflow": False, "policyType": "trunkHost", "portTypeEdgeTrunk": True, "speed": "auto"}
    detail = {"switchId": "SERIAL00001", "interfaceName": "Ethernet1/63", "interfaceType": "ethernet",
              "configData": {"mode": "trunk", "networkOS": {"networkOSType": "nx-os", "policy": policy}},
              "operData": {"adminStatus": "up", "operationalStatus": "down"}}
    state = {"calls": [], "writes": [], "detail": detail, "detail_reads": 0, "lock_reads": 0, "deployed": False}

    def request(method, path, content, timeout):
        assert 0 < timeout <= 30
        state["calls"].append((method, path))
        if method != "get":
            state["writes"].append((method, path, copy.deepcopy(content)))
            if problem == "refused_write":
                return {"status": 207, "current": {"results": [{"status": "failed", "message": "PRIVATE_CANARY"}]}}
            if problem == "foreign_write_identity":
                return {"status": 207, "current": {"results": [{"switchId": "FOREIGN", "interfaceName": "Ethernet1/63", "status": "success"}]}}
            if method == "put":
                state["detail"]["configData"] = copy.deepcopy(content["configData"])
            if path.endswith("interfaceActions/deploy"):
                state["deployed"] = True
                if problem != "verification_failed":
                    state["detail"]["operData"]["adminStatus"] = "down"
            return {"status": 207, "current": {"results": [{"switchId": "SERIAL00001", "interfaceName": "Ethernet1/63", "status": "success"}]}}
        if "anomalies/details" in path:
            return {"status": 200, "current": {"anomalies": [{"cleared": state["deployed"] and problem != "active_warning",
                "anomalyString": "[SERIAL00001] Interface ethernet1/63 in undesired state up:down:Link not connected"}]}}
        if path.endswith("/switches"):
            return {"status": 200, "current": {"switches": [{"switchId": "SERIAL00001",
                "fabricManagementIp": "192.0.2.20" if problem == "wrong_identity" else "192.0.2.10", "switchRole": "leaf",
                "additionalData": {"systemMode": "normal", "intendedSystemMode": "normal", "discoveredSystemMode": "normal", "configSyncStatus": "inSync"}}]}}
        if path.endswith("deploymentFreeze"):
            state["lock_reads"] += 1
            return {"status": 200, "current": {"deploymentFreeze": problem == "frozen" or problem == "race_freeze" and state["lock_reads"] > 1}}
        if path.endswith("softwareUpdatePlan/summary"):
            return {"status": 200, "current": {"softwareUpdateSummary": {"fabricName": "fixture", "updatePlanStatus": "none"}, "updateGroups": [{"installStatus": "none"}]}}
        if "links?" in path:
            rows = [{"srcSwitchId": "SERIAL00001", "srcInterfaceName": "Ethernet1/63", "dstSwitchId": "OTHER", "dstInterfaceName": "Ethernet1/1"}] if problem == "linked" else []
            if problem == "malformed_links":
                return {"status": 200, "current": {"unexpected": []}}
            return {"status": 200, "current": {"links": rows}}
        if path.endswith("/interfaces"):
            names = ["Ethernet1/1", "Ethernet1/63"] + (["Ethernet1/63.42"] if problem == "logical_child" else [])
            body = {"interfaces": [{"interfaceName": name} for name in names]}
            if problem == "paginated":
                body["next"] = "/next-page"
            return {"status": 200, "current": body}
        if "/interfaces/" in path:
            state["detail_reads"] += 1
            current = copy.deepcopy(state["detail"])
            if problem == "nondefault" or problem == "race_config" and state["detail_reads"] > 1:
                current["configData"]["networkOS"]["policy"]["description"] = "KEEP THIS CONFIGURATION"
            if problem == "race_connected" and state["detail_reads"] > 1:
                current["operData"]["operationalStatus"] = "up"
            if problem == "attached":
                current["attachedNetworks"] = [{"networkName": "PRIVATE_ATTACHMENT_CANARY"}]
            return {"status": 200, "current": current}
        raise AssertionError("Unexpected endpoint: " + path)

    return registry, request, state


@pytest.mark.parametrize("apply", [False, True])
def test_runtime_audit_and_scoped_apply_preserve_all_other_configuration(baseline, apply):
    registry, request, state = controller_fixture()
    before = copy.deepcopy(state["detail"]["configData"])
    result = baseline.InterfaceBaseline(registry, ["fixture"], request, apply=apply, poll_seconds=0).run()
    assert result["failed"] is False
    assert result["candidates"] == 1
    assert result["verified"] == (1 if apply else 0)
    assert result["changed"] is apply
    assert len(state["writes"]) == (2 if apply else 0)
    if apply:
        expected = copy.deepcopy(before)
        expected["networkOS"]["policy"]["adminState"] = False
        assert state["detail"]["configData"] == expected
        assert state["writes"][1][2] == {"interfaces": [{"switchId": "SERIAL00001", "interfaceName": "Ethernet1/63"}]}


@pytest.mark.parametrize("problem", ["frozen", "wrong_identity", "linked", "logical_child", "nondefault",
                                     "malformed_links", "race_freeze", "race_connected", "race_config", "attached", "paginated"])
def test_runtime_never_writes_without_fresh_unused_evidence(baseline, problem):
    registry, request, state = controller_fixture(problem)
    result = baseline.InterfaceBaseline(registry, ["fixture"], request, apply=True, poll_seconds=0).run()
    assert state["writes"] == []
    assert result["verified"] == 0


@pytest.mark.parametrize("problem", ["refused_write", "foreign_write_identity"])
def test_runtime_rejected_put_never_deploys_or_logs_private_response(baseline, problem):
    import json

    registry, request, state = controller_fixture(problem)
    result = baseline.InterfaceBaseline(registry, ["fixture"], request, apply=True, poll_seconds=0).run()
    assert result["failed"] is True
    assert len(state["writes"]) == 1 and state["writes"][0][0] == "put"
    assert "PRIVATE_CANARY" not in json.dumps(result)


def test_empty_owned_scope_is_not_permission_to_shutdown_ports(baseline):
    registry, request, state = controller_fixture()
    registry["lab"]["interface_allowlist"]["leaf"] = []
    result = baseline.InterfaceBaseline(registry, ["fixture"], request, apply=True).run()
    assert state["writes"] == []
    assert result["candidates"] == 0
    assert all(row["decision"] == "NO_OWNED_INTERFACE_SCOPE" for row in result["decisions"])


def test_repeated_baseline_does_not_rewrite_already_verified_shutdown(baseline):
    registry, request, state = controller_fixture()
    first = baseline.InterfaceBaseline(registry, ["fixture"], request, apply=True, poll_seconds=0).run()
    writes = copy.deepcopy(state["writes"])
    second = baseline.InterfaceBaseline(registry, ["fixture"], request, apply=True, poll_seconds=0).run()
    assert first["verified"] == 1 and first["failed"] is False
    assert second["changed"] is False and second["failed"] is False
    assert second["candidates"] == 0
    assert state["writes"] == writes


@pytest.mark.parametrize("problem", ["active_warning", "verification_failed"])
def test_post_deploy_proof_is_bounded_and_never_accepts_an_active_warning(baseline, problem):
    registry, request, state = controller_fixture(problem)
    ticks = [0]

    def clock():
        ticks[0] += 1
        return ticks[0]

    result = baseline.InterfaceBaseline(registry, ["fixture"], request, apply=True, clock=clock,
                                        sleep=lambda seconds: None, timeout_seconds=100, poll_seconds=0).run()
    assert result["failed"] is True and result["changed"] is True
    assert result["verified"] == 0
    assert result["reason"] in {"DEADLINE_EXCEEDED", "VERIFICATION_DEADLINE"}
    assert len(state["writes"]) == 2
    assert not any("clear" in path or "acknowledge" in path for _, path in state["calls"])


@pytest.mark.parametrize("check_mode", [False, True])
def test_real_action_adapter_masks_requests_and_check_mode_never_writes(baseline, monkeypatch, check_mode):
    from types import SimpleNamespace

    registry, request, state = controller_fixture()
    monkeypatch.setattr(baseline.ActionBase, "run", lambda *args, **kwargs: {})
    action = baseline.ActionModule.__new__(baseline.ActionModule)
    action._task = SimpleNamespace(args={"registry": registry, "fabrics": ["fixture"], "apply": True,
                                         "poll_seconds": 0}, no_log=False, check_mode=check_mode)
    action._templar = SimpleNamespace(template=lambda value: value)
    action._connection = SimpleNamespace(_socket_path=None)

    def execute(module_name, module_args, task_vars):
        assert module_name == "cisco.nd.nd_rest"
        assert action._task.no_log is True
        return request(module_args["method"], module_args["path"], module_args.get("content"), 30)

    action._execute_module = execute
    result = action.run(task_vars={})
    assert result["failed"] is False
    assert result["verified"] == (0 if check_mode else 1)
    assert len(state["writes"]) == (0 if check_mode else 2)
    assert action._task.no_log is False


FAKE_REST = r'''
import json, os
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule
module = AnsibleModule(argument_spec={'method':{'type':'str'},'path':{'type':'str'},'content':{'type':'raw'}}, supports_check_mode=True)
path = Path(os.environ['BASELINE_FAKE_LEDGER'])
state = json.loads(path.read_text())
method, endpoint, content = module.params['method'], module.params['path'], module.params['content']
state['calls'].append([method, endpoint])
if method == 'put':
    state['detail']['configData'] = content['configData']
if endpoint.endswith('interfaceActions/deploy'):
    state['deployed'] = True
    state['detail']['operData']['adminStatus'] = 'down'
if method != 'get':
    body = {'results':[{'switchId':'SERIAL00001','interfaceName':'Ethernet1/63','status':'success'}]}
elif endpoint.endswith('/switches'):
    body = {'switches':[{'switchId':'SERIAL00001','fabricManagementIp':'192.0.2.10','switchRole':'leaf','additionalData':{
        'systemMode':'normal','intendedSystemMode':'normal','discoveredSystemMode':'normal','configSyncStatus':'inSync'}}]}
elif endpoint.endswith('deploymentFreeze'):
    body = {'deploymentFreeze':state.get('frozen',False)}
elif endpoint.endswith('softwareUpdatePlan/summary'):
    body = {'softwareUpdateSummary':{'fabricName':'fixture','updatePlanStatus':'none'},'updateGroups':[{'installStatus':'none'}]}
elif 'links?' in endpoint:
    body = {'links':[]}
elif endpoint.endswith('/interfaces'):
    body = {'interfaces':[{'interfaceName':'Ethernet1/1'},{'interfaceName':'Ethernet1/63'}]}
elif '/interfaces/' in endpoint:
    body = state['detail']
elif 'anomalies/details' in endpoint:
    body = {'anomalies':[{'cleared':state['deployed'],'anomalyString':'[SERIAL00001] Interface ethernet1/63 in undesired state up:down:Link not connected'}]}
else:
    module.fail_json(msg='UNEXPECTED_FAKE_ENDPOINT')
path.write_text(json.dumps(state))
module.exit_json(changed=method != 'get',status=200 if method == 'get' else 207,current=body)
'''


@pytest.mark.parametrize("apply,check_mode,membership_apply,writes", [
    (False, False, True, 0), (True, False, True, 2),
    (True, True, True, 0), (True, False, False, 0)])
@pytest.mark.parametrize("frozen", [False, True])
def test_real_ansible_shared_task_runs_audit_apply_and_check_mode_without_network(tmp_path, apply, check_mode, membership_apply, writes, frozen):
    registry, _, state = controller_fixture()
    state["frozen"] = frozen
    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text(json.dumps(registry))
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps(state))
    modules = tmp_path / "collections/ansible_collections/cisco/nd/plugins/modules"
    modules.mkdir(parents=True)
    (modules / "nd_rest.py").write_text(FAKE_REST)
    helper = PLUGIN.parent.parent / "nd_prerequisite/interface_baseline.yaml"
    playbook = tmp_path / "play.yaml"
    playbook.write_text(json.dumps([{"hosts": "localhost", "connection": "local", "gather_facts": False,
        "vars": {"ansible_python_interpreter": sys.executable, "nd_interface_baseline_registry_file": str(registry_path),
                 "nd_test_fabric_switches": {"fixture": []}, "nd_interface_baseline_apply": apply,
                 "nd_switch_apply": membership_apply, "nd_interface_baseline_poll_seconds": 0},
        "tasks": [{"ansible.builtin.include_tasks": str(helper)}]}]))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n")
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_COLLECTIONS_PATH=str(tmp_path / "collections"),
        ANSIBLE_COLLECTIONS_SCAN_SYS_PATH="False", ANSIBLE_ACTION_PLUGINS=str(PLUGIN.parent),
        ANSIBLE_STDOUT_CALLBACK="default", ANSIBLE_NOCOLOR="1", BASELINE_FAKE_LEDGER=str(ledger),
        ANSIBLE_LOCAL_TEMP=str(tmp_path / "local"), ANSIBLE_REMOTE_TEMP=str(tmp_path / "remote"),
        OBJC_DISABLE_INITIALIZE_FORK_SAFETY="YES")
    command = [str(Path(sys.executable).with_name("ansible-playbook")), "-i", "localhost,", str(playbook)]
    if check_mode:
        command.append("--check")
    completed = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=60)
    assert (completed.returncode == 0) is (not frozen), completed.stdout + completed.stderr
    captured = json.loads(ledger.read_text())
    assert len([row for row in captured["calls"] if row[0] != "get"]) == (0 if frozen else writes)
    assert "NDP_INTERFACE_BASELINE" in completed.stdout
    if frozen:
        assert "NDP_INTERFACE_BASELINE_BLOCKED" in completed.stdout
    assert "192.0.2.10" not in completed.stdout and "SERIAL00001" not in completed.stdout


def test_real_registry_and_all_lifecycle_delivery_hooks_are_complete(baseline):
    import yaml

    root = PLUGIN.parents[2]
    registry = yaml.safe_load((root / "tests/nd_prerequisite_profiles.yaml").read_text())
    protected = baseline.registry_reservations(registry)
    assert len(protected) == len(registry["lab"]["switches"]) == 8
    for name, interfaces in registry["lab"]["interface_allowlist"].items():
        serial = registry["lab"]["switches"][name]["serial"]
        assert all(baseline.physical_parent(value) in protected[serial] for value in interfaces)
    guard = yaml.safe_load((root / "playbooks/nd_ensure_switches.yaml").read_text())[0]
    moving = next(task for task in guard["tasks"] if task.get("name", "").startswith("Move the roster switches out"))
    assert "NDP_INTERFACE_BASELINE_HOOK before source-fabric removal" in moving["block"][0]["name"]
    assert moving["block"][0]["when"] == "nd_interface_baseline_enabled | default(false) | bool"
    assert any("NDP_INTERFACE_BASELINE_HOOK after membership" in task.get("name", "") for task in guard["tasks"])
    reset = yaml.safe_load((root / "consul/reset_fabric.yaml").read_text())[0]
    assert "NDP_INTERFACE_BASELINE_HOOK after reset" in reset["tasks"][-1]["name"]
    assert guard["vars"]["nd_switch_predelete_copy_timeout_seconds"] == 900
    for variant in ("Jenkinsfile_nd_jenkins_script", "Jenkinsfile_nd_jenkins_script_temp_switches", "Jenkinsfile_nd_jenkins_script_comm_list"):
        source = (root / variant).read_text()
        assert "'nd_prerequisite/interface_baseline.yaml'" in source
        assert "'action_plugins/nd_interface_baseline.py'" in source
        assert "name: 'ND_INTERFACE_BASELINE_ENABLED', defaultValue: false" in source
        assert "name: 'ND_INTERFACE_BASELINE_APPLY', defaultValue: false" in source
        assert "NDP_INTERFACE_BASELINE_RUNTIME_MISSING" in source