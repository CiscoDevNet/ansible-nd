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
        "oper_down": True, "unused_reason": True, "default_host_policy": True, "default_config": True,
        "no_neighbors": True, "no_attachments": True, "no_logical_children": True,
    }


def test_only_positive_unused_evidence_allows_shutdown(baseline):
    evidence = unused_evidence()
    before = copy.deepcopy(evidence)
    assert baseline.shutdown_decision(evidence, {}) == "VERIFIED_UNUSED"
    assert evidence == before


def test_lifecycle_baseline_enablement_and_sync_default_true_without_environment():
    import yaml

    root = PLUGIN.parents[2]
    guard = yaml.safe_load((root / "playbooks/nd_ensure_switches.yaml").read_text())[0]
    reset = yaml.safe_load((root / "consul/reset_fabric.yaml").read_text())[0]
    helper = yaml.safe_load((root / "playbooks/nd_prerequisite/interface_baseline.yaml").read_text())
    recovery = next(task for task in helper if "nd_interface_baseline" in task)["nd_interface_baseline"]["recover_config_sync"]

    assert "default(true, true)" in guard["vars"]["nd_interface_baseline_enabled"]
    assert "default(true, true)" in reset["tasks"][-1]["when"][0]
    assert "default(true, true)" in recovery


@pytest.mark.parametrize('result,reason,status', [
    ({'reason': 'API_REQUEST_REJECTED', 'required_candidates': 8, 'required_verified': 2,
      'api_failure': {'method': 'get', 'operation': '/api/v1/manage/fabrics/{id}/switches', 'http_status': 503}},
     'API_REQUEST_REJECTED', '503'),
    ({'reason': 'CONNECTIVITY_INTERFACE_STATUS_ACTIVE', 'remaining_connectivity_alerts': 4},
     'CONNECTIVITY_INTERFACE_STATUS_ACTIVE', 'None'),
    ({}, 'UNVERIFIED', 'None'),
])
def test_shared_failure_message_identifies_the_cause_without_raw_payloads(result, reason, status):
    import yaml
    from jinja2 import StrictUndefined
    from jinja2.nativetypes import NativeEnvironment

    helper = yaml.safe_load((PLUGIN.parent.parent / 'nd_prerequisite/interface_baseline.yaml').read_text())
    task = next(row for row in helper if row['name'].startswith('Require accepted operations'))
    environment = NativeEnvironment(undefined=StrictUndefined)
    values = {
        '_nd_interface_baseline_result': dict(result, response='PRIVATE_CANARY'),
        '_nd_interface_baseline_checkpoint': {'path': '/protected/checkpoint'},
    }
    values['_nd_baseline_api_failure'] = environment.from_string(
        task['vars']['_nd_baseline_api_failure']).render(values)
    message = environment.from_string(task['ansible.builtin.assert']['fail_msg']).render(values)
    assert f'reason={reason};' in message
    assert f'http_status={status}.' in message
    assert '/protected/checkpoint/mutations.jsonl' in message
    assert 'No membership transfer is permitted' in message
    assert 'PRIVATE_CANARY' not in message
    if 'required_candidates' in result:
        assert 'required_admin_up=2/8;' in message
    if 'remaining_connectivity_alerts' in result:
        assert 'remaining_connectivity_alerts=4;' in message


def batch_controller_fixture(problem=None, journal=None, count=3):
    registry, original_request, state = controller_fixture()
    details = {}
    names = ['Ethernet1/61', 'Ethernet1/62', 'Ethernet1/63'] if count == 3 else [
        'Ethernet1/' + str(port) for port in range(40, 40 + count)]
    for name in names:
        details[name] = copy.deepcopy(state['detail'])
        details[name]['interfaceName'] = name
    state.update(details=details, updated=set(), now=0, batch_writes=[], bulk_reads=0)

    def request(method, path, content, timeout):
        state['now'] += 0.01
        if method == 'get' and path.endswith('/interfaces'):
            state['bulk_reads'] += 1
            if state['batch_writes']:
                if problem == 'race_config':
                    details['Ethernet1/62']['configData']['networkOS']['policy']['description'] = 'new intent'
                if problem == 'race_neighbor':
                    details['Ethernet1/62']['operData']['neighbors'] = [{'switchName': 'new peer'}]
            return {'status': 200, 'current': {'interfaces': copy.deepcopy(list(details.values()))}}
        if method == 'get' and 'links?' in path and problem == 'race_link' and state['batch_writes']:
            return {'status': 200, 'current': {'links': [{'srcSwitchId': 'SERIAL00001',
                'srcInterfaceName': 'Ethernet1/62', 'dstSwitchId': 'PEER', 'dstInterfaceName': 'Ethernet1/1'}]}}
        if method == 'get' and 'anomalies/details' in path:
            assert 'includeAnomalies=all' in path
            # These clear together on the next collector cycle. Waiting for a
            # pilot's warning before updating the rest would never complete.
            cleared = len(state['updated']) == len(details) and problem != 'active_correlated_warning'
            return {'status': 200, 'current': {'anomalies': [
                {'cleared': cleared, 'switchId': 'SERIAL00001', 'mnemonicNumber': 200022,
                 'anomalyString': 'Interface ' + name + ' in undesired state up:down:Link not connected'}
                for name in details]}}
        if method == 'post' and path.endswith('/interfaceActions/updateAdminState'):
            assert set(content) == {'interfaces'}
            rows = content['interfaces']
            assert all(set(row) == {'switchId', 'interfaceName', 'adminState'} and row['adminState'] == 'shut'
                       and row['switchId'] == 'SERIAL00001' for row in rows)
            if journal is not None:
                checkpoints = [json.loads(line) for line in journal.read_text().splitlines()]
                before_images = {row['interfaceName'] for row in checkpoints if row.get('phase') == 'before_change'}
                assert {row['interfaceName'] for row in rows} <= before_images
            state['batch_writes'].append(copy.deepcopy(content))
            results = []
            for row in rows:
                name = row['interfaceName']
                state['updated'].add(name)
                details[name]['configData']['networkOS']['policy']['adminState'] = False
                if problem == 'wrong_readback':
                    details[name]['configData']['networkOS']['policy']['description'] = 'unexpected API change'
                results.append({'switchId': 'FOREIGN' if problem == 'foreign_identity' else 'SERIAL00001',
                    'interfaceName': name, 'status': 'failed' if problem == 'refused_write' else 'success',
                    'adminStatus': 'up' if problem == 'wrong_admin_response' else 'down'})
            return {'status': 207, 'current': {'results': results}}
        if method == 'post' and path.endswith('/interfaceActions/deploy'):
            assert content['interfaces'] == [{k: row[k] for k in ['switchId', 'interfaceName']}
                                              for row in state['batch_writes'][-1]['interfaces']]
            for row in content['interfaces']:
                details[row['interfaceName']]['operData']['adminStatus'] = 'down'
            state.setdefault('batch_deploys', []).append(copy.deepcopy(content))
            return {'status': 207, 'current': {'results': [dict(row, status='success')
                                                        for row in content['interfaces']]}}
        return original_request(method, path, content, timeout)

    def sleep(seconds):
        state['now'] += seconds

    return registry, request, state, sleep


def test_batch_shutdown_checks_pilot_preserves_config_and_waits_for_collective_clearance(baseline, tmp_path):
    journal = tmp_path / 'journal.jsonl'
    registry, request, state, sleep = batch_controller_fixture(journal=journal)
    before = copy.deepcopy(state['details'])
    result = baseline.InterfaceBaseline(registry, ['fixture'], request, apply=True, poll_seconds=1,
        clock=lambda: state['now'], sleep=sleep, timeout_seconds=90, journal_path=str(journal)).run()
    assert not result['failed'] and result['candidates'] == result['verified'] == 3
    assert result['remaining_connectivity_alerts'] == 0
    assert [len(row['interfaces']) for row in state['batch_writes']] == [1, 2]
    assert [len(row['interfaces']) for row in state['batch_deploys']] == [1, 2]
    assert state['bulk_reads'] < 10  # one list per switch/batch, never per port
    for name, detail in state['details'].items():
        expected = before[name]['configData']
        expected['networkOS']['policy']['adminState'] = False
        assert detail['configData'] == expected


@pytest.mark.parametrize('problem,reason', [
    ('foreign_identity', 'OPERATION_IDENTITY_UNVERIFIED'),
    ('wrong_admin_response', 'ADMIN_STATE_RESPONSE_UNVERIFIED'),
    ('refused_write', 'API_REQUEST_REJECTED'),
    ('wrong_readback', 'ADMIN_STATE_UPDATE_READBACK_UNVERIFIED'),
    ('race_config', 'INTERFACE_CHANGED_BEFORE_APPLY'),
    ('race_neighbor', 'INTERFACE_CHANGED_BEFORE_APPLY'),
    ('race_link', 'INTERFACE_CHANGED_BEFORE_APPLY'),
])
def test_unsafe_batch_stops_after_pilot(baseline, problem, reason):
    registry, request, state, sleep = batch_controller_fixture(problem)
    result = baseline.InterfaceBaseline(registry, ['fixture'], request, apply=True, poll_seconds=1,
        clock=lambda: state['now'], sleep=sleep, timeout_seconds=90).run()
    assert result['failed'] and result['reason'] == reason
    assert [len(row['interfaces']) for row in state['batch_writes']] == [1]
    assert state['details']['Ethernet1/62']['configData']['networkOS']['policy']['adminState'] is True


def test_batch_clearance_checks_correlated_connectivity_warnings(baseline):
    registry, request, state, sleep = batch_controller_fixture('active_correlated_warning')
    result = baseline.InterfaceBaseline(registry, ['fixture'], request, apply=True, poll_seconds=1,
        clock=lambda: state['now'], sleep=sleep, timeout_seconds=90).run()
    assert result['failed'] and result['reason'] in {'VERIFICATION_DEADLINE', 'DEADLINE_EXCEEDED'}
    assert result['verified'] == 0 and len(state['batch_writes']) == 2


def test_large_unused_set_uses_small_exact_deployment_batches(baseline):
    registry, request, state, sleep = batch_controller_fixture(count=20)
    result = baseline.InterfaceBaseline(registry, ['fixture'], request, apply=True, poll_seconds=1,
        clock=lambda: state['now'], sleep=sleep, timeout_seconds=90).run()
    assert not result['failed'] and result['verified'] == 20
    assert [len(row['interfaces']) for row in state['batch_writes']] == [1, 8, 8, 3]
    assert [len(row['interfaces']) for row in state['batch_deploys']] == [1, 8, 8, 3]
    assert len(state['updated']) == 20


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
    "identity_verified", "ready", "admin_up", "oper_down", "unused_reason", "default_host_policy",
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
              "operData": {"adminStatus": "up", "operationalStatus": "down", "operationalDescription": "Link not connected"}}
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


@pytest.mark.parametrize('apply',[False,True])
def test_complete_bulk_snapshot_avoids_redundant_planning_reads_but_keeps_fresh_apply_reads(baseline,apply):
    registry,request,state=controller_fixture()
    def full_response(method,path,content,timeout):
        reply=request(method,path,content,timeout)
        if method=='get' and path.endswith('/interfaces'):
            reply['current']['interfaces']=[{'interfaceName':'Ethernet1/1'},copy.deepcopy(state['detail'])]
        return reply
    result=baseline.InterfaceBaseline(registry,['fixture'],full_response,apply=apply,poll_seconds=0).run()
    assert not result['failed'] and result['candidates']==1
    assert state['detail_reads']==(2 if apply else 0)
    assert result['verified']==(1 if apply else 0)


def test_neighbor_appearing_after_bulk_snapshot_still_blocks_the_write(baseline):
    registry,request,state=controller_fixture()
    def changed_response(method,path,content,timeout):
        reply=request(method,path,content,timeout)
        if method=='get' and path.endswith('/interfaces'):
            reply['current']['interfaces']=[{'interfaceName':'Ethernet1/1'},copy.deepcopy(state['detail'])]
        elif method=='get' and '/interfaces/' in path:
            reply['current']['operData']['neighbors']=[{'switchName':'newly-connected-peer'}]
        return reply
    result=baseline.InterfaceBaseline(registry,['fixture'],changed_response,apply=True,poll_seconds=0).run()
    assert result['candidates']==1 and result['reason']=='INTERFACE_CHANGED_BEFORE_APPLY'
    assert state['writes']==[]


def test_unrelated_fabric_warning_without_switch_identity_does_not_break_interface_verification(baseline):
    registry,request,state=controller_fixture()
    def with_fabric_warning(method,path,content,timeout):
        reply=request(method,path,content,timeout)
        if 'anomalies/details' in path:
            reply['current']['anomalies'].append({'cleared':False,'switchId':'',
                'mnemonicNumber':200026,'mnemonicTitle':'Fabric_Configuration',
                'anomalyString':'Recalculate and deploy required before deleting an old switch.'})
        return reply
    result=baseline.InterfaceBaseline(registry,['fixture'],with_fabric_warning,apply=True,poll_seconds=0).run()
    assert not result['failed'] and result['verified']==1 and result['remaining_connectivity_alerts']==0
    assert len(state['writes'])==2


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
    assert {row["decision"] for row in result["decisions"] if "interface" in row} == {"NO_OWNED_INTERFACE_SCOPE"}
    assert result["reason"] == "CONNECTIVITY_INTERFACE_STATUS_ACTIVE"


@pytest.mark.parametrize("apply", [False, True])
@pytest.mark.parametrize("problem", ["out_of_sync", "maintenance", "wrong_address"])
def test_skipped_unready_switch_cannot_report_a_verified_baseline(baseline, apply, problem):
    registry, request, state = controller_fixture()

    def changed_request(method, path, content, timeout):
        reply = request(method, path, content, timeout)
        if path.endswith('/switches'):
            node = reply['current']['switches'][0]
            if problem == 'out_of_sync':
                node['additionalData']['configSyncStatus'] = 'outOfSync'
            elif problem == 'maintenance':
                node['additionalData']['systemMode'] = 'maintenance'
            else:
                node['fabricManagementIp'] = '192.0.2.99'
        return reply

    result = baseline.InterfaceBaseline(registry, ['fixture'], changed_request, apply=apply, poll_seconds=0).run()
    assert result['baseline_failed'] is True
    assert result['reason'] == 'SWITCH_READINESS_OR_IDENTITY_UNVERIFIED'
    assert state['writes'] == [] and result['verified'] == 0
    expected_field = {'out_of_sync': 'configSyncStatus', 'maintenance': 'systemMode',
                      'wrong_address': 'fabricManagementIp'}[problem]
    decision = next(row for row in result['decisions'] if row['decision'] == result['reason'])
    assert decision['failed_checks'] == [expected_field]
    assert '192.0.2.99' not in json.dumps(result)


@pytest.mark.parametrize('variant', ['Jenkinsfile_nd_jenkins_script', 'Jenkinsfile_nd_jenkins_script_temp_switches',
                                   'Jenkinsfile_nd_jenkins_script_comm_list'])
def test_peerlink_probe_loads_private_registry_before_admin_up(variant):
    root = Path(__file__).resolve().parents[1]
    text = (root / variant).read_text()
    probe = text.split("<<'PEERLINK_PROBE_EOF'", 1)[1].split('PEERLINK_PROBE_EOF', 1)[0]
    tasks = json.loads(probe)[0]['tasks']
    load = tasks[0]
    assert load['ansible.builtin.include_vars'] == {
        'file': '{{ playbook_dir }}/nd_prerequisite_profiles.yaml', 'name': '_ndreg'}
    assert load['no_log'] is True
    assert load['when'] == tasks[1]['when']
    assert tasks[1]['ansible.builtin.include_tasks'].endswith('/admin_up_interface.yaml')


@pytest.mark.parametrize('reverse,wrong_port,present,expected', [
    (False, False, True, True), (True, False, True, True),
    (False, True, True, False), (False, False, False, False),
])
def test_advanced_peerlink_probe_matches_exact_approved_ports(tmp_path, reverse, wrong_port, present, expected):
    root = Path(__file__).resolve().parents[1]
    text = (root / 'Jenkinsfile_nd_jenkins_script').read_text()
    probe = text.split("<<'PEERLINK_PROBE_EOF'", 1)[1].split('PEERLINK_PROBE_EOF', 1)[0]
    task = json.loads(probe)[0]['tasks'][-1]
    first = ('SERIAL1', 'Ethernet1/2')
    second = ('SERIAL2', 'Ethernet1/99' if wrong_port else 'Ethernet1/1')
    src, dst = (second, first) if reverse else (first, second)
    link = {'srcSwitchId': src[0], 'srcInterfaceName': src[1], 'dstSwitchId': dst[0],
            'dstInterfaceName': dst[1], 'linkPresent': present}
    play = [{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
             'vars': {'probe_s1': 'SERIAL1', 'probe_s2': 'SERIAL2', 'probe_exact_peerlink': 'advanced',
                      '_probe_links': {'current': {'links': [link]}}}, 'tasks': [task]}]
    path = tmp_path / 'probe.json'
    path.write_text(json.dumps(play))
    env = dict(os.environ, ANSIBLE_LOCAL_TEMP=str(tmp_path / 'local'), ANSIBLE_REMOTE_TEMP=str(tmp_path / 'remote'))
    run = subprocess.run([str(Path(sys.executable).with_name('ansible-playbook')), '-i', 'localhost,', str(path)],
                         cwd=tmp_path, env=env, text=True, capture_output=True, timeout=30)
    assert run.returncode == 0, run.stdout + run.stderr
    assert ('NDP_VPC_PEERLINK_PRESENT' in run.stdout) == expected


@pytest.mark.parametrize('apply', [False, True])
@pytest.mark.parametrize('recovers', [False, True])
def test_initial_sync_readiness_retries_are_fresh_bounded_and_do_not_mutate(baseline, apply, recovers):
    registry, original, state = controller_fixture()
    state['inventory_reads'] = 0
    state['now'] = 0

    def request(method, path, content, timeout):
        reply = original(method, path, content, timeout)
        if path.endswith('/switches'):
            state['inventory_reads'] += 1
            if not recovers or state['inventory_reads'] < 3:
                reply['current']['switches'][0]['additionalData']['configSyncStatus'] = 'outOfSync'
                assert state['writes'] == []
        return reply

    def sleep(seconds):
        state['now'] += seconds

    result = baseline.InterfaceBaseline(registry, ['fixture'], request, apply=apply,
        poll_seconds=1, clock=lambda: state['now'], sleep=sleep).run()
    assert result['baseline_failed'] is (not recovers)
    assert state['now'] == 2
    if recovers:
        assert not any(row['decision'] == 'SWITCH_READINESS_OR_IDENTITY_UNVERIFIED'
                       for row in result['decisions'])
    else:
        assert state['inventory_reads'] == 3 and state['writes'] == []
        assert result['reason'] == 'SWITCH_READINESS_OR_IDENTITY_UNVERIFIED'


def test_initial_readiness_identity_failure_is_never_retried(baseline):
    registry, request, state = controller_fixture('wrong_identity')
    result = baseline.InterfaceBaseline(registry, ['fixture'], request, apply=True).run()
    assert result['baseline_failed'] is True
    assert sum(path.endswith('/switches') for _, path in state['calls']) == 1
    assert state['writes'] == []


@pytest.mark.parametrize('apply', [False, True])
@pytest.mark.parametrize('field,declared', [('seed_ip', None), ('seed_ip', ''),
                                         ('baseline_role', None), ('baseline_role', '')])
def test_missing_identity_on_both_sides_never_counts_as_verified(baseline, apply, field, declared):
    registry, original, state = controller_fixture()
    registry['lab']['switches']['leaf'][field] = declared
    observed_field = 'fabricManagementIp' if field == 'seed_ip' else 'switchRole'

    def request(method, path, content, timeout):
        reply = original(method, path, content, timeout)
        if path.endswith('/switches'):
            reply['current']['switches'][0][observed_field] = declared
        return reply

    result = baseline.InterfaceBaseline(registry, ['fixture'], request, apply=apply, poll_seconds=0).run()
    assert result['baseline_failed'] is True
    assert result['reason'] == 'SWITCH_READINESS_OR_IDENTITY_UNVERIFIED'
    assert result['decisions'][0]['failed_checks'] == [observed_field]
    assert sum(path.endswith('/switches') for _, path in state['calls']) == 1
    assert state['writes'] == []


def test_initial_sync_retry_does_not_extend_the_shared_deadline(baseline):
    registry, original, state = controller_fixture()

    def request(method, path, content, timeout):
        reply = original(method, path, content, timeout)
        if path.endswith('/switches'):
            reply['current']['switches'][0]['additionalData']['configSyncStatus'] = 'pending'
        return reply

    def sleep(seconds):
        pytest.fail('A retry must not consume the remaining deadline')

    result = baseline.InterfaceBaseline(registry, ['fixture'], request, apply=True,
        timeout_seconds=1, poll_seconds=1, clock=lambda: 0, sleep=sleep).run()
    assert result['reason'] == 'SWITCH_READINESS_OR_IDENTITY_UNVERIFIED'
    assert sum(path.endswith('/switches') for _, path in state['calls']) == 1
    assert state['writes'] == []


def sync_recovery_fixture(baseline, tmp_path, initial=('outOfSync',), after_deploy=('inProgress', 'inSync'),
                          problem=None, transient_saves=0, unconfirmed=None, poll_errors=()):
    registry, original, state = controller_fixture()
    registry['lab']['fabrics'] = {'advanced': {'name': 'fixture', 'type': 'vxlanIbgp', 'lifecycle': 'retained'}}
    state.update(now=0.0, sync=list(initial), saves=0, deploys=[], sync_limits=[], poll_errors=list(poll_errors))

    def request(method, path, content, timeout):
        state['now'] += 0.01
        if path.endswith('/actions/configSave') or path.endswith('/switchActions/deploy'):
            state['calls'].append((method, path))
            state['writes'].append((method, path, copy.deepcopy(content)))
            state['sync_limits'].append(timeout)
        if path.endswith('/actions/configSave'):
            state['saves'] += 1
            if unconfirmed == 'save' and state['saves'] == 1:
                state['now'] += timeout
                raise baseline.RequestUnconfirmed('API_CALL_TIMEOUT')
            if state['saves'] <= transient_saves:
                return {'status': 503, 'failed': True, 'current': {}}
            if problem == 'rejected_save':
                return {'status': 400, 'current': {'message': 'rejected'}}
            state['after_save'] = True
            return {'status': 200, 'current': {'status': 'Config save is completed'}}
        if path.endswith('/switchActions/deploy'):
            state['deploys'].append(copy.deepcopy(content))
            if problem == 'foreign_item':
                return {'status': 207, 'current': {'items': [{'switchId': 'FOREIGN', 'status': 'Success'}]}}
            state['sync'] = ['inProgress', 'outOfSync'] if problem == 'never_converges' else list(after_deploy)
            if unconfirmed == 'deploy' and len(state['deploys']) == 1:
                # ND accepted the deploy; only its reply was lost.
                state['now'] += timeout
                raise baseline.RequestUnconfirmed('API_CALL_TIMEOUT')
            return {'status': 207, 'current': {'items': [{'switchId': serial, 'status': 'Success'}
                                                         for serial in content['switchIds']]}}
        if path.endswith('deploymentFreeze') and problem == 'freeze_after_save' and state.get('after_save'):
            return {'status': 200, 'current': {'deploymentFreeze': True}}
        if path.endswith('/switches') and state['deploys'] and state['poll_errors']:
            state['calls'].append((method, path))
            return {'status': state['poll_errors'].pop(0), 'current': {'message': 'PRIVATE_CANARY'}}
        reply = original(method, path, content, timeout)
        if path.endswith('/switches'):
            if problem == 'vanish_after_save' and state.get('after_save'):
                reply['current']['switches'] = []
                return reply
            node = reply['current']['switches'][0]
            node['additionalData']['configSyncStatus'] = state['sync'][0] if len(state['sync']) == 1 else state['sync'].pop(0)
            if problem == 'wrong_identity':
                node['fabricManagementIp'] = '192.0.2.99'
        return reply

    def sleep(seconds):
        state['now'] += seconds

    def run(apply=False, earlier_gap=False, timeout_seconds=900):
        gate = baseline.InterfaceBaseline(registry, ['fixture'], request, apply=apply, poll_seconds=5,
            clock=lambda: state['now'], sleep=sleep, switch_refs=['leaf'], timeout_seconds=timeout_seconds,
            journal_path=str(tmp_path / 'journal.jsonl'), recover_config_sync=True)
        # Simulates an audit-only readiness gap left by an earlier fabric.
        gate.readiness_incomplete = earlier_gap
        return gate.run()

    return state, run


def sync_writes(state):
    return [path.rsplit('/', 2)[-2] + '/' + path.rsplit('/', 1)[-1] for _, path, _ in state['writes']]


@pytest.mark.parametrize('apply', [False, True])
def test_lifecycle_recovery_recalculates_deploys_drifted_switches_and_reverifies(baseline, tmp_path, apply):
    state, run = sync_recovery_fixture(baseline, tmp_path)
    result = run(apply=apply)
    assert result['baseline_failed'] is False, result['reason']
    assert sync_writes(state)[:2] == ['actions/configSave', 'switchActions/deploy']
    assert state['saves'] == 1 and state['deploys'] == [{'switchIds': ['SERIAL00001']}]
    assert result['changed'] is True and result['verified'] == (1 if apply else 0)
    assert len(state['writes']) == (4 if apply else 2)
    decisions = [row['decision'] for row in result['decisions'] if 'fabric' in row]
    assert decisions == ['SYNC_RECOVERY_DEPLOY_REQUESTED', 'SYNC_RECOVERY_CONFIRMED']
    assert 'SERIAL00001' not in json.dumps(result['decisions'])
    journal = [json.loads(line) for line in (tmp_path / 'journal.jsonl').read_text().splitlines()]
    assert [row['path'].rsplit('/', 1)[-1] for row in journal if row['phase'] == 'request'][:2] == ['configSave', 'deploy']


def test_lifecycle_recovery_still_runs_after_an_earlier_fabric_audit_gap(baseline, tmp_path):
    state, run = sync_recovery_fixture(baseline, tmp_path)
    result = run(earlier_gap=True)
    assert state['saves'] == 1 and state['deploys'] == [{'switchIds': ['SERIAL00001']}]
    assert 'SYNC_RECOVERY_CONFIRMED' in [row['decision'] for row in result['decisions']]
    # The earlier gap still fails the final audit verdict.
    assert result['reason'] == 'SWITCH_READINESS_OR_IDENTITY_UNVERIFIED'


def test_lifecycle_recovery_waits_for_busy_switches_without_redeploying(baseline, tmp_path):
    state, run = sync_recovery_fixture(baseline, tmp_path, initial=('inProgress', 'deploymentInProgress', 'inSync'))
    result = run()
    assert result['baseline_failed'] is False and state['writes'] == []
    assert not any(row['decision'].startswith('SYNC_RECOVERY') for row in result['decisions'])


def test_lifecycle_recovery_never_overlaps_a_stuck_deployment(baseline, tmp_path):
    state, run = sync_recovery_fixture(baseline, tmp_path, initial=('inProgress',))
    result = run()
    assert result['reason'] == 'FABRIC_SYNC_IN_PROGRESS_TIMEOUT' and state['writes'] == []
    assert 410 <= state['now'] <= 425


def test_lifecycle_recovery_retries_transient_rejection_after_settling(baseline, tmp_path):
    state, run = sync_recovery_fixture(baseline, tmp_path, transient_saves=1)
    result = run()
    assert result['baseline_failed'] is False, result['reason']
    assert state['saves'] == 2 and len(state['deploys']) == 1
    assert [row['decision'] for row in result['decisions'] if 'fabric' in row] == [
        'SYNC_RECOVERY_TRANSIENT_REJECTION', 'SYNC_RECOVERY_DEPLOY_REQUESTED', 'SYNC_RECOVERY_CONFIRMED']


@pytest.mark.parametrize('errors,reason,retries', [
    ((503, 503), 'AUDIT_COMPLETE', 2),
    ((503, 503, 503), 'API_REQUEST_REJECTED', 2),
    ((401,), 'API_REQUEST_REJECTED', 0),
])
def test_sync_poll_errors_never_repeat_an_accepted_deploy(baseline, tmp_path, errors, reason, retries):
    state, run = sync_recovery_fixture(baseline, tmp_path, poll_errors=errors)
    result = run()
    assert result['reason'] == reason
    assert result['baseline_failed'] is (reason != 'AUDIT_COMPLETE')
    assert state['saves'] == 1 and len(state['deploys']) == 1
    assert sum(row['decision'] == 'SYNC_POLL_TRANSIENT_REJECTION' for row in result['decisions']) == retries
    if result['baseline_failed']:
        assert result['api_failure'] == {
            'method': 'get', 'operation': '/api/v1/manage/fabrics/{id}/switches', 'http_status': errors[-1]}
    else:
        assert result['api_failure'] is None
    assert 'PRIVATE_CANARY' not in json.dumps(result)


@pytest.mark.parametrize('unconfirmed,saves,decisions', [
    ('save', 2, ['SYNC_RECOVERY_TRANSIENT_REJECTION', 'SYNC_RECOVERY_DEPLOY_REQUESTED', 'SYNC_RECOVERY_CONFIRMED']),
    ('deploy', 1, ['SYNC_RECOVERY_TRANSIENT_REJECTION', 'SYNC_RECOVERY_CONFIRMED']),
])
def test_lifecycle_recovery_gives_sync_actions_time_and_never_redeploys_an_unconfirmed_deploy(
        baseline, tmp_path, unconfirmed, saves, decisions):
    state, run = sync_recovery_fixture(baseline, tmp_path, unconfirmed=unconfirmed)
    result = run()
    assert result['baseline_failed'] is False, result['reason']
    assert state['saves'] == saves and len(state['deploys']) == 1
    assert state['sync_limits'] and set(state['sync_limits']) == {180}
    rows = [row for row in result['decisions'] if 'fabric' in row]
    assert [row['decision'] for row in rows] == decisions and rows[0]['reason'] == 'API_CALL_TIMEOUT'
    journal = [json.loads(line) for line in (tmp_path / 'journal.jsonl').read_text().splitlines()]
    assert [row['phase'] for row in journal].count('response_unconfirmed') == 1


def test_lifecycle_recovery_reports_deadline_when_an_unconfirmed_call_used_the_remaining_time(baseline, tmp_path):
    state, run = sync_recovery_fixture(baseline, tmp_path, unconfirmed='save')
    result = run(timeout_seconds=120)
    assert result['reason'] == 'DEADLINE_EXCEEDED'
    assert state['saves'] == 1 and state['deploys'] == [] and state['sync_limits'][0] < 120


@pytest.mark.parametrize('value', [0, -1, float('inf'), float('nan'), 601])
def test_sync_action_timeout_must_be_finite_and_bounded(baseline, tmp_path, value):
    registry, request, state = controller_fixture()
    with pytest.raises(ValueError, match='sync recovery window'):
        baseline.InterfaceBaseline(registry, ['fixture'], request, sync_call_timeout_seconds=value)
    assert state['calls'] == []


def test_lifecycle_recovery_is_bounded_and_skips_interface_cleanup_when_drift_persists(baseline, tmp_path):
    state, run = sync_recovery_fixture(baseline, tmp_path, problem='never_converges')
    result = run(apply=True)
    assert result['reason'] == 'FABRIC_SYNC_RECOVERY_NOT_CONVERGED'
    assert state['saves'] == 3 and len(state['deploys']) == 3
    assert set(sync_writes(state)) == {'actions/configSave', 'switchActions/deploy'}
    assert result['decisions'][-1] == {'fabric': 'fixture', 'decision': 'SYNC_RECOVERY_NOT_CONVERGED',
                                       'attempts': 3, 'switches': {'leaf': 'outOfSync'}}


@pytest.mark.parametrize('problem,reason,saves,deploys', [
    ('wrong_identity', 'SWITCH_READINESS_OR_IDENTITY_UNVERIFIED', 0, 0),
    ('rejected_save', 'API_REQUEST_REJECTED', 1, 0),
    ('freeze_after_save', 'DEPLOYMENT_FREEZE_OR_UNVERIFIED', 1, 0),
    ('vanish_after_save', 'FABRIC_SYNC_ROSTER_CHANGED', 1, 0),
    ('foreign_item', 'SYNC_ACTION_RESPONSE_UNVERIFIED', 1, 1),
])
def test_lifecycle_recovery_fails_closed_without_retrying_unsafe_states(baseline, tmp_path, problem, reason, saves, deploys):
    state, run = sync_recovery_fixture(baseline, tmp_path, problem=problem)
    result = run()
    assert result['baseline_failed'] is True and result['reason'] == reason
    assert state['saves'] == saves and len(state['deploys']) == deploys


@pytest.mark.parametrize('change', ['foreign_fabric', 'no_journal', 'no_switch_scope'])
def test_lifecycle_recovery_requires_owned_fabrics_explicit_switches_and_checkpoint(baseline, tmp_path, change):
    registry, request, _ = controller_fixture()
    registry['lab']['fabrics'] = {'advanced': {'name': 'fixture', 'lifecycle': 'retained'}}
    arguments = {'switch_refs': ['leaf'], 'journal_path': str(tmp_path / 'journal.jsonl'), 'recover_config_sync': True}
    if change == 'foreign_fabric':
        registry['lab']['fabrics']['advanced']['name'] = 'other'
    else:
        arguments.pop('journal_path' if change == 'no_journal' else 'switch_refs')
    with pytest.raises(ValueError, match='retained lab scope'):
        baseline.InterfaceBaseline(registry, ['fixture'], request, **arguments)


def test_explicit_interface_scope_touches_only_the_selected_unused_port(baseline):
    registry, request, state = controller_fixture()
    result = baseline.InterfaceBaseline(registry, ['fixture'], request, apply=True,
        switch_refs=['leaf'], interfaces=['ethernet1/63'], poll_seconds=0).run()
    assert result['baseline_failed'] is False and result['verified'] == 1
    assert result['inspected'] == 1
    assert all(row['interface'] == 'Ethernet1/63' for row in result['decisions'])
    assert len(state['writes']) == 2
    assert state['writes'][0][2]['interfaceName'] == 'Ethernet1/63'
    assert state['writes'][1][2] == {'interfaces': [{'switchId': 'SERIAL00001', 'interfaceName': 'Ethernet1/63'}]}


def test_explicit_lab_switch_and_ports_do_not_require_unrelated_test_reservations(baseline):
    registry, request, state = controller_fixture()
    registry['lab']['interface_allowlist']['leaf'] = []
    result = baseline.InterfaceBaseline(registry, ['fixture'], request, apply=True,
        switch_refs=['leaf'], interfaces=['Ethernet1/63'], poll_seconds=0).run()
    assert result['baseline_failed'] is False and result['verified'] == 1
    assert len(state['writes']) == 2


@pytest.mark.parametrize('switches,interfaces', [
    (['foreign'], ['Ethernet1/63']), ([], ['Ethernet1/63']),
    (['leaf', 'leaf'], ['Ethernet1/63']), (['leaf'], []),
    (['leaf'], ['Ethernet1/63', 'Eth1/63']), (['leaf'], ['Ethernet1/63;shutdown']),
    (None, ['Ethernet1/63']), ([{}], ['Ethernet1/63']),
])
def test_invalid_explicit_scope_is_rejected_before_controller_calls(baseline, switches, interfaces):
    registry, request, state = controller_fixture()
    with pytest.raises(ValueError):
        baseline.InterfaceBaseline(registry, ['fixture'], request, apply=True,
                                   switch_refs=switches, interfaces=interfaces)
    assert state['calls'] == []


def test_missing_selected_interface_is_not_a_successful_noop(baseline):
    registry, request, state = controller_fixture()
    result = baseline.InterfaceBaseline(registry, ['fixture'], request, apply=True,
        switch_refs=['leaf'], interfaces=['Ethernet1/58']).run()
    assert result['baseline_failed'] is True and result['reason'] == 'INTERFACE_SCOPE_INCOMPLETE'
    assert state['writes'] == []


def test_missing_selected_switch_is_not_a_successful_noop(baseline):
    registry, request, state = controller_fixture()
    registry['lab']['switches']['missing'] = {'serial': 'SERIAL00002', 'seed_ip': '192.0.2.20', 'baseline_role': 'leaf'}
    registry['lab']['interface_allowlist']['missing'] = []
    result = baseline.InterfaceBaseline(registry, ['fixture'], request, apply=True,
        switch_refs=['missing'], interfaces=['Ethernet1/63']).run()
    assert result['baseline_failed'] is True and result['reason'] == 'SWITCH_SCOPE_INCOMPLETE'
    assert state['writes'] == []


def test_apply_checkpoints_before_images_and_each_api_response_privately(baseline, tmp_path, monkeypatch):
    registry, request, state = controller_fixture()
    monkeypatch.setenv('NDFC_PASSWORD', 'PASSWORD_CANARY')

    def token_response(method, path, content, timeout):
        result = request(method, path, content, timeout)
        if method != 'get':
            result['current']['token'] = 'TOKEN_CANARY'
            result['current']['note'] = 'PASSWORD_CANARY'
            result['invocation'] = {'module_args': {'password': 'UNBOUND_CANARY'}}
        return result

    journal = tmp_path / 'checkpoint.jsonl'
    result = baseline.InterfaceBaseline(registry, ['fixture'], token_response, apply=True,
        switch_refs=['leaf'], interfaces=['Ethernet1/63'], journal_path=str(journal), poll_seconds=0).run()
    assert result['baseline_failed'] is False
    entries = [json.loads(line) for line in journal.read_text().splitlines()]
    assert [entry['phase'] for entry in entries] == ['before_change', 'request', 'response', 'request', 'response']
    assert entries[0]['before']['configData']['networkOS']['policy']['adminState'] is True
    assert entries[1]['content']['configData']['networkOS']['policy']['adminState'] is False
    assert 'CANARY' not in journal.read_text() and 'invocation' not in journal.read_text()
    assert journal.stat().st_mode & 0o777 == 0o600


def test_checkpoint_failure_after_put_prevents_deploy_or_another_write(baseline, tmp_path):
    registry, request, state = controller_fixture()
    gate = baseline.InterfaceBaseline(registry, ['fixture'], request, apply=True,
        switch_refs=['leaf'], interfaces=['Ethernet1/63'], journal_path=str(tmp_path / 'checkpoint.jsonl'), poll_seconds=0)
    checkpoint = gate.checkpoint

    def fail_response(value):
        if value['phase'] == 'response':
            raise baseline.BaselineBlocked('CHECKPOINT_UNVERIFIED')
        checkpoint(value)

    gate.checkpoint = fail_response
    result = gate.run()
    assert result['baseline_failed'] is True and result['reason'] == 'CHECKPOINT_UNVERIFIED'
    assert result['changed'] is True
    assert len(state['writes']) == 1 and state['writes'][0][0] == 'put'


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


@pytest.mark.parametrize("active", [False, True])
def test_live_nd_structured_switch_identity_without_serial_in_alert_text(baseline, active):
    registry, request, state = controller_fixture("active_warning" if active else None)

    def live_schema(method, path, content, timeout):
        reply = request(method, path, content, timeout)
        if "anomalies/details" in path:
            warning = reply["current"]["anomalies"][0]
            warning.update(switchId="SERIAL00001", entityName="ethernet1/63",
                           mnemonicTitle="CONNECTIVITY_INTERFACE_STATUS", fabricName="fixture")
            warning["anomalyString"] = "Interface ethernet1/63 in undesired state up:down:Link not connected"
            reply["current"]["meta"] = {"counts": {"total": 1, "remaining": 0}, "links": {}}
        return reply

    ticks = [0]

    def clock():
        ticks[0] += 1
        return ticks[0]

    result = baseline.InterfaceBaseline(registry, ["fixture"], live_schema, apply=True,
        clock=clock, sleep=lambda seconds: None, timeout_seconds=200, poll_seconds=0).run()
    assert result["baseline_failed"] is active
    assert result["verified"] == (0 if active else 1)
    if not active:
        assert result["remaining_connectivity_alerts"] == 0
        assert result["connectivity_verified_fabrics"] == ["fixture"]
    else:
        assert result["remaining_connectivity_alerts"] is None


def test_a_remaining_alert_on_another_port_prevents_a_clean_fabric_claim(baseline):
    registry, request, state = controller_fixture()

    def other_active_port(method, path, content, timeout):
        reply = request(method, path, content, timeout)
        if "anomalies/details" in path:
            reply["current"]["anomalies"].append({
                "cleared": False, "switchId": "SERIAL00001", "entityName": "ethernet1/58",
                "mnemonicTitle": "CONNECTIVITY_INTERFACE_STATUS",
                "anomalyString": "Interface ethernet1/58 in undesired state up:down:Link not connected"})
        return reply

    result = baseline.InterfaceBaseline(registry, ["fixture"], other_active_port, apply=True,
        switch_refs=["leaf"], interfaces=["Ethernet1/63"], poll_seconds=0).run()
    assert result["baseline_failed"] is True
    assert result["reason"] == "CONNECTIVITY_INTERFACE_STATUS_ACTIVE"
    assert result["verified"] == 1 and result["remaining_connectivity_alerts"] == 1
    assert result["connectivity_alerts"] == [{
        "fabric": "fixture", "switch": "leaf", "interface": "Ethernet1/58",
        "baseline_decision": "OUT_OF_SCOPE",
    }]
    assert len(state["writes"]) == 2
    assert result["decisions"][-1] == {
        "fabric": "fixture", "decision": "CONNECTIVITY_INTERFACE_STATUS_ACTIVE", "remaining_alerts": 1}


def test_unmapped_connectivity_alert_identity_is_sanitized(baseline):
    registry, request, state = controller_fixture()

    def unknown_switch_warning(method, path, content, timeout):
        reply = request(method, path, content, timeout)
        if "anomalies/details" in path:
            row = reply["current"]["anomalies"][0]
            row.update(
                cleared=False,
                switchId="PRIVATE_SERIAL",
                entityName="eth1/58",
                anomalyString="Interface ethernet1/58 in undesired state up:down:Link not connected",
            )
        return reply

    result = baseline.InterfaceBaseline(registry, ["fixture"], unknown_switch_warning,
        apply=True, switch_refs=["leaf"], interfaces=["Ethernet1/63"], poll_seconds=0).run()
    assert result["reason"] == "CONNECTIVITY_INTERFACE_STATUS_ACTIVE"
    assert result["connectivity_alerts"] == [{
        "fabric": "fixture", "switch": "unmapped", "interface": "Ethernet1/58",
        "baseline_decision": "OUT_OF_SCOPE",
    }]
    assert "PRIVATE_SERIAL" not in json.dumps(result)


@pytest.mark.parametrize("counts", [
    {"total": 3, "remaining": 1}, {"total": 3, "remaining": 0},
    {"total": "2", "remaining": 0}, {"total": 2, "remaining": False},
])
def test_nd_metadata_cannot_hide_an_incomplete_interface_inventory(baseline, counts):
    registry, request, state = controller_fixture()

    def incomplete_inventory(method, path, content, timeout):
        reply = request(method, path, content, timeout)
        if path.endswith("/interfaces"):
            reply["current"]["meta"] = {"counts": counts, "links": {}}
        return reply

    result = baseline.InterfaceBaseline(registry, ["fixture"], incomplete_inventory, apply=True).run()
    assert result["baseline_failed"] is True and result["reason"] == "INVENTORY_INCOMPLETE"
    assert state["writes"] == []


@pytest.mark.parametrize("problem", ["ambiguous_switch", "ambiguous_port", "wrong_fabric", "untyped_cleared"])
def test_ambiguous_live_anomaly_evidence_never_verifies_deployment(baseline, problem):
    registry, request, state = controller_fixture("active_warning")

    def ambiguous_warning(method, path, content, timeout):
        reply = request(method, path, content, timeout)
        if "anomalies/details" in path:
            row = reply["current"]["anomalies"][0]
            row.update(switchId="SERIAL00001", entityName="ethernet1/63", fabricName="fixture")
            if problem == "ambiguous_switch":
                row["switchId"] = "FOREIGN"
            elif problem == "ambiguous_port":
                row["entityName"] = "ethernet1/58"
            elif problem == "wrong_fabric":
                row["fabricName"] = "foreign"
            else:
                row["cleared"] = "false"
        return reply

    result = baseline.InterfaceBaseline(registry, ["fixture"], ambiguous_warning, apply=True).run()
    assert result["baseline_failed"] is True and result["verified"] == 0
    assert result["remaining_connectivity_alerts"] is None


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


def test_check_mode_adapter_never_recalculates_or_deploys_drifted_switches(baseline, monkeypatch, tmp_path):
    from types import SimpleNamespace

    registry, request, state = controller_fixture()
    registry['lab']['fabrics'] = {'advanced': {'name': 'fixture', 'type': 'vxlanIbgp', 'lifecycle': 'retained'}}

    def drifted(method, path, content, timeout):
        reply = request(method, path, content, timeout)
        if path.endswith('/switches'):
            reply['current']['switches'][0]['additionalData']['configSyncStatus'] = 'outOfSync'
        return reply

    monkeypatch.setattr(baseline.ActionBase, 'run', lambda *args, **kwargs: {})
    action = baseline.ActionModule.__new__(baseline.ActionModule)
    action._task = SimpleNamespace(args={'registry': registry, 'fabrics': ['fixture'], 'switch_refs': ['leaf'],
        'journal_path': str(tmp_path / 'journal.jsonl'), 'recover_config_sync': True, 'poll_seconds': 0},
        no_log=False, check_mode=True)
    action._templar = SimpleNamespace(template=lambda value: value)
    action._connection = SimpleNamespace(_socket_path=None)
    action._execute_module = lambda module_name, module_args, task_vars: drifted(
        module_args['method'], module_args['path'], module_args.get('content'), 30)
    result = action.run(task_vars={})
    assert result['reason'] == 'SWITCH_READINESS_OR_IDENTITY_UNVERIFIED' and state['writes'] == []


@pytest.mark.parametrize('failure, reason', [
    ('command timeout triggered, timeout value is 179 secs.', 'API_CALL_TIMEOUT'),
    ('Connection reset by peer', 'API_TRANSPORT_UNVERIFIED'),
    ('client_alarm', 'API_CALL_TIMEOUT'),
], ids=['daemon_timeout', 'transport', 'client_alarm'])
def test_adapter_retries_an_unconfirmed_sync_action_with_its_own_time_budget(
        baseline, monkeypatch, tmp_path, failure, reason):
    # Build 198: a slow configSave left no HTTP status and blocked the baseline.
    import time
    from types import SimpleNamespace
    from ansible.module_utils.connection import ConnectionError as DaemonError

    registry, request, state = controller_fixture()
    registry['lab']['fabrics'] = {'advanced': {'name': 'fixture', 'type': 'vxlanIbgp', 'lifecycle': 'retained'}}
    state.update(sync='outOfSync', sends=[])
    limit = 1 if failure == 'client_alarm' else 180

    def get(module_name, module_args, task_vars):
        assert module_args['method'] == 'get'
        reply = request('get', module_args['path'], None, 30)
        if module_args['path'].endswith('/switches'):
            reply['current']['switches'][0]['additionalData']['configSyncStatus'] = state['sync']
        return reply

    class RPC:
        def __init__(self, *args):
            self.timeout = 30

        def get_option(self, name):
            return self.timeout

        def set_option(self, name, value):
            self.timeout = value

        def send_request(self, method, path, data):
            assert action._task.no_log is True
            name = path.rsplit('/', 1)[-1]
            state['sends'].append((name, self.timeout))
            if name == 'configSave' and len(state['sends']) == 1:
                if failure == 'client_alarm':
                    time.sleep(5)
                raise DaemonError(failure)
            if name == 'deploy':
                state['sync'] = 'inSync'
                return {'status': 207, 'body': {'items': [{'switchId': serial, 'status': 'Success'}
                                                          for serial in json.loads(data)['switchIds']]}}
            return {'status': 200, 'body': {'status': 'Config save is completed'}}

    monkeypatch.setattr(baseline.ActionBase, 'run', lambda *args, **kwargs: {})
    monkeypatch.setattr(baseline, 'Connection', RPC)
    action = baseline.ActionModule.__new__(baseline.ActionModule)
    action._task = SimpleNamespace(args={'registry': registry, 'fabrics': ['fixture'], 'switch_refs': ['leaf'],
        'journal_path': str(tmp_path / 'journal.jsonl'), 'recover_config_sync': True, 'poll_seconds': 0,
        'sync_settle_seconds': 0, 'sync_call_timeout_seconds': limit}, no_log=False, check_mode=False)
    action._templar = SimpleNamespace(template=lambda value: value)
    action._connection = RPC()
    action._connection._socket_path = 'fixture-socket'
    action._execute_module = get
    result = action.run(task_vars={})
    assert result['failed'] is False, result['reason']
    assert [name for name, _ in state['sends']] == ['configSave', 'configSave', 'deploy']
    assert all(limit - 1 <= timeout <= limit for _, timeout in state['sends'])
    rows = [row for row in result['decisions'] if 'fabric' in row]
    assert rows[0]['decision'] == 'SYNC_RECOVERY_TRANSIENT_REJECTION' and rows[0]['reason'] == reason
    assert rows[-1]['decision'] == 'SYNC_RECOVERY_CONFIRMED'
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
if endpoint.endswith('switchActions/deploy'):
    state['sync'] = 'inSync'
if method != 'get':
    body = {'results':[{'switchId':'SERIAL00001','interfaceName':'Ethernet1/63','status':'success'}]}
elif endpoint == '/api/v1/manage/fabrics/fixture':
    body = {'name':'fixture','category':'fabric','management':{'type':'vxlanIbgp','hostInterfaceAdminState':False}}
elif endpoint.endswith('/switches'):
    body = {'switches':[{'switchId':'SERIAL00001','fabricManagementIp':'192.0.2.10','switchRole':'leaf','additionalData':{
        'systemMode':state.get('mode','normal'),'intendedSystemMode':'normal','discoveredSystemMode':'normal',
        'configSyncStatus':state.get('sync','inSync')}}]}
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
    registry['lab']['fabrics']={'advanced':{'name':'fixture','type':'vxlanIbgp','lifecycle':'retained'}}
    registry['lab']['switches']['leaf']['baseline_fabric_ref']='advanced'
    registry['profiles']={'integration.fixture':{'resources':[{'kind':'verify_logical_interface_namespace',
        'switch_ref':'leaf','interface_type':'port_channel','interfaces':['Port-channel520']}]}}
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
    assert ("NDP_RESERVED_MEMBERS_FREE switch=leaf" in completed.stdout) is (membership_apply and apply and not check_mode)
    assert ("NDP_INTERFACE_BASELINE_BLOCKED_CONTINUING" in completed.stdout) is frozen
    assert "192.0.2.10" not in completed.stdout and "SERIAL00001" not in completed.stdout



@pytest.mark.parametrize("problem,apply,advisory,passes", [
    ("outOfSync", False, True, True), ("outOfSync", False, False, False),
    ("outOfSync", True, True, False), ("maintenance", False, True, False)])
def test_post_recovery_audit_sync_gap_is_advisory_only(tmp_path, problem, apply, advisory, passes):
    registry, _, state = controller_fixture()
    registry['lab']['fabrics'] = {'advanced': {'name': 'fixture', 'type': 'vxlanIbgp', 'lifecycle': 'retained'}}
    registry['lab']['switches']['leaf']['baseline_fabric_ref'] = 'advanced'
    state['sync' if problem == 'outOfSync' else 'mode'] = problem
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
                 "nd_switch_apply": apply, "nd_interface_baseline_poll_seconds": 0,
                 "nd_interface_baseline_audit_advisory": advisory,
                 # Classification only; sync recovery has its own helper test.
                 "nd_interface_baseline_recover_config_sync": False},
        "tasks": [{"ansible.builtin.include_tasks": str(helper)}]}]))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n")
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_COLLECTIONS_PATH=str(tmp_path / "collections"),
        ANSIBLE_COLLECTIONS_SCAN_SYS_PATH="False", ANSIBLE_ACTION_PLUGINS=str(PLUGIN.parent),
        ANSIBLE_STDOUT_CALLBACK="default", ANSIBLE_NOCOLOR="1", BASELINE_FAKE_LEDGER=str(ledger),
        ANSIBLE_LOCAL_TEMP=str(tmp_path / "local"), ANSIBLE_REMOTE_TEMP=str(tmp_path / "remote"),
        OBJC_DISABLE_INITIALIZE_FORK_SAFETY="YES")
    command = [str(Path(sys.executable).with_name("ansible-playbook")), "-i", "localhost,", str(playbook)]
    completed = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=60)
    output = completed.stdout + completed.stderr
    assert (completed.returncode == 0) is passes, output
    assert "reason=SWITCH_READINESS_OR_IDENTITY_UNVERIFIED" in output
    assert ("NDP_INTERFACE_BASELINE_ADVISORY" in output) is passes
    assert ("NDP_INTERFACE_BASELINE_BLOCKED" in output) is (not passes)
    assert "NDP_INTERFACE_BASELINE_BLOCKED_CONTINUING" not in output
    assert [row for row in json.loads(ledger.read_text())["calls"] if row[0] != "get"] == []

@pytest.mark.parametrize("switch_apply,knob,recovered", [(True, None, True), (True, "false", False), (False, None, False)])
def test_lifecycle_helper_recovers_config_sync_unless_disabled(tmp_path, switch_apply, knob, recovered):
    registry, _, state = controller_fixture()
    registry['lab']['fabrics'] = {'advanced': {'name': 'fixture', 'type': 'vxlanIbgp', 'lifecycle': 'retained'}}
    registry['lab']['switches']['leaf']['baseline_fabric_ref'] = 'advanced'
    state['sync'] = 'outOfSync'
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
                 "nd_test_fabric_switches": {"fixture": []}, "nd_switch_apply": switch_apply,
                 "nd_interface_baseline_apply": False,
                 "nd_interface_baseline_poll_seconds": 0},
        "tasks": [{"ansible.builtin.include_tasks": str(helper)}]}]))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n")
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_COLLECTIONS_PATH=str(tmp_path / "collections"),
        ANSIBLE_COLLECTIONS_SCAN_SYS_PATH="False", ANSIBLE_ACTION_PLUGINS=str(PLUGIN.parent),
        ANSIBLE_STDOUT_CALLBACK="default", ANSIBLE_NOCOLOR="1", BASELINE_FAKE_LEDGER=str(ledger),
        ANSIBLE_LOCAL_TEMP=str(tmp_path / "local"), ANSIBLE_REMOTE_TEMP=str(tmp_path / "remote"),
        OBJC_DISABLE_INITIALIZE_FORK_SAFETY="YES")
    environment.pop("ND_INTERFACE_BASELINE_APPLY", None)
    environment.pop("ND_INTERFACE_BASELINE_RECOVER_SYNC", None)
    if knob is not None:
        environment["ND_INTERFACE_BASELINE_RECOVER_SYNC"] = knob
    command = [str(Path(sys.executable).with_name("ansible-playbook")), "-i", "localhost,", str(playbook)]
    completed = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=60)
    output = completed.stdout + completed.stderr
    writes = [path.rsplit("/", 2)[-2] + "/" + path.rsplit("/", 1)[-1]
              for method, path in json.loads(ledger.read_text())["calls"] if method != "get"]
    assert writes == (["actions/configSave", "switchActions/deploy"] if recovered else []), output
    assert ("reason=AUDIT_COMPLETE" in output) is recovered
    assert ("reason=SWITCH_READINESS_OR_IDENTITY_UNVERIFIED" in output) is (not recovered)
    assert (completed.returncode == 0) is recovered, output
    assert "192.0.2.10" not in completed.stdout and "SERIAL00001" not in completed.stdout


def test_registry_loader_reports_sanitized_parse_failure(tmp_path):
    registry_path = tmp_path / "private-registry.yaml"
    registry_path.write_text("registry_secret_marker: [unterminated\n")
    helper = PLUGIN.parent.parent / "nd_prerequisite/interface_baseline.yaml"
    playbook = tmp_path / "play.yaml"
    playbook.write_text(json.dumps([{"hosts": "localhost", "connection": "local", "gather_facts": False,
        "vars": {"ansible_python_interpreter": sys.executable,
                 "nd_interface_baseline_registry_file": str(registry_path)},
        "tasks": [{"ansible.builtin.include_tasks": str(helper)}]}]))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n")
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_COLLECTIONS_PATH=str(tmp_path / "collections"),
        ANSIBLE_COLLECTIONS_SCAN_SYS_PATH="False", ANSIBLE_ACTION_PLUGINS=str(PLUGIN.parent),
        ANSIBLE_STDOUT_CALLBACK="default", ANSIBLE_NOCOLOR="1",
        ANSIBLE_LOCAL_TEMP=str(tmp_path / "local"), ANSIBLE_REMOTE_TEMP=str(tmp_path / "remote"),
        OBJC_DISABLE_INITIALIZE_FORK_SAFETY="YES")
    command = [str(Path(sys.executable).with_name("ansible-playbook")), "-i", "localhost,", str(playbook)]
    completed = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=60)
    output = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "NDP_INTERFACE_REGISTRY_LOAD_FAILED: category=REGISTRY_CONTENT_PARSE_FAILED" in output
    assert "registry_secret_marker" not in output
    assert str(registry_path) not in output


@pytest.mark.parametrize("apply,check_mode,writes", [(False, False, 0), (True, False, 2), (True, True, 0)])
def test_isolated_cleanup_playbook_runs_without_membership_or_blanket_enable(tmp_path, apply, check_mode, writes):
    registry, _, state = controller_fixture()
    registry["lab"]["fabrics"] = {"advanced": {"name": "fixture"},
        "network_ebgp": {"name": "ebgp_fixture"}, "external": {"name": "external_fixture"}}
    registry_path = tmp_path / "registry.json"
    registry_path.write_text(json.dumps(registry))
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps(state))
    modules = tmp_path / "collections/ansible_collections/cisco/nd/plugins/modules"
    modules.mkdir(parents=True)
    (modules / "nd_rest.py").write_text(FAKE_REST)
    variables = tmp_path / "variables.json"
    variables.write_text(json.dumps({"ansible_python_interpreter": sys.executable,
        "nd_cleanup_registry_file": str(registry_path), "nd_cleanup_fabric": "fixture",
        "nd_cleanup_switch_refs": ["leaf"], "nd_cleanup_interfaces": ["Ethernet1/63"],
        "nd_cleanup_apply": apply, "nd_cleanup_poll_seconds": 0}))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n")
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_COLLECTIONS_PATH=str(tmp_path / "collections"),
        ANSIBLE_COLLECTIONS_SCAN_SYS_PATH="False", ANSIBLE_ACTION_PLUGINS=str(PLUGIN.parent),
        ANSIBLE_STDOUT_CALLBACK="default", ANSIBLE_NOCOLOR="1", BASELINE_FAKE_LEDGER=str(ledger),
        ANSIBLE_LOCAL_TEMP=str(tmp_path / "local"), ANSIBLE_REMOTE_TEMP=str(tmp_path / "remote"),
        OBJC_DISABLE_INITIALIZE_FORK_SAFETY="YES", TMPDIR=str(tmp_path))
    playbook = PLUGIN.parent.parent / "nd_interface_baseline_scoped.yaml"
    command = [str(Path(sys.executable).with_name("ansible-playbook")), "-i", "nd,", "-c", "local",
               str(playbook), "-e", "@" + str(variables)]
    if check_mode:
        command.append("--check")
    completed = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=60)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    captured = json.loads(ledger.read_text())
    assert len([row for row in captured["calls"] if row[0] != "get"]) == writes
    assert not any("/actions/" in path or "discover" in path for _, path in captured["calls"])
    assert "remaining_connectivity=0" in completed.stdout if writes else "remaining_connectivity=UNVERIFIED" in completed.stdout
    assert "192.0.2.10" not in completed.stdout and "SERIAL00001" not in completed.stdout


FAKE_BRINGUP_REST = r'''
import json, os
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule
module = AnsibleModule(argument_spec={'method':{'type':'str'},'path':{'type':'str'},'content':{'type':'raw'}}, supports_check_mode=True)
ledger = Path(os.environ['BASELINE_FAKE_LEDGER'])
state = json.loads(ledger.read_text())
method, endpoint, content = module.params['method'], module.params['path'], module.params['content']
state['calls'].append([method, endpoint, content])
if method == 'get':
    body = state['detail']
elif method == 'put':
    state['detail']['configData'] = content['configData']
    body = {}
else:
    state['detail']['operData']['adminStatus'] = 'up'
    body = {}
ledger.write_text(json.dumps(state))
module.exit_json(changed=method != 'get',status=200,current=body)
'''


@pytest.mark.parametrize('variant', ['Jenkinsfile_nd_jenkins_script', 'Jenkinsfile_nd_jenkins_script_temp_switches',
                                   'Jenkinsfile_nd_jenkins_script_comm_list'])
def test_generated_peerlink_preparation_executes_with_the_registry(tmp_path, variant):
    root = PLUGIN.parents[2]
    source = (root / variant).read_text()
    probe = json.loads(source.split("<<'PEERLINK_PROBE_EOF'", 1)[1].split('PEERLINK_PROBE_EOF', 1)[0])
    probe[0]['tasks'] = probe[0]['tasks'][:2]
    probe[0]['tasks'][1]['loop'] = probe[0]['tasks'][1]['loop'][:1]
    registry, _, state = controller_fixture()
    registry['lab']['interface_allowlist']['leaf'] = ['Ethernet1/2']
    state['detail']['interfaceName'] = 'Ethernet1/2'
    state['detail']['configData']['networkOS']['policy']['adminState'] = False
    (tmp_path / 'nd_prerequisite_profiles.yaml').write_text(json.dumps(registry))
    helper = tmp_path / 'nd_prerequisite'
    helper.mkdir()
    (helper / 'admin_up_interface.yaml').write_bytes((PLUGIN.parent.parent / 'nd_prerequisite/admin_up_interface.yaml').read_bytes())
    ledger = tmp_path / 'ledger.json'
    ledger.write_text(json.dumps(state))
    modules = tmp_path / 'collections/ansible_collections/cisco/nd/plugins/modules'
    modules.mkdir(parents=True)
    (modules / 'nd_rest.py').write_text(FAKE_BRINGUP_REST)
    playbook = tmp_path / 'probe.json'
    playbook.write_text(json.dumps(probe))
    variables = tmp_path / 'vars.json'
    variables.write_text(json.dumps({'ansible_python_interpreter': sys.executable,
        'probe_prepare_peerlink': True, 'probe_fabric': 'fixture', 'probe_s1': 'SERIAL00001'}))
    config = tmp_path / 'ansible.cfg'
    config.write_text('[defaults]\n')
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_COLLECTIONS_PATH=str(tmp_path / 'collections'),
        ANSIBLE_COLLECTIONS_SCAN_SYS_PATH='False', ANSIBLE_STDOUT_CALLBACK='default', ANSIBLE_NOCOLOR='1',
        BASELINE_FAKE_LEDGER=str(ledger), ANSIBLE_LOCAL_TEMP=str(tmp_path / 'local'),
        ANSIBLE_REMOTE_TEMP=str(tmp_path / 'remote'), OBJC_DISABLE_INITIALIZE_FORK_SAFETY='YES', TMPDIR=str(tmp_path))
    completed = subprocess.run([str(Path(sys.executable).with_name('ansible-playbook')),
        '-i', 'nd_controller,', '-c', 'local', str(playbook), '-e', '@' + str(variables)],
        env=environment, text=True, capture_output=True, timeout=60)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    captured = json.loads(ledger.read_text())
    assert [method for method, _, _ in captured['calls'] if method != 'get'] == ['put', 'post']
    assert captured['detail']['configData']['networkOS']['policy']['adminState'] is True
    assert 'SERIAL00001' not in completed.stdout


@pytest.mark.parametrize("scope,apply,success,expected_writes", [
    ({}, True, False, 0), ({}, False, True, 0),
    ({"leaf": ["Ethernet1/63"]}, True, True, 2),
    ({"leaf": ["Ethernet1/58"]}, True, False, 0),
    ({"foreign": ["Ethernet1/63"]}, True, False, 0),
])
def test_legacy_bringup_requires_used_ports_instead_of_enabling_the_ownership_pool(tmp_path, scope, apply, success, expected_writes):
    registry, _, state = controller_fixture()
    registry["lab"]["switches"]["leaf"]["baseline_fabric_ref"] = "advanced"
    registry["lab"]["fabrics"] = {"advanced": {"name": "fixture"}}
    registry["lab"]["interface_allowlist"]["leaf"] = ["Ethernet1/1", "Ethernet1/63"]
    state["detail"]["configData"]["networkOS"]["policy"]["adminState"] = False
    expected = copy.deepcopy(state["detail"]["configData"])
    expected["networkOS"]["policy"]["adminState"] = True
    registry_path = tmp_path / "registry.json"
    registry_path.write_text(json.dumps(registry))
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps(state))
    modules = tmp_path / "collections/ansible_collections/cisco/nd/plugins/modules"
    modules.mkdir(parents=True)
    (modules / "nd_rest.py").write_text(FAKE_BRINGUP_REST)
    variables = tmp_path / "variables.json"
    variables.write_text(json.dumps({"ansible_python_interpreter": sys.executable,
        "nd_iface_registry_file": str(registry_path), "nd_iface_required_interfaces": scope,
        "nd_iface_apply": apply}))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n")
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_COLLECTIONS_PATH=str(tmp_path / "collections"),
        ANSIBLE_COLLECTIONS_SCAN_SYS_PATH="False", ANSIBLE_STDOUT_CALLBACK="default",
        ANSIBLE_NOCOLOR="1", BASELINE_FAKE_LEDGER=str(ledger),
        ANSIBLE_LOCAL_TEMP=str(tmp_path / "local"), ANSIBLE_REMOTE_TEMP=str(tmp_path / "remote"),
        OBJC_DISABLE_INITIALIZE_FORK_SAFETY="YES")
    playbook = PLUGIN.parent.parent / "nd_ensure_interfaces_up.yaml"
    completed = subprocess.run([str(Path(sys.executable).with_name("ansible-playbook")), "-i", "nd,", "-c", "local",
        str(playbook), "-e", "@" + str(variables)], env=environment, text=True, capture_output=True, timeout=60)
    assert (completed.returncode == 0) is success, completed.stdout + completed.stderr
    calls = json.loads(ledger.read_text())["calls"]
    assert len([row for row in calls if row[0] != "get"]) == expected_writes
    if not expected_writes:
        assert calls == []
    else:
        assert all("Ethernet1%2F63" in path or path.endswith("/interfaceActions/deploy") for _, path, _ in calls)
        assert json.loads(ledger.read_text())["detail"]["configData"] == expected


@pytest.mark.parametrize('enabled,deferred', [(True, False), (True, True), (False, False), (False, True)])
def test_reset_baseline_deferral_is_recovery_only_and_default_safe(tmp_path, enabled, deferred):
    import yaml

    root = PLUGIN.parents[2]
    hook = yaml.safe_load((root / 'consul/reset_fabric.yaml').read_text())[0]['tasks'][-1]
    checkpoint = tmp_path / 'checkpoint.yaml'
    checkpoint.write_text(yaml.safe_dump([{'ansible.builtin.debug': {'msg': 'BASELINE_CHECKPOINT_EXECUTED'}}]))
    hook['ansible.builtin.include_tasks'] = str(checkpoint)
    variables = {'nd_interface_baseline_enabled': enabled}
    if deferred:
        variables['nd_reset_defer_interface_baseline'] = True
    playbook = tmp_path / 'reset-hook.yaml'
    playbook.write_text(yaml.safe_dump([{
        'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
        'vars': variables, 'tasks': [hook]}]))
    config = tmp_path / 'ansible.cfg'
    config.write_text('[defaults]\n')
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_STDOUT_CALLBACK='default',
                       ANSIBLE_NOCOLOR='1', ANSIBLE_LOCAL_TEMP=str(tmp_path / 'local'),
                       ANSIBLE_REMOTE_TEMP=str(tmp_path / 'remote'), OBJC_DISABLE_INITIALIZE_FORK_SAFETY='YES')
    done = subprocess.run([str(Path(sys.executable).with_name('ansible-playbook')), '-i', 'localhost,', str(playbook)],
                          env=environment, text=True, capture_output=True, timeout=30)
    assert done.returncode == 0, done.stdout + done.stderr
    assert ('BASELINE_CHECKPOINT_EXECUTED' in done.stdout) is (enabled and not deferred)


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
    assert reset["tasks"][-1]["when"][-1] == "not (nd_reset_defer_interface_baseline | default(false) | bool)"
    assert guard["vars"]["nd_switch_predelete_copy_timeout_seconds"] == 900
    helper = yaml.safe_load((root / "playbooks/nd_prerequisite/interface_baseline.yaml").read_text())
    recovery = next(task for task in helper if "nd_interface_baseline" in task)["nd_interface_baseline"]["recover_config_sync"]
    # Lifecycle hooks normally audit interfaces; sync recovery must not depend on interface apply.
    assert "nd_switch_apply" in recovery and "nd_prerequisite_only" in recovery
    assert "ND_INTERFACE_BASELINE_RECOVER_SYNC" in recovery and "nd_interface_baseline_recover_config_sync" in recovery
    assert "default(true, true)" in recovery
    assert "INTERFACE_BASELINE_APPLY" not in recovery and "nd_interface_baseline_apply" not in recovery
    assert "default(true, true)" in guard["vars"]["nd_interface_baseline_enabled"]
    assert "default(true, true)" in reset["tasks"][-1]["when"][0]
    for variant in ("Jenkinsfile_nd_jenkins_script", "Jenkinsfile_nd_jenkins_script_temp_switches", "Jenkinsfile_nd_jenkins_script_comm_list"):
        source = (root / variant).read_text()
        assert "'nd_prerequisite/interface_baseline.yaml'" in source
        assert "'action_plugins/nd_interface_baseline.py'" in source
        assert "booleanParam(name: 'ND_INTERFACE_BASELINE_ENABLED'" not in source
        assert "booleanParam(name: 'ND_INTERFACE_BASELINE_RECOVER_SYNC'" not in source
        assert '${ND_INTERFACE_BASELINE_ENABLED:-true}' in source
        assert "name: 'ND_INTERFACE_BASELINE_APPLY', defaultValue: true" in source
        assert "NDP_INTERFACE_BASELINE_RUNTIME_MISSING" in source
        home = source.split('def restoreHomeFabric(', 1)[1].split('\ndef recordUnstartedRound(', 1)[0]
        assert "withEnv(['ND_RESET_DEFER_INTERFACE_BASELINE=true'])" in home
        assert home.index('resetFabricBetweenVersions(') < home.index("runSwitchMembershipSync(homeConfig, 'home', homeRoster)")
        assert "nd_reset_defer_interface_baseline=${env.ND_RESET_DEFER_INTERFACE_BASELINE ?: 'false'}" in source


@pytest.mark.parametrize("extended", [False, True])
def test_live_routed_defaults_without_addresses_are_safe_unused_candidates(baseline, extended):
    registry, original_request, state = controller_fixture()
    policy = {"netflow": False, "policyType": "routedHost", "adminState": True,
              "ptp": "false", "speed": "auto", "mtu": 9216}
    if extended:
        policy.update(ipRedirects=False, qos=False, fec="auto", pimDrPriority=1, pimSparse=False, pfc=False)
    state["detail"]["configData"] = {"mode": "routed", "networkOS": {"networkOSType": "nx-os", "policy": policy}}
    state["detail"]["operData"]["portChannelId"] = -1
    result = baseline.InterfaceBaseline(registry, ["fixture"], original_request, apply=True, poll_seconds=0).run()
    assert result["failed"] is False and result["verified"] == 1
    assert state["detail"]["configData"]["networkOS"]["policy"] == {**policy, "adminState": False}


@pytest.mark.parametrize("extra", [{"ipAddress": "192.0.2.1/30"}, {"vrf": "customer"},
                                  {"pimSparse": True}, {"description": "keep"}, {"policyType": "routedFabric"}])
def test_routed_user_configuration_is_never_unused(baseline, extra):
    registry, request, state = controller_fixture()
    state["detail"]["configData"] = {"mode": "routed", "networkOS": {"networkOSType": "nx-os", "policy": {
        "adminState": True, "policyType": "routedHost", "mtu": 9216, "netflow": False, "speed": "auto", **extra}}}
    result = baseline.InterfaceBaseline(registry, ["fixture"], request, apply=False).run()
    assert result["candidates"] == 0 and state["writes"] == []


def test_live_legacy_link_shape_protects_even_missing_cables(baseline):
    registry, original, state = controller_fixture()
    def request(method, path, content, timeout):
        if "/control/links?" in path:
            return {"status": 200, "current": [{"is-present": False,
                "sw1-info": {"sw-serial-number": "SERIAL00001", "if-name": "Ethernet1/63"},
                "sw2-info": {"sw-serial-number": "PEER", "if-name": "Ethernet1/1"}}]}
        return original(method, path, content, timeout)
    result = baseline.InterfaceBaseline(registry, ["fixture"], request).run()
    assert result["failed"] is False and result["candidates"] == 0
    assert state["writes"] == []


def test_live_trunk_default_variants_are_unused_without_changing_other_fields(baseline):
    registry, request, state = controller_fixture()
    state["detail"]["configData"]["networkOS"]["policy"].update(accessVlan="1", ptp="false")
    state["detail"]["operData"]["portChannelId"] = -1
    result = baseline.InterfaceBaseline(registry, ["fixture"], request, apply=True, poll_seconds=0).run()
    assert result["failed"] is False and result["verified"] == 1


def test_owned_spine_requires_explicit_switch_scope_with_an_empty_test_port_pool(baseline):
    registry, request, state = controller_fixture()
    registry["lab"]["interface_allowlist"]["leaf"] = []
    result = baseline.InterfaceBaseline(registry, ["fixture"], request, switch_refs=["leaf"]).run()
    assert result["failed"] is False and result["candidates"] == 1


def test_anomaly_pagination_reads_the_last_page_before_claiming_clearance(baseline):
    registry, request, state = controller_fixture()
    observed = []
    def pages(method, path, content, timeout):
        offset = 200 if "offset=200" in path else 0
        observed.append(offset)
        rows = [{"anomalyString": "other", "cleared": True} for _ in range(200 if not offset else 1)]
        if offset:
            rows[0] = {"anomalyString": "Interface ethernet1/63 in undesired state up:down:Link not connected",
                       "switchId": "SERIAL00001", "cleared": False}
        return {"status": 200, "current": {"offset": offset, "anomalies": rows,
                "meta": {"counts": {"total": 201, "remaining": 1 if not offset else 0}}}}
    gate = baseline.InterfaceBaseline(registry, ["fixture"], pages)
    gate.deadline = gate.clock() + 5
    rows = gate.anomaly_rows("fixture")
    assert observed == [0, 200] and len(rows) == 201
    assert sum(not row["cleared"] and gate.connectivity_warning(row) for row in rows) == 1


@pytest.mark.parametrize('apply',[False,True])
def test_owned_ibgp_unshut_default_is_audited_or_changed_without_fabric_deploy(baseline,apply):
    registry,original,state=controller_fixture()
    registry['lab']['fabrics']={'advanced':{'name':'fixture','type':'vxlanIbgp','lifecycle':'retained'}}
    config={'name':'fixture','category':'fabric','management':{'type':'vxlanIbgp','bgpAsn':'65001',
        'hostInterfaceAdminState':True},'alertSuspend':'disabled','telemetryCollection':True}
    writes=[]
    def request(method,path,content,timeout):
        if path=='/api/v1/manage/fabrics/fixture':
            if method=='put':
                writes.append(copy.deepcopy(content)); config.clear(); config.update(copy.deepcopy(content))
            return {'status':200,'current':copy.deepcopy(config)}
        return original(method,path,content,timeout)
    result=baseline.InterfaceBaseline(registry,['fixture'],request,apply=apply,poll_seconds=0,
        ensure_host_admin_down_default=True).run()
    assert result['failed'] is False
    assert len(writes)==int(apply)
    assert config['management']['hostInterfaceAdminState'] is (not apply)
    assert config['alertSuspend']=='disabled' and config['telemetryCollection'] is True
    assert not any('/configActions/' in path for _,path in state['calls'])


def test_default_enforcement_cannot_touch_an_unowned_fabric(baseline):
    registry,request,state=controller_fixture()
    with pytest.raises(ValueError,match='retained lab scope'):
        baseline.InterfaceBaseline(registry,['nac-msd-fabric1'],request,apply=True,
            ensure_host_admin_down_default=True)
    assert state['calls']==[]


def required_controller_fixture(source="profile", problem=None, readback=None, deploy_body=None):
    registry, original_request, state, sleep = batch_controller_fixture()
    registry["lab"]["interface_allowlist"]["leaf"] = ["Ethernet1/62"]
    if source == "profile":
        registry["lab"]["interface_allowlist"]["leaf"].append("Ethernet1/61")
        registry["profiles"]["test"] = {"links": [
            {"switch_ref": "leaf", "interfaces": ["Ethernet1/61", "Ethernet1/62"], "admin_state": True}]}
    required = state["details"]["Ethernet1/61"]
    required["configData"]["networkOS"]["policy"].update(adminState=False, description="preserve required link intent")
    required["operData"].update(adminStatus="down", operationalStatus="down")
    state["details"]["Ethernet1/62"]["configData"] = {"mode": "unknown", "networkOS": {"networkOSType": "nx-os"}}
    state["details"]["Ethernet1/62"]["operData"]["adminStatus"] = "down"
    state["mutations"] = []
    state["required_reads"] = 0

    def request(method, path, content, timeout):
        if method == "get" and "links?" in path and source == "live":
            return {"status": 200, "current": {"links": [
                {"srcSwitchId": "SERIAL00001", "srcInterfaceName": "Ethernet1/61",
                 "dstSwitchId": "PEER", "dstInterfaceName": "Ethernet1/1"}]}}
        if method == "get" and "/interfaces/" in path:
            name = path.rsplit("/", 1)[1].replace("%2F", "/")
            if name == "Ethernet1/61":
                state["required_reads"] += 1
                if problem == "race" and state["required_reads"] == 2:
                    required["configData"]["networkOS"]["policy"]["description"] = "new intent"
            return {"status": 200, "current": copy.deepcopy(state["details"][name])}
        if method == "get" and "anomalies/details" in path:
            warnings = [{"cleared": state["details"]["Ethernet1/63"]["operData"]["adminStatus"] == "down",
                         "switchId": "SERIAL00001",
                         "anomalyString": "Interface ethernet1/63 in undesired state up:down:Link not connected"}]
            if problem == "physical":
                warnings.append({"cleared": False, "switchId": "SERIAL00001",
                                 "anomalyString": "Interface ethernet1/61 in undesired state up:down:Link not connected"})
            return {"status": 200, "current": {"anomalies": warnings}}
        if method != "get":
            state["mutations"].append((method, path, copy.deepcopy(content)))
            names = [content["interfaceName"]] if method == "put" else [
                row["interfaceName"] for row in content["interfaces"]]
            if method == "put":
                state["details"][names[0]]["configData"] = copy.deepcopy(content["configData"])
                if readback is not None:
                    # How ND stores and returns the PUT policy.
                    readback(state["details"][names[0]]["configData"]["networkOS"]["policy"])
            if path.endswith("/interfaceActions/deploy"):
                for name in names:
                    enabled = state["details"][name]["configData"]["networkOS"]["policy"]["adminState"]
                    state["details"][name]["operData"]["adminStatus"] = "up" if enabled else "down"
                    if enabled and problem != "physical":
                        state["details"][name]["operData"]["operationalStatus"] = "up"
                if problem == "readback" and names == ["Ethernet1/61"]:
                    required["configData"]["networkOS"]["policy"]["description"] = "unexpected change"
                if deploy_body is not None:
                    return {"status": 207, "current": deploy_body(names)}
            return {"status": 207, "current": {"results": [
                {"switchId": "SERIAL00001", "interfaceName": name, "status": "success"} for name in names]}}
        return original_request(method, path, content, timeout)

    return registry, request, state, sleep


@pytest.mark.parametrize("source", ["profile", "live"])
@pytest.mark.parametrize("apply", [False, True])
def test_required_managed_links_up_unused_ports_down_and_free_reservations_untouched(baseline, tmp_path, source, apply):
    registry, request, state, sleep = required_controller_fixture(source)
    before = copy.deepcopy(state["details"])
    journal = tmp_path / "journal.jsonl"
    result = baseline.InterfaceBaseline(
        registry, ["fixture"], request, apply=apply, switch_refs=["leaf"],
        ensure_required_admin_up=True, journal_path=str(journal),
        clock=lambda: state["now"], sleep=sleep, poll_seconds=1, timeout_seconds=90).run()
    assert not result["failed"]
    assert result["candidates"] == result["required_candidates"] == 1
    assert result["verified"] == result["required_verified"] == int(apply)
    assert len(state["mutations"]) == (4 if apply else 0)
    if apply:
        before["Ethernet1/61"]["configData"]["networkOS"]["policy"]["adminState"] = True
        before["Ethernet1/63"]["configData"]["networkOS"]["policy"]["adminState"] = False
        assert result["remaining_connectivity_alerts"] == 0
        checkpoints = [json.loads(line) for line in journal.read_text().splitlines()]
        assert {row["interfaceName"] for row in checkpoints if row["phase"] == "before_change"} == {
            "Ethernet1/61", "Ethernet1/63"}
    for name, detail in state["details"].items():
        assert detail["configData"] == before[name]["configData"]
    assert not any("clear" in path.lower() or "acknowledge" in path.lower()
                   for _, path, _ in state["mutations"])


@pytest.mark.parametrize("problem, reason", [
    ("race", "INTERFACE_CHANGED_BEFORE_APPLY"),
    ("readback", "REQUIRED_INTERFACE_CONFIG_CHANGED"),
    ("physical", "CONNECTIVITY_INTERFACE_STATUS_ACTIVE"),
])
def test_required_link_failures_are_explicit_and_do_not_relax_safety(baseline, tmp_path, problem, reason):
    registry, request, state, sleep = required_controller_fixture(problem=problem)
    result = baseline.InterfaceBaseline(
        registry, ["fixture"], request, apply=True, switch_refs=["leaf"], ensure_required_admin_up=True,
        journal_path=str(tmp_path / "journal.jsonl"), clock=lambda: state["now"],
        sleep=sleep, poll_seconds=1, timeout_seconds=90).run()
    assert result["failed"] and result["reason"] == reason
    assert len(state["mutations"]) == {"race": 0, "readback": 2, "physical": 4}[problem]


@pytest.mark.parametrize('phase,problem,expected_writes', [
    ('after_plan', None, 4),
    ('after_deploy', None, 4),
    ('after_deploy', 'persistent', 2),
    ('after_plan', 'identity', 0),
    ('after_plan', 'configuration', 0),
])
def test_required_port_sync_settles_before_fresh_checks_and_further_writes(
        baseline, tmp_path, phase, problem, expected_writes):
    registry, original, state, sleep = required_controller_fixture()
    state['settle_reads'] = 0

    def request(method, path, content, timeout):
        reply = original(method, path, content, timeout)
        started = (state['required_reads'] > 0 if phase == 'after_plan'
                   else len(state['mutations']) >= 2)
        if path.endswith('/switches') and started:
            state['settle_reads'] += 1
            if state['settle_reads'] <= 4 or problem == 'persistent':
                node = reply['current']['switches'][0]
                node['additionalData']['configSyncStatus'] = 'pending'
                assert len(state['mutations']) == (0 if phase == 'after_plan' else 2)
                if problem == 'identity' and state['settle_reads'] == 2:
                    node['fabricManagementIp'] = '192.0.2.99'
                if problem == 'configuration' and state['settle_reads'] == 2:
                    state['details']['Ethernet1/61']['configData']['networkOS']['policy']['description'] = 'new intent'
        return reply

    result = baseline.InterfaceBaseline(
        registry, ['fixture'], request, apply=True, switch_refs=['leaf'], ensure_required_admin_up=True,
        journal_path=str(tmp_path / 'journal.jsonl'), clock=lambda: state['now'], sleep=sleep,
        poll_seconds=1, timeout_seconds=30, sync_attempt_seconds=20, sync_settle_seconds=5).run()
    assert result['baseline_failed'] is (problem is not None), result
    assert len(state['mutations']) == expected_writes
    assert state['now'] < 30
    if problem is None:
        assert result['required_verified'] == result['verified'] == 1
        assert state['settle_reads'] >= 5
    else:
        assert result['reason'] == ('INTERFACE_CHANGED_BEFORE_APPLY' if problem == 'configuration'
                                    else 'SWITCH_READINESS_OR_IDENTITY_UNVERIFIED')
        assert result['required_verified'] == result['verified'] == 0
        if problem == 'identity':
            assert state['settle_reads'] == 2
    assert '192.0.2.99' not in json.dumps(result)


@pytest.mark.parametrize("deploy_body", [
    lambda names: {},
    lambda names: {"results": []},
    lambda names: {"results": [{"switchId": "SERIAL00001", "interfaceName": name.lower(), "status": "success"} for name in names]},
], ids=["no_results", "empty_results", "lowercase_names"])
def test_interface_deploy_207_without_exact_rows_is_proven_by_readback(baseline, tmp_path, deploy_body):
    # Build 196: the deploy applied (port came up) but the 207 rows did not match exactly.
    registry, request, state, sleep = required_controller_fixture(deploy_body=deploy_body)
    result = baseline.InterfaceBaseline(
        registry, ["fixture"], request, apply=True, switch_refs=["leaf"], ensure_required_admin_up=True,
        journal_path=str(tmp_path / "journal.jsonl"), clock=lambda: state["now"],
        sleep=sleep, poll_seconds=1, timeout_seconds=90).run()
    assert not result["failed"], result["reason"]
    assert result["required_verified"] == result["verified"] == 1


@pytest.mark.parametrize("deploy_body", [
    lambda names: {"results": [{"switchId": "SERIAL00001", "interfaceName": names[0], "status": "unknown"}]},
    lambda names: {"results": [{"switchId": "FOREIGN", "interfaceName": names[0], "status": "success"}]},
    lambda names: {"results": [{"switchId": "SERIAL00001", "interfaceName": names[0], "status": "success"}] * 2},
    lambda names: {"results": [{"status": "success"}]},
    lambda names: {"results": "success"},
], ids=["unknown_status", "foreign_identity", "duplicate", "anonymous", "not_a_list"])
def test_interface_deploy_207_with_contradictory_rows_still_blocks(baseline, tmp_path, deploy_body):
    registry, request, state, sleep = required_controller_fixture(deploy_body=deploy_body)
    result = baseline.InterfaceBaseline(
        registry, ["fixture"], request, apply=True, switch_refs=["leaf"], ensure_required_admin_up=True,
        journal_path=str(tmp_path / "journal.jsonl"), clock=lambda: state["now"],
        sleep=sleep, poll_seconds=1, timeout_seconds=90).run()
    assert result["failed"] and result["reason"] == "OPERATION_IDENTITY_UNVERIFIED"
    assert [method for method, _, _ in state["mutations"]] == ["put", "post"]


ND_TEMPLATE_READBACK = {
    "bpduFilter": "default", "cdp": True, "duplexMode": "auto", "errorDetectionAcl": True, "fec": "auto",
    "linkType": "auto", "monitor": False, "negotiateAuto": True, "orphanPort": False, "pfc": False,
    "ptp": "false", "qos": False, "stormControl": False, "stormControlAction": "default", "vlanMapping": False}
ND_STORM_LEVELS = {"stormControl%sLevel%s" % (kind, unit): 0
                   for kind in ("Broadcast", "Multicast", "Unicast") for unit in ("", "Pps")}


@pytest.mark.parametrize("extra", [
    ND_TEMPLATE_READBACK,
    dict(ND_TEMPLATE_READBACK, debounceTimer=100),
    dict(ND_TEMPLATE_READBACK, accessVlan="1", nativeVlan=1, debounceTimer=100, **ND_STORM_LEVELS),
], ids=["template", "debounce", "full"])
def test_put_readback_with_nd_template_defaults_verifies_required_and_single_ports(baseline, tmp_path, extra):
    # Build 198 shapes: 8 policy keys sent, 23, 24 or 32 returned.
    registry, request, state, sleep = required_controller_fixture(readback=lambda policy: policy.update(extra))
    result = baseline.InterfaceBaseline(
        registry, ["fixture"], request, apply=True, switch_refs=["leaf"], ensure_required_admin_up=True,
        journal_path=str(tmp_path / "journal.jsonl"), clock=lambda: state["now"],
        sleep=sleep, poll_seconds=1, timeout_seconds=90).run()
    assert not result["failed"], result["reason"]
    assert result["required_verified"] == result["verified"] == 1
    assert [method for method, _, _ in state["mutations"]] == ["put", "post", "put", "post"]


@pytest.mark.parametrize("change, drift", [
    (lambda policy: policy.update(ND_TEMPLATE_READBACK, cdp=False), {"added_keys": ["cdp"]}),
    (lambda policy: policy.update(inheritTtag="PRIVATE_CANARY", ip="PRIVATE_CANARY"), {"added_keys": ["inheritTtag", "ip"]}),
    (lambda policy: policy.update(debounceTimer="100", qos=0), {"added_keys": ["debounceTimer", "qos"]}),
    (lambda policy: policy.update(ND_TEMPLATE_READBACK, description="PRIVATE_CANARY"), {"changed_keys": ["description"]}),
    (lambda policy: policy.pop("description"), {"missing_keys": ["description"]}),
], ids=["non_default", "unknown_key", "wrong_type", "changed_request", "missing_request"])
def test_put_readback_still_rejects_real_drift_and_reports_only_key_names(baseline, tmp_path, change, drift):
    registry, request, state, sleep = required_controller_fixture(readback=change)
    result = baseline.InterfaceBaseline(
        registry, ["fixture"], request, apply=True, switch_refs=["leaf"], ensure_required_admin_up=True,
        journal_path=str(tmp_path / "journal.jsonl"), clock=lambda: state["now"],
        sleep=sleep, poll_seconds=1, timeout_seconds=90).run()
    assert result["failed"] and result["reason"] == "REQUIRED_INTERFACE_CONFIG_CHANGED"
    assert len(state["mutations"]) == 2
    assert result["decisions"][-1] == {
        "switch": "leaf", "interface": "Ethernet1/61", "decision": "REQUIRED_INTERFACE_CONFIG_CHANGED",
        "added_keys": [], "missing_keys": [], "changed_keys": [], "outside_policy_changed": False, **drift}
    assert "PRIVATE_CANARY" not in json.dumps(result)


@pytest.mark.parametrize("check_mode", [False, True])
def test_required_port_action_respects_check_mode(baseline, monkeypatch, tmp_path, check_mode):
    from types import SimpleNamespace

    registry, request, state, _ = required_controller_fixture()
    monkeypatch.setattr(baseline.ActionBase, "run", lambda *args, **kwargs: {})
    action = baseline.ActionModule.__new__(baseline.ActionModule)
    action._task = SimpleNamespace(args={
        "registry": registry, "fabrics": ["fixture"], "apply": True, "switch_refs": ["leaf"],
        "ensure_required_admin_up": True, "journal_path": str(tmp_path / "journal.jsonl"),
        "poll_seconds": 0}, no_log=False, check_mode=check_mode)
    action._templar = SimpleNamespace(template=lambda value: value)
    action._connection = SimpleNamespace(_socket_path=None)

    def execute(module_name, module_args, task_vars):
        assert action._task.no_log is True
        return request(module_args["method"], module_args["path"], module_args.get("content"), 30)

    action._execute_module = execute
    result = action.run(task_vars={})
    assert not result["failed"]
    assert result["required_verified"] == result["verified"] == int(not check_mode)
    assert len(state["mutations"]) == (0 if check_mode else 4)
    assert action._task.no_log is False


def test_required_port_missing_inventory_blocks_before_any_mutation(baseline, tmp_path):
    registry, request, state, sleep = required_controller_fixture()
    del state["details"]["Ethernet1/61"]
    result = baseline.InterfaceBaseline(
        registry, ["fixture"], request, apply=True, switch_refs=["leaf"], ensure_required_admin_up=True,
        journal_path=str(tmp_path / "journal.jsonl"), clock=lambda: state["now"],
        sleep=sleep, poll_seconds=1, timeout_seconds=90).run()
    assert result["failed"] and result["reason"] == "REQUIRED_INTERFACE_SCOPE_INCOMPLETE"
    assert not state["mutations"]


def test_breakout_reservation_does_not_enable_sibling_channels(baseline, tmp_path):
    registry, request, state, sleep = required_controller_fixture()
    for name in ["Ethernet1/61/1", "Ethernet1/61/2"]:
        state["details"][name] = copy.deepcopy(state["details"]["Ethernet1/61"])
        state["details"][name]["interfaceName"] = name
    del state["details"]["Ethernet1/61"]
    registry["profiles"]["test"]["links"][0]["interfaces"] = ["Ethernet1/61/1", "Ethernet1/62"]
    result = baseline.InterfaceBaseline(
        registry, ["fixture"], request, apply=True, switch_refs=["leaf"], ensure_required_admin_up=True,
        journal_path=str(tmp_path / "journal.jsonl"), clock=lambda: state["now"],
        sleep=sleep, poll_seconds=1, timeout_seconds=90).run()
    assert not result["failed"] and result["required_verified"] == 1
    assert state["details"]["Ethernet1/61/1"]["configData"]["networkOS"]["policy"]["adminState"] is True
    assert state["details"]["Ethernet1/61/2"]["configData"]["networkOS"]["policy"]["adminState"] is False


def test_lifecycle_enforces_reservations_and_blocks_unverified_switch_deletion():
    import yaml

    root = PLUGIN.parents[2]
    helper = yaml.safe_load((root / "playbooks/nd_prerequisite/interface_baseline.yaml").read_text())
    action = next(task["nd_interface_baseline"] for task in helper if "nd_interface_baseline" in task)
    assert action["idle_reserved_ports"] is False
    assert action["ensure_required_admin_up"] is True
    assert "default(true, true)" in action["apply"]
    convergence = next(task for task in helper if task.get("ansible.builtin.include_tasks") == "converge_port_channel_member_drift.yaml")
    assert "not ansible_check_mode" in convergence["when"]
    assert any("ND_INTERFACE_BASELINE_APPLY" in condition for condition in convergence["when"])
    gate = next(task for task in helper if "Require accepted operations" in task.get("name", ""))
    assert not gate.get("ignore_errors", False)
    runner = yaml.safe_load((root / "tests/run_integration_module.yaml").read_text())[0]
    deletion = next(task for task in runner["tasks"] if "require safe fabric-wide switch deletion" in task.get("name", ""))
    assert "BASELINE_HOOK before switch-delete admission" in deletion["block"][1]["name"]
    guard = yaml.safe_load((root / "playbooks/nd_ensure_switches.yaml").read_text())[0]
    assert any("BASELINE_HOOK after membership and readiness recovery" in task.get("name", "")
               for task in guard["tasks"])


@pytest.mark.parametrize('problem', [None, 'identity_changed', 'out_of_sync', 'never_finishes', 'warning_after_sync'])
def test_default_update_waits_only_for_normal_pending_compliance(baseline, problem):
    registry, original, state = controller_fixture()
    registry['lab']['fabrics'] = {'advanced': {'name': 'fixture', 'type': 'vxlanIbgp', 'lifecycle': 'retained'}}
    config = {'name': 'fixture', 'category': 'fabric', 'management': {
        'type': 'vxlanIbgp', 'hostInterfaceAdminState': True}}
    state.update(now=0, default_writes=0, sync_polls=0)

    def request(method, path, content, timeout):
        state['now'] += 0.01
        if path == '/api/v1/manage/fabrics/fixture':
            if method == 'put':
                state['default_writes'] += 1
                config.clear()
                config.update(copy.deepcopy(content))
            return {'status': 200, 'current': copy.deepcopy(config)}
        reply = original(method, path, content, timeout)
        if method == 'get' and 'anomalies/details' in path and problem == 'warning_after_sync' and state['sync_polls'] >= 3:
            reply['current']['anomalies'][0]['cleared'] = False
        if method == 'get' and path.endswith('/switches') and state['default_writes']:
            state['sync_polls'] += 1
            node = reply['current']['switches'][0]
            if state['sync_polls'] <= 2 or problem == 'never_finishes':
                node['additionalData']['configSyncStatus'] = 'pending'
            if problem == 'identity_changed':
                node['fabricManagementIp'] = '192.0.2.99'
            if problem == 'out_of_sync':
                node['additionalData']['configSyncStatus'] = 'outOfSync'
        return reply

    def sleep(seconds):
        state['now'] += seconds

    result = baseline.InterfaceBaseline(registry, ['fixture'], request, apply=True, poll_seconds=1,
        clock=lambda: state['now'], sleep=sleep, timeout_seconds=30,
        ensure_host_admin_down_default=True).run()
    assert state['default_writes'] == 1
    assert not any('/actions/configSave' in path or '/configActions/' in path for _, path in state['calls'])
    if problem is None:
        assert not result['failed'] and state['sync_polls'] >= 3
    elif problem == 'never_finishes':
        assert result['failed'] and result['reason'] in {'FABRIC_DEFAULT_SYNC_DEADLINE', 'DEADLINE_EXCEEDED'}
    elif problem == 'warning_after_sync':
        assert result['failed'] and result['reason'] == 'CONNECTIVITY_INTERFACE_STATUS_ACTIVE'
    else:
        assert result['failed'] and result['reason'] == 'SWITCH_READINESS_OR_IDENTITY_UNVERIFIED'
        assert state['sync_polls'] == 1


@pytest.mark.parametrize('refused',[False,True])
def test_action_preserves_the_207_body_and_never_deploys_a_refused_put(baseline,monkeypatch,refused):
    from types import SimpleNamespace
    registry,request,state=controller_fixture('refused_write' if refused else None)
    monkeypatch.setattr(baseline.ActionBase,'run',lambda *a,**kw:{})
    action=baseline.ActionModule.__new__(baseline.ActionModule)
    action._task=SimpleNamespace(args={'registry':registry,'fabrics':['fixture'],'apply':True,'poll_seconds':0},no_log=False,check_mode=False)
    action._templar=SimpleNamespace(template=lambda value:value)
    class RPC:
        def __init__(self,*args):pass
        def get_option(self,name):return 30
        def set_option(self,name,value):pass
        def send_request(self,method,path,data):
            assert action._task.no_log is True
            reply=request(method.lower(),path,json.loads(data),30)
            return {'status':reply['status'],'body':reply['current'],
                    'error':{'code':207,'message':reply['current']}}
    monkeypatch.setattr(baseline,'Connection',RPC)
    action._connection=RPC();action._connection._socket_path='fixture-socket'
    def get(module_name,module_args,task_vars):
        assert module_args['method']=='get'
        return request('get',module_args['path'],None,30)
    action._execute_module=get
    result=action.run(task_vars={})
    assert result['failed'] is refused
    assert len(state['writes'])==(1 if refused else 2)
    assert result['verified']==(0 if refused else 1)
    assert action._task.no_log is False


@pytest.mark.parametrize('problem',[None,'linked','attached','logical_child'])
def test_idle_lifecycle_can_shut_a_future_reservation_only_with_fresh_unused_evidence(baseline,tmp_path,problem):
    registry,request,state=controller_fixture(problem)
    registry['lab']['interface_allowlist']['leaf'].append('Ethernet1/63')
    result=baseline.InterfaceBaseline(registry,['fixture'],request,apply=False,switch_refs=['leaf'],
        idle_reserved_ports=True,journal_path=str(tmp_path/'journal.jsonl')).run()
    assert result['failed'] is False
    assert result['candidates']==(1 if problem is None else 0)
    assert state['writes']==[]


@pytest.mark.parametrize('switch_refs,journal',[(None,None),(['leaf'],None)])
def test_idle_reservations_cannot_be_released_without_explicit_scope_and_checkpoint(baseline,switch_refs,journal):
    registry,request,state=controller_fixture()
    with pytest.raises(ValueError,match='explicit switches and a durable checkpoint'):
        baseline.InterfaceBaseline(registry,['fixture'],request,apply=True,switch_refs=switch_refs,
            idle_reserved_ports=True,journal_path=journal)
    assert state['calls']==[]


@pytest.mark.parametrize('port',['Ethernet1/5','Ethernet1/9','Ethernet1/31','Ethernet1/41','Ethernet1/63'])
def test_full_inventory_repair_covers_lower_and_previously_unlisted_ports_without_deleting_history(baseline,port):
    registry,original,state=controller_fixture()
    state['detail']['interfaceName']=port
    def request(method,path,content,limit):
        reply=original(method,path,content,limit)
        if path.endswith('/interfaces'):
            reply['current']={'interfaces':[{'interfaceName':'Ethernet1/1'},{'interfaceName':port}]}
        if isinstance(reply.get('current'),dict) and 'results' in reply['current']:
            for row in reply['current']['results']:row['interfaceName']=port
        if 'anomalies/details' in path:
            for row in reply['current']['anomalies']:
                row['anomalyString']=row['anomalyString'].replace('ethernet1/63',port.lower())
            reply['current']['anomalies'].append({'cleared':True,'anomalyString':
                '[SERIAL00001] Interface ethernet1/3 in undesired state up:down:Link not connected'})
        return reply
    result=baseline.InterfaceBaseline(registry,['fixture'],request,apply=True,
        switch_refs=['leaf'],poll_seconds=0).run()
    assert result['failed'] is False and result['verified']==1
    assert state['detail']['configData']['networkOS']['policy']['adminState'] is False
    assert [row[0] for row in state['writes']]==['put','post']
    assert state['writes'][0][2]['interfaceName']==port
    assert state['writes'][1][2]['interfaces']==[{'switchId':'SERIAL00001','interfaceName':port}]
    assert result['remaining_connectivity_alerts']==0
    assert not any('acknowledg' in path.lower() or 'clear' in path.lower() for _,path in state['calls'])


@pytest.mark.parametrize('reason',['BPDUGuard errDisable','inactive','sfp-validation-failed','unknown',None,''])
def test_a_real_link_or_vlan_fault_is_not_hidden_by_shutting_a_default_policy_port(baseline,reason):
    registry,request,state=controller_fixture()
    state['detail']['operData']['operationalDescription']=reason
    result=baseline.InterfaceBaseline(registry,['fixture'],request,apply=False).run()
    assert result['candidates']==0 and state['writes']==[]
    assert any(row['decision']=='UNVERIFIED_UNUSED_REASON' for row in result['decisions'])


def test_registry_lookup_drops_empty_default_and_embed_matches():
    import base64, gzip, re
    root = Path(__file__).resolve().parents[1]
    helper = root / "playbooks" / "nd_prerequisite" / "interface_baseline.yaml"
    text = helper.read_text()
    assert "| select | list" in text
    jenkins = (root / "Jenkinsfile_nd_jenkins_script").read_text()
    m = re.search(r"'nd_prerequisite/interface_baseline.yaml': \[sha256: '\w+', bytes: \d+, gzipBase64: '([^']+)'", jenkins)
    assert gzip.decompress(base64.b64decode(m.group(1))) == helper.read_bytes()
    plugin = re.search(r"'action_plugins/nd_interface_baseline.py': \[sha256: '(\w+)', bytes: (\d+), gzipBase64: '([^']+)'", jenkins)
    import hashlib
    assert gzip.decompress(base64.b64decode(plugin.group(3))) == PLUGIN.read_bytes()
    assert int(plugin.group(2)) == len(PLUGIN.read_bytes())
    assert plugin.group(1) == hashlib.sha256(PLUGIN.read_bytes()).hexdigest()
