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
    assert all(row["decision"] == "NO_OWNED_INTERFACE_SCOPE" for row in result["decisions"])


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

    result = baseline.InterfaceBaseline(registry, ['fixture'], changed_request, apply=apply).run()
    assert result['baseline_failed'] is True
    assert result['reason'] == 'SWITCH_READINESS_OR_IDENTITY_UNVERIFIED'
    assert state['writes'] == [] and result['verified'] == 0


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
    assert len(state["writes"]) == 2


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
elif endpoint == '/api/v1/manage/fabrics/fixture':
    body = {'name':'fixture','category':'fabric','management':{'type':'vxlanIbgp','hostInterfaceAdminState':False}}
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
    registry['lab']['fabrics']={'advanced':{'name':'fixture','type':'vxlanIbgp','lifecycle':'retained'}}
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
        expected_default = "true" if variant == "Jenkinsfile_nd_jenkins_script" else "false"
        assert "name: 'ND_INTERFACE_BASELINE_ENABLED', defaultValue: " + expected_default in source
        assert "name: 'ND_INTERFACE_BASELINE_APPLY', defaultValue: " + expected_default in source
        assert "NDP_INTERFACE_BASELINE_RUNTIME_MISSING" in source


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
