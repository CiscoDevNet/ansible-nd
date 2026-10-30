"""Execute the actual move tasks with local fake modules; never contact ND."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from ansible.plugins.filter.core import regex_replace, to_bool
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "playbooks/nd_ensure_switches.yaml"


FAKE_MODULE = r'''
import json, os
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule
m = AnsibleModule(argument_spec={
    'fabric': {'type':'str'}, 'fabric_name': {'type':'str'}, 'state': {'type':'str'},
    'config': {'type':'raw'}, 'path': {'type':'str'}, 'method': {'type':'str'}, 'content': {'type':'raw'}})
p = Path(os.environ['MOVE_FIXTURE_STATE']); s = json.loads(p.read_text()); a = m.params
scenario = s['scenario']
def finish(**result):
    p.write_text(json.dumps(s)); m.exit_json(**result)
def fail(**result):
    p.write_text(json.dumps(s)); m.fail_json(**result)
if a['method']:
    if a['method'] == 'get':
        if a['path'].endswith('/switches'):
            s['predelete_polls'] = s.get('predelete_polls', 0) + 1
            if scenario == 'predelete_call_timeout':
                import time
                time.sleep(3)
            rows = [{'switchId':'FIXTURE'+str(index+1).zfill(4),
                     'additionalData':{'systemMode':'normal','configSyncStatus':'inSync'}}
                    for index in range(len(s['original']))]
            if scenario == 'predelete_pending_then_ready' and s['predelete_polls'] == 1 or scenario == 'predelete_pending_forever':
                rows[-1]['additionalData']['configSyncStatus'] = 'pending'
            if scenario == 'predelete_deployment_failed': rows[-1]['additionalData']['configSyncStatus'] = 'failed'
            if scenario == 'predelete_missing_switch': rows = rows[:-1]
            if scenario == 'predelete_missing_status': rows[-1]['additionalData'].pop('configSyncStatus')
            if scenario == 'predelete_duplicate_switch': rows[-1] = dict(rows[0])
            body = {'switches':rows}
            if scenario == 'predelete_bad_inventory': body = {'switches':None}
            if scenario == 'predelete_inventory_module_failure': fail(status=200, current=body, msg='password=DO_NOT_PRINT_ME')
            finish(changed=False, status=403 if scenario == 'predelete_inventory_403' else 200, current=body)
        code = 500 if scenario == 'destination_http_error' else 200
        kind = 'externalConnectivity' if scenario == 'external' else 'vxlanCampus' if scenario == 'campus' else 'vxlanEbgp'
        finish(changed=False, status=code, current={'management':{'type':kind}})
    s['rest_writes'].append(a['path'])
    if not a['path'].endswith('/switchActions/remove'):
        if a['path'].endswith('/actions/configSave') and scenario == 'predelete_save_400':
            fail(status=400, msg='Save refused password=DO_NOT_PRINT_ME', current={'error':'RAW_PAYLOAD'})
        if a['path'].endswith('/actions/configSave') and scenario == 'predelete_save_module_failure':
            fail(status=200, current={}, msg='password=DO_NOT_PRINT_ME')
        if a['path'].endswith('/switchActions/deploy'):
            if scenario == 'predelete_deploy_403': fail(status=403, msg='Deploy denied password=DO_NOT_PRINT_ME')
            if scenario == 'predelete_deploy_207_refused':
                finish(changed=True, status=207, current={'items':[{'switchId':identity,'status':'failed','message':'password=DO_NOT_PRINT_ME'} for identity in a['content']['switchIds']]})
            if scenario == 'predelete_deploy_207_items':
                finish(changed=True, status=207, current={'items':[{'switchId':identity,'status':'success'} for identity in a['content']['switchIds']]})
            if scenario == 'predelete_deploy_207_message':
                finish(changed=True, status=207, current={'status':'Configuration deployment completed for ['+', '.join(a['content']['switchIds'])+'].'})
            if scenario == 'predelete_deploy_207_partial_message':
                finish(changed=True, status=207, current={'status':'Configuration deployment completed for ['+a['content']['switchIds'][0]+'].'})
            if scenario == 'predelete_deploy_bad_body': finish(changed=True, status=207, current={})
        finish(changed=True, status=200, current={})
    requested = a['content']['switchIds']; s['selected_calls'].append(requested)
    attempt = len(s['selected_calls'])
    if scenario in ('http_500', 'http_429', 'transport_timeout') and attempt == 1:
        if scenario == 'transport_timeout': fail(msg='Connection timed out')
        fail(status=500 if scenario == 'http_500' else 429, msg='Temporary controller failure')
    if scenario == 'transient_forever': fail(status=503, msg='Temporarily unavailable password=DO_NOT_PRINT_ME', payload={'private':'RAW_PAYLOAD'})
    if scenario == 'auth_failure': fail(msg='Authentication failed Connection timed out password=DO_NOT_PRINT_ME')
    if scenario == 'http_400': fail(status=400, msg='ND Error4102: Recalculate and Deploy is required password=DO_NOT_PRINT_ME', payload={'private':'RAW_PAYLOAD'})
    if scenario == 'generic_failure': fail(msg='Unknown local result error')
    refused = set(requested[-2:]) if scenario in ('partial_then_success', 'partial_forever') else set()
    items = [{'switchId': identity, 'status':'failed' if identity in refused else 'success',
              'errorCode':'ND-4102' if identity in refused else '0',
              'message': ('Failed to delete the switch['+identity+']. Please check Anomalies for possible reasons. password=DO_NOT_PRINT_ME') if identity in refused else 'Deleted successfully',
              'private': {'password':'RAW_PAYLOAD'}} for identity in requested]
    if scenario == 'malformed_207': items=[]
    if scenario == 'duplicate_identity': items[-1]=dict(items[0])
    if scenario == 'wrong_identity': items[-1]['switchId']='UNREQUESTED0001'
    if scenario == 'unknown_item_status': items[-1]['status']='pending-unknown'
    if scenario == 'missing_item': items=items[:-1]
    if scenario == 'missing_response': finish(changed=True, status=207)
    body={'items':items}
    if scenario == 'bad_body': body='invalid response shape'
    if scenario == 'body_errors': body={'error':{'message':'Controller rejected operation'},'private':'RAW_PAYLOAD'}
    accepted = not refused and scenario not in ('malformed_207','duplicate_identity','wrong_identity','unknown_item_status','missing_item','bad_body','body_errors','source_never_absent')
    if accepted: s['present']=[]
    code=202 if scenario=='accepted_202' else 204 if scenario=='accepted_204' else 200 if scenario=='accepted_200' else 207
    if code==202:body={'jobId':'queued-fixture-job'}
    if code==204:body=None
    if code==200:body={}
    if scenario == 'current_only': finish(changed=True,status=code,current=body)
    finish(changed=True,status=code,current=body,jsondata=body)
if a['fabric_name']:
    finish(changed=False, gathered={'vpc_pairs':[]})
if a['state'] == 'gathered':
    s['source_gets'] += 1
    if scenario == 'get_failure': fail(msg='FIXTURE_SOURCE_GET_FAILED')
    if scenario == 'missing_gathered': finish(changed=False)
    if scenario == 'bad_gathered': finish(changed=False, gathered=[{}])
    finish(changed=False, gathered=[{'seed_ip':ip} for ip in s['present']])
s['module_delete_calls'] += 1
fail(msg='The switch-module deleted workflow must not be invoked for normal rehome removal')
'''


def guard():
    return yaml.safe_load(GUARD.read_text())[0]


def named(tasks, prefix):
    for task in tasks:
        if task.get("name", "").startswith(prefix):
            return task
        for section in ("block", "rescue", "always"):
            try:
                return named(task.get(section, []), prefix)
            except StopIteration:
                pass
    raise StopIteration(prefix)


def move_tasks():
    play = guard()
    return [copy.deepcopy(named(play["tasks"], "Validate missing-switch destinations")),
            copy.deepcopy(named(play["tasks"], "Move the roster switches out"))]


def expression_environment():
    environment = NativeEnvironment(undefined=StrictUndefined)
    environment.filters["bool"] = to_bool
    environment.filters["intersect"] = lambda left, right: sorted(set(left) & set(right))
    environment.filters["difference"] = lambda left, right: [value for value in left if value not in right]
    environment.filters["regex_replace"] = regex_replace
    environment.tests["succeeded"] = lambda result: not result.get("failed", False)
    environment.tests["match"] = lambda value, pattern: bool(re.match(pattern, value))
    environment.tests["search"] = lambda value, pattern: bool(re.search(pattern, value))
    return environment


@pytest.mark.parametrize("status,body,expected", [
    (207, {"items":[{"switchId":"FIXTURE0001","status":"success"},{"switchId":"FIXTURE0002","status":"success"}]}, "accepted"),
    (207, {"items":[{"switchId":"FIXTURE0001","status":"failed"},{"switchId":"FIXTURE0002","status":"success"}]}, "refused"),
    (207, None, "invalid-response"), (207, {"items":[]}, "invalid-response"),
    (207, {"items":[None]}, "invalid-response"), (207, {"items":[{}]}, "invalid-response"),
    (207, {"items":"success"}, "invalid-response"), (207, [], "invalid-response"),
    (207, {"items":[{"switchId":"FIXTURE0001","status":"success"}]}, "invalid-response"),
    (207, {"items":[{"switchId":"FIXTURE0001","status":"success"},{"switchId":"FIXTURE0001","status":"success"}]}, "invalid-response"),
    (207, {"items":[{"switchId":"FIXTURE0001","status":"success"},{"switchId":"FIXTURE0001","status":"success"}]}, "invalid-response"),
    (200, {}, "accepted"), (202, {"jobId":"queued"}, "accepted"), (204, None, "accepted"),
    (200, [], "invalid-response"), (500, {}, "request-failed"), (400, {}, "request-failed"),
])
def test_immediate_remove_classifier_requires_valid_complete_item_identities(status, body, expected):
    classifier = named(move_tasks()[1]["block"], "Classify the immediate")
    result={"status":status,"jsondata":body,"_rm":{"key":"fixture-source"}}
    rendered=expression_environment().from_string(classifier["vars"]["_remove_report"]).render(
        _removal=result, _requested_ids=["FIXTURE0001","FIXTURE0002"],
        nd_rehome_moves=[{"serial":"FIXTURE0001","name":"first"},{"serial":"FIXTURE0002","name":"second"}],
        _credential_tail=classifier["vars"]["_credential_tail"])
    assert isinstance(rendered,dict)
    assert rendered["classification"] == expected


def test_native_refusal_reason_is_useful_bounded_and_redacted():
    classifier=named(move_tasks()[1]["block"],"Classify the immediate")
    reason=("Failed to delete switch[FIXTURE0001] at 192.0.2.1. Please check Anomalies for possible reasons. "
            "https://private.example/request Bearer BEARER_PRIVATE password=PASSWORD_PRIVATE private details")
    result={"status":207,"_rm":{"key":"fixture-source"},"jsondata":{"items":[
        {"switchId":"FIXTURE0001","status":"failed","errorCode":"ND-4102","message":reason,"private":{"secret":"RAW_PAYLOAD"}},
        {"switchId":"FIXTURE0002","status":"success"}]}}
    report=expression_environment().from_string(classifier["vars"]["_remove_report"]).render(
        _removal=result,_requested_ids=["FIXTURE0001","FIXTURE0002"],
        nd_rehome_moves=[{"serial":"FIXTURE0001","name":"first"},{"serial":"FIXTURE0002","name":"second"}],
        _credential_tail=classifier["vars"]["_credential_tail"])
    assert report["classification"]=="refused"
    assert report["items"][0]["error_code"]=="ND-4102"
    assert "Please check Anomalies for possible reasons" in report["items"][0]["reason"]
    assert len(report["items"][0]["reason"])<=240
    for private in ["192.0.2.1","FIXTURE0001","private.example","BEARER_PRIVATE","PASSWORD_PRIVATE","RAW_PAYLOAD"]:
        assert private not in json.dumps(report)


@pytest.mark.parametrize("result, expected", [
    ({"gathered": []}, True), ({"failed": True, "gathered": []}, False), ({}, False),
    ({"gathered": None}, False), ({"gathered": {}}, False), ({"gathered": [None]}, False),
    ({"gathered": [{}]}, False), ({"gathered": [{"seed_ip": None}]}, False),
    ({"gathered": [{"seed_ip": 42}]}, False), ({"gathered": [{"seed_ip": " "}]}, False),
    ({"gathered": [{"seed_ip": "192.0.2.1"}]}, False),
])
def test_source_absence_requires_successful_well_formed_inventory(result, expected):
    wait = named(move_tasks()[1]["block"], "Wait until ND reports")
    context = {"nd_rehome_left": result, "_rm": {"value": [{"seed_ip": "192.0.2.1"}]}}
    rendered = expression_environment().from_string("{{ " + wait["until"] + " }}").render(**context)
    assert rendered is expected
    assert "ignore_errors" not in wait


def execute(tmp_path, scenario, remove_retries=2):
    state = tmp_path / "state.json"
    ips = ["192.0.2." + str(index) for index in range(1, 7)]
    state.write_text(json.dumps({"scenario": scenario, "original": ips, "present": ips,
                                 "selected_calls": [], "source_gets": 0, "rest_writes": [], "module_delete_calls": 0}))
    modules = tmp_path / "collections/ansible_collections/cisco/nd/plugins/modules"
    modules.mkdir(parents=True)
    for module in ("nd_rest", "nd_manage_switches", "nd_manage_vpc_pair"):
        (modules / (module + ".py")).write_text(FAKE_MODULE)
    moves = [{"fabric": "fixture-destination", "from_fabric": "fixture-source", "seed_ip": ip,
              "serial": "FIXTURE" + str(index + 1).zfill(4), "name": "fixture-" + str(index)}
             for index, ip in enumerate(ips)]
    values = {"ansible_python_interpreter": sys.executable, "nd_switch_apply": True,
              "_nd_switch_clock": guard()["vars"]["_nd_switch_clock"],
              "nd_missing_switches": moves, "nd_rehome_moves": moves,
              "nd_switch_rehome_supported_types": guard()["vars"]["nd_switch_rehome_supported_types"],
              "nd_switch_predelete_deploy": True, "nd_switch_settle_seconds": 0,
              "nd_switch_rehome_force_delete": False, "nd_switch_remove_retries": remove_retries,
              "nd_switch_remove_delay": 0, "nd_switch_rehome_retries": 1, "nd_switch_rehome_delay": 0}
    values.update({key: value for key, value in guard()['vars'].items()
                   if key.startswith('_nd_predelete_') or key.startswith('nd_switch_predelete_')})
    values.update(nd_switch_predelete_timeout_seconds=20,
                  nd_switch_predelete_call_timeout_seconds=1, nd_switch_predelete_poll_seconds=0,
                  nd_switch_predelete_deploy=True)
    if scenario in {'predelete_pending_forever', 'predelete_missing_switch', 'predelete_missing_status',
                    'predelete_duplicate_switch', 'predelete_bad_inventory'}:
        values['nd_switch_predelete_timeout_seconds'] = 3
    if scenario == 'predelete_disabled': values['nd_switch_predelete_deploy'] = False
    if scenario == 'predelete_outer_budget_expired': values['nd_switch_guard_timeout_seconds'] = 1
    tasks = move_tasks() + [{"name": "Destination add becomes eligible", "ansible.builtin.debug": {"msg": "DESTINATION_ADD_REACHED"}}]
    # Keep production no_log: assertions verify only sanitized diagnostics escape.
    play = tmp_path / "play.yaml"
    play.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local", "gather_facts": False,
                                    "vars": values, "tasks": tasks}], sort_keys=False))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\nretry_files_enabled=False\nhost_key_checking=False\n")
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_COLLECTIONS_PATH=str(tmp_path / "collections"),
                       ANSIBLE_COLLECTIONS_SCAN_SYS_PATH="False", ANSIBLE_STDOUT_CALLBACK="default",
                       ANSIBLE_CALLBACK_PLUGINS=str(tmp_path / "callbacks"), MOVE_FIXTURE_STATE=str(state),
                       ANSIBLE_LOCAL_TEMP=str(tmp_path / "local-tmp"), ANSIBLE_LOCAL_TMP=str(tmp_path / "local-tmp"),
                       ANSIBLE_REMOTE_TEMP=str(tmp_path / "remote-tmp"),
                       OBJC_DISABLE_INITIALIZE_FORK_SAFETY="YES")
    command = [str(Path(sys.executable).with_name("ansible-playbook")), "-i", "localhost,", str(play)]
    completed = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=60)
    return completed, json.loads(state.read_text())


@pytest.mark.parametrize("scenario,expected_calls,success", [
    ("accepted_207",1,True),("current_only",1,True),("accepted_202",1,True),("accepted_204",1,True),("accepted_200",1,True),
    ("partial_then_success",1,False),("partial_forever",1,False),("malformed_207",1,False),
    ("missing_response",1,False),("duplicate_identity",1,False),("wrong_identity",1,False),
    ("unknown_item_status",1,False),("missing_item",1,False),("bad_body",1,False),("body_errors",1,False),
    ("http_500",2,True),("http_429",2,True),("transport_timeout",2,True),("transient_forever",3,False),
    ("auth_failure",1,False),("http_400",1,False),("generic_failure",1,False),
    ("get_failure",1,False),("missing_gathered",1,False),("bad_gathered",1,False),("source_never_absent",1,False),
])
def test_actual_guard_immediate_response_and_hard_absence_gate(tmp_path, scenario, expected_calls, success):
    completed,state=execute(tmp_path,scenario)
    assert (completed.returncode==0) is success,completed.stdout+completed.stderr
    assert len(state["selected_calls"])==expected_calls,completed.stdout+completed.stderr
    assert state["module_delete_calls"]==0
    assert ("DESTINATION_ADD_REACHED" in completed.stdout) is success
    assert not any("force=true" in path for path in state["rest_writes"])
    assert "DO_NOT_PRINT_ME" not in completed.stdout and "RAW_PAYLOAD" not in completed.stdout
    if success:
        assert state["source_gets"]>=1
        assert "NDP_SWITCH_REMOVE_ACCEPTED" in completed.stdout
        assert re.search(r"NDP_SWITCH_PHASE: delete [0-9.]+ status=success", completed.stdout)
        assert re.search(r"NDP_SWITCH_PHASE: source-absence [0-9.]+ status=success", completed.stdout)
    elif scenario not in {"get_failure","missing_gathered","bad_gathered","source_never_absent"}:
        assert state["source_gets"]==0
        assert "NDP_SWITCH_REMOVE_REJECTED" in completed.stdout
        assert re.search(r"NDP_SWITCH_PHASE: delete [0-9.]+ status=failed", completed.stdout)
        assert "NDP_SWITCH_PHASE: source-absence" not in completed.stdout
    if scenario.startswith("partial"):
        assert "Please check Anomalies for possible reasons" in completed.stdout
        assert "ND-4102" in completed.stdout
        assert "fixture-" in completed.stdout
    if scenario=="http_400":
        assert "Recalculate and Deploy is required" in completed.stdout


@pytest.mark.parametrize("scenario,budget", [("transient_forever",0),("partial_then_success",5)])
def test_zero_transport_budget_and_terminal_refusal_never_add_extra_attempts(tmp_path,scenario,budget):
    completed,state=execute(tmp_path,scenario,remove_retries=budget)
    assert completed.returncode!=0
    assert len(state["selected_calls"])==1
    assert state["source_gets"]==0 and state["module_delete_calls"]==0
    assert "NDP_SWITCH_REMOVE_REJECTED" in completed.stdout
    assert "DESTINATION_ADD_REACHED" not in completed.stdout


@pytest.mark.parametrize("scenario", ("external", "campus", "destination_http_error"))
def test_incompatible_or_unreadable_destination_stops_before_any_mutation(tmp_path, scenario):
    completed, state = execute(tmp_path, scenario)
    assert completed.returncode != 0
    assert "NDP_SWITCH_REHOME_BLOCKED" in completed.stdout
    assert state["selected_calls"] == []
    assert state["rest_writes"] == []
    assert "DESTINATION_ADD_REACHED" not in completed.stdout


def test_destination_policy_is_checked_before_moves_and_before_missing_add_waits():
    tasks = guard()["tasks"]
    assert tasks.index(named(tasks, "Validate missing-switch destinations")) < tasks.index(named(tasks, "Move the roster switches out"))
    assert tasks.index(named(tasks, "Move the roster switches out")) < tasks.index(named(tasks, "Onboard the missing switches"))
    assert guard()["vars"]["nd_switch_rehome_force_delete"] is False
    assert guard()["vars"]["nd_switch_remove_retries"] == 2
    assert guard()["vars"]["nd_switch_remove_delay"] == 30
