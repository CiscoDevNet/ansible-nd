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
        if a['path'].endswith('/deploymentFreeze'):
            frozen = scenario == 'startup_frozen' or scenario == 'startup_freeze_after_deploy' and any(path.endswith('/actions/deploy') for path in s['rest_writes'])
            finish(changed=False, status=200, current={'deploymentFreeze':frozen, 'private':'RAW_PAYLOAD'})
        if a['path'].endswith('/softwareUpdatePlan/summary'):
            fabric = a['path'].split('/fabrics/', 1)[1].split('/', 1)[0]
            groups = [{'installStatus':'inProgress'}] if scenario == 'startup_upgrade_active' else []
            finish(changed=False, status=200, current={'softwareUpdateSummary':{'fabricName':fabric, 'updatePlanStatus':'none'}, 'updateGroups':groups, 'private':'RAW_PAYLOAD'})
        if '/anomalies/details?' in a['path']:
            s['anomaly_reads'] = s.get('anomaly_reads', 0) + 1
            anomalies = []
            if scenario.startswith('startup_warning_'):
                copies = len(s.get('copy_requests', []))
                active = not copies or scenario == 'startup_warning_persists' or s['anomaly_reads'] == 2
                anomalies = [{'fabricName':'fixture-source', 'cleared':not active,
                              'anomalyString':'Switch [fixture/FIXTURE0006]: ~Periodic "copy run start" has been skipped on the switch due to an active deployment, maintenance mode, or deployment disable mode.'}]
            if scenario.startswith('leaf_tor_') and s['selected_calls']:
                anomalies = [{'fabricName':'fixture-source', 'cleared':False,
                              'anomalyString':'Switch [FIXTURE'+str(index).zfill(4)+']: Please perform Recalculate and Deploy to complete Leaf-ToR unpairing before deleting the leaf switch from the fabric.'}
                             for index in (5, 6)]
                if scenario == 'leaf_tor_foreign_anomaly':
                    for anomaly in anomalies: anomaly['fabricName'] = 'another-fabric'
                if scenario == 'leaf_tor_cleared':
                    for anomaly in anomalies: anomaly['cleared'] = True
                if scenario == 'leaf_tor_other_anomaly':
                    for anomaly in anomalies: anomaly['anomalyString'] = 'Unrelated interface warning'
                if scenario == 'leaf_tor_wrong_identity':
                    anomalies[-1]['anomalyString'] = anomalies[-1]['anomalyString'].replace('FIXTURE0006', 'FIXTURE00060')
                if scenario == 'leaf_tor_partial_anomalies': anomalies.pop()
                if scenario == 'leaf_tor_anomaly_read_failure':
                    fail(status=503, msg='Anomaly lookup failed password=DO_NOT_PRINT_ME')
            finish(changed=False, status=200, current={'anomalies':anomalies})
        if a['path'].endswith('/switches'):
            last_action = s['rest_writes'][-1].rsplit('/', 1)[-1] if s['rest_writes'] else ''
            if last_action != 'deploy':
                s['readiness_reads'] = s.get('readiness_reads', 0) + 1
                rows = [{'switchId':'FIXTURE'+str(index+1).zfill(4),
                         'additionalData':{'systemMode':'normal','configSyncStatus':'inSync'}}
                        for index, address in enumerate(s['original']) if address in s['present']]
                if scenario in ('startup_active_then_idle', 'startup_active_forever'):
                    busy = s['readiness_reads'] == 1 or scenario == 'startup_active_forever'
                    rows.append({'switchId':'OTHER0001', 'additionalData':{'systemMode':'normal','configSyncStatus':'deploymentInProgress' if busy else 'inSync'}})
                if scenario.startswith('startup_maintenance_') or scenario == 'startup_mode_refused':
                    for row in rows[-2:]:
                        if not s.get('mode_changed') or scenario == 'startup_maintenance_stuck':
                            row['additionalData'].update(systemMode='maintenance', intendedSystemMode='maintenance', discoveredSystemMode='maintenance')
                    if s.get('mode_changed') and s.get('mode_polls', 0) == 0:
                        s['mode_polls'] = 1
                        rows[-1]['additionalData'].update(systemMode='inconsistent', intendedSystemMode='normal', discoveredSystemMode='maintenance', configSyncStatus='deploymentInProgress')
                if scenario == 'startup_missing_mode': rows[-1]['additionalData'].pop('systemMode')
                if scenario == 'startup_migration': rows[-1]['additionalData']['systemMode'] = 'migration'
                s['last_active'] = any(row['additionalData']['configSyncStatus'] == 'deploymentInProgress' for row in rows)
                s['last_non_normal'] = any(row['additionalData'].get('systemMode') != 'normal' for row in rows)
                finish(changed=False, status=200, current={'switches':rows})
            s['predelete_polls'] = s.get('predelete_polls', 0) + 1
            if scenario == 'predelete_call_timeout':
                import time
                time.sleep(3)
            rows = [{'switchId':'FIXTURE'+str(index+1).zfill(4),
                     'additionalData':{'systemMode':'normal','configSyncStatus':'inSync'}}
                    for index, address in enumerate(s['original']) if address in s['present']]
            if scenario == 'leaf_tor_retry_pending' and s['selected_calls']:
                rows[-1]['additionalData']['configSyncStatus'] = 'pending'
            if scenario == 'predelete_pending_then_ready' and s['predelete_polls'] == 1 or scenario in ('predelete_pending_forever', 'predelete_deploy_async_not_ready'):
                rows[-1]['additionalData']['configSyncStatus'] = 'pending'
            if scenario == 'predelete_deployment_failed': rows[-1]['additionalData']['configSyncStatus'] = 'failed'
            if scenario == 'predelete_missing_switch': rows = rows[:-1]
            if scenario in ('predelete_missing_status', 'predelete_subset_missing_status', 'predelete_deploy_unknown_missing_status'): rows[-1]['additionalData'].pop('configSyncStatus')
            if scenario == 'predelete_duplicate_switch': rows[-1] = dict(rows[0])
            if scenario == 'startup_late_out_of_sync' and s['predelete_polls'] > 1:
                rows[-1]['additionalData']['configSyncStatus'] = 'outOfSync'
            body = {'switches':rows}
            if scenario == 'predelete_inventory_code': body.update(code=400, message='password=DO_NOT_PRINT_ME RAW_PAYLOAD')
            if scenario == 'predelete_bad_inventory': body = {'switches':None}
            if scenario == 'predelete_inventory_module_failure': fail(status=200, current=body, msg='password=DO_NOT_PRINT_ME')
            finish(changed=False, status=403 if scenario == 'predelete_inventory_403' else 200, current=body)
        code = 500 if scenario == 'destination_http_error' else 200
        kind = 'externalConnectivity' if scenario == 'external' else 'vxlanCampus' if scenario == 'campus' else 'vxlanEbgp'
        finish(changed=False, status=code, current={'management':{'type':kind}})
    s['rest_writes'].append(a['path'])
    if not a['path'].endswith('/switchActions/remove'):
        if '/switchActions/changeSystemMode?' in a['path']:
            assert a['content']['mode'] == 'normal' and not s.get('last_active')
            requested = a['content']['switchIds']
            s.setdefault('mode_requests', []).append(requested)
            s['mode_changed'] = scenario != 'startup_mode_refused'
            finish(changed=True, status=207, current={'items':[{'switchId':identity, 'status':'failed' if scenario == 'startup_mode_refused' else 'success', 'message':'password=DO_NOT_PRINT_ME'} for identity in requested]})
        if a['path'].endswith('/actions/copyRunStart'):
            requested = a['content']['switchIds']
            assert not s.get('last_active') and not s.get('last_non_normal')
            s.setdefault('copy_requests', []).append(requested)
            refused = scenario == 'startup_copy_refused' or scenario == 'startup_copy_after_deploy_refused' and len(s['copy_requests']) == 2
            finish(changed=True, status=207, current={'results':[{'switchId':identity, 'status':'failed' if refused else 'success', 'description':'password=DO_NOT_PRINT_ME' if refused else 'Deployment completed'} for identity in requested], 'private':'RAW_PAYLOAD'})
        if a['path'].endswith('/actions/configSave') and scenario == 'predelete_save_400':
            fail(status=400, msg='Save refused password=DO_NOT_PRINT_ME', current={'error':'RAW_PAYLOAD'})
        if a['path'].endswith('/actions/configSave') and scenario == 'predelete_save_module_failure':
            fail(status=200, current={}, msg='password=DO_NOT_PRINT_ME')
        if a['path'].endswith('/actions/configSave') and scenario == 'predelete_save_code_200':
            finish(changed=True, status=200, current={'code':400, 'message':'password=DO_NOT_PRINT_ME RAW_PAYLOAD'})
        if a['path'].endswith('/actions/deploy'):
            assert a['content'] == {}
            if scenario == 'leaf_tor_deploy_fails' and s['selected_calls']:
                fail(status=403, msg='Remediation deploy denied password=DO_NOT_PRINT_ME')
            deploy_ids = ['FIXTURE'+str(index+1).zfill(4) for index in range(len(s['original']))]
            responses = {
                'predelete_deploy_207_generic': (207, {'status':'Configuration deployment completed', 'note':'password=DO_NOT_PRINT_ME RAW_PAYLOAD'}),
                'predelete_deploy_207_terminal': (207, {'status':'success'}),
                'predelete_deploy_207_subset_items': (207, {'items':[{'switchId':deploy_ids[0], 'status':'success'}]}),
                'predelete_subset_missing_status': (207, {'status':'Configuration deployment completed for ['+deploy_ids[0]+'].'}),
                'predelete_deploy_code_200': (200, {'code':400, 'message':'password=DO_NOT_PRINT_ME RAW_PAYLOAD'}),
                'predelete_deploy_code_207': (207, {'code':400, 'message':'password=DO_NOT_PRINT_ME RAW_PAYLOAD'}),
                'predelete_deploy_nested_code': (207, {'status':'Configuration deployment completed', 'details':{'error':{'code':400, 'message':'password=DO_NOT_PRINT_ME'}}}),
                'predelete_deploy_mixed_items': (207, {'items':[{'switchId':identity, 'status':'failed' if index else 'success', 'message':'password=DO_NOT_PRINT_ME'} for index,identity in enumerate(deploy_ids)]}),
                'predelete_deploy_unknown': (207, {'status':'arbitrary unknown reply', 'message':'RAW_PAYLOAD'}),
                'predelete_deploy_unknown_mapping': (207, {'requestId':'RAW_PAYLOAD'}),
                'predelete_deploy_unknown_missing_status': (207, {'status':'arbitrary unknown reply'}),
                'predelete_deploy_async_not_ready': (207, {'status':'Deployment in progress'}),
                'predelete_deploy_207_pending_items': (207, {'items':[{'switchId':identity, 'status':'queued'} for identity in deploy_ids]}),
                'predelete_deploy_failed_status': (207, {'status':'DeploymentFailed'}),
                'predelete_deploy_not_completed': (207, {'status':'Configuration deployment not completed'}),
                'predelete_deploy_unsuccessful': (207, {'status':'Configuration deployment completed unsuccessfully'}),
                'predelete_deploy_in_progress': (207, {'status':'Configuration deployment in progress'}),
            }
            if scenario == 'predelete_deploy_jsondata_pending':
                finish(changed=True, status=207, jsondata={'status':'Deployment queued', 'requestId':'RAW_PAYLOAD'}, current={})
            if scenario == 'predelete_deploy_jsondata_error':
                finish(changed=True, status=207, jsondata={'error':{'code':400, 'message':'password=DO_NOT_PRINT_ME'}}, current={})
            if scenario in responses:
                http,body = responses[scenario]
                finish(changed=True,status=http,current=body)
            if scenario == 'predelete_deploy_403': fail(status=403, msg='Deploy denied password=DO_NOT_PRINT_ME')
            if scenario == 'predelete_deploy_207_refused':
                finish(changed=True, status=207, current={'items':[{'switchId':identity,'status':'failed','message':'password=DO_NOT_PRINT_ME'} for identity in deploy_ids]})
            if scenario == 'predelete_deploy_207_items':
                finish(changed=True, status=207, current={'items':[{'switchId':identity,'status':'success'} for identity in deploy_ids]})
            if scenario == 'predelete_deploy_207_message':
                finish(changed=True, status=207, current={'status':'Configuration deployment completed for ['+', '.join(deploy_ids)+'].'})
            if scenario == 'predelete_deploy_207_partial_message':
                finish(changed=True, status=207, current={'status':'Configuration deployment completed for ['+deploy_ids[0]+'].'})
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
    first_refusal = 2 if scenario == 'leaf_tor_multi_fabric' else 1
    if scenario.startswith('leaf_tor_') and (attempt == first_refusal or scenario == 'leaf_tor_forever'):
        refused = set(requested[-2:])
    items = [{'switchId': identity, 'status':'failed' if identity in refused else 'success',
              'errorCode':'ND-4102' if identity in refused else '0',
              'message': ('Failed to delete the switch['+identity+']. Please check Anomalies for possible reasons. password=DO_NOT_PRINT_ME') if identity in refused else 'Deleted successfully',
              'private': {'password':'RAW_PAYLOAD'}} for identity in requested]
    if refused:
        s['present'] = [address for index, address in enumerate(s['original'])
                        if address in s['present'] and 'FIXTURE'+str(index+1).zfill(4) not in set(requested)-refused]
    if scenario == 'leaf_tor_malformed_refusal': items[-1] = dict(items[0])
    if scenario == 'leaf_tor_auth_refusal':
        for item in items:
            if item['status'] == 'failed': item['message'] = 'Unauthorized. Check Anomalies.'
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
    if accepted:
        s['present'] = [address for index, address in enumerate(s['original'])
                        if address in s['present'] and 'FIXTURE'+str(index+1).zfill(4) not in requested]
    code=202 if scenario=='accepted_202' else 204 if scenario=='accepted_204' else 200 if scenario=='accepted_200' else 207
    if code==202:body={'jobId':'queued-fixture-job'}
    if code==204:body=None
    if code==200:body={}
    if scenario == 'current_only': finish(changed=True,status=code,current=body)
    finish(changed=True,status=code,current=body,jsondata=body)
if a['fabric_name']:
    if scenario.startswith('startup_'):
        if a['state'] == 'deleted':
            s.setdefault('vpc_unpairs', []).append(a['config'])
            finish(changed=True)
        finish(changed=False, gathered={'vpc_pairs':[{'switch_id':'FIXTURE0005', 'peer_switch_id':'FIXTURE0006'}]})
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


def test_predelete_copies_running_configuration_before_recalculate(tmp_path):
    completed, state = execute(tmp_path, 'accepted_207')
    assert completed.returncode == 0, completed.stdout + completed.stderr
    actions = [path.rsplit('/', 1)[-1] for path in state['rest_writes']]
    assert actions == ['copyRunStart', 'configSave', 'deploy', 'copyRunStart', 'remove']
    assert actions.index('copyRunStart') < actions.index('configSave') < actions.index('remove')
    assert state['copy_requests'] == [state['selected_calls'][0], state['selected_calls'][0]]


@pytest.mark.parametrize('scenario', ['startup_active_then_idle', 'startup_maintenance_recovers', 'startup_warning_clears'])
def test_predelete_resolves_startup_save_preconditions_before_recalculate(tmp_path, scenario):
    completed, state = execute(tmp_path, scenario)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert len(state['selected_calls']) == 1
    assert len(state['copy_requests']) == 2
    assert state['readiness_reads'] >= 2
    assert 'NDP_SWITCH_PREDELETE_STARTUP_SAVED' in completed.stdout
    if scenario == 'startup_maintenance_recovers':
        assert state['mode_requests'] == [['FIXTURE0005', 'FIXTURE0006']]
        assert '/switchActions/changeSystemMode?' in state['rest_writes'][0]
        assert state['mode_polls'] == 1
    if scenario == 'startup_warning_clears':
        assert state['anomaly_reads'] >= 4
    assert 'DO_NOT_PRINT_ME' not in completed.stdout and 'RAW_PAYLOAD' not in completed.stdout


@pytest.mark.parametrize('scenario', [
    'startup_frozen', 'startup_upgrade_active', 'startup_active_forever', 'startup_maintenance_stuck',
    'startup_mode_refused', 'startup_missing_mode', 'startup_migration', 'startup_copy_refused',
    'startup_warning_persists', 'startup_copy_after_deploy_refused', 'startup_freeze_after_deploy',
    'startup_late_out_of_sync',
])
def test_unsafe_startup_save_preconditions_never_remove_or_onboard(tmp_path, scenario):
    completed, state = execute(tmp_path, scenario)
    assert completed.returncode != 0, completed.stdout + completed.stderr
    assert state['selected_calls'] == []
    assert state['source_gets'] == 0
    assert 'DESTINATION_ADD_REACHED' not in completed.stdout
    assert 'NDP_SWITCH_PREDELETE_DEPLOY_BLOCKED' in completed.stdout
    if scenario in {'startup_frozen', 'startup_upgrade_active', 'startup_active_forever', 'startup_missing_mode', 'startup_migration'}:
        assert state['rest_writes'] == []
        assert state.get('vpc_unpairs', []) == []
    if scenario in {'startup_maintenance_stuck', 'startup_mode_refused'}:
        assert len(state['mode_requests']) == 1
        assert state.get('copy_requests', []) == []
        assert state.get('vpc_unpairs', []) == []
    if scenario in {'startup_copy_refused', 'startup_warning_persists'}:
        assert all(path.endswith('/actions/copyRunStart') for path in state['rest_writes'])
        assert state.get('vpc_unpairs', []) == []
    assert not any('force=true' in path for path in state['rest_writes'])
    assert 'DO_NOT_PRINT_ME' not in completed.stdout and 'RAW_PAYLOAD' not in completed.stdout


@pytest.mark.parametrize('scenario', ['leaf_tor_then_success', 'leaf_tor_forever', 'leaf_tor_deploy_fails'])
def test_leaf_tor_refusal_recalculates_deploys_and_retries_only_refused_switches(tmp_path, scenario):
    completed, state = execute(tmp_path, scenario)
    assert (completed.returncode == 0) is (scenario == 'leaf_tor_then_success'), completed.stdout + completed.stderr
    assert len(state['selected_calls']) == (1 if scenario == 'leaf_tor_deploy_fails' else 2)
    assert len(state['selected_calls'][0]) == 6
    if len(state['selected_calls']) == 2:
        assert state['selected_calls'][1] == ['FIXTURE0005', 'FIXTURE0006']
    assert state['anomaly_reads'] >= 2
    assert [path.rsplit('/', 1)[-1] for path in state['rest_writes'] if not path.endswith('/actions/copyRunStart')] == (
        ['configSave', 'deploy', 'remove', 'configSave', 'deploy']
        + ([] if scenario == 'leaf_tor_deploy_fails' else ['remove']))
    assert all(request == ['FIXTURE0005', 'FIXTURE0006'] for request in state['copy_requests'][2:])
    assert ('DESTINATION_ADD_REACHED' in completed.stdout) is (scenario == 'leaf_tor_then_success')
    assert state['module_delete_calls'] == 0
    assert 'DO_NOT_PRINT_ME' not in completed.stdout and 'RAW_PAYLOAD' not in completed.stdout


@pytest.mark.parametrize('scenario', [
    'leaf_tor_foreign_anomaly', 'leaf_tor_cleared', 'leaf_tor_other_anomaly',
    'leaf_tor_wrong_identity', 'leaf_tor_partial_anomalies', 'leaf_tor_anomaly_read_failure',
    'leaf_tor_malformed_refusal', 'leaf_tor_auth_refusal', 'leaf_tor_retry_pending',
])
def test_unverified_leaf_tor_remediation_never_retries_deletion(tmp_path, scenario):
    completed, state = execute(tmp_path, scenario)
    assert completed.returncode != 0, completed.stdout + completed.stderr
    assert len(state['selected_calls']) == 1
    assert state['source_gets'] == 0
    assert 'DESTINATION_ADD_REACHED' not in completed.stdout
    assert len([path for path in state['rest_writes'] if not path.endswith('/actions/copyRunStart')]) == (5 if scenario == 'leaf_tor_retry_pending' else 3)
    assert 'DO_NOT_PRINT_ME' not in completed.stdout and 'RAW_PAYLOAD' not in completed.stdout


def test_leaf_tor_retry_excludes_fabrics_whose_removal_already_succeeded(tmp_path):
    completed, state = execute(tmp_path, 'leaf_tor_multi_fabric')
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert state['selected_calls'] == [
        ['FIXTURE0001', 'FIXTURE0002', 'FIXTURE0003', 'FIXTURE0004'],
        ['FIXTURE0005', 'FIXTURE0006'], ['FIXTURE0005', 'FIXTURE0006'],
    ]
    accepted_fabric_writes = [path for path in state['rest_writes'] if '/fixture-accepted/' in path]
    assert [path.rsplit('/', 1)[-1] for path in accepted_fabric_writes] == ['copyRunStart', 'configSave', 'deploy', 'copyRunStart', 'remove']


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


def test_routine_maintenance_recovery_uses_controller_action_not_broken_collection_module():
    task = named(guard()['tasks'], 'Change each Maintenance-mode switch back to Normal')
    action = task['cisco.nd.nd_rest']
    switch = {'fabric':'fixture-source', 'serial':'FIXTURE0001', 'seed_ip':'192.0.2.1'}
    path = expression_environment().from_string(action['path']).render(_sw=switch)
    identity = expression_environment().from_string(action['content']['switchIds'][0]).render(_sw=switch)
    assert action['method'] == 'post'
    assert path == '/api/v1/manage/fabrics/fixture-source/switchActions/changeSystemMode?deploy=true&blocking=false'
    assert action['content']['mode'] == 'normal'
    assert identity == switch['serial']
    assert task['no_log'] is True


@pytest.mark.parametrize('envelope', ['current', 'jsondata'])
@pytest.mark.parametrize('body, expected', [
    ({'results':[{'switchId':'FIXTURE0001','status':'success'}, {'switchId':'FIXTURE0002','status':'success'}]}, True),
    ({'results':[{'switchId':'FIXTURE0001','status':'success'}]}, False),
    ({'results':[{'switchId':'FIXTURE0001','status':'success'}, {'switchId':'FIXTURE0001','status':'success'}]}, False),
    ({'results':[{'switchId':'FIXTURE0001','status':'success'}, {'switchId':'UNREQUESTED','status':'success'}]}, False),
    ({'results':[{'switchId':'FIXTURE0001','status':'success'}, {'switchId':'FIXTURE0002','status':'failed'}]}, False),
    ({'results':[{'switchId':'FIXTURE0001','status':'success'}, {'switchId':'FIXTURE0002','status':'queued'}]}, False),
    ({'results':[{'switchId':'FIXTURE0001','status':'success'}, {'switchId':'FIXTURE0002','status':'success','description':'Periodic save skipped due to active deployment'}]}, False),
    ({'results':[{'switchId':'FIXTURE0001','status':'success'}, {'switchId':'FIXTURE0002','status':'success','details':{'error':{'code':400}}}]}, False),
    ({'results':[{'switchId':'FIXTURE0001','status':'success'}, {'switchId':'FIXTURE0002','status':'success'}], 'error_code':400}, False),
    ({'results':[]}, False), ({'results':'success'}, False), ({'results':[None]}, False),
    ({}, False), (None, False),
])
def test_startup_save_requires_complete_successful_per_switch_results(envelope, body, expected):
    result = expression_environment().from_string(guard()['vars']['_nd_predelete_switch_action_ready']).render(
        _predelete_action_reply={'status':207, envelope:body}, _predelete_action_results='results',
        _predelete_requested_ids=['FIXTURE0001', 'FIXTURE0002'])
    assert result is expected


@pytest.mark.parametrize('status, mode, ready, normal', [
    ('inSync', 'normal', True, True), ('pending', 'normal', True, True),
    ('deploymentInProgress', 'normal', False, True), ('inProgress', 'normal', False, True),
    ('previewInProgress', 'normal', False, True), ('inSync', 'maintenance', True, False),
    ('inSync', 'migration', False, False), ('inSync', 'waiting', False, False),
    ('inSync', None, False, False), ('unexpected', 'normal', False, False),
])
def test_source_startup_save_readiness_uses_actual_modes_and_deployment_status(status, mode, ready, normal):
    reply = {'status':200, 'current':{'switches':[{'switchId':'FIXTURE0001',
             'additionalData':{'systemMode':mode, 'configSyncStatus':status}}]}}
    result = expression_environment().from_string(guard()['vars']['_nd_predelete_idle_report']).render(
        _predelete_inventory_reply=reply, _predelete_requested_ids=['FIXTURE0001'],
        _nd_predelete_inventory_error=False)
    assert result['ready'] is ready
    assert result['normal'] is normal
    assert result['maintenance_ids'] == (['FIXTURE0001'] if mode == 'maintenance' else [])


@pytest.mark.parametrize('status, expected', [
    ('none', True), ('ready', True), ('success', True), ('failed', True), ('skipped', True),
    ('inProgress', False), ('paused', False), ('unknown', False), (None, False),
])
def test_software_update_must_be_confirmed_inactive_before_mode_change_or_save(status, expected):
    reply = {'status':200, '_rf':'fixture-source', 'current':{
        'softwareUpdateSummary':{'fabricName':'fixture-source', 'updatePlanStatus':'none'},
        'updateGroups':[{'installStatus':status}]}}
    result = expression_environment().from_string(guard()['vars']['_nd_predelete_update_idle']).render(
        _predelete_update_reply=reply)
    assert result is expected


@pytest.mark.parametrize('fabric, identity, cleared, expected', [
    ('fixture-source', 'FIXTURE0001', False, False),
    ('fixture-source', 'FIXTURE0001', None, False),
    ('fixture-source', 'FIXTURE0001', True, True),
    ('another-fabric', 'FIXTURE0001', False, True),
    ('fixture-source', 'FIXTURE00010', False, True),
    ('fixture-source', 'UNREQUESTED', False, True),
])
def test_startup_save_anomaly_requires_exact_source_and_switch_identity(fabric, identity, cleared, expected):
    reply = {'status':200, 'current':{'anomalies':[{
        'fabricName':fabric, 'cleared':cleared,
        'anomalyString':'Switch [fixture/' + identity + ']: ~Periodic "copy run start" has been skipped.'}]}}
    result = expression_environment().from_string(guard()['vars']['_nd_predelete_copy_anomalies_clear']).render(
        _predelete_anomaly_reply=reply, _predelete_anomaly_fabric='fixture-source',
        _predelete_requested_ids=['FIXTURE0001'])
    assert result is expected


@pytest.mark.parametrize("status,body,expected", [
    (207, {"items":[{"switchId":"FIXTURE0001","status":"success"},{"switchId":"FIXTURE0002","status":"success"}]}, "accepted"),
    (207, {"items":[{"switchId":"FIXTURE0001","status":"failed"},{"switchId":"FIXTURE0002","status":"success"}]}, "refused"),
    (207, None, "invalid-response"), (207, {"items":[]}, "invalid-response"),
    (207, {"items":[None]}, "invalid-response"), (207, {"items":[{}]}, "invalid-response"),
    (207, {"items":"success"}, "invalid-response"), (207, [], "invalid-response"),
    (207, {"items":[{"switchId":"FIXTURE0001","status":"success"}]}, "invalid-response"),
    (207, {"items":[{"switchId":"FIXTURE0001","status":"success"},{"switchId":"FIXTURE0001","status":"success"}]}, "invalid-response"),
    (207, {"items":[{"switchId":"FIXTURE0001","status":"success"},{"switchId":"UNREQUESTED","status":"success"}]}, "invalid-response"),
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
    if scenario == 'leaf_tor_multi_fabric':
        for move in moves[:4]:
            move['from_fabric'] = 'fixture-accepted'
    values = {"ansible_python_interpreter": sys.executable, "nd_switch_apply": True,
              "_nd_switch_clock": guard()["vars"]["_nd_switch_clock"],
              "nd_missing_switches": moves, "nd_rehome_moves": moves,
              "nd_switch_rehome_supported_types": guard()["vars"]["nd_switch_rehome_supported_types"],
              "nd_switch_predelete_deploy": True, "nd_switch_settle_seconds": 0,
              "nd_switch_rehome_force_delete": False, "nd_switch_remove_retries": remove_retries,
              "nd_switch_remove_delay": 0, "nd_switch_rehome_retries": 1, "nd_switch_rehome_delay": 0}
    values.update({key: value for key, value in guard()['vars'].items()
                   if key.startswith('_nd_predelete_') or key.startswith('nd_switch_predelete_')})
    values.update(nd_switch_predelete_timeout_seconds=45,
                  nd_switch_predelete_call_timeout_seconds=1, nd_switch_predelete_poll_seconds=0,
                  nd_switch_predelete_deploy=True)
    if scenario in {'predelete_pending_forever', 'predelete_missing_switch', 'predelete_missing_status',
                    'predelete_duplicate_switch', 'predelete_bad_inventory', 'predelete_subset_missing_status',
                    'predelete_deploy_async_not_ready', 'predelete_deploy_unknown_missing_status', 'leaf_tor_retry_pending'}:
        values['nd_switch_predelete_timeout_seconds'] = 12
    if scenario in {'startup_active_forever', 'startup_maintenance_stuck', 'startup_warning_persists', 'startup_late_out_of_sync'}:
        values['nd_switch_predelete_timeout_seconds'] = 12
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
    completed = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=90)
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
