"""Run production pre-delete tasks against fake ND modules, without network access."""
import json
from pathlib import Path

import pytest

from test_switch_rehome_preflight import execute, expression_environment, guard, named, move_tasks


@pytest.mark.parametrize('filename', [
    'Jenkinsfile_nd_jenkins_script', 'Jenkinsfile_nd_jenkins_script_temp_switches',
    'Jenkinsfile_nd_jenkins_script_comm_list',
])
def test_active_pipelines_select_fabric_deployment_release(filename):
    source = (Path(__file__).resolve().parents[1] / filename).read_text()
    assert "def SWITCH_LIFECYCLE_CONSUL_PREFIX = 'releases/predelete-diagnostics-20261106'" in source


@pytest.mark.parametrize('scenario', [
    'predelete_pending_then_ready', 'predelete_deploy_207_items', 'predelete_deploy_207_message',
    'predelete_deploy_207_partial_message', 'predelete_deploy_207_generic',
    'predelete_deploy_207_terminal', 'predelete_deploy_207_subset_items',
    'predelete_deploy_unknown', 'predelete_deploy_not_completed', 'predelete_deploy_in_progress',
    'predelete_deploy_unknown_mapping', 'predelete_deploy_207_pending_items',
    'predelete_deploy_jsondata_pending',
])
def test_predelete_waits_for_all_six_switches_before_removal(tmp_path, scenario):
    completed, state = execute(tmp_path, scenario)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert len(state['selected_calls']) == 1
    assert len(state['selected_calls'][0]) == 6
    assert any(path.endswith('/actions/deploy') for path in state['rest_writes'])
    assert not any(path.endswith('/switchActions/deploy') for path in state['rest_writes'])
    assert state['predelete_polls'] >= (2 if scenario == 'predelete_pending_then_ready' else 1)
    assert 'NDP_SWITCH_PREDELETE_DEPLOY_CONFIRMED' in completed.stdout
    assert completed.stdout.index('NDP_SWITCH_PREDELETE_DEPLOY_CONFIRMED') < completed.stdout.index('NDP_SWITCH_REMOVE_ACCEPTED')
    assert 'NDP_SWITCH_PREDELETE_RESPONSE' in completed.stdout
    assert 'DO_NOT_PRINT_ME' not in completed.stdout and 'RAW_PAYLOAD' not in completed.stdout


@pytest.mark.parametrize('scenario', [
    'predelete_save_400', 'predelete_save_module_failure', 'predelete_save_code_200', 'predelete_deploy_403',
    'predelete_deploy_207_refused', 'predelete_deploy_bad_body',
    'predelete_deploy_code_200', 'predelete_deploy_code_207', 'predelete_deploy_nested_code',
    'predelete_deploy_mixed_items', 'predelete_deploy_unsuccessful', 'predelete_deploy_failed_status',
    'predelete_deploy_jsondata_error', 'predelete_deploy_async_not_ready', 'predelete_deploy_unknown_missing_status',
    'predelete_inventory_403', 'predelete_inventory_code', 'predelete_inventory_module_failure', 'predelete_deployment_failed',
    'predelete_pending_forever', 'predelete_missing_switch', 'predelete_missing_status',
    'predelete_duplicate_switch', 'predelete_bad_inventory', 'predelete_call_timeout', 'predelete_subset_missing_status',
    'predelete_disabled', 'predelete_outer_budget_expired',
])
def test_unconfirmed_predelete_gate_never_removes_or_onboards(tmp_path, scenario):
    completed, state = execute(tmp_path, scenario)
    assert completed.returncode != 0, completed.stdout + completed.stderr
    assert state['selected_calls'] == []
    assert state['source_gets'] == 0
    assert 'DESTINATION_ADD_REACHED' not in completed.stdout
    assert 'NDP_SWITCH_PREDELETE_DEPLOY_BLOCKED' in completed.stdout
    assert 'NDP_SWITCH_PREDELETE_DEPLOY_CONFIRMED' not in completed.stdout
    assert 'DO_NOT_PRINT_ME' not in completed.stdout and 'RAW_PAYLOAD' not in completed.stdout
    if scenario in {'predelete_save_400', 'predelete_save_module_failure', 'predelete_save_code_200'}:
        assert not any(path.endswith('/actions/deploy') for path in state['rest_writes'])
    if scenario in {'predelete_inventory_403', 'predelete_inventory_code', 'predelete_deployment_failed'}:
        assert state['predelete_polls'] == 1
    if scenario in {'predelete_disabled', 'predelete_outer_budget_expired'}:
        assert state['rest_writes'] == []
    if scenario in {'predelete_deploy_async_not_ready', 'predelete_deploy_unknown_missing_status'}:
        assert state['predelete_polls'] > 0
        assert 'ACCEPTED_FOR_POLLING' in completed.stdout
    if scenario in {'predelete_deploy_failed_status', 'predelete_deploy_jsondata_error'}:
        assert state.get('predelete_polls', 0) == 0


def test_late_positive_inventory_cannot_pass_the_final_gate():
    task = named(move_tasks()[1]['block'], 'Require fresh inSync evidence')
    environment = expression_environment()
    for condition in task['ansible.builtin.assert']['that']:
        result = environment.from_string('{{ ' + condition + ' }}').render(
            _nd_predelete_remaining=-0.01, _nd_predelete_inventory_ready=True)
        if result is False:
            break
    else:
        pytest.fail('A late inSync inventory passed the final deadline gate')


def test_response_checker_rejects_module_failure_even_with_http_200():
    response = {'status': 200, 'failed': True, 'current': {}}
    result = response_report(response)
    assert result['accepted'] is False and result['category'] == 'MODULE_FAILURE'


@pytest.mark.parametrize('scenario', ['predelete_save_module_failure', 'predelete_save_400', 'predelete_deploy_403'])
def test_failed_requests_emit_safe_diagnostics_before_stopping(tmp_path, scenario):
    completed, state = execute(tmp_path, scenario)
    assert completed.returncode != 0
    assert 'NDP_SWITCH_PREDELETE_RESPONSE' in completed.stdout
    assert 'failure_kind' in completed.stdout
    assert state['selected_calls'] == []
    assert 'DESTINATION_ADD_REACHED' not in completed.stdout
    assert 'DO_NOT_PRINT_ME' not in completed.stdout
    assert 'RAW_PAYLOAD' not in completed.stdout


@pytest.mark.parametrize('reply,expected', [
    ({'status': 401, 'msg': 'secret DO_NOT_PRINT_ME'}, 'AUTHENTICATION_OR_AUTHORIZATION'),
    ({'status': 403}, 'AUTHENTICATION_OR_AUTHORIZATION'),
    ({'status': 504}, 'TIMEOUT'),
    ({'msg': 'request timed out password=DO_NOT_PRINT_ME'}, 'TIMEOUT'),
    ({'status': 400}, 'HTTP_REJECTION'),
    ({'msg': 'configuration dependency RAW_PAYLOAD'}, 'CONFIGURATION_OR_DEPENDENCY'),
    ({'failed': True}, 'MODULE_FAILURE'),
])
def test_request_failure_kind_never_contains_payloads(reply, expected):
    task = named(move_tasks()[1]['block'], 'Report sanitized failed pre-delete request')
    value = expression_environment().from_string(task['vars']['_nd_predelete_failure_kind']).render(
        _predelete_reply=reply)
    assert value == expected



def response_report(response):
    report = expression_environment().from_string(guard()['vars']['_nd_predelete_response_report']).render(
        _predelete_reply=response, _predelete_operation='deploy',
        _predelete_requested_ids=['FIXTURE0001','FIXTURE0002'])
    assert isinstance(report, dict)
    return report


@pytest.mark.parametrize('status', [
    'Configuration deployment completed', 'Configuration deployment completed for [FIXTURE0001].',
    'DEPLOYMENT: COMPLETED', 'Successfully completed deployment', 'DeploymentCompleted', 'success',
    'Deployment in progress', 'Deployment queued', 'Configuration deployment not completed',
    'No deployment completed', 'arbitrary response', 'DeploymentNotCompleted',
])
def test_sdk_non_error_response_only_authorizes_fresh_inventory_polling(status):
    result = response_report({'status':207,'current':{'status':status}})
    assert result['accepted'] is True and result['category'] == 'ACCEPTED_FOR_POLLING'


@pytest.mark.parametrize('body', [
    {'code':0}, {'code':400}, {'error':{'code':400}}, {'errors':[{'message':'RAW_PAYLOAD'}]},
    {'status':'Configuration deployment completed','details':{'code':400}},
    {'errorCode':'ND-4102'}, {'error_code':400},
])
@pytest.mark.parametrize('http', [200,207])
def test_embedded_errors_are_rejected_before_inventory_or_removal(http, body):
    result = response_report({'status':http,'current':body})
    assert result['accepted'] is False and result['category'] == 'EMBEDDED_ERROR'
    assert result['has_embedded_error'] is True


@pytest.mark.parametrize('status', [
    'Configuration deployment completed unsuccessfully', 'Deployment completed with errors',
    'Deployment refused', 'Deployment cancelled', 'DeploymentFailed', 'DeployError', 'deploymentfailed',
])
@pytest.mark.parametrize('http', [200,207])
def test_explicit_failure_status_is_rejected_before_inventory_polling(http, status):
    result = response_report({'status':http,'current':{'status':status}})
    assert result['accepted'] is False


@pytest.mark.parametrize('body', [None,{},[],{'items':[]},{'items':[{}]},
    {'items':[{'switchId':'UNREQUESTED','status':'success'}]},
    {'items':[{'switchId':'FIXTURE0001','status':'success'},{'switchId':'FIXTURE0001','status':'success'}]},
    {'items':[{'switchId':'FIXTURE0001','status':'success'},{'switchId':'FIXTURE0002','status':'failed'}]},
    {'status':True}])
def test_ambiguous_or_partial_failure_207_is_rejected(body):
    assert response_report({'status':207,'current':body})['accepted'] is False


def test_public_diagnostics_contain_only_bounded_categories_and_counts():
    report = response_report({'status':207,'current':{'status':'Configuration deployment completed for [FIXTURE0001].',
        'message':'password=DO_NOT_PRINT_ME', 'private':{'value':'RAW_PAYLOAD'}}})
    encoded = json.dumps(report)
    assert set(report) == {'operation','http_status','body_kind','response_field','status_present','status_kind',
                           'has_embedded_error','requested_count','item_count','category','accepted'}
    assert len(encoded) < 400
    assert report['response_field'] == 'current' and report['status_present'] is True
    assert all(value not in encoded for value in ['FIXTURE0001','FIXTURE0002','DO_NOT_PRINT_ME','RAW_PAYLOAD'])


@pytest.mark.parametrize('field', ['jsondata', 'current'])
def test_sdk_response_envelopes_accept_non_error_207_mapping_for_polling(field):
    result = response_report({'status':207,field:{'requestId':'RAW_PAYLOAD'}})
    assert result['accepted'] is True and result['category'] == 'ACCEPTED_FOR_POLLING'
    assert result['response_field'] == field and result['status_present'] is False
    assert 'RAW_PAYLOAD' not in json.dumps(result)


def test_raw_jsondata_error_cannot_be_hidden_by_sanitized_current():
    result = response_report({'status':207,'jsondata':{'code':400},'current':{'status':'success'}})
    assert result['category'] == 'EMBEDDED_ERROR' and result['accepted'] is False


@pytest.mark.parametrize('error', [{'code':400},{'error':{'code':400}},{'errors':['controller refusal']},
                                  {'errorCode':'ND-4102'},{'error_code':400}])
def test_inventory_error_indicator_is_always_boolean_even_with_in_sync_rows(error):
    body = {'switches':[{'switchId':'FIXTURE0001','additionalData':{'configSyncStatus':'inSync'}}], **error}
    indicator = expression_environment().from_string(guard()['vars']['_nd_predelete_inventory_error']).render(
        _predelete_inventory_reply={'status':200,'current':body})
    assert indicator is True


def test_budget_reserves_a_final_call_and_gap_before_the_outer_timeout():
    task = named(move_tasks()[1]['block'], 'Start deploy-settle timing')
    result = expression_environment().from_string(
        task['ansible.builtin.set_fact']['_nd_phase_deploy_settle_budget']).render(
            _nd_switch_clock=100, _nd_switch_guard_started=40, nd_switch_guard_timeout_seconds=200,
            nd_switch_predelete_timeout_seconds=600, nd_switch_predelete_call_timeout_seconds=20,
            nd_switch_predelete_poll_seconds=10)
    assert result == 80


@pytest.mark.parametrize('elapsed,expected', [(0, 900), (899, 1), (901, -1)])
def test_startup_save_has_independent_fifteen_minute_window(elapsed, expected):
    settings = guard()['vars']
    assert settings['nd_switch_predelete_copy_timeout_seconds'] == 900
    task = named(move_tasks()[1]['block'], 'Persist leaving switch configuration')
    remaining = expression_environment().from_string(task['vars']['_nd_predelete_remaining']).render(
        nd_switch_predelete_copy_timeout_seconds=900, _nd_predelete_copy_started=500,
        _nd_switch_clock=500 + elapsed, _nd_switch_guard_started=0,
        nd_switch_guard_timeout_seconds=3600, nd_switch_predelete_call_timeout_seconds=60,
        nd_switch_predelete_poll_seconds=10,
        _nd_phase_deploy_settle_started=0, _nd_phase_deploy_settle_budget=600)
    assert remaining == expected


def test_copy_wait_does_not_consume_the_deployment_poll_budget():
    remaining = expression_environment().from_string(guard()['vars']['_nd_predelete_remaining']).render(
        _nd_phase_deploy_settle_started=100, _nd_phase_deploy_settle_budget=600,
        _nd_switch_clock=1400, _nd_predelete_copy_elapsed_total=900,
        _nd_switch_guard_started=0, nd_switch_guard_timeout_seconds=3600,
        nd_switch_predelete_call_timeout_seconds=60, nd_switch_predelete_poll_seconds=10)
    assert remaining == 200


@pytest.mark.parametrize('reply,category', [
    ({'status': 503, 'current': {}}, 'HTTP_ERROR'),
    ({'status': 200, 'current': {'code': 400}}, 'API_ERROR_BODY'),
    ({'status': 200, 'current': {'other': []}}, 'INVALID_RESPONSE'),
    ({'status': 200, 'current': {'anomalies': [{}] * 200}}, 'PAGINATION_REQUIRED'),
    ({'status': 200, 'current': {'anomalies': ['PRIVATE_CANARY']}}, 'INVALID_RESPONSE'),
    ({'status': 200, 'current': {'anomalies': []}}, 'CLEAR'),
])
def test_startup_warning_diagnostic_classifies_unverifiable_responses(reply, category):
    report = expression_environment().from_string(guard()['vars']['_nd_predelete_copy_anomaly_report']).render(
        _predelete_anomaly_reply=reply, _predelete_anomaly_fabric='fixture',
        _predelete_requested_ids=['FIXTURE0001'])
    assert report['category'] == category
    assert 'PRIVATE_CANARY' not in json.dumps(report)
    assert len(json.dumps(report)) < 600


@pytest.mark.parametrize('cleared,failed,category', [
    (False, False, 'WARNING_ACTIVE'), (False, True, 'WARNING_ACTIVE'),
    (True, False, 'CLEAR'), ('true', False, 'CLEARANCE_UNVERIFIED'),
])
def test_startup_warning_diagnostic_distinguishes_active_warning_from_poll_failure(cleared, failed, category):
    reply = {'status': 200, 'failed': failed, 'current': {'anomalies': [{
        'fabricName': 'fixture', 'cleared': cleared,
        'anomalyString': '[FIXTURE0001] periodic Copy Run Start was skipped PRIVATE_CANARY'}]}}
    report = expression_environment().from_string(guard()['vars']['_nd_predelete_copy_anomaly_report']).render(
        _predelete_anomaly_reply=reply, _predelete_anomaly_fabric='fixture',
        _predelete_requested_ids=['FIXTURE0001'])
    assert report['category'] == category
    assert report['matching_records'] == 1
    assert 'PRIVATE_CANARY' not in json.dumps(report)
    assert 'FIXTURE0001' not in json.dumps(report)
