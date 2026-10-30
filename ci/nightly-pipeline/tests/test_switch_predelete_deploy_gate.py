"""Run production pre-delete tasks against fake ND modules, without network access."""
import json

import pytest

from test_switch_rehome_preflight import execute, expression_environment, guard, named, move_tasks


@pytest.mark.parametrize('scenario', [
    'predelete_pending_then_ready', 'predelete_deploy_207_items', 'predelete_deploy_207_message',
    'predelete_deploy_207_partial_message', 'predelete_deploy_207_generic',
    'predelete_deploy_207_terminal', 'predelete_deploy_207_subset_items',
])
def test_predelete_waits_for_all_six_switches_before_removal(tmp_path, scenario):
    completed, state = execute(tmp_path, scenario)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert len(state['selected_calls']) == 1
    assert len(state['selected_calls'][0]) == 6
    assert state['predelete_polls'] >= (2 if scenario == 'predelete_pending_then_ready' else 1)
    assert 'NDP_SWITCH_PREDELETE_DEPLOY_CONFIRMED' in completed.stdout
    assert completed.stdout.index('NDP_SWITCH_PREDELETE_DEPLOY_CONFIRMED') < completed.stdout.index('NDP_SWITCH_REMOVE_ACCEPTED')
    assert 'NDP_SWITCH_PREDELETE_RESPONSE' in completed.stdout
    assert 'DO_NOT_PRINT_ME' not in completed.stdout and 'RAW_PAYLOAD' not in completed.stdout


@pytest.mark.parametrize('scenario', [
    'predelete_save_400', 'predelete_save_module_failure', 'predelete_save_code_200', 'predelete_deploy_403',
    'predelete_deploy_207_refused', 'predelete_deploy_bad_body',
    'predelete_deploy_code_200', 'predelete_deploy_code_207', 'predelete_deploy_nested_code',
    'predelete_deploy_mixed_items', 'predelete_deploy_unknown', 'predelete_deploy_not_completed',
    'predelete_deploy_unsuccessful', 'predelete_deploy_in_progress',
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
        assert not any(path.endswith('/switchActions/deploy') for path in state['rest_writes'])
    if scenario in {'predelete_inventory_403', 'predelete_inventory_code', 'predelete_deployment_failed'}:
        assert state['predelete_polls'] == 1
    if scenario in {'predelete_disabled', 'predelete_outer_budget_expired'}:
        assert state['rest_writes'] == []


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


def response_report(response):
    report = expression_environment().from_string(guard()['vars']['_nd_predelete_response_report']).render(
        _predelete_reply=response, _predelete_operation='deploy',
        _predelete_requested_ids=['FIXTURE0001','FIXTURE0002'])
    assert isinstance(report, dict)
    return report


@pytest.mark.parametrize('status', [
    'Configuration deployment completed', 'Configuration deployment completed for [FIXTURE0001].',
    'DEPLOYMENT: COMPLETED', 'Successfully completed deployment', 'DeploymentCompleted', 'success',
])
def test_sdk_completion_does_not_require_exact_wording_or_all_ids(status):
    result = response_report({'status':207,'current':{'status':status}})
    assert result['accepted'] is True and result['category'] == 'ACCEPTED_COMPLETION'


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
    'Configuration deployment not completed', 'Configuration deployment completed unsuccessfully',
    'Deployment completed with errors', 'Deployment in progress', 'Deployment queued',
    'Deployment refused', 'Deployment cancelled', 'No deployment completed', 'arbitrary response',
    'DeploymentFailed', 'DeployError', 'deploymentfailed', 'DeploymentNotCompleted',
])
@pytest.mark.parametrize('http', [200,207])
def test_negative_pending_and_ambiguous_completion_is_rejected(http, status):
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
    assert set(report) == {'operation','http_status','body_kind','has_embedded_error','requested_count','item_count','category','accepted'}
    assert len(encoded) < 300
    assert all(value not in encoded for value in ['FIXTURE0001','FIXTURE0002','DO_NOT_PRINT_ME','RAW_PAYLOAD'])


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
