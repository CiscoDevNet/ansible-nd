"""Run production pre-delete tasks against fake ND modules, without network access."""
import re

import pytest

from test_switch_rehome_preflight import execute, expression_environment, guard, named, move_tasks


@pytest.mark.parametrize('scenario', [
    'predelete_pending_then_ready', 'predelete_deploy_207_items', 'predelete_deploy_207_message',
])
def test_predelete_waits_for_all_six_switches_before_removal(tmp_path, scenario):
    completed, state = execute(tmp_path, scenario)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert len(state['selected_calls']) == 1
    assert len(state['selected_calls'][0]) == 6
    assert state['predelete_polls'] >= (2 if scenario == 'predelete_pending_then_ready' else 1)
    assert 'NDP_SWITCH_PREDELETE_DEPLOY_CONFIRMED' in completed.stdout
    assert completed.stdout.index('NDP_SWITCH_PREDELETE_DEPLOY_CONFIRMED') < completed.stdout.index('NDP_SWITCH_REMOVE_ACCEPTED')


@pytest.mark.parametrize('scenario', [
    'predelete_save_400', 'predelete_save_module_failure', 'predelete_deploy_403',
    'predelete_deploy_207_refused', 'predelete_deploy_207_partial_message', 'predelete_deploy_bad_body',
    'predelete_inventory_403', 'predelete_inventory_module_failure', 'predelete_deployment_failed',
    'predelete_pending_forever', 'predelete_missing_switch', 'predelete_missing_status',
    'predelete_duplicate_switch', 'predelete_bad_inventory', 'predelete_call_timeout',
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
    if scenario in {'predelete_save_400', 'predelete_save_module_failure'}:
        assert not any(path.endswith('/switchActions/deploy') for path in state['rest_writes'])
    if scenario in {'predelete_inventory_403', 'predelete_deployment_failed'}:
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
    environment = expression_environment()
    environment.filters['regex_findall'] = lambda value, pattern: re.findall(pattern, value)
    response = {'status': 200, 'failed': True, 'current': {}}
    result = environment.from_string(guard()['vars']['_nd_predelete_response_valid']).render(
        _predelete_reply=response, _predelete_operation='config-save',
        _predelete_requested_ids=['FIXTURE0001'])
    assert result is False


def test_budget_reserves_a_final_call_and_gap_before_the_outer_timeout():
    task = named(move_tasks()[1]['block'], 'Start deploy-settle timing')
    result = expression_environment().from_string(
        task['ansible.builtin.set_fact']['_nd_phase_deploy_settle_budget']).render(
            _nd_switch_clock=100, _nd_switch_guard_started=40, nd_switch_guard_timeout_seconds=200,
            nd_switch_predelete_timeout_seconds=600, nd_switch_predelete_call_timeout_seconds=20,
            nd_switch_predelete_poll_seconds=10)
    assert result == 80
