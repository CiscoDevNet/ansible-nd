"""Exercise concise Webex rendering in all three local Jenkinsfiles offline."""
from pathlib import Path

import pytest

from test_restored_webex_options import POST, groovy_runner


@pytest.mark.parametrize('variant', ['Jenkinsfile_nd_jenkins_script',
    'Jenkinsfile_nd_jenkins_script_temp_switches', 'Jenkinsfile_nd_jenkins_script_comm_list'])
def test_integration_case_contract_never_uses_whole_invocation_recaps(variant):
    source = (Path(__file__).resolve().parents[1] / variant).read_text()
    counter = source.split('def webexOutcomeCount(rows, name) {', 1)[1].split('\ndef webexModuleTotals', 1)[0]
    assert 'recordedRecapCount' not in counter
    assert "test_type == 'integration'" in counter
    assert 'caseOutcomeCount(' in counter
    assert 'Counts use the closed-log task recap' not in source
    assert "test_type: target[1]" in source
    assert "test_type: PLAYBOOK_FILES.contains(module) ? 'smoke' : 'integration'" in source


def test_actual_notification_omits_global_notes_and_footers_but_retains_module_evidence(groovy_runner):
    groovy_runner(POST + r'''
def setField = { name, value ->
    def field = script.getClass().getDeclaredField(name)
    field.setAccessible(true)
    field.set(script, value)
}
setField('BUILD_FAILURE_REASON_BUF', '\nGLOBAL_NOTE_SHOULD_STAY_OUT_OF_WEBEX')
setField('TEST_RESULT_ARTIFACTS_BUF', 'fixture_module iBGP|module_IBGP.txt')
setField('SKIPLIST_FILES_BUF', 'Module skips|skipped_tests_build_131.txt')
script.MODULE_ACTIVITY_RESULTS.putAll([
    ibgp: [module:'fixture_module', test_type:'integration', nd:'4.3', scope:'iBGP', round_label:'iBGP', fabric:'home',
        result:'FAIL', coverage:'COMPLETE', case_totals:[passed:2,failed:1,skipped:0],
        base:'Ran', cleanup:'Ran', duration:'1m', failure:'Unsupported module parameter: timeout'],
    ebgp: [module:'fixture_module', test_type:'integration', nd:'4.3', scope:'eBGP', round_label:'eBGP', fabric:'destination',
        result:'NOT_RUN', coverage:'UNKNOWN', failure:'preflight blocked']
])
script.run()
assert sent.size() == 1 : logs
def message = sent[0]
['Execution/reporting notes:', 'GLOBAL_NOTE_SHOULD_STAY_OUT_OF_WEBEX',
 'Passed/Failed/Skipped =', 'Mixed/shared rows contain', '? = case count'].each {
    assert !message.contains(it)
}
assert !message.contains('RESULT DETAILS:')
assert !message.contains('unsupported parameter timeout')
assert message.contains('fixture_module') && message.contains('iBGP') && message.contains('eBGP')
assert message.contains('Passed: 2') && message.contains('Failed: 1') && message.contains('Skipped: 0')
assert message.contains('ansible-nd branch: fixture-owner:feature/example')
assert message.contains('ansible-nd commit: ' + ('a' * 40))
assert message.contains('[Build artifacts](https://jenkins.example/job/nd/122/artifact/)')
assert message.count('/artifact/') == 1
assert !message.contains('/artifact/module_IBGP.txt')
assert !message.contains('/artifact/skipped_tests_build_131.txt')
assert !message.contains('/artifact/activity.txt')
assert !logs.any { it.startsWith('NDP_DETAILED_NOTIFICATION_FAILED:') }
''')


def test_report_table_has_no_explanatory_footer_for_either_count_unit(groovy_runner):
    groovy_runner(r'''
def raw = 'FAIL|fixture_module|home|4.3|2|1|0|1m|Unsupported module parameter: timeout|iBGP'
['module test cases', 'Ansible tasks'].each { unit ->
    def table = script.formatResultsTable(raw, unit)
    assert table.count('```') == 2
    def header = table.readLines().find { it.startsWith('Module ') }.trim().split(/\s{2,}/).toList()
    assert header == ['Module', 'iBGP', 'Passed', 'Failed', 'Skipped', 'Time',
                      'eBGP', 'Passed', 'Failed', 'Skipped', 'Time']
    assert table.contains('fixture_module')
    assert !table.contains('RESULT DETAILS:')
    assert !table.contains('unsupported parameter timeout')
    assert !table.contains('Unsupported module parameter: timeout')
    assert table.contains('NOT_RUN') && table.contains('eBGP')
    assert !table.contains('Passed/Failed/Skipped =')
    assert !table.contains('Mixed/shared rows contain')
    assert !table.contains('? = case count')
}
''')


def test_missing_case_numbers_fail_validation_without_fabricating_counts(groovy_runner):
    groovy_runner(POST + r'''
script.MODULE_ACTIVITY_RESULTS.putAll([
    ibgp: [module:'fixture_module', test_type:'integration', nd:'4.3', scope:'iBGP', round_label:'iBGP', fabric:'home',
        result:'FAIL', coverage:'UNKNOWN', case_totals:[:], base:'Failed', cleanup:'Not observed',
        failure:'module base: SETUP: Remove test values; Unsupported module parameter: timeout'],
    ebgp: [module:'fixture_module', test_type:'integration', nd:'4.3', scope:'eBGP', round_label:'eBGP', fabric:'destination',
        result:'NOT_RUN', coverage:'UNKNOWN', case_totals:[:],
        failure:'Switch membership pre-flight failed: phase=pre, classification=ANSIBLE_FAILED']
])
def original = script.writeReportingJson(script.MODULE_ACTIVITY_RESULTS)
assert script.moduleCaseTotals(script.MODULE_ACTIVITY_RESULTS.values().toList()).passed == '?'
script.run()
assert sent.size() == 1 : logs
def message = sent[0]
assert message.contains('CASE COUNTS VALIDATION FAILED')
assert !message.contains('Passed:') && !message.contains('Failed:') && !message.contains('Skipped:')
assert !(message =~ /(?i)N\/A|unknown/)
assert script.binding.env.PIPELINE_FAILED == 'true'
assert !message.contains('RESULT DETAILS:')
assert !message.contains('Setup failed: unsupported parameter timeout')
assert !message.contains('fixture_module (eBGP): Not run: switch preparation failed')
assert !message.contains('[Console](https://jenkins.example/job/nd/122/console)')
assert !message.contains('case coverage')
assert !message.contains('classification=') && !message.contains('phase=pre')
def tableRows = message.readLines().findAll { it.startsWith('fixture_module ') }
assert tableRows.isEmpty()
assert !message.contains('home') && !message.contains('destination')
assert script.writeReportingJson(script.MODULE_ACTIVITY_RESULTS) == original
assert script.moduleCaseTotals(script.MODULE_ACTIVITY_RESULTS.values().toList()).passed == '?'
''')


def test_closed_log_recap_cannot_replace_unavailable_integration_case_counts(groovy_runner):
    groovy_runner(POST + r'''
script.MODULE_ACTIVITY_RESULTS.putAll([
    ibgp: [module:'fixture_module', test_type:'integration', nd:'4.3', scope:'iBGP', round_label:'iBGP', fabric:'home',
        result:'FAIL', coverage:'UNKNOWN', case_totals:[:], duration:'1m',
        invocation:[counts:[ok:11, failed:2, skipped:4, unreachable:0]],
        failure:'unlabelled module task'],
    ebgp: [module:'fixture_module', test_type:'integration', nd:'4.3', scope:'eBGP', round_label:'eBGP', fabric:'destination',
        result:'NOT_RUN', coverage:'UNKNOWN', case_totals:[:],
        failure:'Switch membership pre-flight failed']
])
script.run()
assert sent.size() == 1 : logs
def message = sent[0]
assert message.contains('CASE COUNTS VALIDATION FAILED')
assert !(message =~ /(?i)N\/A|unknown/)
assert !message.contains('Passed:') && !message.contains('Failed:') && !message.contains('Skipped:')
assert !message.contains('Passed: 11') && !message.contains('Failed: 2') && !message.contains('Skipped: 4')
def tableRows = message.readLines().findAll { it.startsWith('fixture_module ') }
assert tableRows.isEmpty()
assert script.moduleCaseTotals(script.MODULE_ACTIVITY_RESULTS.values().toList()).passed == '?'
''')


def test_integration_counts_ignore_recaps_and_explicit_non_integration_rows(groovy_runner):
    groovy_runner(POST + r'''
script.MODULE_ACTIVITY_RESULTS.putAll([
    authored: [module:'fixture_module', test_type:'integration', nd:'4.3', scope:'iBGP', round_label:'iBGP',
        result:'FAIL', coverage:'COMPLETE', case_totals:[passed:2,failed:1,skipped:3,incomplete:0],
        invocation:[counts:[ok:6657,failed:18,skipped:4438]], duration:'1m'],
    smoke: [module:'smoke_fixture.yaml', test_type:'smoke', nd:'4.3', scope:'iBGP', round_label:'iBGP', result:'PASS', coverage:'COMPLETE',
        case_totals:[passed:100,failed:10,skipped:200], invocation:[counts:[ok:1000,failed:10,skipped:2000]]],
    prerequisite: [module:'prerequisite_fixture', test_type:'prerequisites', nd:'4.3', scope:'iBGP', round_label:'iBGP', result:'PASS', coverage:'COMPLETE',
        case_totals:[passed:900,failed:0,skipped:900]],
    unreached: [module:'not_started', test_type:'integration', nd:'4.3', scope:'iBGP', round_label:'iBGP', result:'NOT_RUN', coverage:'UNKNOWN', case_totals:[:]]
])
assert script.webexModuleTotals(script.MODULE_ACTIVITY_RESULTS.values().toList()) == [passed:'2',failed:'1',skipped:'3']
script.run()
assert sent.size() == 1 : logs
def message = sent[0]
assert message.contains('Passed: 2') && message.contains('Failed: 1') && message.contains('Skipped: 3')
assert !message.contains('Passed: 6657') && !message.contains('Failed: 18') && !message.contains('Skipped: 4438')
def row = message.readLines().find { it.startsWith('fixture_module ') }.trim().split(/\s{2,}/)
assert row[1..4] == ['FAIL','2','1','3']
''')


def test_integration_counts_keep_unknown_types_partial_coverage_and_measured_zero_explicit(groovy_runner):
    groovy_runner(r'''
def zero = [test_type:'integration',result:'PASS',coverage:'COMPLETE',case_totals:[passed:0,failed:0,skipped:0]]
assert script.webexModuleTotals([zero]) == [passed:'0',failed:'0',skipped:'0']
assert script.webexModuleTotals([[test_type:'integration',result:'NOT_RUN']]) == [passed:'0',failed:'0',skipped:'0']
assert script.webexModuleTotals([[test_type:'smoke',result:'PASS',case_totals:[passed:50]]]) == [passed:'0',failed:'0',skipped:'0']
def untypedFailure = null
try { script.webexModuleTotals([[result:'PASS',case_totals:[passed:50,failed:0,skipped:0]]]) }
catch (Exception failure) { untypedFailure = failure }
assert untypedFailure?.message?.contains('NDP_CASE_COUNTS_UNRECOVERABLE')
def partial = [test_type:'integration',result:'FAIL',coverage:'PARTIAL',case_totals:[:],
    identified_testcase_totals:[passed:2,failed:1,skipped:0,incomplete:1],invocation:[counts:[ok:800,failed:2,skipped:600]]]
def partialFailure = null
try { script.webexModuleTotals([partial]) } catch (Exception failure) { partialFailure = failure }
assert partialFailure?.message?.contains('NDP_CASE_COUNTS_UNRECOVERABLE')
''')


def test_results_table_refuses_missing_case_numbers(groovy_runner):
    groovy_runner(r'''
def raw = 'FAIL|fixture_module|home|4.3|3 + ?|?|0|1m|case coverage INCOMPLETE; 1 incomplete case(s)|iBGP'
def caught = null
try { script.formatResultsTable(raw, 'module test cases') } catch (Exception failure) { caught = failure }
assert caught?.message?.contains('NDP_CASE_COUNTS_UNRECOVERABLE')
assert raw.contains('3 + ?')
''')


def test_notification_cannot_publish_totals_before_report_preparation_finishes(groovy_runner):
    groovy_runner(POST + r'''
reportReadyField.set(script, false)
script.run()
assert sent.size() == 1
def message = sent[0]
assert message.contains('CASE COUNTS VALIDATION FAILED')
assert !message.contains('Passed:') && !message.contains('Failed:') && !message.contains('Skipped:')
assert !message.contains('DETAILED TEST RESULTS')
assert !(message =~ /(?i)N\/A|unknown/)
assert script.binding.env.PIPELINE_FAILED == 'true'
''')


def test_activity_artifact_refuses_missing_integration_case_numbers(groovy_runner):
    groovy_runner(r'''
def caught = null
try {
    script.formatModuleActivityTable([[module:'fixture_module',test_type:'integration',
        result:'FAIL',coverage:'UNKNOWN',case_totals:[:]]], '140')
} catch (Exception failure) { caught = failure }
assert caught?.message?.contains('NDP_CASE_COUNTS_UNRECOVERABLE')
''')
