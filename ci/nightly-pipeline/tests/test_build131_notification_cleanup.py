"""Exercise concise Webex rendering in all three local Jenkinsfiles offline."""
import json
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
    recap = source.split('def moduleTaskRecapText() {', 1)[1].split('\ndef moduleCaseSummaryRows()', 1)[0]
    assert "['ok', 'changed', 'unreachable', 'failed', 'skipped', 'rescued', 'ignored']" in recap
    assert "it.result != 'NOT_RUN' && it.test_type == 'integration'" in recap
    assert "row.reporting_status != 'ERROR'" in recap
    assert "invocation.status in ['OK', 'FAIL', 'SKIP']" in recap
    assert "INTEGRATION TARGET TASK COUNTS (not test-case counts)" in recap
    assert source.count('moduleTaskRecapText()') == 1
    assert 'Counts use the closed-log task recap' not in source
    assert "test_type: target[1]" in source
    assert "test_type: PLAYBOOK_FILES.contains(module) ? 'smoke' : 'integration'" in source
    assert "webexOutcomeCount([row], 'incomplete')" not in source
    assert "timeout(time: 20, unit: 'HOURS')" not in source
    assert "validResponseCodes: '200', timeout: 300" in source
    assert 'timeout: 45' not in source
    assert '--parse-timeout' not in source
    assert "timeout(time: 15, unit: 'MINUTES')" not in source
    assert 'MODULE_TIMEOUT' not in source
    assert 'SWITCHES_MODULE_TIMEOUT' not in source
    assert '\n                                TIMEOUT_CMD=' not in source
    assert ' ${TIMEOUT_CMD}' not in source
    assert 'MOD_TIMEOUT_CMD' not in source
    assert 'foldStructuredResultsWithRecovery()' in source
    recovery_call = source.index('                            foldStructuredResultsWithRecovery()')
    assert recovery_call < source.index('// Clean workspace - best effort')
    assert 'if (!ND_CASE_REPORT_READY && !recoverCaseReportFromMemory())' in source
    recovery = source.split('def recoverCaseReportFromMemory() {', 1)[1].split('\ndef foldStructuredResultsWithRecovery', 1)[0]
    assert 'if (!unvalidatedRows.isEmpty()) { return false }' in recovery
    assert "row.result != 'NOT_RUN' && (row.validated != true" in recovery
    assert 'NDP_CASE_REPORT_RECOVERY_EXHAUSTED' in source
    assert 'NDP_WEBEX_NOTIFICATION_SUPPRESSED' not in source
    assert "sendMinimalBuildNotification('CaseReportIncomplete')" in source
    assert "sendMinimalBuildNotification('CaseReportUnavailable')" not in source


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
def row = message.readLines().find { it.startsWith('fixture_module ') }.trim().split(/\s{2,}/)
assert row[1..4] == ['FAIL', '2', '1', '0']
assert !message.contains('Incomplete:')
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
def raw = 'FAIL|fixture_module|home|4.3|2|1|0|0|1m|Unsupported module parameter: timeout|iBGP|iBGP'
['module test cases', 'Ansible tasks'].each { unit ->
    def table = script.formatResultsTable(raw, unit)
    assert table.count('```') == 2
    def header = table.readLines().find { it.startsWith('Module ') }.trim().split(/\s{2,}/).toList()
    assert header == ['Module', 'iBGP', 'Passed', 'Failed', 'Skipped', 'Time',
                      'eBGP', 'Passed', 'Failed', 'Skipped', 'Time']
    assert !header.contains('Incomplete')
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
assert message.contains('Pipeline FAILED: the authored case report could not be verified.')
assert message.contains('CASE COUNTS NOT GENERATED')
assert message.contains('- FAIL | fixture module | iBGP') && message.contains('- NOT RUN | fixture module | eBGP')
assert !message.contains('Total passed cases:') && !message.contains('AUTHORED CASE RESULTS')
assert !message.contains('Unsupported module parameter') && !message.contains('classification=')
assert !logs.any { it.contains('NOTIFICATION_SUPPRESSED') }
assert script.binding.env.PIPELINE_FAILED == 'true'
assert script.currentBuild.result == 'FAILURE'
assert !logs.join('\n').contains('Unsupported module parameter: timeout')
assert !logs.join('\n').contains('classification=') && !logs.join('\n').contains('phase=pre')
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
assert sent[0].contains('CASE COUNTS NOT GENERATED')
['Total passed cases:', 'ok=11', 'Passed: 11', 'Failed: 2', 'Skipped: 4'].each { assert !sent[0].contains(it) }
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
assert !message.contains('Passed: 6657') && !message.contains('Failed: 18') && !message.contains('Skipped: 4438')
def row = message.readLines().find { it.startsWith('fixture_module ') }.trim().split(/\s{2,}/)
assert row[1..4] == ['FAIL','2','1','3']
''')


def test_notification_omits_task_recaps_for_all_modules(groovy_runner):
    groovy_runner(POST + r'''
script.MODULE_ACTIVITY_RESULTS.putAll([
    policy: [module:'policy_fixture', test_type:'integration', nd:'4.3', scope:'iBGP', round_label:'iBGP',
        result:'PASS', coverage:'COMPLETE', validated:true, case_totals:[started:1,passed:1,failed:0,skipped:0,incomplete:0],
        invocation:[status:'OK',counts:[ok:999,changed:999,unreachable:0,failed:0,skipped:999,rescued:0,ignored:0],
            integration_recap:[scope:'integration_target',counts:[ok:150,changed:21,unreachable:0,failed:0,skipped:125,rescued:0,ignored:7]]]],
    other: [module:'other_fixture', test_type:'integration', nd:'4.3', scope:'iBGP', round_label:'iBGP',
        result:'FAIL', coverage:'COMPLETE', validated:true, case_totals:[started:1,passed:0,failed:1,skipped:0,incomplete:0],
        invocation:[status:'FAIL',counts:[ok:20,changed:3,unreachable:0,failed:1,skipped:9,rescued:0,ignored:0]]],
    missing: [module:'missing_fixture', test_type:'integration', nd:'4.3', scope:'eBGP', round_label:'eBGP',
        result:'NOT_RUN', coverage:'UNKNOWN', case_totals:[:]]
])
script.run()
def message = sent.join('\n')
assert message.contains('policy_fixture') && message.contains('other_fixture')
assert !message.contains('INTEGRATION TARGET TASK COUNTS')
assert !message.contains('policy_fixture [iBGP]: ok=150')
assert !message.contains('other_fixture [iBGP]: unavailable')
assert !message.contains('ok=999')
assert !message.contains('missing_fixture [eBGP]: ok=0')
''')


def test_fallback_keeps_large_validated_table_within_webex_limit(groovy_runner):
    groovy_runner(POST + r'''
script.binding.env.ACTIVE_FABRIC_ROUNDS = 'iBGP + eBGP'
100.times { index ->
    def name = 'fixture_module_' + index
    script.MODULE_ACTIVITY_RESULTS[name] = [module:name, test_type:'integration', nd:'4.3', scope:'iBGP',
        round_label:'iBGP', result:'PASS', coverage:'COMPLETE',
        case_totals:[started:1,passed:1,failed:0,skipped:0,incomplete:0],
        base:'Ran', cleanup:'Ran', duration:'1m', failure:'']
}
def attempts = 0
def renderAttempts = 0
def fallbackTable = (0..<100).collect { index -> 'fixture_module_' + index + '_' + ('x' * 100) }.join('\n')
script.metaClass.formatResultsTable = { Object rows, Object unit ->
    renderAttempts++
    if (renderAttempts <= 2) { throw new SecurityException('temporary renderer failure') }
    fallbackTable
}
script.metaClass.sendWebexNotificationMessages = { Object messages ->
    attempts++
    sent.addAll(messages)
}
script.run()
assert renderAttempts == 3
assert attempts == 1 && sent.size() > 1 : [attempts, sent.size(), logs]
assert sent.every { it.length() <= 7000 }
def combined = sent.join('\n')
assert !combined.contains('AUTHORED INTEG TEST CASE COUNTS')
assert !combined.contains('Incomplete:')
100.times { index -> assert combined.contains('fixture_module_' + index) }
assert combined.contains('Detailed notification failed after report validation')
''')


def test_delivery_failure_after_attempt_is_not_retried(groovy_runner):
    groovy_runner(POST + r'''
def attempted = script.getClass().getDeclaredField('ND_WEBEX_DELIVERY_ATTEMPTED')
attempted.setAccessible(true)
def calls = 0
script.metaClass.sendWebexNotificationMessages = { Object messages ->
    calls++
    attempted.set(script, true)
    throw new IllegalStateException('delivery outcome unknown')
}
script.run()
assert calls == 1
assert logs.any { it.contains('delivery may be partial; no automatic retry') }
''')


def test_minimal_notification_propagates_interruption(groovy_runner):
    groovy_runner(POST + r'''
def interruption = loader.loadClass('org.jenkinsci.plugins.workflow.steps.FlowInterruptedException')
    .newInstance('injected interruption')
script.metaClass.webexModuleTotals = { Object rows -> throw interruption }
def caught = null
try { script.minimalBuildNotification('FixtureError') } catch (Exception error) { caught = error }
assert caught != null && caught.is(interruption)
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


def test_unready_report_still_sends_failure_notification_with_totals_withheld(groovy_runner):
    groovy_runner(POST + r'''
reportReadyField.set(script, false)
script.MODULE_ACTIVITY_RESULTS.putAll([
    planned: [module:'fixture_module', test_type:'integration', nd:'4.3', scope:'iBGP', round_label:'iBGP',
        result:'UNKNOWN', coverage:'UNKNOWN', case_totals:[:], failure:'result not collected; execution may be interrupted']
])
script.run()
assert sent.size() == 1 : logs
assert sent[0].contains('Pipeline FAILED') && sent[0].contains('CASE COUNTS NOT GENERATED')
assert sent[0].contains('- UNKNOWN | fixture module | iBGP')
assert logs.any { it.startsWith('NDP_CASE_REPORT_INCOMPLETE:') }
assert !logs.any { it.contains('NOTIFICATION_SUPPRESSED') }
assert script.binding.env.PIPELINE_FAILED == 'true'
''')


def test_failed_fallback_delivery_is_bounded_and_logged_without_aborting_post(groovy_runner):
    groovy_runner(POST + r'''
reportReadyField.set(script, false)
def attemptedField = script.getClass().getDeclaredField('ND_WEBEX_DELIVERY_ATTEMPTED')
attemptedField.setAccessible(true)
def calls = 0
// Failure before any HTTP request: exactly one bounded retry, then a logged failure.
script.metaClass.sendWebexNotificationMessages = { Object messages ->
    calls++
    throw new IllegalStateException('webex unavailable')
}
script.run()
assert calls == 2
assert logs.any { it.startsWith('NDP_WEBEX_NOTIFICATION_FAILED: java.lang.IllegalStateException') }

// Failure after an HTTP request was attempted: never re-post (avoids duplicate messages).
calls = 0
logs.clear()
script.metaClass.sendWebexNotificationMessages = { Object messages ->
    calls++
    attemptedField.set(script, true)
    throw new IllegalStateException('webex returned 500')
}
script.run()
assert calls == 1
assert logs.any { it.startsWith('NDP_WEBEX_NOTIFICATION_FAILED: java.lang.IllegalStateException') && it.contains('no automatic retry') }
''')


@pytest.mark.parametrize('variant', ['Jenkinsfile_nd_jenkins_script',
    'Jenkinsfile_nd_jenkins_script_temp_switches', 'Jenkinsfile_nd_jenkins_script_comm_list'])
def test_fallback_sender_withholds_counts_but_never_refuses_delivery(variant):
    source = (Path(__file__).resolve().parents[1] / variant).read_text()
    sender = source.split('def sendMinimalBuildNotification(reasonClass) {', 1)[1].split('\ndef sendFallbackNotificationOnce', 1)[0]
    assert 'refusing Webex fallback' not in sender and 'error(' not in sender
    assert 'NDP_CASE_COUNTS_WITHHELD' in sender
    for name in ('passed', 'failed', 'skipped'):
        assert 'validatedCaseNumber(counts.%s)' % name in sender
    assert sender.index('validatedCaseNumber(counts.skipped)') < sender.index('sendWebexNotificationMessages(')
    assert 'NOTIFICATION_SUPPRESSED' not in source


def test_minimal_notification_sends_with_unverified_counts_withheld(groovy_runner):
    groovy_runner(POST + r'''
reportReadyField.set(script, false)
script.MODULE_ACTIVITY_RESULTS['partial'] = [module:'fixture_module', test_type:'integration', nd:'4.3',
    scope:'iBGP', round_label:'iBGP', result:'FAIL', coverage:'UNKNOWN', case_totals:[:],
    invocation:[counts:[ok:42, failed:1, skipped:0]]]
script.sendMinimalBuildNotification('FixtureError')
assert sent.size() == 1
assert sent[0].contains('CASE COUNTS NOT GENERATED') && sent[0].contains('- FAIL | fixture module | iBGP')
assert !sent[0].contains('ok=42') && !sent[0].contains('Total passed cases:')
assert script.binding.env.PIPELINE_FAILED == 'true'
assert script.currentBuild.result == 'FAILURE'

// A report marked ready whose counts fail validation is downgraded, not silenced.
reportReadyField.set(script, true)
sent.clear()
script.sendMinimalBuildNotification('FixtureError')
assert sent.size() == 1 && sent[0].contains('CASE COUNTS NOT GENERATED')
assert logs.any { it.startsWith('NDP_CASE_COUNTS_WITHHELD:') }
assert reportReadyField.get(script) == false

// Even a rendering failure still produces the fixed failure notice.
script.metaClass.minimalBuildNotification = { Object reason -> throw new IllegalStateException('render failed') }
sent.clear()
script.sendMinimalBuildNotification('FixtureError')
assert sent.size() == 1 && sent[0].contains('the result report could not be rendered')
''')


def test_detailed_render_retries_once_before_using_fallback(groovy_runner):
    groovy_runner(POST + r'''
script.MODULE_ACTIVITY_RESULTS['verified'] = [module:'fixture_module', test_type:'integration', nd:'4.3',
    scope:'iBGP', round_label:'iBGP', result:'PASS', coverage:'COMPLETE', validated:true,
    case_totals:[started:1, passed:1, failed:0, skipped:0, incomplete:0], duration:'1m', failure:'']
def renderAttempts = 0
script.metaClass.formatResultsTable = { Object rows, Object unit ->
    renderAttempts++
    if (renderAttempts == 1) { throw new SecurityException('temporary renderer failure') }
    return '```\nfixture_module  OK  1\n```'
}
script.run()
assert renderAttempts == 2
assert sent.size() == 1 : logs
assert sent[0].contains('AUTHORED CASE RESULTS') && sent[0].contains('fixture_module')
assert !sent[0].contains('AUTHORED INTEG TEST CASE COUNTS')
assert logs.any { it.startsWith('NDP_DETAILED_NOTIFICATION_RETRY:') }
assert !logs.any { it.startsWith('NDP_DETAILED_NOTIFICATION_RETRY_FAILED:') }
''')


def test_detailed_render_retries_then_falls_back_with_validated_counts(groovy_runner):
    groovy_runner(POST + r'''
script.MODULE_ACTIVITY_RESULTS['verified'] = [module:'fixture_module', test_type:'integration', nd:'4.3',
    scope:'iBGP', round_label:'iBGP', result:'PASS', coverage:'COMPLETE', validated:true,
    case_totals:[started:1, passed:1, failed:0, skipped:0, incomplete:0], duration:'1m', failure:'']
def renderAttempts = 0
script.metaClass.formatResultsTable = { Object rows, Object unit ->
    renderAttempts++
    throw new SecurityException('renderer unavailable')
}
script.run()
assert sent.size() == 1 : logs
assert !sent[0].contains('Passed: 1') && !sent[0].contains('Failed: 0')
assert renderAttempts == 3
assert sent[0].contains('DETAILED TEST RESULTS UNAVAILABLE: table rendering failed.')
assert sent[0].contains('CASE COUNTS NOT GENERATED') == false
assert logs.count { it.startsWith('NDP_DETAILED_NOTIFICATION_RETRY:') } == 1
assert logs.any { it.startsWith('NDP_DETAILED_NOTIFICATION_RETRY_FAILED:') }
''')


def test_supplement_failures_cannot_withhold_a_validated_case_report(groovy_runner):
    groovy_runner(r'''
def reportReadyField = script.getClass().getDeclaredField('ND_CASE_REPORT_READY')
reportReadyField.setAccessible(true)
reportReadyField.set(script, false)
script.metaClass.sh = { Object ignored -> '' }
script.metaClass.readFile = { Map ignored -> script.writeReportingJson([
    rows: [[version_id:'ND43', module:'fixture_module', run_id:'current', test_type:'integration', nd:'4.3',
        scope:'iBGP', round_label:'iBGP', fabric:'home', result:'PASS', coverage:'COMPLETE', validated:true,
        case_totals:[started:3, passed:3, failed:0, skipped:0, incomplete:0], duration:'1m',
        phase_seconds:[execution:60], process_seconds:70, artifact:'out.txt', archive_status:'success']],
    failed:false, reporting_errors:[], skiplist_file:'skipped_tests_build_122.txt']) }
script.metaClass.archiveArtifacts = { Map ignored -> throw new RuntimeException('archive rejected') }
script.metaClass.formatResultsTable = { Object rows, Object unit -> throw new SecurityException('table rejected') }
script.foldStructuredResults()
assert reportReadyField.get(script) == true
assert script.MODULE_ACTIVITY_RESULTS['ND43|fixture_module|current'].case_totals.passed == 3
assert script.PHASE_TIMING_RESULTS['ND43|fixture_module|current'] == [execution:60, process_seconds:70]
assert script.binding.env.TOTAL_PASSED_COUNT == '3'
assert logs.any { it.startsWith('NDP_REPORT_SUPPLEMENT_FAILED: skip list; java.lang.RuntimeException') }
assert logs.any { it.startsWith('NDP_REPORT_SUPPLEMENT_FAILED: console case table; java.lang.SecurityException') }
assert script.binding.env.PIPELINE_FAILED == 'true'
''')


def test_unvalidated_counts_still_record_timings_skip_list_and_single_failure_reason(groovy_runner):
    groovy_runner(r'''
def reportReadyField = script.getClass().getDeclaredField('ND_CASE_REPORT_READY')
reportReadyField.setAccessible(true)
reportReadyField.set(script, false)
def archived = []
script.metaClass.sh = { Object ignored -> '' }
script.metaClass.readFile = { Map ignored -> script.writeReportingJson([
    rows: [[version_id:'ND43', module:'fixture_module', run_id:'current', test_type:'integration', nd:'4.3',
        scope:'iBGP', round_label:'iBGP', fabric:'home', result:'FAIL', coverage:'UNKNOWN', validated:false,
        case_totals:[:], duration:'1m', failure:'module base failed',
        phase_seconds:[execution:42], process_seconds:50]],
    failed:true, reporting_errors:[], skiplist_file:'skipped_tests_build_122.txt']) }
script.metaClass.archiveArtifacts = { Map options -> archived.add(options.artifacts.toString()) }
2.times {
    def caught = null
    try { script.foldStructuredResults() } catch (Exception failure) { caught = failure }
    assert caught?.message?.contains('NDP_CASE_COUNTS_UNRECOVERABLE')
}
assert reportReadyField.get(script) == false
assert script.PHASE_TIMING_RESULTS['ND43|fixture_module|current'] == [execution:42, process_seconds:50]
assert archived == ['skipped_tests_build_122.txt', 'skipped_tests_build_122.txt']
def notes = script.getClass().getDeclaredField('BUILD_FAILURE_REASON_BUF')
notes.setAccessible(true)
assert notes.get(script).count('fixture_module (iBGP): module base failed') == 1
''')


@pytest.mark.parametrize('variant', ['Jenkinsfile_nd_jenkins_script',
    'Jenkinsfile_nd_jenkins_script_temp_switches', 'Jenkinsfile_nd_jenkins_script_comm_list'])
def test_reporting_avoids_calls_outside_the_default_sandbox_whitelist(variant):
    source = (Path(__file__).resolve().parents[1] / variant).read_text()
    for rejected in ('.withIndex(', 'new LinkedHashMap(', '.intdiv(', 'new IllegalArgumentException('):
        assert rejected not in source, rejected


def test_case_report_retries_closed_evidence_before_marking_ready(groovy_runner):
    groovy_runner(r'''
def reportReadyField = script.getClass().getDeclaredField('ND_CASE_REPORT_READY')
reportReadyField.setAccessible(true)
reportReadyField.set(script, false)
def aggregateAttempts = 0
def preparationAttempts = 0
script.metaClass.foldStructuredResults = {
    aggregateAttempts++
    if (aggregateAttempts == 1) { throw new RuntimeException('transient aggregate read') }
    reportReadyField.set(script, true)
}
script.metaClass.publishStructuredArtifacts = { preparationAttempts++ }
script.foldStructuredResultsWithRecovery()
assert aggregateAttempts == 2 && preparationAttempts == 1
assert reportReadyField.get(script) == true
''')


def test_memory_recovery_requires_complete_numeric_rows_and_keeps_three_count_table(groovy_runner):
    groovy_runner(POST + r'''
reportReadyField.set(script, false)
script.MODULE_ACTIVITY_RESULTS.putAll([
    verified: [module:'fixture_module', test_type:'integration', nd:'4.3', scope:'iBGP', round_label:'iBGP',
        result:'FAIL', coverage:'INCOMPLETE', validated:true,
        case_totals:[started:2,passed:1,failed:0,skipped:0,incomplete:1],
        base:'Ran', cleanup:'Ran', duration:'1m', failure:''],
    unreached: [module:'unreached_module', test_type:'integration', nd:'4.3', scope:'iBGP', round_label:'iBGP',
        result:'NOT_RUN', coverage:'UNKNOWN', validated:false, case_totals:[:], duration:'-']
])
assert script.webexModuleTotals(script.MODULE_ACTIVITY_RESULTS.values().toList()) == [passed:'1',failed:'0',skipped:'0']
assert script.moduleCaseSummaryRows().contains('fixture_module')
script.run()
assert sent.size() == 1 : logs
def message = sent[0]
assert !message.contains('AUTHORED INTEG TEST CASE COUNTS')
def row = message.readLines().find { it.startsWith('fixture_module ') }.trim().split(/\s{2,}/)
assert row[1..4] == ['FAIL', '1', '0', '0']
assert !message.contains('Incomplete:')
assert logs.any { it.startsWith('NDP_CASE_REPORT_RECOVERED_FROM_VALIDATED_ROWS:') }
assert reportReadyField.get(script) == true
assert script.binding.env.TOTAL_PASSED_COUNT == '1'
assert script.binding.env.TOTAL_FAILED_COUNT == '0'
reportReadyField.set(script, false)
script.MODULE_ACTIVITY_RESULTS.verified.coverage = 'UNKNOWN'
assert !script.recoverCaseReportFromMemory()
assert reportReadyField.get(script) == false
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


def test_build174_blocked_round_folds_to_a_complete_detailed_notification(groovy_runner, tmp_path):
    from test_nd_reporting_pipeline_smoke import blocked_round, publish_all, record_blocked_modules, run_passing_module
    queue, log_dir, cli = blocked_round(tmp_path)
    record_blocked_modules(tmp_path, 'Jenkinsfile_nd_jenkins_script', queue, log_dir)
    run_passing_module(cli, log_dir)
    aggregate = publish_all(cli)
    assert aggregate['reporting_errors'] == []
    encoded = json.dumps(aggregate).replace('\\', '\\\\').replace("'", "\\'")
    groovy_runner(POST + "def aggregateText = '" + encoded + "'\n" + r'''
reportReadyField.set(script, false)
script.metaClass.sh = { Object ignored -> '' }
script.metaClass.readFile = { Map ignored -> aggregateText }
script.metaClass.archiveArtifacts = { Map ignored -> null }
script.foldStructuredResultsWithRecovery()
assert reportReadyField.get(script) == true : logs
script.run()
assert sent.size() == 1 : logs
def message = sent[0]
assert message.contains('AUTHORED CASE RESULTS')
assert message.contains('nd_blocked') && message.contains('nd_example')
assert message.readLines().find { it.startsWith('nd_blocked ') }.contains('NOT_RUN')
assert !message.contains('CASE COUNTS NOT GENERATED')
assert !logs.any { it.contains('NOTIFICATION_SUPPRESSED') || it.startsWith('NDP_CASE_REPORT_INCOMPLETE') }
assert script.binding.env.PIPELINE_FAILED == 'true'
''')


def test_module_recap_does_not_use_whole_invocation_counts():
    for name in ("Jenkinsfile_nd_jenkins_script", "Jenkinsfile_nd_jenkins_script_temp_switches",
                 "Jenkinsfile_nd_jenkins_script_comm_list"):
        source = (Path(__file__).resolve().parents[1] / name).read_text()
        recap = source.split('def moduleTaskRecapText() {', 1)[1].split('\ndef moduleCaseSummaryRows()', 1)[0]
        assert 'integration_recap' in recap
        assert 'invocation.counts' not in recap


@pytest.mark.parametrize('variant', ['Jenkinsfile_nd_jenkins_script',
    'Jenkinsfile_nd_jenkins_script_temp_switches', 'Jenkinsfile_nd_jenkins_script_comm_list'])
def test_webex_table_preserves_incomplete_case_evidence(variant):
    source = (Path(__file__).resolve().parents[1] / variant).read_text()
    formatter = source.split('def formatResultsTable(', 1)[1].split('\ndef splitWebexMessage(', 1)[0]
    assert 'CASE COVERAGE / RESULT DETAILS:' in formatter
    assert "it.status != 'SKIP' && it.note" in formatter
    assert "record.note.split('; ').findAll" in formatter
    assert "${record.module} (${record.label}): ${record.note}" not in formatter


def test_webex_omits_incomplete_case_notes_after_the_table(groovy_runner):
    groovy_runner(POST + r'''
script.MODULE_ACTIVITY_RESULTS.putAll([
    policy: [module:'nd_manage_policy_group', test_type:'integration', nd:'4.3', scope:'iBGP', round_label:'iBGP',
        result:'PASS', coverage:'INCOMPLETE', validated:true,
        case_totals:[started:121,passed:81,failed:0,skipped:0,incomplete:40], duration:'24m',
        failure:'PRIVATE_DIAGNOSTIC_CANARY'],
    missing: [module:'nd_manage_policy_group', test_type:'integration', nd:'4.3', scope:'eBGP', round_label:'eBGP',
        result:'NOT_RUN', coverage:'UNKNOWN', failure:'preflight blocked']
])
script.run()
def message = sent.join('\n')
def row = message.readLines().find { it.startsWith('nd_manage_policy_group ') }.trim().split(/\s{2,}/)
assert row[1..4] == ['OK', '81', '0', '0']
assert !message.contains('case coverage INCOMPLETE') && !message.contains('40 incomplete case(s)')
assert !message.contains('PRIVATE_DIAGNOSTIC_CANARY')
''')


def test_all_pipelines_use_only_the_table_for_webex_counts():
    root = Path(__file__).resolve().parents[1]
    paths = [root / name for name in ('Jenkinsfile_nd_jenkins_script',
        'Jenkinsfile_nd_jenkins_script_temp_switches', 'Jenkinsfile_nd_jenkins_script_comm_list')]
    paths += sorted((root / 'individual_jenkinsfiles').glob('Jenkinsfile_*'))
    assert len(paths) == 37
    for path in paths:
        source = path.read_text()
        notification = source.split('def webexResultsTable() {', 1)[1].split('\ndef runLintCheck()', 1)[0]
        assert notification.count('webexResultsTable()') == 2, path
        assert notification.count('validatedCaseNumber(') == 6, path
        assert 'table.substring(0, closingFence + 3)' in notification
        assert 'Total passed cases: ${caseTotals.passed} | PLAY RECAP failed tasks: ${recapTotals.failed}' in notification, path
        assert 'Total passed cases: ${counts.passed} | PLAY RECAP failed tasks: ${recapTotals.failed}' in notification, path
        for forbidden in ('INTEG PLAY RECAP COUNTS', 'AUTHORED INTEG TEST CASE COUNTS',
                'moduleTaskRecapText()', 'modulePlayRecapText()', 'Build result:'):
            assert forbidden not in notification, (path, forbidden)


def test_webex_shows_case_table_without_duplicate_recaps(groovy_runner):
    groovy_runner(POST + r'''
script.MODULE_ACTIVITY_RESULTS.putAll([
    ibgp: [module:'nd_manage_l3out', test_type:'integration', nd:'4.3', scope:'iBGP', round_label:'iBGP',
        result:'FAIL', coverage:'COMPLETE', validated:true, case_totals:[started:6,passed:5,failed:1,skipped:0,incomplete:0],
        invocation:[status:'FAIL', counts:[ok:339,changed:29,unreachable:0,failed:1,skipped:313,rescued:0,ignored:0]]],
    ebgp: [module:'nd_manage_l3out', test_type:'integration', nd:'4.3', scope:'eBGP', round_label:'eBGP',
        result:'NOT_RUN', coverage:'UNKNOWN', case_totals:[:]],
    missing: [module:'other_fixture', test_type:'integration', nd:'4.3', scope:'iBGP', round_label:'iBGP',
        result:'FAIL', coverage:'COMPLETE', validated:true, case_totals:[started:1,passed:0,failed:1,skipped:0,incomplete:0],
        invocation:[status:'FAIL', counts:[ok:1,failed:1,skipped:1]]]
])
script.run()
def message = sent.join('\n')
assert message.contains('Total passed cases: 5 | PLAY RECAP failed tasks: 2')
assert message.indexOf('Total passed cases:') < message.indexOf('AUTHORED CASE RESULTS:')
def row = message.readLines().find { it.startsWith('nd_manage_l3out ') }.trim().split(/\s{2,}/)
assert row[1..4] == ['FAIL', '5', '1', '0']
assert row[6] == 'NOT_RUN'
['INTEG PLAY RECAP COUNTS', 'AUTHORED INTEG TEST CASE COUNTS',
 'INTEGRATION TARGET TASK COUNTS', 'PLAY RECAP COUNTS BY MODULE', 'Build result:',
 '339 | 1 | 313', 'ok=339'].each { assert !message.contains(it) }
''')


def test_minimal_notification_withholds_counts_when_case_report_is_unavailable(groovy_runner):
    groovy_runner(POST + r'''
reportReadyField.set(script, false)
script.MODULE_ACTIVITY_RESULTS['executed'] = [module:'fixture_module', test_type:'integration',
    round_label:'iBGP', result:'FAIL', invocation:[status:'FAIL',counts:[ok:191,failed:0,skipped:124]]]
def message = script.minimalBuildNotification('FixtureError')
assert !message.contains('Passed (ok): 191')
assert message.contains('CASE COUNTS NOT GENERATED')
assert !message.contains('Total passed cases:')
assert !message.contains('AUTHORED INTEG TEST CASE COUNTS')
''')


def test_invalid_recaps_do_not_appear_in_the_case_table(groovy_runner):
    groovy_runner(POST + r'''
script.MODULE_ACTIVITY_RESULTS.putAll([
    valid: [module:'valid_fixture', test_type:'integration', round_label:'iBGP', result:'PASS', coverage:'COMPLETE',
        case_totals:[passed:4,failed:0,skipped:0], invocation:[status:'OK',counts:[ok:10,failed:0,skipped:2]]],
    invalid: [module:'invalid_fixture', test_type:'integration', round_label:'eBGP', result:'FAIL', coverage:'COMPLETE',
        case_totals:[passed:0,failed:1,skipped:0], invocation:[status:'FAIL',counts:[ok:3,failed:1]]],
    not_run: [module:'not_run_fixture', test_type:'integration', round_label:'eBGP', result:'NOT_RUN']
])
script.run()
def message = sent.join('\n')
assert message.contains('invalid_fixture') && message.contains('not_run_fixture')
assert message.contains('PLAY RECAP failed tasks: unavailable')
assert !message.contains('PLAY RECAP COUNTS BY MODULE')
''')


def test_recap_failures_include_failed_setup_for_unstarted_cases(groovy_runner):
    groovy_runner(r'''
def rows = [
    [test_type:'integration', result:'NOT_RUN', invocation:[status:'FAIL', counts:[ok:5,failed:1,skipped:2]]],
    [test_type:'integration', result:'PASS', invocation:[status:'OK', counts:[ok:10,failed:0,skipped:4]]],
    [test_type:'integration', result:'NOT_RUN', invocation:[status:'NOT_RUN', counts:[:]]]
]
assert script.webexPlayRecapTotals(rows) == [passed:'15', failed:'1', skipped:'6']
assert script.webexPlayRecapTotals(rows + [[test_type:'integration', result:'NOT_RUN', invocation:[status:'ERR', counts:[:]]]]).failed == 'unavailable'
rows[1].invocation.counts.remove('failed')
assert script.webexPlayRecapTotals(rows).failed == 'unavailable'
''')


def test_canonical_webex_totals_label_recap_failures_separately():
    source = (Path(__file__).resolve().parents[1] / 'Jenkinsfile_nd_jenkins_script').read_text()
    detailed = source.split('def prepareDetailedWebexNotification() {', 1)[1].split('\ndef minimalBuildNotification', 1)[0]
    fallback = source.split('def minimalBuildNotification(', 1)[1].split('\ndef runLintCheck()', 1)[0]
    assert detailed.index('webexPlayRecapTotals(') < detailed.index('PLAY RECAP failed tasks: ${recapTotals.failed}')
    assert detailed.index('Total passed cases: ${caseTotals.passed}') < detailed.index('AUTHORED CASE RESULTS:')
    assert fallback.index('webexPlayRecapTotals(') < fallback.index('PLAY RECAP failed tasks: ${recapTotals.failed}')
    assert fallback.index('Total passed cases: ${counts.passed}') < fallback.index('AUTHORED CASE RESULTS:')
