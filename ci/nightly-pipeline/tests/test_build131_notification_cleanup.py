"""Exercise concise Webex rendering in all three local Jenkinsfiles offline."""
from test_restored_webex_options import POST, groovy_runner


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
    ibgp: [module:'fixture_module', nd:'4.3', scope:'iBGP', round_label:'iBGP', fabric:'home',
        result:'FAIL', coverage:'COMPLETE', case_totals:[passed:2,failed:1,skipped:0],
        base:'Ran', cleanup:'Ran', duration:'1m', failure:'Unsupported module parameter: timeout'],
    ebgp: [module:'fixture_module', nd:'4.3', scope:'eBGP', round_label:'eBGP', fabric:'destination',
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
assert message.contains('/artifact/module_IBGP.txt')
assert message.contains('/artifact/skipped_tests_build_131.txt')
assert message.contains('/artifact/activity.txt')
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


def test_unknown_setup_case_counts_are_unavailable_without_changing_internal_evidence(groovy_runner):
    groovy_runner(POST + r'''
script.MODULE_ACTIVITY_RESULTS.putAll([
    ibgp: [module:'fixture_module', nd:'4.3', scope:'iBGP', round_label:'iBGP', fabric:'home',
        result:'FAIL', coverage:'UNKNOWN', case_totals:[:], base:'Failed', cleanup:'Not observed',
        failure:'module base: SETUP: Remove test values; Unsupported module parameter: timeout'],
    ebgp: [module:'fixture_module', nd:'4.3', scope:'eBGP', round_label:'eBGP', fabric:'destination',
        result:'NOT_RUN', coverage:'UNKNOWN', case_totals:[:],
        failure:'Switch membership pre-flight failed: phase=pre, classification=ANSIBLE_FAILED']
])
def original = script.writeReportingJson(script.MODULE_ACTIVITY_RESULTS)
assert script.moduleCaseTotals(script.MODULE_ACTIVITY_RESULTS.values().toList()).passed == '?'
script.run()
assert sent.size() == 1 : logs
def message = sent[0]
assert message.contains('Passed: N/A') && message.contains('Failed: N/A') && message.contains('Skipped: N/A')
assert !message.contains('RESULT DETAILS:')
assert !message.contains('Setup failed: unsupported parameter timeout')
assert !message.contains('fixture_module (eBGP): Not run: switch preparation failed')
assert !message.contains('[Console](https://jenkins.example/job/nd/122/console)')
assert message.contains('**Artifact links:**')
assert !message.contains('UNKNOWN') && !message.contains('case coverage')
assert !message.contains('classification=') && !message.contains('phase=pre')
def tableRows = message.readLines().findAll { it.startsWith('fixture_module ') }
assert tableRows.size() == 1
def cells = tableRows[0].trim().split(/\s{2,}/)
assert cells[1..4] == ['FAIL','N/A','N/A','N/A']
assert cells[6..9] == ['NOT_RUN','-','-','-']
assert !message.contains('home') && !message.contains('destination')
assert script.writeReportingJson(script.MODULE_ACTIVITY_RESULTS) == original
assert script.moduleCaseTotals(script.MODULE_ACTIVITY_RESULTS.values().toList()).passed == '?'
''')


def test_closed_log_recap_replaces_unavailable_case_counts(groovy_runner):
    groovy_runner(POST + r'''
script.MODULE_ACTIVITY_RESULTS.putAll([
    ibgp: [module:'fixture_module', nd:'4.3', scope:'iBGP', round_label:'iBGP', fabric:'home',
        result:'FAIL', coverage:'UNKNOWN', case_totals:[:], duration:'1m',
        invocation:[counts:[ok:11, failed:2, skipped:4, unreachable:0]],
        failure:'unlabelled module task'],
    ebgp: [module:'fixture_module', nd:'4.3', scope:'eBGP', round_label:'eBGP', fabric:'destination',
        result:'NOT_RUN', coverage:'UNKNOWN', case_totals:[:],
        failure:'Switch membership pre-flight failed']
])
script.run()
assert sent.size() == 1 : logs
def message = sent[0]
assert message.contains('Passed: 11') && message.contains('Failed: 2') && message.contains('Skipped: 4')
assert !message.contains('N/A  N/A  N/A') && !message.contains('N/A N/A N/A')
def tableRows = message.readLines().findAll { it.startsWith('fixture_module ') }
assert tableRows.size() == 1
def cells = tableRows[0].trim().split(/\s{2,}/)
assert cells[1..4] == ['FAIL','11','2','4']
assert cells[6..9] == ['NOT_RUN','-','-','-']
assert script.moduleCaseTotals(script.MODULE_ACTIVITY_RESULTS.values().toList()).passed == '?'
''')


def test_partial_case_counts_remain_explicit_in_the_readable_table(groovy_runner):
    groovy_runner(r'''
def raw = 'FAIL|fixture_module|home|4.3|3 + ?|?|0|1m|case coverage INCOMPLETE; 1 incomplete case(s)|iBGP'
def table = script.formatResultsTable(raw, 'module test cases')
assert table.contains('3 + unknown') && table.contains('N/A')
assert !table.contains('RESULT DETAILS:')
assert !table.contains('1 incomplete case(s)')
assert !table.contains('case coverage INCOMPLETE')
assert !table.contains('?')
assert raw.contains('3 + ?')
''')
