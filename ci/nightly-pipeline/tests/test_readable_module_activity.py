"""Execute the production TXT formatter with real Groovy; no services contacted."""
import os
from pathlib import Path
import subprocess
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ("Jenkinsfile_nd_jenkins_script",)


def method(source, name):
    start = source.index("def " + name + "(")
    return source[start:source.index("\n}\n", start) + 3]


@pytest.fixture(scope="module", params=VARIANTS)
def groovy(request, tmp_path_factory):
    java = Path(os.environ.get("ND_WEBEX_TEST_JAVA") or shutil.which("java") or "")
    jar = Path(os.environ.get("ND_WEBEX_TEST_GROOVY", ""))
    if not java.is_file() or not jar.is_file():
        pytest.skip("Local JVM and Groovy jar required")
    current = (ROOT / request.param).read_text()
    helpers = "\n".join(method(current, name) for name in (
        "tableColumnWidths", "activityCount", "activityCountSum", "caseOutcomeCount", "moduleCaseTotals", "activityStageLabel"))
    formatter = method(current, "formatModuleActivityTable")
    directory = tmp_path_factory.mktemp("readable-module-activity")
    sequence = 0

    def run(body):
        nonlocal sequence
        sequence += 1
        script = directory / f"test_{sequence}.groovy"
        script.write_text(helpers + "\n" + formatter + "\n" + FIXTURE + "\n" + body + '\nprintln("CHECK_PASSED")\n')
        result = subprocess.run([str(java), "-cp", str(jar), "groovy.ui.GroovyMain", str(script)],
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "CHECK_PASSED" in result.stdout
        return result.stdout

    return run


FIXTURE = r'''
def complete = [module: 'nd_manage_policy', nd: '4.3', scope: 'iBGP', round_label: 'iBGP',
    fabric: 'VXLAN_EVPN_Fabric', result: 'PASS', coverage: 'COMPLETE', validated: true,
    case_totals: [started: 7, passed: 7, failed: 0, skipped: 0, incomplete: 0],
    counts: [merged: [started: 2], replaced: [started: 1], overridden: [started: 1],
             deleted: [started: 2], gathered: [started: 1], other: [started: 0]],
    base: 'Ran', cleanup: 'Ran', artifact: 'reports/nd_manage_policy_ibgp.txt']
def dataRows = { text -> text.readLines().findAll { it.startsWith('|') }.drop(2).collect { line ->
    line.split(/\|/, -1).toList()[1..-2].collect { it.trim() }
} }
def actualRows = { text -> dataRows(text).findAll { !(it[2] in ['Subtotal', 'MAIN TOTAL']) } }
def totals = { text -> dataRows(text).find { it[2] == 'MAIN TOTAL' } }
'''


def test_fixed_width_rows_and_long_failure_details(groovy):
    groovy(r'''
def failed = new LinkedHashMap(complete)
failed.scope = failed.round_label = 'eBGP'; failed.result = 'FAIL'
failed.case_totals = [started: 7, passed: 6, failed: 1, skipped: 0, incomplete: 0]
failed.failure = 'Permanent discovery failure ' + ('long payload ' * 300)
def text = formatModuleActivityTable([complete, failed], '128')
def table = text.readLines().findAll { it.startsWith('|') }
assert table.collect { it.size() }.unique().size() == 1
assert table[0].contains('Result / failure') && table[0].contains('S.No.')
assert table.every { !it.contains('long payload') }
assert table[0].size() <= 200
assert text.replaceAll(/\s+/, ' ').contains(failed.failure.trim())
assert actualRows(text)*.getAt(2) == ['nd_manage_policy', '']
assert actualRows(text)*.getAt(3) == ['iBGP', 'eBGP']
assert actualRows(text)[1][12].startsWith('FAIL [')
assert text.contains('cases passed 6, failed 1')
assert text.readLines().findAll { it.contains('long payload') }.every { it.size() <= 110 }
''')


def test_started_case_counts_are_not_tasks_catalog_or_passes(groovy):
    groovy(r'''
complete.catalog_case_count = 2000; complete.invocation = [counts: [ok: 9999]]
def text = formatModuleActivityTable([complete], '128')
assert actualRows(text)[0][4..8] == ['2', '1', '1', '2', '1']
assert actualRows(text)[0][12].startsWith('PASS [')
assert text.contains('Source catalog: 2000 authored cases; this is inventory, not execution or pass evidence.')
assert !text.contains('9999')
assert text.contains('not passes, source inventory, pipeline tasks or API calls')
assert text.contains('1 validated executions / 1 selected; cases passed 7, failed 0')
''')


def test_counterpart_not_run_is_display_only(groovy):
    groovy(r'''
def text = formatModuleActivityTable([complete], '128')
assert actualRows(text).size() == 2
assert actualRows(text)[1][4..11] == ['-', '-', '-', '-', '-', '-', '-', '-']
assert actualRows(text)[1][12].startsWith('NOT_RUN [')
assert totals(text)[4..8] == ['2', '1', '1', '2', '1']
assert text.readLines().count { it.startsWith('MAIN TOTAL ') && it.contains('/ 1 selected;') } == 1
''')


def test_real_not_run_has_no_zero_case_claim(groovy):
    groovy(r'''
complete.result = 'NOT_RUN'; complete.validated = false
complete.failure = 'Round setup did not start'; complete.case_totals.passed = 999
def text = formatModuleActivityTable([complete], '128')
assert actualRows(text)[0][4..11] == ['-', '-', '-', '-', '-', 'NoRun', 'NoRun', '-']
assert totals(text)[4..11] == ['-', '-', '-', '-', '-', '-', '-', '-']
assert totals(text)[12] == 'NOT_RUN'
assert !text.contains('999')
assert text.contains('0 validated executions / 1 selected; no module execution; case counts not applicable.')
''')


def test_unknown_execution_counts_stay_unknown(groovy):
    groovy(r'''
complete.result = 'UNKNOWN'; complete.coverage = 'UNKNOWN'; complete.validated = false
complete.counts = [:]; complete.case_totals = [:]
def text = formatModuleActivityTable([complete], '128')
assert actualRows(text)[0][4..8] == ['?', '?', '?', '?', '?']
assert actualRows(text)[0][11] == '?'
assert actualRows(text)[0][12].startsWith('UNKNOWN !')
assert totals(text)[4] == '?'
assert text.contains('WARNING: case coverage UNKNOWN')
''')


def test_external_scope_keeps_both_rounds_and_separate_subtotals(groovy):
    groovy(r'''
complete.module = 'nd_vpc_pair.external'; complete.scope = 'External'
def second = new LinkedHashMap(complete); second.round_label = 'eBGP'
def text = formatModuleActivityTable([complete, second], '128')
assert actualRows(text)*.getAt(3) == ['External (iBGP)', 'External (eBGP)']
assert dataRows(text).findAll { it[2] == 'Subtotal' }*.getAt(3) == ['External (iBGP)', 'External (eBGP)']
assert totals(text)[4..8] == ['4', '2', '2', '4', '2']
assert text.contains('MAIN TOTAL All rounds/scopes: 2 validated executions / 2 selected; cases passed 14, failed 0')
''')


def test_incomplete_verification_cannot_look_like_complete_pass(groovy):
    groovy(r'''
complete.coverage = 'INCOMPLETE'
complete.case_totals = [started: 6, passed: 1, failed: 0, skipped: 0, incomplete: 5]
def text = formatModuleActivityTable([complete], '128')
assert actualRows(text)[0][12].startsWith('PASS !')
assert totals(text)[12] == 'P1+? F?'
assert text.contains('WARNING: 5 incomplete case(s); required verification was not fully observed.')
assert text.contains('case coverage INCOMPLETE')
''')


def test_partial_identifiers_remain_unknown_with_labeled_observed_subset(groovy):
    groovy(r'''
complete.coverage = 'PARTIAL'; complete.counts = [:]; complete.case_totals = [:]
complete.identified_testcase_totals = [started: 5, passed: 2, failed: 1, skipped: 2, incomplete: 2]
def text = formatModuleActivityTable([complete], '128')
assert actualRows(text)[0][4..8] == ['?', '?', '?', '?', '?']
assert actualRows(text)[0][11] == '2 + ?'
assert actualRows(text)[0][12].startsWith('PASS !')
assert text.contains('Identified observed subset, not full module totals:')
assert text.replaceAll(/\s+/, ' ').contains('passed 2, failed 1, skipped 2, incomplete 2.')
assert !text.contains('[started:')
assert text.contains('Individual skipped-case reasons unavailable')
''')


@pytest.mark.parametrize("with_reason", [True, False])
def test_skips_and_reason_evidence_remain_visible(groovy, with_reason):
    notes = "['Merged TC4: unsupported on this fabric']" if with_reason else "[]"
    groovy('complete.skipped_case_notes = ' + notes + r'''
complete.case_totals = [started: 7, passed: 7, failed: 0, skipped: 2, incomplete: 0]
complete.skipped_case_notes_truncated = true
def text = formatModuleActivityTable([complete], '128')
assert actualRows(text)[0][11] == '2'
assert text.contains('cases passed 7, failed 0, skipped 2')
assert text.contains('Additional skip details are in skipped_tests_build_128.txt.')
''' + ("assert text.contains('Skipped: Merged TC4: unsupported on this fabric')\n"
       if with_reason else "assert text.contains('Individual skipped-case reasons unavailable')\n"))


def test_all_66_executions_collated_once_and_artifacts_retained(groovy):
    groovy(r'''
def records = []
(1..33).each { number -> ['iBGP', 'eBGP'].each { scope ->
    def row = new LinkedHashMap(complete)
    row.module = 'nd_manage_example_' + number
    row.scope = row.round_label = scope
    row.artifact = "reports/${row.module}_${scope}.txt".toString()
    records.add(row)
} }
def text = formatModuleActivityTable(records, '128')
assert actualRows(text).size() == 66
assert actualRows(text).findAll { it[2] }.size() == 33
assert dataRows(text).findAll { it[2] == 'Subtotal' }.size() == 2
assert totals(text)[4..8] == ['132', '66', '66', '132', '66']
assert text.readLines().count { it.trim().startsWith('reports/nd_manage_example_') } == 66
assert text.contains('66 validated executions / 66 selected; cases passed 462, failed 0')
''')


def test_empty_plan_reports_no_execution_and_valid_shape(groovy):
    groovy(r'''
def text = formatModuleActivityTable([], '128')
assert actualRows(text).isEmpty()
assert totals(text)[12] == 'NOT_RUN'
assert text.contains('0 validated executions / 0 selected')
''')


def test_long_labels_and_runner_stage_evidence_stay_bounded(groovy):
    groovy(r'''
complete.module = 'nd_interface_ethernet_multicast_replication_very_long_fixture'
complete.scope = 'Shared_scope_with_a_very_long_fixture_description'; complete.round_label = 'eBGP'
complete.base = 'Ran (runner failed)'; complete.cleanup = 'Runner observed'
complete.result = 'REPORT_ERROR'; complete.failure = 'x' * 500
def text = formatModuleActivityTable([complete], '128')
assert text.readLines().findAll { it.startsWith('|') }.every { it.size() <= 200 }
assert actualRows(text)[0][9..10] == ['R.Fail', 'Runner']
assert actualRows(text)[0][12].size() <= 24
assert text.contains('Base: Ran (runner failed); Cleanup: Runner observed.')
assert text.readLines().findAll { it.contains('xxx') }.every { it.size() <= 110 }
assert text.replaceAll(/\s+/, ' ').contains(complete.module)
''')


def test_build128_failure_layout_preserves_unknowns_and_real_not_run(groovy, tmp_path):
    output = groovy(r'''
def first = [module: 'nd_manage_community_list', nd: '4.3', scope: 'iBGP', round_label: 'iBGP',
    fabric: 'VXLAN_EVPN_Fabric', result: 'FAIL', validated: false, coverage: 'UNKNOWN',
    counts: [:], case_totals: [:], base: 'Failed', cleanup: 'Not observed',
    failure: 'BASE SETUP - Remove test community lists failed before identified module cases were observed.']
def second = [module: first.module, nd: '4.3', scope: 'eBGP', round_label: 'eBGP',
    fabric: 'VXLAN_EVPN_Fabric_eBGP', result: 'NOT_RUN', validated: false, coverage: 'UNKNOWN',
    counts: [:], case_totals: [:], failure: 'Membership preflight exited with code 2 before module execution.']
def text = formatModuleActivityTable([first, second], '128')
assert actualRows(text).size() == 2
assert actualRows(text)[0][4..8] == ['?', '?', '?', '?', '?']
assert actualRows(text)[0][9..10] == ['Failed', 'Unseen']
assert actualRows(text)[1][4..8] == ['-', '-', '-', '-', '-']
assert actualRows(text)[1][9..10] == ['NoRun', 'NoRun']
assert totals(text)[4] == '?' && totals(text)[12] == 'P? F?'
assert text.contains('MAIN TOTAL All rounds/scopes: 0 validated executions / 2 selected; cases passed ?, failed ?')
assert text.readLines().findAll { it.startsWith('|') }.collect { it.size() }.unique().size() == 1
assert text.readLines().find { it.startsWith('|') }.size() <= 200
println('PREVIEW_START')
println(text)
println('PREVIEW_END')
''')
    preview = output.split("PREVIEW_START\n", 1)[1].split("PREVIEW_END", 1)[0]
    (tmp_path / "preview_build128_layout_fixture.txt").write_text(
        "LAYOUT FIXTURE based on described Build 128 failures; not a new test run or artifact re-analysis.\n\n" + preview)

def test_shared_scope_rows_remain_ibgp_then_ebgp_when_recovery_rows_arrive_first(groovy):
    groovy(r'''
def ibgp = new LinkedHashMap(complete)
ibgp.scope = 'External'; ibgp.round_label = 'iBGP'
def ebgp = new LinkedHashMap(ibgp)
ebgp.round_label = 'eBGP'
def text = formatModuleActivityTable([ebgp, ibgp], '128')
assert actualRows(text)*.getAt(3) == ['External (iBGP)', 'External (eBGP)']
assert totals(text)[4] == '4'
''')
