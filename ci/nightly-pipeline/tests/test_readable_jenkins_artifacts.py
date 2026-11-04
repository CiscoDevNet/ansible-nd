"""Execute artifact publication and aligned TXT selection without network access."""
import json
import os
from pathlib import Path
import subprocess

import pytest

from test_five_issue_pipeline_fixes import PRELUDE
from test_restored_webex_options import POST

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ("Jenkinsfile_nd_jenkins_script", "Jenkinsfile_nd_jenkins_script_temp_switches",
            "Jenkinsfile_nd_jenkins_script_comm_list")


@pytest.fixture(scope="module", params=VARIANTS)
def pipeline(request, tmp_path_factory):
    java = Path(os.environ.get("ND_WEBEX_TEST_JAVA", "/private/tmp/nd-local-groovy-runtime/jdk-21.0.13+9-jre/Contents/Home/bin/java"))
    jar = Path(os.environ.get("ND_WEBEX_TEST_GROOVY", "/private/tmp/nd-groovy-all-2.4.21.jar"))
    if not java.is_file() or not jar.is_file():
        pytest.skip("A local JVM and Groovy jar are required")
    directory = tmp_path_factory.mktemp("readable-artifacts")
    sequence = 0

    def run(body):
        nonlocal sequence
        sequence += 1
        script = directory / (str(sequence) + ".groovy")
        script.write_text(PRELUDE + "\n" + body + '\nprintln("CHECK_PASSED")\n')
        result = subprocess.run([str(java), "-cp", str(jar), "groovy.ui.GroovyMain",
                                 str(script), str(ROOT / request.param)],
                                text=True, capture_output=True, timeout=45)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "CHECK_PASSED" in result.stdout

    return run


PUBLISHER = r'''
def archived = []
int nextCalls = 0
script.binding.env.ND_REPORTING_RELATIVE_ROOT = 'fixture-reports'
script.metaClass.writeStructuredArchiveReceipt = { String relativePath, Map receipt -> null }
script.metaClass.sh = { Object options ->
    if (options instanceof Map && options.returnStdout) {
        nextCalls++
        return script.writeReportingJson([build: script.binding.getVariable('BUILD_NUMBER').toString(),
            run_id:'fixture-run', archive_attempts:2,
            executions:[[id:'fixture-job', files:selectedFiles, attempt:1]]])
    }
    return ''
}
script.metaClass.archiveArtifacts = { Map options -> archived.add(options.artifacts.toString()) }
script.metaClass.timeout = { Map options, Closure work -> work.call() }
script.metaClass.retry = { int attempts, Closure work -> work.call() }
script.metaClass.withEnv = { List entries, Closure work -> work.call() }
script.publishStructuredArtifacts()
'''


def test_publisher_archives_only_the_flat_round_labelled_module_log(pipeline):
    pipeline("def selectedFiles = ['test_output_fabric_ND43_IBGP_nd_example.txt']\n" + PUBLISHER + r'''
assert archived == selectedFiles
assert nextCalls == 1
assert !logs.any { it.startsWith('NDP_REPORTER_FAILED:') }
''')


@pytest.mark.parametrize("files", [
    ["fixture-reports/executions/log.txt"],
    ["test_output_fabric_ND43_EBGP_nd_example.txt", "log.summary.json"],
    ["../test_output_fabric_ND43_IBGP_nd_example.txt"],
    ["aggregate.json"],
])
def test_publisher_rejects_internal_metadata_and_unsafe_descriptors(pipeline, files):
    literal = json.dumps(json.dumps(files)).replace("$", "\\$")
    pipeline("def selectedFiles = script.parseReportingJson(" + literal + ")\n" + PUBLISHER + r'''
assert archived.isEmpty()
assert logs.any { it.startsWith('NDP_REPORTER_FAILED:') }
''')


def test_final_fold_publishes_the_combined_skip_list_and_no_internal_json(pipeline):
    pipeline(r'''
def archived = []
script.metaClass.sh = { Object options -> '' }
script.metaClass.readFile = { Map options ->
    script.writeReportingJson([rows: [], reporting_errors: [], failed: false,
        skiplist_file: 'skipped_tests_build_122.txt'])
}
script.metaClass.archiveArtifacts = { Map options -> archived.add(options.artifacts.toString()) }
script.foldStructuredResults()
assert archived == ['skipped_tests_build_122.txt']
assert script.SKIPLIST_FILES_BUF.contains('skipped_tests_build_122.txt')
assert !script.SKIPLIST_FILES_BUF.contains('progress')
''')


@pytest.mark.parametrize("valid", [True, False])
def test_final_fold_only_marks_report_ready_after_numeric_validation(pipeline, valid):
    pipeline("def validCounts = " + str(valid).lower() + "\n" + r'''
script.metaClass.sh = { Object options -> '' }
script.metaClass.readFile = { Map options ->
    script.writeReportingJson([rows: [[module:'fixture_module',test_type:'integration',
        version_id:'ND43',run_id:'fixture-run',nd:'4.3',scope:'iBGP',round_label:'iBGP',
        result:'PASS',coverage:validCounts ? 'COMPLETE' : 'UNKNOWN',
        case_totals:validCounts ? [started:2,passed:2,failed:0,skipped:0,incomplete:0] : [:]]],
        reporting_errors:[],failed:false,skiplist_file:'skipped_tests_build_122.txt'])
}
script.metaClass.archiveArtifacts = { Map ignored -> null }
def caught = null
try { script.foldStructuredResults() } catch (Exception failure) { caught = failure }
def field = script.getClass().getDeclaredField('ND_CASE_REPORT_READY')
field.setAccessible(true)
assert field.get(script) == validCounts
assert (caught == null) == validCounts
if (!validCounts) { assert caught.message.contains('NDP_CASE_COUNTS_UNRECOVERABLE') }
''')


def test_final_report_is_aligned_timing_txt_without_zip_or_duplicate_summary(pipeline):
    pipeline(r'''
def written = [:]
def archived = []
script.binding.env.LOG_BUNDLE_FILE = 'stale.zip'
script.metaClass.writeFile = { Map options -> written[options.file.toString()] = options.text.toString() }
script.metaClass.archiveArtifacts = { Map options -> archived.add(options.artifacts.toString()) }
script.metaClass.sh = { Object options -> throw new IllegalStateException('ZIP_OR_CONSOLE_DOWNLOAD_MUST_NOT_RUN') }
script.PHASE_TIMING_RESULTS.fixture = [prerequisites:1,execution:3601,cleanup:0,parsing:0.125,archiving:2]
script.MODULE_ACTIVITY_RESULTS.putAll([
    shortName:[module:'nd_example',nd:'4.3',round_label:'iBGP',phase_seconds:[execution:1,parsing:0.125]],
    longName:[module:'nd_interface_port_channel_trunk_host',nd:'4.3',round_label:'eBGP',
        phase_seconds:[prerequisites:1200,execution:3601,cleanup:2,parsing:0.125,archiving:10]]
])
script.SWITCH_LIFECYCLE_TIMINGS.addAll([
    [nd:'4.3',round:'iBGP',phase:'pre',seconds:10,exit_code:0],
    [nd:'4.3',round:'eBGP',phase:'home-fabric restore',seconds:1200,exit_code:2]
])
script.bundleAllLogs()
assert archived == ['pipeline_timing_build_122.txt'] : logs
assert written.keySet().toList() == ['pipeline_timing_build_122.txt']
assert script.binding.env.LOG_BUNDLE_FILE == ''
def text = written.values().first()
assert text.contains('nd_interface_port_channel_trunk_host')
assert text.contains('00h 00m 00.125s') && text.contains('01h 00m 01.000s')
assert !text.contains('reporting overlaps') && !text.contains('combined log bundle')
def positions = { String line -> (0..<line.size()).findAll { line.substring(it,it+1) == '|' } }
def sections = [text.split('MODULE / ROUND TIMINGS',2)[0],
    text.split('MODULE / ROUND TIMINGS',2)[1].split('SWITCH LIFECYCLE INVOCATIONS',2)[0],
    text.split('SWITCH LIFECYCLE INVOCATIONS',2)[1]]
sections.each { section ->
    def lines = section.readLines().findAll { it.contains('|') }
    assert lines.size() >= 3
    assert lines.every { positions(it) == positions(lines[0]) } : lines
    assert lines.every { it.length() == lines[0].length() } : lines
}
assert !logs.any { it.startsWith('NDP_TIMING_REPORT_FAILED:') }
''')


def test_notification_has_one_artifact_browser_link_without_duplicate_file_links(pipeline):
    pipeline(POST + r'''
def logsField = script.getClass().getDeclaredField('TEST_RESULT_ARTIFACTS_BUF')
logsField.setAccessible(true)
logsField.set(script, 'fixture_module iBGP|test_output_fabric_ND43_IBGP_fixture_module.txt')
def skipField = script.getClass().getDeclaredField('SKIPLIST_FILES_BUF')
skipField.setAccessible(true)
skipField.set(script, 'skipped_tests_build_122.txt')
script.run()
assert sent.size() == 1 : logs
def message = sent[0]
assert message.contains('[Build artifacts](https://jenkins.example/job/nd/122/artifact/)')
assert message.count('/artifact/') == 1
assert !message.contains('test_output_')
assert !message.contains('all-logs.zip') && !message.contains('All logs (zip)')
assert !message.contains('/artifact/activity.txt') && !message.contains('/artifact/skipped_tests_build_122.txt')
assert !logs.any { it.startsWith('NDP_DETAILED_NOTIFICATION_FAILED:') }
''')


def test_activity_table_keeps_full_module_names_and_consistent_column_alignment(pipeline):
    pipeline(r'''
def row = [module:'nd_interface_port_channel_trunk_host',test_type:'integration',nd:'4.3',
    scope:'iBGP',round_label:'iBGP',result:'PASS',coverage:'COMPLETE',validated:true,
    counts:[merged:[started:1],replaced:[started:0],overridden:[started:0],deleted:[started:0],gathered:[started:0]],
    case_totals:[started:1,passed:1,failed:0,skipped:0,incomplete:0],base:'Ran',cleanup:'Ran']
def text = script.formatModuleActivityTable([row], '122')
def lines = text.readLines().findAll { it.startsWith('|') }
def positions = { String line -> (0..<line.size()).findAll { line.substring(it,it+1) == '|' } }
assert lines.every { positions(it) == positions(lines[0]) }
assert lines.every { it.length() == lines[0].length() }
assert lines.any { it.split(/\|/,-1)[3].trim() == row.module }
''')
