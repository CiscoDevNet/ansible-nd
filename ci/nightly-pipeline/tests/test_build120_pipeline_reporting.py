"""Offline regressions for the reporting failures observed in Jenkins build 120.

The real Jenkinsfile is compiled and its post-actions are invoked with in-memory
Pipeline step substitutes. Script.run(), Jenkins, Ansible and HTTP are never run.
These checks verify control flow and payloads, not Jenkins CPS or its whitelist.
"""

import json
import os
from pathlib import Path
import subprocess

import pytest


JENKINSFILE = Path(__file__).resolve().parents[1] / "Jenkinsfile_nd_jenkins_script"


PRELUDE = r'''
def loader = new GroovyClassLoader()
loader.parseClass(''' + '"""' + r'''
package org.jenkinsci.plugins.workflow.steps
class FlowInterruptedException extends Exception {
    FlowInterruptedException(String message) { super(message) }
}
''' + '"""' + r''')
loader.parseClass(''' + '"""' + r'''
package com.cloudbees.groovy.cps
import java.lang.annotation.*
@Retention(RetentionPolicy.RUNTIME)
@Target([ElementType.METHOD])
@interface NonCPS {}
''' + '"""' + r''')
def source = new File(args[0]).getText('UTF-8')
def marker = '    post {\n        always {\n            script {\n'
def start = source.indexOf(marker)
assert start >= 0
start += marker.length()
def end = source.indexOf('\n            }\n        }\n        cleanup {', start)
assert end > start
def postBody = source.substring(start, end)
def pipelineType = loader.parseClass(source + '\ndef runPostForTest() {\n' + postBody + '\n}\n',
    'NdBuild120Pipeline.groovy')
def script = pipelineType.newInstance()
script.binding = new Binding([
    env: [ACTIVE_DCNM_VERSIONS: '4.3', ND_GIT_BRANCH: 'fixture-branch',
          ND_GIT_COMMIT: 'abcdef0123456789', WEBEX_ROOM_ID: 'fixture-room',
          WEBEX_TOKEN: 'fixture-token'],
    BUILD_NUMBER: '121', JOB_URL: 'https://jenkins.example/job/nd/',
    currentBuild: [currentResult: 'FAILURE', startTimeInMillis: System.currentTimeMillis() - 125000]
])
def logs = []
def sent = []
script.metaClass.echo = { Object message -> logs.add(message.toString()) }
script.metaClass.error = { Object message -> throw new IllegalStateException(message.toString()) }
script.metaClass.sendWebexNotificationMessages = { Object messages ->
    sent.addAll(messages.collect { it.toString() })
}
'''


@pytest.fixture(scope="module")
def groovy_runner(tmp_path_factory):
    java = Path(os.environ.get(
        "ND_WEBEX_TEST_JAVA",
        "/private/tmp/nd-local-groovy-runtime/jdk-21.0.13+9-jre/Contents/Home/bin/java",
    ))
    jar = Path(os.environ.get("ND_WEBEX_TEST_GROOVY", "/private/tmp/nd-groovy-all-2.4.21.jar"))
    if not java.is_file() or not jar.is_file():
        pytest.skip("A local JVM and Groovy jar are required for offline Jenkins helper execution")
    directory = tmp_path_factory.mktemp("build120-pipeline")
    sequence = 0

    def run(body):
        nonlocal sequence
        sequence += 1
        harness = directory / f"regression_{sequence}.groovy"
        harness.write_text(PRELUDE + "\n" + body + '\nprintln("CHECK_PASSED")\n', encoding="utf-8")
        result = subprocess.run(
            [str(java), "-cp", str(jar), "groovy.ui.GroovyMain", str(harness), str(JENKINSFILE)],
            capture_output=True, text=True, timeout=45, check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "CHECK_PASSED" in result.stdout
        return result.stdout

    return run


def test_timing_render_failure_does_not_prevent_detailed_notification(groovy_runner):
    groovy_runner(r'''
script.metaClass.formatPhaseTimingTable = { Object rows, Object elapsed ->
    throw new IllegalStateException('injected timing rejection')
}
script.runPostForTest()
assert sent.size() == 1
assert sent[0].contains('DETAILED TEST RESULTS')
assert sent[0].contains('fixture-branch')
assert sent[0].indexOf('fixture-branch') < sent[0].indexOf('abcdef0123456789')
assert logs.any { it.contains('NDP_TIMING_REPORT_UNAVAILABLE') }
''')


def test_result_table_failure_sends_unknown_count_fallback(groovy_runner):
    groovy_runner(r'''
script.metaClass.formatResultsTable = { Object summary, Object unit ->
    throw new IllegalStateException('injected result-table rejection')
}
script.runPostForTest()
assert sent.size() == 1
assert sent[0].contains('Test-case counts are unknown')
assert !sent[0].contains('Test cases passed: 0')
assert sent[0].contains('Build result: FAILURE')
assert sent[0].contains('Branch: fixture-branch\nCommit: abcdef0123456789')
assert sent[0].contains('https://jenkins.example/job/nd/121/console')
assert sent[0].contains('https://jenkins.example/job/nd/121/artifact/')
assert logs.any { it.contains('NDP_DETAILED_NOTIFICATION_FAILED') }
''')


def test_final_activity_table_failure_does_not_undo_delivery(groovy_runner):
    groovy_runner(r'''
script.metaClass.formatModuleActivityTable = { Object rows, Object build ->
    throw new IllegalStateException('injected final activity rejection')
}
script.runPostForTest()
assert sent.size() == 1
assert sent[0].contains('DETAILED TEST RESULTS')
assert logs.any { it.contains('NDP_FINAL_ACTIVITY_TABLE_UNAVAILABLE') }
''')


def test_delivery_failure_gets_one_minimal_fallback_attempt(groovy_runner):
    groovy_runner(r'''
int attempts = 0
script.metaClass.sendWebexNotificationMessages = { Object messages ->
    attempts++
    if (attempts == 1) { throw new IllegalStateException('injected send failure') }
    sent.addAll(messages.collect { it.toString() })
}
script.runPostForTest()
assert attempts == 2
assert sent.size() == 1
assert sent[0].contains('Detailed reporting was unavailable')
''')


def test_both_delivery_failures_are_bounded_and_logged(groovy_runner):
    groovy_runner(r'''
int attempts = 0
script.metaClass.sendWebexNotificationMessages = { Object messages ->
    attempts++
    throw new IllegalStateException('injected delivery failure')
}
script.runPostForTest()
assert attempts == 2
assert sent.isEmpty()
assert logs.any { it.contains('NDP_WEBEX_NOTIFICATION_FAILED') }
''')


def test_abort_is_preserved_without_fallback_delivery(groovy_runner):
    groovy_runner(r'''
def interruption = loader.loadClass('org.jenkinsci.plugins.workflow.steps.FlowInterruptedException')
    .newInstance('injected abort')
script.metaClass.formatPhaseTimingTable = { Object rows, Object elapsed -> throw interruption }
boolean interrupted = false
try { script.runPostForTest() }
catch (Exception actual) { interrupted = actual.is(interruption) }
assert interrupted
assert sent.isEmpty()
''')


def test_duration_unknown_values_rounding_and_phase_totals(groovy_runner):
    groovy_runner(r'''
assert script.formatPhaseDuration(null) == 'N/A'
assert script.formatPhaseDuration('3') == 'N/A'
assert script.formatPhaseDuration(-1) == 'N/A'
assert script.formatPhaseDuration(Double.NaN) == 'N/A'
assert script.formatPhaseDuration(Double.POSITIVE_INFINITY) == 'N/A'
assert script.formatPhaseDuration(Double.NEGATIVE_INFINITY) == 'N/A'
assert script.formatPhaseDuration(0) == '00h 00m 00.000s'
assert script.formatPhaseDuration(3661.2346) == '01h 01m 01.235s'
def table = script.formatPhaseTimingTable([
    [execution: 1.25, cleanup: null], [execution: 2.5, cleanup: 0]
], 12)
assert table.contains('00h 00m 03.750s')
assert table.contains('00h 00m 12.000s')
assert table.contains('2 / 2')
''')


def test_tables_preserve_fabric_rows_with_long_cells(groovy_runner):
    groovy_runner(r'''
def name = 'nd_' + ('long_module_name_' * 15)
def table = script.formatResultsTable(
    'OK|' + name + '|fixture-fabric|4.3|7|0|2|01m||iBGP\n' +
    'FAIL|' + name + '|fixture-ebgp|4.3|6|1|3|02m||eBGP', 'module test cases')
assert table.contains(name)
assert table.readLines().count { it.startsWith('OK ') } == 1
assert table.readLines().count { it.startsWith('FAIL ') } == 1
assert !table.readLines().any { it.startsWith('NOT_RUN ') }
def activity = script.formatModuleActivityTable([], '121')
assert activity.contains('MAIN TOTAL')
assert activity.contains('Fabric type')
''')


def test_real_delivery_helper_builds_ascii_json_and_masks_auth_header(groovy_runner):
    output = groovy_runner(r'''
script.metaClass = null
def requests = []
script.metaClass.echo = { Object message -> logs.add(message.toString()) }
script.metaClass.error = { Object message -> throw new IllegalStateException(message.toString()) }
script.metaClass.string = { Object params -> params }
script.metaClass.withCredentials = { Object credentials, Closure body -> body.call() }
script.metaClass.httpRequest = { Object request -> requests.add(request); [status: 200] }
script.sendWebexNotificationMessages(['ND \uD83D\uDCCA\nmodule "name"'])
assert requests.size() == 1
assert requests[0].customHeaders[0].maskValue == true
assert requests[0].customHeaders[0].value == 'Bearer fixture-token'
assert requests[0].requestBody.every { (int) it <= 127 }
assert logs.every { !it.contains('fixture-token') }
println('PAYLOAD=' + requests[0].requestBody)
''')
    payload_line = next(line for line in output.splitlines() if line.startswith("PAYLOAD="))
    assert json.loads(payload_line[len("PAYLOAD="):]) == {
        "roomId": "fixture-room", "markdown": 'ND 📊\nmodule "name"',
    }


def test_registration_round_trips_plan_and_rejects_unsafe_reply_directory(groovy_runner):
    groovy_runner(r'''
def environment = script.binding.getVariable('env')
environment.ND_REPORTING_RELATIVE_ROOT = 'nd_reporting_fixture'
environment.ND_REPORTING_ROOT = '/workspace/nd_reporting_fixture'
environment.WORKSPACE = '/workspace'
def writes = []
def exported = []
def reply = [log_dir: '/workspace/nd_reporting_fixture/executions/run-121',
    round_key: 'ND43', selected_executions: 2]
script.metaClass.writeFile = { Object options -> writes.add(options) }
script.metaClass.withEnv = { Object entries, Closure body -> exported.addAll(entries); body.call() }
script.metaClass.sh = { Object options ->
    if (options.returnStatus) { assert options.script.contains('rm -f'); return 0 }
    assert options.returnStdout == true
    assert options.script.contains('nd_reporting_pipeline.py" register')
    script.writeReportingJson(reply)
}
def config = [version: '4.3', versionId: 'ND43', round_label: 'iBGP',
    fabric_name: 'VXLAN_EVPN_Fabric', fabric_type: 'vxlanIbgp']
def targets = [['nd_manage_policy', 'integration'], ['nd_manage_networks', 'integration']]
assert script.registerStructuredExecutions(config, targets, 'run-121',
    'VXLAN_EVPN_Fabric', []) == reply.log_dir
assert writes.size() == 1
assert writes[0].file == 'nd_reporting_plan_ND43.json'
def plan = script.parseReportingJson(writes[0].text)
assert plan.build == '121'
assert plan.run_id == 'run-121'
assert plan.version_id == 'ND43'
assert plan.round_label == 'iBGP'
assert plan.targets.collect { it.module } == ['nd_manage_policy', 'nd_manage_networks']
assert plan.targets.every { it.scope == 'iBGP' && it.fabric == 'VXLAN_EVPN_Fabric' }
assert exported == ['ND_REPORT_PLAN=/workspace/nd_reporting_fixture/plan_ND43.json',
    'ND_REPORT_STAGED_PLAN=/workspace/nd_reporting_plan_ND43.json']
reply.log_dir = '/outside/unsafe-directory'
boolean rejected = false
try { script.registerStructuredExecutions(config, targets, 'run-121', 'VXLAN_EVPN_Fabric', []) }
catch (IllegalStateException actual) { rejected = actual.message.contains('unsafe execution directory') }
assert rejected
''')
