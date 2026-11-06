"""Offline regressions for the five reviewed pipeline defects.

The real Groovy methods run with local step substitutes. No Jenkins build,
HTTP request, device command or fabric operation is performed.
"""

import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ("Jenkinsfile_nd_jenkins_script",)

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
def pipelineType = loader.parseClass(source, 'FiveIssuePipeline.groovy')
def script = pipelineType.newInstance()
script.binding = new Binding([
    params: [:],
    env: [ND_REPORTING_RELATIVE_ROOT: 'fixture-reports', ND_REPORTING_ROOT: '/workspace/fixture-reports'],
    BUILD_NUMBER: '122', JOB_URL: 'https://jenkins.example/job/nd/',
    currentBuild: [currentResult: 'FAILURE', startTimeInMillis: System.currentTimeMillis()]
])
def logs = []
script.metaClass.echo = { Object message -> logs.add(message.toString()) }
script.metaClass.error = { Object message -> throw new IllegalStateException(message.toString()) }
'''


@pytest.fixture(scope="module", params=VARIANTS)
def groovy_runner(request, tmp_path_factory):
    java = Path(os.environ.get("ND_WEBEX_TEST_JAVA", "/private/tmp/nd-local-groovy-runtime/jdk-21.0.13+9-jre/Contents/Home/bin/java"))
    jar = Path(os.environ.get("ND_WEBEX_TEST_GROOVY", "/private/tmp/nd-groovy-all-2.4.21.jar"))
    if not java.is_file() or not jar.is_file():
        pytest.skip("Local JVM and Groovy jar are required")
    directory = tmp_path_factory.mktemp("five-issue-groovy")
    sequence = 0

    def run(body):
        nonlocal sequence
        sequence += 1
        harness = directory / f"regression_{sequence}.groovy"
        harness.write_text(PRELUDE + "\n" + body + '\nprintln("CHECK_PASSED")\n', encoding="utf-8")
        result = subprocess.run(
            [str(java), "-cp", str(jar), "groovy.ui.GroovyMain", str(harness), str(ROOT / request.param)],
            text=True, capture_output=True, timeout=45,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "CHECK_PASSED" in result.stdout
        return result.stdout

    return run


def test_abort_during_reporter_failure_receipt_propagates(groovy_runner):
    groovy_runner(r'''
def interruption = loader.loadClass('org.jenkinsci.plugins.workflow.steps.FlowInterruptedException')
    .newInstance('injected receipt abort')
int calls = 0
script.metaClass.sh = { Object options ->
    calls++
    if (calls == 1) { throw new IllegalStateException('injected initial report failure') }
    assert options.toString().contains('reporter-failed')
    throw interruption
}
def caught = null
try { script.publishStructuredArtifacts() }
catch (Exception actual) { caught = actual }
assert calls == 2
assert caught != null && caught.is(interruption)
assert !logs.any { it.startsWith('NDP_REPORTER_FAILED:') }
''')


def test_original_abort_is_not_hidden_by_failure_receipt_error(groovy_runner):
    groovy_runner(r'''
def interruption = loader.loadClass('org.jenkinsci.plugins.workflow.steps.FlowInterruptedException')
    .newInstance('injected initial abort')
int calls = 0
script.metaClass.sh = { Object options ->
    calls++
    if (calls == 1) { throw interruption }
    throw new IllegalStateException('injected receipt write failure')
}
def caught = null
try { script.publishStructuredArtifacts() }
catch (Exception actual) { caught = actual }
assert calls == 2
assert caught != null && caught.is(interruption)
''')


def test_ordinary_reporting_errors_remain_independent_of_execution(groovy_runner):
    groovy_runner(r'''
int calls = 0
script.metaClass.sh = { Object options ->
    calls++
    throw new IllegalStateException('injected ordinary failure')
}
script.publishStructuredArtifacts()
assert calls == 2
assert logs.any { it.startsWith('NDP_REPORTER_FAILED:') }
assert logs.any { it.startsWith('NDP_REPORTER_TERMINAL_WRITE_FAILED:') }
''')


@pytest.mark.parametrize("phase", ["pre", "post", "home"])
def test_membership_guard_always_receives_explicit_false(groovy_runner, phase):
    groovy_runner(r'''
script.binding.env.ND_SWITCH_PREFLIGHT_READY = 'true'
script.binding.env.CURRENT_NDFC_INVENTORY = '/fixture/inventory.yaml'
script.binding.env.ND_PREREQUISITE_ONLY_EFFECTIVE = 'false'
script.binding.setVariable('COLLECTIONS_DIRECTORY', '/fixture/collection')
script.metaClass.stage = { Object name, Closure body -> body.call() }
script.metaClass.withEnv = { Object entries, Closure body -> body.call() }
def captured = []
script.metaClass.sh = { Object command -> captured.add(command.toString()); return 0 }
script.runSwitchMembershipSync([version: '4.3', fabric_name: 'fixture', rehome_fabrics: []],
''' + repr(phase) + r''', '/fixture/roster.yaml')
assert captured.size() == 1
assert captured[0].contains('-e "nd_switch_preserve_config=false"')
assert !captured[0].contains('nd_switch_preserve_config=auto')
''')


ROW_FIXTURE = r'''
def complete = [module: 'nd_manage_switches', nd: '4.3', scope: 'iBGP',
    fabric: 'fixture-ibgp', round_label: 'iBGP', result: 'PASS', validated: true,
    coverage: 'COMPLETE', case_totals: [started: 7, passed: 7, failed: 0, skipped: 0, incomplete: 0],
    counts: [merged: [started: 2], replaced: [started: 1], overridden: [started: 1],
             deleted: [started: 2], gathered: [started: 1]],
    base: 'Ran', cleanup: 'Ran', duration: '10m', failure: '']
'''


def test_complete_case_rows_keep_exact_counts_and_validated_total(groovy_runner):
    groovy_runner(ROW_FIXTURE + r'''
script.MODULE_ACTIVITY_RESULTS['fixture'] = complete
def raw = script.moduleCaseSummaryRows()
def columns = raw.split('\\|', -1)
assert columns[4..6] == ['7', '0', '0'] : raw
def activity = script.formatModuleActivityTable([complete], '122')
assert activity.contains('1 validated executions / 1 selected') : activity
assert activity.contains('cases passed 7, failed 0') : activity
''')


def test_incomplete_case_rows_disclose_unknowns_and_visible_note(groovy_runner):
    groovy_runner(ROW_FIXTURE + r'''
def incomplete = new LinkedHashMap(complete)
incomplete.coverage = 'INCOMPLETE'
incomplete.case_totals = [started: 6, passed: 1, failed: 0, skipped: 0, incomplete: 5]
script.MODULE_ACTIVITY_RESULTS['incomplete'] = incomplete
def raw = script.moduleCaseSummaryRows()
def columns = raw.split('\\|', -1)
assert columns[4].contains('?') : raw
assert columns[5].contains('?') : raw
assert columns[8].toLowerCase().contains('incomplete') : raw
assert columns[8].contains('5') : raw
def table = script.formatResultsTable(raw, 'module test cases')
assert table.toLowerCase().contains('incomplete') && table.contains('5') : table
''')


def test_incomplete_totals_preserve_known_contributions_and_exclude_not_run(groovy_runner):
    groovy_runner(ROW_FIXTURE + r'''
def incomplete = new LinkedHashMap(complete)
incomplete.coverage = 'INCOMPLETE'
incomplete.case_totals = [started: 3, passed: 1, failed: 0, skipped: 0, incomplete: 2]
def notRun = new LinkedHashMap(complete)
notRun.result = 'NOT_RUN'
notRun.validated = false
notRun.case_totals = [:]
def totals = script.moduleCaseTotals([complete, incomplete, notRun])
assert totals.passed.startsWith('8') && totals.passed.contains('?') : totals
assert totals.failed.contains('?') : totals
''')


def embedded_python(marker, filename="Jenkinsfile_nd_jenkins_script"):
    source = (ROOT / filename).read_text(encoding="utf-8")
    start = source.index(marker + "\n")
    end = source.index("\nPY\n", start)
    return source[start:end]


def run_python(code, environment, cwd):
    import sys

    completed = subprocess.run(
        [sys.executable, "-c", code], cwd=cwd, env=dict(os.environ, **environment),
        text=True, capture_output=True, timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return completed.stdout


@pytest.mark.parametrize("fabric_type", ["vxlanIbgp", "vxlanEbgp"])
@pytest.mark.parametrize("filename", VARIANTS)
def test_dynamic_inventory_no_longer_disables_greenfield_cases(tmp_path, fabric_type, filename):
    import json
    import yaml

    source = (ROOT / filename).read_text()
    method = source.index("def generateDynamicInventory(")
    start = source.index("import json\nimport os\n", method)
    end = source.index("\nPY\n", start)
    names = ("vxlan_leaf_1", "vxlan_leaf_2", "vxlan_spine_1", "vxlan_border_1",
             "vxlan_leaf_3", "vxlan_leaf_4", "external_edge_1", "external_edge_2")
    switches = [dict(name=name, ip=f"192.0.2.{index}", serial=f"FIXTURE{index:05d}",
                     fabric="fixture-primary", role="leaf") for index, name in enumerate(names, 1)]
    inventory = tmp_path / "inventory.yaml"
    run_python(source[start:end], {
        "INVENTORY_SWITCHES_JSON": json.dumps(switches),
        "INVENTORY_PRIMARY_FABRIC": "fixture-primary",
        "INVENTORY_PRIMARY_FABRIC_TYPE": fabric_type,
        "INVENTORY_SECONDARY_FABRIC": "fixture-external",
        "INVENTORY_FILE_NAME": str(inventory),
        "INVENTORY_HOST": "192.0.2.100",
        "NDFC_USER": "fixture-user", "NDFC_PASSWORD": "fixture-secret",
    }, tmp_path)
    actual = yaml.safe_load(inventory.read_text())["all"]["vars"]
    assert "nd_switch_brownfield_supported" not in actual
    assert actual["save"] is True and actual["deploy"] is True
