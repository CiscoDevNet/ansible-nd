"""Offline regressions for host/container plan writes and detailed Webex delivery.

The actual Jenkinsfile methods execute through local step substitutes. Reporting
registration uses real helper programs; Webex HTTP calls are always intercepted.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ("Jenkinsfile_nd_jenkins_script",)
HELPERS = ("nd_report.py", "nd_result_summary.py", "nd_test_activity.py", "nd_reporting_pipeline.py")
DESTINATION_HASHES = {
    VARIANTS[0]: "11e594f481958c10e3015d0bf0447a22f068a8a647f475df15ce2c7ab4b8f3f1",
}

PRELUDE = r'''
import groovy.json.JsonSlurper
import groovy.json.JsonOutput
def loader = new GroovyClassLoader()
loader.parseClass("package org.jenkinsci.plugins.workflow.steps; class FlowInterruptedException extends Exception { FlowInterruptedException(String message) { super(message) } }")
loader.parseClass("package com.cloudbees.groovy.cps; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) @Target([ElementType.METHOD]) @interface NonCPS {}")
def source = new File(args[0]).getText('UTF-8')
def pipelineType = loader.parseClass(source, 'Build122PermissionsPipeline.groovy')
def script = pipelineType.newInstance()
def workspace = new File(args[1])
def reportRoot = new File(workspace, 'fixture-reports')
def mode = args[2]
def context = [WORKSPACE: workspace.absolutePath,
    HOME: new File(workspace, 'home').absolutePath,
    ND_REPORTING_RELATIVE_ROOT: 'fixture-reports',
    ND_REPORTING_ROOT: reportRoot.absolutePath,
    ND_REPORTING_TOOLS: new File(reportRoot, 'tools').absolutePath,
    COLLECTIONS_DIRECTORY: new File(workspace, 'collection').absolutePath,
    ND_GIT_BRANCH: 'develop', ND_GIT_COMMIT: 'a' * 40,
    ACTIVE_DCNM_VERSIONS: '4.3', PIPELINE_FAILED: 'false', WEBEX_ROOM_ID: 'fixture-room']
script.binding = new Binding([env: context, BUILD_NUMBER: '122',
    JOB_URL: 'https://jenkins.invalid/job/nd/',
    currentBuild: [currentResult: 'FAILURE', startTimeInMillis: System.currentTimeMillis()]])
def logs = []
def writes = []
def shells = []
def requests = []
script.metaClass.echo = { Object message -> logs.add(message.toString()) }
script.metaClass.error = { Object message -> throw new IllegalStateException(message.toString()) }
script.metaClass.writeFile = { Map options ->
    def relative = options.file.toString()
    writes.add(relative)
    // Model the Jenkins host account: it cannot write the container-owned tree.
    if (relative.contains('/') || mode == 'write') {
        throw new java.nio.file.AccessDeniedException(relative)
    }
    def text = options.text.toString()
    if (mode == 'bad-plan') {
        def plan = new JsonSlurper().parseText(text)
        plan.build = 'another-build'
        text = JsonOutput.toJson(plan)
    }
    new File(workspace, relative).setText(text, 'UTF-8')
}
script.metaClass.withEnv = { List entries, Closure body ->
    def saved = new LinkedHashMap(context)
    for (def entry : entries) {
        def text = entry.toString()
        int split = text.indexOf('=')
        assert split > 0
        context[text.substring(0, split)] = text.substring(split + 1)
    }
    try { return body.call() }
    finally { context.clear(); context.putAll(saved) }
}
script.metaClass.sh = { Object options ->
    def step = options instanceof Map ? options : [script: options]
    boolean installation = step.script.toString().contains('os.replace(staged, target)')
    shells.add(installation ? 'install-register' : 'cleanup')
    if (mode == 'install' && installation) {
        throw new IllegalStateException('injected container installation failure')
    }
    def builder = new ProcessBuilder(['/bin/bash', '-c', step.script.toString()])
    builder.directory(workspace)
    context.each { key, value ->
        if (value != null) { builder.environment()[key.toString()] = value.toString() }
    }
    def process = builder.start()
    def output = new StringBuilder()
    def errors = new StringBuilder()
    process.waitForProcessOutput(output, errors)
    if (step.returnStatus) { return process.exitValue() }
    if (process.exitValue() != 0) {
        throw new IllegalStateException('local agent command failed: ' + errors.toString() + output.toString())
    }
    return step.returnStdout ? output.toString() : null
}
script.metaClass.string = { Map credential -> credential }
script.metaClass.withCredentials = { List credentials, Closure body ->
    def prior = context.WEBEX_TOKEN
    context.WEBEX_TOKEN = 'OFFLINE_TOKEN_NOT_FOR_NETWORK'
    try { return body.call() }
    finally {
        if (prior == null) { context.remove('WEBEX_TOKEN') }
        else { context.WEBEX_TOKEN = prior }
    }
}
script.metaClass.httpRequest = { Map options ->
    requests.add(new JsonSlurper().parseText(options.requestBody.toString()))
    assert options.customHeaders[0].maskValue == true
    assert options.timeout == 45
    return [status: 200]
}
def round = [version: '4.3', versionId: 'ND43', round_label: 'iBGP',
             fabric_name: 'VXLAN_EVPN_Fabric', vpc_pair_fabric_type: 'vxlanIbgp']
def targets = [['nd_manage_policy', 'integration']]
'''


@pytest.fixture(scope="module", params=VARIANTS)
def groovy_runner(request, tmp_path_factory):
    java = Path(os.environ.get(
        "ND_WEBEX_TEST_JAVA",
        "/private/tmp/nd-local-groovy-runtime/jdk-21.0.13+9-jre/Contents/Home/bin/java",
    ))
    jar = Path(os.environ.get("ND_WEBEX_TEST_GROOVY", "/private/tmp/nd-groovy-all-2.4.21.jar"))
    if not java.is_file() or not jar.is_file():
        pytest.skip("Local JVM and Groovy jar are required")
    directory = tmp_path_factory.mktemp("build122-permissions")
    sequence = 0

    def run(body, mode="success"):
        nonlocal sequence
        sequence += 1
        workspace = directory / f"workspace-{sequence}"
        workspace.mkdir()
        python = workspace / "home/ansible/venv/bin/python"
        python.parent.mkdir(parents=True)
        python.symlink_to(sys.executable)
        report_root = workspace / "fixture-reports"
        tools = report_root / "tools"
        tools.mkdir(parents=True)
        for name in HELPERS:
            shutil.copy2(ROOT / "playbooks" / name, tools / name)
        collection = workspace / "collection"
        role = collection / "tests/integration/targets/nd_manage_policy/tasks"
        role.mkdir(parents=True)
        (role / "main.yaml").write_text(
            "- name: Merged TC1 - offline authored case\n"
            "  ansible.builtin.debug:\n"
            "    msg: offline fixture\n"
        )
        subprocess.run([
            sys.executable, str(tools / "nd_reporting_pipeline.py"), "init",
            "--root", str(report_root), "--workspace", str(workspace),
            "--build", "122", "--run-id", "fixture-build-122",
        ], text=True, capture_output=True, check=True)
        harness = directory / f"check-{sequence}.groovy"
        harness.write_text(PRELUDE + "\n" + body + '\nprintln("CHECK_PASSED")\n')
        result = subprocess.run([
            str(java), "-cp", str(jar), "groovy.ui.GroovyMain", str(harness),
            str(ROOT / request.param), str(workspace), mode,
        ], text=True, capture_output=True, timeout=60)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "CHECK_PASSED" in result.stdout
        assert "OFFLINE_TOKEN_NOT_FOR_NETWORK" not in result.stdout + result.stderr
        return workspace, result.stdout

    return run


def test_plan_registration_stages_in_host_workspace_then_uses_real_agent_helpers(groovy_runner):
    workspace, _ = groovy_runner(r'''
def logDir = script.registerStructuredExecutions(round, targets, 'fixture-module-run', round.fabric_name, [])
assert logDir.startsWith(new File(reportRoot, 'executions').absolutePath + '/')
assert writes == ['nd_reporting_plan_ND43.json']
assert shells == ['install-register', 'cleanup']
assert !new File(workspace, 'nd_reporting_plan_ND43.json').exists()
def plan = new JsonSlurper().parse(new File(reportRoot, 'plan_ND43.json'))
assert plan.build == '122'
assert plan.run_id == 'fixture-module-run'
assert plan.version_id == 'ND43'
assert plan.round_label == 'iBGP'
assert plan.fabric_name == 'VXLAN_EVPN_Fabric'
assert plan.targets == [[module:'nd_manage_policy', test_type:'integration',
                        scope:'iBGP', fabric:'VXLAN_EVPN_Fabric']]
assert requests.isEmpty()
''')
    jobs = list((workspace / "fixture-reports/jobs").glob("*.json"))
    assert len(jobs) == 1
    job = json.loads(jobs[0].read_text())
    assert (job["build"], job["module"], job["run_id"], job["scope"]) == (
        "122", "nd_manage_policy", "fixture-module-run", "iBGP"
    )
    assert (workspace / "fixture-reports").stat().st_mode & 0o777 == 0o755


@pytest.mark.parametrize("failure, expected", [
    ("write", "AccessDeniedException"),
    ("install", "injected container installation failure"),
    ("bad-plan", "round plan belongs to another build"),
])
def test_plan_staging_is_cleaned_after_host_install_or_registration_failure(groovy_runner, failure, expected):
    workspace, _ = groovy_runner(r'''
def caught = null
try { script.registerStructuredExecutions(round, targets, 'fixture-module-run', round.fabric_name, []) }
catch (Exception actual) { caught = actual }
assert caught != null
assert writes == ['nd_reporting_plan_ND43.json']
assert shells[-1] == 'cleanup'
assert !new File(workspace, 'nd_reporting_plan_ND43.json').exists()
assert requests.isEmpty()
assert (caught.getClass().getName() + ': ' + caught.message).contains(''' + json.dumps(expected) + r''')
''', mode=failure)
    assert not list((workspace / "fixture-reports/jobs").glob("*.json"))


def test_oversized_detailed_report_splits_and_sends_every_part_without_with_index(groovy_runner):
    groovy_runner(r'''
assert !source.contains('.withIndex(')
def fence = ((char) 96).toString() * 3
def table = new StringBuilder('ND 4.3 NIGHTLY NOTIFICATION - Build 123\nBranch: develop\nCommit: ' + ('a' * 40) + '\n')
table.append(fence).append('\nStatus  Module  Fabric  Passed  Failed  Skipped\n')
table.append('------  ------  ------  ------  ------  -------\n')
for (int index = 0; index < 220; index++) {
    table.append('OK  unique_module_').append(index).append('  ')
    table.append(index % 2 == 0 ? 'iBGP' : 'eBGP')
    table.append('  12  0  0  completed original authored cases\n')
}
table.append(fence).append('\nFAILURE: fixture prerequisite issue remains visible.\n')
assert table.length() > 15600
def parts = script.splitWebexMessage(table.toString(), 'ND 4.3 - Build 123\nBranch: develop\n', 7000)
assert parts.size() >= 3
for (int index = 0; index < parts.size(); index++) {
    assert parts[index].length() <= 7000
    assert parts[index].startsWith('📄 Report part ' + (index + 1) + '/' + parts.size())
}
def combined = parts.join('\n')
for (int index = 0; index < 220; index++) {
    assert combined.contains('unique_module_' + index + '  ')
}
assert combined.contains('FAILURE: fixture prerequisite issue remains visible.')
script.sendWebexNotificationMessages(parts)
assert requests.size() == parts.size()
for (int index = 0; index < requests.size(); index++) {
    assert requests[index].roomId == 'fixture-room'
    assert requests[index].markdown == parts[index]
}
assert logs.count { it.startsWith('NDP_WEBEX_NOTIFICATION_SENT:') } == parts.size()
assert writes.isEmpty() && shells.isEmpty()
''')


def test_minimal_failure_notification_remains_bounded_without_workspace_access(groovy_runner):
    groovy_runner(r'''
context.ND_GIT_BRANCH = 'b' * 2000
context.ND_GIT_COMMIT = 'c' * 2000
script.metaClass.sh = { Object ignored -> throw new AssertionError('fallback must not require a shell') }
script.metaClass.writeFile = { Map ignored -> throw new AssertionError('fallback must not require FilePath') }
def fallback = script.minimalBuildNotification()
assert fallback.length() < 1500
assert fallback.contains('Build result: FAILURE')
assert fallback.contains('Branch: ' + ('b' * 200) + '\n')
assert fallback.contains('Commit: ' + ('c' * 80) + '\n')
assert fallback.contains('Test-case counts are unknown')
assert fallback.contains('https://jenkins.invalid/job/nd/122/console')
assert source.contains('sendWebexNotificationMessages([minimalBuildNotification(e.getClass().getName())])')
script.sendWebexNotificationMessages([fallback])
assert requests.size() == 1
assert requests[0].markdown == fallback
''')


@pytest.mark.parametrize("filename, active", [
    (VARIANTS[0], "WEBEX_ROOM_ID_PUBLIC"),
])
def test_room_names_preserve_the_original_resolved_destinations(filename, active):
    source = (ROOT / filename).read_text()
    definitions = dict(re.findall(r'def (WEBEX_ROOM_ID_(?:PUBLIC|PRIVATE))\s*=\s*"([^"]+)"', source))
    selected = re.search(r'^\s*WEBEX_ROOM_ID\s*=\s*"\$\{(WEBEX_ROOM_ID_[A-Z]+)\}"', source, re.M)
    assert selected.group(1) == active
    assert hashlib.sha256(definitions[active].encode()).hexdigest() == DESTINATION_HASHES[filename]
    canonical = dict(re.findall(
        r'def (WEBEX_ROOM_ID_(?:PUBLIC|PRIVATE))\s*=\s*"([^"]+)"',
        (ROOT / VARIANTS[0]).read_text(),
    ))
    assert definitions == canonical
    assert ".withIndex(" not in source



def test_unicode_boundary_reports_remain_valid_and_deliver(groovy_runner):
    groovy_runner(r"""
def text = ('a' * 6918) + '😀' + ('b' * 100)
assert text.length() == 7020
assert script.parseReportingJson(script.writeReportingJson([markdown: text])).markdown == text
def parts = script.splitWebexMessage(text, '', 7000)
assert parts.size() == 2
for (def part : parts) {
    assert part.length() <= 7000
    assert script.parseReportingJson(script.writeReportingJson([markdown: part])).markdown == part
}
assert parts.join('\n').count('😀') == 1
script.sendWebexNotificationMessages(parts)
assert requests.size() == 2
assert requests.collect { it.markdown }.join('\n').count('😀') == 1
""")


def test_fallback_reports_only_revision_and_safe_exception_class(groovy_runner):
    groovy_runner(r"""
def name = 'org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException'
def fallback = script.minimalBuildNotification(name)
assert fallback.contains('Reporting revision: selected-branch-pipeline-20261029')
assert fallback.contains('Detailed reporting error class: ' + name)
assert fallback.contains('Branch: develop\nCommit: ' + ('a' * 40) + '\n')
def unsafe = script.minimalBuildNotification('Authorization: Bearer OFFLINE_RAW_SECRET\nresponse body')
assert unsafe.contains('Detailed reporting error class: unavailable')
assert !unsafe.contains('OFFLINE_RAW_SECRET')
assert fallback.length() < 1500 && unsafe.length() < 1500
""")


POST_DSL = r"""
// Execute the real post.always closure, skipping all build and cleanup stages.
script.metaClass.pipeline = { Closure body -> body.call() }
for (def name : ['agent', 'parameters', 'environment', 'options', 'stages', 'cleanup']) {
    script.metaClass."${name}" = { Closure ignored -> null }
}
script.metaClass.post = { Closure body -> body.call() }
script.metaClass.always = { Closure body -> body.call() }
script.metaClass.script = { Closure body -> body.call() }
script.metaClass.formatPhaseTimingTable = { Object rows, Object seconds -> 'Offline phase timings' }
script.metaClass.formatModuleActivityTable = { Object rows, Object build -> 'Offline activity table' }
script.metaClass.sh = { Object ignored -> throw new AssertionError('post must not require an agent shell') }
script.metaClass.writeFile = { Map ignored -> throw new AssertionError('post must not require FilePath') }
"""


def test_real_post_fallback_identifies_revision_and_exception_without_raw_message(groovy_runner):
    groovy_runner(POST_DSL + r"""
def type = loader.parseClass('package org.jenkinsci.plugins.scriptsecurity.sandbox; class RejectedAccessException extends RuntimeException { RejectedAccessException(String text) { super(text) } }')
def failure = type.newInstance('OFFLINE_RAW_SECRET_ERROR_BODY_NEVER_FORWARD')
script.metaClass.moduleCaseTotals = { Object rows -> throw failure }
script.run()
assert requests.size() == 1
assert requests[0].markdown.contains('Build result: FAILURE')
assert requests[0].markdown.contains('Reporting revision: selected-branch-pipeline-20261029')
assert requests[0].markdown.contains('Detailed reporting error class: org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException')
assert !requests[0].markdown.contains('OFFLINE_RAW_SECRET')
assert logs.any { it == 'NDP_NOTIFICATION_REVISION: selected-branch-pipeline-20261029' }
assert logs.any { it.startsWith('NDP_DETAILED_NOTIFICATION_FAILED: org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException; revision=') }
assert !logs.join('\n').contains('OFFLINE_RAW_SECRET')
assert writes.isEmpty() && shells.isEmpty()
""")


def test_real_post_delivers_all_oversized_rows_without_fallback(groovy_runner):
    groovy_runner(POST_DSL + r"""
def rows = []
for (int index = 0; index < 220; index++) {
    rows.add('OK|unique_post_module_' + index + '|VXLAN_EVPN_Fabric|4.3|12|0|0|00h 01m 00s||iBGP')
}
script.metaClass.moduleCaseTotals = { Object ignored -> [passed: '2640', failed: '0', skipped: '0'] }
script.metaClass.moduleCaseSummaryRows = { -> rows.join('\n') }
def artifacts = []
for (int index = 0; index < 30; index++) {
    artifacts.add('unique_artifact_' + index + '|fixture-reports/executions/unique_artifact_' + index + '.txt')
}
script.TEST_RESULT_ARTIFACTS_BUF = artifacts.join('\n')
context.LOG_BUNDLE_FILE = 'all_logs_build_122.zip'
context.MODULE_ACTIVITY_REPORT_FILE = 'module_test_activity_build_122.txt'
script.run()
assert requests.size() >= 3
for (def request : requests) { assert request.markdown.length() <= 7000 }
def delivered = requests.collect { it.markdown }.join('\n')
for (int index = 0; index < 220; index++) { assert delivered.contains('unique_post_module_' + index + ' ') }
for (int index = 0; index < 30; index++) {
    assert delivered.contains('https://jenkins.invalid/job/nd/122/artifact/fixture-reports/executions/unique_artifact_' + index + '.txt')
}
assert delivered.contains('https://jenkins.invalid/job/nd/122/artifact/all_logs_build_122.zip')
assert delivered.contains('https://jenkins.invalid/job/nd/122/artifact/module_test_activity_build_122.txt')
assert !source.contains('compactMessage')
assert logs.any { it.startsWith('NDP_WEBEX_REPORT_SIZE: characters=') && it.endsWith('part_limit=7000') }
assert logs.any { it.startsWith('📨 Webex notification before delivery (') && it.contains('unique_post_module_219') && it.contains('unique_artifact_29.txt') }
assert !delivered.contains('Detailed reporting was unavailable')
assert logs.any { it == 'NDP_NOTIFICATION_REVISION: selected-branch-pipeline-20261029' }
assert !logs.any { it.startsWith('NDP_DETAILED_NOTIFICATION_FAILED:') }
assert writes.isEmpty() && shells.isEmpty()
""")


@pytest.mark.parametrize('filename', VARIANTS)
def test_current_file_fingerprint_cannot_match_captured_build124_old_signature(filename):
    source = (ROOT / filename).read_text()
    old_fingerprint = {
        'revision': 'five-issue-fixes-20261028',
        'rejected_splitter': 'parts.withIndex().collect',
        'denied_plan_write': 'writeFile file: planFile',
    }
    assert all(value not in source for value in old_fingerprint.values())
    assert "ND_REPORTING_REVISION = 'selected-branch-pipeline-20261029'" in source
    assert 'NDP_NOTIFICATION_REVISION: ${ND_REPORTING_REVISION}' in source
    assert 'writeFile file: stagedPlanFile' in source
    # This detects local source drift; it does not activate or inspect live Jenkins.
