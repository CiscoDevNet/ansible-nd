"""Offline bootstrap checks for build 121's missing Consul reporting helper.

The canonical Jenkinsfile is compiled without running its Pipeline. Its
installer shell runs only in an isolated local workspace; all HTTP calls are
substituted and no ND, Jenkins or Webex service is contacted.
"""

import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
JENKINSFILE = ROOT / "Jenkinsfile_nd_jenkins_script"
HELPERS = ("nd_report.py", "nd_result_summary.py", "nd_test_activity.py", "nd_reporting_pipeline.py")


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
def pipelineType = loader.parseClass(source, 'NdBuild121Pipeline.groovy')
def script = pipelineType.newInstance()
def workspace = new File(args[1])
def helperSources = new File(args[2])
def context = [WORKSPACE: workspace.absolutePath, BUILD_TAG: 'jenkins-fixture-121', BUILD_NUMBER: '121',
               HOME: new File(workspace, 'home').absolutePath,
               PATH: new File(args[3]).parent + File.pathSeparator + System.getenv('PATH'),
               CONSUL_SYNC_FAILED: 'false']
script.binding = new Binding([env: context, params: [:], BUILD_NUMBER: '121', CONSUL_URL: 'http://consul.invalid'])
def logs = []
def requests = []
script.metaClass.echo = { Object message -> logs.add(message.toString()) }
script.metaClass.error = { Object message -> throw new IllegalStateException(message.toString()) }
script.metaClass.writeFile = { Map options ->
    def destination = new File(workspace, options.file.toString())
    destination.parentFile.mkdirs()
    destination.setText(options.text.toString(), 'UTF-8')
}
script.metaClass.withEnv = { List entries, Closure body ->
    def saved = new LinkedHashMap(context)
    entries.each { entry ->
        def text = entry.toString()
        def split = text.indexOf('=')
        assert split > 0
        context[text.substring(0, split)] = text.substring(split + 1)
    }
    try { return body.call() }
    finally { context.clear(); context.putAll(saved) }
}
script.metaClass.sh = { Object options ->
    def step = options instanceof Map ? options : [script: options]
    def builder = new ProcessBuilder(['/bin/bash', '-c', step.script.toString()])
    builder.directory(workspace)
    context.each { key, value -> if (value != null) { builder.environment()[key.toString()] = value.toString() } }
    def process = builder.start()
    def output = new StringBuilder()
    def errors = new StringBuilder()
    process.waitForProcessOutput(output, errors)
    if (step.returnStatus) { return process.exitValue() }
    if (process.exitValue() != 0) {
        throw new IllegalStateException('Local installer failed: ' + errors.toString() + output.toString())
    }
    return step.returnStdout ? output.toString() : null
}
script.metaClass.httpRequest = { Map options ->
    requests.add(options)
    throw new IllegalStateException('Unexpected HTTP request in embedded-helper check')
}
def helpers = ['nd_report.py', 'nd_result_summary.py', 'nd_test_activity.py', 'nd_reporting_pipeline.py']
'''


@pytest.fixture(scope="module")
def groovy_runner(tmp_path_factory):
    java = Path(os.environ.get(
        "ND_WEBEX_TEST_JAVA",
        "/private/tmp/nd-local-groovy-runtime/jdk-21.0.13+9-jre/Contents/Home/bin/java",
    ))
    jar = Path(os.environ.get("ND_WEBEX_TEST_GROOVY", "/private/tmp/nd-groovy-all-2.4.21.jar"))
    if not java.is_file() or not jar.is_file():
        pytest.skip("A local JVM and Groovy jar are required")
    directory = tmp_path_factory.mktemp("build121-embedded")
    sequence = 0

    def run(body, setup=None, jenkinsfile=JENKINSFILE):
        nonlocal sequence
        sequence += 1
        workspace = directory / f"workspace-{sequence}"
        workspace.mkdir()
        python = workspace / "home/ansible/venv/bin/python"
        python.parent.mkdir(parents=True)
        python.symlink_to(sys.executable)
        if setup:
            setup(workspace)
        harness = directory / f"check-{sequence}.groovy"
        harness.write_text(PRELUDE + "\n" + body + '\nprintln("CHECK_PASSED")\n', encoding="utf-8")
        result = subprocess.run(
            [str(java), "-cp", str(jar), "groovy.ui.GroovyMain", str(harness),
             str(jenkinsfile), str(workspace), str(ROOT / "playbooks"), sys.executable],
            capture_output=True, text=True, timeout=60, check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "CHECK_PASSED" in result.stdout
        return workspace, result.stdout

    return run


def test_bootstrap_initializes_frozen_reporting_without_consul(groovy_runner):
    workspace, _ = groovy_runner(r'''
script.prepareStructuredReporting()
assert requests.isEmpty()
def tools = new File(context.ND_REPORTING_TOOLS)
helpers.each { name ->
    assert java.util.Arrays.equals(new File(tools, name).bytes, new File(helperSources, name).bytes)
}
def run = new groovy.json.JsonSlurper().parse(new File(context.ND_REPORTING_ROOT, 'run.json'))
assert run.build == '121'
assert run.tool_sha256.keySet() == helpers.toSet()
assert logs.any { it.contains('NDP_REPORTING_REVISION:') }
''')
    for path in workspace.glob("nd_reporting_*/tools/*.py"):
        assert path.stat().st_mode & 0o777 == 0o644


def test_flat_collection_helpers_use_the_same_embedded_bytes(groovy_runner):
    groovy_runner(r'''
helpers.each { name ->
    assert script.downloadFromConsul(name) == true
    assert java.util.Arrays.equals(new File(workspace, name).bytes, new File(helperSources, name).bytes)
}
assert requests.isEmpty()
assert context.CONSUL_SYNC_FAILED == 'false'
''')


def test_yaml_inputs_still_use_consul(groovy_runner):
    groovy_runner(r'''
script.metaClass.httpRequest = { Map options ->
    requests.add(options)
    return [content: '---\n- hosts: localhost\n  gather_facts: false\n']
}
assert script.downloadFromConsul('run_integration_module.yaml') == true
assert requests.size() == 1
assert requests[0].url.toString() == 'http://consul.invalid/v1/kv/ansible-nd/run_integration_module.yaml?raw'
assert new File(workspace, 'run_integration_module.yaml').text.startsWith('---\n')
''')


def test_bad_helper_digest_fails_closed_without_http_fallback(groovy_runner):
    groovy_runner(r'''
script.EMBEDDED_REPORTING_HELPERS['nd_report.py'].sha256 = '0' * 64
def failure = null
try { script.downloadFromConsul('nd_report.py', 'tools/nd_report.py') }
catch (Exception problem) { failure = problem }
assert failure != null
assert context.CONSUL_SYNC_FAILED == 'true'
assert !new File(workspace, 'tools/nd_report.py').exists()
assert requests.isEmpty()
''')


@pytest.mark.parametrize("destination", ["../escape.py", "/tmp/nd-build121-outside.py", "redirect/nd_report.py"])
def test_unsafe_helper_destination_is_rejected(groovy_runner, destination):
    def setup(workspace):
        outside = workspace.parent / (workspace.name + "-outside")
        outside.mkdir()
        (workspace / "redirect").symlink_to(outside, target_is_directory=True)

    groovy_runner(r'''
def failure = null
try { script.downloadFromConsul('nd_report.py', DESTINATION) }
catch (Exception problem) { failure = problem }
assert failure != null
assert context.CONSUL_SYNC_FAILED == 'true'
assert requests.isEmpty()
assert !new File(workspace.parentFile, 'escape.py').exists()
assert !new File(workspace, 'redirect/nd_report.py').exists()
'''.replace("DESTINATION", repr(destination)), setup=setup)


def test_canonical_selection_and_both_rounds_remain_enabled(groovy_runner):
    groovy_runner(r'''
assert script.INTEGRATION_MODULES.containsAll(['nd_manage_policy', 'nd_local_user', 'nd_manage_tor', 'nd_maintenance_mode'])
assert !script.INTEGRATION_MODULES.contains('nd_manage_switches')
assert !script.TRAILING_INTEGRATION_MODULES.contains('nd_manage_switches')
assert script.INTERFACE_INTEGRATION_MODULES.size() == 12
assert script.STANDALONE_INTEGRATION_MODULES == ['nd_vpc_pair']
assert script.VPC_PAIR_EXECUTIONS.collect { it.id } == ['advanced', 'external']
assert script.PLAYBOOK_FILES == []
assert script.FABRIC_ROUNDS.collect { it.label } == ['iBGP', 'eBGP']
assert requests.isEmpty()
''')


@pytest.mark.parametrize("filename", ["Jenkinsfile_nd_jenkins_script"])
def test_python_cache_prefix_redirects_reads_away_from_workspace_bytecode(groovy_runner, filename):
    import importlib.util
    import importlib._bootstrap_external

    workspace, output = groovy_runner(r"""
context.BUILD_TAG = 'cache / proof:' + workspace.name
script.prepareStructuredReporting()
def first = context.PYTHONPYCACHEPREFIX.toString()
assert first.startsWith('/tmp/nd-python-cache-cache___proof_')
assert !first.contains(' ') && !first.contains(':')
context.BUILD_TAG = 'cache / second:' + workspace.name
script.prepareStructuredReporting()
assert context.PYTHONPYCACHEPREFIX != first
println('CACHE_PREFIX=' + context.PYTHONPYCACHEPREFIX)
""", jenkinsfile=ROOT / filename)
    prefix = next(line.split("=", 1)[1] for line in output.splitlines() if line.startswith("CACHE_PREFIX="))
    module = workspace / "cache_probe.py"
    module.write_text("VALUE = 'SOURCE'\n")
    cached = Path(importlib.util.cache_from_source(str(module)))
    cached.parent.mkdir(exist_ok=True)
    code = compile("VALUE = 'CACHED'\n", str(module), "exec")
    stat = module.stat()
    cached.write_bytes(importlib._bootstrap_external._code_to_timestamp_pyc(code, int(stat.st_mtime), stat.st_size))
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    environment.pop("PYTHONPYCACHEPREFIX", None)
    command = [sys.executable, "-c", "import cache_probe; print(cache_probe.VALUE)"]
    control = subprocess.check_output(command, cwd=workspace, env=environment, text=True).strip()
    redirected = subprocess.check_output(command, cwd=workspace, env=dict(environment, PYTHONPYCACHEPREFIX=prefix), text=True).strip()
    assert control == "CACHED"  # Disabling writes alone still permits stale bytecode reads.
    assert redirected == "SOURCE"
