"""Run real producer/version/batch methods with only external operations substituted."""
import json
import os
from pathlib import Path
import re
import subprocess

import pytest
from test_build124_switch_preflight import PRELUDE, PRODUCER

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ("Jenkinsfile_nd_jenkins_script",)
PRODUCER_WITH_REAL_VERSION = re.sub(
    r"script\.metaClass\.runNDFCVersionTests = \{.*?\n\}\n", "", PRODUCER, count=1, flags=re.S)


@pytest.fixture(scope="module", params=VARIANTS)
def groovy(request, tmp_path_factory):
    java = Path(os.environ.get("ND_WEBEX_TEST_JAVA", "/private/tmp/nd-local-groovy-runtime/jdk-21.0.13+9-jre/Contents/Home/bin/java"))
    jar = Path(os.environ.get("ND_WEBEX_TEST_GROOVY", "/private/tmp/nd-groovy-all-2.4.21.jar"))
    assert java.is_file() and jar.is_file(), "Real Groovy runtime is required"
    folder = tmp_path_factory.mktemp("restored-round-flow")
    counter = 0

    def run(body):
        nonlocal counter
        counter += 1
        path = folder / f"flow-{counter}.groovy"
        path.write_text(PRELUDE + "\n" + PRODUCER_WITH_REAL_VERSION + "\n" + body + '\nprintln("CHECK_PASSED")\n')
        result = subprocess.run([str(java), "-cp", str(jar), "groovy.ui.GroovyMain", str(path), str(ROOT / request.param)],
                                text=True, capture_output=True, timeout=45)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "CHECK_PASSED" in result.stdout

    return run


@pytest.mark.parametrize("scenario", ["healthy", "ibgp-test-failed", "both-tests-failed", "batch-setup-failed",
                                     "preflight-failed", "missing-receipt", "malformed-receipt", "restore-failed",
                                     "flow-aborted", "java-interrupted"])
def test_real_full_flow_continues_collected_failures_but_blocks_infrastructure(groovy, scenario):
    groovy("def scenario = " + json.dumps(scenario) + "\n" + r'''
context.ND_RUNTIME_INPUTS_READY = 'true'
context.ND_REPORTING_RELATIVE_ROOT = 'fixture-reports'
context.ND_REPORTING_ROOT = '/fixture/reports'
script.binding.setVariable('BASE_DIRECTORY', '/fixture/base')
script.binding.setVariable('COLLECTIONS_DIRECTORY', '/fixture/collection')
script.binding.setVariable('params', [DEBUG:false, DEBUG_MODULES:''])
script.metaClass.pwd = { -> '/fixture/workspace' }
script.metaClass.stage = { Object name, Closure work ->
    if (!(name in ['Set environment', 'Clone Repository'])) { work.call() }
}
// withEnv restores only its own bindings; unrelated build-failure flags persist.
script.metaClass.withEnv = { List entries, Closure work ->
    def prior = [:]
    def absent = []
    entries.each { entry ->
        int split = entry.indexOf('='); def key = entry.substring(0, split)
        if (context.containsKey(key)) { prior[key] = context[key] } else { absent.add(key) }
        context[key] = entry.substring(split + 1)
    }
    try { work.call() }
    finally { absent.each { context.remove(it) }; prior.each { key,value -> context[key]=value } }
}
script.metaClass.usernamePassword = { Map options -> options }
script.metaClass.withCredentials = { List options, Closure work -> work.call() }
script.metaClass.applyFabricRound = { Object round -> calls.add('apply:' + round.round_label) }
script.metaClass.generateDynamicInventory = { Object round ->
    context.CURRENT_NDFC_INVENTORY = '/fixture/inventory.yaml'
}
script.metaClass.runSwitchPreflight = { Object round ->
    calls.add('pre:' + round.round_label)
    if (scenario == 'preflight-failed') { throw new IllegalStateException('preflight failed') }
}
script.metaClass.runSwitchPostRestore = { Object round ->
    calls.add('post:' + round.round_label)
    context.ND_SWITCH_RESTORE_FAILED = (scenario == 'restore-failed' ? 'true' : 'false')
    if (scenario == 'restore-failed') { context.PIPELINE_FAILED='true' }
}
script.metaClass.registerStructuredExecutions = { Object round, Object targets, Object run, Object fabric, Object pairs ->
    calls.add('register:' + round.round_label)
    return '/fixture/reports/executions/' + round.versionId + '/' + run
}
def swallowed = []
script.metaClass.catchError = { Map options, Closure work ->
    try { work.call() } catch (Exception e) {
        script.rethrowIfInterrupt(e)
        swallowed.add(e.message)
    }
}
script.metaClass.sh = { Object options ->
    def text = (options instanceof Map ? options.script : options).toString()
    if (text.contains('NDP_MODULE_BATCH_CLOSED:')) {
        def round = context.VERSION_ID.endsWith('_EBGP') ? 'eBGP' : 'iBGP'
        calls.add('batch:' + round)
        if (scenario == 'batch-setup-failed') { throw new IllegalStateException('source validation failed') }
        if (scenario == 'flow-aborted') { throw loader.loadClass('org.jenkinsci.plugins.workflow.steps.FlowInterruptedException').newInstance('aborted') }
        if (scenario == 'java-interrupted') { throw new InterruptedException('interrupted') }
        return 0
    }
    if (text.contains('cat -- "$ND_MODULE_BATCH_STATUS"')) {
        calls.add('receipt')
        if (scenario == 'missing-receipt') { throw new IllegalStateException('missing receipt') }
        if (scenario == 'malformed-receipt') { return 'invalid' }
        return scenario == 'both-tests-failed' || (scenario == 'ibgp-test-failed' && !context.VERSION_ID.endsWith('_EBGP')) ? '1\n' : '0\n'
    }
    return options instanceof Map && options.returnStdout ? 'fixture listing' : 0
}
def caught = null
try { script.run() } catch (Exception e) { caught = e }
assert calls.contains('pre:iBGP')
assert calls.any { it.startsWith('home:') }
if (scenario in ['healthy', 'ibgp-test-failed', 'both-tests-failed']) {
    assert caught == null
    assert calls.contains('batch:iBGP') && calls.contains('post:iBGP')
    assert calls.contains('batch:eBGP') && calls.contains('post:eBGP')
    assert calls.contains('reset') && calls.contains('finish:success')
    assert (context.PIPELINE_FAILED == 'true') == (scenario != 'healthy')
    assert swallowed.size() == (scenario == 'both-tests-failed' ? 2 : (scenario == 'ibgp-test-failed' ? 1 : 0))
} else {
    assert !calls.contains('batch:eBGP')
    assert swallowed.empty  // Infrastructure errors are never hidden by catchError.
    if (scenario == 'restore-failed') { assert caught == null && context.PIPELINE_FAILED == 'true' }
    else { assert caught != null }
    if (scenario in ['flow-aborted', 'java-interrupted']) { assert calls.contains('finish:interrupted') }
    else if (scenario != 'restore-failed') { assert calls.contains('finish:failed') }
}
''')


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("failure", [0, 1])
def test_real_completed_batch_shell_writes_status_without_raising_test_failure(tmp_path, variant, failure):
    source = (ROOT / variant).read_text()
    tail = source.split('# Module case progress/skips are rendered once', 1)[1].split("\n", 1)[1].split("'''", 1)[0]
    receipt = tmp_path / "module_batch.status"
    result = subprocess.run(["bash", "-c", "set -e\n" + tail],
                            env=dict(os.environ, RUN_FAILURE=str(failure), ND_MODULE_BATCH_STATUS=str(receipt),
                                     FABRIC_NAME="fixture", VERSION_ID="fixture"),
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert receipt.read_text() == str(failure) + "\n"
