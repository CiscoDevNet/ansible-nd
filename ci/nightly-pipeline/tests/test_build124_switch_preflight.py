# Offline phase/exit regressions using the actual Jenkinsfile Groovy methods.
# All shell, credential, Jenkins and device operations are local substitutes.
import json
import os
from pathlib import Path
import subprocess

import pytest
from test_five_issue_pipeline_fixes import PRELUDE as BASE_PRELUDE

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ('Jenkinsfile_nd_jenkins_script',)

PRELUDE = BASE_PRELUDE + r'''
script.binding.setVariable('BUILD_NUMBER', '124')
script.binding.setVariable('COLLECTIONS_DIRECTORY', '/fixture/collection')
script.binding.setVariable('pwd', '/fixture/workspace')
script.binding.env.putAll([ND_SWITCH_PREFLIGHT_READY: 'true', ND_SWITCH_RESTORE_FAILED: 'false',
    PIPELINE_FAILED: 'false', ND_PREREQUISITE_ONLY_EFFECTIVE: 'false'])
def context = script.binding.env
def calls = []
def shells = []
def capturedEnvironments = []
script.metaClass.stage = { Object name, Closure work -> work.call() }
script.metaClass.withEnv = { List entries, Closure work ->
    def saved = new LinkedHashMap(context)
    entries.each { entry ->
        def text = entry.toString(); int split = text.indexOf('=')
        context[text.substring(0, split)] = text.substring(split + 1)
    }
    capturedEnvironments.add(new LinkedHashMap(context))
    try { return work.call() }
    finally { context.clear(); context.putAll(saved) }
}
def config = [version: '4.3', versionId: 'ND43_EBGP', fabric_name: 'VXLAN_EVPN_Fabric_eBGP',
    round_tag: ' (eBGP)', rehome_fabrics: ['VXLAN_EVPN_Fabric', 'VXLAN_EVPN_Fabric_eBGP']]
'''

@pytest.fixture(scope='module', params=VARIANTS)
def groovy_runner(request, tmp_path_factory):
    java = Path(os.environ.get('ND_WEBEX_TEST_JAVA', '/private/tmp/nd-local-groovy-runtime/jdk-21.0.13+9-jre/Contents/Home/bin/java'))
    jar = Path(os.environ.get('ND_WEBEX_TEST_GROOVY', '/private/tmp/nd-groovy-all-2.4.21.jar'))
    if not java.is_file() or not jar.is_file():
        pytest.skip('Local JVM and Groovy jar are required')
    directory = tmp_path_factory.mktemp('build124-preflight')
    sequence = 0
    def run(body):
        nonlocal sequence
        sequence += 1
        harness = directory / f'check-{sequence}.groovy'
        harness.write_text(PRELUDE + '\n' + body + '\nprintln("CHECK_PASSED")\n')
        result = subprocess.run([str(java), '-cp', str(jar), 'groovy.ui.GroovyMain', str(harness), str(ROOT / request.param)], text=True, capture_output=True, timeout=45)
        assert result.returncode == 0, result.stdout + result.stderr
        assert 'CHECK_PASSED' in result.stdout
    return run

@pytest.mark.parametrize('phase', ['pre', 'post', 'home'])
@pytest.mark.parametrize('exit_code, classification', [(0, 'SUCCESS'), (2, 'ANSIBLE_FAILED'), (124, 'TIMEOUT'), (7, 'COMMAND_FAILED')])
def test_actual_guard_classifies_status_and_preserves_phase_failure_semantics(groovy_runner, phase, exit_code, classification):
    groovy_runner('def phase = ' + json.dumps(phase) + '\ndef exitCode = ' + str(exit_code) + '\ndef expectedClass = ' + json.dumps(classification) + '\n' + r'''
script.metaClass.sh = { Object options ->
    assert options instanceof Map && options.returnStatus == true
    shells.add(options.script.toString())
    return exitCode
}
def caught = null
try { script.runSwitchMembershipSync(config, phase, '') } catch (Exception e) { caught = e }
assert shells.size() == 1
assert shells[0].contains('-e "nd_switch_preserve_config=false"')
assert shells[0].contains('-e "nd_switch_rehome_fabrics_csv=${PREFLIGHT_REHOME_FABRICS}"')
assert shells[0].contains('timeout "${PREFLIGHT_TIMEOUT}" ansible-playbook')
assert capturedEnvironments[0].PREFLIGHT_REHOME_FABRICS == 'VXLAN_EVPN_Fabric,VXLAN_EVPN_Fabric_eBGP'
assert capturedEnvironments[0].PREFLIGHT_TIMEOUT == '3600'
assert logs.any { it.contains('phase=' + phase) && it.contains('exit_code=' + exitCode) && it.contains('classification=' + expectedClass) && it.contains('timeout_limit_seconds=3600') }
assert !logs.any { it.startsWith('NDP_SWITCH_MEMBERSHIP_COMMAND_EXCEPTION') }
assert !logs.join('\n').contains('never became manageable')
assert !logs.join('\n').contains('power/reachability')
if (exitCode == 0) {
    assert caught == null
    assert logs.any { it.startsWith('NDP_SWITCH_MEMBERSHIP_READY:') }
    assert context.ND_SWITCH_RESTORE_FAILED == 'false'
} else {
    assert !logs.any { it.startsWith('NDP_SWITCH_MEMBERSHIP_READY:') }
    assert logs.any { it.contains('first fatal Ansible task') && it.contains('ND removal response') }
    assert (caught != null) == (phase != 'post')
    if (phase != 'pre') {
        assert context.ND_SWITCH_RESTORE_FAILED == 'true'
        assert context.PIPELINE_FAILED == 'true'
        assert logs.any { it.startsWith('NDP_SWITCH_RESTORE_INCOMPLETE:') && it.contains('later rounds blocked') }
    }
}
''')

@pytest.mark.parametrize('phase', ['pre', 'post', 'home'])
def test_command_launcher_exception_is_distinct_and_post_remains_best_effort(groovy_runner, phase):
    groovy_runner('def phase = ' + json.dumps(phase) + '\n' + r'''
def failure = new IllegalStateException('offline launcher failure')
script.metaClass.sh = { Object options -> throw failure }
def caught = null
try { script.runSwitchMembershipSync(config, phase, '') } catch (Exception e) { caught = e }
if (phase == 'post') { assert caught == null }
else { assert caught != null && caught.is(failure) }
assert logs.any { it.contains('NDP_SWITCH_MEMBERSHIP_COMMAND_EXCEPTION phase=' + phase) && it.contains('command exit status is unavailable') }
assert !logs.any { it.startsWith('NDP_SWITCH_MEMBERSHIP_RESULT') || it.startsWith('NDP_SWITCH_MEMBERSHIP_READY:') }
if (phase != 'pre') { assert context.ND_SWITCH_RESTORE_FAILED == 'true' && context.PIPELINE_FAILED == 'true' }
''')

@pytest.mark.parametrize('phase', ['pre', 'post', 'home'])
def test_all_phase_flow_interruptions_propagate_without_becoming_timeout_results(groovy_runner, phase):
    groovy_runner('def phase = ' + json.dumps(phase) + '\n' + r'''
def failure = loader.loadClass('org.jenkinsci.plugins.workflow.steps.FlowInterruptedException').newInstance('offline abort')
script.metaClass.sh = { Object options -> throw failure }
def caught = null
try { script.runSwitchMembershipSync(config, phase, '') } catch (Exception e) { caught = e }
assert caught != null && caught.is(failure)
assert !logs.any { it.startsWith('NDP_SWITCH_MEMBERSHIP_COMMAND_EXCEPTION') || it.startsWith('NDP_SWITCH_MEMBERSHIP_RESULT') || it.startsWith('NDP_SWITCH_MEMBERSHIP_READY:') }
''')

LIFECYCLE = r'''
script.metaClass.script = { Closure work -> work.call() }
script.metaClass.downloadFromConsul = { Object name, Object target = null -> true }
script.metaClass.usernamePassword = { Map options -> options }
script.metaClass.withCredentials = { List options, Closure work -> work.call() }
script.metaClass.sh = { Object options -> (options instanceof Map && options.returnStdout) ? 'offline listing' : 0 }
script.metaClass.applyFabricRound = { Object round -> calls.add('apply') }
script.metaClass.generateDynamicInventory = { Object round -> calls.add('inventory') }
script.metaClass.runSwitchPreflight = { Object round ->
    calls.add('preflight')
    if (failureMode == 'preflight') { throw failure }
}
script.metaClass.runFabricTest = { Object round ->
    calls.add('tests')
    if (failureMode in ['tests', 'tests-interrupted', 'tests-secondary']) { throw failure }
}
script.metaClass.runSwitchPostRestore = { Object round ->
    calls.add('active-post')
    if (failureMode in ['tests-interrupted', 'tests-secondary']) { throw new IllegalStateException('secondary post failure') }
}
'''

@pytest.mark.parametrize('mode', ['preflight', 'tests', 'tests-interrupted', 'tests-secondary', 'success'])
def test_failed_preflight_never_retries_active_destination_and_keeps_home_required(groovy_runner, mode):
    body = 'def failureMode = ' + json.dumps(mode) + '\n' + r'''
def failure = failureMode == 'tests-interrupted' ? loader.loadClass('org.jenkinsci.plugins.workflow.steps.FlowInterruptedException').newInstance('primary abort') : new IllegalStateException('offline infrastructure failure')
'''
    body += LIFECYCLE + r'''
def caught = null
try { script.runNDFCVersionTests(config) } catch (Exception e) { caught = e }
assert calls.contains('preflight')
assert context.HOME_RESTORE_REQUIRED == 'true'
if (failureMode == 'preflight') {
    assert caught != null && caught.is(failure)
    assert !calls.contains('tests') && !calls.contains('active-post')
    assert context.ND_SWITCH_RESTORE_FAILED == 'true' && context.PIPELINE_FAILED == 'true'
    assert logs.any { it.startsWith('NDP_SWITCH_ACTIVE_ROUND_RESTORE_SKIPPED:') && it.contains('Outer home-fabric recovery remains required') }
} else {
    assert calls.contains('tests') && calls.contains('active-post')
    if (failureMode == 'success') { assert caught == null }
    else { assert caught != null && caught.is(failure) }
}
assert source.contains('restoreHomeFabric(roundConfigs, activeRound)')
'''
    groovy_runner(body)

PRODUCER = r'''
// Run the real producer branch while skipping clone/setup, publisher and post DSLs.
script.metaClass.pipeline = { Closure work -> work.call() }
for (def name : ['agent', 'parameters', 'environment', 'options', 'post']) {
    script.metaClass."${name}" = { Closure ignored -> null }
}
script.metaClass.stages = { Closure work -> work.call() }
script.metaClass.stage = { Object name, Closure work ->
    if (name == 'Test NDFC/ND Versions Sequentially') { return work.call() }
    return null
}
script.metaClass.steps = { Closure work -> work.call() }
script.metaClass.script = { Closure work -> work.call() }
script.metaClass.runLintCheck = { -> null }
script.metaClass.prepareStructuredReporting = { -> calls.add('prepare-reporting') }
script.metaClass.parallel = { Map branches -> branches['Sequential tests and recovery'].call() }
script.metaClass.runNDFCVersionTests = { Object round ->
    calls.add('round:' + round.round_label)
    if (failureMode == 'infrastructure') { throw failure }
    script.setFailureFlag('NDFC_' + round.versionId + '_FAILED', true)
}
script.metaClass.resetFabricBetweenVersions = { Object label -> calls.add('reset') }
script.metaClass.restoreHomeFabric = { Object rounds, Object active -> calls.add('home:' + active.round_label) }
script.metaClass.recordUnstartedRound = { Object round, Object reason -> calls.add('record:' + round.round_label) }
script.metaClass.finishStructuredExecution = { Object status -> calls.add('finish:' + status) }
script.metaClass.foldStructuredResults = { -> calls.add('fold') }
script.metaClass.publishModuleActivityReport = { -> calls.add('activity') }
script.metaClass.bundleAllLogs = { -> calls.add('bundle') }
script.metaClass.cleanWs = { -> calls.add('clean') }
'''

@pytest.mark.parametrize('mode', ['infrastructure', 'reported-module-failure'])
def test_producer_stops_on_infrastructure_but_continues_collected_module_failures(groovy_runner, mode):
    body = 'def failureMode = ' + json.dumps(mode) + '\ndef failure = new IllegalStateException("offline setup failed")\n'
    body += PRODUCER + r'''
def caught = null
try { script.run() } catch (Exception e) { caught = e }
assert calls.contains('round:iBGP')
assert calls.any { it.startsWith('home:') }
if (failureMode == 'infrastructure') {
    assert caught != null && caught.is(failure)
    assert !calls.contains('round:eBGP') && !calls.contains('reset')
    assert calls.contains('finish:failed')
} else {
    assert caught == null
    assert calls.contains('round:eBGP') && calls.contains('reset')
    assert calls.contains('finish:success')
    assert context.PIPELINE_FAILED == 'true'
}
'''
    groovy_runner(body)
