# Compound-failure regressions execute real Jenkinsfile methods through offline
# Groovy step substitutes. No Jenkins, Webex, Consul or ND call is performed.
import json
import os
from pathlib import Path
import subprocess

import pytest
from test_build124_switch_preflight import PRELUDE, PRODUCER

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ('Jenkinsfile_nd_jenkins_script',)

@pytest.fixture(scope='module', params=VARIANTS)
def groovy_runner(request, tmp_path_factory):
    java = Path(os.environ.get('ND_WEBEX_TEST_JAVA', '/private/tmp/nd-local-groovy-runtime/jdk-21.0.13+9-jre/Contents/Home/bin/java'))
    jar = Path(os.environ.get('ND_WEBEX_TEST_GROOVY', '/private/tmp/nd-groovy-all-2.4.21.jar'))
    if not java.is_file() or not jar.is_file():
        pytest.skip('Local JVM and Groovy jar are required')
    directory = tmp_path_factory.mktemp('weekly-failure-preservation')
    sequence = 0
    def run(body):
        nonlocal sequence
        sequence += 1
        harness = directory / f'check-{sequence}.groovy'
        harness.write_text(PRELUDE + '\n' + MAKE_FAILURE + '\n' + body + '\nprintln("CHECK_PASSED")\n')
        result = subprocess.run([str(java), '-cp', str(jar), 'groovy.ui.GroovyMain', str(harness), str(ROOT / request.param)], text=True, capture_output=True, timeout=45)
        assert result.returncode == 0, result.stdout + result.stderr
        assert 'CHECK_PASSED' in result.stdout
    return run

MAKE_FAILURE = r'''
def makeFailure = { String kind, String label ->
    if (kind == 'none') { return null }
    if (kind == 'flow') { return loader.loadClass('org.jenkinsci.plugins.workflow.steps.FlowInterruptedException').newInstance(label) }
    if (kind == 'java') { return new InterruptedException(label) }
    return new IllegalStateException(label)
}
'''


def specification(value):
    return 'def scenario = script.parseReportingJson(' + json.dumps(json.dumps(value)) + ')\n'


@pytest.mark.parametrize('primary, secondary, expected', [
    ('flow', 'ordinary', 'primary'), ('java', 'ordinary', 'primary'),
    ('ordinary', 'flow', 'secondary'), ('ordinary', 'ordinary', 'primary'),
    ('none', 'ordinary', 'secondary'), ('none', 'none', 'result'),
])
def test_cleanup_preserves_failure_or_later_interruption(groovy_runner, primary, secondary, expected):
    groovy_runner(specification({'primary': primary, 'secondary': secondary, 'expected': expected}) + r'''
def primary = makeFailure(scenario.primary, 'primary')
def secondary = makeFailure(scenario.secondary, 'secondary')
def caught = null
def result = null
try {
    result = script.withCleanupPreservingFailure({
        calls.add('work'); if (primary != null) { throw primary }; return 'work-result'
    }, {
        calls.add('cleanup'); if (secondary != null) { throw secondary }
    })
} catch (Exception e) { caught = e }
assert calls == ['work', 'cleanup']
if (scenario.expected == 'result') { assert caught == null && result == 'work-result' }
else { assert caught != null && caught.is(scenario.expected == 'primary' ? primary : secondary) }
''')


@pytest.mark.parametrize('archive, ack, receipt, next_failure, expected', [
    ('flow', 'ordinary', 'none', 'none', 'archive'),
    ('java', 'ordinary', 'none', 'none', 'archive'),
    ('java', 'none', 'none', 'none', 'archive'),
    ('flow', 'flow', 'ordinary', 'none', 'archive'),
    ('ordinary', 'flow', 'none', 'none', 'ack'),
    ('none', 'none', 'flow', 'flow', 'next'),
])
def test_actual_publisher_never_loses_interruptions_to_ack_or_failure_receipts(groovy_runner, archive, ack, receipt, next_failure, expected):
    groovy_runner(specification({'archive': archive, 'ack': ack, 'receipt': receipt, 'next': next_failure, 'expected': expected}) + r'''
def errors = scenario.collectEntries { key, value -> [(key): makeFailure(value, key.toString())] }
int nextCalls = 0
script.metaClass.timeout = { Map options, Closure work -> work.call() }
script.metaClass.retry = { Integer count, Closure work -> work.call() }
script.metaClass.archiveArtifacts = { Map options ->
    calls.add('archive'); if (errors.archive != null) { throw errors.archive }
}
script.metaClass.sh = { Object options ->
    def text = (options instanceof Map ? options.script : options).toString()
    if (text.contains(' next ')) {
        calls.add('next'); nextCalls++
        if (errors.next != null) { throw errors.next }
        return nextCalls == 1 ? '{"done":false,"execution":{"id":"job","files":["test_output_fabric_ND43_IBGP_nd_fixture.txt"],"attempt":1}}' : '{"done":true}'
    }
    if (text.contains(' ack ')) { calls.add('ack'); if (errors.ack != null) { throw errors.ack }; return '' }
    if (text.contains('reporter-failed')) { calls.add('receipt'); if (errors.receipt != null) { throw errors.receipt }; return '' }
    throw new AssertionError('Unexpected offline step')
}
def caught = null
try { script.publishStructuredArtifacts() } catch (Exception e) { caught = e }
assert caught != null && caught.is(errors[scenario.expected])
assert calls.contains('receipt')
if (scenario.next == 'none') { assert calls.contains('archive') && calls.contains('ack') }
assert !logs.any { it.startsWith('NDP_REPORTER_FAILED:') }
''')


@pytest.mark.parametrize('work, cleanup, expected', [
    ('flow', 'ordinary', 'work'), ('java', 'ordinary', 'work'),
    ('ordinary', 'ordinary', 'work'), ('ordinary', 'flow', 'cleanup'),
    ('none', 'ordinary', 'cleanup'),
])
def test_actual_plan_registration_cleanup_preserves_primary(groovy_runner, work, cleanup, expected):
    groovy_runner(specification({'work': work, 'cleanup': cleanup, 'expected': expected}) + r'''
def errors = [work: makeFailure(scenario.work, 'work'), cleanup: makeFailure(scenario.cleanup, 'cleanup')]
context.WORKSPACE = '/workspace'
script.metaClass.writeFile = { Map options -> calls.add('stage') }
script.metaClass.sh = { Object options ->
    def text = options.script.toString()
    if (text.contains('os.replace(staged, target)')) {
        calls.add('install'); if (errors.work != null) { throw errors.work }
        return '{"log_dir":"/workspace/fixture-reports/executions/x"}'
    }
    if (text.contains('rm -f --')) { calls.add('cleanup'); if (errors.cleanup != null) { throw errors.cleanup }; return 0 }
    throw new AssertionError('Unexpected offline step')
}
def caught = null
try { script.registerStructuredExecutions(config, [['nd_manage_policy', 'integration']], 'weekly-fixture', config.fabric_name, []) }
catch (Exception e) { caught = e }
assert calls == ['stage', 'install', 'cleanup']
assert caught != null && caught.is(errors[scenario.expected])
''')


@pytest.mark.parametrize('primary_site, primary_kind, secondary_site, secondary_kind, expected', [
    ('round', 'flow', 'home', 'ordinary', 'primary'),
    ('round', 'ordinary', 'home', 'ordinary', 'primary'),
    ('round', 'ordinary', 'home', 'flow', 'secondary'),
    ('home', 'flow', 'record', 'ordinary', 'primary'),
    ('round', 'flow', 'aggregate', 'ordinary', 'primary'),
    ('round', 'ordinary', 'aggregate', 'flow', 'secondary'),
    ('aggregate', 'flow', 'activity', 'ordinary', 'primary'),
    ('round', 'flow', 'terminal', 'flow', 'primary'),
    ('round', 'java', 'terminal', 'ordinary', 'primary'),
])
def test_real_producer_home_and_reporting_cleanup_preserve_primary(groovy_runner, primary_site, primary_kind, secondary_site, secondary_kind, expected):
    details = {'primary_site': primary_site, 'primary_kind': primary_kind, 'secondary_site': secondary_site, 'secondary_kind': secondary_kind, 'expected': expected}
    body = specification(details) + r'''
def failureMode = 'reported-module-failure'
def failure = new IllegalStateException('unused producer fixture default')
def primary = makeFailure(scenario.primary_kind, 'primary')
def secondary = makeFailure(scenario.secondary_kind, 'secondary')
def failAt = { String site ->
    if (scenario.primary_site == site) { throw primary }
    if (scenario.secondary_site == site) { throw secondary }
}
'''
    body += PRODUCER + r'''
script.metaClass.runNDFCVersionTests = { Object round -> calls.add('round:' + round.round_label); failAt('round') }
script.metaClass.restoreHomeFabric = { Object rounds, Object active -> calls.add('home'); failAt('home') }
script.metaClass.recordUnstartedRound = { Object round, Object reason ->
    calls.add('record:' + round.round_label)
    if (reason.toString().startsWith('not reached after')) { failAt('record') }
}
script.metaClass.finishStructuredExecution = { Object status -> calls.add('finish:' + status); failAt('terminal') }
script.metaClass.foldStructuredResults = { -> calls.add('aggregate'); failAt('aggregate') }
script.metaClass.publishModuleActivityReport = { -> calls.add('activity'); failAt('activity') }
script.metaClass.bundleAllLogs = { -> calls.add('bundle') }
def caught = null
try { script.run() } catch (Exception e) { caught = e }
assert caught != null && caught.is(scenario.expected == 'primary' ? primary : secondary)
assert calls.contains('home')
assert calls.any { it.startsWith('finish:') }
if (scenario.primary_site == 'round' && scenario.primary_kind in ['flow', 'java']) { assert calls.contains('finish:interrupted') }
assert calls.contains('aggregate') && calls.contains('activity')
if (scenario.primary_site == 'round') { assert !calls.contains('round:eBGP') }
'''
    groovy_runner(body)
