# Compound-failure regressions execute real Jenkinsfile methods through offline
# Groovy step substitutes. No Jenkins, Webex, Consul or ND call is performed.
import json
import os
from pathlib import Path
import subprocess

import pytest
from test_build124_switch_preflight import PRELUDE, PRODUCER

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ('Jenkinsfile_nd_jenkins_script', 'Jenkinsfile_nd_jenkins_script_temp_switches')

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


def test_required_consul_download_uses_five_minute_request_timeout(groovy_runner):
    groovy_runner(r'''
script.binding.setVariable('CONSUL_URL', 'https://consul.example')
script.metaClass.httpRequest = { Map options ->
    assert options.timeout == 300
    assert options.validResponseCodes == '200'
    return [content: 'offline runtime fixture']
}
script.metaClass.writeFile = { Map options -> calls.add('write') }
script.metaClass.sh = { Object options -> calls.add('install'); return 0 }
assert script.downloadFromConsul('offline-required.yaml') == true
assert calls == ['write','install']
''')


@pytest.mark.parametrize('variant', (*VARIANTS, 'Jenkinsfile_nd_jenkins_script_comm_list'))
def test_missing_timeout_tool_stops_before_module_execution(tmp_path, variant):
    source = (ROOT / variant).read_text()
    anchor = '                                if ! command -v timeout'
    assert source.count(anchor) == 1
    check = anchor + source.split(anchor, 1)[1].split('\n                                fi', 1)[0] + '\nfi'
    shell = 'set -e\ncommand() { return 1; }\n' + check + '\nprintf "MODULE_MUST_NOT_START\\n"\n'
    result = subprocess.run(['/bin/bash'], input=shell, cwd=tmp_path,
                            text=True, capture_output=True, timeout=5)
    assert result.returncode != 0
    assert 'NDP_REQUIRED_TIMEOUT_UNAVAILABLE' in result.stderr
    assert 'MODULE_MUST_NOT_START' not in result.stdout
    assert '                                TIMEOUT_CMD=' not in source
    assert ' ${TIMEOUT_CMD}' not in source


@pytest.mark.parametrize('variant', (*VARIANTS, 'Jenkinsfile_nd_jenkins_script_comm_list'))
def test_module_playbooks_have_no_execution_timeout(variant):
    source = (ROOT / variant).read_text()
    assert 'MODULE_TIMEOUT' not in source
    assert 'SWITCHES_MODULE_TIMEOUT' not in source
    assert '                                TIMEOUT_CMD=' not in source
    assert ' ${TIMEOUT_CMD}' not in source
    assert 'MOD_TIMEOUT_CMD' not in source
    assert 'run_logged_playbook' in source


@pytest.mark.parametrize('variant', (*VARIANTS, 'Jenkinsfile_nd_jenkins_script_comm_list'))
@pytest.mark.parametrize('mode', ['normal', 'missing_parent', 'parent_symlink', 'target_symlink', 'absolute_path'])
def test_archive_receipt_uses_container_shell_and_rejects_unsafe_paths(tmp_path, variant, mode):
    source = (ROOT / variant).read_text()
    writer = source.split('def writeStructuredArchiveReceipt(', 1)[1].split('\ndef publishStructuredArtifacts', 1)[0]
    shell = writer.split("sh '''", 1)[1].split("'''", 1)[0]
    parent = tmp_path / 'fixture-reports' / 'archive-inputs'
    parent.mkdir(parents=True)
    target = parent / 'execution.0001.json'
    outside = tmp_path / 'outside.json'
    outside.write_text('unchanged')
    if mode == 'missing_parent':
        parent.rmdir()
    elif mode == 'parent_symlink':
        parent.rmdir()
        parent.symlink_to(tmp_path, target_is_directory=True)
    elif mode == 'target_symlink':
        target.symlink_to(outside)
    relative = str(target) if mode == 'absolute_path' else str(target.relative_to(tmp_path))
    receipt = {'id': 'execution', 'build': '137', 'build_run_id': 'fixture-run',
               'status': 'success', 'attempt': 1, 'seconds': 1.5, 'archived_at': 1000}
    environment = dict(os.environ, ND_ARCHIVE_RECEIPT_PATH=relative,
                       ND_ARCHIVE_RECEIPT_JSON=json.dumps(receipt))
    result = subprocess.run(['/bin/bash'], input=shell, cwd=tmp_path, env=environment,
                            text=True, capture_output=True, timeout=5)
    assert outside.read_text() == 'unchanged'
    assert 'fixture-run' not in result.stdout + result.stderr
    if mode in ('normal', 'missing_parent'):
        assert result.returncode == 0, result.stderr
        assert json.loads(target.read_text()) == receipt
        assert target.stat().st_mode & 0o777 == 0o600
        assert not list(parent.glob('*.tmp.*'))
    else:
        assert result.returncode != 0
    publisher = source.split('def publishStructuredArtifacts()', 1)[1].split('\ndef foldStructuredResults', 1)[0]
    assert 'writeStructuredArchiveReceipt(' in publisher
    assert 'writeFile file:' not in publisher


@pytest.mark.parametrize('variant', (*VARIANTS, 'Jenkinsfile_nd_jenkins_script_comm_list'))
@pytest.mark.parametrize('module_status,pipefail,archive_status', [
    (0, False, 0), (2, False, 0), (2, True, 0), (124, True, 0), (0, True, 74),
])
def test_module_logging_collects_failure_without_losing_later_modules(
        tmp_path, variant, module_status, pipefail, archive_status):
    source = (ROOT / variant).read_text()
    anchor = '                                run_logged_playbook() {'
    assert source.count(anchor) == 1
    helper = anchor + source.split(anchor, 1)[1].split('\n                                }\n', 1)[0] + '\n}'
    log = tmp_path / 'module.txt'
    shell = 'set -e\n' + ('set -o pipefail\n' if pipefail else 'set +o pipefail\n')
    shell += f'run_reported_playbook() {{ printf "offline module result\\n"; return {module_status}; }}\n'
    if archive_status:
        shell += f'tee() {{ cat >/dev/null; return {archive_status}; }}\n'
    shell += helper + '\nrun_logged_playbook "$1" nd_fixture "$1" execution\n'
    shell += 'printf "COLLECTED_STATUS=%s\\n" "$ANSIBLE_STATUS"\nprintf "NEXT_MODULE_REACHED\\n"\n'
    result = subprocess.run(['/bin/bash', '-s', '--', str(log)], input=shell,
                            text=True, capture_output=True, timeout=5)
    if archive_status:
        assert result.returncode == 125
        assert 'NEXT_MODULE_REACHED' not in result.stdout
        assert 'NDP_MODULE_LOG_WRITE_FAILED' in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        assert f'COLLECTED_STATUS={module_status}' in result.stdout
        assert 'NEXT_MODULE_REACHED' in result.stdout
        assert log.read_text() == 'offline module result\n'


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
context.ND_REPORTING_RELATIVE_ROOT = 'fixture-reports'
script.metaClass.timeout = { Map options, Closure work -> work.call() }
script.metaClass.retry = { Integer count, Closure work -> work.call() }
script.metaClass.writeStructuredArchiveReceipt = { String relativePath, Map receipt -> calls.add('record-receipt') }
script.metaClass.archiveArtifacts = { Map options ->
    calls.add('archive'); if (errors.archive != null) { throw errors.archive }
}
script.metaClass.sh = { Object options ->
    def text = (options instanceof Map ? options.script : options).toString()
    if (text.contains(' prepare ')) {
        assert !text.contains('--wait')
        calls.add('next'); nextCalls++
        if (errors.next != null) { throw errors.next }
        return script.writeReportingJson([build: script.binding.getVariable('BUILD_NUMBER').toString(), run_id:'fixture-run', archive_attempts:2,
            executions:[[id:'job', files:['test_output_fabric_ND43_IBGP_nd_fixture.txt'], attempt:1]]])
    }
    if (text.contains(' ack-batch ')) { calls.add('ack'); if (errors.ack != null) { throw errors.ack }; return '' }
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


@pytest.mark.parametrize('failing_first', [False, True])
def test_publisher_prepares_once_and_keeps_later_modules_after_upload_failure(groovy_runner, failing_first):
    groovy_runner('def failingFirst = ' + str(failing_first).lower() + '\n' + r'''
def recorded = []
context.ND_REPORTING_RELATIVE_ROOT = 'fixture-reports'
script.metaClass.timeout = { Map options, Closure work -> work.call() }
script.metaClass.retry = { Integer count, Closure work -> work.call() }
script.metaClass.writeStructuredArchiveReceipt = { String relativePath, Map receipt -> recorded.add(receipt) }
script.metaClass.archiveArtifacts = { Map options ->
    calls.add('archive:' + options.artifacts)
    if (failingFirst && options.artifacts.contains('first')) { throw new IllegalStateException('upload failed') }
}
script.metaClass.sh = { Object options ->
    def text = (options instanceof Map ? options.script : options).toString()
    if (text.contains(' prepare ')) {
        calls.add('prepare')
        return script.writeReportingJson([build: script.binding.getVariable('BUILD_NUMBER').toString(), run_id:'fixture-run', archive_attempts:2,
            executions:['first','second'].collect { name ->
                [id:name, files:["test_output_${name}.txt".toString()], attempt:1]
            }])
    }
    if (text.contains(' ack-batch ')) { calls.add('ack-batch'); return '' }
    throw new AssertionError('No per-module parser process is allowed')
}
script.publishStructuredArtifacts()
assert calls.count('prepare') == 1
assert calls.count('ack-batch') == 1
assert recorded.findAll { it.id == 'second' }*.status == ['success']
assert recorded.findAll { it.id == 'first' }*.status == (failingFirst ? ['failed','failed'] : ['success'])
assert recorded.every { it.build_run_id == 'fixture-run' && it.seconds >= 0 && it.archived_at > 0 }
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
script.metaClass.preserveModuleLogs = { -> calls.add('raw-logs') }
script.metaClass.publishModuleActivityReport = { -> calls.add('activity'); failAt('activity') }
script.metaClass.bundleAllLogs = { -> calls.add('bundle') }
def caught = null
try { script.run() } catch (Exception e) { caught = e }
assert caught != null && caught.is(scenario.expected == 'primary' ? primary : secondary)
assert calls.contains('home')
assert calls.any { it.startsWith('finish:') }
if (scenario.primary_site == 'round' && scenario.primary_kind in ['flow', 'java']) { assert calls.contains('finish:interrupted') }
assert calls.contains('aggregate') && calls.contains('activity')
assert calls.indexOf('raw-logs') < calls.indexOf('aggregate')
assert calls.contains('bundle')
if (scenario.primary_site == 'round') { assert !calls.contains('round:eBGP') }
'''
    groovy_runner(body)


@pytest.mark.parametrize('variant', (*VARIANTS, 'Jenkinsfile_nd_jenkins_script_comm_list'))
@pytest.mark.parametrize('problem', ['none', 'no_logs', 'log_symlink', 'root_symlink'])
def test_raw_log_archive_is_independent_of_reporter_and_excludes_private_inputs(tmp_path, variant, problem):
    import zipfile

    source = (ROOT / variant).read_text()
    helper = source.split('def preserveModuleLogs()', 1)[1].split('\ndef bundleAllLogs()', 1)[0]
    shell = helper.split("sh(script: '''", 1)[1].split("'''", 1)[0]
    root = tmp_path / 'reports'
    logs = root / 'executions' / 'round-iBGP'
    logs.mkdir(parents=True)
    private = root / 'runtime-inputs' / 'inventory.yaml'
    private.parent.mkdir()
    private.write_text('PRIVATE_INPUT_MUST_NOT_BE_ARCHIVED')
    log = logs / 'test_output_fixture_nd_manage_policy.txt'
    if problem == 'log_symlink':
        log.symlink_to(private)
    elif problem != 'no_logs':
        log.write_text('partial module log without a summary or receipt\n')
        log.chmod(0o600)
    if problem == 'root_symlink':
        linked = tmp_path / 'linked-reports'
        linked.symlink_to(root, target_is_directory=True)
        root = linked
    env = dict(os.environ, WORKSPACE=str(tmp_path), ND_REPORTING_ROOT=str(root),
               ND_LOG_ARCHIVE_DIR='module_logs_build_147', ND_LOG_ARCHIVE_ZIP='module_logs_build_147.zip')
    done = subprocess.run(['/bin/bash'], input='umask 077\n' + shell, env=env, text=True, capture_output=True, timeout=15)
    bundle = tmp_path / 'module_logs_build_147.zip'
    if problem in ['log_symlink', 'root_symlink']:
        assert done.returncode != 0
        assert not bundle.exists()
    elif problem == 'no_logs':
        assert done.returncode == 0, done.stderr
        assert done.stdout.strip() == '0'
        assert not bundle.exists()
    else:
        assert done.returncode == 0, done.stderr
        assert done.stdout.strip() == '1'
        with zipfile.ZipFile(bundle) as archive:
            assert archive.namelist() == ['round-iBGP/' + log.name]
            assert archive.read(archive.namelist()[0]) == log.read_bytes()
        copy = tmp_path / 'module_logs_build_147' / 'round-iBGP' / log.name
        assert copy.stat().st_mode & 0o777 == 0o644
        assert copy.parent.stat().st_mode & 0o777 == 0o755
        assert copy.parent.parent.stat().st_mode & 0o777 == 0o755
        assert bundle.stat().st_mode & 0o777 == 0o644
    assert 'preserveModuleLogs()' in source[:source.index('    post {')]
    assert source.count("if (env.MODULE_LOG_ARCHIVE_STATUS == 'failed')") == 2
    assert source.count('Module logs ZIP') == 2
    assert source.index('                            preserveModuleLogs()') < source.index('                                foldStructuredResultsWithRecovery()')
    timing_helper = source.split('def bundleAllLogs()', 1)[1].split('\ndef installEmbeddedReportingHelper', 1)[0]
    assert "env.LOG_BUNDLE_FILE = ''" not in timing_helper
