"""Execute local Jenkins methods and the real guard shell; services are stubbed."""
import os
from pathlib import Path
import subprocess

import pytest
from test_build121_embedded_reporting import groovy_runner

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ('Jenkinsfile_nd_jenkins_script',)


@pytest.mark.parametrize('variant', VARIANTS)
@pytest.mark.parametrize('source_ok', (True, False))
def test_two_rounds_use_one_complete_snapshot_and_fresh_working_copies(groovy_runner, variant, source_ok):
    def setup(workspace):
        collection = workspace / 'collection'
        collection.mkdir()
        subprocess.run(['git', 'init', '-q', str(collection)], check=True)
        subprocess.run(['git', '-C', str(collection), 'remote', 'add', 'origin',
                        'https://github.com/CiscoDevNet/ansible-nd.git'], check=True)

    groovy_runner('def sourceOk = ' + str(source_ok).lower() + '\n' + r'''
script.prepareStructuredReporting()
context.COLLECTIONS_DIRECTORY = new File(workspace, 'collection').absolutePath
new File(context.COLLECTIONS_DIRECTORY).mkdirs()
script.binding.setVariable('pwd', workspace.absolutePath)
context.ND_GIT_BRANCH = 'feature/fixture'
context.ND_GIT_REPOSITORY = 'https://github.com/CiscoDevNet/ansible-nd.git'
context.ND_GIT_COMMIT = 'a' * 40
context.BASE_DIRECTORY = new File(context.HOME, 'ansible').absolutePath
context.PATH = '/usr/bin:/bin'
script.metaClass.httpRequest = { Map options ->
    requests.add(options)
    if (options.url.endsWith('/nd_verify_develop_sources.py?raw')) {
        return [content: 'import os,sys\nassert sys.argv[1:] == ["--collection-root",os.environ["COLLECTIONS_DIRECTORY"],"--expected-branch",os.environ["ND_GIT_BRANCH"],"--expected-commit",os.environ["ND_GIT_COMMIT"]]\nopen(os.path.join(os.environ["WORKSPACE"],"source-checks"),"a").write("verified")\n' + (sourceOk ? '' : 'sys.exit(3)\n')]
    }
    return [content: 'canonical input: ' + options.url.toString() + '\n']
}
script.metaClass.stage = { Object name, Closure work -> work.call() }
script.metaClass.script = { Closure work -> work.call() }
script.metaClass.usernamePassword = { Map value -> value }
script.metaClass.withCredentials = { List entries, Closure work ->
    context.ANSIBLE_NXOS_SWITCH_USERNAME = 'offline-user'
    context.ANSIBLE_NXOS_SWITCH_PASSWORD = 'offline-fixture'
    work.call()
}
def phases = []
script.metaClass.applyFabricRound = { Object config ->
    assert new File(context.COLLECTIONS_DIRECTORY, 'integration_config.yml').text.startsWith('canonical input:')
    phases.add('render')
}
script.metaClass.generateDynamicInventory = { Object config -> phases.add('inventory') }
script.metaClass.runSwitchPreflight = { Object config -> phases.add('pre') }
script.metaClass.runFabricTest = { Object config ->
    phases.add('tests')
    new File(context.COLLECTIONS_DIRECTORY, 'integration_config.yml').text = 'mutated working copy'
}
script.metaClass.runSwitchPostRestore = { Object config -> phases.add('post') }
def config = [version: '4.3', versionId: 'fixture', fabric_name: 'fixture', round_tag: '']
def failure = null
try { script.runNDFCVersionTests(config) } catch (Exception e) { failure = e }
if (!sourceOk) {
    assert failure != null
    assert phases.isEmpty() : phases
    assert new File(workspace, 'source-checks').text == 'verified'
    assert context.REQUIRED_FILES_READY != 'true'
} else {
assert failure == null : failure
assert requests.size() == 36 : requests.size()
script.runNDFCVersionTests(config)
assert requests.size() == 36
def releaseRequests = requests.findAll { it.url.contains('/releases/bounded-switch-lifecycle-20261029/') }
assert releaseRequests.size() == 2
assert releaseRequests.any { it.url.endsWith('/nd_ensure_switches.yaml?raw') }
assert releaseRequests.any { it.url.endsWith('/action_plugins/nd_switch_discovery.py?raw') }
assert new File(context.ND_RUNTIME_INPUTS, 'nd_ensure_switches.yaml').text.contains('/releases/bounded-switch-lifecycle-20261029/')
assert new File(context.ND_RUNTIME_INPUTS, 'action_plugins/nd_switch_discovery.py').text.contains('/releases/bounded-switch-lifecycle-20261029/')
assert !new File(context.ND_RUNTIME_INPUTS, 'releases').exists()
assert phases == ['render', 'inventory', 'pre', 'tests', 'post'] * 2
assert new File(workspace, 'source-checks').text == 'verifiedverified'
assert new File(context.ND_RUNTIME_INPUTS, 'integration_config.yml').text.startsWith('canonical input:')
assert !new File(context.COLLECTIONS_DIRECTORY, 'requirements.txt').exists()
assert !new File(context.COLLECTIONS_DIRECTORY, 'nd_report.py').exists()
assert requests.every { !it.url.contains('requirements.') }
}
''', setup=setup, jenkinsfile=ROOT / variant)


@pytest.mark.parametrize('variant', VARIANTS)
def test_branch_parameter_uses_the_actual_blank_fallback_expression(groovy_runner, variant):
    groovy_runner(r'''
def expression = (source =~ /def selection = ([^\r\n]+)/)
assert expression.find()
def code = expression.group(1)
[[null, 'develop'], ['', 'develop'], ['   ', 'develop'],
 ['feature/topic', 'feature/topic'], ['  feature/topic  ', 'feature/topic']].each { pair ->
    def shell = new GroovyShell(new Binding([params: [ND_GIT_BRANCH: pair[0]]]))
    assert shell.evaluate(code) == pair[1]
}
''', jenkinsfile=ROOT / variant)


@pytest.mark.parametrize('variant', VARIANTS)
def test_partial_snapshot_never_becomes_ready(groovy_runner, variant):
    groovy_runner(r'''
script.prepareStructuredReporting()
script.metaClass.httpRequest = { Map options ->
    requests.add(options)
    return [content: requests.size() == 3 ? '' : 'fixture\n']
}
def failure = null
try { script.prepareRuntimeInputs() } catch (Exception e) { failure = e }
assert failure != null
assert context.ND_RUNTIME_INPUTS_READY == 'false'
assert context.CONSUL_SYNC_FAILED == 'true'
''', jenkinsfile=ROOT / variant)


@pytest.mark.parametrize('variant', VARIANTS)
@pytest.mark.parametrize('failure', ('none', 'source', 'preflight', 'physical'))
def test_guard_scoping_preserves_integrity_and_physical_failures(tmp_path, variant, failure):
    source = (ROOT / variant).read_text()
    guard = source.split('                                FIRST_TARGET_GUARD=true', 1)[1].split('                                # nd_vpc_pair', 1)[0]
    collection = tmp_path / 'collection'
    collection.mkdir()
    (collection / 'nd_verify_develop_sources.py').write_text('import os,sys\nassert sys.argv[sys.argv.index("--expected-branch")+1] == os.environ["ND_GIT_BRANCH"]\nopen(os.environ["CALLS"], "a").write("source\\n")\nsys.exit(3 if os.environ["FAILURE"] == "source" else 0)\n')
    guard_file = collection / 'guard.yaml'
    guard_file.write_text('---\n')
    binary = tmp_path / 'bin'
    binary.mkdir()
    command = binary / 'ansible-playbook'
    command.write_text('#!/bin/sh\necho physical >> "$CALLS"\n[ "$FAILURE" != physical ]\n')
    command.chmod(0o755)
    env = dict(os.environ, COLLECTIONS_DIRECTORY=str(collection), ND_GIT_COMMIT='fixture',
               ND_GIT_BRANCH='feature/fixture',
               CALLS=str(tmp_path / 'calls'), FAILURE=failure,
               ND_SWITCH_PREFLIGHT_READY='false' if failure == 'preflight' else 'true',
               PATH=str(binary) + os.pathsep + os.environ['PATH'])
    shell = 'set -e\nFIRST_TARGET_GUARD=true\n' + guard + '''
SWITCH_GUARD_PLAYBOOK="$COLLECTIONS_DIRECTORY/guard.yaml"
SWITCH_GUARD_TIMEOUT=30
SWITCH_GUARD_APPLY=true
ensure_switches_ready "first policy" nd_manage_policy
ensure_switches_ready "controller" nd_local_user
ensure_switches_ready "fabric policy" nd_manage_policy
'''
    result = subprocess.run(['/bin/bash', '-c', shell], env=env, text=True, capture_output=True)
    calls = (tmp_path / 'calls').read_text().splitlines()
    if failure == 'none':
        assert result.returncode == 0, result.stdout + result.stderr
        assert calls == ['source', 'source', 'source', 'physical']
        assert 'REUSED_PREFLIGHT' in result.stdout and 'NOT_APPLICABLE' in result.stdout
    else:
        assert result.returncode != 0
        assert calls == (['source', 'source', 'source', 'physical'] if failure == 'physical' else ['source'])
