"""Offline checks for the sole approved switches topology patch."""

import importlib.util
from pathlib import Path
import subprocess
import sys

from ansible.plugins.filter.core import FilterModule
from jinja2.nativetypes import NativeEnvironment
import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = Path(__file__).with_name('switches_topology.py').resolve()
SPEC = importlib.util.spec_from_file_location('switches_topology', POLICY_PATH)
assert SPEC is not None and SPEC.loader is not None
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


@pytest.fixture
def checkout(tmp_path):
    root = tmp_path / 'collection'
    root.mkdir()
    candidates = [ROOT.parents[1], ROOT.parent / 'checkouts/build148-collection-fixes']
    original_root = next((candidate for candidate in candidates
                          if all((candidate / relative).is_file() for relative in POLICY.FILES)), None)
    assert original_root is not None, 'Original collection switches integration sources are required'
    for relative in POLICY.FILES:
        source = original_root / relative
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(source.read_bytes())
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()
    git('init', '-q', '-b', 'develop')
    git('config', 'user.name', 'Offline fixture')
    git('config', 'user.email', 'fixture@example.invalid')
    git('add', '.')
    git('commit', '-qm', 'Original switches fixtures')
    commit = git('rev-parse', 'HEAD')
    patch = tmp_path / 'counts.patch'
    patch.write_text(POLICY.render_patch(root, commit))
    tools = root / 'temp_patches_for_topology'
    tools.mkdir()
    (tools / 'switches_topology.py').write_bytes(POLICY_PATH.read_bytes())
    (tools / 'nd_manage_switches_counts.patch').write_bytes(patch.read_bytes())
    (root / 'nd_verify_develop_sources.py').write_bytes((ROOT / 'playbooks/nd_verify_develop_sources.py').read_bytes())
    return root, commit, patch, git


def test_only_two_assertions_change_and_restore_is_exact(checkout):
    root, commit, patch, git = checkout
    before = {name: (root / name).read_bytes() for name in POLICY.FILES}
    POLICY.apply(root, commit, patch)
    assert set(git('diff', '--name-only').splitlines()) == set(POLICY.FILES)
    POLICY.apply(root, commit, patch)
    for name, original in before.items():
        original_tasks = yaml.safe_load(original)
        changed_tasks = yaml.safe_load((root / name).read_bytes())
        assert len(changed_tasks) == len(original_tasks)
        for original_task, changed_task in zip(original_tasks, changed_tasks):
            if 'Validate Gathered Count' not in original_task.get('name', ''):
                assert original_task == changed_task
    POLICY.restore(root, commit)
    assert git('diff', '--name-only') == ''
    assert all((root / name).read_bytes() == value for name, value in before.items())


def test_reviewed_patch_artifact_matches_the_current_generator(checkout):
    _, _, generated, _ = checkout
    assert POLICY.normalized_patch(POLICY.PATCH.read_text()) == POLICY.normalized_patch(generated.read_text())


@pytest.mark.parametrize('actual,valid', [
    ([1, 2, 3], True), ([1, 2, 3, 4, 5, 6], True),
    ([1, 2], False), ([1, 2, 3, 4, 5], False),
    ([1, 2, 3, 4, 5, 6, 7], False), ([1, 2, 3, 4, 5, 5], False),
    ([1, 2, 4, 5, 6, 7], False),
])
@pytest.mark.parametrize('relative', POLICY.FILES)
def test_exact_fixture_or_full_declared_roster_only(checkout, relative, actual, valid):
    root, _, _, _ = checkout
    changed = yaml.safe_load(POLICY.patched_bytes(relative, (root / relative).read_bytes()))
    task = next(item for item in changed if 'Validate Gathered Count' in item.get('name', ''))
    result_name = POLICY.FILES[relative]
    switches = lambda values: [{'seed_ip': '192.0.2.' + str(value)} for value in values]
    environment = NativeEnvironment()
    environment.filters.update(FilterModule().filters())
    variables = {result_name: {'gathered': switches(actual)},
                 'nd_switches_base_conf': switches([1, 2, 3]),
                 'nd_pipeline_switches_topology': switches([1, 2, 3, 4, 5, 6])}
    assert all(environment.from_string('{{ ' + condition + ' }}').render(**variables)
               for condition in task['ansible.builtin.assert']['that']) is valid


def test_unknown_changes_and_extra_patch_are_rejected(checkout):
    root, commit, patch, _ = checkout
    path = root / next(iter(POLICY.FILES))
    path.write_bytes(path.read_bytes() + b'\n# unrelated edit\n')
    with pytest.raises(ValueError, match='Unrelated'):
        POLICY.apply(root, commit, patch)
    with pytest.raises(ValueError, match='unrelated'):
        POLICY.restore(root, commit)
    patch.write_text(patch.read_text() + '\n--- a/plugins/modules/nd_other.py\n')
    with pytest.raises(ValueError, match='Only the reviewed'):
        POLICY.apply(root, commit, patch)


@pytest.mark.parametrize('exit_code', [0, 2])
def test_switches_command_restores_pristine_sources_even_after_failure(checkout, exit_code):
    root, commit, patch, git = checkout
    assert POLICY.run(root, commit, 'develop', [sys.executable, '-c', 'raise SystemExit(' + str(exit_code) + ')']) == exit_code
    assert git('diff', '--name-only') == ''


def test_integrity_exception_accepts_only_the_exact_two_topology_edits(checkout):
    root, commit, patch, _ = checkout
    specification = importlib.util.spec_from_file_location('topology_verifier_test', root / 'nd_verify_develop_sources.py')
    assert specification is not None and specification.loader is not None
    verifier = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(verifier)
    POLICY.apply(root, commit, patch)
    with pytest.raises(ValueError, match='modified'):
        verifier.verify(root, commit)
    assert verifier.verify(root, commit, allow_switches_topology_patch=True) == commit
    target = root / next(iter(POLICY.FILES))
    target.write_bytes(target.read_bytes() + b'\n# another patch\n')
    with pytest.raises(ValueError, match='modified'):
        verifier.verify(root, commit, allow_switches_topology_patch=True)


def test_jenkins_applies_only_the_named_switches_topology_patch():
    for variant in ('Jenkinsfile_nd_jenkins_script', 'Jenkinsfile_nd_jenkins_script_temp_switches', 'Jenkinsfile_nd_jenkins_script_comm_list'):
        source = (ROOT / variant).read_text()
        assert "'temp_patches_for_topology/nd_manage_switches_counts.patch'" in source
        assert 'if [ "${result_module}" = "nd_manage_switches" ]; then\n                                        result_command=(python' in source
        assert '--expected-commit "${ND_GIT_COMMIT}" -- "$@")' in source
        assert 'git apply' not in source


@pytest.mark.parametrize('variant', ['Jenkinsfile_nd_jenkins_script', 'Jenkinsfile_nd_jenkins_script_temp_switches', 'Jenkinsfile_nd_jenkins_script_comm_list'])
@pytest.mark.parametrize('module', ['nd_manage_switches', 'nd_manage_policy', 'nd_fabric_update_group'])
def test_real_shell_dispatch_wraps_only_the_switches_target(variant, module):
    source = (ROOT / variant).read_text()
    start = '                                    local result_command=("$@")'
    block = start + source.split(start, 1)[1].split('                                    result_end=', 1)[0]
    shell = '''set -e
COLLECTIONS_DIRECTORY=/fixture
ND_GIT_BRANCH=develop
ND_GIT_COMMIT=fixture-commit
python() { printf 'TOPOLOGY_WRAPPER\\n'; }
fixture_command() { printf 'ORIGINAL_COMMAND\\n'; }
dispatch() {
    local result_module="$1"
    shift
    local result_status
    local result_compat_env=() result_compat_args=()
''' + block + '\nreturn "$result_status"\n}\ndispatch ' + module + ' fixture_command -e test_module=' + module + '\n'
    done = subprocess.run(['/bin/bash'], input=shell, text=True, capture_output=True, timeout=5)
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.strip() == ('TOPOLOGY_WRAPPER' if module == 'nd_manage_switches' else 'ORIGINAL_COMMAND')


def test_sync_manifest_contains_only_the_named_topology_patch():
    sync_path = ROOT / 'consul_sync.py'
    if not sync_path.is_file():
        sync_path = ROOT.parent / 'consul_sync.py'
    specification = importlib.util.spec_from_file_location('topology_consul_sync_test', sync_path)
    assert specification is not None and specification.loader is not None
    sync = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(sync)
    sources = sync.required_runtime_sources()
    patch_keys = [key for key in sources if key.endswith(('.patch', '.diff'))]
    assert patch_keys == ['temp_patches_for_topology/nd_manage_switches_counts.patch']
    assert Path(sources[patch_keys[0]]).resolve() == Path(POLICY.PATCH).resolve()
    assert Path(sources['temp_patches_for_topology/switches_topology.py']).resolve() == POLICY_PATH


def test_authoritative_eight_switch_identities_roles_and_fixture_projection():
    expected = {
        'VXLAN_EVPN_Fabric': {
            ('vxlan_border_1', '192.0.2.88', 'SERIAL00004', 'border'),
            ('vxlan_leaf_1', '192.0.2.195', 'SERIAL00001', 'leaf'),
            ('vxlan_leaf_2', '192.0.2.196', 'SERIAL00002', 'leaf'),
            ('vxlan_leaf_3', '192.0.2.85', 'SERIAL00008', 'leaf'),
            ('vxlan_leaf_4', '192.0.2.86', 'SERIAL00009', 'leaf'),
            ('vxlan_spine_1', '192.0.2.194', 'SERIAL00003', 'spine'),
        },
        'External_Connectivity_Fabric': {
            ('external_edge_1', '192.0.2.89', 'SERIAL00005', 'edge_router'),
            ('external_edge_2', '192.0.2.90', 'SERIAL00006', 'edge_router'),
        },
    }
    config = yaml.safe_load((ROOT / 'tests/integration_config.yml').read_text())
    registry = yaml.safe_load((ROOT / 'tests/nd_prerequisite_profiles.yaml').read_text())
    fields = ('name', 'seed_ip', 'serial', 'role')
    for roster in (config['nd_test_fabric_switches'], registry['runtime_defaults']['nd_test_fabric_switches']):
        assert {fabric: {tuple(switch[key] for key in fields) for switch in switches}
                for fabric, switches in roster.items()} == expected
        assert len(roster['VXLAN_EVPN_Fabric']) == 6
        assert len(roster['External_Connectivity_Fabric']) == 2
    assert config['nd_manage_switches_test_projection'] == {
        'ansible_switch1': '192.0.2.195',
        'ansible_switch2': '192.0.2.194',
        'ansible_switch3': '192.0.2.88',
    }
    for switches in expected.values():
        for name, address, serial, role in switches:
            declared = registry['lab']['switches'][name]
            assert (declared['seed_ip'], declared['serial'], declared['baseline_role']) == (address, serial, role)


@pytest.mark.parametrize('relative', POLICY.FILES)
def test_empty_declared_topology_cannot_accept_empty_gathered_output(checkout, relative):
    root, _, _, _ = checkout
    tasks = yaml.safe_load(POLICY.patched_bytes(relative, (root / relative).read_bytes()))
    task = next(item for item in tasks if 'Validate Gathered Count' in item.get('name', ''))
    environment = NativeEnvironment()
    environment.filters.update(FilterModule().filters())
    variables = {POLICY.FILES[relative]: {'gathered': []}, 'nd_pipeline_switches_topology': [],
                 'nd_switches_base_conf': [{'seed_ip': '192.0.2.1'}]}
    assert not all(environment.from_string('{{ ' + condition + ' }}').render(**variables)
                   for condition in task['ansible.builtin.assert']['that'])