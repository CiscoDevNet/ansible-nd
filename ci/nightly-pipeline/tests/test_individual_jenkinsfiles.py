"""Verify isolated target selection without changing the shared pipeline."""

import importlib.util
import json
from pathlib import Path
import re

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'individual_jenkinsfiles', ROOT / 'tools/generate_individual_jenkinsfiles.py')
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


@pytest.fixture(scope='module')
def source():
    return generator.TEMPLATE.read_text(encoding='utf-8')


def selections(script, name):
    block = generator.selector_pattern(name).search(script).group()
    return re.findall(r"^\s*'([^']+)',?\s*$", block, re.M)


@pytest.mark.parametrize('target', generator.TARGETS)
def test_each_script_selects_only_its_target_and_private_webex(source, target):
    script = generator.render(source, target)
    selected = []
    for name in generator.SELECTORS:
        if name != 'VPC_PAIR_EXECUTIONS':
            selected.extend(selections(script, name))
    assert selected == (['nd_vpc_pair'] if target.startswith('nd_vpc_pair.') else [target])
    pairs = generator.selector_pattern('VPC_PAIR_EXECUTIONS').search(script).group()
    assert re.findall(r"\[id: '([^']+)'", pairs) == (
        [target.split('.')[1]] if target.startswith('nd_vpc_pair.') else [])
    assert re.findall(r'^\s*WEBEX_ROOM_ID\s*=\s*(.+)$', script, re.M) == [
        '"${WEBEX_ROOM_ID_PRIVATE}"     // Private space']
    assert 'for m in ${ORDERED_INTEGRATION_LIST}; do' in script
    assert all(line == line.rstrip() for line in script.splitlines())
    if target.startswith('nd_vpc_pair.'):
        assert script.count('orderedIntegrationTargets.addAll(standaloneTargets)') == 2
        assert '    targets.addAll(pairRows.collect { "nd_vpc_pair.${it.id}".toString() })' in script


@pytest.mark.parametrize('target', generator.TARGETS)
def test_template_is_preserved_outside_selection_and_vpc_routing(source, target):
    rendered = generator.render(source, target)
    if target.startswith('nd_vpc_pair.'):
        rendered = rendered.replace(
            "            if (env.ND_PREREQUISITE_ONLY_EFFECTIVE != 'true') {\n"
            '                orderedIntegrationTargets.addAll(standaloneTargets)\n'
            '            }\n', '', 1)
        rendered = rendered.replace(
            '\n    targets.addAll(pairRows.collect { "nd_vpc_pair.${it.id}".toString() })\n'
            '    targets.addAll(PLAYBOOK_FILES)',
            '\n    targets.addAll(PLAYBOOK_FILES)', 1)
    for name in generator.SELECTORS:
        rendered = generator.selector_pattern(name).sub('SELECTION_' + name, rendered)
        source = generator.selector_pattern(name).sub('SELECTION_' + name, source)
    assert rendered == '\n'.join(line.rstrip() for line in source.splitlines()) + '\n'


def test_generate_all_34_scripts_with_manifest_and_non_destructive_recheck(tmp_path):
    output = tmp_path / 'individual'
    assert generator.generate(output=output) == 34
    assert len(list(output.glob('Jenkinsfile_*'))) == 34
    manifest = json.loads((output / 'index.json').read_text())
    assert [row['target'] for row in manifest['targets']] == list(generator.TARGETS)
    assert generator.generate(output=output, check=True) == 34
    assert generator.generate(output=output) == 34
    changed = output / manifest['targets'][0]['file']
    changed.write_text('user edit')
    with pytest.raises(ValueError, match='Refusing to overwrite'):
        generator.generate(output=output)
    assert changed.read_text() == 'user edit'


def test_public_destination_and_template_drift_fail_closed(source):
    with pytest.raises(ValueError, match='private Webex'):
        generator.render(source.replace(
            'WEBEX_ROOM_ID = "${WEBEX_ROOM_ID_PRIVATE}"',
            'WEBEX_ROOM_ID = "${WEBEX_ROOM_ID_PUBLIC}"'), generator.TARGETS[0])
    with pytest.raises(ValueError, match='selector'):
        generator.render(source.replace('def PLAYBOOK_FILES = [', 'def OTHER_FILES = ['), generator.TARGETS[0])


def test_refresh_updates_unmodified_outputs_but_preserves_user_edits(tmp_path, source):
    template = tmp_path / 'template'
    template.write_text(source)
    output = tmp_path / 'individual'
    generator.generate(template=template, output=output)
    template.write_text(source + '\n')
    assert generator.generate(template=template, output=output, refresh=True) == 34
    assert generator.generate(template=template, output=output, check=True) == 34
    changed = output / 'Jenkinsfile_nd_manage_policy'
    changed.write_text('user edit')
    untouched = output / 'Jenkinsfile_nd_manage_policy_group'
    before = untouched.read_bytes()
    template.write_text(source + '\n\n')
    with pytest.raises(ValueError, match='Refusing to overwrite'):
        generator.generate(template=template, output=output, refresh=True)
    assert changed.read_text() == 'user edit'
    assert untouched.read_bytes() == before