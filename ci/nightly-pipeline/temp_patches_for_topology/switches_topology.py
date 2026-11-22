"""The sole allowed collection patch: switches gathered-count topology assertions."""

import argparse
import difflib
import importlib.util
from pathlib import Path
import re
import subprocess


PATCH = Path(__file__).with_name('nd_manage_switches_counts.patch')
FILES = {
    'tests/integration/targets/nd_manage_switches/tests/sanity.yaml': 'gathered_result',
    'tests/integration/targets/nd_manage_switches/tests/gathered.yaml': 'query_result',
}


def git(root, *arguments):
    return subprocess.check_output(['git', '-C', str(root), *arguments], stderr=subprocess.DEVNULL)


def patched_bytes(relative, original):
    if relative not in FILES:
        raise ValueError('Path is outside the switches topology exception')
    result = FILES[relative]
    source = original.decode('utf-8')
    old = f'      - {result}.gathered | length == nd_switches_base_conf | length\n'
    seeds = f"({result}.gathered | map(attribute='seed_ip') | list)"
    fixture = "(nd_switches_base_conf | map(attribute='seed_ip') | sort | list)"
    roster = "(nd_pipeline_switches_topology | default(nd_switches_base_conf) | map(attribute='seed_ip') | sort | list)"
    new = ('      - nd_pipeline_switches_topology | default(nd_switches_base_conf) | length > 0\n'
           f'      - {seeds} | unique | list | length == {result}.gathered | length\n'
           f'      - ({seeds} | sort | list) in [{fixture}, {roster}]\n')
    old_message = '      expected {{ nd_switches_base_conf | length }}\n'
    new_message = ('      expected the exact test fixture ({{ nd_switches_base_conf | length }}) or the exact declared fabric roster '
                   '({{ nd_pipeline_switches_topology | default(nd_switches_base_conf) | length }}); '
                   'missing, duplicate, or unexpected seeds are not allowed\n')
    if source.count(old) != 1 or source.count(old_message) != 1:
        raise ValueError('Switches count assertion changed upstream; patch review is required')
    return source.replace(old, new, 1).replace(old_message, new_message, 1).encode('utf-8')


def originals(root, expected_commit):
    root = Path(root).resolve()
    if git(root, 'rev-parse', 'HEAD').decode().strip() != expected_commit:
        raise ValueError('Collection commit differs from the selected checkout')
    return {name: git(root, 'show', expected_commit + ':' + name) for name in FILES}


def render_patch(root, expected_commit):
    sources = originals(root, expected_commit)
    return ''.join(''.join(difflib.unified_diff(
        value.decode().splitlines(keepends=True), patched_bytes(name, value).decode().splitlines(keepends=True),
        fromfile='a/' + name, tofile='b/' + name)) for name, value in sources.items())


def normalized_patch(value):
    return re.sub(r'^@@ .*? @@.*$', '@@', value, flags=re.M)


def apply(root, expected_commit, patch_path=PATCH):
    root = Path(root).resolve()
    sources = originals(root, expected_commit)
    expected = render_patch(root, expected_commit)
    actual = Path(patch_path).read_text(encoding='utf-8')
    if normalized_patch(actual) != normalized_patch(expected):
        raise ValueError('Only the reviewed two-file switches topology patch is allowed')
    already_applied = []
    for name, value in sources.items():
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Unsafe collection source path')
        current = path.read_bytes()
        approved = patched_bytes(name, value)
        if current not in (value, approved):
            raise ValueError('Unrelated collection edits must not be overwritten')
        already_applied.append(current == approved)
    if all(already_applied):
        return
    if any(already_applied):
        raise ValueError('Partial topology patch detected; restore and review before retry')
    subprocess.run(['git', '-C', str(root), 'apply', '--check', str(Path(patch_path).resolve())], check=True, capture_output=True)
    subprocess.run(['git', '-C', str(root), 'apply', str(Path(patch_path).resolve())], check=True, capture_output=True)
    for name, value in sources.items():
        if (root / name).read_bytes() != patched_bytes(name, value):
            raise ValueError('Topology patch readback mismatch')


def restore(root, expected_commit):
    root = Path(root).resolve()
    sources = originals(root, expected_commit)
    for name, value in sources.items():
        path = root / name
        if path.is_symlink() or path.read_bytes() not in (value, patched_bytes(name, value)):
            raise ValueError('Refusing to overwrite an unrelated source change during restore')
    for name, value in sources.items():
        if (root / name).read_bytes() != value:
            (root / name).write_bytes(value)


def run(root, expected_commit, expected_branch, command):
    if not command:
        raise ValueError('A switches integration command is required')
    root = Path(root).resolve()
    specification = importlib.util.spec_from_file_location('nd_topology_source_verifier', root / 'nd_verify_develop_sources.py')
    verifier = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(verifier)
    verifier.verify(root, expected_commit, expected_branch)
    apply(root, expected_commit, root / 'temp_patches_for_topology/nd_manage_switches_counts.patch')
    try:
        verifier.verify(root, expected_commit, expected_branch, allow_switches_topology_patch=True)
        return subprocess.run(command, cwd=root).returncode
    finally:
        restore(root, expected_commit)
        verifier.verify(root, expected_commit, expected_branch)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['render', 'apply', 'restore', 'run'])
    parser.add_argument('--collection-root', type=Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--expected-branch', default='develop')
    args, command = parser.parse_known_args()
    if command[:1] == ['--']:
        command = command[1:]
    try:
        if args.action == 'render':
            PATCH.write_text(render_patch(args.collection_root, args.expected_commit), encoding='utf-8')
        elif args.action == 'apply':
            apply(args.collection_root, args.expected_commit)
        elif args.action == 'run':
            return run(args.collection_root, args.expected_commit, args.expected_branch, command)
        else:
            restore(args.collection_root, args.expected_commit)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('NDP_SWITCHES_TOPOLOGY_PATCH_FAILED: ' + type(error).__name__)
        return 1
    print('NDP_SWITCHES_TOPOLOGY_PATCH: ' + args.action)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())