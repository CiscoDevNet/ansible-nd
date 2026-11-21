#!/usr/bin/env python3
"""Check that every ND4x harness consumer can load the shared test role.

Run from any directory with:

    python tests/scripts/check_nd4x_helper_reachability.py

Add ``--loader-smoke`` to run a local Ansible syntax check for the role-local
action plugin and helper modules. The smoke check does not contact an ND device.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
TARGETS_ROOT = REPO_ROOT / "tests" / "integration" / "targets"
HELPER_ROLE = "nd4x_test_helpers"
HELPER_ROOT = TARGETS_ROOT / HELPER_ROLE
NEW_CALLS = {"nd4x_module_test", "ansible.legacy.nd4x_module_test"}
CALL_RE = re.compile(
    r"^\s*(?P<call>(?:cisco\.nd\.|ansible\.legacy\.)?nd4x_module_test)\s*:"
)
ACTION_RE = re.compile(
    r"^\s*(?:ansible\.builtin\.)?action\s*:\s*"
    r"(?P<call>(?:cisco\.nd\.|ansible\.legacy\.)?nd4x_module_test)(?:\s|$)"
)


@dataclass(frozen=True)
class Consumer:
    name: str
    role_path: Path
    files: tuple[Path, ...]
    calls: tuple[tuple[Path, int, str], ...]


def _iter_source_files(directory: Path) -> Iterable[Path]:
    for pattern in ("*.yml", "*.yaml", "*.md"):
        yield from directory.rglob(pattern)


def _calls_in_file(path: Path) -> list[tuple[int, str]]:
    calls: list[tuple[int, str]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        match = CALL_RE.match(line) or ACTION_RE.match(line)
        if match:
            calls.append((line_number, match.group("call")))
    return calls


def discover_consumers(targets_root: Path = TARGETS_ROOT) -> list[Consumer]:
    """Find each integration target that invokes the ND4x test harness."""
    consumers: list[Consumer] = []
    if not targets_root.is_dir():
        return consumers

    for role_path in sorted(path for path in targets_root.iterdir() if path.is_dir()):
        if role_path.name == HELPER_ROLE:
            continue
        files = tuple(_iter_source_files(role_path))
        calls = tuple(
            (path, line_number, call)
            for path in files
            for line_number, call in _calls_in_file(path)
        )
        if calls:
            consumers.append(Consumer(role_path.name, role_path, files, calls))
    return consumers


def _dependency_names(meta_path: Path) -> set[str]:
    if not meta_path.is_file():
        return set()
    try:
        meta = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return set()
    dependencies = meta.get("dependencies", []) if isinstance(meta, dict) else []
    if not isinstance(dependencies, list):
        return set()

    names: set[str] = set()
    for dependency in dependencies:
        if isinstance(dependency, str):
            names.add(dependency)
        elif isinstance(dependency, dict):
            name = dependency.get("role") or dependency.get("name")
            if isinstance(name, str):
                names.add(name)
    return names


def _display_path(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def contract_errors(
    consumers: list[Consumer],
    helper_root: Path = HELPER_ROOT,
    repo_root: Path = REPO_ROOT,
    require_consumers: bool = False,
) -> list[str]:
    """Return migration-contract failures for the proposed role layout."""
    errors: list[str] = []
    required_files = (
        helper_root / "aliases",
        helper_root / "tasks" / "main.yml",
        helper_root / "action_plugins" / "nd4x_module_test.py",
        helper_root / "library" / "nd4x_module_test.py",
        helper_root / "library" / "nd4x_l3out_create_lock.py",
    )
    for path in required_files:
        if not path.is_file():
            display_path = _display_path(path, repo_root)
            errors.append(f"missing helper-role file: {display_path}")

    if require_consumers and not consumers:
        errors.append(f"no harness consumers found under {TARGETS_ROOT}")

    for consumer in consumers:
        meta_path = consumer.role_path / "meta" / "main.yml"
        if HELPER_ROLE not in _dependency_names(meta_path):
            errors.append(
                f"{consumer.name}: meta/main.yml must depend on role {HELPER_ROLE!r}"
            )
        outdated_calls = [call for call in consumer.calls if call[2] not in NEW_CALLS]
        if outdated_calls:
            examples = ", ".join(
                f"{_display_path(path, repo_root)}:{line_number} ({call})"
                for path, line_number, call in outdated_calls[:3]
            )
            suffix = " ..." if len(outdated_calls) > 3 else ""
            errors.append(
                f"{consumer.name}: {len(outdated_calls)} call(s) need the new "
                f"short name; examples: {examples}{suffix}"
            )
    return errors


def run_loader_smoke(
    ansible_playbook: str | None = None,
    targets_root: Path = TARGETS_ROOT,
) -> tuple[bool, str]:
    """Resolve helper plugins through a consumer role dependency, without running it."""
    executable = ansible_playbook or shutil.which("ansible-playbook")
    if not executable:
        return (
            False,
            "ansible-playbook was not found (activate the project venv or pass --ansible-playbook)",
        )

    with tempfile.TemporaryDirectory(prefix="nd4x-loader-smoke-") as temp_dir:
        temp_path = Path(temp_dir)
        consumer_roles_root = temp_path / "consumer_roles"
        consumer_role = consumer_roles_root / "nd4x_loader_probe"
        (consumer_role / "meta").mkdir(parents=True)
        (consumer_role / "tasks").mkdir()
        (consumer_role / "meta" / "main.yml").write_text(
            "---\ndependencies:\n  - role: nd4x_test_helpers\n",
            encoding="utf-8",
        )
        (consumer_role / "tasks" / "main.yml").write_text(
            """---
- name: Resolve the helper action through its consumer dependency
  nd4x_module_test:
    module: ansible.builtin.debug
    module_args:
      msg: loader-smoke
- name: Resolve the L3Out lock module through its consumer dependency
  nd4x_l3out_create_lock:
    config:
      name: loader-smoke
""",
            encoding="utf-8",
        )
        playbook = temp_path / "loader-smoke.yml"
        playbook.write_text(
            """---
- name: Verify helper plugin discovery through a consumer role dependency
  hosts: localhost
  gather_facts: false
  roles:
    - nd4x_loader_probe
""",
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["ANSIBLE_ROLES_PATH"] = os.pathsep.join(
            (str(consumer_roles_root), str(targets_root))
        )
        env["ANSIBLE_LOCAL_TEMP"] = str(temp_path / "ansible-local")
        result = subprocess.run(
            [executable, "--syntax-check", str(playbook)],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        output = (result.stdout + result.stderr).strip()
        if result.returncode:
            return (
                False,
                output or f"ansible-playbook exited with status {result.returncode}",
            )
        return True, output or "ansible-playbook syntax check passed"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--loader-smoke",
        action="store_true",
        help="also run an offline ansible-playbook syntax check for plugin discovery",
    )
    parser.add_argument(
        "--ansible-playbook",
        help="ansible-playbook executable to use with --loader-smoke",
    )
    parser.add_argument(
        "--targets-root",
        type=Path,
        default=TARGETS_ROOT,
        help="integration targets directory to scan (defaults to this checkout)",
    )
    parser.add_argument(
        "--require-consumers",
        action="store_true",
        help="fail if the selected targets directory has no harness callers",
    )
    args = parser.parse_args(argv)

    targets_root = args.targets_root.resolve()
    helper_root = targets_root / HELPER_ROLE
    consumers = discover_consumers(targets_root)
    print(
        f"Found {len(consumers)} integration target(s) calling nd4x_module_test "
        f"under {targets_root}."
    )
    errors = contract_errors(
        consumers,
        helper_root=helper_root,
        repo_root=REPO_ROOT,
        require_consumers=args.require_consumers,
    )
    for consumer in consumers:
        print(f"  {consumer.name}: {len(consumer.calls)} call site(s)")

    if args.loader_smoke:
        passed, message = run_loader_smoke(args.ansible_playbook, targets_root)
        print(f"Loader smoke: {'PASS' if passed else 'FAIL'}: {message}")
        if not passed:
            errors.append("Ansible loader smoke check failed")

    if errors:
        print("\nReachability contract failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print("\nReachability contract passed for every discovered consumer.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
