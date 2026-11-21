"""Migration-gate tests for the shared role-local ND4x harness."""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = REPO_ROOT / "tests" / "scripts" / "check_nd4x_helper_reachability.py"
SPEC = importlib.util.spec_from_file_location("nd4x_helper_reachability", CHECKER_PATH)
CHECKER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


HELPER_ROOT = CHECKER.HELPER_ROOT


def _make_consumer(targets_root, call_name, *, helper_dependency):
    consumer_root = targets_root / "example_target"
    tasks = consumer_root / "tasks"
    tasks.mkdir(parents=True)
    (tasks / "main.yml").write_text(
        f"---\n- name: Call the harness\n  {call_name}:\n    module: cisco.nd.nd_interface_loopback\n",
        encoding="utf-8",
    )
    if helper_dependency:
        meta = consumer_root / "meta"
        meta.mkdir()
        (meta / "main.yml").write_text(
            f"---\ndependencies:\n  - role: {CHECKER.HELPER_ROLE}\n",
            encoding="utf-8",
        )
    return CHECKER.discover_consumers(targets_root)[0]


def test_contract_accepts_migrated_consumer(tmp_path):
    targets_root = tmp_path / "targets"
    targets_root.mkdir()
    consumer = _make_consumer(
        targets_root,
        "nd4x_module_test",
        helper_dependency=True,
    )

    errors = CHECKER.contract_errors([consumer], helper_root=HELPER_ROOT, repo_root=REPO_ROOT)
    assert not errors, "\n".join(errors)


def test_contract_reports_consumer_that_has_not_migrated(tmp_path):
    targets_root = tmp_path / "targets"
    targets_root.mkdir()
    consumer = _make_consumer(
        targets_root,
        "cisco.nd.nd4x_module_test",
        helper_dependency=False,
    )

    errors = CHECKER.contract_errors([consumer], helper_root=HELPER_ROOT, repo_root=REPO_ROOT)
    assert any("must depend on role" in error for error in errors)
    assert any("call(s) need the new short name" in error for error in errors)


def test_shared_helper_role_files_are_present():
    errors = CHECKER.contract_errors([], helper_root=HELPER_ROOT, repo_root=REPO_ROOT)
    file_errors = [error for error in errors if error.startswith("missing helper-role file:")]
    assert not file_errors, "\n".join(file_errors)


def test_discovery_finds_harness_consumers(tmp_path):
    fixture_targets = tmp_path / "targets"
    fixture_consumer = fixture_targets / "example_target"
    task_dir = fixture_consumer / "tasks"
    task_dir.mkdir(parents=True, exist_ok=True)
    (task_dir / "main.yml").write_text(
        """---
- name: Exercise test harness
  nd4x_module_test:
    module: cisco.nd.nd_interface_loopback
""",
        encoding="utf-8",
    )
    consumers = CHECKER.discover_consumers(fixture_targets)
    assert [consumer.name for consumer in consumers] == ["example_target"]
    assert consumers[0].calls[0][2] == "nd4x_module_test"


def test_ansible_resolves_helper_plugins_through_consumer_dependency(tmp_path):
    ansible_playbook = os.environ.get("ANSIBLE_PLAYBOOK") or shutil.which("ansible-playbook")
    if not ansible_playbook:
        pytest.skip("set ANSIBLE_PLAYBOOK or put ansible-playbook on PATH")

    helper_root = tmp_path / "targets" / CHECKER.HELPER_ROLE
    (helper_root / "action_plugins").mkdir(parents=True)
    (helper_root / "library").mkdir()
    (helper_root / "tasks").mkdir()
    (helper_root / "aliases").write_text("hidden\n", encoding="utf-8")
    (helper_root / "tasks" / "main.yml").write_text("---\n[]\n", encoding="utf-8")
    (helper_root / "action_plugins" / "nd4x_module_test.py").write_text(
        """from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    pass
""",
        encoding="utf-8",
    )
    (helper_root / "library" / "nd4x_module_test.py").write_text(
        "#!/usr/bin/python\n"
        "DOCUMENTATION = r'''\n"
        "---\n"
        "module: nd4x_module_test\n"
        "short_description: Loader test module\n"
        "options: {}\n"
        "'''\n"
        "def main():\n"
        "    pass\n",
        encoding="utf-8",
    )
    (helper_root / "library" / "nd4x_l3out_create_lock.py").write_text(
        "#!/usr/bin/python\n"
        "DOCUMENTATION = r'''\n"
        "---\n"
        "module: nd4x_l3out_create_lock\n"
        "short_description: Loader test module\n"
        "options:\n"
        "  config:\n"
        "    type: dict\n"
        "    required: true\n"
        "'''\n"
        "def main():\n"
        "    pass\n",
        encoding="utf-8",
    )

    passed, message = CHECKER.run_loader_smoke(ansible_playbook, tmp_path / "targets")
    assert passed, message
