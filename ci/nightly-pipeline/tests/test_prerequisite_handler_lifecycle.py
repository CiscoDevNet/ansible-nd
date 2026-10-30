"""Exercise production prerequisite lock/restore boundaries with local files, never ND."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PREREQUISITES = ROOT / "playbooks/nd_prerequisite"
RUNNER = ROOT / "tests/run_integration_module.yaml"


def named(tasks, text):
    return copy.deepcopy(next(task for task in tasks if text in task.get("name", "")))


def execute(tmp_path, scenario, *, journal, custom, occupied=False):
    wrapper = yaml.safe_load((PREREQUISITES / "nd_prerequisite_wrapper.yaml").read_text())
    runner = yaml.safe_load(RUNNER.read_text())[0]
    assets = tmp_path / "nd_prerequisite"
    assets.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    parent = tmp_path / "prepared-parent"
    cleanup = tmp_path / "target-cleanup"
    lock = tmp_path / "nd-prerequisite-baseline.lock"
    if occupied:
        lock.mkdir()
        (lock / "owner.json").write_text('{"run_id":"another-run","execution_id":"another-target"}')

    # Keep the production restore journal, receipt, ownership check and lock release.
    # Replace only controller mutation with a local file operation.
    restore = yaml.safe_load((PREREQUISITES / "nd_prerequisite_restore.yaml").read_text())
    restore = [task for task in restore if not task.get("name", "").startswith((
        "Delete managed test subinterfaces", "Delete unmanaged test subinterfaces"))]
    (assets / "nd_prerequisite_restore.yaml").write_text(yaml.safe_dump(restore, sort_keys=False))
    (assets / "restore_interface_operation.yaml").write_text(yaml.safe_dump([
        {"name": "Verify authored cleanup precedes interface restoration", "ansible.builtin.assert": {
            "that": ["lookup('file', cleanup_marker) == 'complete'"]},
         "when": "lifecycle_scenario in ['success', 'target-failure']"},
        {"name": "Restore fixture parent", "ansible.builtin.file": {"path": str(parent), "state": "absent"}},
    ], sort_keys=False))

    preparation = [named(wrapper, "Initialize run-scoped"), named(wrapper, "Hold the exclusive")]
    if journal:
        preparation.extend([
            {"ansible.builtin.set_fact": {"_ndp_prerequisite_restore_operations": [
                {"action": "fixture_restore", "interface": "Ethernet1/35"}]}},
            {"ansible.builtin.copy": {"dest": str(parent), "content": "prepared"}},
        ])
    if scenario == "setup-failure":
        preparation.append({"ansible.builtin.fail": {"msg": "injected setup failure"}})
    if scenario == "skip":
        preparation.append({"ansible.builtin.set_fact": {"_ndp_plan": {"rc": 3}}})
        preparation.extend(named(wrapper, text) for text in (
            "Release run-owned resources", "End the play cleanly"))
    (assets / "nd_prerequisite_wrapper.yaml").write_text(yaml.safe_dump(preparation, sort_keys=False))

    pre = named(runner["pre_tasks"], "prepare and verify declared prerequisites")
    arm = named(runner["tasks"], "arm forced prerequisite restore handler")
    checks = [
        {"ansible.builtin.stat": {"path": str(lock)}, "register": "held_lock"},
        {"ansible.builtin.stat": {"path": str(parent)}, "register": "prepared_parent"},
        {"name": "Verify prerequisites survived the pre_tasks handler boundary", "ansible.builtin.assert": {
            "that": ["held_lock.stat.exists", "prepared_parent.stat.exists == journal_expected",
                     "(_ndp_prerequisite_restore_operations | length > 0) == journal_expected"]}},
    ]
    if scenario == "target-failure":
        checks.append({"ansible.builtin.fail": {"msg": "injected target failure"}})
    values = {
        "ansible_python_interpreter": sys.executable,
        "test_module": "nd_interface_loopback", "nd_prerequisite_enable": True,
        "nd_prerequisite_mode": "live", "nd_prerequisite_apply": True,
        "nd_prerequisite_repair_baseline": not custom,
        "nd_prerequisite_wrapper_path": str(assets / "nd_prerequisite_wrapper.yaml"),
        "nd_prerequisite_repair_lock_dir": str(lock), "_ndp_state_dir": str(state),
        "_ndp_run_id": "fixture-run", "_ndp_execution_id": "integration.nd_interface_loopback",
        "_ndp_profile": {"interface_selection_changed": custom, "switches": {"members": [{"ref": "leaf"}]}},
        "lifecycle_scenario": scenario, "cleanup_marker": str(cleanup), "journal_expected": journal,
    }
    play = {"hosts": "localhost", "connection": "local", "gather_facts": False,
            "force_handlers": runner["force_handlers"], "vars": values, "pre_tasks": [pre],
            "tasks": [arm, {"block": checks, "always": [
                {"ansible.builtin.copy": {"dest": str(cleanup), "content": "complete"}}]}],
            "handlers": runner["handlers"]}
    playbook = tmp_path / "play.yaml"
    playbook.write_text(yaml.safe_dump([play], sort_keys=False))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n")
    env = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_STDOUT_CALLBACK="default",
               ANSIBLE_LOCAL_TEMP=str(tmp_path / "local"), ANSIBLE_REMOTE_TEMP=str(tmp_path / "remote"),
               ANSIBLE_NOCOLOR="1", OBJC_DISABLE_INITIALIZE_FORK_SAFETY="YES")
    completed = subprocess.run([str(Path(sys.executable).with_name("ansible-playbook")),
                                "-i", "localhost,", str(playbook)], capture_output=True, text=True,
                               env=env, timeout=45)
    return completed, lock, parent, cleanup, state


@pytest.mark.parametrize("scenario", ["success", "target-failure", "setup-failure", "skip"])
@pytest.mark.parametrize("journal", [False, True], ids=["lock-only", "parent-journal"])
@pytest.mark.parametrize("custom", [False, True], ids=["baseline", "custom-selection"])
def test_production_lifecycle_holds_then_releases_own_resources(tmp_path, scenario, journal, custom):
    result, lock, parent, cleanup, state = execute(tmp_path, scenario, journal=journal, custom=custom)
    evidence = result.stdout + result.stderr
    assert result.returncode == (2 if scenario.endswith("failure") else 0), evidence
    assert not lock.exists(), evidence
    assert not parent.exists(), evidence
    assert cleanup.exists() == (scenario in {"success", "target-failure"}), evidence
    receipt = state / "interface-restore-complete.yaml"
    assert receipt.exists() == journal, evidence
    if journal:
        assert len(yaml.safe_load(receipt.read_text())["restored_operations"]) == 1
    if scenario in {"success", "target-failure"}:
        assert "Verify prerequisites survived the pre_tasks handler boundary" in result.stdout


def test_failed_lock_acquisition_never_releases_another_run(tmp_path):
    result, lock, parent, cleanup, _ = execute(tmp_path, "success", journal=False, custom=True, occupied=True)
    assert result.returncode == 2, result.stdout + result.stderr
    assert json.loads((lock / "owner.json").read_text())["run_id"] == "another-run"
    assert not parent.exists() and not cleanup.exists()
