"""Offline regressions for successful-result rendering across Ansible versions."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def callback(monkeypatch):
    for name in ("ND_RESULT_LOG", "ND_RESULT_MODULE", "TEST_RUN_MARKER", "ND_REPORT_DEBUG"):
        monkeypatch.delenv(name, raising=False)
    spec = importlib.util.spec_from_file_location("nd_report_compat", ROOT / "playbooks/nd_report.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.CallbackModule()


class ReadOnlyResult:
    """The getter-only interface introduced by CallbackTaskResult in Ansible 2.19."""

    def __init__(self, payload, no_log=False):
        self.payload = payload
        self._task = SimpleNamespace(no_log=no_log)

    @property
    def _result(self):
        return self.payload


def test_compaction_accepts_read_only_result_and_keeps_loop_identity(callback):
    result = ReadOnlyResult({
        "changed": True,
        "_ansible_item_label": "leaf",
        "ansible_loop_var": "device",
        "msg": "large private controller response",
        "data": {"private": "payload"},
    })
    payload = result._result
    assert callback._compact(result) is result
    assert result._result is payload
    assert result._result == {
        "changed": True, "_ansible_item_label": "leaf", "ansible_loop_var": "device",
    }


@pytest.mark.parametrize("debug", [False, True])
@pytest.mark.parametrize("payload_no_log,task_no_log", [(True, False), (False, True)])
def test_hidden_skip_message_does_not_change_module_status(callback, debug, payload_no_log, task_no_log):
    callback.debug = debug
    result = ReadOnlyResult({
        "msg": "NDP_MODULE_SKIPPED: secret details",
        "_ansible_no_log": payload_no_log,
    }, no_log=task_no_log)
    callback._compact(result)
    assert callback.module_skipped is False
    assert result._result["_ansible_no_log"] is True
    if not debug:
        assert "msg" not in result._result


def test_only_visible_skip_messages_are_rendered(callback):
    visible = ReadOnlyResult({"msg": "NDP_MODULE_SKIPPED: private lab details"})
    callback._compact(visible)
    assert callback.module_skipped is True
    assert visible._result["msg"] == "NDP_MODULE_SKIPPED: declared lab substrate unavailable"
    hidden = ReadOnlyResult({"msg": "NDP_MODULE_SKIPPED: hidden details"}, no_log=True)
    callback._compact(hidden)
    assert "msg" not in hidden._result


def test_real_callback_renders_ok_loop_and_captures_before_compaction(tmp_path):
    playbook = tmp_path / "callback.yaml"
    playbook.write_text(json.dumps([{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "tasks": [
            {"name": "Ordinary success", "ansible.builtin.debug": {"msg": "PRIVATE_BODY"}},
            {"name": "Loop success", "ansible.builtin.debug": {"msg": "PRIVATE_LOOP"},
             "loop": ["one", "two"], "loop_control": {"label": "item-label"}},
            {"name": "Hidden result", "ansible.builtin.debug": {
                "msg": "NDP_MODULE_SKIPPED: PRIVATE_NO_LOG"}, "no_log": True},
        ],
    }]))
    log = tmp_path / "callback.txt"
    environment = dict(os.environ,
        ANSIBLE_STDOUT_CALLBACK="nd_report", ANSIBLE_CALLBACK_PLUGINS=str(ROOT / "playbooks"),
        ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible-local"), ANSIBLE_LOCAL_TMP=str(tmp_path / "ansible-local"),
        ANSIBLE_REMOTE_TEMP=str(tmp_path / "ansible-remote"), ANSIBLE_NOCOLOR="1", ANSIBLE_VERBOSITY="0",
        ND_RESULT_LOG=str(log), ND_RESULT_MODULE="example", TEST_RUN_MARKER="callback-current",
        ND_REPORT_DEBUG="false")
    command = str(Path(sys.executable).with_name("ansible-playbook"))
    completed = subprocess.run([command, "-i", "localhost,", str(playbook)], env=environment,
                               capture_output=True, text=True, timeout=45)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "Callback dispatch" not in output
    assert "has no setter" not in output
    assert "ok: [localhost]" in output
    assert "(item=item-label)" in output
    assert "PRIVATE_BODY" not in output
    assert "PRIVATE_LOOP" not in output
    assert "PRIVATE_NO_LOG" not in output
    summary = json.loads(Path(str(log) + ".event-summary.json").read_text())
    assert summary["completed"] is True
    assert summary["capture_error"] is False
    assert summary["module_skipped"] is False
    events_text = Path(str(log) + ".events.jsonl").read_text()
    events = [json.loads(line) for line in events_text.splitlines()]
    assert any(event.get("kind") == "outcome" and event.get("outcome") == "ok" for event in events)
    assert len([event for event in events if event.get("item")]) == 2
    assert any(event.get("no_log") and event.get("name") == "" for event in events)
    assert "PRIVATE_" not in events_text
