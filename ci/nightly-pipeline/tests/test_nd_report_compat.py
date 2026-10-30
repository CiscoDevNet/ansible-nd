"""Offline regressions for successful-result rendering across Ansible versions."""

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
import yaml


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


def captured_skip(callback, payload, *, task_no_log=False, item=False, outcome="skipped"):
    callback._event_stream = io.BytesIO()
    result = ReadOnlyResult(payload, no_log=task_no_log)
    result._task._uuid = "skip-task-1"
    result._task.action = "cisco.nd.nd_example"
    result._task.get_name = lambda: "TC1 - module applicability"
    result._task.get_path = lambda: "tests/integration/targets/nd_example/tests/merged.yaml:12"
    result._task._role = SimpleNamespace(get_name=lambda: "nd_example")
    result._host = SimpleNamespace(get_name=lambda: "localhost")
    callback._capture_result(result, outcome, item=item)
    assert callback.event_errors == []
    event = json.loads(callback._event_stream.getvalue().decode())
    return result, event


@pytest.mark.parametrize("debug", [False, True])
def test_skip_evidence_is_captured_before_owned_result_compaction(callback, debug):
    callback.debug = debug
    result, event = captured_skip(callback, {
        "skip_reason": "Conditional result was False", "false_condition": "fabric_type == 'vxlanEbgp'",
        "msg": "PRIVATE_RESULT_BODY", "data": {"private": "PRIVATE_PAYLOAD"},
    })
    payload = result._result
    callback._compact(result)
    assert result._result is payload
    assert event["skip_reason"] == "Conditional result was False"
    assert event["false_condition"] == "fabric_type == 'vxlanEbgp'"
    assert event["role"] == "nd_example" and event["line"] == 12
    assert event["outcome"] == "skipped" and event["terminal"] is True
    assert "PRIVATE_" not in json.dumps(event)


@pytest.mark.parametrize("payload_no_log,task_no_log", [(True, False), (False, True)])
@pytest.mark.parametrize("item", [False, True])
def test_hidden_skip_evidence_never_records_reason_or_condition(callback, payload_no_log, task_no_log, item):
    _, event = captured_skip(callback, {
        "_ansible_no_log": payload_no_log, "skip_reason": "PRIVATE_REASON",
        "false_condition": "PRIVATE_CONDITION == 'PRIVATE_VALUE'",
    }, task_no_log=task_no_log, item=item)
    assert event["skip_reason"] == "Reason withheld (no_log)"
    assert "false_condition" not in event
    assert "PRIVATE_" not in json.dumps(event)
    assert event["item"] is item and event["terminal"] is not item


@pytest.mark.parametrize("reason,condition", [
    ("password=SKIP_CANARY", "login_password == 'SKIP_CANARY'"),
    ("Bearer SKIP_CANARY", "api_key == 'SKIP_CANARY'"),
])
def test_credential_related_skip_evidence_is_withheld(callback, reason, condition):
    _, event = captured_skip(callback, {"skip_reason": reason, "false_condition": condition})
    assert event["skip_reason"] == event["false_condition"] == "Credential-related skip evidence withheld"
    assert "SKIP_CANARY" not in json.dumps(event)


def test_skip_evidence_is_bounded_and_redacts_arbitrary_values(callback):
    _, event = captured_skip(callback, {
        "skip_reason": "Unsupported on https://fixture.invalid/private address 192.0.2.1 " + "x" * 5000,
        "false_condition": "mode == 'PRIVATE_VALUE' or mode == '" + "LONG_PRIVATE_VALUE" * 1000,
    })
    assert len(event["skip_reason"]) <= 240 and len(event["false_condition"]) <= 240
    assert "fixture.invalid" not in event["skip_reason"] and "192.0.2.1" not in event["skip_reason"]
    assert "PRIVATE_VALUE" not in event["false_condition"]


@pytest.mark.parametrize("payload,outcome", [({}, "skipped"),
    ({"skip_reason": {"private": "PRIVATE_VALUE"}, "false_condition": ["PRIVATE_VALUE"]}, "skipped"),
    ({"skip_reason": "Conditional result was False", "false_condition": "false"}, "ok")])
def test_missing_non_string_or_non_skipped_reason_is_not_invented(callback, payload, outcome):
    _, event = captured_skip(callback, payload, outcome=outcome)
    assert "skip_reason" not in event and "false_condition" not in event


def test_real_callback_renders_ok_loop_and_captures_before_compaction(tmp_path, monkeypatch):
    collection = tmp_path / "collection"
    playbook = collection / "tests/integration/targets/nd_vpc_pair/tests/merged.yaml"
    playbook.parent.mkdir(parents=True)
    playbook.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "vars": {"fabric_type": "vxlanIbgp"},
        "tasks": [
            {"name": "Ordinary success", "ansible.builtin.debug": {"msg": "PRIVATE_BODY"}},
            {"name": "Loop success", "ansible.builtin.debug": {"msg": "PRIVATE_LOOP"},
             "loop": ["one", "two"], "loop_control": {"label": "item-label"}},
            {"name": "Hidden result", "ansible.builtin.debug": {
                "msg": "NDP_MODULE_SKIPPED: PRIVATE_NO_LOG"}, "no_log": True},
            {"name": "Conditional module case", "ansible.builtin.debug": {"msg": "PRIVATE_SKIPPED_BODY"},
             "when": "fabric_type == 'vxlanEbgp'"},
            {"name": "Hidden skip", "ansible.builtin.debug": {"msg": "PRIVATE_NO_LOG_BODY"},
             "when": "'PRIVATE_NO_LOG_CONDITION' == 'never'", "no_log": True},
        ],
    }], sort_keys=False))
    log = tmp_path / "callback.txt"
    environment = dict(os.environ,
        ANSIBLE_STDOUT_CALLBACK="nd_report", ANSIBLE_CALLBACK_PLUGINS=str(ROOT / "playbooks"),
        ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible-local"), ANSIBLE_LOCAL_TMP=str(tmp_path / "ansible-local"),
        ANSIBLE_REMOTE_TEMP=str(tmp_path / "ansible-remote"), ANSIBLE_NOCOLOR="1", ANSIBLE_VERBOSITY="0",
        ND_RESULT_LOG=str(log), ND_RESULT_MODULE="nd_vpc_pair.external", TEST_RUN_MARKER="callback-current",
        ND_REPORT_COLLECTION_ROOT=str(collection),
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
    assert summary["counts"]["skipped"] == 2
    events_text = Path(str(log) + ".events.jsonl").read_text()
    events = [json.loads(line) for line in events_text.splitlines()]
    assert any(event.get("kind") == "outcome" and event.get("outcome") == "ok" for event in events)
    assert len([event for event in events if event.get("item")]) == 2
    assert any(event.get("no_log") and event.get("name") == "" for event in events)
    skipped = [event for event in events if event.get("outcome") == "skipped"]
    assert len(skipped) == 2
    visible = next(event for event in skipped if not event["no_log"])
    hidden = next(event for event in skipped if event["no_log"])
    assert visible["skip_reason"] == "Conditional result was False"
    assert visible["false_condition"] == "fabric_type == 'vxlanEbgp'"
    assert hidden["skip_reason"] == "Reason withheld (no_log)"
    assert "false_condition" not in hidden
    assert "PRIVATE_" not in events_text
    assert all(event["path"].startswith("tests/integration/targets/nd_vpc_pair/") for event in skipped)

    # Feed actual callback records through the publishing helper, including its
    # relative source paths and no_log task with a censored name.
    monkeypatch.syspath_prepend(str(ROOT / "playbooks"))
    spec = importlib.util.spec_from_file_location("callback_readable_reporting", ROOT / "playbooks/nd_reporting_pipeline.py")
    reporting = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reporting)
    document = yaml.compose(playbook.read_text())
    task_nodes = next(value.value for key, value in document.value[0].value if key.value == "tasks")
    catalog = {"target": "nd_vpc_pair", "tasks": {}}
    positions = {}
    for node in task_nodes:
        name = next(value.value for key, value in node.value if key.value == "name")
        record = {"name": name, "path": "tests/merged.yaml", "line": node.start_mark.line + 1,
                  "base": False, "cleanup": False}
        catalog["tasks"][name] = [record]
        positions.setdefault((record["path"], record["line"]), []).append(record)
    job = {"log": str(log), "module": "nd_vpc_pair.external", "run_id": "callback-current"}
    observations = list(reporting.skipped_tasks(job, {"summary_source": "structured_events"}, catalog))
    assert len(observations) == 2
    assert any(event["no_log"] and not event["name"] for _, event in observations)
    assert reporting.owned_skip_task(dict(visible, role="nd_manage_vpc_pair"), catalog, positions)
    assert reporting.owned_skip_task(dict(visible, path="nd_prerequisite/reconcile.yaml", role="nd_vpc_pair"), catalog, positions) is None
