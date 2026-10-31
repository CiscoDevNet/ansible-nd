"""Offline producer/publisher CLI contract smoke checks; no Jenkins or ND access."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "playbooks/nd_reporting_pipeline.py"
MODULE = "nd_example"
TASKS = [
    ("BASE - setup", "debug", {}, "ok"),
    ("MERGED TC1 - configure", MODULE, {"state": "merged"}, "ok"),
    ("MERGED TC1 - verify", "assert", {"that": [True]}, "ok"),
    ("DELETED TC2 - delete", MODULE, {"state": "deleted"}, "failed"),
    ("GATHERED TC3 - gather", MODULE, {"state": "gathered"}, "skipped"),
    ("CLEANUP - restore", "debug", {}, "ok"),
]


def write_json(path, value):
    path.write_text(json.dumps(value) + "\n")


def queue_fixture(tmp_path, structured, stale_marker=False, skip_fields=None, extra_events=()):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    queue = workspace / "reports"
    collection = workspace / "collection"
    source = collection / "tests/integration/targets" / MODULE / "tasks/main.yaml"
    source.parent.mkdir(parents=True)
    write_json(source, [{"name": name, action: arguments} for name, action, arguments, _ in TASKS])

    def cli(command, *arguments):
        completed = subprocess.run([sys.executable, str(HELPER), command, "--root", str(queue), *arguments],
                                   text=True, capture_output=True, timeout=20)
        assert completed.returncode == 0, completed.stdout + completed.stderr
        return json.loads(completed.stdout)

    cli("init", "--workspace", str(workspace), "--build", "120", "--run-id", "smoke-build")
    plan = workspace / "plan.json"
    write_json(plan, {"build": "120", "version_id": "ND43", "version": "4.3", "run_id": "smoke-round",
                     "round_label": "iBGP", "fabric_name": "fabric", "targets": [
                         {"module": MODULE, "test_type": "integration", "scope": "iBGP", "fabric": "fabric"}]})
    selected = cli("register", "--plan", str(plan), "--collection-root", str(collection), "--include-executions")
    job = selected["executions"][0]
    execution_args = ["--version-id", "ND43", "--module", MODULE, "--run-id", "smoke-round"]
    begun = cli("begin", *execution_args)
    assert begun["log"] == job["log"]
    log = Path(job["log"])
    marker = "stale-round" if stale_marker else "smoke-round"
    counts = {key: 0 for key in ("ok", "changed", "unreachable", "failed", "skipped", "rescued", "ignored")}
    counts["changed"] = 1
    for outcome in [row[3] for row in TASKS] + [event.get("outcome") for event in extra_events]:
        if outcome in counts:
            counts[outcome] += 1
    lines = [f"[MODULE: {MODULE}] Starting execution...", f"[RUN_MARKER: {marker}]", "[TIMESTAMP_START: 100]"]
    for name, _, _, outcome in TASKS:
        if outcome is None:
            continue
        result_line = {"ok": "ok: [localhost]", "failed": "fatal: [localhost]: FAILED!", "skipped": "skipping: [localhost]"}[outcome]
        if outcome == "skipped" and skip_fields:
            result_line += " => " + json.dumps(skip_fields)
        lines += [f"TASK [{MODULE} : {name}] ***", f"task path: {source}:1",
                  result_line]
    lines += ["PLAY RECAP", "localhost : " + " ".join(f"{key}={value}" for key, value in counts.items()),
              "[ANSIBLE_EXIT_STATUS: 2]", "[TIMESTAMP_END: 110]", "[DURATION_SECONDS: 10]",
              f"[MODULE: {MODULE}] Execution completed."]
    log.write_text("\n".join(lines) + "\n")
    write_json(Path(str(log) + ".execution.json"), {
        "module": MODULE, "run_id": "smoke-round", "exit_code": 2, "started_at": 100, "ended_at": 110})
    if structured:
        records = []
        for index, (name, action, _, outcome) in enumerate(TASKS):
            if outcome is None:
                continue
            event = {"schema_version": 1, "module": MODULE, "run_id": "smoke-round", "invocation_id": "smoke",
                     "phase": "execution", "task_uuid": str(index), "task_instance": 1, "name": name,
                     "path": str(source), "line": 1, "action": action, "role": MODULE, "no_log": False}
            if outcome == "skipped":
                event.update(skip_fields or {})
            records.append(dict(event, kind="task", seq=len(records) + 1))
            records.append(dict(event, kind="outcome", seq=len(records) + 1, outcome=outcome,
                                host="localhost", terminal=True, item=False, ignored=False, reason_codes=[]))
        for event in extra_events:
            records.append(dict(event, seq=len(records) + 1))
        journal = "".join(json.dumps(event, sort_keys=True) + "\n" for event in records).encode()
        Path(str(log) + ".events.jsonl").write_bytes(journal)
        write_json(Path(str(log) + ".event-summary.json"), {
            "schema_version": 1, "module": MODULE, "run_id": "smoke-round", "invocation_id": "smoke",
            "completed": True, "capture_error": False, "errors": [], "event_count": len(records),
            "event_bytes": len(journal), "event_sha256": hashlib.sha256(journal).hexdigest(),
            "host_count": 1, "counts": counts})
    closed = cli("close", *execution_args, "--exit-code", "2", "--duration-seconds", "10")
    assert closed["summary_ready"] is (structured and not stale_marker)
    return workspace, queue, job, cli


@pytest.mark.parametrize("structured", [True, False])
def test_closed_execution_reaches_artifact_receipt_and_ordered_aggregate(tmp_path, structured):
    workspace, queue, job, cli = queue_fixture(tmp_path, structured)
    available = cli("next")
    execution = available["execution"]
    assert available["done"] is False
    assert execution["summary_source"] == ("structured_events" if structured else "raw_log_recovery")
    assert execution["files"] == cli("next")["execution"]["files"]
    assert all(not Path(path).is_absolute() and (workspace / path).is_file() for path in execution["files"])
    receipt = cli("ack", "--id", job["id"], "--status", "success", "--seconds", "2.5", "--attempt", "1")
    assert receipt == cli("ack", "--id", job["id"], "--status", "success", "--seconds", "2.5", "--attempt", "1")
    cli("finish", "--status", "failed")
    assert cli("next")["done"] is True
    aggregate = cli("aggregate")
    assert aggregate["selected_executions"] == 1
    assert aggregate["failed"] is True
    assert aggregate["reporting_errors"] == []
    row = aggregate["rows"][0]
    assert row["result"] == "FAIL"
    assert row["validated"] is True
    assert row["case_totals"] == {"started": 2, "passed": 1, "failed": 1, "skipped": 1, "incomplete": 0}
    assert row["phase_seconds"]["archiving"] == 2.5
    assert row["reporting_metrics"]["archive_attempts"] == 1
    assert row["base"] != "Not observed" and row["cleanup"] != "Not observed"
    assert row["summary_source"] == execution["summary_source"]


def test_stale_log_marker_cannot_become_a_passing_summary(tmp_path):
    _, _, _, cli = queue_fixture(tmp_path, structured=False, stale_marker=True)
    cli("finish", "--status", "failed")
    available = cli("next")
    if available.get("execution"):
        assert available["execution"]["summary_source"] == "unavailable"
        cli("ack", "--id", available["execution"]["id"], "--status", "success", "--seconds", "1")
    assert cli("next")["done"] is True
    aggregate = cli("aggregate")
    assert aggregate["failed"] is True
    assert aggregate["reporting_errors"]
    row = aggregate["rows"][0]
    assert row["validated"] is False
    assert row["result"] in {"FAIL", "UNKNOWN"}
    assert row["case_totals"].get("passed") in {None, 0}
    assert row["summary_source"] == "unavailable"


@pytest.mark.parametrize("validation", [None, False, "true", 1, {}])
def test_aggregate_does_not_invent_validation_for_missing_or_non_boolean_flag(tmp_path, validation):
    _, queue, job, cli = queue_fixture(tmp_path, structured=True)
    assert cli("next")["execution"]["summary_source"] == "structured_events"
    cli("ack", "--id", job["id"], "--status", "success", "--seconds", "1", "--attempt", "1")
    cli("finish", "--status", "failed")
    result_path = queue / "results" / (job["id"] + ".json")
    result = json.loads(result_path.read_text())
    if validation is None:
        result["activity"].pop("validated", None)
    else:
        result["activity"]["validated"] = validation
    write_json(result_path, result)
    row = cli("aggregate")["rows"][0]
    assert row["validated"] is False


def test_aggregate_keeps_identity_validation_separate_from_incomplete_cases(tmp_path):
    _, queue, job, cli = queue_fixture(tmp_path, structured=True)
    cli("next")
    cli("ack", "--id", job["id"], "--status", "success", "--seconds", "1", "--attempt", "1")
    cli("finish", "--status", "failed")
    result_path = queue / "results" / (job["id"] + ".json")
    result = json.loads(result_path.read_text())
    result["activity"].update(
        validated=True,
        coverage="INCOMPLETE",
        testcase_totals={"started": 3, "passed": 1, "failed": 0, "skipped": 0, "incomplete": 2},
        notes=["2 authored cases have incomplete verification"],
    )
    write_json(result_path, result)
    row = cli("aggregate")["rows"][0]
    assert row["validated"] is True
    assert row["coverage"] == "INCOMPLETE"
    assert row["case_totals"] == {"started": 3, "passed": 1, "failed": 0, "skipped": 0, "incomplete": 2}
    assert row["source_notes"] == ["2 authored cases have incomplete verification"]


def test_aggregate_preserves_identified_subsets_and_case_skip_notes(tmp_path):
    _, queue, job, cli = queue_fixture(tmp_path, structured=True)
    cli("next")
    cli("ack", "--id", job["id"], "--status", "success", "--seconds", "1", "--attempt", "1")
    cli("finish", "--status", "success")
    result_path = queue / "results" / (job["id"] + ".json")
    result = json.loads(result_path.read_text())
    result["invocation"]["status"] = "OK"
    result["activity"].update(
        validated=True, result="PASS", coverage="PARTIAL",
        testcase_totals={name: None for name in ("started", "passed", "failed", "skipped", "incomplete")},
        identified_case_counts={"merged": 1, "gathered": 1},
        identified_testcase_totals={"started": 2, "passed": 2, "failed": 0, "skipped": 2, "incomplete": 0},
        identified_other_cases=0,
        case_results=[
            {"id": "merged::TC4", "label": "MERGED TC4", "outcome": "skipped",
             "reason": "Brownfield preserve_config=true is unsupported on eBGP"},
            {"id": "merged::TC5", "label": "MERGED TC5", "outcome": "skipped",
             "reason": "Brownfield replay requires the unsupported Brownfield case"},
        ],
    )
    write_json(result_path, result)
    row = cli("aggregate")["rows"][0]
    assert row["result"] == "PASS"
    assert row["validated"] is True
    assert row["case_totals"]["passed"] is None
    assert row["identified_case_counts"] == {"merged": 1, "gathered": 1}
    assert row["identified_testcase_totals"]["passed"] == 2
    assert row["identified_other_cases"] == 0
    assert row["skipped_case_notes"] == [
        "MERGED TC4: Brownfield preserve_config=true is unsupported on eBGP",
        "MERGED TC5: Brownfield replay requires the unsupported Brownfield case",
    ]
    assert row["skipped_case_notes_truncated"] is False


def test_aggregate_bounds_and_sanitizes_case_skip_notes(tmp_path):
    _, queue, job, cli = queue_fixture(tmp_path, structured=True)
    cli("next")
    cli("ack", "--id", job["id"], "--status", "success", "--seconds", "1", "--attempt", "1")
    cli("finish", "--status", "failed")
    result_path = queue / "results" / (job["id"] + ".json")
    result = json.loads(result_path.read_text())
    result["activity"]["case_results"] = [
        {"label": "TC" + str(index), "outcome": "skipped",
         "reason": "unsupported on endpoint https://fixture.invalid/private address 192.0.2.1 password=fixture " + "x" * 300}
        for index in range(12)
    ]
    write_json(result_path, result)
    row = cli("aggregate")["rows"][0]
    assert len(row["skipped_case_notes"]) == 8
    assert row["skipped_case_notes_truncated"] is True
    for note in row["skipped_case_notes"]:
        assert len(note) <= 220
        assert "fixture.invalid" not in note
        assert "192.0.2.1" not in note
        assert "password=fixture" not in note
