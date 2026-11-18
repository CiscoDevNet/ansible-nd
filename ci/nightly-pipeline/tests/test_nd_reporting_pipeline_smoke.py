"""Offline producer/publisher CLI contract smoke checks; no Jenkins or ND access."""

import hashlib
import json
import os
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
PIPELINE_VARIANTS = ("Jenkinsfile_nd_jenkins_script", "Jenkinsfile_nd_jenkins_script_temp_switches",
                     "Jenkinsfile_nd_jenkins_script_comm_list")
BLOCKED_REASON = "Source or switch readiness could not be verified; see switch-guard diagnostics"
BLOCKED_RECORD = ["[MODULE: nd_blocked] Prerequisite blocked; authored target not started.",
                  "[RUN_MARKER: smoke-round]", "[TIMESTAMP_START: 100]",
                  f"ERROR! NDP_MODULE_BLOCKED: nd_blocked: {BLOCKED_REASON}; continuing with the next module",
                  "[ANSIBLE_EXIT_STATUS: 125]", "[TIMESTAMP_END: 103]", "[DURATION_SECONDS: 3]",
                  "[MODULE: nd_blocked] Execution completed."]


def write_json(path, value):
    path.write_text(json.dumps(value) + "\n")


def queue_fixture(tmp_path, structured, stale_marker=False, skip_fields=None, extra_events=(), preparation_recap=False, scoped_events=False):
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
    if preparation_recap:
        lines += ["PLAY RECAP", "localhost : ok=11 changed=1 unreachable=0 failed=1 skipped=125 rescued=0 ignored=1",
                  "TASKS RECAP"]
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
            phase = "prerequisites" if scoped_events and index == 0 else "cleanup" if scoped_events and index == len(TASKS) - 1 else "execution"
            event = {"schema_version": 1, "module": MODULE, "run_id": "smoke-round", "invocation_id": "smoke",
                     "phase": phase, "task_uuid": str(index), "task_instance": 1, "name": name,
                     "path": str(source), "line": 1, "action": action, "role": MODULE, "no_log": False}
            if outcome == "skipped":
                event.update(skip_fields or {})
            records.append(dict(event, kind="task", seq=len(records) + 1))
            records.append(dict(event, kind="outcome", seq=len(records) + 1, outcome=outcome,
                                host="localhost", terminal=True, item=False, ignored=False, reason_codes=[],
                                **({"changed": index == 1} if scoped_events else {})))
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
    assert closed["summary_ready"] is False
    return workspace, queue, job, cli


@pytest.mark.parametrize("structured", [True, False])
def test_scoped_recap_excludes_pipeline_setup_and_cleanup(tmp_path, structured):
    _, queue, job, cli = queue_fixture(tmp_path, structured, scoped_events=True)
    cli("finish", "--status", "failed")
    cli("next", "--after-execution")
    result = json.loads((queue / "results" / (job["id"] + ".json")).read_text())
    scoped = result["invocation"].get("integration_recap")
    if structured:
        assert scoped == {"scope": "integration_target", "counts": {
            "ok": 2, "changed": 1, "unreachable": 0, "failed": 1,
            "skipped": 1, "rescued": 0, "ignored": 0}}
    else:
        assert scoped is None


@pytest.mark.parametrize("structured", [True, False])
def test_preparation_recap_does_not_change_module_task_counts(tmp_path, structured):
    _, queue, job, cli = queue_fixture(tmp_path, structured, preparation_recap=True)
    cli("finish", "--status", "failed")
    result = cli("next", "--after-execution")["execution"]
    assert result["summary_source"] == ("structured_events" if structured else "raw_log_recovery")
    stored = json.loads((queue / "results" / (job["id"] + ".json")).read_text())
    assert stored["invocation"]["counts"] == {"ok": 4, "changed": 1, "unreachable": 0, "failed": 1,
                                               "skipped": 1, "rescued": 0, "ignored": 0}


def test_failed_recap_before_authored_cases_is_reported_as_fail(tmp_path):
    _, queue, job, cli = queue_fixture(tmp_path, structured=True)
    cli("finish", "--status", "failed")
    cli("next", "--after-execution")
    result_path = queue / "results" / (job["id"] + ".json")
    result = json.loads(result_path.read_text())
    result["activity"].update(coverage="NOT_STARTED", result="FAIL",
                              testcase_totals=dict.fromkeys(("started", "passed", "failed", "skipped", "incomplete"), 0))
    write_json(result_path, result)
    cli("ack", "--id", job["id"], "--status", "success", "--seconds", "1", "--attempt", "1")
    aggregate = cli("aggregate")
    row = aggregate["rows"][0]
    # Module status follows the PLAY RECAP, even when no authored case started.
    assert row["result"] == "FAIL"
    assert row["invocation"]["status"] == "FAIL"
    assert row["invocation"]["counts"]["failed"] == 1
    assert aggregate["failed"] is True


@pytest.mark.parametrize("structured", [True, False])
def test_closed_execution_reaches_artifact_receipt_and_ordered_aggregate(tmp_path, structured):
    workspace, queue, job, cli = queue_fixture(tmp_path, structured)
    assert not list((queue / "results").iterdir())
    cli("finish", "--status", "failed")
    producer_path = queue / "producer.json"
    producer = json.loads(producer_path.read_text())
    producer["finished_at"] = 1
    write_json(producer_path, producer)
    available = cli("next", "--after-execution", "--drain-timeout", "1")
    execution = available["execution"]
    assert available["done"] is False
    assert execution["summary_source"] == ("structured_events" if structured else "raw_log_recovery")
    assert execution["files"] == cli("next", "--after-execution", "--drain-timeout", "1")["execution"]["files"]
    assert all(not Path(path).is_absolute() and (workspace / path).is_file() for path in execution["files"])
    receipt = cli("ack", "--id", job["id"], "--status", "success", "--seconds", "2.5", "--attempt", "1")
    assert receipt == cli("ack", "--id", job["id"], "--status", "success", "--seconds", "2.5", "--attempt", "1")
    cli("finish", "--status", "failed")
    assert cli("next", "--after-execution", "--drain-timeout", "1")["done"] is True
    aggregate = cli("aggregate")
    assert aggregate["selected_executions"] == 1
    assert aggregate["failed"] is True
    assert aggregate["reporting_errors"] == []
    row = aggregate["rows"][0]
    assert row["result"] == "FAIL"
    assert row["validated"] is True
    assert row["case_totals"] == {"started": 2, "passed": 1, "failed": 1, "skipped": 1, "incomplete": 0}
    assert row["phase_seconds"]["archiving"] == 2.5
    assert row["process_seconds"] == 10
    assert row["reporting_metrics"]["archive_attempts"] == 1
    assert row["base"] != "Not observed" and row["cleanup"] != "Not observed"
    assert row["summary_source"] == execution["summary_source"]


@pytest.mark.parametrize("cached", [False, True, "legacy_error"])
def test_missing_numeric_case_counts_recalculate_from_closed_log(tmp_path, monkeypatch, cached):
    monkeypatch.syspath_prepend(str(HELPER.parent))
    import nd_reporting_pipeline as pipeline

    _, queue, job, _ = queue_fixture(tmp_path, structured=True)
    closed = json.loads((queue / "closed" / (job["id"] + ".json")).read_text())
    structured = pipeline.structured_summary
    fallback = pipeline.fallback_summary
    recoveries = []

    def missing_counts(*args, **kwargs):
        summary, activity = structured(*args, **kwargs)
        activity["testcase_totals"] = {key: None for key in activity["testcase_totals"]}
        activity["coverage"] = "UNKNOWN"
        return summary, activity

    def recover(*args, **kwargs):
        recoveries.append(args[0]["id"])
        return fallback(*args, **kwargs)

    if cached:
        result = pipeline.ensure_summary(queue, job, closed, 10)
        result["activity"]["testcase_totals"] = {key: None for key in result["activity"]["testcase_totals"]}
        result["activity"]["coverage"] = "UNKNOWN"
        if cached == "legacy_error":
            result["reporting_status"] = "ERROR"
            result.pop("count_recalculation_complete", None)
        write_json(queue / "results" / (job["id"] + ".json"), result)
    monkeypatch.setattr(pipeline, "structured_summary", missing_counts)
    monkeypatch.setattr(pipeline, "fallback_summary", recover)

    result = pipeline.ensure_summary(queue, job, closed, 10)
    assert result["reporting_status"] == "SUCCESS"
    assert result["summary_source"] == "raw_log_recovery"
    assert result["activity"]["testcase_totals"] == {
        "started": 2, "passed": 1, "failed": 1, "skipped": 1, "incomplete": 0}
    assert recoveries == [job["id"]]


def test_numeric_case_counts_accepts_incomplete_and_not_started_evidence(monkeypatch):
    monkeypatch.syspath_prepend(str(HELPER.parent))
    import nd_reporting_pipeline as pipeline

    incomplete = {"validated": True, "coverage": "INCOMPLETE",
        "testcase_totals": {"started": 4, "passed": 2, "failed": 1, "skipped": 0, "incomplete": 1}}
    not_started = {"validated": True, "coverage": "NOT_STARTED",
        "testcase_totals": {"started": 0, "passed": 0, "failed": 0, "skipped": 0, "incomplete": 0}}
    inconsistent = {"validated": True, "coverage": "INCOMPLETE",
        "testcase_totals": {"started": 4, "passed": 2, "failed": 1, "skipped": 0, "incomplete": 0}}
    assert pipeline.numeric_case_counts(incomplete)
    assert pipeline.numeric_case_counts(not_started)
    assert not pipeline.numeric_case_counts(inconsistent)


@pytest.mark.parametrize("first_failure", ["missing_counts", "read_error"])
def test_second_sequential_recalculation_recovers_counts(tmp_path, monkeypatch, first_failure):
    monkeypatch.syspath_prepend(str(HELPER.parent))
    import nd_reporting_pipeline as pipeline

    _, queue, job, _ = queue_fixture(tmp_path, structured=True)
    closed = json.loads((queue / "closed" / (job["id"] + ".json")).read_text())
    structured = pipeline.structured_summary
    fallback = pipeline.fallback_summary
    recoveries = []

    def missing_counts(*args, **kwargs):
        summary, activity = structured(*args, **kwargs)
        activity["testcase_totals"] = {key: None for key in activity["testcase_totals"]}
        return summary, activity

    def recover(*args, **kwargs):
        recoveries.append(args[0]["id"])
        if len(recoveries) == 1:
            if first_failure == "read_error":
                raise OSError("temporary evidence read failed")
            return missing_counts(*args, **kwargs)
        return fallback(*args, **kwargs)

    monkeypatch.setattr(pipeline, "structured_summary", missing_counts)
    monkeypatch.setattr(pipeline, "fallback_summary", recover)
    result = pipeline.ensure_summary(queue, job, closed, 10)
    assert result["reporting_status"] == "SUCCESS"
    assert result["activity"]["testcase_totals"] == {
        "started": 2, "passed": 1, "failed": 1, "skipped": 1, "incomplete": 0}
    assert result["count_recalculation_attempts"] == 2
    assert recoveries == [job["id"], job["id"]]


def test_unrecoverable_case_counts_fail_reporting_after_two_recalculations(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(HELPER.parent))
    import nd_reporting_pipeline as pipeline

    _, queue, job, _ = queue_fixture(tmp_path, structured=True)
    closed = json.loads((queue / "closed" / (job["id"] + ".json")).read_text())
    structured = pipeline.structured_summary
    fallback = pipeline.fallback_summary
    recoveries = []

    def incomplete(adapter, *args, **kwargs):
        summary, activity = adapter(*args, **kwargs)
        activity["testcase_totals"] = {key: None for key in activity["testcase_totals"]}
        activity["coverage"] = "UNKNOWN"
        return summary, activity

    def recover(*args, **kwargs):
        recoveries.append(args[0]["id"])
        return incomplete(fallback, *args, **kwargs)

    monkeypatch.setattr(pipeline, "structured_summary", lambda *args, **kwargs: incomplete(structured, *args, **kwargs))
    monkeypatch.setattr(pipeline, "fallback_summary", recover)
    result = pipeline.ensure_summary(queue, job, closed, 10)
    assert result["reporting_status"] == "ERROR"
    assert "NDP_CASE_COUNTS_UNRECOVERABLE" in result["reporting_error"]
    assert all(value is None for value in result["activity"]["counts"].values())
    assert recoveries == [job["id"], job["id"]]
    assert result["count_recalculation_attempts"] == 2
    assert pipeline.ensure_summary(queue, job, closed, 10) == result
    assert recoveries == [job["id"], job["id"]]


def test_count_recalculation_does_not_restart_an_exhausted_total_deadline(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(HELPER.parent))
    import nd_reporting_pipeline as pipeline

    _, queue, job, _ = queue_fixture(tmp_path, structured=True)
    closed = json.loads((queue / "closed" / (job["id"] + ".json")).read_text())
    recoveries = []

    def unavailable(*args, **kwargs):
        raise ValueError("Structured evidence needs recalculation")

    def expired(*args, **kwargs):
        recoveries.append(args[0]["id"])
        raise TimeoutError("Total reporting deadline exhausted")

    monkeypatch.setattr(pipeline, "structured_summary", unavailable)
    monkeypatch.setattr(pipeline, "fallback_summary", expired)
    result = pipeline.ensure_summary(queue, job, closed, 10)
    assert result["reporting_status"] == "ERROR"
    assert result["count_recalculation_attempts"] == 1
    assert recoveries == [job["id"]]
    assert "TimeoutError" in result["reporting_error"]


def test_prepare_repairs_missing_counts_even_after_artifact_acknowledgement(tmp_path):
    _, queue, job, cli = queue_fixture(tmp_path, structured=True)
    cli("next")
    cli("ack", "--id", job["id"], "--status", "success", "--seconds", "1", "--attempt", "1")
    cli("finish", "--status", "failed")
    result_path = queue / "results" / (job["id"] + ".json")
    result = json.loads(result_path.read_text())
    result["activity"]["coverage"] = "UNKNOWN"
    result["activity"]["testcase_totals"] = {key: None for key in result["activity"]["testcase_totals"]}
    write_json(result_path, result)
    receipt = (queue / "archives" / (job["id"] + ".json")).read_bytes()
    assert cli("prepare")["executions"] == []
    repaired = json.loads(result_path.read_text())
    assert repaired["activity"]["testcase_totals"] == {
        "started": 2, "passed": 1, "failed": 1, "skipped": 1, "incomplete": 0}
    assert repaired["reporting_status"] == "SUCCESS"
    assert (queue / "archives" / (job["id"] + ".json")).read_bytes() == receipt


def test_end_of_run_parser_refuses_to_parse_while_execution_is_active(tmp_path):
    _, queue, _, _ = queue_fixture(tmp_path, structured=True)
    completed = subprocess.run(
        [sys.executable, str(HELPER), "next", "--root", str(queue), "--after-execution"],
        text=True, capture_output=True, timeout=20)
    assert completed.returncode != 0
    assert "execution has not finished" in json.loads(completed.stdout)["error"]
    assert not list((queue / "results").iterdir())
    assert not list((queue / "archives").iterdir())


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


def blocked_round(tmp_path):
    workspace = tmp_path / "workspace"
    queue = workspace / "reports"
    collection = workspace / "collection"
    for module in ("nd_blocked", MODULE):
        source = collection / "tests/integration/targets" / module / "tasks/main.yaml"
        source.parent.mkdir(parents=True)
        write_json(source, [{"name": "MERGED TC1 - configure", module: {"state": "merged"}},
                            {"name": "MERGED TC1 - verify", "assert": {"that": [True]}}])

    def cli(command, *arguments, check=True):
        completed = subprocess.run([sys.executable, str(HELPER), command, "--root", str(queue), *arguments],
                                   text=True, capture_output=True, timeout=20)
        if check:
            assert completed.returncode == 0, completed.stdout + completed.stderr
        return json.loads(completed.stdout)

    cli("init", "--workspace", str(workspace), "--build", "174", "--run-id", "blocked-build")
    plan = workspace / "plan.json"
    write_json(plan, {"build": "174", "version_id": "ND43", "version": "4.3", "run_id": "smoke-round",
                     "round_label": "iBGP", "fabric_name": "fabric", "targets": [
                         {"module": "nd_blocked", "test_type": "integration", "scope": "iBGP"},
                         {"module": MODULE, "test_type": "integration", "scope": "iBGP"},
                         {"module": "blocked.yaml", "test_type": "smoke", "scope": "iBGP"}]})
    registered = cli("register", "--plan", str(plan), "--collection-root", str(collection), "--include-executions")
    return queue, Path(registered["log_dir"]), cli


def run_passing_module(cli, log_dir):
    arguments = ["--version-id", "ND43", "--module", MODULE, "--run-id", "smoke-round"]
    cli("begin", *arguments)
    source = log_dir.parent.parent.parent / "collection/tests/integration/targets" / MODULE / "tasks/main.yaml"
    log = log_dir / ("test_output_fabric_ND43_%s.txt" % MODULE)
    lines = [f"[MODULE: {MODULE}] Starting execution...", "[RUN_MARKER: smoke-round]", "[TIMESTAMP_START: 100]"]
    for name in ("MERGED TC1 - configure", "MERGED TC1 - verify"):
        lines += [f"TASK [{MODULE} : {name}] ***", f"task path: {source}:1", "ok: [localhost]"]
    lines += ["PLAY RECAP", "localhost : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0",
              "[ANSIBLE_EXIT_STATUS: 0]", "[TIMESTAMP_END: 110]", "[DURATION_SECONDS: 10]",
              f"[MODULE: {MODULE}] Execution completed."]
    log.write_text("\n".join(lines) + "\n")
    write_json(Path(str(log) + ".execution.json"), {
        "module": MODULE, "run_id": "smoke-round", "exit_code": 0, "started_at": 100, "ended_at": 110})
    cli("close", *arguments, "--exit-code", "0", "--duration-seconds", "10")


def publish_all(cli):
    cli("finish", "--status", "failed")
    while True:
        available = cli("next", "--after-execution")
        if available["done"]:
            return cli("aggregate")
        cli("ack", "--id", available["execution"]["id"], "--status", "success", "--seconds", "1", "--attempt", "1")


def record_blocked_modules(tmp_path, variant, queue, log_dir):
    """Run the pipeline's own record_blocked_module shell helper against the real reporter."""
    source = (ROOT / variant).read_text()
    helpers = "begin_reported_module() {" + source.split("begin_reported_module() {", 1)[1].split(
        'PROFILE_VALIDATOR="${COLLECTIONS_DIRECTORY}', 1)[0]
    helpers = helpers.replace('"$HOME/ansible/venv/bin/python"', '"$TEST_PYTHON"')
    script = tmp_path / "blocked.sh"
    script.write_text("set -e\nRUN_FAILURE=0\n" + helpers + f'''
PREREQUISITE_START=$(( $(date +%s) - 7 ))
record_blocked_module nd_blocked "{BLOCKED_REASON}"
unset PREREQUISITE_START
record_blocked_module blocked.yaml "Required Consul smoke playbook is missing, empty, or unsafe" PLAYBOOK
echo "RUN_FAILURE=$RUN_FAILURE"
''')
    environment = dict(os.environ, PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
                       TEST_PYTHON=sys.executable, ND_REPORT_LOG_DIR=str(log_dir), FABRIC_NAME="fabric",
                       VERSION_ID="ND43", TEST_RUN_MARKER="smoke-round", ND_REPORTING_ROOT=str(queue),
                       ND_REPORTING_TOOLS=str(ROOT / "playbooks"))
    completed = subprocess.run(["bash", str(script)], env=environment, text=True, capture_output=True, timeout=60)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "RUN_FAILURE=1" in completed.stdout
    assert "NDP_MODULE_CLOSE_FAILED" not in completed.stderr


@pytest.mark.parametrize("variant", PIPELINE_VARIANTS)
def test_prerequisite_blocked_modules_produce_a_complete_report(tmp_path, variant):
    queue, log_dir, cli = blocked_round(tmp_path)
    record_blocked_modules(tmp_path, variant, queue, log_dir)
    run_passing_module(cli, log_dir)

    aggregate = publish_all(cli)
    assert aggregate["reporting_errors"] == []
    assert aggregate["failed"] is True
    rows = {row["module"]: row for row in aggregate["rows"]}
    assert rows[MODULE]["result"] == "PASS"
    for module, reason in (("nd_blocked", BLOCKED_REASON),
                           ("blocked.yaml", "Required Consul smoke playbook is missing, empty, or unsafe")):
        row = rows[module]
        assert row["result"] == "NOT_RUN"
        assert row["summary_source"] == "prerequisite_blocked"
        assert row["reporting_status"] == "SUCCESS"
        assert set(row["case_totals"].values()) == {0}
        assert reason in row["failure"]
    nd_blocked = json.loads((log_dir / "test_output_fabric_ND43_nd_blocked.txt.summary.json").read_text())
    assert nd_blocked["phase_seconds"]["prerequisites"] >= 7


def write_blocked_record(cli, log_dir, lines, exit_code=125, sidecar_exit=125):
    arguments = ["--version-id", "ND43", "--module", "nd_blocked", "--run-id", "smoke-round"]
    cli("begin", *arguments)
    log = log_dir / "test_output_fabric_ND43_nd_blocked.txt"
    log.write_text("\n".join(lines) + "\n")
    write_json(Path(str(log) + ".execution.json"), {
        "module": "nd_blocked", "run_id": "smoke-round", "exit_code": sidecar_exit,
        "started_at": 100, "ended_at": 103})
    cli("close", *arguments, "--exit-code", str(exit_code), "--duration-seconds", "3")


@pytest.mark.parametrize("lines,sidecar_exit,expected", [
    # Build 174 record: no completion marker, so it could never be reported.
    (BLOCKED_RECORD[:7], 125, "malformed"),
    (["[MODULE: nd_blocked] Starting execution..."] + BLOCKED_RECORD[1:7], 125, "completion marker"),
    (BLOCKED_RECORD[:4] + ["PLAY RECAP", "localhost : ok=9 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0"]
     + BLOCKED_RECORD[4:], 125, "malformed"),
    (BLOCKED_RECORD, 2, "wrapper execution"),
])
def test_untrusted_blocked_records_remain_reporting_errors(tmp_path, lines, sidecar_exit, expected):
    queue, log_dir, cli = blocked_round(tmp_path)
    write_blocked_record(cli, log_dir, lines, sidecar_exit=sidecar_exit)
    run_passing_module(cli, log_dir)
    aggregate = publish_all(cli)
    errors = [error for error in aggregate["reporting_errors"] if error["module"] == "nd_blocked"]
    assert len(errors) == 1 and expected in errors[0]["reason"]
    assert {row["module"]: row["result"] for row in aggregate["rows"]}["nd_blocked"] != "PASS"
