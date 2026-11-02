"""Offline reporting work regressions; no Jenkins or controller access."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace

import pytest

from test_nd_reporting_pipeline_smoke import queue_fixture


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def pipeline(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "playbooks"))
    spec = importlib.util.spec_from_file_location("performance_pipeline", ROOT / "playbooks/nd_reporting_pipeline.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def collect_events(pipeline, job, snapshot):
    return pipeline.case_parser.summarize_events(
        job["log"], job["module"], job["run_id"], job["build"], job["scope"],
        job["collection_root"], job["test_type"], catalog_snapshot=snapshot)


def add_backlog_execution(workspace, job, cli, ordinal, round_label="eBGP", structured=True):
    module = job["module"] if ordinal == 1 else job["module"] + ".variant" + str(ordinal)
    run_id = "smoke-round-" + str(ordinal)
    version_id = "ND43_" + round_label.upper() + "_" + str(ordinal)
    plan = workspace / ("additional-plan-" + str(ordinal) + ".json")
    plan.write_text(json.dumps({"build": job["build"], "version_id": version_id, "version": "4.3",
        "run_id": run_id, "round_label": round_label, "fabric_name": "fabric_" + round_label.lower(),
        "targets": [{"module": module, "test_type": "integration", "scope": round_label,
                     "fabric": "fabric_" + round_label.lower()}]}))
    added = cli("register", "--plan", str(plan), "--collection-root", job["collection_root"],
                "--include-executions")["executions"][0]
    arguments = ["--version-id", version_id, "--module", module, "--run-id", run_id]
    cli("begin", *arguments)
    text = Path(job["log"]).read_text().replace("[MODULE: " + job["module"] + "]", "[MODULE: " + module + "]")
    text = re.sub(r"\[RUN_MARKER: [^\]]+\]", "[RUN_MARKER: " + run_id + "]", text)
    Path(added["log"]).write_text(text)
    execution = json.loads(Path(job["log"] + ".execution.json").read_text())
    execution.update(module=module, run_id=run_id)
    Path(added["log"] + ".execution.json").write_text(json.dumps(execution))
    if structured:
        events = [json.loads(line) for line in Path(job["log"] + ".events.jsonl").read_text().splitlines()]
        for event in events:
            event.update(module=module, run_id=run_id)
        journal = "".join(json.dumps(event, sort_keys=True) + "\n" for event in events).encode()
        Path(added["log"] + ".events.jsonl").write_bytes(journal)
        summary = json.loads(Path(job["log"] + ".event-summary.json").read_text())
        summary.update(module=module, run_id=run_id, event_bytes=len(journal),
                       event_sha256=hashlib.sha256(journal).hexdigest())
        Path(added["log"] + ".event-summary.json").write_text(json.dumps(summary))
    cli("close", *arguments, "--exit-code", "2", "--duration-seconds", "10")
    return added


def test_backlog_keeps_both_rounds_and_other_modules_after_invalid_evidence(tmp_path, pipeline):
    workspace, queue, job, cli = queue_fixture(tmp_path, structured=True, stale_marker=True)
    second = add_backlog_execution(workspace, job, cli, 1)
    third = add_backlog_execution(workspace, job, cli, 2, round_label="iBGP", structured=False)
    cli("finish", "--status", "failed")
    backlog = cli("prepare")
    assert [entry["id"] for entry in backlog["executions"]] == [job["id"], second["id"], third["id"]]
    assert [entry["summary_source"] for entry in backlog["executions"]] == [
        "unavailable", "structured_events", "raw_log_recovery"]
    assert [entry["round_label"] for entry in backlog["executions"]] == ["iBGP", "eBGP", "iBGP"]
    _, config = pipeline.configuration(queue)
    for entry in backlog["executions"]:
        pipeline.atomic_json(queue / "archive-inputs" / (entry["id"] + ".0001.json"), {
            "id": entry["id"], "build": config["build"], "build_run_id": config["run_id"],
            "status": "success", "attempt": 1, "seconds": 1, "archived_at": 1000})
    cli("ack-batch")
    report = cli("aggregate")
    assert len(report["rows"]) == 3
    assert report["rows"][0]["validated"] is False
    assert report["rows"][0]["result"] != "PASS"
    for row in report["rows"][1:]:
        assert row["case_totals"] == {"started": 2, "passed": 1, "failed": 1, "skipped": 1, "incomplete": 0}


@pytest.mark.parametrize("structured", [True, False])
def test_backlog_prepares_results_without_spawning_parser_processes(tmp_path, monkeypatch, pipeline, structured):
    workspace, queue, job, _ = queue_fixture(tmp_path, structured=structured)
    _, config = pipeline.configuration(queue)
    pipeline.finish(queue, config, "failed")

    def reject_process(*args, **kwargs):
        raise AssertionError("Batch parsing must not start another process")

    monkeypatch.setattr(subprocess, "Popen", reject_process)
    result = pipeline.prepare_backlog(queue, config, SimpleNamespace(parse_timeout=20, archive_attempts=2))
    assert result["selected_executions"] == 1
    assert len(result["executions"]) == 1
    execution = result["executions"][0]
    assert execution["id"] == job["id"]
    assert execution["summary_source"] == ("structured_events" if structured else "raw_log_recovery")
    assert all((workspace / name).is_file() for name in execution["files"])
    assert not list((queue / "archives").iterdir())
    finalized = pipeline.read_json(queue / "results" / (job["id"] + ".json"))
    assert finalized["activity"]["testcase_totals"] == {
        "started": 2, "passed": 1, "failed": 1, "skipped": 1, "incomplete": 0}


def test_backlog_requires_execution_completion(tmp_path, pipeline):
    _, queue, _, _ = queue_fixture(tmp_path, structured=True)
    _, config = pipeline.configuration(queue)
    with pytest.raises(ValueError, match="execution has not finished"):
        pipeline.prepare_backlog(queue, config, SimpleNamespace(parse_timeout=20, archive_attempts=2))
    assert not list((queue / "results").iterdir())


def test_batch_ack_preserves_upload_timing_and_is_idempotent(tmp_path, pipeline):
    _, queue, job, cli = queue_fixture(tmp_path, structured=True)
    cli("finish", "--status", "failed")
    backlog = cli("prepare")
    assert len(backlog["executions"]) == 1
    _, config = pipeline.configuration(queue)
    pointer = queue / "archive-inputs" / (job["id"] + ".0001.json")
    pipeline.atomic_json(pointer, {"id": job["id"], "build": config["build"],
        "build_run_id": config["run_id"], "status": "success", "attempt": 1,
        "seconds": 2.5, "archived_at": 1000.0})
    assert cli("ack-batch") == {"acknowledged": 1}
    assert cli("ack-batch") == {"acknowledged": 1}
    receipt = pipeline.read_json(queue / "archives" / (job["id"] + ".json"))
    assert receipt["seconds"] == 2.5
    assert receipt["archived_at"] == 1000.0
    row = cli("aggregate")["rows"][0]
    assert row["case_totals"] == {"started": 2, "passed": 1, "failed": 1, "skipped": 1, "incomplete": 0}


def test_batch_ack_rejects_foreign_build_receipts(tmp_path, pipeline):
    _, queue, job, _ = queue_fixture(tmp_path, structured=True)
    _, config = pipeline.configuration(queue)
    pipeline.atomic_json(queue / "archive-inputs" / (job["id"] + ".0001.json"), {
        "id": job["id"], "build": "another-build", "build_run_id": config["run_id"],
        "status": "success", "attempt": 1, "seconds": 1, "archived_at": 1000})
    with pytest.raises(ValueError, match="identity or timing"):
        pipeline.acknowledge_batch(queue, config)
    assert not list((queue / "archives").iterdir())


@pytest.mark.parametrize("structured", [True, False])
@pytest.mark.parametrize("censored", [True, False])
def test_summary_and_skip_report_share_one_evidence_pass(tmp_path, monkeypatch, pipeline, structured, censored):
    fields = {"skip_reason": "unsupported on this fabric", "no_log" if structured else "_ansible_no_log": censored}
    _, queue, job, _ = queue_fixture(tmp_path, structured=structured, skip_fields=fields)
    _, config = pipeline.configuration(queue)
    pipeline.finish(queue, config, "failed")
    original_open = Path.open
    evidence_reads = []

    def counted_open(path, mode="r", *args, **kwargs):
        if str(path) == job["log"] + ".events.jsonl" and mode == "rb":
            evidence_reads.append("events")
        if str(path) == job["log"] and mode == "r":
            evidence_reads.append("raw")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", counted_open)
    backlog = pipeline.prepare_backlog(queue, config, SimpleNamespace(parse_timeout=20, archive_attempts=2))
    assert len(backlog["executions"]) == 1
    assert evidence_reads == ["events" if structured else "raw"]
    report = Path(job["log"] + ".skips.txt").read_text()
    assert report.count("host=localhost") == 1
    assert ("Reason withheld (no_log)" if censored else "unsupported on this fabric") in report
    if censored:
        assert "unsupported on this fabric" not in report


def test_invalid_journal_discards_partial_skip_observations_before_raw_fallback(tmp_path, pipeline):
    _, queue, job, _ = queue_fixture(tmp_path, structured=True)
    metadata = pipeline.read_json(job["log"] + ".event-summary.json")
    metadata["event_sha256"] = "0" * 64
    pipeline.atomic_json(job["log"] + ".event-summary.json", metadata)
    _, config = pipeline.configuration(queue)
    pipeline.finish(queue, config, "failed")
    backlog = pipeline.prepare_backlog(queue, config, SimpleNamespace(parse_timeout=20, archive_attempts=2))
    assert backlog["executions"][0]["summary_source"] == "raw_log_recovery"
    assert Path(job["log"] + ".skips.txt").read_text().count("host=localhost") == 1


def test_changed_skip_observations_cannot_be_published_as_valid(tmp_path, pipeline):
    _, queue, job, _ = queue_fixture(tmp_path, structured=True)
    _, config = pipeline.configuration(queue)
    pipeline.finish(queue, config, "failed")
    pipeline.prepare_backlog(queue, config, SimpleNamespace(parse_timeout=20, archive_attempts=2))
    Path(job["log"] + ".skip-observations.txt").write_text("changed after parsing\n")
    with pytest.raises(ValueError, match="skip observations changed"):
        pipeline.artifact_files(queue, config, job)


def test_close_defers_parsing_and_keeps_catalog_publication_check(tmp_path, monkeypatch, pipeline):
    _, queue, job, _ = queue_fixture(tmp_path, structured=True)
    (queue / "closed" / (job["id"] + ".json")).unlink()
    (queue / "results" / (job["id"] + ".json")).unlink(missing_ok=True)
    catalog_reads = []
    original_coordinator_read = pipeline.read_json
    original_case_read = pipeline.case_parser._read_json

    def coordinator_read(path, *args, **kwargs):
        if Path(path) == Path(job["catalog"]):
            catalog_reads.append("coordinator")
        return original_coordinator_read(path, *args, **kwargs)

    def case_read(path, *args, **kwargs):
        if Path(path) == Path(job["catalog"]):
            catalog_reads.append("case adapter")
        return original_case_read(path, *args, **kwargs)

    monkeypatch.setattr(pipeline, "read_json", coordinator_read)
    monkeypatch.setattr(pipeline.case_parser, "_read_json", case_read)
    result = pipeline.close_execution(queue, job, SimpleNamespace(exit_code=2, duration_seconds=10, parse_timeout=20))
    assert result["summary_ready"] is False
    assert catalog_reads == []
    closed = original_coordinator_read(queue / "closed" / (job["id"] + ".json"))
    finalized = pipeline.ensure_summary(queue, job, closed, 20)
    assert catalog_reads == ["coordinator"]
    assert finalized["summary_source"] == "structured_events"
    assert finalized["activity"]["testcase_totals"] == {
        "started": 2, "passed": 1, "failed": 1, "skipped": 1, "incomplete": 0}

    catalog = json.loads(Path(job["catalog"]).read_text())
    catalog["unexpected_change_after_close"] = True
    Path(job["catalog"]).write_text(json.dumps(catalog))
    with pytest.raises(ValueError, match="frozen catalog changed"):
        pipeline.artifact_files(queue, {"workspace": str(queue.parent)}, job)
    assert catalog_reads == ["coordinator", "coordinator"]


def test_decoded_catalog_is_reusable_without_mutating_its_json_shape(tmp_path, pipeline):
    _, _, job, _ = queue_fixture(tmp_path, structured=True)
    snapshot = json.loads(Path(job["catalog"]).read_text())
    original = copy.deepcopy(snapshot)
    first = collect_events(pipeline, job, snapshot)
    second = collect_events(pipeline, job, snapshot)
    legacy = pipeline.case_parser.summarize_events(
        job["log"], job["module"], job["run_id"], job["build"], job["scope"],
        job["collection_root"], job["test_type"], catalog_path=job["catalog"])
    assert snapshot == original
    assert json.dumps(snapshot)
    assert first == second == legacy


def test_legacy_smoke_event_summary_keeps_unknown_case_counts_and_scope_note(tmp_path, pipeline):
    _, _, job, _ = queue_fixture(tmp_path, structured=True)
    result = pipeline.case_parser.summarize_events(
        job["log"], job["module"], job["run_id"], job["build"], job["scope"],
        job["collection_root"], test_type="smoke")
    assert result["validated"] is True
    assert result["coverage"] == "UNKNOWN"
    assert all(value is None for value in result["counts"].values())
    assert "smoke playbooks have no module integration case catalog" in result["notes"]


@pytest.mark.parametrize("change", ["module", "version", "target", "digest", "body"])
def test_decoded_catalog_preserves_identity_and_digest_validation(tmp_path, pipeline, change):
    _, _, job, _ = queue_fixture(tmp_path, structured=True)
    snapshot = json.loads(Path(job["catalog"]).read_text())
    if change == "module":
        snapshot["module"] = "another_module"
    elif change == "version":
        snapshot["catalog_version"] -= 1
    elif change == "target":
        snapshot["catalog"]["target"] = "another_target"
        snapshot["catalog_sha256"] = pipeline.case_parser._json_digest(snapshot["catalog"])
    elif change == "digest":
        snapshot["catalog_sha256"] = "0" * 64
    else:
        snapshot["catalog"]["errors"].append("changed without updating digest")
    with pytest.raises(ValueError, match="frozen catalog"):
        collect_events(pipeline, job, snapshot)


@pytest.mark.parametrize("value", [[], None, "invalid"])
def test_catalog_validation_rejects_non_objects(pipeline, value):
    with pytest.raises(ValueError, match="JSON object"):
        pipeline.case_parser.validate_frozen_catalog(value, "nd_example")
