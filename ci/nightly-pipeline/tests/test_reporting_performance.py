"""Offline reporting work regressions; no Jenkins or controller access."""

import copy
import importlib.util
import json
from pathlib import Path
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


def test_valid_structured_close_decodes_catalog_once_and_keeps_publication_check(tmp_path, monkeypatch, pipeline):
    _, queue, job, _ = queue_fixture(tmp_path, structured=True)
    (queue / "closed" / (job["id"] + ".json")).unlink()
    (queue / "results" / (job["id"] + ".json")).unlink()
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
    assert result["summary_ready"] is True
    assert catalog_reads == ["coordinator"]
    finalized = original_coordinator_read(queue / "results" / (job["id"] + ".json"))
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
