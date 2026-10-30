"""Human artifact projection preserves internal evidence and authored-case truth."""
import importlib.util
import json
from pathlib import Path
import re
import sys

import pytest

import test_nd_reporting_pipeline_smoke as smoke

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "playbooks"))
spec = importlib.util.spec_from_file_location("readable_reporting", ROOT / "playbooks/nd_reporting_pipeline.py")
reporting = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporting)


def aggregate_with_receipt(cli, job):
    cli("ack", "--id", job["id"], "--status", "success", "--seconds", "1", "--attempt", "1")
    cli("finish", "--status", "failed")
    return cli("aggregate")


@pytest.mark.parametrize("structured", [True, False])
def test_publisher_exports_one_flat_full_txt_and_one_build_skip_report(tmp_path, structured):
    workspace, queue, job, cli = smoke.queue_fixture(tmp_path, structured)
    raw = Path(job["log"]).read_bytes()
    result_before = json.loads((queue / "results" / (job["id"] + ".json")).read_text()) if structured else None
    descriptor = cli("next")["execution"]
    assert descriptor["files"] == ["test_output_fabric_ND43_IBGP_nd_example.txt"]
    public_log = workspace / descriptor["files"][0]
    assert public_log.parent == workspace
    assert public_log.read_bytes().endswith(raw)
    assert b"ROUND: iBGP" in public_log.read_bytes()
    assert Path(job["log"]).read_bytes() == raw
    assert (queue / "jobs" / (job["id"] + ".json")).is_file()
    assert Path(job["catalog"]).is_file()
    assert Path(job["log"] + ".summary.json").is_file()
    assert all(Path(path).suffix == ".txt" for path in descriptor["files"])
    aggregate = aggregate_with_receipt(cli, job)
    assert aggregate["skiplist_file"] == "skipped_tests_build_120.txt"
    assert "progress_file" not in aggregate
    assert aggregate["rows"][0]["artifact"] == public_log.name
    assert aggregate["rows"][0]["result"] == "FAIL"
    assert aggregate["rows"][0]["case_totals"] == {"started": 2, "passed": 1, "failed": 1, "skipped": 1, "incomplete": 0}
    skip_text = (workspace / aggregate["skiplist_file"]).read_text()
    assert "FAILED CASES" in skip_text and "DELETED TC2" in skip_text
    assert "FULLY SKIPPED CASES" in skip_text and "GATHERED TC3" in skip_text
    assert "Failure evidence:" in skip_text
    assert "Reason not recorded" in skip_text
    assert "not unique case counts; pipeline tasks excluded" in skip_text
    if structured:
        result_after = json.loads((queue / "results" / (job["id"] + ".json")).read_text())
        assert result_after == result_before


def test_public_names_distinguish_rounds_and_external_scope_without_duplicate_version_suffix():
    base = {"fabric_name": "VXLAN_EVPN_Fabric", "module": "nd_vpc_pair.external", "version_id": "ND43", "round_label": "iBGP"}
    ibgp = reporting.public_log_name(base)
    ebgp = reporting.public_log_name(dict(base, round_label="eBGP", version_id="ND43_EBGP"))
    assert ibgp == "test_output_VXLAN_EVPN_Fabric_ND43_IBGP_nd_vpc_pair.external.txt"
    assert ebgp == "test_output_VXLAN_EVPN_Fabric_ND43_EBGP_nd_vpc_pair.external.txt"
    assert ibgp != ebgp and "EBGP_EBGP" not in ebgp
    header = reporting.readable_header(dict(base, nd="4.3", scope="External", fabric="External_Connectivity_Fabric", build="128"))
    assert "ROUND: iBGP" in header and "SCOPE: External" in header and "FABRIC: External_Connectivity_Fabric" in header


@pytest.mark.parametrize("path,role,owned", [
    ("/collection/tests/integration/targets/nd_vpc_pair/tests/merged.yaml", "nd_manage_vpc_pair", True),
    ("tests/integration/targets/nd_vpc_pair/tests/merged.yaml", "nd_manage_vpc_pair", True),
    ("/pipeline/nd_prerequisite.yaml", "nd_vpc_pair", False),
    ("", "cisco.nd.nd_vpc_pair", True),
])
def test_pinned_module_path_handles_aliases_without_accepting_pipeline_tasks(path, role, owned):
    record = {"name": "MERGED TC1 - conditional action", "path": "tests/merged.yaml", "line": 8,
              "base": False, "cleanup": False}
    catalog = {"target": "nd_vpc_pair", "tasks": {record["name"]: [record]}}
    result = reporting.owned_skip_task({"name": record["name"], "path": path, "line": 8, "role": role},
                                      catalog, {(record["path"], 8): [record]})
    assert bool(result) is owned


def test_raw_recovery_uses_only_named_skip_details_without_result_payloads(tmp_path):
    workspace, _, job, cli = smoke.queue_fixture(tmp_path, False, skip_fields={
        "skip_reason": "Conditional result was False", "false_condition": "state == 'gathered'",
        "msg": "PRIVATE_PAYLOAD_CANARY"})
    cli("next")
    aggregate = aggregate_with_receipt(cli, job)
    text = (workspace / aggregate["skiplist_file"]).read_text()
    assert "Conditional result was False" in text and "state == 'gathered'" in text
    assert "PRIVATE_PAYLOAD_CANARY" not in text
    assert "raw_log_recovery" in text


@pytest.mark.parametrize("key", ["api_key", "passwd", "ansible_password", "snmp_community", "username", "auth_pass"])
def test_old_credential_fields_in_skip_details_are_withheld(key):
    assert reporting.skip_detail(key + "=RAW_CANARY") == "Credential-related skip evidence withheld"


def test_unterminated_or_bounded_quoted_conditions_do_not_disclose_values():
    for condition in ("selected == 'hidden-canary", "selected == 'hidden-canary" + "x" * 2000):
        text = reporting.skip_detail(condition, condition=True)
        assert "hidden-canary" not in text and "[value]" in text


def test_raw_recovery_withholds_legacy_api_key_skip_reason(tmp_path):
    workspace, _, job, cli = smoke.queue_fixture(tmp_path, False,
        skip_fields={"skip_reason": "api_key=RAW_CANARY", "false_condition": "private == 'hidden-canary"})
    cli("next")
    aggregate = aggregate_with_receipt(cli, job)
    text = (workspace / aggregate["skiplist_file"]).read_text()
    assert "Credential-related skip evidence withheld" in text
    assert "RAW_CANARY" not in text and "hidden-canary" not in text


def test_full_skip_stream_keeps_more_than_256_tasks_and_excludes_pipeline_skips(tmp_path, monkeypatch):
    monkeypatch.setattr(smoke, "TASKS", smoke.TASKS + [
        (f"GATHERED TC{index} - conditional gather", smoke.MODULE, {"state": "gathered"}, "skipped")
        for index in range(4, 304)])
    pipeline = []
    for index in range(129):
        pipeline.append({"schema_version": 1, "module": smoke.MODULE, "run_id": "smoke-round", "invocation_id": "smoke",
            "kind": "outcome", "phase": "prerequisites", "task_uuid": "pipeline-" + str(index), "task_instance": 1,
            "name": "NDP_PIPELINE_ONLY_CANARY", "path": "/pipeline/nd_prerequisite.yaml", "line": 1, "role": "",
            "action": "debug", "outcome": "skipped", "host": "localhost", "terminal": True, "item": False,
            "ignored": False, "no_log": False, "reason_codes": [], "skip_reason": "pipeline condition"})
    workspace, _, job, cli = smoke.queue_fixture(tmp_path, True,
        skip_fields={"skip_reason": "Conditional result was False", "false_condition": "state == 'gathered'"}, extra_events=pipeline)
    cli("next")
    aggregate = aggregate_with_receipt(cli, job)
    text = (workspace / aggregate["skiplist_file"]).read_text()
    assert "GATHERED TC303 - conditional gather" in text
    assert text.count("| Conditional result was False") == 301
    assert "NDP_PIPELINE_ONLY_CANARY" not in text and "pipeline condition" not in text
    assert "condition: state == 'gathered'" in text
    assert "Case labels are bounded" in text
    assert aggregate["rows"][0]["case_totals"]["skipped"] == 301


def test_unreached_authored_case_is_not_reported_as_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(smoke, "TASKS", smoke.TASKS + [
        ("REPLACED TC4 - never reached", smoke.MODULE, {"state": "replaced"}, None)])
    workspace, _, job, cli = smoke.queue_fixture(tmp_path, True)
    cli("next")
    aggregate = aggregate_with_receipt(cli, job)
    text = (workspace / aggregate["skiplist_file"]).read_text()
    not_reached = text.split("NOT OBSERVED / NOT REACHED", 1)[1].split("AUTHORED TASK SKIP", 1)[0]
    skipped = text.split("FULLY SKIPPED CASES", 1)[1].split("INCOMPLETE CASES", 1)[0]
    assert "REPLACED TC4" in not_reached and "REPLACED TC4" not in skipped
    assert aggregate["rows"][0]["case_totals"]["skipped"] == 1


def test_missing_case_identifiers_are_unknown_even_when_task_skips_are_visible(tmp_path, monkeypatch):
    monkeypatch.setattr(smoke, "TASKS", [(re.sub(r" TC\d+", "", name), action, arguments, outcome)
                                       for name, action, arguments, outcome in smoke.TASKS])
    workspace, _, job, cli = smoke.queue_fixture(tmp_path, True)
    cli("next")
    aggregate = aggregate_with_receipt(cli, job)
    text = (workspace / aggregate["skiplist_file"]).read_text()
    assert "Authored case inventory unavailable" in text
    assert "skipped=unknown" in text and "GATHERED - gather" in text
    assert aggregate["rows"][0]["case_totals"]["skipped"] is None


def test_no_log_skip_and_quoted_condition_values_remain_private(tmp_path):
    workspace, _, job, cli = smoke.queue_fixture(tmp_path, True,
        skip_fields={"no_log": True, "skip_reason": "PRIVATE_REASON_CANARY", "false_condition": "private == 'hidden-canary'"})
    cli("next")
    aggregate = aggregate_with_receipt(cli, job)
    text = (workspace / aggregate["skiplist_file"]).read_text()
    assert "Reason withheld (no_log)" in text
    assert "PRIVATE_REASON_CANARY" not in text and "hidden-canary" not in text
    assert reporting.skip_detail("private == 'hidden-canary'", condition=True) == "private == '[value]'"


def test_unstarted_execution_does_not_get_a_fabricated_public_log(tmp_path):
    workspace, queue, job, cli = smoke.queue_fixture(tmp_path, True)
    # A registered but unstarted execution has no evidence to copy or count.
    for path in list(Path(job["log"]).parent.iterdir()):
        path.unlink()
    for directory in ("closed", "results", "started"):
        for path in (queue / directory).glob("*.json"):
            path.unlink()
    cli("finish", "--status", "failed")
    aggregate = cli("aggregate")
    assert aggregate["rows"][0]["result"] == "NOT_RUN"
    assert aggregate["rows"][0]["artifact"] == ""
    assert not (workspace / reporting.public_log_name(job)).exists()
    text = (workspace / aggregate["skiplist_file"]).read_text()
    assert "NOT_RUN" in text and "started=unknown" in text
