"""Authored-case regression fixtures; no controller or Ansible execution."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("case_activity", ROOT / "playbooks/nd_test_activity.py")
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)
COLLECTION = ROOT.parents[1]
MODULE = "nd_manage_switches"


@pytest.fixture(scope="module", autouse=True)
def pinned_authored_roles(tmp_path_factory):
    """Read authored fixtures from Git objects, preserving the user's worktree."""
    global COLLECTION
    original = COLLECTION
    pinned_commit = subprocess.check_output(
        ["git", "-C", str(original), "rev-parse", "HEAD"], text=True,
    ).strip()
    assert len(pinned_commit) == 40
    archive = subprocess.run(
        ["git", "-C", str(original), "archive", pinned_commit,
         "tests/integration/targets/nd_manage_switches", "tests/integration/targets/nd_vpc_pair"],
        check=True, stdout=subprocess.PIPE,
    ).stdout
    COLLECTION = tmp_path_factory.mktemp("authored-repository-roles")
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        for member in source:
            relative = Path(member.name)
            if member.isfile() and relative.suffix in {".yaml", ".yml"}:
                assert not relative.is_absolute() and ".." not in relative.parts
                destination = COLLECTION / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(source.extractfile(member).read())
    yield
    COLLECTION = original


def records_for(collection=None, module=MODULE, relative="tests/sanity.yaml"):
    collection = collection or COLLECTION
    catalog = REPORT.load_catalog(collection, module)
    return sorted([record for records in catalog["tasks"].values() for record in records
                   if record["path"] == relative], key=lambda record: record["line"])


def emit_log(tmp_path, rows, failing_assert=None, paths=True, collection=None, module=MODULE, outcomes=None, ignored=()):
    collection = collection or COLLECTION
    target = REPORT.load_catalog(collection, module)["target"]
    log = tmp_path / "cases.txt"
    lines = [f"[MODULE: {module}] Starting execution...", "[RUN_MARKER: current]"]
    used = []
    number = 0
    failed = False
    for record in rows:
        if record["name"] == "Assert":
            number += 1
        outcome = (outcomes or {}).get(record["key"], "ok")
        if record["name"] == "Assert" and number == failing_assert:
            outcome = "failed"
        lines.append(f"TASK [{target} : {record['name']}] ***")
        if paths:
            path = collection / "tests/integration/targets" / target / record["path"]
            lines.append(f"task path: {path}:{record['line']}")
        lines.append({"ok": "ok: [fixture]", "failed": "fatal: [fixture]: FAILED!",
                      "skipped": "skipping: [fixture]"}[outcome])
        if record["key"] in ignored:
            lines.append("...ignoring")
        used.append((record, outcome))
        if outcome == "failed" and record["key"] not in ignored:
            failed = True
            break
    exit_code = 2 if failed else 0
    lines += ["PLAY RECAP", f"fixture : ok=99 changed=0 unreachable=0 failed={int(failed)} skipped=0 rescued=0 ignored=0",
              f"[ANSIBLE_EXIT_STATUS: {exit_code}]"]
    log.write_text("\n".join(lines) + "\n")
    Path(str(log) + ".execution.json").write_text(json.dumps({"module": module, "run_id": "current", "exit_code": exit_code}))
    return log, used, exit_code


def events_for(log, used, exit_code, collection=None, module=MODULE):
    collection = collection or COLLECTION
    target = REPORT.load_catalog(collection, module)["target"]
    records = []
    for index, (record, outcome) in enumerate(used):
        event = {"schema_version": 1, "module": module, "run_id": "current", "invocation_id": "fixture",
                 "task_uuid": str(index), "task_instance": 1, "name": record["name"],
                 "path": str(collection / "tests/integration/targets" / target / record["path"]),
                 "line": record["line"], "action": record["action"], "role": target}
        records.append(dict(event, kind="task", seq=len(records) + 1))
        records.append(dict(event, kind="outcome", seq=len(records) + 1, outcome=outcome,
                            terminal=True, ignored=False, item=False, host="fixture", reason_codes=[]))
    raw = "".join(json.dumps(value) + "\n" for value in records).encode()
    Path(str(log) + ".events.jsonl").write_bytes(raw)
    Path(str(log) + ".event-summary.json").write_text(json.dumps({
        "schema_version": 1, "module": module, "run_id": "current", "invocation_id": "fixture",
        "completed": True, "capture_error": False, "errors": [], "event_count": len(records),
        "event_bytes": len(raw), "event_sha256": hashlib.sha256(raw).hexdigest(), "host_count": 1,
        "counts": {"ok": 99, "changed": 0, "failed": int(exit_code != 0), "unreachable": 0,
                   "skipped": 0, "rescued": 0, "ignored": 0}}))


@pytest.mark.parametrize("adapter", ["verbose", "quiet", "events"])
def test_actual_switch_sanity_counts_all_seven_cases_and_independent_gather(tmp_path, adapter):
    log, used, code = emit_log(tmp_path, records_for(), paths=adapter != "quiet")
    if adapter == "events":
        events_for(log, used, code)
        catalog = tmp_path / "catalog.json"
        REPORT.freeze_catalog(COLLECTION, MODULE, catalog)
        result = REPORT.summarize_events(log, MODULE, "current", "121", "iBGP", COLLECTION, catalog_path=catalog)
    else:
        result = REPORT.summarize(log, MODULE, "current", "121", "iBGP", COLLECTION)
    assert result["result"] == "PASS"
    assert result["coverage"] == "COMPLETE"
    assert result["testcase_totals"] == {"started": 7, "passed": 7, "failed": 0, "skipped": 0, "incomplete": 0}
    assert result["counts"] == {"merged": 2, "replaced": 1, "overridden": 1, "deleted": 2, "gathered": 1}


@pytest.mark.parametrize("number,started,passed", [(1, 2, 1), (2, 4, 3), (3, 5, 4), (4, 7, 6)])
@pytest.mark.parametrize("adapter", ["verbose", "quiet", "events"])
def test_fatal_unnamed_assert_is_attributed_to_its_case_and_stops_execution(tmp_path, number, started, passed, adapter):
    log, used, code = emit_log(tmp_path, records_for(), failing_assert=number, paths=adapter != "quiet")
    if adapter == "events":
        events_for(log, used, code)
        result = REPORT.summarize_events(log, MODULE, "current", "121", "iBGP", COLLECTION)
    else:
        result = REPORT.summarize(log, MODULE, "current", "121", "iBGP", COLLECTION)
    assert result["result"] == "FAIL"
    assert result["coverage"] == "COMPLETE"
    assert result["testcase_totals"] == {"started": started, "passed": passed, "failed": 1, "skipped": 0, "incomplete": 0}
    assert sum(case["outcome"] == "failed" for case in result["case_results"]) == 1


def synthetic_collection(tmp_path, tasks, module="nd_fixture"):
    source = tmp_path / "collection/tests/integration/targets" / module / "tasks/main.yaml"
    source.parent.mkdir(parents=True)
    source.write_text(json.dumps(tasks, indent=2))
    return tmp_path / "collection", module


def test_verification_gather_is_not_another_case(tmp_path):
    collection, module = synthetic_collection(tmp_path, [
        {"name": "Merged TC1 - configure", "nd_fixture": {"state": "merged"}},
        {"name": "Merged TC1 - first verify", "ansible.builtin.assert": {"that": [True]}},
        {"name": "Merged TC1 - Gathered - Query readback", "nd_fixture": {"state": "gathered"}},
        {"name": "Assert", "ansible.builtin.assert": {"that": [True]}},
    ])
    rows = records_for(collection, module, "tasks/main.yaml")
    log, _, _ = emit_log(tmp_path, rows, collection=collection, module=module)
    result = REPORT.summarize(log, module, "current", "121", "iBGP", collection)
    assert result["testcase_totals"]["passed"] == 1
    assert result["counts"]["merged"] == 1
    assert result["counts"]["gathered"] == 0


def test_actual_poap_preparation_is_not_promoted_to_an_extra_case():
    catalog = REPORT.load_catalog(COLLECTION, MODULE)
    poap = {identity: case for identity, case in catalog["cases"].items()
            if identity.startswith("tests/poap.yaml::")}
    assert len(poap) == 4
    assert "tests/poap.yaml::POAP::TC1" in poap
    assert not any(identity.count("::") > 2 for identity in poap)


def test_ambiguous_quiet_assert_without_case_context_remains_unknown(tmp_path):
    catalog = REPORT.load_catalog(COLLECTION, MODULE)
    row = catalog["tasks"]["Assert"][0]
    log, _, _ = emit_log(tmp_path, [row], paths=False)
    result = REPORT.summarize(log, MODULE, "current", "121", "iBGP", COLLECTION)
    assert result["coverage"] == "PARTIAL"
    assert result["testcase_totals"]["passed"] is None


def test_missing_verification_is_incomplete_not_complete_pass(tmp_path):
    collection, module = synthetic_collection(tmp_path, [
        {"name": "Merged TC1 - configure", "nd_fixture": {"state": "merged"}},
        {"name": "Merged TC1 - verify", "ansible.builtin.assert": {"that": [True]}},
    ])
    log, _, _ = emit_log(tmp_path, records_for(collection, module, "tasks/main.yaml")[:1], collection=collection, module=module)
    result = REPORT.summarize(log, module, "current", "121", "iBGP", collection)
    assert result["coverage"] == "INCOMPLETE"
    assert result["testcase_totals"]["passed"] == 0
    assert result["testcase_totals"]["incomplete"] == 1


def test_applicability_notice_needs_complete_skipped_work_and_preserves_reason(tmp_path):
    collection, module = synthetic_collection(tmp_path, [
        {"name": "Merged TC4 - Applicability", "ansible.builtin.debug": {"msg": "NDP_CASE_SKIPPED: Brownfield unsupported on eBGP"}},
        {"name": "Merged TC4 - configure", "nd_fixture": {"state": "merged"}},
        {"name": "Merged TC4 - verify", "ansible.builtin.assert": {"that": [True]}},
    ])
    rows = records_for(collection, module, "tasks/main.yaml")
    outcomes = {record["key"]: "skipped" for record in rows if not record["applicability"]}
    log, _, _ = emit_log(tmp_path, rows, collection=collection, module=module, outcomes=outcomes)
    result = REPORT.summarize(log, module, "current", "121", "eBGP", collection)
    assert result["testcase_totals"] == {"started": 0, "passed": 0, "failed": 0, "skipped": 1, "incomplete": 0}
    assert result["case_results"][0]["reason"] == "Brownfield unsupported on eBGP"


def test_notice_alone_does_not_prove_a_skipped_case(tmp_path):
    collection, module = synthetic_collection(tmp_path, [
        {"name": "Merged TC4 - Applicability", "ansible.builtin.debug": {"msg": "NDP_CASE_SKIPPED: unsupported on eBGP"}},
        {"name": "Merged TC4 - configure", "nd_fixture": {"state": "merged"}},
        {"name": "Assert", "ansible.builtin.assert": {"that": [True]}},
    ])
    rows = records_for(collection, module, "tasks/main.yaml")
    log, _, _ = emit_log(tmp_path, rows[:1], collection=collection, module=module)
    result = REPORT.summarize(log, module, "current", "121", "eBGP", collection)
    assert result["coverage"] == "INCOMPLETE"
    assert result["testcase_totals"]["started"] == result["testcase_totals"]["skipped"] == 0
    assert result["case_results"][0]["outcome"] == "incomplete"


@pytest.mark.parametrize("paths", [True, False])
def test_repeated_assert_names_within_a_case_require_source_positions(tmp_path, paths):
    collection, module = synthetic_collection(tmp_path, [
        {"name": "Merged TC1 - configure", "nd_fixture": {"state": "merged"}},
        {"name": "Assert", "ansible.builtin.assert": {"that": [True]}},
        {"name": "Assert", "ansible.builtin.assert": {"that": [True]}},
    ])
    log, _, _ = emit_log(tmp_path, records_for(collection, module, "tasks/main.yaml"), collection=collection, module=module, paths=paths)
    result = REPORT.summarize(log, module, "current", "121", "iBGP", collection)
    assert result["coverage"] == ("COMPLETE" if paths else "PARTIAL")
    assert result["testcase_totals"]["passed"] == (1 if paths else None)


def test_source_position_mismatch_is_unknown_instead_of_matching_by_name(tmp_path):
    rows = records_for()
    log, _, _ = emit_log(tmp_path, rows)
    actual_line = rows[0]["line"]
    log.write_text(log.read_text().replace(f"sanity.yaml:{actual_line}\n", "sanity.yaml:99999\n", 1))
    result = REPORT.summarize(log, MODULE, "current", "121", "iBGP", COLLECTION)
    assert result["coverage"] == "PARTIAL"
    assert result["testcase_totals"]["passed"] is None


@pytest.mark.parametrize("adapter", ["raw", "events"])
def test_failed_custom_validator_is_a_failed_case(tmp_path, adapter):
    rows = records_for()
    validator = next(record for record in rows if record["action"].endswith("_validate"))
    log, used, code = emit_log(tmp_path, rows, outcomes={validator["key"]: "failed"})
    if adapter == "events":
        events_for(log, used, code)
        result = REPORT.summarize_events(log, MODULE, "current", "121", "iBGP", COLLECTION)
    else:
        result = REPORT.summarize(log, MODULE, "current", "121", "iBGP", COLLECTION)
    assert result["testcase_totals"] == {"started": 1, "passed": 0, "failed": 1, "skipped": 0, "incomplete": 0}


def test_base_cleanup_and_expected_ignored_negative_are_not_added_as_cases(tmp_path):
    collection, module = synthetic_collection(tmp_path, [
        {"name": "Base - prerequisite", "nd_fixture": {"state": "merged"}},
        {"name": "Merged TC1 - invalid request", "nd_fixture": {"state": "merged"}, "ignore_errors": True},
        {"name": "Assert", "ansible.builtin.assert": {"that": [True]}},
        {"name": "Cleanup - restore", "nd_fixture": {"state": "deleted"}},
    ])
    rows = records_for(collection, module, "tasks/main.yaml")
    negative = next(record for record in rows if record["ignored"])
    log, _, _ = emit_log(tmp_path, rows, collection=collection, module=module,
                         outcomes={negative["key"]: "failed"}, ignored={negative["key"]})
    result = REPORT.summarize(log, module, "current", "121", "iBGP", collection)
    assert result["base"] == result["cleanup"] == "Ran"
    assert result["testcase_totals"] == {"started": 1, "passed": 1, "failed": 0, "skipped": 0, "incomplete": 0}


@pytest.mark.parametrize("module", ["nd_vpc_pair.advanced", "nd_vpc_pair.external", "nd_manage_vpc_pair"])
@pytest.mark.parametrize("adapter", ["verbose", "quiet", "events"])
def test_actual_develop_vpc_merge_case_uses_module_alias_for_state_and_required_actions(tmp_path, module, adapter):
    catalog = REPORT.load_catalog(COLLECTION, module)
    identity = "tasks/nd_vpc_pair_merge.yaml::MERGE::TC1"
    rows = [record for record in records_for(module=module, relative="tasks/nd_vpc_pair_merge.yaml")
            if record["case"] == identity]
    assert rows and any(record["action"] == "nd_manage_vpc_pair" for record in rows)
    log, used, code = emit_log(tmp_path, rows, paths=adapter != "quiet", module=module)
    if adapter == "events":
        events_for(log, used, code, module=module)
        frozen = tmp_path / "vpc.catalog.json"
        REPORT.freeze_catalog(COLLECTION, module, frozen)
        result = REPORT.summarize_events(log, module, "current", "124", "iBGP", COLLECTION, catalog_path=frozen)
    else:
        result = REPORT.summarize(log, module, "current", "124", "iBGP", COLLECTION)
    assert result["coverage"] == "COMPLETE"
    assert result["testcase_totals"] == {"started": 1, "passed": 1, "failed": 0, "skipped": 0, "incomplete": 0}
    assert result["counts"] == {"merged": 1, "replaced": 0, "overridden": 0, "deleted": 0, "gathered": 0}
    assert result["other_cases"] == 0
    assert catalog["cases"][identity]["module_actions"]
    assert len(catalog["cases"]) == 65
    assert sum(case["state"] == "other" for case in catalog["cases"].values()) == 1


@pytest.mark.parametrize("target,action", [("nd_vpc_pair", "nd_manage_vpc_pair"),
                                           ("nd_resource_manager", "nd_manage_resource_manager")])
@pytest.mark.parametrize("omit", [None, "action", "verification"])
def test_alias_actions_require_observed_execution_and_verification(tmp_path, target, action, omit):
    collection, _ = synthetic_collection(tmp_path, [
        {"name": "Merged TC1 - configure", "cisco.nd." + action: {"state": "merged"}},
        {"name": "Merged TC1 - verify", "ansible.builtin.assert": {"that": [True]}},
    ], module=target)
    rows = records_for(collection, action, "tasks/main.yaml")
    if omit:
        rows = [record for record in rows if record["verification"] == (omit == "action")]
    log, _, _ = emit_log(tmp_path, rows, collection=collection, module=action)
    result = REPORT.summarize(log, action, "current", "124", "iBGP", collection)
    assert result["coverage"] == ("INCOMPLETE" if omit else "COMPLETE")
    assert result["testcase_totals"]["passed"] == (0 if omit else 1)
    assert result["testcase_totals"]["incomplete"] == (1 if omit else 0)


def test_actual_develop_vpc_base_and_five_end_cleanups_are_observations_only(tmp_path):
    module = "nd_vpc_pair.advanced"
    catalog = REPORT.load_catalog(COLLECTION, module)
    owned = [record for records in catalog["tasks"].values() for record in records
             if record["action"] == "nd_manage_vpc_pair" and not record["case"]]
    assert len(owned) == 7  # Six formerly untagged actions plus an existing cleanup.
    assert sum(record["base"] for record in owned) == 1
    assert sum(record["cleanup"] for record in owned) == 6
    assert sum(" - END - " in record["name"] and record["cleanup"] for record in owned) == 5
    assert catalog["untagged_actions"] == 0
    log, _, _ = emit_log(tmp_path, owned, module=module)
    result = REPORT.summarize(log, module, "current", "124", "iBGP", COLLECTION)
    assert result["base"] == result["cleanup"] == "Ran"
    assert result["testcase_totals"] == {"started": 0, "passed": 0, "failed": 0, "skipped": 0, "incomplete": 0}


@pytest.mark.parametrize("name,state", [("MERGE - END - validate input", "deleted"),
                                      ("MERGE - END - remove staged value", "merged"),
                                      ("Verify END - remove value", "deleted")])
def test_end_word_without_explicit_owned_delete_cleanup_remains_uncounted(tmp_path, name, state):
    collection, module = synthetic_collection(tmp_path, [
        {"name": name, "nd_fixture": {"state": state}},
    ])
    catalog = REPORT.load_catalog(collection, module)
    assert catalog["untagged_actions"] == 1
    assert all(not record["cleanup"] for records in catalog["tasks"].values() for record in records)


def test_catalog_from_previous_classification_version_is_rebuilt(tmp_path):
    module = "nd_vpc_pair.advanced"
    frozen = tmp_path / "catalog.json"
    current = REPORT.freeze_catalog(COLLECTION, module, frozen)
    current["catalog_version"] -= 1
    for case in current["catalog"]["cases"].values():
        case["state"] = "other"
    current["catalog_sha256"] = REPORT._json_digest(current["catalog"])
    frozen.write_text(json.dumps(current))
    rebuilt = REPORT.freeze_catalog(COLLECTION, module, frozen)
    assert rebuilt["catalog_version"] == REPORT.CATALOG_VERSION
    assert rebuilt["catalog"]["cases"]["tasks/nd_vpc_pair_merge.yaml::MERGE::TC1"]["state"] == "merged"
