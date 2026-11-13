import importlib.util
import base64
import json
import re
from types import SimpleNamespace
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "send_build_webex_report.py"
SPEC = importlib.util.spec_from_file_location("manual_webex_report", SCRIPT)
sender = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sender)


def execution(round_name, passed=12, result="PASS", **extra):
    return dict(module="nd_manage_community_list", nd="4.3", scope=round_name,
                round_label=round_name, test_type="integration", sequence=1,
                result=result, duration="2m 27s",
                validated=True, coverage="COMPLETE",
                case_totals=dict(started=passed, passed=passed, failed=0, skipped=0, incomplete=0), **extra)


def table_cells(rows):
    return [re.split(r"\s{2,}", line.strip())
            for line in sender.render_table(rows).splitlines()[1:-1]]


def test_missing_ebgp_has_numeric_not_run_cells():
    cells = table_cells([execution("iBGP")])
    assert cells[0] == ["Module", "iBGP", "Passed", "Failed", "Skipped", "Time",
                        "eBGP", "Passed", "Failed", "Skipped", "Time"]
    assert cells[2] == ["nd_manage_community_list", "OK", "12", "0", "0", "2m 27s",
                        "NOT_RUN", "0", "0", "0", "-"]


def test_successful_ebgp_is_grouped_with_ibgp():
    cells = table_cells([execution("eBGP", 9), execution("iBGP")])
    assert len(cells) == 3
    assert cells[2][1:] == ["OK", "12", "0", "0", "2m 27s", "OK", "9", "0", "0", "2m 27s"]


def test_explicit_not_run_requires_no_case_evidence():
    row = execution("eBGP", result="NOT_RUN")
    row["case_totals"] = {}
    assert table_cells([row])[2][1:] == ["NOT_RUN", "0", "0", "0", "-",
                                        "NOT_RUN", "0", "0", "0", "-"]


@pytest.mark.parametrize("value", [None, True, -1, "12", 1.5])
def test_invalid_counts_are_not_published(value):
    row = execution("iBGP")
    row["case_totals"]["passed"] = value
    with pytest.raises(SystemExit):
        sender.render_table([row])


def arguments():
    return SimpleNamespace(build="142", note="", branch="", commit="", build_result="FAILURE",
                           job_url="https://jenkins.example/job/nd", duration="")


def test_build_message_counts_actual_rounds_once():
    report = dict(build="142", rows=[execution("iBGP"), execution("eBGP", 9)])
    text = sender.build_message(report, arguments())
    assert "Passed: 21" in text
    assert "iBGP, eBGP" in text
    assert text.count("nd_manage_community_list") == 1


@pytest.mark.parametrize("problem", ["build", "validation", "coverage", "started", "type", "errors"])
def test_unsafe_report_is_rejected(problem):
    report = dict(build="142", rows=[execution("iBGP")])
    row = report["rows"][0]
    if problem == "build":
        report["build"] = "143"
    elif problem == "validation":
        row["validated"] = False
    elif problem == "coverage":
        row["coverage"] = "UNKNOWN"
    elif problem == "started":
        row["case_totals"]["started"] = 13
    elif problem == "type":
        del row["test_type"]
    else:
        report["reporting_errors"] = [dict(reason="missing evidence")]
    with pytest.raises(SystemExit):
        sender.build_message(report, arguments())


def test_multiple_versions_and_scopes_remain_distinct():
    first = execution("iBGP")
    second = execution("eBGP", 9)
    second["nd"] = "4.4"
    external = execution("iBGP", 3)
    external["scope"] = "External"
    cells = table_cells([first, second, external])
    assert cells[0][:2] == ["Module", "ND"]
    assert len(cells) == 5


def test_split_preserves_rows_and_balances_fences():
    rows = []
    for index in range(120):
        row = execution("iBGP")
        row["module"] = f"module_{index:03d}"
        rows.append(row)
    text = sender.build_message(dict(build="142", rows=rows), arguments())
    parts = sender.split_message(text, "Build 142 continued\n", limit=1200)
    assert len(parts) > 1
    assert all(len(part.encode("utf-16-le")) // 2 <= 1200 for part in parts)
    assert all(part.count("```") % 2 == 0 for part in parts)
    combined = "\n".join(parts)
    for row in rows:
        assert combined.count(row["module"]) == 1


def test_split_long_unicode_line_without_loss():
    text = "\U0001f600" * 8000
    parts = sender.split_message(text, "", limit=1200)
    assert sum(part.count("\U0001f600") for part in parts) == 8000
    assert all(len(part.encode("utf-16-le")) // 2 <= 1200 for part in parts)


def test_load_last_closed_aggregate_from_console(tmp_path):
    path = tmp_path / "console.txt"
    report = dict(build="142", rows=[execution("iBGP")])
    path.write_text('[Pipeline] sh\n' + json.dumps(dict(build="141", rows=[])) + '\n' + json.dumps(report))
    assert sender.load_report(path) == report


@pytest.mark.parametrize("room", ["private", "public"])
def test_generated_jenkins_sender_preserves_messages_and_destination(room):
    messages = ["Build 142 part one", "Build 142 part two"]
    script = sender.jenkins_groovy(messages, sender.ROOMS[room])
    assert f"def roomId = '{sender.ROOMS[room]}'" in script
    for message in messages:
        assert base64.b64encode(message.encode()).decode() in script
    assert "ANSIBLE_WEBEX_TOKEN" in script
    assert "conn.connectTimeout = 30000" in script
    assert "conn.readTimeout = 30000" in script
    assert "if (conn.responseCode != 200)" in script
    assert script.endswith("null\n")


def test_delivery_failure_stops_remaining_parts_without_retry(monkeypatch):
    requests = []

    def fail(request, timeout):
        requests.append(request)
        assert timeout == 30
        raise sender.urllib.error.HTTPError(request.full_url, 404, "room unavailable", {}, None)

    monkeypatch.setattr(sender.urllib.request, "urlopen", fail)
    with pytest.raises(SystemExit, match="part 1/2 failed: HTTP 404"):
        sender.send(["first", "second"], sender.ROOMS["private"], "offline-test-token")
    assert len(requests) == 1


def test_incomplete_verification_is_disclosed_without_inflating_totals():
    row = execution("iBGP")
    row["coverage"] = "INCOMPLETE"
    row["case_totals"].update(started=15, incomplete=3)
    text = sender.build_message(dict(build="142", rows=[row]), arguments())
    assert "Passed: 12" in text
    assert "3 incomplete case(s)" in text


def test_missing_round_placeholders_do_not_inflate_totals():
    unstarted = execution("eBGP", result="NOT_RUN")
    unstarted["case_totals"] = {}
    text = sender.build_message(dict(build="142", rows=[execution("iBGP"), unstarted]), arguments())
    assert "Passed: 12" in text
    assert "Failed: 0" in text
    assert "Skipped: 0" in text