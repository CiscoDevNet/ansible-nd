import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("nd_result_summary", ROOT / "playbooks/nd_result_summary.py")
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


def log_text(extra="", recap="host : ok=43 changed=6 unreachable=0 failed=0 skipped=2 rescued=0 ignored=0"):
    return ("[RUN_MARKER: current]\n[TIMESTAMP_START: 100]\n" + extra +
            "\nPLAY RECAP ********\n" + recap +
            "\n[TIMESTAMP_END: 120]\n[DURATION_SECONDS: 20]\n")


def test_counts_only_real_recap_rows():
    result = REPORT.parse_log(io.StringIO(log_text("debug: failed=19 ok=999\n")), "current")
    assert result["status"] == "OK"
    assert result["counts"]["ok"] == 43
    assert result["counts"]["failed"] == 0


@pytest.mark.parametrize("extra,status", [
    ("[ANSIBLE_EXIT_STATUS: 2]", "FAIL"),
    ("NDP_MODULE_SKIPPED missing link", "SKIP"),
    ("NDP_MODULE_SKIPPED missing link\n[ANSIBLE_EXIT_STATUS: 2]", "FAIL"),
    ("[RUN_MARKER: stale]", "ERR"),
    ("[ANSIBLE_EXIT_STATUS: invalid]", "ERR"),
])
def test_fail_closed_and_skip(extra, status):
    assert REPORT.parse_log(io.StringIO(log_text(extra)), "current")["status"] == status


def test_unreachable_is_failure():
    result = REPORT.parse_log(io.StringIO(log_text(recap="host : ok=0 changed=0 unreachable=1 failed=0")), "current")
    assert result["status"] == "FAIL"


def test_missing_recap_and_unfinished_log():
    result = REPORT.parse_log(io.StringIO("[RUN_MARKER: current]\n"), "current")
    assert result["status"] == "ERR"
    assert "no PLAY RECAP" in result["reason"]
    assert "did not complete" in result["reason"]


def test_summary_is_small_and_atomic(tmp_path):
    log = tmp_path / "output.txt"
    log.write_text(log_text("payload=" + "x" * 1000000))
    result = REPORT.summarize(log, "example", "current")
    assert result["module"] == "example"
    assert result["phase_seconds"]["execution"] is None
    summary = Path(str(log) + ".summary.json")
    assert summary.stat().st_size < 2000
    assert json.loads(summary.read_text())["status"] == "OK"


@pytest.mark.parametrize("guard_seconds", [0, 7])
def test_missing_phase_measurements_remain_unknown(tmp_path, guard_seconds):
    log = tmp_path / "output.txt"
    log.write_text(log_text())
    REPORT.atomic_json(str(log) + ".execution.json", {
        "module": "example", "run_id": "current", "exit_code": 0,
        "started_at": 100, "ended_at": 120,
        "prerequisite_guard_seconds": guard_seconds,
    })
    result = REPORT.summarize(log, "example", "current", require_execution=True)
    assert result["prerequisite_guard_seconds"] == guard_seconds
    assert result["process_seconds"] == 20
    for phase in ("prerequisites", "execution", "cleanup"):
        assert result["phase_seconds"][phase] is None


def test_stale_execution_metadata_is_rejected(tmp_path):
    log = tmp_path / "output.txt"
    log.write_text(log_text())
    REPORT.atomic_json(str(log) + ".execution.json", {"module": "example", "run_id": "old"})
    with pytest.raises(ValueError, match="another run"):
        REPORT.summarize(log, "example", "current")


def test_missing_metadata_fails_closed(tmp_path):
    log = tmp_path / "output.txt"
    log.write_text(log_text())
    result = REPORT.summarize(log, "example", "current", require_execution=True)
    with pytest.raises(ValueError, match="metadata"):
        REPORT.compact_recap(result)


def test_archive_timing_keeps_summary_and_rejects_stale_runs(tmp_path):
    log = tmp_path / "output.txt"
    log.write_text(log_text())
    REPORT.summarize(log, "example", "current")
    result = REPORT.record_archive(log, "example", "current", 12.5, "success")
    assert result["phase_seconds"]["archiving"] == 12.5
    assert result["status"] == "OK"
    assert result["archive_status"] == "success"
    with pytest.raises(ValueError, match="another run"):
        REPORT.record_archive(log, "example", "old", 5, "failed")


def test_failure_details_are_bounded_task_names_not_response_payloads():
    payload = "TASK [check link] ***\nfatal: [host]: FAILED! => private_response_payload\n"
    result = REPORT.parse_log(io.StringIO(log_text(payload)), "current")
    assert result["failure_tasks"] == ["check link"]
    assert "private_response_payload" not in json.dumps(result)


@pytest.mark.parametrize("ignored", [False, True])
def test_capability_failure_classification_survives_compaction(ignored):
    payload = ("TASK [check virtual peer-link] ***\nfatal: [host]: FAILED! => {\n"
               '"platform": "N9K-C9300v",\n"msg": "virtual peer-link is not supported",\n'
               '"response": "private_response_payload"}\n')
    if ignored:
        payload += "...ignoring\n"
    result = REPORT.parse_log(io.StringIO(log_text(payload)), "current")
    assert result["capability_tasks"] == ([] if ignored else ["check virtual peer-link"])
    compact = REPORT.compact_recap(result)
    assert ("N9K-C9300v virtual peer-link unsupported" in compact) is not ignored
    assert "private_response_payload" not in compact
    assert "private_response_payload" not in json.dumps(result)


def test_compact_recap_preserves_unreachable_and_exit_code():
    result = REPORT.parse_log(io.StringIO(log_text("[ANSIBLE_EXIT_STATUS: 4]", "host : ok=2 changed=0 unreachable=1 failed=0")), "current")
    recap = REPORT.compact_recap(result)
    assert "failed=1" in recap
    assert "[ANSIBLE_EXIT_STATUS: 4]" in recap
    assert len(recap) < 400


def test_bounded_lines_discards_oversized_payloads():
    stream = io.StringIO("x" * 2000000 + "\nPLAY RECAP\n")
    lines = list(REPORT.bounded_lines(stream))
    assert len(lines[0]) == 65536
    assert lines[1] == "PLAY RECAP\n"


@pytest.mark.parametrize("debug", [False, True])
@pytest.mark.parametrize("prerequisite_only", [False, True])
def test_real_ansible_callback_records_failure_cleanup_and_compact_output(tmp_path, debug, prerequisite_only):
    playbook = tmp_path / "local.yaml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "tasks": [
            {"name": "Preparation", "debug": {"msg": "PAYLOAD_MARKER" * 1000}},
            {"name": "Execution", "debug": {"msg": "phase"}, "tags": ["nd_phase_execution"],
             "when": not prerequisite_only},
            {"block": [{"name": "Expected failure", "fail": {"msg": "test failure details"}}],
             "always": [{"name": "Cleanup", "debug": {"msg": "done"}, "tags": ["nd_phase_cleanup"]}],
             "when": not prerequisite_only},
        ],
    }]))
    log = tmp_path / "local.txt"
    environment = dict(os.environ, ANSIBLE_STDOUT_CALLBACK="nd_report",
                       ANSIBLE_CALLBACK_PLUGINS=str(ROOT / "playbooks"),
                       ND_RESULT_LOG=str(log), TEST_RUN_MARKER="current", ND_RESULT_MODULE="example",
                       ND_RESULT_PHASE="prerequisites", ND_REPORT_DEBUG=str(debug).lower(),
                       ANSIBLE_NOCOLOR="1", ANSIBLE_VERBOSITY="0")
    command = str(Path(sys.executable).parent / "ansible-playbook")
    completed = subprocess.run([command, "-i", "localhost,", str(playbook)], env=environment,
                               capture_output=True, text=True, timeout=30)
    assert completed.returncode == (0 if prerequisite_only else 2), completed.stdout + completed.stderr
    assert ("test failure details" in completed.stdout) == (not prerequisite_only)
    assert ("PAYLOAD_MARKER" in completed.stdout) == debug
    phases = json.loads(Path(str(log) + ".phases.json").read_text())
    assert phases["completed"] is True
    assert phases["phase_seconds"]["prerequisites"] >= 0
    if prerequisite_only:
        assert phases["phase_seconds"]["execution"] is None
        assert phases["phase_seconds"]["cleanup"] is None
    else:
        assert all(value is not None and value >= 0 for value in phases["phase_seconds"].values())
    assert phases["run_id"] == "current"
    assert "PLAY RECAP" in completed.stdout


def test_jenkins_reporting_wiring_and_shell_syntax(tmp_path):
    source = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    parser = source.split("def parseTestResults(", 1)[1].split("def resetFabricBetweenVersions", 1)[0]
    assert "--require-execution --format recap" in parser
    assert "cat --" not in parser
    assert 'e.getMessage().contains(' not in parser
    assert "failedCount > 0 || ansibleExitStatus > 0" in parser
    assert source.count("run_reported_playbook ") == 3
    for index, block in enumerate(source.split("'''#!/bin/bash")[1:]):
        block = block.split("'''", 1)[0]
        if "run_reported_playbook()" not in block and "--log \"$ND_REPORT_LOG\"" not in block:
            continue
        script = tmp_path / f"script-{index}.sh"
        script.write_text("#!/bin/bash" + block.replace("\\\\", "\\").replace("\\$", "$"))
        checked = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        assert checked.returncode == 0, checked.stderr


@pytest.mark.parametrize("enabled,selected,expected", [
    ("false", "", "false"), ("true", "", "true"),
    ("true", "other, example", "true"), ("true", "other", "false"),
])
@pytest.mark.parametrize("exit_code", [0, 2])
def test_execution_wrapper_records_exit_and_selects_debug(tmp_path, enabled, selected, expected, exit_code):
    source = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    start = source.index("                                run_reported_playbook() {")
    end = source.index("\n                                }", start) + len("\n                                }")
    wrapper = source[start:end].replace("\\\\", "\\")
    probe = ("import json, os, sys; "
             "print(json.dumps({key: os.environ[key] for key in "
             "('ND_REPORT_DEBUG', 'ANSIBLE_VERBOSITY', 'ANSIBLE_STDOUT_CALLBACK')})); "
             f"sys.exit({exit_code})")
    script = tmp_path / "wrapper.sh"
    script.write_text("set -e\n" + wrapper + "\nPREREQUISITE_START=$(date +%s)\n"
                      "run_reported_playbook example output.txt execution " +
                      shlex.join([sys.executable, "-c", probe]) + "\n")
    environment = dict(os.environ, COLLECTIONS_DIRECTORY=str(ROOT / "playbooks"),
                       TEST_RUN_MARKER="current", ND_REPORT_DEBUG_ENABLED=enabled,
                       ND_REPORT_DEBUG_MODULES=selected,
                       PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", ""))
    completed = subprocess.run(["bash", str(script)], cwd=tmp_path, env=environment,
                               capture_output=True, text=True, timeout=30)
    assert completed.returncode == exit_code, completed.stdout + completed.stderr
    observed = json.loads(completed.stdout)
    assert observed == {"ND_REPORT_DEBUG": expected, "ANSIBLE_VERBOSITY": "4" if expected == "true" else "0",
                        "ANSIBLE_STDOUT_CALLBACK": "nd_report"}
    recorded = json.loads((tmp_path / "output.txt.execution.json").read_text())
    assert recorded["exit_code"] == exit_code
    assert recorded["module"] == "example"
    assert recorded["run_id"] == "current"
    assert recorded["ended_at"] >= recorded["started_at"]
    assert recorded["prerequisite_guard_seconds"] >= 0


def test_final_phase_timing_table_groovy_runtime(tmp_path):
    java = os.environ.get("ND_REPORT_JAVA")
    groovy_jar = os.environ.get("ND_REPORT_GROOVY_JAR")
    if not java or not groovy_jar:
        pytest.skip("Set ND_REPORT_JAVA and ND_REPORT_GROOVY_JAR for offline Groovy checks")
    assert java and groovy_jar
    source = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    functions = source.split("def formatPhaseDuration(", 1)[1].split("def fabricScopeLabel(", 1)[0]
    harness = "def formatPhaseDuration(" + functions + r'''
assert formatPhaseDuration(null) == 'N/A'
assert formatPhaseDuration(-1) == 'N/A'
assert formatPhaseDuration(Double.NaN) == 'N/A'
assert formatPhaseDuration(Double.POSITIVE_INFINITY) == 'N/A'
assert formatPhaseDuration('12') == 'N/A'
assert formatPhaseDuration(0) == '00h 00m 00.000s'
assert formatPhaseDuration(3661.125) == '01h 01m 01.125s'
assert formatPhaseDuration(59.9999) == '00h 01m 00.000s'
assert formatPhaseDuration(360000) == '100h 00m 00.000s'
def table = formatPhaseTimingTable([
    [prerequisites: 10, execution: 3600, cleanup: 2, parsing: 0.125, archiving: 3,
     process_seconds: 99999, prerequisite_guard_seconds: 99999],
    [prerequisites: null, execution: 60, cleanup: 0, parsing: 0.125, archiving: 2],
    [:]
], 4000)
def rows = table.readLines().findAll { it.contains(' | ') }.collect { line ->
    line.split('\\|').collect { it.trim() }
}
assert rows.find { it[0] == 'Prerequisite setup' } == ['Prerequisite setup', '00h 00m 10.000s', '1 / 3']
assert rows.find { it[0] == 'Test execution' } == ['Test execution', '01h 01m 00.000s', '2 / 3']
assert rows.find { it[0] == 'Cleanup' } == ['Cleanup', '00h 00m 02.000s', '2 / 3']
assert rows.find { it[0] == 'Result parsing' } == ['Result parsing', '00h 00m 00.250s', '2 / 3']
assert rows.find { it[0] == 'Measured phase subtotal' }[1] == '01h 01m 17.250s'
assert rows.find { it[0] == 'Build elapsed (to report)' }[1] == '01h 06m 40.000s'
assert formatPhaseTimingTable([], 0).contains('0 / 0')
assert formatPhaseTimingTable([[:]], 10).contains('N/A')
println table
'''
    script = tmp_path / "timing.groovy"
    script.write_text(harness)
    completed = subprocess.run([java, "-cp", groovy_jar, "groovy.ui.GroovyMain", str(script)],
                               capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "FINAL TIME BREAKDOWN" in completed.stdout
    post = source.split("    post {", 1)[1]
    assert post.index("echo formatPhaseTimingTable") < post.index("Post-build Webex")
    archive = source.split("def archiveTestOutput(", 1)[1].split("def archiveSkipList(", 1)[0]
    assert "PHASE_TIMING_RESULTS[timingKey] = [:]" in archive
    assert "timingSummary.run_id != expectedRunMarker" in archive
    assert archive.index("PHASE_TIMING_RESULTS[timingKey] = timingSummary.phase_seconds") < archive.index(
        'archiveArtifacts artifacts: "${archivedFileName}.*.json"')


@pytest.mark.parametrize("scenario", ["null_message", "nonzero_exit", "success"])
def test_jenkins_result_rows_groovy_runtime(tmp_path, scenario):
    java = os.environ.get("ND_REPORT_JAVA")
    groovy_jar = os.environ.get("ND_REPORT_GROOVY_JAR")
    if not java or not groovy_jar:
        pytest.skip("Set ND_REPORT_JAVA and ND_REPORT_GROOVY_JAR for offline Groovy checks")
    assert java and groovy_jar
    source = (ROOT / "Jenkinsfile_nd_jenkins_script").read_text()
    start = source.index("def parseTestResults(")
    parser = source[start:source.index("\n}\n", start) + 3]
    helpers = ""
    for function_name in ("fabricScopeLabel", "activityResultKey"):
        helper_start = source.index(f"def {function_name}(")
        helpers += source[helper_start:source.index("\n}\n", helper_start) + 3]
    harness = r'''
import groovy.transform.Field
@Field def env = [COLLECTIONS_DIRECTORY: '/tmp/collection', TOTAL_FAILED_COUNT: '0',
                  TOTAL_PASSED_COUNT: '0', TEST_RESULT_SUMMARY: '', BUILD_FAILURE_REASON: '']
@Field def TEST_RESULT_SUMMARY_BUF = ''
@Field def BUILD_FAILURE_REASON_BUF = ''
@Field def MODULE_ACTIVITY_RESULTS = [:]
@Field def scenario = 'SCENARIO'
@Field def flags = [:]
def echo(message) {}
def setFailureFlag(name, value) { flags[name] = value }
def error(message) { throw new RuntimeException(message.toString()) }
def withEnv(values, body) { body() }
def virtualPeerLinkCapabilityFailures(output) { [] }
def sh(options) {
    if (scenario == 'null_message') { throw new RuntimeException() }
    return '[RUN_MARKER: current]\n[DURATION_SECONDS: 20]\nPLAY RECAP\n' +
           'host : ok=43 changed=6 unreachable=0 failed=0 skipped=2\n' +
           '[ANSIBLE_EXIT_STATUS: ' + (scenario == 'nonzero_exit' ? '2' : '0') + ']\n'
}
HELPERS
PARSER
def caught = null
try {
    parseTestResults([fabric_name: 'fabric', versionId: '43', version: '4.3'],
                     'failed', 'example', 'integration', 'current')
} catch (Exception failure) { caught = failure }
def rows = (env.TEST_RESULT_SUMMARY ?: TEST_RESULT_SUMMARY_BUF).readLines().findAll { it.trim() }
assert rows.size() == 1 : rows
def expected = scenario == 'null_message' ? 'ERR' : (scenario == 'nonzero_exit' ? 'FAIL' : 'OK')
assert rows[0].startsWith(expected + '|example|') : rows
assert (caught != null) == (scenario != 'success')
if (scenario != 'success') { assert flags.failed == true }
if (scenario == 'null_message') {
    assert caught.message.contains('java.lang.RuntimeException') : caught.message
    assert !caught.message.contains('contains() on null')
}
'''.replace("SCENARIO", scenario).replace("HELPERS", helpers).replace("PARSER", parser)
    script = tmp_path / "Reporting.groovy"
    script.write_text(harness)
    result = subprocess.run([java, "-cp", groovy_jar, "groovy.ui.GroovyMain", str(script)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr