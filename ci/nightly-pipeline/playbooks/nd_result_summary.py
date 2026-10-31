"""Bounded-memory Ansible result extraction for the nightly agent."""

import argparse
import json
import os
from pathlib import Path
import re
import tempfile
import time


COUNTERS = ("ok", "changed", "unreachable", "failed", "skipped", "rescued", "ignored")
ROW = re.compile(r"^\S+\s+:\s+ok=\d+\s+changed=\d+\s+unreachable=\d+\s+failed=\d+\b")
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
MARKER = re.compile(r"^\[(RUN_MARKER|TIMESTAMP_START|TIMESTAMP_END|DURATION_SECONDS|ANSIBLE_EXIT_STATUS):\s*(.*?)\]$")
CAPABILITY = (
    re.compile(r"\b(?:n9k[-_ ]?c)?9300v\b", re.I),
    re.compile(r"virtual[ _-]+peer[ _-]*link|vpc[ _-]+fabric[ _-]+peering", re.I),
    re.compile(r"not supported|unsupported|does not support", re.I),
)


def atomic_json(path, value):
    destination = Path(path)
    descriptor, temporary = tempfile.mkstemp(dir=destination.parent, prefix=destination.name + ".")
    try:
        with os.fdopen(descriptor, "w") as output:
            json.dump(value, output, sort_keys=True)
            output.write("\n")
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def parse_log(stream, run_id):
    counts = dict.fromkeys(COUNTERS, 0)
    markers = {}
    recap_rows = 0
    in_recap = False
    skipped = False
    conflicting_run = False
    task_name = ""
    failure_tasks = []
    capability_tasks = []
    failure_evidence = None

    def finish_failure():
        if failure_evidence and all(failure_evidence["matches"]) and not failure_evidence["ignored"]:
            label = re.sub(r"[|\r\n\t`\[\]=]", " ", task_name or "unidentified task")[:160]
            if label not in capability_tasks and len(capability_tasks) < 20:
                capability_tasks.append(label)

    for raw_line in stream:
        line = ANSI.sub("", raw_line).strip()
        boundary = line.startswith(("TASK [", "PLAY ", "fatal:", "ERROR!"))
        if boundary:
            finish_failure()
            failure_evidence = None
        if line.startswith("TASK ["):
            task_name = line[6:].split("]", 1)[0][:200]
        if line.startswith(("fatal:", "ERROR!")):
            failure_evidence = {"matches": [False] * len(CAPABILITY), "ignored": False, "tail": ""}
        if failure_evidence is not None:
            evidence = failure_evidence["tail"] + " " + line
            failure_evidence["matches"] = [
                found or bool(pattern.search(evidence))
                for found, pattern in zip(failure_evidence["matches"], CAPABILITY)
            ]
            failure_evidence["ignored"] |= "...ignoring" in line.lower()
            failure_evidence["tail"] = evidence[-128:]
        if line.startswith("fatal:") and task_name and task_name not in failure_tasks and len(failure_tasks) < 20:
            failure_tasks.append(task_name)
        match = MARKER.fullmatch(line)
        if match:
            key, value = match.groups()
            if key == "RUN_MARKER" and value != run_id:
                conflicting_run = True
            markers[key] = value
            in_recap = False
            continue
        if line.startswith("PLAY RECAP ") or line == "PLAY RECAP":
            in_recap = True
            continue
        if in_recap and ROW.match(line):
            recap_rows += 1
            for key, value in re.findall(r"\b(" + "|".join(COUNTERS) + r")=(\d+)\b", line):
                counts[key] += int(value)
        elif line:
            in_recap = False
        if "NDP_MODULE_SKIPPED" in line and not line.startswith("TASK ["):
            skipped = True
    finish_failure()
    errors = []
    if not run_id or markers.get("RUN_MARKER") != run_id or conflicting_run:
        errors.append("missing or conflicting current-run marker")
    if not recap_rows:
        errors.append("no PLAY RECAP rows")
    numeric = {}
    for key in ("TIMESTAMP_START", "TIMESTAMP_END", "DURATION_SECONDS", "ANSIBLE_EXIT_STATUS"):
        value = markers.get(key)
        if value is not None:
            if not value.isdigit():
                errors.append("invalid " + key)
            else:
                numeric[key] = int(value)
    if "TIMESTAMP_END" not in numeric:
        errors.append("execution did not complete")
    exit_code = numeric.get("ANSIBLE_EXIT_STATUS", 0)
    failed = bool(exit_code or counts["failed"] or counts["unreachable"])
    status = "ERR" if errors else "FAIL" if failed else "SKIP" if skipped else "OK"
    return {
        "schema_version": 1, "run_id": run_id, "status": status, "counts": counts,
        "exit_code": exit_code, "failure_tasks": failure_tasks, "started_at": numeric.get("TIMESTAMP_START"),
        "capability_tasks": capability_tasks,
        "ended_at": numeric.get("TIMESTAMP_END"), "duration_seconds": numeric.get("DURATION_SECONDS"),
        "reason": "; ".join(errors) if errors else "Ansible execution failed" if failed else
        "Declared lab substrate unavailable" if skipped else "",
    }


def bounded_lines(stream):
    while True:
        line = stream.readline(65536)
        if not line:
            return
        tail = line
        while tail and not tail.endswith("\n"):
            tail = stream.readline(65536)
        yield line


def summarize(log, module, run_id, require_execution=False):
    started = time.monotonic()
    with open(log, encoding="utf-8", errors="replace") as stream:
        result = parse_log(bounded_lines(stream), run_id)
    result["module"] = module
    execution_path = Path(str(log) + ".execution.json")
    if execution_path.exists():
        execution = json.loads(execution_path.read_text())
        if execution.get("run_id") != run_id or execution.get("module") != module:
            raise ValueError("execution metadata belongs to another run or module")
        if execution["exit_code"] != result["exit_code"]:
            result.update(status="ERR", reason="exit status disagrees with execution metadata")
        result["execution"] = execution
    elif require_execution:
        result.update(status="ERR", reason="missing execution metadata")
    phases_path = Path(str(log) + ".phases.json")
    result["phase_seconds"] = {"prerequisites": None, "execution": None, "cleanup": None}
    if phases_path.exists():
        phases = json.loads(phases_path.read_text())
        if phases.get("run_id") != run_id or phases.get("module") != module:
            raise ValueError("phase timings belong to another run")
        result["phase_seconds"].update(phases["phase_seconds"])
        result["phase_scope"] = phases.get("scope")
        result["phases_completed"] = phases.get("completed", False)
        if phases.get("module_skipped") and result["status"] == "OK":
            result.update(status="SKIP", reason="Declared lab substrate unavailable")
    if execution_path.exists():
        guard_seconds = execution.get("prerequisite_guard_seconds", 0)
        result["prerequisite_guard_seconds"] = guard_seconds
        prerequisites_seconds = result["phase_seconds"]["prerequisites"]
        if prerequisites_seconds is not None:
            result["phase_seconds"]["prerequisites"] = round(prerequisites_seconds + guard_seconds, 6)
        result["process_seconds"] = execution["ended_at"] - execution["started_at"]
    result["phase_seconds"]["parsing"] = round(time.monotonic() - started, 6)
    atomic_json(str(log) + ".summary.json", result)
    return result


def compact_recap(result):
    if result["status"] == "ERR":
        raise ValueError(result["reason"])
    counts = result["counts"]
    lines = ["[RUN_MARKER: " + result["run_id"] + "]", "PLAY RECAP"]
    failed = counts["failed"] + counts["unreachable"]
    lines.append(f"result : ok={counts['ok']} failed={failed} skipped={counts['skipped']}")
    lines.append(f"[ANSIBLE_EXIT_STATUS: {result['exit_code']}]")
    if result["duration_seconds"] is not None:
        lines.append(f"[DURATION_SECONDS: {result['duration_seconds']}]")
    if result["status"] == "SKIP":
        lines.append("NDP_MODULE_SKIPPED: declared lab substrate unavailable")
    for task in result.get("capability_tasks", []):
        lines.extend([f"TASK [{task}]", "fatal: [result]: N9K-C9300v virtual peer-link unsupported"])
    return "\n".join(lines)


def record_archive(log, module, run_id, seconds, status):
    summary_path = Path(str(log) + ".summary.json")
    result = json.loads(summary_path.read_text()) if summary_path.exists() else {
        "schema_version": 1, "module": module, "run_id": run_id, "status": "ERR",
        "reason": "summary unavailable; see original log", "phase_seconds": {},
    }
    if result.get("module") != module or result.get("run_id") != run_id:
        raise ValueError("refusing to archive another run's summary")
    result["phase_seconds"]["archiving"] = seconds
    result["archive_status"] = status
    result["archive_scope"] = "log copy, upload, fingerprint and workspace copy removal; excludes metadata upload"
    atomic_json(summary_path, result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("record", "summarize", "archive"))
    parser.add_argument("--log", required=True)
    parser.add_argument("--module", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--started", type=int)
    parser.add_argument("--ended", type=int)
    parser.add_argument("--exit-code", type=int)
    parser.add_argument("--prerequisite-seconds", type=int, default=0)
    parser.add_argument("--format", choices=("json", "recap"), default="json")
    parser.add_argument("--require-execution", action="store_true")
    parser.add_argument("--archive-seconds", type=float)
    parser.add_argument("--archive-status", choices=("success", "failed"), default="success")
    arguments = parser.parse_args()
    if arguments.command == "record":
        if None in (arguments.started, arguments.ended, arguments.exit_code):
            parser.error("record requires started, ended and exit-code")
        if arguments.ended < arguments.started or arguments.exit_code < 0 or arguments.prerequisite_seconds < 0:
            parser.error("invalid execution timestamps or exit status")
        atomic_json(arguments.log + ".execution.json", {
            "schema_version": 1, "module": arguments.module, "run_id": arguments.run_id,
            "started_at": arguments.started, "ended_at": arguments.ended,
            "exit_code": arguments.exit_code,
            "prerequisite_guard_seconds": arguments.prerequisite_seconds,
        })
    elif arguments.command == "archive":
        if arguments.archive_seconds is None or arguments.archive_seconds < 0:
            parser.error("archive requires a nonnegative archive-seconds")
        result = record_archive(arguments.log, arguments.module, arguments.run_id,
                                arguments.archive_seconds, arguments.archive_status)
        print("Phase seconds: " + json.dumps(result["phase_seconds"], sort_keys=True))
    else:
        result = summarize(arguments.log, arguments.module, arguments.run_id, arguments.require_execution)
        print(compact_recap(result) if arguments.format == "recap" else json.dumps(result))


if __name__ == "__main__":
    main()