#!/usr/bin/env python3
"""Durable agent-side module summaries and artifact handoff for the ND pipeline.

Only the execution branch registers/closes executions.  A separate Jenkins
branch calls ``next`` and archives the explicit, workspace-relative file list,
then records an ``ack``.  The process that mutates the fabric never waits for an
archive acknowledgement.  All shared state is atomic JSON on local agent disk;
the final ordered aggregation is the only writer of Jenkins result totals.
"""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import tempfile
import time

import nd_result_summary as invocation_parser
import nd_test_activity as case_parser


SCHEMA_VERSION = 1
MAX_JSON = 2 * 1024 * 1024
MAX_CATALOG = case_parser.MAX_CATALOG_BYTES
MAX_OUTPUT = 16 * 1024 * 1024
MAX_JOBS = 2000
MAX_COMPACT_BYTES = 8 * 1024 * 1024
MAX_COMPACT_LINES = 100000
MAX_FAILURES = 12
COUNTERS = ("ok", "changed", "failed", "unreachable", "skipped", "rescued", "ignored")
STATES = ("merged", "replaced", "overridden", "deleted", "gathered")
TOKEN = re.compile(r"^[A-Za-z0-9_.-]{1,180}$")
MARKER = re.compile(r"^\[(RUN_MARKER|TIMESTAMP_START|TIMESTAMP_END|DURATION_SECONDS|ANSIBLE_EXIT_STATUS):\s*(.*?)\]$", re.M)


def clean_error(value):
    """Never copy a raw exception/API response into public result metadata."""
    return case_parser.safe_label(str(value), 220)


def json_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def unknown_catalog(module, reason):
    target = case_parser.MODULE_ALIASES.get(module.split(".", 1)[0], module.split(".", 1)[0])
    catalog = {"target": target, "tasks": {}, "cases": {}, "errors": [clean_error(reason)],
               "untagged_actions": 0, "ignored_names": []}
    return {"schema_version": 1, "catalog_version": case_parser.CATALOG_VERSION,
            "module": module, "target": target, "source_fingerprint": "unavailable",
            "source_files": [], "catalog_sha256": json_digest(catalog), "catalog": catalog}


def token(value, name="identifier"):
    value = str(value)
    if not TOKEN.fullmatch(value) or value in {".", ".."}:
        raise ValueError("invalid " + name)
    return value


def atomic_json(path, value, limit=MAX_JSON):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    if path.is_symlink():
        raise ValueError("refusing a symlink metadata destination")
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(payload) > limit:
        raise ValueError("metadata exceeds the bounded JSON size")
    fd, temporary = tempfile.mkstemp(prefix=".nd-report-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path, missing=False, limit=MAX_JSON):
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        if missing:
            return None
        raise
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError("metadata is not a bounded regular file")
    with path.open("rb") as stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("metadata exceeds the bounded JSON size")
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("metadata must be a JSON object")
    return value


def within(root, path):
    """Reject traversal/symlinks, including a symlink in a parent directory."""
    root, path = Path(root).resolve(), Path(path)
    if not path.is_absolute():
        path = root / path
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise ValueError("execution path is outside the reporting root")
    if ".." in relative.parts:
        raise ValueError("execution path contains traversal")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("execution path contains a symlink")
    if not path.resolve().is_relative_to(root):
        raise ValueError("execution path escapes the reporting root")
    return path


def configuration(root):
    root = Path(root).absolute()
    if root.is_symlink():
        raise ValueError("reporting root is a symlink")
    value = read_json(root / "run.json", limit=65536)
    if value.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported reporting run schema")
    workspace = Path(value["workspace"]).resolve()
    if not root.resolve().is_relative_to(workspace):
        raise ValueError("reporting root is outside the workspace")
    return root, value


@contextmanager
def lock(root, name):
    path = within(root, Path(root) / ("." + name + ".lock"))
    with path.open("a") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


@contextmanager
def deadline(seconds):
    seconds = max(1, int(seconds))
    previous = signal.getsignal(signal.SIGALRM)

    def expired(signum, frame):
        raise TimeoutError("module summary processing deadline exceeded")

    signal.signal(signal.SIGALRM, expired)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def regular(path):
    info = Path(path).lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("execution evidence is not a regular file")
    return info


def file_stamp(path):
    info = regular(path)
    return {"bytes": info.st_size, "mtime_ns": info.st_mtime_ns}


def initialize(args):
    workspace = Path(args.workspace).resolve()
    root = Path(args.root).absolute()
    if root.is_symlink() or not root.resolve().is_relative_to(workspace):
        raise ValueError("reporting root must be a real directory inside the workspace")
    root.mkdir(parents=True, exist_ok=True, mode=0o755)
    os.chmod(root, 0o755)
    wanted = {"schema_version": SCHEMA_VERSION, "build": str(args.build),
              "run_id": str(args.run_id), "workspace": str(workspace),
              "min_free_bytes": args.min_free_bytes}
    tools = root / "tools"
    wanted["tool_sha256"] = {}
    for name in ("nd_reporting_pipeline.py", "nd_report.py", "nd_result_summary.py", "nd_test_activity.py"):
        tool = tools / name
        if tool.exists():
            if tool.is_symlink() or regular(tool).st_size > 2 * 1024 * 1024:
                raise ValueError("reporting tool is unsafe or oversized")
            wanted["tool_sha256"][name] = hashlib.sha256(tool.read_bytes()).hexdigest()
    with lock(root, "init"):
        old = read_json(root / "run.json", missing=True)
        if old is not None and any(old.get(key) != wanted[key] for key in ("schema_version", "build", "run_id", "workspace")):
            raise ValueError("reporting root belongs to another build attempt")
        if old is not None and old.get("tool_sha256", {}) != wanted["tool_sha256"]:
            raise ValueError("frozen reporting tools changed within the build attempt")
        if old is None:
            if (root / "producer.json").exists() or any((root / name).exists() and any((root / name).iterdir())
                    for name in ("jobs", "rounds", "closed", "results", "archives")):
                raise ValueError("reporting root contains orphaned evidence without run identity")
            wanted["created_at"] = time.time()
            atomic_json(root / "run.json", wanted)
        for name in ("jobs", "rounds", "catalogs", "catalog-cache", "executions", "started", "closed", "results", "archives", "receipts"):
            directory = within(root, root / name)
            directory.mkdir(exist_ok=True, mode=0o755)
            os.chmod(directory, 0o755)
    return {"root": str(root), "build": str(args.build), "initialized": True}


def jobs(root):
    run = read_json(root / "run.json", limit=65536)
    paths = sorted((root / "jobs").glob("*.json"))
    if len(paths) > MAX_JOBS:
        raise ValueError("selected execution count exceeds safe limits")
    result = []
    ids, sequences = set(), set()
    for path in paths:
        job = read_json(within(root, path))
        identity = token(job.get("id", ""), "execution ID")
        sequence = job.get("sequence")
        if (path.stem != identity or identity in ids or not isinstance(sequence, int) or isinstance(sequence, bool)
                or sequence < 1 or sequence in sequences or job.get("schema_version") != SCHEMA_VERSION
                or job.get("build") != run["build"]):
            raise ValueError("duplicate or malformed selected execution identity")
        token(job.get("module", ""), "module")
        token(job.get("version_id", ""), "version ID")
        within(root, job["log"])
        within(root, job["catalog"])
        ids.add(identity)
        sequences.add(sequence)
        result.append(job)
    return sorted(result, key=lambda item: item["sequence"])


def check_space(root, config):
    available = shutil.disk_usage(root).free
    if available < config.get("min_free_bytes", 512 * 1024 * 1024):
        raise ValueError("agent free disk is below the reporting safety reserve")
    return {"free_bytes": available}


def register(root, config, args):
    plan = read_json(args.plan)
    if str(plan.get("build")) != config["build"]:
        raise ValueError("round plan belongs to another build")
    version_id = token(plan.get("version_id", ""), "version ID")
    fabric_name = token(plan.get("fabric_name", ""), "fabric name")
    run_id = str(plan.get("run_id", ""))
    if not run_id or len(run_id) > 512:
        raise ValueError("round run marker is missing or oversized")
    targets = plan.get("targets")
    if not isinstance(targets, list) or len(targets) > MAX_JOBS:
        raise ValueError("round target list is malformed or oversized")
    seen = set()
    normalized = []
    for item in targets:
        module = token(item.get("module", ""), "module")
        test_type = item.get("test_type", "integration")
        if test_type not in {"integration", "smoke"} or (module, test_type) in seen:
            raise ValueError("round has a duplicate or invalid target")
        seen.add((module, test_type))
        normalized.append({"module": module, "test_type": test_type,
                           "scope": str(item.get("scope", "Unknown"))[:100],
                           "fabric": str(item.get("fabric", fabric_name))[:300]})
    digest = hashlib.sha256(json.dumps({"plan": plan, "targets": normalized}, sort_keys=True).encode()).hexdigest()
    round_key = version_id + "-" + hashlib.sha256(run_id.encode()).hexdigest()[:16]
    round_path = root / "rounds" / (round_key + ".json")
    log_dir = root / "executions" / round_key
    with lock(root, "registration"):
        old = read_json(round_path, missing=True, limit=MAX_OUTPUT)
        if old is not None:
            if old.get("plan_digest") != digest:
                raise ValueError("registered round plan changed for the same run marker")
            return old
        check_space(root, config)
        selected = jobs(root)
        partial = {}
        for job in selected:
            if job["version_id"] == version_id and job["run_id"] == run_id:
                key = job["module"], job["test_type"]
                if key in partial or job.get("plan_digest") != digest:
                    raise ValueError("partial round registration conflicts with the selected plan")
                partial[key] = job
        if set(partial) - seen:
            raise ValueError("partial round registration contains an unexpected selected target")
        if len(selected) + len(normalized) - len(partial) > MAX_JOBS:
            raise ValueError("selected execution count exceeds safe limits")
        log_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
        sequence = max([job["sequence"] for job in selected] or [0])
        executions = []
        collection = Path(args.collection_root).resolve()
        for item in normalized:
            previous = partial.get((item["module"], item["test_type"]))
            if previous is not None:
                executions.append(previous)
                continue
            sequence += 1
            execution_id = "%04d-%s-%s-%s" % (sequence, version_id[:30], item["module"][:80], round_key.rsplit("-", 1)[-1])
            basename = "test_output_%s_%s_%s.txt" % (fabric_name, version_id, item["module"])
            if len(os.fsencode(basename)) > 240:
                raise ValueError("selected execution log filename exceeds safe limits")
            # Mutable cache files are never referenced by a registered execution.
            cached = root / "catalogs" / (item["module"] + ".cache.json")
            catalog_error = ""
            if item["test_type"] == "integration":
                try:
                    frozen = case_parser.freeze_catalog(str(collection), item["module"], str(cached),
                                                        cache_dir=str(root / "catalog-cache"))
                except Exception as error:
                    catalog_error = clean_error("catalog preparation failed: " + type(error).__name__)
                    frozen = unknown_catalog(item["module"], catalog_error)
            else:
                frozen = unknown_catalog(item["module"], "smoke playbooks have no module integration case catalog")
            catalog_digest = json_digest(frozen)
            catalog_path = root / "catalogs" / (item["module"] + "." + catalog_digest + ".json")
            if not catalog_path.exists():
                atomic_json(catalog_path, frozen, limit=MAX_CATALOG)
            job = dict(item, schema_version=SCHEMA_VERSION, id=execution_id, sequence=sequence,
                       plan_digest=digest,
                       build=config["build"], run_id=run_id, version_id=version_id,
                       nd=str(plan.get("version", "")), round_label=str(plan.get("round_label", "")),
                       fabric_name=fabric_name, log=str(log_dir / basename), catalog=str(catalog_path),
                       collection_root=str(collection), catalog_sha256=frozen["catalog_sha256"],
                       catalog_snapshot_sha256=catalog_digest, source_fingerprint=frozen.get("source_fingerprint"),
                       catalog_error=catalog_error, tool_sha256=config.get("tool_sha256", {}),
                       registered_at=time.time())
            atomic_json(root / "jobs" / (execution_id + ".json"), job)
            executions.append(job)
        result = {"schema_version": SCHEMA_VERSION, "plan_digest": digest, "round_key": round_key,
                  "log_dir": str(log_dir), "executions": executions}
        atomic_json(round_path, result, limit=MAX_OUTPUT)
        return result


def find_job(root, version_id, module, run_id):
    matching = [job for job in jobs(root) if job["version_id"] == version_id and job["module"] == module and job["run_id"] == run_id]
    if len(matching) != 1:
        raise ValueError("execution is not uniquely selected in this build")
    return matching[0]


def identity(value, job):
    if value.get("module") != job["module"] or value.get("run_id") != job["run_id"]:
        raise ValueError("execution evidence belongs to another module or run")


def validate_catalog(root, job):
    value = read_json(within(root, job["catalog"]), limit=MAX_CATALOG)
    if (json_digest(value) != job["catalog_snapshot_sha256"] or
            value.get("catalog_sha256") != job["catalog_sha256"] or value.get("module") != job["module"]):
        raise ValueError("frozen catalog changed after execution registration")
    return value


def begin(root, config, job):
    check_space(root, config)
    if (root / "closed" / (job["id"] + ".json")).exists():
        raise ValueError("refusing to overwrite a closed selected execution")
    path = root / "started" / (job["id"] + ".json")
    old = read_json(path, missing=True)
    if old is not None or Path(job["log"]).exists():
        raise ValueError("selected execution already started; a retry requires a new attempt marker")
    atomic_json(path, {"id": job["id"], "started_at": time.time()})
    return {"id": job["id"], "log": job["log"], "catalog": job["catalog"]}


def boundary_evidence(job, closed):
    """Read bounded head/tail, never the complete raw log on the normal path."""
    log = Path(job["log"])
    before = file_stamp(log)
    if closed.get("log_stamp") != before:
        raise ValueError("raw log changed after its completion marker")
    with log.open("rb") as stream:
        head = stream.read(65536).decode("utf-8", errors="replace")
        stream.seek(max(0, before["bytes"] - 131072))
        tail = stream.read(131072).decode("utf-8", errors="replace")
    first = dict(MARKER.findall(head))
    last = dict(MARKER.findall(tail))
    if first.get("RUN_MARKER") != job["run_id"]:
        raise ValueError("raw log lacks the selected current-run marker")
    marker_kind = "PLAYBOOK" if job["test_type"] == "smoke" else "MODULE"
    if "[%s: %s]" % (marker_kind, job["module"]) not in head:
        raise ValueError("raw log lacks the selected module marker")
    if "[%s: %s] Execution completed." % (marker_kind, job["module"]) not in tail:
        raise ValueError("raw log has no final module completion marker")
    for name in ("TIMESTAMP_END", "DURATION_SECONDS", "ANSIBLE_EXIT_STATUS"):
        if not last.get(name, "").isdigit():
            raise ValueError("raw log lacks a valid final " + name)
    if int(last["ANSIBLE_EXIT_STATUS"]) != closed["exit_code"]:
        raise ValueError("closed execution and raw log exit statuses disagree")
    execution = read_json(str(log) + ".execution.json", limit=65536)
    identity(execution, job)
    if (not isinstance(execution.get("exit_code"), int) or isinstance(execution.get("exit_code"), bool)
            or execution["exit_code"] != closed["exit_code"]):
        raise ValueError("wrapper execution and closed exit statuses disagree")
    if any(not isinstance(execution.get(name), (int, float)) or isinstance(execution.get(name), bool)
           or not math.isfinite(execution.get(name))
           for name in ("started_at", "ended_at")) or execution["ended_at"] < execution["started_at"]:
        raise ValueError("wrapper execution timestamps are invalid")
    if file_stamp(log) != before:
        raise ValueError("raw log changed while validating completion")
    return execution, {key: int(value) for key, value in last.items() if value.isdigit()}


def phase_timings(job, event_stats=None):
    phases = {"prerequisites": None, "execution": None, "cleanup": None}
    path = str(job["log"]) + ".phases.json"
    value = read_json(path, missing=True, limit=65536)
    if value is not None:
        identity(value, job)
        phases.update(value.get("phase_seconds", {}))
    elif event_stats:
        phases.update(event_stats.get("phase_seconds", {}))
    for name, seconds in phases.items():
        if seconds is not None and (not isinstance(seconds, (int, float)) or isinstance(seconds, bool)
                                    or not math.isfinite(seconds) or seconds < 0):
            raise ValueError("phase timing is invalid")
    return phases


def attach_execution(summary, job, execution, markers, event_stats=None):
    summary.update(schema_version=SCHEMA_VERSION, module=job["module"], run_id=job["run_id"], execution=execution,
                   started_at=markers.get("TIMESTAMP_START", execution["started_at"]),
                   ended_at=markers["TIMESTAMP_END"], duration_seconds=markers["DURATION_SECONDS"],
                   exit_code=execution["exit_code"], phase_seconds=phase_timings(job, event_stats),
                   process_seconds=execution["ended_at"] - execution["started_at"])
    summary["count_unit"] = "Ansible task recap diagnostics; excluded from authored module-case totals"
    guard = execution.get("prerequisite_guard_seconds", 0)
    if not isinstance(guard, (int, float)) or isinstance(guard, bool) or not math.isfinite(guard) or guard < 0:
        raise ValueError("prerequisite guard timing is invalid")
    summary["prerequisite_guard_seconds"] = guard
    if summary["phase_seconds"].get("prerequisites") is not None:
        summary["phase_seconds"]["prerequisites"] += guard
    return summary


def structured_summary(job, closed, catalog_snapshot=None):
    execution, markers = boundary_evidence(job, closed)
    activity = case_parser.summarize_events(job["log"], job["module"], job["run_id"], job["build"],
        job["scope"], job["collection_root"], job["test_type"], catalog_path=job["catalog"],
        catalog_snapshot=catalog_snapshot)
    if not activity.get("validated"):
        raise ValueError("structured module activity was not validated")
    stats = read_json(job["log"] + ".event-summary.json")
    identity(stats, job)
    if not stats.get("completed"):
        raise ValueError("structured callback did not finish")
    counts = stats.get("counts", {})
    if any(not isinstance(counts.get(key), int) or isinstance(counts.get(key), bool) or counts[key] < 0 for key in COUNTERS):
        raise ValueError("structured task recap counters are invalid")
    failed = bool(execution["exit_code"] or counts["failed"] or counts["unreachable"])
    summary = {"status": "FAIL" if failed else "SKIP" if stats.get("module_skipped") else "OK", "counts": counts,
               "failure_tasks": [clean_error(value) for value in stats.get("failure_tasks", [])[:20]],
               "capability_tasks": [clean_error(value) for value in stats.get("capability_tasks", [])[:20]],
               "reason": "Ansible execution failed" if failed else "Declared lab substrate unavailable" if stats.get("module_skipped") else ""}
    return attach_execution(summary, job, execution, markers, stats), activity


def fallback_summary(job, closed):
    execution, markers = boundary_evidence(job, closed)
    compact, size = [], 0
    truncated = False

    def remember(line):
        nonlocal size, truncated
        encoded_size = len(line.encode("utf-8"))
        if size + encoded_size <= MAX_COMPACT_BYTES and len(compact) < MAX_COMPACT_LINES:
            compact.append(line)
            size += encoded_size
        else:
            truncated = True

    def lines():
        nonlocal size, truncated
        with Path(job["log"]).open("r", encoding="utf-8", errors="replace") as stream:
            for value in invocation_parser.bounded_lines(stream):
                # Retain only structural events for the same authored-case
                # reducer.  Full API/exception bodies never enter this buffer.
                line = invocation_parser.ANSI.sub("", value).rstrip("\r\n")
                stripped = line.strip()
                keep = stripped.startswith(("TASK [", "task path:", "PLAY RECAP", "[MODULE:", "[PLAYBOOK:",
                    "[RUN_MARKER:", "[ANSIBLE_EXIT_STATUS:", "[EXIT_CODE:", "ok: [", "changed: [", "skipping: [",
                    "fatal: [", "failed: [", "included: [", "...ignoring")) or bool(invocation_parser.ROW.match(stripped))
                if "NDP_MODULE_SKIPPED" in stripped:
                    line = "NDP_MODULE_SKIPPED: declared lab substrate unavailable"
                    keep = True
                if keep:
                    if stripped.startswith(("ok: [", "changed: [", "skipping: [", "fatal: [", "failed: [", "included: [")):
                        # Outcome recognition needs only the prefix, not payload.
                        line = stripped.split("]", 1)[0][:300] + "]"
                    remember(line)
                # Preserve only fixed reason labels for the case reducer; no
                # response body enters the recovery evidence buffer.
                for pattern, reason in case_parser.FAILURE_REASONS:
                    if pattern.search(stripped):
                        remember(reason)
                # The invocation parser still sees every bounded raw line for
                # marker disagreement and failure classification.
                yield value

    summary = invocation_parser.parse_log(lines(), job["run_id"])
    if summary.get("status") == "ERR":
        raise ValueError("raw-log recovery did not find complete execution evidence")
    if summary.get("exit_code") != execution["exit_code"]:
        raise ValueError("raw-log recovery and wrapper exits disagree")
    activity = case_parser.summarize_lines(job["log"], job["module"], job["run_id"], job["build"], job["scope"],
        job["collection_root"], job["test_type"], lines=iter(compact), catalog_path=job["catalog"])
    if truncated:
        activity.update(coverage="PARTIAL", counts={key: None for key in STATES},
                        testcase_totals={key: None for key in ("started", "passed", "failed", "skipped", "incomplete")},
                        other_cases=None)
        activity.setdefault("notes", []).append("bounded recovery evidence limit reached; case totals remain unknown")
    if not activity.get("validated"):
        raise ValueError("raw-log recovery did not validate authored module activity")
    summary = attach_execution(summary, job, execution, markers)
    summary["recovery_evidence_truncated"] = truncated
    return summary, activity


def result_error(job, message, closed=None, not_run=False):
    status = "NOT_RUN" if not_run else "FAIL" if closed and closed.get("exit_code", 0) else "UNKNOWN"
    return {"schema_version": SCHEMA_VERSION, "id": job["id"], "module": job["module"], "run_id": job["run_id"],
            "summary_source": "unavailable", "reporting_status": "ERROR", "reporting_error": clean_error(message),
            "reporting_metrics": {"log_bytes": (closed or {}).get("log_stamp", {}).get("bytes"),
                                  "closed_at": (closed or {}).get("closed_at"), "summary_ready_at": time.time()},
            "invocation": {"status": "NOT_RUN" if not_run else "ERR", "exit_code": closed.get("exit_code") if closed else None,
                           "counts": {}, "phase_seconds": {}, "capability_tasks": []},
            "activity": {"schema_version": 1, "module": job["module"], "run_id": job["run_id"],
                         "build": job["build"], "fabric": job["scope"], "validated": False, "result": status,
                         "coverage": "UNKNOWN", "counts": {state: None for state in STATES}, "testcase_totals": {},
                         "other_cases": None, "base": "Not reached" if not_run else "Not observed",
                         "cleanup": "Not reached" if not_run else "Not observed", "failure": [clean_error(message)],
                         "notes": ["reporting error; no module cases inferred from task recap"]}}


def persist_result(root, job, summary, activity, source, seconds, closed):
    if not isinstance(activity.get("testcase_totals"), dict):
        raise ValueError("module case totals are malformed")
    summary["phase_seconds"]["parsing"] = round(seconds, 6)
    event_bytes = None
    event_path = Path(job["log"] + ".events.jsonl")
    if event_path.exists():
        event_bytes = regular(event_path).st_size
    evidence_stamps = {}
    for suffix in (".execution.json", ".phases.json", ".events.jsonl", ".event-summary.json"):
        path = Path(job["log"] + suffix)
        if path.exists():
            evidence_stamps[suffix] = file_stamp(path)
    result = {"schema_version": SCHEMA_VERSION, "id": job["id"], "module": job["module"], "run_id": job["run_id"],
              "closure": closed, "evidence_stamps": evidence_stamps,
              "summary_source": source, "reporting_status": "ERROR" if job.get("catalog_error") else "SUCCESS",
              "reporting_error": job.get("catalog_error", ""),
              "reporting_metrics": {"log_bytes": closed.get("log_stamp", {}).get("bytes"),
                                    "event_bytes": event_bytes, "event_count": activity.get("event_count"),
                                    "closed_at": closed["closed_at"], "summary_ready_at": time.time(),
                                    "summary_seconds": round(seconds, 6)},
              "invocation": summary, "activity": activity}
    atomic_json(job["log"] + ".summary.json", summary)
    atomic_json(job["log"] + ".activity.json", activity)
    atomic_json(root / "results" / (job["id"] + ".json"), result)
    return result


def close_execution(root, job, args):
    path = root / "closed" / (job["id"] + ".json")
    if path.exists():
        old = read_json(path)
        if old.get("exit_code") != args.exit_code:
            raise ValueError("refusing to change a closed execution exit status")
        return {"id": job["id"], "closed": True, "already_closed": True}
    log = within(root, job["log"])
    closed = {"schema_version": SCHEMA_VERSION, "id": job["id"], "module": job["module"],
              "run_id": job["run_id"], "exit_code": args.exit_code, "closed_at": time.time(),
              "duration_seconds": args.duration_seconds, "log_stamp": file_stamp(log), "complete": True}
    # Fast structured finalization is bounded.  Any raw-log recovery is deferred
    # to the artifact branch so the next module can start immediately.
    start = time.monotonic()
    try:
        with deadline(args.parse_timeout):
            catalog_snapshot = validate_catalog(root, job)
            summary, activity = structured_summary(job, closed, catalog_snapshot=catalog_snapshot)
            persist_result(root, job, summary, activity, "structured_events", time.monotonic() - start, closed)
    except Exception as error:
        closed["structured_error"] = clean_error(type(error).__name__ + ": " + str(error))
    atomic_json(path, closed)
    return {"id": job["id"], "closed": True, "summary_ready": (root / "results" / (job["id"] + ".json")).exists()}


def finish(root, config, status, home_recovery_status="unverified"):
    if home_recovery_status not in {"confirmed", "failed", "not_required", "unverified"}:
        raise ValueError("invalid home recovery status")
    path = root / "producer.json"
    with lock(root, "finish"):
        value = read_json(path, missing=True)
        if value is None:
            value = {"schema_version": SCHEMA_VERSION, "run_id": config["run_id"], "status": status,
                     "status_scope": "execution_branch", "execution_status": status,
                     "home_recovery_status": home_recovery_status, "finished_at": time.time()}
            atomic_json(path, value)
        return value


def settle_unclosed(root, selected):
    for job in selected:
        path = root / "closed" / (job["id"] + ".json")
        if path.exists():
            continue
        prior = read_json(root / "results" / (job["id"] + ".json"), missing=True)
        if prior and prior.get("closure", {}).get("complete"):
            # Recover an interrupted atomic-publication sequence.  No new test
            # outcome is inferred: accept the already validated summary only
            # while all of its original closed evidence remains unchanged.
            try:
                identity(prior, job)
                boundary_evidence(job, prior["closure"])
                validate_catalog(root, job)
                for suffix, stamp in prior.get("evidence_stamps", {}).items():
                    if suffix not in {".execution.json", ".phases.json", ".events.jsonl", ".event-summary.json"}:
                        raise ValueError("unexpected evidence stamp")
                    if file_stamp(Path(job["log"] + suffix)) != stamp:
                        raise ValueError("summary evidence changed before closure recovery")
                atomic_json(path, prior["closure"])
                continue
            except Exception:
                prior = result_error(job, "closed evidence changed before publication recovery", prior["closure"])
                atomic_json(job["log"] + ".summary.json", prior["invocation"])
                atomic_json(job["log"] + ".activity.json", prior["activity"])
                atomic_json(root / "results" / (job["id"] + ".json"), prior)
        if prior and prior.get("activity", {}).get("result") == "NOT_RUN":
            continue
        log = within(root, job["log"])
        started = (root / "started" / (job["id"] + ".json")).exists()
        if log.exists() or started:
            closed = {"schema_version": SCHEMA_VERSION, "id": job["id"], "module": job["module"],
                      "run_id": job["run_id"], "exit_code": None, "closed_at": time.time(),
                      "log_stamp": file_stamp(log) if log.exists() else {}, "complete": False,
                      "reason": "execution stopped before its final close boundary"}
            atomic_json(path, closed)
        else:
            result = result_error(job, "selected execution was not reached; no current-run output", not_run=True)
            atomic_json(root / "results" / (job["id"] + ".json"), result)


def ensure_summary(root, job, closed, timeout):
    path = root / "results" / (job["id"] + ".json")
    result = read_json(path, missing=True)
    if result is not None:
        identity(result, job)
        return result
    start = time.monotonic()
    try:
        if not closed.get("complete"):
            raise ValueError(closed.get("reason", "execution closure was incomplete"))
        with deadline(timeout):
            validate_catalog(root, job)
            summary, activity = fallback_summary(job, closed)
            result = persist_result(root, job, summary, activity, "raw_log_recovery", time.monotonic() - start, closed)
            result["structured_error"] = closed.get("structured_error", "structured evidence unavailable")
            atomic_json(path, result)
            return result
    except Exception as error:
        result = result_error(job, type(error).__name__ + ": " + str(error), closed)
        result["invocation"]["phase_seconds"]["parsing"] = round(time.monotonic() - start, 6)
        result["reporting_metrics"]["summary_seconds"] = result["invocation"]["phase_seconds"]["parsing"]
        atomic_json(job["log"] + ".summary.json", result["invocation"])
        atomic_json(job["log"] + ".activity.json", result["activity"])
        atomic_json(path, result)
        return result


def public_log_name(job):
    """Readable flat artifact name; private execution paths remain unchanged."""
    round_name = token(str(job.get("round_label") or "UNSPECIFIED").upper(), "round")
    version = token(job["version_id"], "version ID")
    version = version.removesuffix("_" + round_name) or version
    name = "test_output_%s_%s_%s_%s.txt" % (
        token(job["fabric_name"], "fabric"), version, round_name, token(job["module"], "module"))
    if len(os.fsencode(name)) > 240:
        raise ValueError("readable log filename exceeds safe limits")
    return name


@contextmanager
def readable_file(destination, binary=False):
    """Publish one complete human report atomically; never follow a symlink."""
    destination = Path(destination)
    if destination.is_symlink() or (destination.exists() and not destination.is_file()):
        raise ValueError("unsafe readable artifact destination")
    descriptor, temporary = tempfile.mkstemp(dir=destination.parent, prefix="." + destination.name + ".")
    try:
        with os.fdopen(descriptor, "wb" if binary else "w", **({} if binary else {"encoding": "utf-8"})) as stream:
            yield stream
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)


def readable_header(job):
    return ("MODULE: %s | ND: %s | ROUND: %s\nFABRIC: %s | SCOPE: %s | BUILD: %s\n" % (
        job["module"], job.get("nd", ""), job.get("round_label") or "UNSPECIFIED",
        case_parser.safe_label(job.get("fabric", job["fabric_name"]), 300),
        case_parser.safe_label(job.get("scope", "Unknown"), 100), job["build"]))


def skip_detail(value, condition=False):
    if not isinstance(value, str) or not value.strip():
        return ""
    value = case_parser.normal_name(value[:1024])
    if re.search(r"password|passwd|pwd|token|secret|bearer|authorization|credential|community|username|private.?key|api.?key|auth[_-]?(?:pass|key)|priv[_-]?(?:pass|key)", value, re.I):
        return "Credential-related skip evidence withheld"
    if condition or "'" in value or '"' in value:
        labels = {"all", "merged", "replaced", "overridden", "deleted", "gathered", "vxlanibgp", "vxlanebgp", "externalconnectivity", "nxos", "true", "false"}
        value = re.sub(r'''(['"])((?:\\.|(?!\1).)*)(?:\1|$)''',
            lambda match: match[0] if match[2].lower() in labels else "'[value]'", value)
    return case_parser.safe_label(value, 240)


def owned_skip_task(event, catalog, positions):
    """Use pinned authored names/paths/roles, never pipeline header totals."""
    name = case_parser.normal_name(event.get("name"))
    role, separator, tail = name.partition(" : ")
    role = str(event.get("role") or (role if separator else ""))
    name = tail if separator else name
    path = str(event.get("path") or "").replace("\\", "/")
    path = "/" + path.lstrip("/") if path else ""
    fragment = "/tests/integration/targets/" + catalog["target"] + "/"
    candidates = catalog["tasks"].get(name, [])
    if not path and role and role not in {catalog["target"], "cisco.nd." + catalog["target"]}:
        return None
    if path:
        if fragment not in path:
            return None
        relative = path.split(fragment, 1)[1]
        candidates = [record for record in candidates if record["path"] == relative]
        # Dynamic display names can still be resolved through a pinned source position.
        if not candidates and isinstance(event.get("line"), int):
            candidates = positions.get((relative, event["line"]), [])
    elif not role:
        return None
    if not candidates:
        return None
    phase = "Base" if all(record.get("base") for record in candidates) else (
        "Cleanup" if all(record.get("cleanup") for record in candidates) else "Authored test task")
    label = candidates[0]["name"] if len({record["name"] for record in candidates}) == 1 else name
    return phase, case_parser.safe_label(label, 512)


def skipped_tasks(job, result, catalog):
    """Stream full skip evidence; compact case-label limits do not truncate tasks."""
    positions = {}
    for records in catalog["tasks"].values():
        for record in records:
            positions.setdefault((record["path"], record.get("line")), []).append(record)
    if result.get("summary_source") == "structured_events":
        with Path(job["log"] + ".events.jsonl").open("rb") as source:
            for _ in range(case_parser.MAX_EVENT_RECORDS + 1):
                raw = source.readline(case_parser.MAX_EVENT_LINE + 1)
                if not raw:
                    return
                if len(raw) > case_parser.MAX_EVENT_LINE or not raw.endswith(b"\n"):
                    raise ValueError("skip journal contains an oversized or partial record")
                event = json.loads(raw)
                identity(event, job)
                if event.get("kind") == "outcome" and event.get("outcome") == "skipped":
                    owned = owned_skip_task(event, catalog, positions)
                    if owned:
                        yield owned, event
            raise ValueError("skip journal exceeds the event bound")
    elif result.get("summary_source") == "raw_log_recovery":
        current = None
        with Path(job["log"]).open("r", encoding="utf-8", errors="replace") as source:
            for raw in invocation_parser.bounded_lines(source):
                line = invocation_parser.ANSI.sub("", raw).rstrip("\r\n")
                match = case_parser.TASK_HEADER.match(line)
                if match:
                    current = {"name": match[1], "path": ""}
                match = case_parser.SOURCE_PATH.match(line)
                if current and match:
                    current.update(path=match[1], line=int(match[2]))
                if current and line.lstrip().startswith("skipping: ["):
                    owned = owned_skip_task(current, catalog, positions)
                    if owned:
                        event = dict(current, host=line.split("[", 1)[1].split("]", 1)[0])
                        try:
                            payload = json.loads(line.partition("=>")[2].strip())
                        except ValueError:
                            payload = {}
                        if isinstance(payload, dict):
                            event.update({key: payload[key] for key in ("skip_reason", "false_condition", "_ansible_no_log") if key in payload})
                        yield owned, event


def module_skip_report(root, job, result):
    """Internal text projection; case outcomes and task observations stay distinct."""
    destination = within(root, job["log"] + ".skips.txt")
    frozen = validate_catalog(root, job)
    catalog = frozen["catalog"]
    activity = result["activity"]
    cases = activity.get("case_results", [])
    not_run = activity.get("result") == "NOT_RUN"
    with readable_file(destination) as output:
        output.write(readable_header(job))
        output.write("RESULT: %s | COVERAGE: %s | BASE: %s | CLEANUP: %s\n" % (
            activity.get("result", "UNKNOWN"), "N/A" if not_run else activity.get("coverage", "UNKNOWN"),
            activity.get("base", "Not observed"), activity.get("cleanup", "Not observed")))
        if not_run:
            reason = " ".join(str(value) for value in activity.get("failure", [])).lower()
            blocked = "preflight blocked" if "preflight" in reason or "pre-flight" in reason else "earlier execution stopped"
            output.write("Not executed—" + blocked + ".\n")
        totals = activity.get("testcase_totals", {})
        if not_run:
            output.write("Authored case totals: N/A (no module execution)\n")
        else:
            output.write("Authored case totals: " + "; ".join("%s=%s" % (key,
                totals[key] if isinstance(totals.get(key), int) and not isinstance(totals[key], bool) else "unknown")
                for key in ("started", "passed", "failed", "skipped", "incomplete")) + "\n")
        if not catalog["cases"]:
            output.write("Authored case inventory unavailable: case-level skips and unreached cases cannot be enumerated; task skips below are separate observations.\n")
        if activity.get("failure"):
            output.write("Failure evidence: " + "; ".join(case_parser.safe_label(value, 220)
                for value in activity["failure"][:4]) + "\n")
        for label, outcome in (("FAILED CASES", "failed"), ("FULLY SKIPPED CASES", "skipped"), ("INCOMPLETE CASES", "incomplete")):
            selected = [case for case in cases if case.get("outcome") == outcome]
            output.write("\n" + label + "\n")
            for case in selected:
                output.write("- %s [%s]%s\n" % (case_parser.safe_label(case.get("label", case.get("id", "Unknown")), 512),
                    case.get("state", "other"), ": " + skip_detail(case["reason"]) if case.get("reason") else ""))
            if not selected:
                output.write("None recorded.\n")
        output.write("\nNOT OBSERVED / NOT REACHED (not counted as skipped cases)\n")
        if activity.get("validated") is not True or activity.get("evidence_truncated"):
            output.write("Unverified: absent case labels cannot be classified from incomplete or bounded evidence.\n")
        else:
            observed = {case["id"] for case in cases}
            missing = [case for key, case in catalog["cases"].items() if key not in observed]
            for case in missing:
                output.write("- " + case_parser.safe_label(case.get("label", "Unknown"), 512) + "\n")
            if not missing:
                output.write("None recorded.\n")
        if activity.get("evidence_truncated"):
            output.write("Case labels are bounded; full case totals above are retained. Task skips below use the complete evidence stream.\n")
        output.write("\nAUTHORED TASK SKIP OBSERVATIONS (not unique case counts; pipeline tasks excluded)\n")
        count = 0
        for (phase, label), event in skipped_tasks(job, result, catalog):
            count += 1
            censored = event.get("no_log") or event.get("_ansible_no_log")
            reason = "Reason withheld (no_log)" if censored else skip_detail(event.get("skip_reason")) or "Reason not recorded"
            condition = "" if censored else skip_detail(event.get("false_condition"), condition=True)
            output.write("- %s | %s | host=%s%s | %s%s\n" % (phase, "Censored task" if censored else label,
                case_parser.safe_label(event.get("host", "unknown"), 100), " | loop item" if event.get("item") else "", reason,
                " | condition: " + condition if condition else ""))
        if not count:
            output.write("No module-owned task skips recorded.\n")
        if result.get("summary_source") != "structured_events":
            output.write("Evidence: %s; unavailable skip reasons are not reconstructed.\n" % result.get("summary_source", "unavailable"))
        output.write("\n")
    return destination


def artifact_files(root, config, job):
    log = within(root, job["log"])
    regular(log)
    closed = read_json(root / "closed" / (job["id"] + ".json"))
    if closed.get("complete") and file_stamp(log) != closed.get("log_stamp"):
        raise ValueError("raw log changed between summary generation and archive")
    result = read_json(root / "results" / (job["id"] + ".json"))
    for suffix, stamp in result.get("evidence_stamps", {}).items():
        if suffix not in {".execution.json", ".phases.json", ".events.jsonl", ".event-summary.json"}:
            raise ValueError("unexpected evidence stamp")
        if file_stamp(Path(job["log"] + suffix)) != stamp:
            raise ValueError("structured evidence changed between summary and archive")
    # Queue indexes live outside executions/.  Freeze their small evidence next
    # to the raw log so a single strictly scoped Jenkins fileset archives it.
    metadata = {
        ".job.json": job,
        ".catalog.json": validate_catalog(root, job),
        ".closed.json": closed,
        ".result.json": result,
    }
    for suffix, value in metadata.items():
        path = Path(str(log) + suffix)
        if not path.exists():
            atomic_json(path, value, limit=MAX_CATALOG if suffix == ".catalog.json" else MAX_JSON)
    module_skip_report(root, job, result)
    destination = Path(config["workspace"]) / public_log_name(job)
    with readable_file(destination, binary=True) as output, log.open("rb") as source:
        output.write((readable_header(job) + "\nFULL EXECUTION LOG (including prerequisites and cleanup)\n\n").encode("utf-8"))
        shutil.copyfileobj(source, output, length=1024 * 1024)
    return [destination.relative_to(Path(config["workspace"])).as_posix()]


def next_execution(root, config, args):
    started = time.monotonic()
    selected, job_generation, last_state, settled_generation = [], None, None, None
    delay = 0.5

    def generation(directory):
        info = directory.stat()
        return info.st_mtime_ns, info.st_ctime_ns

    while True:
        producer = read_json(root / "producer.json", missing=True)
        current_generation = generation(root / "jobs")
        if current_generation != job_generation:
            selected = jobs(root)
            job_generation = current_generation
        if producer:
            if settled_generation != job_generation:
                settle_unclosed(root, selected)
                settled_generation = job_generation
            if time.time() - producer["finished_at"] > args.drain_timeout:
                error = {"error": "reporting drain deadline exceeded", "at": time.time()}
                atomic_json(root / "reporter.error.json", error)
                return {"done": True, "reporting_error": error["error"], "producer_status": producer["status"]}
        state = (job_generation, generation(root / "closed"), generation(root / "archives"), bool(producer))
        changed = state != last_state
        if changed:
            delay = 0.5
        for job in selected if changed else ():
            receipt = read_json(root / "archives" / (job["id"] + ".json"), missing=True)
            if receipt and (receipt.get("terminal") or receipt.get("status") == "success" or receipt.get("attempts", 0) >= args.archive_attempts):
                continue
            closed = read_json(root / "closed" / (job["id"] + ".json"), missing=True)
            if closed is None:
                continue
            result = ensure_summary(root, job, closed, args.parse_timeout)
            try:
                files = artifact_files(root, config, job)
            except Exception as error:
                reason = clean_error("artifact preparation failed: " + type(error).__name__ + ": " + str(error))
                result["reporting_status"] = "ERROR"
                result["reporting_error"] = "; ".join(filter(None, [result.get("reporting_error"), reason]))
                atomic_json(root / "results" / (job["id"] + ".json"), result)
                atomic_json(root / "archives" / (job["id"] + ".json"),
                            {"schema_version": SCHEMA_VERSION, "id": job["id"], "status": "unavailable",
                             "terminal": True, "attempts": 0, "seconds": None, "reason": reason,
                             "terminal_at": time.time()})
                continue
            return {"done": False, "execution": {"id": job["id"], "sequence": job["sequence"],
                "module": job["module"], "scope": job["scope"], "round_label": job["round_label"],
                "attempt": (receipt or {}).get("attempts", 0) + 1,
                "reporting_status": result["reporting_status"], "summary_source": result["summary_source"],
                "files": files}}
        if producer:
            atomic_json(root / "reporter.json", {"schema_version": SCHEMA_VERSION, "finished_at": time.time(), "status": "drained"})
            return {"done": True, "producer_status": producer["status"]}
        if not args.wait or time.monotonic() - started >= args.timeout:
            return {"done": False, "waiting": True, "execution": None}
        last_state = state
        time.sleep(delay)
        delay = min(5, delay * 1.5)


def acknowledge(root, args):
    execution_id = token(args.id, "execution ID")
    job = read_json(root / "jobs" / (execution_id + ".json"))
    if job["id"] != execution_id:
        raise ValueError("archive acknowledgement identity mismatch")
    if not math.isfinite(args.seconds) or args.seconds < 0:
        raise ValueError("archive duration is invalid")
    with lock(root, "ack"):
        pointer = root / "archives" / (execution_id + ".json")
        previous = read_json(pointer, missing=True)
        if previous and previous.get("status") == "success":
            return previous
        attempt = args.attempt or ((previous or {}).get("attempts", 0) + 1)
        receipt_path = root / "receipts" / (execution_id + ".%04d.json" % attempt)
        receipt = read_json(receipt_path, missing=True)
        if receipt is None:
            completed = time.time()
            result = read_json(root / "results" / (execution_id + ".json"), missing=True)
            ready_at = (result or {}).get("reporting_metrics", {}).get("summary_ready_at")
            receipt = {"schema_version": SCHEMA_VERSION, "id": execution_id, "status": args.status,
                       "seconds": args.seconds, "attempts": attempt, "archived_at": completed,
                       "archive_started_at": completed - args.seconds,
                       "archive_queue_seconds": max(0, completed - args.seconds - ready_at) if isinstance(ready_at, (int, float)) else None}
            atomic_json(receipt_path, receipt)
        if not previous or receipt["attempts"] >= previous.get("attempts", 0):
            atomic_json(pointer, receipt)
        return receipt


def duration(value):
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value < 0:
        return "-"
    value = int(value)
    return "%dm %ds" % (value // 60, value % 60)


def archive_measurements(root, execution_id):
    """Sum observed logical attempts once, independently of the latest pointer."""
    measured, invalid, errors = {}, set(), []
    pattern = re.compile(re.escape(execution_id) + r"\.(\d{4,})\.json$")
    for path in sorted((root / "receipts").glob(execution_id + ".*.json")):
        match = pattern.fullmatch(path.name)
        try:
            if not match:
                raise ValueError("archive receipt filename is malformed")
            value = read_json(within(root, path), limit=65536)
            attempt = value.get("attempts")
            seconds, ended = value.get("seconds"), value.get("archived_at")
            if (value.get("schema_version") != SCHEMA_VERSION or value.get("id") != execution_id
                    or not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1
                    or attempt != int(match.group(1)) or value.get("status") not in {"success", "failed"}
                    or not isinstance(seconds, (int, float)) or isinstance(seconds, bool)
                    or not math.isfinite(seconds) or seconds < 0
                    or not isinstance(ended, (int, float)) or isinstance(ended, bool)
                    or not math.isfinite(ended) or ended < 0):
                raise ValueError("archive receipt timing or identity is invalid")
            if attempt in invalid:
                continue
            if attempt in measured and measured[attempt] != value:
                measured.pop(attempt)
                invalid.add(attempt)
                raise ValueError("conflicting receipts for the same archive attempt")
            measured[attempt] = value
        except Exception as error:
            errors.append(clean_error(type(error).__name__ + ": " + str(error)))
    values = [measured[key] for key in sorted(measured)]
    if measured and len(measured) != max(measured):
        errors.append("archive attempt timing ledger has a missing logical attempt")
    known = sum(value["seconds"] for value in values) if values else None
    # A damaged ledger has an unknown complete duration.  Retain its measured
    # subset separately instead of presenting that subset as the complete phase.
    return {"seconds": known if not errors else None, "known_seconds": known,
            "last": values[-1] if values else None, "attempts": len(values),
            "highest_attempt": max(measured, default=0), "errors": errors,
            "completed_at": max(value["archived_at"] for value in values) if values else None}


def aggregate(root, config, args):
    producer = read_json(root / "producer.json", missing=True)
    if producer:
        settle_unclosed(root, jobs(root))
    skip_sections = []
    rows, errors, archive_times, progress = [], [], [], ["ND MODULE CASE PROGRESS - Build " + config["build"],
        "Counts describe authored module cases; pipeline, base and cleanup tasks are excluded.", ""]
    for job in jobs(root):
        result = read_json(root / "results" / (job["id"] + ".json"), missing=True)
        if result is None:
            attempted = Path(job["log"]).exists() or (root / "started" / (job["id"] + ".json")).exists()
            result = result_error(job, "execution summary missing at final reconciliation", not_run=not attempted)
        identity(result, job)
        activity, invocation = result["activity"], result["invocation"]
        receipt = read_json(root / "archives" / (job["id"] + ".json"), missing=True)
        archive_work = archive_measurements(root, job["id"])
        archive_status = (receipt or {}).get("status", "not archived")
        if (receipt and archive_status in {"success", "failed"}
                and receipt.get("attempts") != archive_work["highest_attempt"]):
            archive_work["errors"].append("archive acknowledgement has no matching complete attempt ledger")
            archive_work["seconds"] = None
        reporting_error = result.get("reporting_error", "")
        if archive_work["errors"]:
            reporting_error = "; ".join(filter(None, [reporting_error, "archive attempt timing ledger is incomplete or invalid"]))
        if activity.get("result") != "NOT_RUN" and archive_status != "success":
            reporting_error = "; ".join(filter(None, [reporting_error, "artifact publishing failed or incomplete"]))
        if reporting_error:
            errors.append({"id": job["id"], "module": job["module"], "scope": job["scope"], "reason": reporting_error})
        activity_result = activity.get("result", "UNKNOWN")
        if invocation.get("status") == "FAIL":
            activity_result = "FAIL"
        elif invocation.get("status") == "ERR" and activity_result not in {"FAIL", "NOT_RUN"}:
            activity_result = "UNKNOWN"
        phases = dict(invocation.get("phase_seconds", {}))
        metrics = dict(result.get("reporting_metrics", {}))
        last_archive = archive_work["last"] or {}
        if receipt:
            phases["archiving"] = archive_work["seconds"]
            metrics.update(archive_completed_at=archive_work["completed_at"], archive_seconds=archive_work["seconds"],
                           known_archive_seconds=archive_work["known_seconds"], last_archive_seconds=last_archive.get("seconds"),
                           archive_attempts=archive_work["attempts"],
                           archive_timing_complete=archive_work["seconds"] is not None and not archive_work["errors"],
                           archive_queue_seconds=last_archive.get("archive_queue_seconds"))
        if archive_work["completed_at"] is not None:
            archive_times.append(archive_work["completed_at"])
        counts = {state: {"started": activity.get("counts", {}).get(state)} for state in STATES}
        counts["other"] = {"started": activity.get("other_cases")}
        failure = "; ".join([str(value) for value in activity.get("failure", [])[:4]])
        skip_reason = invocation.get("reason", "") if activity_result == "SKIP" else ""
        if not failure and activity_result in {"FAIL", "SKIP"}:
            failure = clean_error(invocation.get("reason", ""))
        if reporting_error:
            failure = "; ".join(filter(None, [failure, reporting_error]))
        skipped_case_notes = []
        skipped_case_notes_truncated = bool(activity.get("evidence_truncated"))
        for case in activity.get("case_results", [])[:256]:
            if case.get("outcome") != "skipped":
                continue
            label = case.get("label", case.get("id", "Skipped case"))
            reason = case.get("reason") or "skipped by an authored condition; no specific reason recorded"
            note = clean_error(str(label) + ": " + str(reason))
            if note not in skipped_case_notes:
                if len(skipped_case_notes) < 8:
                    skipped_case_notes.append(note)
                else:
                    skipped_case_notes_truncated = True
        row = {"id": job["id"], "sequence": job["sequence"], "module": job["module"], "test_type": job["test_type"],
               "nd": job["nd"], "version_id": job["version_id"], "round_label": job["round_label"],
               "run_id": job["run_id"], "scope": job["scope"], "fabric": job["fabric"],
               "fabric_name": job["fabric_name"], "result": activity_result, "coverage": activity.get("coverage", "UNKNOWN"),
               "validated": activity.get("validated") is True,
               "count_unit": activity.get("count_unit", "distinct authored module cases"),
               "counts": counts, "case_totals": activity.get("testcase_totals", {}),
               "identified_case_counts": activity.get("identified_case_counts", {}),
               "identified_testcase_totals": activity.get("identified_testcase_totals", {}),
               "identified_other_cases": activity.get("identified_other_cases"),
               "base": activity.get("base", "Not observed"), "cleanup": activity.get("cleanup", "Not observed"),
               "failure": failure, "skip_reason": skip_reason,
               "skipped_case_notes": skipped_case_notes,
               "skipped_case_notes_truncated": skipped_case_notes_truncated,
               "source_notes": [clean_error(value) for value in activity.get("notes", [])[:4]],
               "duration": duration(invocation.get("duration_seconds")),
               "phase_seconds": phases, "invocation": invocation, "reporting_metrics": metrics,
               "summary_source": result["summary_source"], "reporting_status": "ERROR" if reporting_error else "SUCCESS",
               "archive_status": archive_status,
               "artifact": public_log_name(job)
                           if archive_status == "success" and (Path(config["workspace"]) / public_log_name(job)).is_file() else ""}
        rows.append(row)
        skip_path = Path(job["log"] + ".skips.txt")
        if not skip_path.exists():
            skip_path = module_skip_report(root, job, result)
        skip_sections.append(skip_path)
        progress += ["=" * 72, "MODULE: %s | FABRIC: %s | ROUND: %s" % (job["module"], job["scope"], job["round_label"]),
                     "RESULT: %s | COVERAGE: %s | SUMMARY: %s" % (activity_result, row["coverage"], row["summary_source"]),
                     "BASE: %s | CLEANUP: %s" % (row["base"], row["cleanup"]),
                     "CASE OUTCOMES: " + json.dumps(row["case_totals"], sort_keys=True),
                     "STATE CASES STARTED: " + json.dumps(activity.get("counts", {}), sort_keys=True)]
        for case in activity.get("case_results", [])[:256]:
            progress.append("  %s | %s | %s" % (case.get("outcome", "UNKNOWN"), case.get("state", "other"), clean_error(case.get("label", case.get("id", "")))))
        if activity.get("evidence_truncated"):
            progress.append("  Additional per-case labels omitted by the evidence bound; totals retained.")
        for note in row["source_notes"]:
            progress.append("NOTE: " + note)
        if failure:
            progress.append("FAILURE / REPORTING: " + failure)
        progress.append("")
    if not producer:
        errors.append({"reason": "execution producer did not publish its terminal receipt"})
    fatal = read_json(root / "reporter.error.json", missing=True)
    if fatal:
        errors.append({"reason": fatal.get("error", "artifact reporter failed")})
    progress_path = root / ("module_progress_build_" + token(config["build"], "build") + ".txt")
    progress_path.write_text("\n".join(progress) + "\n", encoding="utf-8")
    os.chmod(progress_path, 0o644)
    skiplist_path = Path(config["workspace"]) / ("skipped_tests_build_" + token(config["build"], "build") + ".txt")
    with readable_file(skiplist_path) as output:
        output.write("ND MODULE SKIPS AND UNREACHED CASES - Build " + config["build"] + "\n")
        output.write("Case outcomes are distinct authored module cases. Task skips are observations, not case counts.\n")
        output.write("Modules or rounds never registered are NOT_RUN in the activity table; they are not fabricated skips.\n\n")
        for skip_path in skip_sections:
            output.write("=" * 80 + "\n")
            regular(skip_path)
            with skip_path.open("r", encoding="utf-8") as source:
                shutil.copyfileobj(source, output, length=65536)
    value = {"schema_version": SCHEMA_VERSION, "build": config["build"], "run_id": config["run_id"],
             "rows": rows, "reporting_errors": errors[:MAX_JOBS], "selected_executions": len(rows),
             "producer_status": (producer or {}).get("status", "missing"),
             "status_scope": "execution_branch",
             "execution_status": (producer or {}).get("execution_status", (producer or {}).get("status", "missing")),
             "home_recovery_status": (producer or {}).get("home_recovery_status", "unverified"),
             "reporting_tail_seconds": max(0, max(archive_times) - producer["finished_at"]) if archive_times and producer else None,
             "summary_sources": {name: sum(row["summary_source"] == name for row in rows)
                                 for name in ("structured_events", "raw_log_recovery", "unavailable")},
             "failed": bool(errors or any(row["result"] in {"FAIL", "UNKNOWN", "NOT_RUN"} for row in rows)
                            or (producer or {}).get("status") != "success"
                            or (producer or {}).get("home_recovery_status") == "failed"),
             "skiplist_file": skiplist_path.name}
    destination = within(root, args.output) if args.output else root / "aggregate.json"
    atomic_json(destination, value, limit=MAX_OUTPUT)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", "register", "begin", "log-path", "close", "next", "ack", "finish", "aggregate", "check-space", "reporter-failed"))
    parser.add_argument("--root", required=True)
    parser.add_argument("--workspace")
    parser.add_argument("--build")
    parser.add_argument("--run-id")
    parser.add_argument("--version-id")
    parser.add_argument("--module")
    parser.add_argument("--plan")
    parser.add_argument("--collection-root")
    parser.add_argument("--exit-code", type=int)
    parser.add_argument("--duration-seconds", type=int)
    parser.add_argument("--status", choices=("success", "failed", "interrupted"), default="success")
    parser.add_argument("--home-recovery-status", choices=("confirmed", "failed", "not_required", "unverified"), default="unverified")
    parser.add_argument("--id")
    parser.add_argument("--seconds", type=float, default=0)
    parser.add_argument("--attempt", type=int)
    parser.add_argument("--output")
    parser.add_argument("--reason", default="artifact publisher failed")
    parser.add_argument("--include-executions", action="store_true", help="include full registered job descriptors in CLI output")
    parser.add_argument("--wait", action="store_true")
    parser.add_argument("--timeout", type=int, default=36000)
    parser.add_argument("--parse-timeout", type=int)
    parser.add_argument("--drain-timeout", type=int, default=1800)
    parser.add_argument("--archive-attempts", type=int, default=2)
    parser.add_argument("--min-free-bytes", type=int, default=512 * 1024 * 1024)
    args = parser.parse_args()
    root = None
    try:
        if args.command == "init":
            if not all((args.workspace, args.build, args.run_id)) or args.min_free_bytes < 0:
                parser.error("init requires workspace, build and run-id")
            value = initialize(args)
        else:
            root, config = configuration(args.root)
            if args.command == "register":
                if not args.plan or not args.collection_root:
                    parser.error("register requires plan and collection-root")
                registered = register(root, config, args)
                value = registered if args.include_executions else {
                    "log_dir": registered["log_dir"], "round_key": registered["round_key"],
                    "selected_executions": len(registered["executions"])}
            elif args.command in {"begin", "log-path", "close"}:
                if not all((args.version_id, args.module, args.run_id)):
                    parser.error("execution command requires version-id, module and run-id")
                job = find_job(root, args.version_id, args.module, args.run_id)
                if args.command == "close":
                    if args.exit_code is None or args.exit_code < 0 or (args.duration_seconds is not None and args.duration_seconds < 0):
                        parser.error("close requires a nonnegative exit-code and duration")
                    args.parse_timeout = args.parse_timeout or 20
                    value = close_execution(root, job, args)
                else:
                    value = begin(root, config, job) if args.command == "begin" else {"id": job["id"], "log": job["log"], "catalog": job["catalog"]}
            elif args.command == "next":
                args.parse_timeout = args.parse_timeout or 600
                if min(args.timeout, args.parse_timeout, args.drain_timeout, args.archive_attempts) < 1:
                    parser.error("worker time and attempt limits must be positive")
                value = next_execution(root, config, args)
            elif args.command == "ack":
                if not args.id or args.status == "interrupted" or (args.attempt is not None and args.attempt < 1):
                    parser.error("ack requires execution id and success/failed status")
                value = acknowledge(root, args)
            elif args.command == "finish":
                value = finish(root, config, args.status, args.home_recovery_status)
            elif args.command == "aggregate":
                value = aggregate(root, config, args)
            elif args.command == "check-space":
                value = check_space(root, config)
            else:
                value = {"error": clean_error(args.reason), "at": time.time()}
                atomic_json(root / "reporter.error.json", value)
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    except Exception as error:
        message = clean_error(type(error).__name__ + ": " + str(error))
        if root is not None and args.command == "next":
            atomic_json(root / "reporter.error.json", {"error": message, "at": time.time()})
        print(json.dumps({"error": message, "done": args.command == "next"}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
