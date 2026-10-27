#!/usr/bin/env python3
"""Collect authored integration case activity without counting Ansible tasks.

The state counters describe distinct authored cases that started, including a
case whose action failed.  They are never derived from PLAY RECAP or from TASK
header totals.  Setup and cleanup are reported only as observations.  A source
without explicit TC identifiers has unknown case counts rather than invented
one-task-per-case counts.  The raw log is processed as a bounded line stream.

Usage::

    python nd_test_activity.py summarize --log output.txt --module nd_manage_policy \
        --run-id 118_abcd --build 118 --fabric iBGP --collection-root "$PWD" \
        --output output.txt.activity.json

The JSON sidecar is deliberately small and contains no Ansible result payloads.
"""

import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import re
import tempfile

try:
    import yaml
except ImportError:
    yaml = None


SCHEMA_VERSION = 1
STATES = ("merged", "replaced", "overridden", "deleted", "gathered")
MAX_SOURCE_FILES = 2000
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_TASKS = 30000
MAX_LOG_LINE = 65536
CASE_ID = re.compile(r"(?i)\bTC\s*[-_.]?\s*(\d+[a-z]?(?:\.\d+)*)\b")
TASK_HEADER = re.compile(r"^TASK\s*\[(.*?)\]\s*\*+\s*$")
SOURCE_PATH = re.compile(r"^task path:\s*(.*?):\d+\s*$", re.I)
MODULE_MARKER = re.compile(r"^\[MODULE:\s*([^\]]+)\]")
PLAYBOOK_MARKER = re.compile(r"^\[PLAYBOOK:\s*([^\]]+)\]")
RUN_MARKER = re.compile(r"^\[RUN_MARKER:\s*([^\]]+)\]\s*$")
EXIT_STATUS = re.compile(r"^\[(?:ANSIBLE_EXIT_STATUS|EXIT_CODE):\s*(-?\d+)\]\s*$")
RECAP = re.compile(r"^\S+\s*:\s+ok=(\d+)\b.*?\bfailed=(\d+)\b.*?\bskipped=(\d+)\b")
RESULT = re.compile(r"^(ok|changed|skipping|fatal|failed|included):\s*\[")
PREREQUISITE = re.compile(r"(?i)\b(?:setup|prerequisite|preflight|pre-flight|pre-test|teardown)\b|TC\s*\d+[a-z]?-PRE\b")
CLEANUP = re.compile(r"(?i)\b(?:clean[ _-]?up|teardown|purge|restore initial)\b")
MODULE_ALIASES = {
    "nd_manage_vpc_pair": "nd_vpc_pair",
    "nd_manage_resource_manager": "nd_resource_manager",
}
FAILURE_REASONS = (
    (re.compile(r"No Commands to execute", re.I), "No Commands to execute"),
    (re.compile(r"Assertion failed", re.I), "Assertion failed"),
    (re.compile(r"unexpected link neighbor", re.I), "Unexpected link neighbor"),
    (re.compile(r"Deployment failed", re.I), "Deployment failed"),
    (re.compile(r"\bAttributeError\b"), "AttributeError"),
    (re.compile(r"\bTypeError\b"), "TypeError"),
    (re.compile(r"Request failed.{0,100}\b400\b", re.I), "Request failed (400)"),
    (re.compile(r"Request failed.{0,100}\b207\b", re.I), "Request failed (207)"),
)


def normal_name(value):
    return re.sub(r"\s+", " ", str(value or "")).strip()


def safe_label(value, limit=180):
    """Use only static source/header labels, never an API response body."""
    value = normal_name(value)
    value = re.sub(r"https?://\S+", "[endpoint]", value, flags=re.I)
    value = re.sub(r"(?<!\w)(?:\d{1,3}\.){3}\d{1,3}(?!\w)", "[address]", value)
    value = re.sub(r"(?i)\b(?:password|token|secret|authorization)\s*[:=]\s*\S+", "[credential]", value)
    value = re.sub(r"\b[A-Z0-9]{9,}\b", "[identifier]", value)
    value = value.replace("|", "/").replace("`", "'")
    return value[:limit]


def source_loader():
    """Accept Ansible scalar tags; reject actual duplicate YAML mapping keys."""
    class Loader(yaml.SafeLoader):
        pass

    def construct_mapping(loader, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in seen
                seen.add(key)
            except TypeError:
                raise yaml.constructor.ConstructorError(None, None, "unhashable mapping key", key_node.start_mark)
            if duplicate:
                raise yaml.constructor.ConstructorError(None, None, "duplicate mapping key", key_node.start_mark)
        loader.flatten_mapping(node)
        return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)

    def unknown_tag(loader, tag_suffix, node):
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return construct_mapping(loader, node)

    Loader.construct_mapping = construct_mapping
    Loader.add_multi_constructor("!", unknown_tag)
    return Loader


def iter_tasks(value):
    """Walk only executable task/play branches, never module configuration."""
    if isinstance(value, list):
        for child in value:
            yield from iter_tasks(child)
    elif isinstance(value, dict):
        if "name" in value and not any(key in value for key in ("hosts", "gather_facts")):
            yield value
        for key in ("tasks", "pre_tasks", "post_tasks", "handlers", "block", "rescue", "always"):
            if key in value:
                yield from iter_tasks(value[key])


def task_action(task):
    builtin = {
        "assert", "debug", "set_fact", "include_tasks", "import_tasks", "include_role", "import_role",
        "fail", "find", "stat", "file", "copy", "template", "command", "shell", "uri", "pause", "meta",
    }
    for key, value in task.items():
        short = str(key).rsplit(".", 1)[-1]
        if str(key).startswith("cisco.nd.") or short.startswith("nd_") or short in builtin:
            return short, value if isinstance(value, dict) else {}
    return "", {}


def case_identity(name, relative):
    match = CASE_ID.search(name)
    if not match:
        return None
    # Scope TC1 to its authored suite/file; TC1 in another suite is another case.
    suite = re.sub(r"[\W_]+", "_", name[:match.start()].upper()).strip("_") or Path(relative).stem.upper()
    return "%s::%s::TC%s" % (relative, suite, match.group(1).upper())


def load_catalog(collection_root, module):
    target_name = MODULE_ALIASES.get(module.split(".", 1)[0], module.split(".", 1)[0])
    target = Path(collection_root) / "tests" / "integration" / "targets" / target_name
    catalog = {"target": target_name, "tasks": {}, "cases": {}, "errors": [], "untagged_actions": 0, "ignored_names": set()}
    if yaml is None:
        catalog["errors"].append("PyYAML unavailable; authored case counts unknown")
        return catalog
    if not target.is_dir() or target.is_symlink():
        catalog["errors"].append("integration target source unavailable; authored case counts unknown")
        return catalog
    files = sorted(set(target.rglob("*.yaml")) | set(target.rglob("*.yml")))
    if len(files) > MAX_SOURCE_FILES:
        catalog["errors"].append("integration target exceeds source file limit")
        return catalog
    loader = source_loader()
    source_task_count = 0
    for path in files:
        relative = path.relative_to(target).as_posix()
        if any(part in {"defaults", "vars", "files", "meta", "templates"} for part in path.relative_to(target).parts):
            continue
        try:
            if path.is_symlink() or path.stat().st_size > MAX_SOURCE_BYTES:
                raise ValueError("source file exceeds safe limits")
            documents = list(yaml.load_all(path.read_text(encoding="utf-8"), Loader=loader))
        except (OSError, ValueError, yaml.YAMLError):
            catalog["errors"].append("unreadable or ambiguous source: " + relative)
            continue
        for document in documents:
            for task in iter_tasks(document):
                name = normal_name(task.get("name"))
                if not name:
                    continue
                action, arguments = task_action(task)
                if action in {"include_tasks", "import_tasks", "include_role", "import_role"}:
                    catalog["ignored_names"].add(name)
                    continue
                if not action:
                    continue
                identity = case_identity(name, relative)
                cleanup = bool(CLEANUP.search(path.stem) or (not identity and CLEANUP.search(name)))
                base = not cleanup and bool(PREREQUISITE.search(path.stem) or (
                    PREREQUISITE.search(name) and (not identity or re.search(r"(?i)prerequisite|TC\s*\d+[a-z]?-PRE\b", name))
                ))
                # This policy prerequisite has an authored TC label but is
                # explicitly documented as substrate for the subsequent case.
                if target_name == "nd_manage_policy" and re.search(r"(?i)^MERGED_MULTI_SWITCH\s+TC3a\b", name):
                    base = True
                if cleanup or base:
                    identity = None
                record = {
                    "name": name, "path": relative, "action": action, "case": identity,
                    "base": base, "cleanup": cleanup,
                    "ignored": bool(task.get("ignore_errors")),
                    "state": str(arguments.get("state", "")).lower(),
                }
                catalog["tasks"].setdefault(name, []).append(record)
                source_task_count += 1
                if source_task_count > MAX_SOURCE_TASKS:
                    raise ValueError("integration target exceeds source task limit")
                if identity:
                    case = catalog["cases"].setdefault(identity, {
                        "label": safe_label(identity.split("::", 1)[1].replace("::", " ")),
                        "state": "other", "tasks": set(), "assertions": set(), "module_actions": [],
                    })
                    case["tasks"].add(name)
                    if action == "assert":
                        case["assertions"].add(name)
                    if action == target_name:
                        case["module_actions"].append(record)
                elif action == target_name and not base and not cleanup:
                    catalog["untagged_actions"] += 1
    for case in catalog["cases"].values():
        # Verification gathers never create another Gather case.  The first
        # authored action establishes this case's tested module state.
        if case["module_actions"]:
            state = case["module_actions"][0]["state"]
            case["state"] = state if state in STATES else "other"
    return catalog


def line_stream(path):
    """Ignore oversized payload tails instead of loading a giant result line."""
    with open(path, "r", encoding="utf-8", errors="replace") as source:
        while True:
            value = source.readline(MAX_LOG_LINE + 1)
            if not value:
                return
            if len(value) > MAX_LOG_LINE and not value.endswith("\n"):
                while value and not value.endswith("\n"):
                    value = source.readline(MAX_LOG_LINE + 1)
                continue
            yield re.sub(r"\x1b\[[0-9;]*m", "", value).rstrip("\r\n")


def execution_exit(log_path, module, run_id):
    """Return (exit code, reporting error), distinguishing absent from invalid."""
    try:
        path = Path(str(log_path) + ".execution.json")
        if path.is_symlink() or path.stat().st_size > 65536:
            return None, "execution metadata exceeds safe limits or is a symlink"
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            return None, "execution metadata is not a JSON object"
        if value.get("module") != module or value.get("run_id") != run_id:
            return None, "execution metadata module/run identity mismatch"
        exit_code = value.get("exit_code")
        if not isinstance(exit_code, int) or isinstance(exit_code, bool):
            return None, "execution metadata exit code is missing or invalid"
        return exit_code, None
    except FileNotFoundError:
        # Older archived logs may have an explicit raw exit marker but no
        # sidecar.  A present sidecar must always be valid and match identity.
        return None, None
    except (OSError, ValueError, TypeError):
        return None, "execution metadata is unreadable or corrupt"


def summarize(log, module, run_id, build, fabric, collection_root, test_type="integration"):
    result = {
        "schema_version": SCHEMA_VERSION, "module": module, "run_id": run_id,
        "build": str(build), "fabric": fabric, "test_type": test_type,
        "validated": False, "coverage": "UNKNOWN", "counts": {state: None for state in STATES},
        "testcase_totals": {key: None for key in ("started", "passed", "failed", "skipped", "incomplete")},
        "other_cases": None, "base": "Not observed", "cleanup": "Not observed",
        "result": "UNKNOWN", "failure": [], "notes": [],
        "count_unit": "distinct authored suite/file + TC identifier; state columns count started cases",
        "exclusions": "pipeline/harness tasks, role discovery/includes, setup, prerequisites and cleanup",
    }
    catalog = load_catalog(collection_root, module) if test_type == "integration" else {
        "target": "", "tasks": {}, "cases": {}, "errors": ["smoke playbooks have no module integration case catalog"],
        "untagged_actions": 0, "ignored_names": set(),
    }
    observed = defaultdict(lambda: defaultdict(set))
    phase_outcomes = {"base": set(), "cleanup": set()}
    runner_outcomes = {"base": set(), "cleanup": set()}
    untagged_seen = set()
    markers, modules = set(), set()
    state = {"current": None, "recap": False, "recap_rows": 0, "recap_failed": 0,
             "exit_code": None, "exit_conflict": False,
             "module_skip": False, "outside_failure": False, "outside_reasons": set(), "unmatched_case": False}

    def add_failure(label):
        label = safe_label(label)
        if label not in result["failure"] and len(result["failure"]) < 4:
            result["failure"].append(label)

    def with_reason(label, event):
        # Only fixed phrases selected from the allowlist are copied.  No
        # exception body, API response, command, address or entity is retained.
        reasons = sorted(event["reasons"])
        return safe_label(label, 115) + ("; " + ", ".join(reasons[:2]) if reasons else "")

    def finish_task():
        event = state["current"]
        if not event:
            return
        if event["name"] in catalog["ignored_names"] or event["outcomes"] == {"included"}:
            return
        if not event["role"]:
            runner = re.match(r"^\[" + re.escape(module.split(".", 1)[0]) + r"\]\s+(SETUP|BASE|CLEANUP|TEARDOWN)\b", event["name"], re.I)
            if runner:
                phase = "base" if runner.group(1).upper() in {"SETUP", "BASE"} else "cleanup"
                runner_status = set(event["outcomes"])
                if event["ignored"]:
                    runner_status.discard("failed")
                    runner_status.add("ignored")
                runner_outcomes[phase].update(runner_status)
                if "failed" in event["outcomes"] and not event["ignored"]:
                    add_failure(with_reason("runner " + phase + ": " + event["name"], event))
        candidates = catalog["tasks"].get(event["name"], [])
        role_matches = event["role"] in {catalog["target"], "cisco.nd." + catalog["target"]}
        if event["role"] and not role_matches:
            candidates = []
        if event["path"]:
            fragment = "/tests/integration/targets/" + catalog["target"] + "/"
            if fragment not in event["path"]:
                candidates = []
            else:
                relative = event["path"].split(fragment, 1)[1]
                candidates = [item for item in candidates if item["path"] == relative]
        # An exact authored task-name match is allowed for standalone targets
        # whose playbook tasks have no role prefix.  Conflicting catalog names
        # need a verbose source path and remain unknown without it.
        identities = {(item["path"], item["case"], item["base"], item["cleanup"]) for item in candidates}
        if len(identities) != 1:
            owns_path = bool(event["path"] and ("/tests/integration/targets/" + catalog["target"] + "/") in event["path"])
            if (role_matches or owns_path) and (CASE_ID.search(event["name"]) or any(item["case"] for item in candidates)):
                state["unmatched_case"] = True
            if "failed" in event["outcomes"] and not event["ignored"]:
                state["outside_failure"] = True
                state["outside_reasons"].update(event["reasons"])
            return
        record = candidates[0]
        outcomes = set(event["outcomes"])
        if event["ignored"]:
            outcomes.discard("failed")
            outcomes.add("ignored")
        if not outcomes:
            outcomes.add("unknown")
        for phase in ("base", "cleanup"):
            if record[phase]:
                phase_outcomes[phase].update(outcomes)
        identity = record["case"]
        if identity:
            observed[identity][record["name"]].update(outcomes)
            if "failed" in outcomes:
                label = catalog["cases"][identity]["label"] + ": " + safe_label(record["name"])
                add_failure(with_reason(label, event))
        elif record["action"] == catalog["target"] and not record["base"] and not record["cleanup"]:
            untagged_seen.add((record["path"], record["name"]))
        if not identity and "failed" in outcomes:
            phase = "module base" if record["base"] else "module cleanup" if record["cleanup"] else "unlabelled module task"
            add_failure(with_reason(phase + ": " + record["name"], event))

    try:
        for line in line_stream(log):
            match = (PLAYBOOK_MARKER if test_type == "smoke" else MODULE_MARKER).match(line)
            if match:
                # Two different identities are enough to reject a log; retain
                # no unbounded set of arbitrary marker values.
                if len(modules) < 2:
                    modules.add(match.group(1).strip())
            match = RUN_MARKER.match(line)
            if match:
                if len(markers) < 2:
                    markers.add(match.group(1).strip())
            match = EXIT_STATUS.match(line)
            if match:
                raw_exit = int(match.group(1))
                if state["exit_code"] is not None and state["exit_code"] != raw_exit:
                    state["exit_conflict"] = True
                state["exit_code"] = raw_exit
            match = TASK_HEADER.match(line)
            if match:
                finish_task()
                body = match.group(1)
                role, separator, name = body.partition(" : ")
                state["current"] = {"name": normal_name(name if separator else body),
                                    "role": role if separator else "", "path": "", "outcomes": set(), "ignored": False, "reasons": set()}
                continue
            event = state["current"]
            if event:
                match = SOURCE_PATH.match(line)
                if match:
                    event["path"] = match.group(1).replace("\\", "/")
                match = RESULT.match(line)
                if match:
                    outcome = match.group(1)
                    event["outcomes"].add({"fatal": "failed", "changed": "ok", "skipping": "skipped"}.get(outcome, outcome))
                if "failed" in event["outcomes"]:
                    for pattern, reason in FAILURE_REASONS:
                        if pattern.search(line):
                            event["reasons"].add(reason)
                if line.strip() == "...ignoring":
                    event["ignored"] = True
            if line.startswith("PLAY RECAP"):
                finish_task()
                state["current"] = None
                state["recap"] = True
            if state["recap"]:
                match = RECAP.search(line)
                if match:
                    state["recap_rows"] += 1
                    state["recap_failed"] += int(match.group(2))
                    unreachable = re.search(r"\bunreachable=(\d+)\b", line)
                    state["recap_failed"] += int(unreachable.group(1)) if unreachable else 0
            if "NDP_MODULE_SKIPPED" in line:
                state["module_skip"] = True
        finish_task()
    except OSError:
        result["notes"].append("raw log unavailable")
        return result

    if markers != {run_id} or modules != {module}:
        result["notes"].append("module/run marker mismatch or missing; no case counts accepted")
        return result
    exit_code, execution_error = execution_exit(log, module, run_id)
    if execution_error:
        result["notes"].append(execution_error + "; no case counts accepted")
        return result
    result["validated"] = True
    for phase, outcomes in phase_outcomes.items():
        result[phase] = "Failed" if "failed" in outcomes else "Ran" if {"ok", "ignored"} & outcomes else "Skipped" if outcomes == {"skipped"} else "Not observed"
        runner = runner_outcomes[phase]
        if "failed" in runner:
            result[phase] = "Runner failed" if result[phase] == "Not observed" else result[phase] + " (runner failed)"
        elif result[phase] == "Not observed" and {"ok", "ignored"} & runner:
            result[phase] = "Runner observed"
    exit_conflict = state["exit_conflict"] or (
        exit_code is not None and state["exit_code"] is not None and exit_code != state["exit_code"]
    )
    if exit_code is None:
        exit_code = state["exit_code"]
    if exit_conflict:
        result["notes"].append("execution metadata/raw exit statuses disagree; invocation result unknown")
    elif state["recap_failed"] or (exit_code is not None and exit_code != 0):
        result["result"] = "FAIL"
    elif state["module_skip"] and state["recap_rows"] > 0:
        result["result"] = "SKIP"
    elif state["recap_rows"] > 0 and exit_code == 0:
        result["result"] = "PASS"
    if state["recap_rows"] == 0:
        result["notes"].append("no valid PLAY RECAP row observed; no successful invocation result inferred")
    if state["outside_failure"]:
        add_failure(with_reason("failure outside an identified module test case; no pipeline task counted", {"reasons": state["outside_reasons"]}))
    if any(runner_outcomes.values()):
        result["notes"].append("runner setup/cleanup labels are stage indicators only; runner task counts are excluded")
    result["notes"].extend(catalog["errors"][:4])

    if not catalog["cases"]:
        result["notes"].append("source has no explicit authored TC identifiers; task totals are excluded")
        return result
    # Explicit case evidence is still useful in a partially labelled target,
    # but totals cannot masquerade as a complete count of the module's cases.
    partial = bool(catalog["errors"] or catalog["untagged_actions"] or state["unmatched_case"])
    result["coverage"] = "PARTIAL" if partial else "COMPLETE"
    result["identified_case_counts"] = {state: 0 for state in STATES}
    totals = {key: 0 for key in ("started", "passed", "failed", "skipped", "incomplete")}
    other = 0
    partly_skipped_not_started = 0
    for identity, tasks in observed.items():
        case = catalog["cases"][identity]
        outcomes = set().union(*tasks.values())
        if outcomes == {"skipped"}:
            required = case["assertions"] | {action["name"] for action in case["module_actions"]}
            if required and all(name in tasks for name in required):
                totals["skipped"] += 1
            else:
                # An early skip followed by an aborted play is insufficient
                # evidence that the entire authored case was skipped.
                partly_skipped_not_started += 1
            continue
        totals["started"] += 1
        if case["state"] in STATES:
            result["identified_case_counts"][case["state"]] += 1
        else:
            other += 1
        if "failed" in outcomes:
            totals["failed"] += 1
            continue
        assertions = case["assertions"]
        assertion_results = [tasks.get(name, set()) for name in assertions]
        all_assertions_observed = bool(assertions) and all(item and item <= {"ok", "skipped"} for item in assertion_results)
        assertion_passed = any("ok" in item for item in assertion_results)
        all_actions_observed = all(action["name"] in tasks for action in case["module_actions"])
        if all_assertions_observed and assertion_passed and all_actions_observed:
            totals["passed"] += 1
        else:
            totals["incomplete"] += 1
    result["identified_testcase_totals"] = totals
    result["identified_other_cases"] = other
    result["catalog_case_count"] = len(catalog["cases"])
    if partial:
        result["notes"].append("partial authored identifiers: state counts and overall case totals unknown; identified subset retained separately")
        if untagged_seen:
            result["notes"].append("unlabelled module actions observed; not converted to cases")
        if state["unmatched_case"]:
            result["notes"].append("authored case labels were ambiguous or rendered differently; unmatched tasks were not counted")
    else:
        result["counts"] = dict(result["identified_case_counts"])
        result["testcase_totals"] = dict(totals)
        result["other_cases"] = other
    if other:
        result["notes"].append("%d identified started cases use other/unspecified state; included in case totals only" % other)
    if totals["incomplete"]:
        result["notes"].append("incomplete means required source verification was not observed; it is not a pass or a skip")
    if partly_skipped_not_started:
        result["notes"].append("%d cases have only partial skip evidence; not counted as started or skipped" % partly_skipped_not_started)
    return result


def atomic_json(path, value):
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".nd_activity_", dir=str(destination.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("summarize", help="stream one run log into a case-activity JSON sidecar")
    for name in ("log", "module", "run-id", "build", "fabric", "collection-root"):
        command.add_argument("--" + name, required=True)
    command.add_argument("--test-type", choices=("integration", "smoke"), default="integration")
    command.add_argument("--output", help="default: LOG.activity.json")
    arguments = parser.parse_args()
    value = summarize(arguments.log, arguments.module, arguments.run_id, arguments.build,
                      arguments.fabric, arguments.collection_root, arguments.test_type)
    atomic_json(arguments.output or arguments.log + ".activity.json", value)
    return 0 if value["validated"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
