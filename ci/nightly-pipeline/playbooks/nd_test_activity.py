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
import hashlib
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
CATALOG_VERSION = 3
MAX_CATALOG_BYTES = 16 * 1024 * 1024
MAX_CATALOG_SOURCE_BYTES = 64 * 1024 * 1024
MAX_EVENT_BYTES = 32 * 1024 * 1024
MAX_EVENT_RECORDS = 100000
MAX_EVENT_LINE = 8192
MAX_EVENT_TASKS = 60000
MAX_CASE_EVIDENCE = 256
CASE_ID = re.compile(r"(?i)\bTC\s*[-_.]?\s*(\d+[a-z]?(?:\.\d+)*)\b")
TASK_HEADER = re.compile(r"^TASK\s*\[(.*?)\]\s*\*+\s*$")
SOURCE_PATH = re.compile(r"^task path:\s*(.*?):(\d+)\s*$", re.I)
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

    class SourceMapping(dict):
        """Keep YAML source position outside the authored mapping keys."""
        pass

    def construct_yaml_map(loader, node):
        value = SourceMapping()
        value._nd_source_line = node.start_mark.line + 1
        yield value
        value.update(loader.construct_mapping(node))

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
    Loader.add_constructor("tag:yaml.org,2002:map", construct_yaml_map)
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


def _source_bytes(path):
    with path.open("rb") as source:
        data = source.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError("source file exceeds safe limits")
    return data


def _verification_action(action):
    """Recognize Ansible assertions and collection integration validators."""
    return action == "assert" or action.endswith("_validate")


def _target_action(action, target):
    """Match module actions to their source role without changing event identity."""
    return MODULE_ALIASES.get(action, action) == target


def _section_state(name):
    """An explicit state chapter after TC can distinguish a reused identifier."""
    match = CASE_ID.search(name)
    if not match:
        return None
    tail = name[match.end():]
    state = re.match(r"(?i)^[\s:_.-]*(merged|replaced|overridden|deleted|gathered)\b", tail)
    return state.group(1).lower() if state else None


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
            documents = list(yaml.load_all(_source_bytes(path).decode("utf-8"), Loader=loader))
        except (OSError, ValueError, yaml.YAMLError):
            catalog["errors"].append("unreadable or ambiguous source: " + relative)
            continue
        records = []
        last_case = None
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
                # Some roles explicitly label their final, unnumbered removal
                # work as '<state> - END'. Require both the owned delete action
                # and a cleanup verb; an arbitrary END word is not evidence.
                end_cleanup = bool(not identity and _target_action(action, target_name)
                                   and str(arguments.get("state", "")).lower() == "deleted"
                                   and re.match(r"(?i)^(?:DELETE|GATHER|MERGE|OVERRIDE|REPLACE)\s*-\s*END\s*-\s*(?:remove\b|ensure clean state\b)", name))
                cleanup = bool(CLEANUP.search(path.stem) or (not identity and CLEANUP.search(name)) or end_cleanup)
                base = not cleanup and bool(path.stem.lower() == "base_tasks" or PREREQUISITE.search(path.stem)
                                            or (not identity and re.match(r"(?i)^BASE\s*(?:[-:]|$)", name)) or (
                    PREREQUISITE.search(name) and (not identity or re.search(r"(?i)prerequisite|TC\s*\d+[a-z]?-PRE\b", name))
                ))
                if target_name == "nd_manage_policy" and re.search(r"(?i)^MERGED_MULTI_SWITCH\s+TC3a\b", name):
                    base = True
                if cleanup or base:
                    identity = None
                    last_case = None
                elif identity:
                    last_case = identity
                elif _verification_action(action):
                    # A generic Assert/validator directly following an authored
                    # case belongs to that source chapter, not a new task-case.
                    identity = last_case
                line = getattr(task, "_nd_source_line", None)
                key = "%s:%s" % (relative, line) if line else relative + ":" + hashlib.sha256(name.encode()).hexdigest()[:16]
                message = arguments.get("msg")
                applicability = bool(action == "debug" and isinstance(message, str)
                                     and message.startswith("NDP_CASE_SKIPPED:")
                                     and re.search(r"(?i)\bApplicability$", name))
                record = {
                    "name": name, "path": relative, "action": action, "case": identity,
                    "key": key, "line": line, "base": base, "cleanup": cleanup,
                    "ignored": bool(task.get("ignore_errors")),
                    "state": str(arguments.get("state", "")).lower(),
                    "verification": _verification_action(action), "applicability": applicability,
                }
                if applicability:
                    record["skip_reason"] = safe_label(message.partition(":")[2].strip())
                records.append(record)
                source_task_count += 1
                if source_task_count > MAX_SOURCE_TASKS:
                    raise ValueError("integration target exceeds source task limit")
        # Group contiguous source chapters. A reused TC number with a new
        # explicit tested state after verification is an independent chapter.
        # A verification gather inside the original chapter never adds a case.
        groups = defaultdict(list)
        active = {}
        for record in records:
            identity = record["case"]
            if identity:
                group = active.get(identity)
                section = _section_state(record["name"])
                if group is None:
                    group = {"records": [], "state": "other", "verified": False, "explicit_state": False}
                    groups[identity].append(group)
                    active[identity] = group
                elif (_target_action(record["action"], target_name) and section in STATES
                      and group["state"] in STATES and group["explicit_state"] and section != group["state"]
                      and not re.search(r"(?i)\b(?:verify|verification|query|readback)\b", record["name"])):
                    if group["verified"]:
                        group = {"records": [], "state": "other", "verified": False, "explicit_state": False}
                        groups[identity].append(group)
                        active[identity] = group
                    else:
                        catalog["errors"].append("ambiguous reused testcase state: " + safe_label(identity))
                if _target_action(record["action"], target_name) and group["state"] == "other":
                    group["state"] = record["state"] if record["state"] in STATES else "other"
                    group["explicit_state"] = section == group["state"]
                if record["verification"]:
                    group["verified"] = True
                group["records"].append(record)
            elif _target_action(record["action"], target_name) and not record["base"] and not record["cleanup"]:
                catalog["untagged_actions"] += 1
        for identity, chapters in groups.items():
            for ordinal, group in enumerate(chapters, 1):
                case_id = identity if len(chapters) == 1 else identity + "::" + group["state"].upper() + "_" + str(ordinal)
                case = {"label": safe_label(case_id.split("::", 1)[1].replace("::", " ")),
                        "state": group["state"], "tasks": set(), "assertions": set(),
                        "module_actions": [], "skip_notices": set()}
                for record in group["records"]:
                    record["case"] = case_id
                    case["tasks"].add(record["key"])
                    if record["verification"]:
                        case["assertions"].add(record["key"])
                    if _target_action(record["action"], target_name):
                        case["module_actions"].append(record)
                    if record["applicability"]:
                        case["skip_notices"].add(record["key"])
                catalog["cases"][case_id] = case
        for record in records:
            catalog["tasks"].setdefault(record["name"], []).append(record)
    return catalog


def _json_value(value):
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    return value


def _json_digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_json(path, limit):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("reporting metadata is missing, oversized or a symlink")
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError("reporting metadata exceeds safe limits")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("reporting metadata must be a JSON object")
    return value


def _source_fingerprint(collection_root, module):
    target_name = MODULE_ALIASES.get(module.split(".", 1)[0], module.split(".", 1)[0])
    target = Path(collection_root) / "tests" / "integration" / "targets" / target_name
    records = []
    if not target.is_dir() or target.is_symlink():
        return target_name, records, _json_digest({"target": target_name, "available": False})
    files = sorted(set(target.rglob("*.yaml")) | set(target.rglob("*.yml")))
    if len(files) > MAX_SOURCE_FILES:
        raise ValueError("integration target exceeds source file limit")
    total = 0
    for path in files:
        relative = path.relative_to(target)
        if any(part in {"defaults", "vars", "files", "meta", "templates"} for part in relative.parts):
            continue
        if path.is_symlink() or path.stat().st_size > MAX_SOURCE_BYTES:
            raise ValueError("catalog source is oversized or a symlink")
        data = _source_bytes(path)
        total += len(data)
        if len(data) > MAX_SOURCE_BYTES or total > MAX_CATALOG_SOURCE_BYTES:
            raise ValueError("catalog source exceeds safe byte limits")
        records.append({"path": relative.as_posix(), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return target_name, records, _json_digest({"target": target_name, "files": records})


def _restore_catalog(value):
    if not isinstance(value, dict) or not isinstance(value.get("tasks"), dict) or not isinstance(value.get("cases"), dict):
        raise ValueError("frozen catalog schema is invalid")
    if sum(len(tasks) for tasks in value["tasks"].values()) > MAX_SOURCE_TASKS:
        raise ValueError("frozen catalog exceeds safe task limits")
    restored = dict(value, ignored_names=set(value.get("ignored_names", [])), cases={})
    for identity, case in value["cases"].items():
        restored["cases"][identity] = dict(case, tasks=set(case["tasks"]), assertions=set(case["assertions"]),
                                           skip_notices=set(case.get("skip_notices", [])))
    return restored


def validate_frozen_catalog(value, module):
    """Validate a decoded snapshot without mutating the caller's JSON object."""
    if not isinstance(value, dict):
        raise ValueError("frozen catalog must be a JSON object")
    target = MODULE_ALIASES.get(module.split(".", 1)[0], module.split(".", 1)[0])
    if (value.get("schema_version") != SCHEMA_VERSION or value.get("catalog_version") != CATALOG_VERSION or
            value.get("module") != module or value.get("target") != target or
            value.get("catalog_sha256") != _json_digest(value.get("catalog"))):
        raise ValueError("frozen catalog identity or digest mismatch")
    if value["catalog"].get("target") != target:
        raise ValueError("frozen catalog target mismatch")
    return dict(value, catalog=_restore_catalog(value["catalog"]))


def read_frozen_catalog(path, module):
    """Read an immutable catalog without consulting later rewritten sources."""
    return validate_frozen_catalog(_read_json(path, MAX_CATALOG_BYTES), module)


def freeze_catalog(collection_root, module, output_path, cache_dir=None):
    """Compile once per actual source fingerprint, including uncommitted edits."""
    target, files, fingerprint = _source_fingerprint(collection_root, module)
    destination = Path(output_path)
    cache_path = None
    if cache_dir is not None:
        key = _json_digest({"module": module, "catalog_version": CATALOG_VERSION,
                            "source_fingerprint": fingerprint})
        cache_path = Path(cache_dir) / (key + ".catalog.json")
    for candidate in (destination, cache_path):
        if candidate is None or not candidate.exists():
            continue
        try:
            cached = read_frozen_catalog(candidate, module)
            if cached.get("source_fingerprint") == fingerprint and not cached["catalog"].get("errors"):
                cached["catalog"] = _json_value(cached["catalog"])
                if candidate != destination:
                    atomic_json(destination, cached)
                return cached
        except (OSError, ValueError, TypeError, KeyError):
            pass
    catalog = load_catalog(collection_root, module)
    if _source_fingerprint(collection_root, module)[2] != fingerprint:
        raise ValueError("catalog source changed during compilation")
    encoded = _json_value(catalog)
    value = {"schema_version": SCHEMA_VERSION, "catalog_version": CATALOG_VERSION,
             "module": module, "target": target, "source_fingerprint": fingerprint,
             "source_files": files, "catalog_sha256": _json_digest(encoded), "catalog": encoded}
    if len(json.dumps(value)) > MAX_CATALOG_BYTES:
        raise ValueError("frozen catalog exceeds safe byte limits")
    if cache_path is not None and cache_path != destination:
        atomic_json(cache_path, value)
    atomic_json(destination, value)
    return value


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


def summarize_lines(log, module, run_id, build, fabric, collection_root, test_type="integration", lines=None, catalog_path=None):
    """Apply one authored-case reducer to a bounded normalized line iterable.

    ``log`` still identifies the wrapper's real execution metadata. Supplying
    ``lines`` lets recovery combine collectors behind one physical log read.
    """
    frozen = read_frozen_catalog(catalog_path, module) if catalog_path and test_type == "integration" else None
    catalog = (frozen["catalog"] if frozen else load_catalog(collection_root, module)) if test_type == "integration" else {
        "target": "", "tasks": {}, "cases": {}, "errors": ["smoke playbooks have no module integration case catalog"],
        "untagged_actions": 0, "ignored_names": set(),
    }
    return _summarize_catalog(log, module, run_id, build, fabric, collection_root, test_type,
                              lines=lines, catalog=catalog, frozen=frozen)


def _summarize_catalog(log, module, run_id, build, fabric, collection_root, test_type, *, lines, catalog, frozen):
    """Common reducer; its caller supplies an already validated catalog once."""
    result = {
        "schema_version": SCHEMA_VERSION, "module": module, "run_id": run_id,
        "build": str(build), "fabric": fabric, "test_type": test_type,
        "validated": False, "coverage": "UNKNOWN", "counts": {state: None for state in STATES},
        "testcase_totals": {key: None for key in ("started", "passed", "failed", "skipped", "incomplete")},
        "other_cases": None, "base": "Not observed", "cleanup": "Not observed",
        "result": "UNKNOWN", "failure": [], "notes": [],
        "case_results": [], "evidence_truncated": False,
        "count_unit": "distinct authored source chapter (suite/file + TC identifier, disambiguated by tested state); state columns count started cases",
        "exclusions": "pipeline/harness tasks, role discovery/includes, setup, prerequisites and cleanup",
    }
    if frozen:
        result["catalog_sha256"] = frozen["catalog_sha256"]
        result["source_fingerprint"] = frozen["source_fingerprint"]
    observed = defaultdict(lambda: defaultdict(set))
    phase_outcomes = {"base": set(), "cleanup": set()}
    runner_outcomes = {"base": set(), "cleanup": set()}
    untagged_seen = set()
    markers, modules = set(), set()
    state = {"current": None, "recap": False, "recap_rows": 0, "recap_failed": 0,
             "exit_code": None, "exit_conflict": False,
             "module_skip": False, "outside_failure": False, "outside_reasons": set(), "unmatched_case": False,
             "last_case": None, "last_path": None}

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
        if event.get("line", 0) and event["line"] > 0:
            # A real source position must match. Falling back to a familiar
            # display name would accept drifted or stale task evidence.
            candidates = [item for item in candidates if item.get("line") == event["line"]]
        # Quiet raw logs lack positions. An unnamed verification may be linked
        # only to one task in the most recently identified source case. If two
        # candidates remain, retain unknown evidence rather than guess by name.
        if len(candidates) > 1 and state["last_case"]:
            contextual = [item for item in candidates if item["case"] == state["last_case"]
                          and item["path"] == state["last_path"]]
            if len(contextual) == 1:
                candidates = contextual
        identities = {(item["path"], item.get("key", item["name"]), item["case"], item["base"], item["cleanup"]) for item in candidates}
        if len(identities) != 1:
            owns_path = bool(event["path"] and ("/tests/integration/targets/" + catalog["target"] + "/") in event["path"])
            authored_name = any(item["case"] for item in catalog["tasks"].get(event["name"], []))
            if (role_matches or owns_path) and (CASE_ID.search(event["name"]) or authored_name):
                state["unmatched_case"] = True
                state["last_case"], state["last_path"] = None, None
            if "failed" in event["outcomes"] and not event["ignored"]:
                state["outside_failure"] = True
                state["outside_reasons"].update(event["reasons"])
            return
        record = candidates[0]
        if record["case"]:
            state["last_case"], state["last_path"] = record["case"], record["path"]
        elif record["base"] or record["cleanup"]:
            state["last_case"], state["last_path"] = None, None
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
            observed[identity][record.get("key", record["name"])].update(outcomes)
            if "failed" in outcomes:
                label = catalog["cases"][identity]["label"] + ": " + safe_label(record["name"])
                add_failure(with_reason(label, event))
        elif _target_action(record["action"], catalog["target"]) and not record["base"] and not record["cleanup"]:
            untagged_seen.add((record["path"], record["name"]))
        if not identity and "failed" in outcomes:
            phase = "module base" if record["base"] else "module cleanup" if record["cleanup"] else "unlabelled module task"
            add_failure(with_reason(phase + ": " + record["name"], event))

    try:
        for line in line_stream(log) if lines is None else lines:
            line = re.sub(r"\x1b\[[0-9;]*m", "", line).rstrip("\r\n")
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
                                    "role": role if separator else "", "path": "", "line": None, "outcomes": set(), "ignored": False, "reasons": set()}
                continue
            event = state["current"]
            if event:
                match = SOURCE_PATH.match(line)
                if match:
                    event["path"] = match.group(1).replace("\\", "/")
                    event["line"] = int(match.group(2))
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
    def record_case(identity, case, outcome, reason=None):
        if len(result["case_results"]) >= MAX_CASE_EVIDENCE:
            result["evidence_truncated"] = True
            return
        # Normal authored IDs remain readable; unusually large IDs retain a
        # stable digest instead of growing the summary without a bound.
        label_id = identity if len(identity) <= 512 else "sha256:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()
        evidence = {"id": label_id, "label": case["label"], "state": case["state"], "outcome": outcome}
        if reason:
            evidence["reason"] = safe_label(reason)
        result["case_results"].append(evidence)
    for identity, tasks in observed.items():
        case = catalog["cases"][identity]
        notices = case.get("skip_notices", set())
        work = {key: value for key, value in tasks.items() if key not in notices}
        if not work:
            # An applicability notice by itself proves no action or whole-case skip.
            partly_skipped_not_started += 1
            record_case(identity, case, "incomplete")
            continue
        outcomes = set().union(*work.values())
        if outcomes == {"skipped"}:
            required = case["assertions"] | {action.get("key", action["name"]) for action in case["module_actions"]}
            if required and all(name in tasks for name in required):
                totals["skipped"] += 1
                reasons = [record.get("skip_reason") for records in catalog["tasks"].values() for record in records
                           if record.get("key") in notices and "ok" in tasks.get(record.get("key"), set())
                           and record.get("skip_reason")]
                record_case(identity, case, "skipped", "; ".join(dict.fromkeys(reasons)))
            else:
                # An early skip followed by an aborted play is insufficient
                # evidence that the entire authored case was skipped.
                partly_skipped_not_started += 1
                record_case(identity, case, "incomplete")
            continue
        totals["started"] += 1
        if case["state"] in STATES:
            result["identified_case_counts"][case["state"]] += 1
        else:
            other += 1
        if "failed" in outcomes:
            totals["failed"] += 1
            record_case(identity, case, "failed")
            continue
        assertions = case["assertions"]
        assertion_results = [tasks.get(name, set()) for name in assertions]
        all_assertions_observed = bool(assertions) and all(item and item <= {"ok", "skipped"} for item in assertion_results)
        assertion_passed = any("ok" in item for item in assertion_results)
        all_actions_observed = all(action.get("key", action["name"]) in tasks for action in case["module_actions"])
        if all_assertions_observed and assertion_passed and all_actions_observed:
            totals["passed"] += 1
            record_case(identity, case, "passed")
        else:
            totals["incomplete"] += 1
            record_case(identity, case, "incomplete")
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
    if totals["incomplete"] or partly_skipped_not_started:
        if not partial:
            result["coverage"] = "INCOMPLETE"
        result["notes"].append("incomplete means required source verification was not observed; it is not a pass or a skip")
    if partly_skipped_not_started:
        result["notes"].append("%d cases have only partial skip evidence; not counted as started or skipped" % partly_skipped_not_started)
    return result


def summarize(log, module, run_id, build, fabric, collection_root, test_type="integration", catalog_path=None):
    """Backward-compatible bounded raw-log adapter."""
    return summarize_lines(log, module, run_id, build, fabric, collection_root, test_type,
                           catalog_path=catalog_path)


def _event_task_metadata(record, catalog, position_index):
    """Resolve source positions without reading any path supplied by an event."""
    name = normal_name(record.get("name"))
    if " : " in name:
        name = name.partition(" : ")[2]
    path = str(record.get("path") or "").replace("\\", "/")
    role = normal_name(record.get("role"))
    fragment = "/tests/integration/targets/" + catalog["target"] + "/"
    normalized = "/" + path.lstrip("/")
    relative = normalized.split(fragment, 1)[1] if fragment in normalized else None
    candidates = []
    line = record.get("line")
    if relative and isinstance(line, int) and not isinstance(line, bool):
        candidates = position_index.get((relative, line), [])
        if len({item["name"] for item in candidates}) == 1:
            name = candidates[0]["name"]
    if not candidates:
        candidates = catalog["tasks"].get(name, [])
        if relative:
            candidates = [item for item in candidates if item["path"] == relative]
    if relative:
        # A pinned source path is sufficient evidence for standalone targets
        # and is stronger than a display role alias.
        path, role = fragment + relative, ""
    required = any(item.get("case") and (item.get("verification") or _target_action(item["action"], catalog["target"])) for item in candidates)
    action = str(record.get("action") or "").rsplit(".", 1)[-1]
    if relative and not candidates and (CASE_ID.search(name) or _target_action(action, catalog["target"])):
        # Keep unmatched owned work explicitly ambiguous in the common reducer.
        name = name if CASE_ID.search(name) else "STRUCTURED_UNMATCHED TC0"
    return {"name": name or "unidentified structured task", "path": path,
            "line": line if isinstance(line, int) and not isinstance(line, bool) else None,
            "role": role, "required": required}


def summarize_events(log, module, run_id, build, fabric, collection_root, test_type="integration", catalog_path=None,
                     catalog_snapshot=None):
    """Reduce a closed, validated event journal through the same case rules.

    Invalid or incomplete structured evidence raises ``ValueError`` so the
    caller can run the bounded raw-log recovery adapter. No journal result
    payloads are copied into activity metadata.

    A coordinator that already decoded its immutable snapshot may supply it as
    ``catalog_snapshot``; identity/digest checks still apply to that object.
    """
    metadata = _read_json(str(log) + ".event-summary.json", 256 * 1024)
    if (metadata.get("schema_version") != SCHEMA_VERSION or metadata.get("module") != module or
            metadata.get("run_id") != run_id or metadata.get("completed") is not True or
            metadata.get("capture_error") or metadata.get("errors")):
        raise ValueError("structured event summary is incomplete or belongs to another execution")
    invocation = metadata.get("invocation_id")
    if not isinstance(invocation, str) or not invocation or len(invocation) > 160:
        raise ValueError("structured event invocation identity is missing")
    count = metadata.get("event_count")
    if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= MAX_EVENT_RECORDS:
        raise ValueError("structured event count is invalid")
    expected_digest = metadata.get("event_sha256")
    if not isinstance(expected_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise ValueError("structured event digest is invalid")
    counts = metadata.get("counts")
    counters = ("ok", "changed", "failed", "unreachable", "skipped", "rescued", "ignored")
    if not isinstance(counts, dict) or any(not isinstance(counts.get(key), int) or isinstance(counts.get(key), bool) or counts[key] < 0 for key in counters):
        raise ValueError("structured recap counters are invalid")
    recap_rows = metadata.get("recap_rows", metadata.get("host_count"))
    if not isinstance(recap_rows, int) or isinstance(recap_rows, bool) or recap_rows <= 0:
        raise ValueError("structured execution has no completed host recap")
    exit_code, execution_error = execution_exit(log, module, run_id)
    if execution_error or exit_code is None:
        raise ValueError("structured execution requires valid wrapper exit metadata")
    if not Path(str(log) + ".execution.json").is_file():
        raise ValueError("structured execution requires wrapper exit metadata")
    frozen = (validate_frozen_catalog(catalog_snapshot, module) if catalog_snapshot is not None
              else read_frozen_catalog(catalog_path, module) if catalog_path else None) if test_type == "integration" else None
    catalog = (frozen["catalog"] if frozen else load_catalog(collection_root, module)) if test_type == "integration" else {
        "target": "", "tasks": {}, "cases": {}, "errors": ["smoke playbooks have no module integration case catalog"],
        "untagged_actions": 0, "ignored_names": set(),
    }
    positions = defaultdict(list)
    for tasks in catalog["tasks"].values():
        for task in tasks:
            positions[(task["path"], task.get("line"))].append(task)
    journal = Path(str(log) + ".events.jsonl")
    if journal.is_symlink() or not journal.is_file() or journal.stat().st_size > MAX_EVENT_BYTES:
        raise ValueError("structured journal is missing, oversized or a symlink")
    digest = hashlib.sha256()
    sequence, total_bytes = 0, 0
    starts, groups, inferred = {}, {}, defaultdict(int)
    allowed_reasons = {reason for _, reason in FAILURE_REASONS}
    with journal.open("rb") as source:
        while True:
            raw = source.readline(MAX_EVENT_LINE + 1)
            if not raw:
                break
            sequence += 1
            total_bytes += len(raw)
            if sequence > MAX_EVENT_RECORDS or total_bytes > MAX_EVENT_BYTES or len(raw) > MAX_EVENT_LINE or not raw.endswith(b"\n"):
                raise ValueError("structured journal exceeds bounds or has a partial record")
            digest.update(raw)
            try:
                event = json.loads(raw)
            except (ValueError, UnicodeError):
                raise ValueError("structured journal contains an invalid record") from None
            if not isinstance(event, dict) or event.get("schema_version") != SCHEMA_VERSION or event.get("module") != module or event.get("run_id") != run_id or event.get("invocation_id") != invocation or event.get("seq") != sequence:
                raise ValueError("structured journal identity or sequence mismatch")
            kind = event.get("kind")
            if kind not in {"task", "outcome"}:
                raise ValueError("structured journal event kind is unsupported")
            for key, limit in (("task_uuid", 160), ("name", 4096), ("path", 4096), ("host", 256), ("role", 256)):
                value = event.get(key, "")
                if not isinstance(value, str) or len(value) > limit or any(character in value for character in ("\r", "\n", "\x00")):
                    raise ValueError("structured event metadata exceeds safe limits")
            task = event.get("task_uuid")
            if not task:
                raise ValueError("structured task identity is missing")
            if "task_instance" in event:
                instance = event["task_instance"]
                if not isinstance(instance, int) or isinstance(instance, bool) or instance < 0:
                    raise ValueError("structured task instance is invalid")
            else:
                if kind == "task":
                    inferred[task] += 1
                instance = inferred[task]
            task_key = (task, instance)
            if kind == "task":
                if task_key in starts:
                    raise ValueError("structured task start is duplicated")
                starts[task_key] = _event_task_metadata(event, catalog, positions)
            else:
                outcome = event.get("outcome")
                if outcome not in {"ok", "failed", "unreachable", "skipped"}:
                    raise ValueError("structured terminal outcome is invalid")
                reasons = event.get("reason_codes", [])
                if not isinstance(reasons, list) or len(reasons) > len(allowed_reasons) or any(not isinstance(reason, str) or reason not in allowed_reasons for reason in reasons):
                    raise ValueError("structured failure reason code is invalid")
                if any(key in event and not isinstance(event[key], bool) for key in ("ignored", "item", "terminal")):
                    raise ValueError("structured outcome flags are invalid")
                host = event.get("host", "")
                key = (task, instance, host)
                group = groups.setdefault(key, {"meta": _event_task_metadata(event, catalog, positions), "parent": None,
                                                 "items": set(), "item_reasons": set()})
                if event.get("terminal", not event.get("item", False)):
                    terminal = {"outcome": outcome, "ignored": bool(event.get("ignored")), "reasons": set(reasons)}
                    if group["parent"] is not None and group["parent"] != terminal:
                        raise ValueError("structured parent outcome conflicts with an earlier terminal result")
                    group["parent"] = terminal
                else:
                    group["items"].add(outcome)
                    group["item_reasons"].update(reasons)
            if len(starts) > MAX_EVENT_TASKS or len(groups) > MAX_EVENT_RECORDS:
                raise ValueError("structured execution exceeds safe task limits")
    if sequence != count or digest.hexdigest() != expected_digest:
        raise ValueError("structured journal count or digest mismatch")
    if "event_bytes" in metadata and metadata["event_bytes"] != total_bytes:
        raise ValueError("structured journal byte count mismatch")
    for key, group in groups.items():
        if group["parent"] is None and group["meta"]["required"]:
            raise ValueError("structured authored task has no terminal parent outcome")
    tasks_with_results = {key[:2] for key in groups}
    if any(meta["required"] and key not in tasks_with_results for key, meta in starts.items()):
        raise ValueError("structured authored task started without an outcome")

    def normalized_lines():
        marker = "PLAYBOOK" if test_type == "smoke" else "MODULE"
        yield "[%s: %s] Execution completed." % (marker, module)
        yield "[RUN_MARKER: %s]" % run_id
        for key, group in groups.items():
            meta = group["meta"]
            body = (meta["role"] + " : " if meta["role"] else "") + meta["name"]
            yield "TASK [%s] ***" % body
            if meta["path"]:
                yield "task path: %s:%s" % (meta["path"], meta.get("line") or 0)
            parent = group["parent"]
            outcomes = {parent["outcome"]} if parent is not None else group["items"]
            for outcome in sorted(outcomes):
                yield {"ok": "ok: [structured]", "failed": "fatal: [structured]",
                       "unreachable": "fatal: [structured]", "skipped": "skipping: [structured]"}[outcome]
            for reason in sorted(parent["reasons"] if parent is not None else group["item_reasons"]):
                yield reason
            if parent is not None and parent["ignored"]:
                yield "...ignoring"
        if metadata.get("module_skipped"):
            yield "NDP_MODULE_SKIPPED: declared lab substrate unavailable"
        yield "PLAY RECAP"
        yield "structured : " + " ".join("%s=%s" % (key, counts[key]) for key in ("ok", "changed", "unreachable", "failed", "skipped", "rescued", "ignored"))
        yield "[ANSIBLE_EXIT_STATUS: %s]" % exit_code

    result = _summarize_catalog(log, module, run_id, build, fabric, collection_root, test_type,
                               lines=normalized_lines(), catalog=catalog, frozen=frozen)
    result.update(summary_source="events", structured_validated=True,
                  event_count=sequence, event_sha256=expected_digest)
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
    for mode, help_text in (("summarize", "stream one run log into a case-activity JSON sidecar"),
                            ("events", "reduce a validated closed event journal into case activity")):
        command = commands.add_parser(mode, help=help_text)
        for name in ("log", "module", "run-id", "build", "fabric", "collection-root"):
            command.add_argument("--" + name, required=True)
        command.add_argument("--test-type", choices=("integration", "smoke"), default="integration")
        command.add_argument("--catalog", help="immutable frozen catalog JSON")
        command.add_argument("--output", help="default: LOG.activity.json")
    command = commands.add_parser("catalog", help="freeze and optionally cache an authored-case catalog")
    for name in ("module", "collection-root", "output"):
        command.add_argument("--" + name, required=True)
    command.add_argument("--cache-dir")
    arguments = parser.parse_args()
    if arguments.command == "catalog":
        freeze_catalog(arguments.collection_root, arguments.module, arguments.output, arguments.cache_dir)
        return 0
    collect = summarize_events if arguments.command == "events" else summarize
    value = collect(arguments.log, arguments.module, arguments.run_id, arguments.build,
                    arguments.fabric, arguments.collection_root, arguments.test_type,
                    catalog_path=arguments.catalog)
    atomic_json(arguments.output or arguments.log + ".activity.json", value)
    return 0 if value["validated"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
