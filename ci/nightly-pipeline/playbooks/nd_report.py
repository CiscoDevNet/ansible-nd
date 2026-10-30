"""Concise stdout, phase measurements and bounded structured result capture.

The event journal contains task identity and outcomes, never result payloads.
Its final stats record is provisional: the invoking wrapper must still validate
the real process exit, required cleanup and closed log before publishing a run.
"""

import hashlib
import json
import os
import re
import tempfile
import time
import uuid

from ansible.plugins.callback.default import CallbackModule as DefaultCallback
from ansible.plugins.callback.default import DOCUMENTATION as DEFAULT_DOCUMENTATION


DOCUMENTATION = DEFAULT_DOCUMENTATION.replace("name: default", "name: nd_report")

COUNTERS = ("ok", "changed", "failed", "unreachable", "skipped", "rescued", "ignored")
MAX_EVENTS = 100000
MAX_EVENT_BYTES = 8192
MAX_JOURNAL_BYTES = 32 * 1024 * 1024
MAX_FAILURE_LABELS = 20
REASON_PATTERNS = (
    (re.compile(r"No Commands to execute", re.I), "No Commands to execute"),
    (re.compile(r"Assertion failed", re.I), "Assertion failed"),
    (re.compile(r"unexpected link neighbor", re.I), "Unexpected link neighbor"),
    (re.compile(r"Deployment failed", re.I), "Deployment failed"),
    (re.compile(r"\bAttributeError\b"), "AttributeError"),
    (re.compile(r"\bTypeError\b"), "TypeError"),
    (re.compile(r"Request failed.{0,100}\b400\b", re.I), "Request failed (400)"),
    (re.compile(r"Request failed.{0,100}\b207\b", re.I), "Request failed (207)"),
)
CAPABILITY_PATTERNS = (
    re.compile(r"\b(?:n9k[-_ ]?c)?9300v\b", re.I),
    re.compile(r"virtual[ _-]+peer[ _-]*link|vpc[ _-]+fabric[ _-]+peering", re.I),
    re.compile(r"not supported|unsupported|does not support", re.I),
)


def _bounded(value, limit):
    return re.sub(r"[\r\n\t]+", " ", str(value or ""))[:limit]


def _failure_label(value):
    label = _bounded(value, 200)
    label = re.sub(r"https?://\S+", "[endpoint]", label, flags=re.I)
    label = re.sub(r"(?<!\w)(?:\d{1,3}\.){3}\d{1,3}(?!\w)", "[address]", label)
    label = re.sub(r"(?i)\b(?:password|token|secret|authorization)\s*[:=]\s*\S+", "[credential]", label)
    return label.replace("|", "/").replace("`", "'")


def _skip_evidence(value):
    if not isinstance(value, str) or not value.strip():
        return ""
    text = _bounded(value, 1024)
    if re.search(r"password|passwd|pwd|token|secret|bearer|authorization|credential|community|username|private.?key|api.?key|auth[_-]?(?:pass|key)|priv[_-]?(?:pass|key)", text, re.I):
        return "Credential-related skip evidence withheld"
    # Retain authored applicability labels, not arbitrary quoted values.
    safe_literals = {"all", "merged", "replaced", "overridden", "deleted", "gathered",
                     "vxlanibgp", "vxlanebgp", "externalconnectivity", "nxos", "true", "false"}
    text = re.sub(r'''(['"])((?:\\.|(?!\1).)*)(?:\1|$)''',
                  lambda match: match.group(0) if match.group(2).lower() in safe_literals else "'[value redacted]'", text)
    text = re.sub(r"https?://\S+", "[endpoint]", text, flags=re.I)
    text = re.sub(r"(?<!\w)(?:\d{1,3}\.){3}\d{1,3}(?!\w)", "[address]", text)
    return text[:240]


class CallbackModule(DefaultCallback):
    CALLBACK_NAME = "nd_report"

    def __init__(self):
        super().__init__()
        requested_phase = os.environ.get("ND_RESULT_PHASE", "execution")
        self.phase = requested_phase if requested_phase in ("prerequisites", "execution", "cleanup") else "execution"
        self.phase_seconds = {"prerequisites": None, "execution": None, "cleanup": None}
        self.started = time.monotonic()
        self.module_skipped = False
        self.debug = os.environ.get("ND_REPORT_DEBUG", "false") == "true"
        self.invocation_id = uuid.uuid4().hex
        self.event_module = os.environ.get("ND_RESULT_MODULE", "")
        self.event_run_id = os.environ.get("TEST_RUN_MARKER", "")
        self.event_log = os.environ.get("ND_RESULT_LOG", "")
        self.event_count = 0
        self.event_bytes = 0
        self.event_digest = hashlib.sha256()
        self.event_errors = []
        if requested_phase != self.phase:
            self._capture_error("invalid initial phase")
        self.failure_tasks = []
        self.capability_tasks = []
        self._event_stream = None
        self._task_instances = {}
        self._host_instances = {}
        self._failure_records = {}
        self._open_events()
        self._save_event_summary(completed=False)

    def _capture_error(self, code):
        # Error codes are fixed labels; exception strings can contain secrets.
        if code not in self.event_errors and len(self.event_errors) < 8:
            self.event_errors.append(code)

    def _open_events(self):
        if not self.event_log:
            return
        if not self.event_module or not self.event_run_id:
            self._capture_error("missing capture identity")
            return
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.event_log + ".events.jsonl", flags, 0o600)
            self._event_stream = os.fdopen(descriptor, "wb", buffering=65536)
        except Exception:
            self._capture_error("event journal unavailable")

    def _atomic_json(self, path, value):
        temporary = None
        try:
            descriptor, temporary = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)))
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(value, output, sort_keys=True)
                output.write("\n")
            os.replace(temporary, path)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)

    def _record_event(self, event):
        if self._event_stream is None or self.event_errors:
            return
        try:
            record = {
                "schema_version": 1, "module": self.event_module, "run_id": self.event_run_id,
                "invocation_id": self.invocation_id, "seq": self.event_count + 1,
                "phase": self.phase,
            }
            record.update(event)
            encoded = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")
            if self.event_count >= MAX_EVENTS or len(encoded) > MAX_EVENT_BYTES or self.event_bytes + len(encoded) > MAX_JOURNAL_BYTES:
                self._capture_error("event capture limit exceeded")
                return
            self._event_stream.write(encoded)
            self.event_digest.update(encoded)
            self.event_count += 1
            self.event_bytes += len(encoded)
            if self.event_count % 32 == 0:
                self._event_stream.flush()
        except Exception:
            self._capture_error("event journal write failed")

    def _task_fields(self, task, no_log=False):
        task_uuid = _bounded(getattr(task, "_uuid", ""), 96)
        if not task_uuid:
            self._capture_error("missing task identity")
        try:
            source = task.get_path() or ""
        except Exception:
            source = ""
        if not isinstance(source, str):
            source = ""
        match = re.match(r"^(.*):(\d+)$", source)
        source, line = (match.group(1), int(match.group(2))) if match else (source, None)
        collection_root = os.environ.get("ND_REPORT_COLLECTION_ROOT") or os.environ.get("COLLECTIONS_DIRECTORY")
        if source and collection_root:
            try:
                absolute = os.path.abspath(source)
                root = os.path.abspath(collection_root)
                if os.path.commonpath((absolute, root)) == root:
                    source = os.path.relpath(absolute, root)
            except (OSError, ValueError):
                pass
        try:
            name = "" if no_log else task.get_name()
        except Exception:
            name = ""
        role = getattr(task, "_role", None)
        try:
            role_name = role.get_name() if role else ""
        except Exception:
            role_name = ""
        return {
            "task_uuid": task_uuid, "name": _bounded(name, 1024),
            "path": _bounded(source, 2048), "line": line,
            "action": _bounded(getattr(task, "action", ""), 160),
            "role": _bounded(role_name, 200), "no_log": bool(no_log),
        }

    def _task_start(self, task, prefix="TASK"):
        # DefaultCallback calls this for task/handler banners. Keeping capture in
        # this shared hook also preserves the original stdout behavior.
        if self._event_stream is not None and not self.event_errors:
            try:
                task_uuid = _bounded(getattr(task, "_uuid", ""), 96)
                self._task_instances[task_uuid] = self._task_instances.get(task_uuid, 0) + 1
                event = self._task_fields(task, bool(getattr(task, "no_log", False)))
                event.update(kind="task", task_instance=self._task_instances[task_uuid])
                self._record_event(event)
            except Exception:
                self._capture_error("task boundary capture failed")
        super()._task_start(task, prefix=prefix)

    def v2_runner_on_start(self, host, task):
        if self._event_stream is not None and not self.event_errors:
            task_uuid = _bounded(getattr(task, "_uuid", ""), 96)
            try:
                host_name = _bounded(host.get_name(), 200)
            except Exception:
                host_name = ""
            if len(self._host_instances) >= MAX_EVENTS:
                self._capture_error("event identity limit exceeded")
            else:
                self._host_instances[(task_uuid, host_name)] = self._task_instances.get(task_uuid, 0)
        super().v2_runner_on_start(host, task)

    def _capture_result(self, result, outcome, ignored=False, item=False):
        if self._event_stream is None or self.event_errors:
            return
        try:
            payload = result._result
            no_log = bool(payload.get("_ansible_no_log") or getattr(result._task, "no_log", False))
            message = payload.get("msg", "")
            if not no_log and isinstance(message, str) and "NDP_MODULE_SKIPPED" in message:
                self.module_skipped = True
            event = self._task_fields(result._task, no_log)
            try:
                host_name = _bounded(result._host.get_name(), 200)
            except Exception:
                host_name = ""
            event.update(
                kind="outcome", outcome=outcome, ignored=bool(ignored), item=bool(item),
                terminal=not item, host=host_name,
                task_instance=self._host_instances.get(
                    (event["task_uuid"], host_name), self._task_instances.get(event["task_uuid"], 0)),
            )
            if outcome == "skipped":
                if no_log:
                    event["skip_reason"] = "Reason withheld (no_log)"
                else:
                    for key in ("skip_reason", "false_condition"):
                        value = _skip_evidence(payload.get(key))
                        if value:
                            event[key] = value
            reasons = []
            capability = False
            if outcome in ("failed", "unreachable") and not no_log:
                # Inspect only bounded strings to derive fixed reason codes. No
                # message, exception, API body, argument or loop item is stored.
                parts = []
                for key in ("msg", "exception"):
                    value = payload.get(key)
                    if isinstance(value, str):
                        parts.append(value[:8192] + value[-8192:])
                evidence = " ".join(parts)
                reasons = [label for pattern, label in REASON_PATTERNS if pattern.search(evidence)]
                capability = all(pattern.search(evidence) for pattern in CAPABILITY_PATTERNS)
            if not item:
                # Parent task outcomes are authoritative for loop ignore/error
                # semantics. Items remain journal evidence, not duplicate cases.
                key = (event["task_uuid"], event["task_instance"], host_name)
                self._failure_records[key] = {
                    "failed": outcome in ("failed", "unreachable") and not ignored,
                    "label": _failure_label(event["name"] or "redacted or unidentified task"),
                    "capability": capability and not ignored,
                }
            event["reason_codes"] = reasons
            self._record_event(event)
        except Exception:
            self._capture_error("task event capture failed")

    def _save_event_summary(self, completed=False, counts=None, host_count=0):
        if not self.event_log:
            return
        value = {
            "schema_version": 1, "module": self.event_module, "run_id": self.event_run_id,
            "invocation_id": self.invocation_id, "completed": bool(completed and not self.event_errors),
            "event_count": self.event_count, "event_bytes": self.event_bytes,
            "event_sha256": self.event_digest.hexdigest(),
            "counts": counts if counts is not None else dict.fromkeys(COUNTERS, 0),
            "host_count": host_count, "recap_rows": host_count,
            "module_skipped": self.module_skipped, "phase_seconds": self.phase_seconds,
            "failure_tasks": self.failure_tasks, "capability_tasks": self.capability_tasks,
            "capture_error": bool(self.event_errors), "errors": list(self.event_errors),
            "scope": "provisional callback evidence; wrapper exit, cleanup and closure remain authoritative",
        }
        try:
            self._atomic_json(self.event_log + ".event-summary.json", value)
        except Exception:
            self._capture_error("event summary write failed")

    def _close_events(self):
        if self._event_stream is None:
            return
        stream = self._event_stream
        self._event_stream = None
        try:
            stream.flush()
        except Exception:
            self._capture_error("event journal close failed")
        finally:
            try:
                stream.close()
            except Exception:
                self._capture_error("event journal close failed")

    def _save(self, completed=False):
        path = os.environ.get("ND_RESULT_LOG")
        if not path:
            return
        value = {
            "run_id": os.environ.get("TEST_RUN_MARKER"),
            "module": os.environ.get("ND_RESULT_MODULE"),
            "phase_seconds": self.phase_seconds,
            "completed": completed,
            "module_skipped": self.module_skipped,
            "scope": "runner boundaries; target-internal setup/cleanup remain within execution",
        }
        try:
            self._atomic_json(path + ".phases.json", value)
        except Exception:
            self._capture_error("phase metadata write failed")

    def _close_phase(self):
        now = time.monotonic()
        self.phase_seconds[self.phase] = round((self.phase_seconds[self.phase] or 0) + now - self.started, 6)
        self.started = now

    def _compact(self, result):
        payload = result._result
        message = payload.get("msg", "")
        no_log = bool(payload.get("_ansible_no_log") or getattr(result._task, "no_log", False))
        module_skipped = not no_log and isinstance(message, str) and "NDP_MODULE_SKIPPED" in message
        if module_skipped:
            self.module_skipped = True
        if no_log:
            # Preserve censorship even when an older result omitted the flag.
            payload["_ansible_no_log"] = True
        if self.debug:
            return result
        compact_payload = {
            key: value for key, value in payload.items()
            if key in ("changed", "_ansible_no_log", "_ansible_item_label", "ansible_loop_var")
        }
        if module_skipped:
            compact_payload["msg"] = "NDP_MODULE_SKIPPED: declared lab substrate unavailable"
        # Ansible 2.19+ supplies a callback-local mutable mapping through a
        # getter-only _result property. Update that mapping; assigning _result
        # raises AttributeError and suppresses successful-result output.
        payload.clear()
        payload.update(compact_payload)
        return result

    def v2_runner_on_ok(self, result):
        for phase in self.phase_seconds:
            if "nd_phase_" + phase in result._task.tags and phase != self.phase:
                self._close_phase()
                self.phase = phase
                self._save()
                break
        self._capture_result(result, "ok")
        super().v2_runner_on_ok(self._compact(result))

    def v2_runner_item_on_ok(self, result):
        self._capture_result(result, "ok", item=True)
        super().v2_runner_item_on_ok(self._compact(result))

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._capture_result(result, "failed", ignored=ignore_errors)
        super().v2_runner_on_failed(result, ignore_errors=ignore_errors)

    def v2_runner_on_unreachable(self, result):
        self._capture_result(result, "unreachable", ignored=bool(getattr(result._task, "ignore_unreachable", False)))
        super().v2_runner_on_unreachable(result)

    def v2_runner_on_skipped(self, result):
        self._capture_result(result, "skipped")
        super().v2_runner_on_skipped(result)

    def v2_runner_item_on_failed(self, result):
        self._capture_result(result, "failed", ignored=bool(getattr(result._task, "ignore_errors", False)), item=True)
        super().v2_runner_item_on_failed(result)

    def v2_runner_item_on_skipped(self, result):
        self._capture_result(result, "skipped", item=True)
        super().v2_runner_item_on_skipped(result)

    def v2_runner_on_async_ok(self, result):
        self._capture_result(result, "ok")
        super().v2_runner_on_async_ok(result)

    def v2_runner_on_async_failed(self, result):
        self._capture_result(result, "failed", ignored=bool(getattr(result._task, "ignore_errors", False)))
        super().v2_runner_on_async_failed(result)

    def v2_playbook_on_stats(self, stats):
        self._close_phase()
        self._save(completed=True)
        counts = dict.fromkeys(COUNTERS, 0)
        host_count = 0
        try:
            for host in stats.processed:
                host_counts = stats.summarize(host)
                host_count += 1
                for name in COUNTERS:
                    value = host_counts.get("failures" if name == "failed" else name, 0)
                    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                        raise ValueError("invalid recap counter")
                    counts[name] += value
            if not host_count:
                self._capture_error("no recap hosts")
        except Exception:
            self._capture_error("invalid recap statistics")
        for record in self._failure_records.values():
            if not record["failed"]:
                continue
            label = record["label"]
            if label not in self.failure_tasks and len(self.failure_tasks) < MAX_FAILURE_LABELS:
                self.failure_tasks.append(label)
            if record["capability"] and label not in self.capability_tasks and len(self.capability_tasks) < MAX_FAILURE_LABELS:
                self.capability_tasks.append(label)
        self._close_events()
        self._save_event_summary(completed=True, counts=counts, host_count=host_count)
        super().v2_playbook_on_stats(stats)
