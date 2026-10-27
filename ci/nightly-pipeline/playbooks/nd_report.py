"""Concise Ansible stdout and controller-local phase measurements."""

import copy
import json
import os
import tempfile
import time

from ansible.plugins.callback.default import CallbackModule as DefaultCallback
from ansible.plugins.callback.default import DOCUMENTATION as DEFAULT_DOCUMENTATION


DOCUMENTATION = DEFAULT_DOCUMENTATION.replace("name: default", "name: nd_report")


class CallbackModule(DefaultCallback):
    CALLBACK_NAME = "nd_report"

    def __init__(self):
        super().__init__()
        self.phase = os.environ.get("ND_RESULT_PHASE", "execution")
        self.phase_seconds = {"prerequisites": None, "execution": None, "cleanup": None}
        self.started = time.monotonic()
        self.module_skipped = False
        self.debug = os.environ.get("ND_REPORT_DEBUG", "false") == "true"

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
        descriptor, temporary = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)))
        try:
            with os.fdopen(descriptor, "w") as output:
                json.dump(value, output)
            os.replace(temporary, path + ".phases.json")
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _close_phase(self):
        now = time.monotonic()
        self.phase_seconds[self.phase] = round((self.phase_seconds[self.phase] or 0) + now - self.started, 6)
        self.started = now

    def _compact(self, result):
        payload = result._result
        message = payload.get("msg", "")
        if not payload.get("_ansible_no_log") and isinstance(message, str) and "NDP_MODULE_SKIPPED" in message:
            self.module_skipped = True
        if self.debug:
            return result
        compact = copy.copy(result)
        compact._result = {
            key: value for key, value in payload.items()
            if key in ("changed", "_ansible_no_log", "_ansible_item_label", "ansible_loop_var")
        }
        if self.module_skipped and isinstance(message, str) and "NDP_MODULE_SKIPPED" in message:
            compact._result["msg"] = "NDP_MODULE_SKIPPED: declared lab substrate unavailable"
        return compact

    def v2_runner_on_ok(self, result):
        for phase in self.phase_seconds:
            if "nd_phase_" + phase in result._task.tags and phase != self.phase:
                self._close_phase()
                self.phase = phase
                self._save()
                break
        super().v2_runner_on_ok(self._compact(result))

    def v2_runner_item_on_ok(self, result):
        super().v2_runner_item_on_ok(self._compact(result))

    def v2_playbook_on_stats(self, stats):
        self._close_phase()
        self._save(completed=True)
        super().v2_playbook_on_stats(stats)