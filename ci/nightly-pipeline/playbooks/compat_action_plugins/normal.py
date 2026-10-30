"""Pipeline-only transport compatibility; collection sources stay unchanged."""
from collections.abc import Mapping

from ansible.plugins.loader import action_loader
from ansible.utils.display import Display


# A direct normal import would resolve this override again. The builtin FQCN
# deliberately bypasses local action paths and retains Ansible's normal behavior.
BuiltinNormalAction = action_loader.get("ansible.builtin.normal", class_only=True)
TARGETS = {"cisco.nd.nd_manage_community_list", "cisco.nd.nd_manage_extended_community_list"}
DISPLAY = Display()


class ActionModule(BuiltinNormalAction):
    def run(self, tmp=None, task_vars=None):
        variables = task_vars or {}
        original = self._task.args
        action = self._task.action
        timeout = original.get("timeout")
        if (action not in TARGETS or variables.get("nd_pipeline_community_timeout_compat") is not True
                or not isinstance(timeout, int) or isinstance(timeout, bool) or timeout != 300
                or variables.get("ansible_command_timeout") not in (300, "300")):
            return super().run(tmp, task_vars)

        # TaskExecutor has merged module_defaults by now. get_ds() retains the
        # original authored task, so explicit/unknown argument styles stay intact.
        source = self._task.get_ds()
        direct = source.get(action) if isinstance(source, Mapping) else None
        extra = source.get("args", {}) if isinstance(source, Mapping) else None
        if (not isinstance(direct, Mapping) or not isinstance(extra, Mapping)
                or "timeout" in direct or "timeout" in extra):
            return super().run(tmp, task_vars)

        self._task.args = dict(original)
        self._task.args.pop("timeout")
        try:
            DISPLAY.display("NDP_COMMUNITY_TIMEOUT_COMPAT: %s inherited timeout=300; "
                            "using ansible_command_timeout=300; collection sources unchanged" % action)
            return super().run(tmp, task_vars)
        finally:
            self._task.args = original
