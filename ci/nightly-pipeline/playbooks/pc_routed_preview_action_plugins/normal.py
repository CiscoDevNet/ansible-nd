"""Pipeline-only diagnostic for cisco.nd issue #652; collection sources stay unchanged.

Immediately before the authored routed delete check, record the pending lines of
ND's read-only interface preview for port-channel520, then run the task unchanged.
"""
import json
from collections.abc import Mapping
from urllib.parse import quote

from ansible.module_utils.connection import Connection
from ansible.plugins.loader import action_loader
from ansible.utils.display import Display


# A direct normal import would resolve this override again. The builtin FQCN
# deliberately bypasses local action paths and retains Ansible's normal behavior.
BuiltinNormalAction = action_loader.get("ansible.builtin.normal", class_only=True)
TARGET_ACTION = "cisco.nd.nd_interface_port_channel_routed"
TARGET_TASK = "DELETED RECONCILE: Check exact staged delete with deployment enabled"
TARGET_INTERFACE = "port-channel520"
ENABLE_VAR = "nd_pipeline_pc_routed_preview_capture"
MARKER = "NDP_PC_ROUTED_DELETE_PREVIEW"
MAX_LINES = 500
DISPLAY = Display()


def _data(info, what):
    code = info.get("RETURN_CODE") if isinstance(info, Mapping) else None
    if not isinstance(code, int) or not 200 <= code < 300:
        raise ValueError("%s returned HTTP %s" % (what, code))
    return info.get("DATA")


def _switch_serial(connection, base, switch_ip):
    switches = _data(connection.send_request("GET", base + "/switches"), "switch inventory")
    rows = switches.get("switches") if isinstance(switches, Mapping) else None
    serials = sorted({str(row.get("switchId")) for row in rows or [] if isinstance(row, Mapping)
                      and row.get("fabricManagementIp") == switch_ip and row.get("switchId")})
    if len(serials) != 1:
        raise ValueError("expected one switchId for the test switch, found %d" % len(serials))
    return serials[0]


def _report(diffs, interface, switch_ip, clean):
    report = ["%s_BEGIN interface=%s switch_ip=%s rows=%d" % (MARKER, interface, switch_ip, len(diffs))]
    count = 0
    for row_index, row in enumerate(diffs):
        row = row if isinstance(row, Mapping) else {}
        report.append("%s row=%d interfaceName=%s status=%s" % (
            MARKER, row_index, clean(row.get("interfaceName")), clean(row.get("status"))))
        configs = row.get("combinedConfigs") if isinstance(row.get("combinedConfigs"), list) else []
        pending = [item.get("config") for item in configs if isinstance(item, Mapping)
                   and str(item.get("configType") or "").strip().lower() == "pending"]
        for pending_index, config in enumerate(pending):
            for line in str(config or "").splitlines():
                if count >= MAX_LINES:
                    report.append("%s truncated_after=%d" % (MARKER, MAX_LINES))
                    report.append("%s_END pending_lines=%d" % (MARKER, count))
                    return report
                # JSON quoting keeps leading/trailing whitespace and blank lines visible.
                report.append("%s row=%d pending=%d line[%02d]=%s" % (
                    MARKER, row_index, pending_index, count, json.dumps(clean(line))))
                count += 1
    report.append("%s_END pending_lines=%d" % (MARKER, count))
    return report


def capture(connection, fabric, switch_ip, interface=TARGET_INTERFACE):
    """Return report lines in ND's original order; the switch serial is shown as <serial>."""
    connection.set_params({})
    base = "/api/v1/manage/fabrics/%s" % quote(fabric, safe="")
    serial = _switch_serial(connection, base, switch_ip)

    def clean(value):
        return str(value).replace(serial, "<serial>")

    try:
        body = json.dumps({"interfaces": [{"interfaceName": interface, "switchId": serial}]})
        preview = _data(connection.send_request("POST", base + "/interfaceActions/preview", body), "preview")
        diffs = preview.get("configurationDiffs") if isinstance(preview, Mapping) else None
        if not isinstance(diffs, list):
            raise ValueError("preview response has no configurationDiffs list")
        return _report(diffs, interface, switch_ip, clean)
    except Exception as error:
        raise ValueError("%s: %s" % (type(error).__name__, clean(error))) from None


class ActionModule(BuiltinNormalAction):
    def _target_switch_ip(self, task_vars):
        actions = {self._task.action, getattr(self._task, "resolved_action", None)}
        if (TARGET_ACTION not in actions or self._task.name != TARGET_TASK
                or (task_vars or {}).get(ENABLE_VAR) is not True
                or not isinstance(self._task.args.get("fabric_name"), str)):
            return None
        for item in self._task.args.get("config") or []:
            if (isinstance(item, Mapping) and item.get("interface_name") == TARGET_INTERFACE
                    and isinstance(item.get("switch_ip"), str)):
                return item["switch_ip"]
        return None

    def run(self, tmp=None, task_vars=None):
        try:
            switch_ip = self._target_switch_ip(task_vars)
            if switch_ip is not None:
                socket_path = getattr(self._connection, "socket_path", None) or (task_vars or {}).get("ansible_socket")
                if not socket_path:
                    raise ValueError("no persistent connection socket")
                report = capture(Connection(socket_path), self._task.args["fabric_name"], switch_ip)
                DISPLAY.display("\n".join(report))
        except Exception as error:  # noqa: BLE001 - diagnostics must never change the authored result
            DISPLAY.display("%s_UNAVAILABLE reason=%s: %s" % (MARKER, type(error).__name__, str(error)[:300]))
        return super().run(tmp, task_vars)
