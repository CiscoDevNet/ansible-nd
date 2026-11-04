import copy
import importlib.util
import json
import math
from pathlib import Path
import re
import time
from urllib.parse import quote

from ansible.module_utils.connection import Connection
from ansible.plugins.action import ActionBase


def registry_reservations(registry):
    if not isinstance(registry, dict) or not isinstance(registry.get("lab"), dict):
        raise ValueError("Invalid interface reservation registry")
    lab = registry["lab"]
    switches, allowlist, profiles = lab.get("switches"), lab.get("interface_allowlist"), registry.get("profiles")
    if not isinstance(switches, dict) or not switches or not isinstance(allowlist, dict) or not isinstance(profiles, dict):
        raise ValueError("Incomplete interface reservation registry")
    identities = {}
    for name, switch in switches.items():
        serial = switch.get("serial") if isinstance(switch, dict) else None
        if not isinstance(serial, str) or not serial or serial in identities.values() or name not in allowlist:
            raise ValueError("Ambiguous interface reservation identity")
        identities[name] = serial
    protected = {serial: set() for serial in identities.values()}
    visited = 0

    def collect(value, targets, depth=0):
        nonlocal visited
        visited += 1
        if depth > 24 or visited > 100000:
            raise ValueError("Interface reservation registry exceeds bounds")
        if isinstance(value, dict):
            if "switch_ref" in value:
                reference = value["switch_ref"]
                if reference not in identities:
                    raise ValueError("Unknown switch reservation reference")
                targets = [identities[reference]]
            for child in value.values():
                collect(child, targets, depth + 1)
        elif isinstance(value, (list, tuple)):
            for child in value:
                collect(child, targets, depth + 1)
        elif isinstance(value, str):
            parent = physical_parent(value)
            if parent:
                for serial in targets:
                    protected[serial].add(parent)
            elif re.match(r"(?i)^(ethernet|eth)[0-9]", value):
                raise ValueError("Unresolved physical interface reservation")

    for name, interfaces in allowlist.items():
        if name not in identities or not isinstance(interfaces, list):
            raise ValueError("Invalid switch interface allowlist")
        collect(interfaces, [identities[name]])
    for profile in profiles.values():
        if not isinstance(profile, dict):
            raise ValueError("Invalid interface reservation profile")
        members = profile.get("switches", {}).get("members", [])
        targets = []
        for member in members:
            reference = member.get("ref") if isinstance(member, dict) else None
            if reference not in identities:
                raise ValueError("Unknown profile switch reference")
            targets.append(identities[reference])
        collect(profile, targets or list(identities.values()))
    return {serial: sorted(interfaces) for serial, interfaces in protected.items()}


def physical_parent(value):
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"(?:ethernet|eth)([1-9][0-9]*/[1-9][0-9]*)(?:/[1-9][0-9]*)?(?:\.[0-9]+)?", value, re.IGNORECASE)
    return "Ethernet" + match.group(1) if match else None


def shutdown_decision(evidence, protected):
    if not isinstance(evidence, dict) or not isinstance(protected, dict):
        return "EVIDENCE_UNVERIFIED"
    serial, interface = evidence.get("serial"), evidence.get("interface")
    if not isinstance(serial, str) or not serial:
        return "IDENTITY_UNVERIFIED"
    if not isinstance(interface, str) or not re.fullmatch(
            r"(?:ethernet|eth)[1-9][0-9]*/[1-9][0-9]*(?:/[1-9][0-9]*)?", interface, re.IGNORECASE):
        return "NON_PHYSICAL_INTERFACE"
    reservations = protected.get(serial, [])
    if not isinstance(reservations, (list, tuple, set)):
        return "RESERVATIONS_UNVERIFIED"
    parent = physical_parent(interface)
    if any(physical_parent(value) == parent for value in reservations):
        return "PROTECTED_INTERFACE"
    for field in ("identity_verified", "ready", "admin_up", "oper_down", "default_host_policy",
                  "default_config", "no_neighbors", "no_attachments", "no_logical_children"):
        if evidence.get(field) is not True:
            return "UNVERIFIED_" + field.upper()
    return "VERIFIED_UNUSED"


DEFAULT_POLICY = {
    "adminState": True, "allowedVlans": "none", "bpduGuard": "default", "mtu": "jumbo",
    "netflow": False, "policyType": "trunkHost", "portTypeEdgeTrunk": True, "speed": "auto",
    "accessVlan": 1, "nativeVlan": 1, "bpduFilter": "default", "cdp": True,
    "configTemplate": "int_trunk_host", "debounceTimer": 100, "description": "", "duplexMode": "auto",
    "errorDetectionAcl": True, "extraConfig": "", "fec": "auto", "linkType": "auto", "mode": "trunk",
    "monitor": False, "negotiateAuto": True, "netflowMonitor": "", "netflowSampler": "", "orphanPort": False,
    "pfc": False, "qos": False, "qosPolicy": "", "queuingPolicy": "", "stormControl": False,
    "stormControlAction": "default", "stormControlBroadcastLevel": 0, "stormControlBroadcastLevelPps": 0,
    "stormControlMulticastLevel": 0, "stormControlMulticastLevelPps": 0,
    "stormControlUnicastLevel": 0, "stormControlUnicastLevelPps": 0, "vlanMapping": False,
}
REQUIRED_POLICY_FIELDS = {"adminState", "allowedVlans", "bpduGuard", "mtu", "netflow", "policyType", "portTypeEdgeTrunk", "speed"}


class BaselineBlocked(Exception):
    pass


class InterfaceBaseline:
    def __init__(self, registry, fabrics, request, apply=False, timeout_seconds=900, call_timeout_seconds=30,
                 poll_seconds=5, clock=time.monotonic, sleep=time.sleep):
        self.registry = registry
        self.protected = registry_reservations(registry)
        if (type(apply) is not bool or not isinstance(fabrics, list) or not fabrics or len(fabrics) > 16
                or any(not isinstance(value, str) or not value or len(value) > 200 for value in fabrics)):
            raise ValueError("Invalid interface baseline arguments")
        self.timeout, self.call_timeout, self.poll = map(float, (timeout_seconds, call_timeout_seconds, poll_seconds))
        if (not all(math.isfinite(value) for value in (self.timeout, self.call_timeout, self.poll))
                or not 0 < self.timeout <= 900 or not 0 < self.call_timeout <= 30 or self.poll < 0):
            raise ValueError("Invalid interface baseline deadline")
        self.fabrics, self.request, self.apply = list(dict.fromkeys(fabrics)), request, apply
        self.clock, self.sleep = clock, sleep
        self.changed, self.candidates, self.verified, self.inspected = False, 0, 0, 0
        self.decisions = []

    def call(self, method, path, content=None):
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise BaselineBlocked("DEADLINE_EXCEEDED")
        reply = self.request(method, path, content, min(remaining, self.call_timeout))
        if self.clock() >= self.deadline:
            raise BaselineBlocked("DEADLINE_EXCEEDED")
        if not isinstance(reply, dict) or reply.get("failed") or type(reply.get("status")) is not int:
            raise BaselineBlocked("API_RESPONSE_UNVERIFIED")
        body = reply.get("jsondata", reply.get("current"))
        if reply["status"] not in ([200] if method == "get" else [200, 201, 202, 204, 207]):
            raise BaselineBlocked("API_REQUEST_REJECTED")
        if len(json.dumps(body)) > 4 * 1024 * 1024:
            raise BaselineBlocked("API_RESPONSE_TOO_LARGE")

        def validate(value, depth=0):
            if depth > 16:
                raise BaselineBlocked("API_RESPONSE_UNVERIFIED")
            if isinstance(value, dict):
                if "code" in value or value.get("error") or value.get("errors") or value.get("errorCode") or value.get("error_code"):
                    raise BaselineBlocked("API_REQUEST_REJECTED")
                status = value.get("status")
                if isinstance(status, str) and re.search(r"fail|error|denied|reject|refus|unsuccess|cancel", status, re.I):
                    raise BaselineBlocked("API_REQUEST_REJECTED")
                for child in value.values():
                    validate(child, depth + 1)
            elif isinstance(value, list):
                if len(value) > 4096:
                    raise BaselineBlocked("API_RESPONSE_TOO_LARGE")
                for child in value:
                    validate(child, depth + 1)

        validate(body)
        if method != "get" and reply["status"] == 207:
            results = body.get("results", body.get("items")) if isinstance(body, dict) else None
            requested = content.get("interfaces", [content])
            expected = {(row.get("switchId"), row.get("interfaceName")) for row in requested}
            if not isinstance(results, list) or not results or len(results) != len(expected):
                raise BaselineBlocked("OPERATION_IDENTITY_UNVERIFIED")
            observed = set()
            for row in results:
                if (not isinstance(row, dict) or not isinstance(row.get("status"), str)
                        or row["status"].lower() not in {"success", "accepted", "pending", "inprogress", "queued"}):
                    raise BaselineBlocked("OPERATION_IDENTITY_UNVERIFIED")
                identity = (row.get("switchId"), row.get("interfaceName"))
                if identity not in expected or identity in observed:
                    raise BaselineBlocked("OPERATION_IDENTITY_UNVERIFIED")
                observed.add(identity)
        return body

    def rows(self, body, key, limit=4096):
        rows = body.get(key) if isinstance(body, dict) else body
        if (not isinstance(rows, list) or len(rows) >= limit or any(not isinstance(row, dict) for row in rows)
                or isinstance(body, dict) and (body.get("next") or body.get("total", len(rows)) != len(rows))):
            raise BaselineBlocked("INVENTORY_INCOMPLETE")
        meta = body.get("meta", {}) if isinstance(body, dict) else {}
        if isinstance(meta, dict) and (meta.get("next") or isinstance(meta.get("links"), dict) and meta["links"].get("next")):
            raise BaselineBlocked("INVENTORY_INCOMPLETE")
        return rows

    def ready_switches(self, fabric):
        prefix = "/api/v1/manage/fabrics/" + quote(fabric, safe="")
        inventory = self.rows(self.call("get", prefix + "/switches"), "switches")
        identities = [row.get("switchId") for row in inventory]
        if any(not isinstance(serial, str) or not serial for serial in identities) or len(set(identities)) != len(identities):
            raise BaselineBlocked("SWITCH_IDENTITY_UNVERIFIED")
        if not inventory:
            return prefix, []
        freeze = self.call("get", prefix + "/deploymentFreeze")
        update = self.call("get", prefix + "/softwareUpdatePlan/summary")
        if not isinstance(freeze, dict) or freeze.get("deploymentFreeze") is not False:
            raise BaselineBlocked("DEPLOYMENT_FREEZE_OR_UNVERIFIED")
        if (not isinstance(update, dict) or not isinstance(update.get("softwareUpdateSummary"), dict)
                or update["softwareUpdateSummary"].get("fabricName") != fabric
                or update["softwareUpdateSummary"].get("updatePlanStatus") != "none"
                or not isinstance(update.get("updateGroups"), list)
                or any(not isinstance(group, dict) or group.get("installStatus") != "none" for group in update["updateGroups"])):
            raise BaselineBlocked("SOFTWARE_UPDATE_OR_UNVERIFIED")
        expected = {value["serial"]: dict(value, name=name) for name, value in self.registry["lab"]["switches"].items()}
        ready = []
        for node in inventory:
            target = expected.get(node["switchId"])
            if target is None:
                continue
            data = node.get("additionalData", {})
            if (node.get("fabricManagementIp") == target.get("seed_ip") and isinstance(data, dict)
                    and all(data.get(key) in ["normal", "Normal"] for key in ("systemMode", "intendedSystemMode", "discoveredSystemMode"))
                    and data.get("configSyncStatus") == "inSync"
                    and str(node.get("switchRole", "")).lower().replace("_", "") == str(target.get("baseline_role", "")).lower().replace("_", "")):
                ready.append(target)
            else:
                self.decisions.append({"switch": target["name"], "decision": "SWITCH_READINESS_OR_IDENTITY_UNVERIFIED"})
        return prefix, ready

    def linked_ports(self, fabric):
        managed = self.rows(self.call("get", "/api/v1/manage/links?fabricName=" + quote(fabric, safe="")), "links")
        body = self.call("get", "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/links?fabric=" + quote(fabric, safe=""))
        physical = self.rows(body, "DATA" if isinstance(body, dict) and "DATA" in body else "links")
        linked = set()
        for row in managed + physical:
            for short, long_name in (("src", "source"), ("dst", "destination")):
                serial = row.get(short + "SwitchId", row.get(long_name + "SwitchId"))
                name = row.get(short + "InterfaceName", row.get(long_name + "InterfaceName"))
                if not isinstance(serial, str) or not serial or not isinstance(name, str) or not name:
                    raise BaselineBlocked("LINK_ENDPOINT_UNVERIFIED")
                parent = physical_parent(name)
                if parent:
                    linked.add((serial, parent))
        return linked

    def default_config(self, detail):
        config = detail.get("configData")
        if not isinstance(config, dict) or set(config) != {"mode", "networkOS"} or config["mode"] != "trunk":
            return False
        network = config["networkOS"]
        if not isinstance(network, dict) or set(network) != {"networkOSType", "policy"} or network["networkOSType"] != "nx-os":
            return False
        policy = network["policy"]

        def matches(value, expected):
            if type(expected) is bool:
                return type(value) is bool and value is expected
            if isinstance(expected, str):
                return isinstance(value, str) and value == expected
            return type(value) in (int, float) and value == expected

        return (isinstance(policy, dict) and REQUIRED_POLICY_FIELDS <= set(policy) <= set(DEFAULT_POLICY)
                and all(matches(value, DEFAULT_POLICY[key]) for key, value in policy.items()))

    def observe(self, prefix, target, name, interfaces, linked):
        path = prefix + "/switches/" + quote(target["serial"], safe="") + "/interfaces/" + quote(name, safe="")
        detail = self.call("get", path)
        if not isinstance(detail, dict):
            raise BaselineBlocked("INTERFACE_DETAIL_UNVERIFIED")
        config = detail.get("configData", {})
        network = config.get("networkOS", {}) if isinstance(config, dict) else {}
        policy = network.get("policy", {}) if isinstance(network, dict) else {}
        oper = detail.get("operData", {})
        valid_default = self.default_config(detail)
        attachments = ("attachments", "attachedNetworks", "attachedVrfs", "networkAttachments", "vrfAttachments",
                   "portChannelId", "portChannel", "memberOf")
        neighbors = ("neighbor", "neighbors", "lldpNeighbors", "cdpNeighbors")
        empty_attachments = all(container.get(key) in (None, False, 0, "", [], {})
                    for container in (detail, oper) if isinstance(container, dict) for key in attachments)
        empty_neighbors = all(container.get(key) in (None, False, 0, "", [], {})
                      for container in (detail, oper) if isinstance(container, dict) for key in neighbors)
        evidence = {"serial": target["serial"], "interface": name, "ready": True,
                    "identity_verified": detail.get("switchId") == target["serial"] and detail.get("interfaceName") == name and detail.get("interfaceType") == "ethernet",
                    "admin_up": isinstance(policy, dict) and policy.get("adminState") is True,
                    "oper_down": isinstance(oper, dict) and oper.get("operationalStatus") == "down" and oper.get("adminStatus") == "up",
                    "default_host_policy": isinstance(policy, dict) and policy.get("policyType") == "trunkHost",
                    "default_config": valid_default, "no_attachments": valid_default and empty_attachments,
                    "no_neighbors": empty_neighbors and (target["serial"], physical_parent(name)) not in linked,
                    "no_logical_children": not any(row["interfaceName"].lower().startswith(name.lower() + ".") for row in interfaces)}
        return shutdown_decision(evidence, self.protected), detail, path

    def interface_rows(self, prefix, serial):
        rows = self.rows(self.call("get", prefix + "/switches/" + quote(serial, safe="") + "/interfaces"), "interfaces")
        names = [row.get("interfaceName") for row in rows]
        if any(not isinstance(name, str) or not name for name in names) or len(set(name.lower() for name in names)) != len(names):
            raise BaselineBlocked("INTERFACE_INVENTORY_UNVERIFIED")
        return rows

    def verify(self, path, expected, fabric, target, name):
        while self.clock() < self.deadline:
            detail = self.call("get", path)
            warnings = self.rows(self.call("get", "/api/v1/analyze/anomalies/details?fabricName=" + quote(fabric, safe="") + "&max=200&offset=0"), "anomalies", 200)
            clear = True
            for warning in warnings:
                text = warning.get("anomalyString")
                if not isinstance(text, str) or type(warning.get("cleared")) is not bool:
                    raise BaselineBlocked("ANOMALY_EVIDENCE_UNVERIFIED")
                serial_match = re.search(r"(?<![A-Za-z0-9])" + re.escape(target["serial"]) + r"(?![A-Za-z0-9])", text, re.I)
                ports = re.findall(r"(?i)(?:ethernet|eth)\s*([1-9][0-9]*/[1-9][0-9]*(?:/[1-9][0-9]*)?)", text)
                if serial_match and any(("Ethernet" + port).lower() == name.lower() for port in ports) and not warning["cleared"]:
                    clear = False
            if (isinstance(detail, dict) and detail.get("switchId") == target["serial"] and detail.get("interfaceName") == name
                    and detail.get("configData") == expected and isinstance(detail.get("operData"), dict)
                    and detail["operData"].get("adminStatus") == "down" and detail["operData"].get("operationalStatus") == "down" and clear):
                _, ready = self.ready_switches(fabric)
                if any(row["serial"] == target["serial"] for row in ready):
                    return
            self.sleep(min(self.poll, max(0, self.deadline - self.clock())))
        raise BaselineBlocked("VERIFICATION_DEADLINE")

    def run(self):
        self.deadline = self.clock() + self.timeout
        reason = "AUDIT_COMPLETE" if not self.apply else "BASELINE_VERIFIED"
        failed = False
        plan = []
        try:
            seen = set()
            for fabric in self.fabrics:
                prefix, targets = self.ready_switches(fabric)
                linked = self.linked_ports(fabric) if targets else set()
                for target in targets:
                    if target["serial"] in seen:
                        raise BaselineBlocked("DUPLICATE_SWITCH_MEMBERSHIP")
                    seen.add(target["serial"])
                    rows = self.interface_rows(prefix, target["serial"])
                    owned = self.registry["lab"]["interface_allowlist"].get(target["name"])
                    for row in rows:
                        name = row["interfaceName"]
                        if physical_parent(name) is None or "." in name:
                            continue
                        self.inspected += 1
                        if self.inspected > 2048:
                            raise BaselineBlocked("INTERFACE_SCOPE_EXCEEDED")
                        if not owned:
                            decision = "NO_OWNED_INTERFACE_SCOPE"
                        elif physical_parent(name) in self.protected[target["serial"]]:
                            decision = "PROTECTED_INTERFACE"
                        else:
                            decision, detail, path = self.observe(prefix, target, name, rows, linked)
                            if decision == "VERIFIED_UNUSED":
                                plan.append((fabric, target, name, copy.deepcopy(detail["configData"])))
                        self.decisions.append({"switch": target["name"], "interface": name, "decision": decision})
            self.candidates = len(plan)
            for fabric, target, name, original in plan if self.apply else []:
                prefix, fresh_targets = self.ready_switches(fabric)
                if not any(row["serial"] == target["serial"] for row in fresh_targets):
                    raise BaselineBlocked("SWITCH_CHANGED_BEFORE_APPLY")
                rows = self.interface_rows(prefix, target["serial"])
                decision, detail, path = self.observe(prefix, target, name, rows, self.linked_ports(fabric))
                if decision != "VERIFIED_UNUSED" or detail.get("configData") != original:
                    self.decisions.append({"switch": target["name"], "interface": name, "decision": "CHANGED_BEFORE_APPLY"})
                    continue
                expected = copy.deepcopy(original)
                expected["networkOS"]["policy"]["adminState"] = False
                self.changed = True
                self.call("put", path, {"switchId": target["serial"], "interfaceName": name, "interfaceType": "ethernet", "configData": expected})
                self.call("post", prefix + "/interfaceActions/deploy", {"interfaces": [{"switchId": target["serial"], "interfaceName": name}]})
                self.verify(path, expected, fabric, target, name)
                self.verified += 1
        except BaselineBlocked as error:
            failed, reason = True, str(error)
        except Exception:
            failed, reason = True, "API_OR_SCHEMA_UNVERIFIED"
        return {"changed": self.changed, "failed": failed, "baseline_failed": failed, "msg": "NDP_INTERFACE_BASELINE " + reason,
                "candidates": self.candidates, "verified": self.verified, "inspected": self.inspected,
                "apply": self.apply, "decisions": self.decisions, "reason": reason}


class ActionModule(ActionBase):
    _supports_check_mode = True

    def run(self, tmp=None, task_vars=None):
        super().run(tmp, task_vars)
        values = task_vars or {}
        gate = None
        try:
            arguments = self._templar.template(dict(self._task.args))
            if self._task.check_mode:
                arguments["apply"] = False
            module_path = Path(__file__).with_name("nd_switch_discovery.py")
            if module_path.is_symlink() or not module_path.is_file():
                raise ValueError("Missing bounded controller transport")
            specification = importlib.util.spec_from_file_location("nd_baseline_bounds", module_path)
            bounds = importlib.util.module_from_spec(specification)
            specification.loader.exec_module(bounds)

            def request(method, path, content, limit):
                old_no_log = self._task.no_log
                self._task.no_log = True
                connection = None
                previous_remote = previous_local = None
                expires = time.monotonic() + limit
                try:
                    with bounds.bounded_call(limit):
                        try:
                            if getattr(self._connection, "_socket_path", None):
                                connection = Connection(self._connection._socket_path)
                                previous_remote = connection.get_option("persistent_command_timeout")
                                previous_local = self._connection.get_option("persistent_command_timeout")
                                seconds = max(1, int(expires - time.monotonic()))
                                connection.set_option("persistent_command_timeout", seconds)
                                self._connection.set_option("persistent_command_timeout", seconds)
                            payload = {"method": method, "path": path}
                            if content is not None:
                                payload["content"] = content
                            return self._execute_module(module_name="cisco.nd.nd_rest", module_args=payload, task_vars=values)
                        finally:
                            if previous_local is not None:
                                self._connection.set_option("persistent_command_timeout", previous_local)
                            if connection is not None and previous_remote is not None and time.monotonic() < expires:
                                connection.set_option("persistent_command_timeout", previous_remote)
                finally:
                    self._task.no_log = old_no_log

            gate = InterfaceBaseline(request=request, **arguments)
            with bounds.bounded_call(gate.timeout):
                return gate.run()
        except Exception:
            return {"changed": gate.changed if gate is not None else False, "failed": True, "baseline_failed": True,
                    "msg": "NDP_INTERFACE_BASELINE API_OR_ARGUMENTS_OR_DEADLINE_UNVERIFIED",
                    "reason": "API_OR_ARGUMENTS_OR_DEADLINE_UNVERIFIED", "candidates": gate.candidates if gate else 0,
                    "verified": gate.verified if gate else 0, "decisions": []}