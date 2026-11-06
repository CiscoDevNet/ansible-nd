import copy
import importlib.util
import json
import math
import os
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
    for field in ("identity_verified", "ready", "admin_up", "oper_down", "unused_reason", "default_host_policy",
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
    "ptp": "false",
}
REQUIRED_POLICY_FIELDS = {"adminState", "allowedVlans", "bpduGuard", "mtu", "netflow", "policyType", "portTypeEdgeTrunk", "speed"}
DEFAULT_ROUTED_POLICY = {
    "adminState": True, "policyType": "routedHost", "mtu": 9216, "netflow": False,
    "ptp": "false", "speed": "auto", "ipRedirects": False, "qos": False,
    "fec": "auto", "pimDrPriority": 1, "pimSparse": False, "pfc": False,
}
REQUIRED_ROUTED_FIELDS = {"adminState", "policyType", "mtu", "netflow", "speed"}


class BaselineBlocked(Exception):
    pass


class InterfaceBaseline:
    def __init__(self, registry, fabrics, request, apply=False, timeout_seconds=900, call_timeout_seconds=30,
                 poll_seconds=5, clock=time.monotonic, sleep=time.sleep, switch_refs=None,
                 interfaces=None, journal_path=None, ensure_host_admin_down_default=False,
                 idle_reserved_ports=False):
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
        if type(ensure_host_admin_down_default) is not bool:
            raise ValueError("Invalid fabric default enforcement flag")
        self.ensure_host_admin_down_default = ensure_host_admin_down_default
        self.fabric_defaults = []
        if ensure_host_admin_down_default:
            owned_fabrics = {row.get("name") for row in registry["lab"].get("fabrics", {}).values()
                            if isinstance(row, dict) and row.get("lifecycle") in {"retained", "preserved"}}
            if not set(self.fabrics) <= owned_fabrics:
                raise ValueError("Fabric default update outside the retained lab scope")
        if switch_refs is not None and (not isinstance(switch_refs, list) or not switch_refs
                or any(not isinstance(value, str) for value in switch_refs)
                or len(switch_refs) != len(set(switch_refs))
                or any(value not in registry["lab"]["switches"] for value in switch_refs)):
            raise ValueError("Invalid selected switch scope")
        if interfaces is not None and (switch_refs is None or not isinstance(interfaces, list)
                or not interfaces or len(interfaces) > 64
                or any(not isinstance(value, str) or not re.fullmatch(
                    r"(?:ethernet|eth)[1-9][0-9]*/[1-9][0-9]*(?:/[1-9][0-9]*)?", value, re.I) for value in interfaces)):
            raise ValueError("Invalid selected interface scope")
        self.switch_refs = set(switch_refs) if switch_refs is not None else None
        if type(idle_reserved_ports) is not bool or idle_reserved_ports and (switch_refs is None or journal_path is None):
            raise ValueError("Idle reserved-port cleanup requires explicit switches and a durable checkpoint")
        self.idle_reserved_ports = idle_reserved_ports
        if idle_reserved_ports:
            # Lifecycle boundaries have no active target. A future test reservation
            # does not require no-shutdown now. All live link, neighbor, attachment,
            # child-interface, identity, readiness and default-policy checks remain.
            self.protected = {serial: [] for serial in self.protected}
        self.interfaces = {re.sub(r"(?i)^eth(?:ernet)?", "Ethernet", value).lower() for value in interfaces} if interfaces is not None else None
        if interfaces is not None and len(self.interfaces) != len(interfaces):
            raise ValueError("Duplicate selected interface")
        self.journal_path = Path(journal_path) if journal_path is not None else None
        if self.journal_path is not None and (not self.journal_path.is_absolute()
                or self.journal_path.is_symlink() or self.journal_path.parent.is_symlink()
                or not self.journal_path.parent.is_dir()):
            raise ValueError("Invalid protected checkpoint path")
        self.clock, self.sleep = clock, sleep
        self.changed, self.candidates, self.verified, self.inspected = False, 0, 0, 0
        self.decisions = []
        self.readiness_incomplete = False
        self.connectivity_verified_fabrics = []
        self.remaining_connectivity_alerts = None

    def checkpoint(self, value):
        if self.journal_path is None:
            return
        secrets = [os.environ.get(key, "") for key in ("NDFC_USER", "NDFC_PASSWORD", "ANSIBLE_NXOS_SWITCH_USERNAME", "ANSIBLE_NXOS_SWITCH_PASSWORD")]

        def redact(item):
            if isinstance(item, dict):
                return {key: "[redacted]" if re.search(r"(?i)password|passwd|secret|token|authorization|credentials?|community|api.?key", str(key)) else redact(child)
                        for key, child in item.items() if key != "invocation"}
            if isinstance(item, list):
                return [redact(child) for child in item]
            if isinstance(item, str):
                for secret in secrets:
                    if secret:
                        item = item.replace(secret, "[redacted]")
            return item

        try:
            if self.journal_path.is_symlink():
                raise OSError("Checkpoint symlink")
            descriptor = os.open(self.journal_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(descriptor, "a") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(json.dumps(redact({"time_unix": time.time(), **value})) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        except (OSError, TypeError, ValueError) as error:
            raise BaselineBlocked("CHECKPOINT_UNVERIFIED") from error

    def call(self, method, path, content=None):
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise BaselineBlocked("DEADLINE_EXCEEDED")
        if method != "get":
            self.checkpoint({"phase": "request", "method": method, "path": path, "content": content})
        reply = self.request(method, path, content, min(remaining, self.call_timeout))
        if method != "get":
            self.checkpoint({"phase": "response", "method": method, "path": path,
                             "reply": {key: reply[key] for key in ("status", "current", "jsondata", "response", "failed") if isinstance(reply, dict) and key in reply}})
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
        if isinstance(meta, dict) and "counts" in meta:
            counts = meta["counts"]
            if (not isinstance(counts, dict) or type(counts.get("total")) is not int
                    or type(counts.get("remaining")) is not int or counts["remaining"] != 0
                    or counts["total"] != len(rows)):
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
            if target is None or self.switch_refs is not None and target["name"] not in self.switch_refs:
                continue
            data = node.get("additionalData", {})
            if (node.get("fabricManagementIp") == target.get("seed_ip") and isinstance(data, dict)
                    and all(data.get(key) in ["normal", "Normal"] for key in ("systemMode", "intendedSystemMode", "discoveredSystemMode"))
                    and data.get("configSyncStatus") == "inSync"
                    and str(node.get("switchRole", "")).lower().replace("_", "") == str(target.get("baseline_role", "")).lower().replace("_", "")):
                ready.append(target)
            else:
                self.readiness_incomplete = True
                self.decisions.append({"switch": target["name"], "decision": "SWITCH_READINESS_OR_IDENTITY_UNVERIFIED"})
                if self.apply:
                    raise BaselineBlocked("SWITCH_READINESS_OR_IDENTITY_UNVERIFIED")
        return prefix, ready

    def linked_ports(self, fabric):
        managed = self.rows(self.call("get", "/api/v1/manage/links?fabricName=" + quote(fabric, safe="")), "links")
        body = self.call("get", "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/links?fabric=" + quote(fabric, safe=""))
        physical = self.rows(body, "DATA" if isinstance(body, dict) and "DATA" in body else "links")
        linked = set()
        for row in managed + physical:
            legacy = "sw1-info" in row or "sw2-info" in row
            for index, (short, long_name) in enumerate((("src", "source"), ("dst", "destination")), 1):
                endpoint = row.get("sw%d-info" % index, {}) if legacy else {}
                if not isinstance(endpoint, dict):
                    raise BaselineBlocked("LINK_ENDPOINT_UNVERIFIED")
                serial = endpoint.get("sw-serial-number") if legacy else row.get(short + "SwitchId", row.get(long_name + "SwitchId"))
                name = endpoint.get("if-name") if legacy else row.get(short + "InterfaceName", row.get(long_name + "InterfaceName"))
                if not isinstance(serial, str) or not serial or not isinstance(name, str) or not name:
                    raise BaselineBlocked("LINK_ENDPOINT_UNVERIFIED")
                parent = physical_parent(name)
                if parent:
                    linked.add((serial, parent))
        return linked

    def default_config(self, detail):
        config = detail.get("configData")
        if not isinstance(config, dict) or set(config) != {"mode", "networkOS"} or config["mode"] not in {"trunk", "routed"}:
            return False
        network = config["networkOS"]
        if not isinstance(network, dict) or set(network) != {"networkOSType", "policy"} or network["networkOSType"] != "nx-os":
            return False
        policy = network["policy"]
        defaults, required = ((DEFAULT_POLICY, REQUIRED_POLICY_FIELDS) if config["mode"] == "trunk"
                              else (DEFAULT_ROUTED_POLICY, REQUIRED_ROUTED_FIELDS))

        def matches(value, expected):
            if type(expected) is bool:
                return type(value) is bool and value is expected
            if isinstance(expected, str):
                return isinstance(value, str) and value == expected
            return type(value) in (int, float) and value == expected

        # ND returns the default access VLAN as either integer 1 or string "1".
        # Do not coerce other values: an address, VRF, custom policy or unknown field is intent.
        return (isinstance(policy, dict) and required <= set(policy) <= set(defaults)
                and all((key == "accessVlan" and value == "1") or matches(value, defaults[key])
                        for key, value in policy.items()))

    def observe(self, prefix, target, name, interfaces, linked, detail=None):
        path = prefix + "/switches/" + quote(target["serial"], safe="") + "/interfaces/" + quote(name, safe="")
        if detail is None:
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
        empty_attachments = all(container.get(key) in ((None, False, 0, -1, "", [], {}) if key == "portChannelId"
                                                       else (None, False, 0, "", [], {}))
                    for container in (detail, oper) if isinstance(container, dict) for key in attachments)
        empty_neighbors = all(container.get(key) in (None, False, 0, "", [], {})
                      for container in (detail, oper) if isinstance(container, dict) for key in neighbors)
        evidence = {"serial": target["serial"], "interface": name, "ready": True,
                    "identity_verified": detail.get("switchId") == target["serial"] and detail.get("interfaceName") == name and detail.get("interfaceType") == "ethernet",
                    "admin_up": isinstance(policy, dict) and policy.get("adminState") is True,
                    "oper_down": isinstance(oper, dict) and oper.get("operationalStatus") == "down" and oper.get("adminStatus") == "up",
                    "unused_reason": isinstance(oper, dict) and isinstance(oper.get("operationalDescription"), str)
                        and oper["operationalDescription"].strip().lower() == "link not connected",
                    "default_host_policy": isinstance(policy, dict) and policy.get("policyType") in {"trunkHost", "routedHost"},
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

    def anomaly_rows(self, fabric):
        rows, total = [], None
        for page in range(32):
            offset = page * 200
            body = self.call("get", "/api/v1/analyze/anomalies/details?fabricName="
                             + quote(fabric, safe="") + "&max=200&offset=" + str(offset)
                             + "&fabricStatus=all&includeSuspendedAlerts=true")
            batch = body.get("anomalies") if isinstance(body, dict) else None
            counts = body.get("meta", {}).get("counts") if isinstance(body, dict) else None
            if (not isinstance(batch, list) or len(batch) > 200
                    or any(not isinstance(row, dict) for row in batch)):
                raise BaselineBlocked("ANOMALY_EVIDENCE_UNVERIFIED")
            if counts is None:
                # Older releases omit pagination metadata only for a complete short result.
                if page or len(batch) >= 200 or body.get("next") or body.get("meta", {}).get("links", {}).get("next"):
                    raise BaselineBlocked("INVENTORY_INCOMPLETE")
                rows.extend(batch)
                break
            if (not isinstance(counts, dict) or type(counts.get("total")) is not int
                    or type(counts.get("remaining")) is not int or counts["total"] < 0
                    or counts["remaining"] != counts["total"] - offset - len(batch)
                    or body.get("offset", offset) != offset
                    or total is not None and total != counts["total"]):
                raise BaselineBlocked("INVENTORY_INCOMPLETE")
            total = counts["total"]
            rows.extend(batch)
            if counts["remaining"] == 0:
                break
            if len(batch) != 200:
                raise BaselineBlocked("INVENTORY_INCOMPLETE")
        else:
            raise BaselineBlocked("INVENTORY_INCOMPLETE")
        if total is not None and len(rows) != total:
            raise BaselineBlocked("INVENTORY_INCOMPLETE")
        for row in rows:
            if (not isinstance(row.get("anomalyString"), str) or type(row.get("cleared")) is not bool
                    or "fabricName" in row and row["fabricName"] != fabric):
                raise BaselineBlocked("ANOMALY_EVIDENCE_UNVERIFIED")
        return rows

    @staticmethod
    def connectivity_warning(row):
        return (any(row.get(key) == "CONNECTIVITY_INTERFACE_STATUS" for key in ("mnemonicTitle", "mnemonicDescription"))
                or row.get("mnemonicNumber") == 200022
                or row.get("resourceType") == "INTERFACE_STATUS" and str(row.get("category", "")).lower() == "connectivity"
                or re.search(r"(?i)interface\s+(?:ethernet|eth)[0-9/]+\s+in undesired state", row["anomalyString"]) is not None)

    def warning_matches(self, warning, serial, name):
        text = warning["anomalyString"]
        switch_id = warning.get("switchId")
        if switch_id is not None and (not isinstance(switch_id, str) or not switch_id):
            raise BaselineBlocked("ANOMALY_IDENTITY_UNVERIFIED")
        serial_in_text = re.search(r"(?<![A-Za-z0-9])" + re.escape(serial) + r"(?![A-Za-z0-9])", text, re.I) is not None
        if switch_id is not None and switch_id != serial:
            if serial_in_text:
                raise BaselineBlocked("ANOMALY_IDENTITY_UNVERIFIED")
            return False
        ports = {"Ethernet" + port for port in re.findall(
            r"(?i)(?:ethernet|eth)\s*([1-9][0-9]*/[1-9][0-9]*(?:/[1-9][0-9]*)?)(?![0-9/.])", text)}
        entity = warning.get("entityName")
        if isinstance(entity, str) and re.fullmatch(r"(?:ethernet|eth)[1-9][0-9]*/[1-9][0-9]*(?:/[1-9][0-9]*)?", entity, re.I):
            entity = re.sub(r"(?i)^eth(?:ernet)?", "Ethernet", entity)
            if ports and entity.lower() not in {port.lower() for port in ports}:
                raise BaselineBlocked("ANOMALY_IDENTITY_UNVERIFIED")
            ports.add(entity)
        port_matches = name.lower() in {port.lower() for port in ports}
        if port_matches and switch_id is None and not serial_in_text:
            raise BaselineBlocked("ANOMALY_IDENTITY_UNVERIFIED")
        return port_matches and (switch_id == serial or serial_in_text)

    def verify(self, path, expected, fabric, target, name):
        while self.clock() < self.deadline:
            detail = self.call("get", path)
            warnings = self.anomaly_rows(fabric)
            clear = not any(self.warning_matches(warning, target["serial"], name)
                            for warning in warnings if not warning["cleared"] and self.connectivity_warning(warning))
            if (isinstance(detail, dict) and detail.get("switchId") == target["serial"] and detail.get("interfaceName") == name
                    and detail.get("configData") == expected and isinstance(detail.get("operData"), dict)
                    and detail["operData"].get("adminStatus") == "down" and detail["operData"].get("operationalStatus") == "down" and clear):
                _, ready = self.ready_switches(fabric)
                if any(row["serial"] == target["serial"] for row in ready):
                    return
            self.sleep(min(self.poll, max(0, self.deadline - self.clock())))
        raise BaselineBlocked("VERIFICATION_DEADLINE")

    def host_admin_default(self, fabric):
        path = "/api/v1/manage/fabrics/" + quote(fabric, safe="")
        current = self.call("get", path)
        if (not isinstance(current, dict) or current.get("name") != fabric
                or current.get("category") != "fabric" or not isinstance(current.get("management"), dict)):
            raise BaselineBlocked("FABRIC_DEFAULT_UNVERIFIED")
        management = current["management"]
        # eBGP/external do not expose this property in ND 4.3. Never invent it.
        if management.get("type") != "vxlanIbgp":
            self.fabric_defaults.append({"fabric": fabric, "decision": "NOT_APPLICABLE"})
            return
        if type(management.get("hostInterfaceAdminState")) is not bool:
            raise BaselineBlocked("FABRIC_DEFAULT_UNVERIFIED")
        if management["hostInterfaceAdminState"] and self.apply:
            self.ready_switches(fabric)
            fresh = self.call("get", path)
            if fresh != current:
                raise BaselineBlocked("FABRIC_CHANGED_BEFORE_APPLY")
            expected = copy.deepcopy(current)
            expected["management"]["hostInterfaceAdminState"] = False
            self.checkpoint({"phase": "before_fabric_default", "fabric": fabric, "before": current})
            self.changed = True
            self.call("put", path, expected)
            verified = self.call("get", path)
            if verified != expected:
                raise BaselineBlocked("FABRIC_DEFAULT_UPDATE_UNVERIFIED")
            management = verified["management"]
        self.fabric_defaults.append({"fabric": fabric, "hostInterfaceAdminState": management["hostInterfaceAdminState"]})
        if self.apply:
            self.ready_switches(fabric)

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
                    if self.interfaces is not None:
                        present = {re.sub(r"(?i)^eth(?:ernet)?", "Ethernet", row["interfaceName"]).lower() for row in rows}
                        if not self.interfaces <= present:
                            raise BaselineBlocked("INTERFACE_SCOPE_INCOMPLETE")
                    owned = self.registry["lab"]["interface_allowlist"].get(target["name"])
                    for row in rows:
                        name = row["interfaceName"]
                        if self.interfaces is not None and re.sub(r"(?i)^eth(?:ernet)?", "Ethernet", name).lower() not in self.interfaces:
                            continue
                        if physical_parent(name) is None or "." in name:
                            continue
                        self.inspected += 1
                        if self.inspected > 2048:
                            raise BaselineBlocked("INTERFACE_SCOPE_EXCEEDED")
                        if not owned and self.switch_refs is None:
                            decision = "NO_OWNED_INTERFACE_SCOPE"
                        elif physical_parent(name) in self.protected[target["serial"]]:
                            decision = "PROTECTED_INTERFACE"
                        else:
                            # ND 4.3's complete interface list contains the same
                            # configuration and operational data as each detail
                            # GET. Use that fresh snapshot only for planning;
                            # apply below still fetches the individual interface
                            # again and compares its exact before-state.
                            snapshot = row if (isinstance(row.get("configData"), dict)
                                               and isinstance(row.get("operData"), dict)) else None
                            decision, detail, path = self.observe(prefix, target, name, rows, linked, detail=snapshot)
                            if decision == "VERIFIED_UNUSED":
                                plan.append((fabric, target, name, copy.deepcopy(detail["configData"])))
                        self.decisions.append({"switch": target["name"], "interface": name, "decision": decision})
            if self.readiness_incomplete:
                raise BaselineBlocked("SWITCH_READINESS_OR_IDENTITY_UNVERIFIED")
            if self.switch_refs is not None and seen != {self.registry["lab"]["switches"][ref]["serial"] for ref in self.switch_refs}:
                raise BaselineBlocked("SWITCH_SCOPE_INCOMPLETE")
            if self.apply and not self.inspected:
                raise BaselineBlocked("INTERFACE_SCOPE_UNVERIFIED")
            self.candidates = len(plan)
            for fabric, target, name, original in plan if self.apply else []:
                prefix, fresh_targets = self.ready_switches(fabric)
                if not any(row["serial"] == target["serial"] for row in fresh_targets):
                    raise BaselineBlocked("SWITCH_CHANGED_BEFORE_APPLY")
                rows = self.interface_rows(prefix, target["serial"])
                decision, detail, path = self.observe(prefix, target, name, rows, self.linked_ports(fabric))
                if decision != "VERIFIED_UNUSED" or detail.get("configData") != original:
                    self.decisions.append({"switch": target["name"], "interface": name, "decision": "CHANGED_BEFORE_APPLY"})
                    raise BaselineBlocked("INTERFACE_CHANGED_BEFORE_APPLY")
                expected = copy.deepcopy(original)
                expected["networkOS"]["policy"]["adminState"] = False
                self.checkpoint({"phase": "before_change", "fabric": fabric, "switchId": target["serial"], "interfaceName": name, "before": detail})
                self.changed = True
                self.call("put", path, {"switchId": target["serial"], "interfaceName": name, "interfaceType": "ethernet", "configData": expected})
                self.call("post", prefix + "/interfaceActions/deploy", {"interfaces": [{"switchId": target["serial"], "interfaceName": name}]})
                self.verify(path, expected, fabric, target, name)
                self.verified += 1
            if self.apply:
                remaining = 0
                for fabric in self.fabrics:
                    remaining += sum(not row["cleared"] and self.connectivity_warning(row)
                                     for row in self.anomaly_rows(fabric))
                    self.connectivity_verified_fabrics.append(fabric)
                self.remaining_connectivity_alerts = remaining
                if remaining:
                    raise BaselineBlocked("CONNECTIVITY_INTERFACE_STATUS_ACTIVE")
            if self.ensure_host_admin_down_default:
                for fabric in self.fabrics:
                    self.host_admin_default(fabric)
        except BaselineBlocked as error:
            failed, reason = True, str(error)
        except Exception:
            failed, reason = True, "API_OR_SCHEMA_UNVERIFIED"
        return {"changed": self.changed, "failed": failed, "baseline_failed": failed, "msg": "NDP_INTERFACE_BASELINE " + reason,
                "candidates": self.candidates, "verified": self.verified, "inspected": self.inspected,
                "apply": self.apply, "decisions": self.decisions, "reason": reason,
                "remaining_connectivity_alerts": self.remaining_connectivity_alerts,
                "connectivity_verified_fabrics": self.connectivity_verified_fabrics,
                "fabric_defaults": self.fabric_defaults, "idle_reserved_ports": self.idle_reserved_ports}


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
                            if method != "get" and connection is not None:
                                # Keep the existing httpapi session and TLS policy, but
                                # retain the 207 body older nd_rest versions discard.
                                info = connection.send_request(method.upper(), path,
                                                               json.dumps(content) if content is not None else None)
                                return {"status": info.get("status"), "current": info.get("body"),
                                        "failed": bool(info.get("error")) and info.get("status") != 207}
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
