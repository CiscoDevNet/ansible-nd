import copy
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import time
from urllib.parse import quote

from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils.connection import Connection, ConnectionError as PersistentConnectionError
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


def physical_interface(value):
    return re.sub(r"(?i)^eth(?:ernet)?", "Ethernet", value.split(".", 1)[0]) if physical_parent(value) else None


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
READBACK_DEFAULTS = {("trunk", "trunkHost"): DEFAULT_POLICY, ("routed", "routedHost"): DEFAULT_ROUTED_POLICY}


def default_value_matches(key, value, default):
    # ND returns the default access VLAN as either integer 1 or string "1".
    # Do not coerce other values: an address, VRF, custom policy or unknown field is intent.
    if key == "accessVlan" and value == "1":
        return True
    if type(default) is bool:
        return type(value) is bool and value is default
    if isinstance(default, str):
        return isinstance(value, str) and value == default
    return type(value) in (int, float) and value == default


def without_readback_defaults(expected, current):
    """Drop policy keys ND adds on readback with their exact template default.

    After a configData PUT, ND 4.3 may return the stored policy expanded with
    template defaults that were not sent. Requested keys, unknown keys and
    non-default values are kept, so any real change still differs from expected.
    """
    try:
        wanted, observed = expected["networkOS"]["policy"], current["networkOS"]["policy"]
        defaults = READBACK_DEFAULTS.get((expected["mode"], wanted["policyType"]))
    except (KeyError, TypeError):
        return current
    if defaults is None or not isinstance(observed, dict):
        return current
    normalized = copy.deepcopy(current)
    normalized["networkOS"]["policy"] = {
        key: value for key, value in observed.items()
        if key in wanted or key not in defaults or not default_value_matches(key, value, defaults[key])}
    return normalized


def readback_drift(expected, current):
    # Key names only: values can carry descriptions, addresses or other intent.
    try:
        wanted, observed = expected["networkOS"]["policy"], current["networkOS"]["policy"]
    except (KeyError, TypeError):
        wanted = observed = None
    if not isinstance(wanted, dict) or not isinstance(observed, dict):
        return {"policy_unverified": True}
    probe = copy.deepcopy(current)
    probe["networkOS"]["policy"] = wanted
    return {"added_keys": sorted(set(observed) - set(wanted)), "missing_keys": sorted(set(wanted) - set(observed)),
            "changed_keys": sorted(key for key in set(wanted) & set(observed) if observed[key] != wanted[key]),
            "outside_policy_changed": probe != expected}


def interface_identity(switch_id, interface_name):
    # ND may echo interface names in a different case (ethernet1/1 for Ethernet1/1).
    if not isinstance(switch_id, str) or not switch_id.strip() or not isinstance(interface_name, str) or not interface_name.strip():
        return None
    return switch_id.strip(), interface_name.strip().lower()

# configSyncStatus values from the lifecycle pre-delete gate. Busy switches are
# only polled (never overlapped); drift may be recalculated and deployed.
# Anything else, including notApplicable, stays a fail-closed readiness failure.
SYNC_BUSY_STATUSES = {"deploymentInProgress", "inProgress", "previewInProgress"}
SYNC_DRIFT_STATUSES = {"deployed", "failed", "outOfSync", "pending", "success"}
SYNC_RECOVERY_ATTEMPTS = 3
SYNC_ACTION_FAILURE = re.compile(
    r"fail|error|denied|reject|unauthori|forbid|unsuccess|refus|cancel|abort|incomplete|cannot|unable", re.I)


class BaselineBlocked(Exception):
    pass


class TransientRejection(BaselineBlocked):
    """HTTP 408/429/5xx or an unconfirmed reply. Keeps the reason text; only sync recovery retries it."""


class RequestUnconfirmed(Exception):
    """No HTTP status arrived (timeout or lost transport); a write may or may not have applied."""


class InterfaceBaseline:
    def __init__(self, registry, fabrics, request, apply=False, timeout_seconds=900, call_timeout_seconds=30,
                 poll_seconds=5, clock=time.monotonic, sleep=time.sleep, switch_refs=None,
                 interfaces=None, journal_path=None, ensure_host_admin_down_default=False,
                 idle_reserved_ports=False, recover_config_sync=False, sync_attempt_seconds=420,
                 sync_settle_seconds=60, ensure_required_admin_up=False, sync_call_timeout_seconds=180,
                 stable_drift_settle_seconds=None, preexisting_connectivity_advisory=False):
        self.registry = registry
        self.protected = registry_reservations(registry)
        serial_names = {}
        for name, switch in registry.get("lab", {}).get("switches", {}).items():
            serial = switch.get("serial") if isinstance(switch, dict) else None
            if isinstance(serial, str) and serial:
                serial_names[serial] = name if serial not in serial_names else None
        self.serial_names = {serial: name for serial, name in serial_names.items() if name is not None}
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
        if (type(ensure_required_admin_up) is not bool
                or ensure_required_admin_up and (switch_refs is None or journal_path is None or idle_reserved_ports)):
            raise ValueError("Required-port enforcement needs explicit switches, a checkpoint and retained reservations")
        self.ensure_required_admin_up = ensure_required_admin_up
        self.required_ports = set()
        if ensure_required_admin_up:
            for profile in registry["profiles"].values():
                links = profile.get("links", [])
                if not isinstance(links, list):
                    raise ValueError("Invalid required interface links")
                for link in links:
                    if not isinstance(link, dict) or type(link.get("admin_state")) is not bool:
                        raise ValueError("Invalid required interface state")
                    if not link["admin_state"]:
                        continue
                    reference, names = link.get("switch_ref"), link.get("interfaces")
                    if reference not in registry["lab"]["switches"] or not isinstance(names, list) or not names:
                        raise ValueError("Invalid required interface scope")
                    serial = registry["lab"]["switches"][reference]["serial"]
                    for name in names:
                        parent = physical_parent(name)
                        if parent is None or parent not in self.protected[serial]:
                            raise ValueError("Required interface is not reserved")
                        self.required_ports.add((serial, physical_interface(name)))
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
        # Lifecycle-only Recalculate & Deploy of verified lab switches whose sole
        # readiness gap is configSyncStatus. Independent of interface apply.
        if type(recover_config_sync) is not bool:
            raise ValueError("Invalid configuration sync recovery flag")
        # configSave and switchActions/deploy reply only after ND finishes; a
        # deploy has taken about 35 s, longer than the 30 s read-call budget.
        self.sync_attempt_seconds, self.sync_settle_seconds, self.sync_call_timeout = map(
            float, (sync_attempt_seconds, sync_settle_seconds, sync_call_timeout_seconds))
        if (not all(math.isfinite(value) for value in (self.sync_attempt_seconds, self.sync_settle_seconds, self.sync_call_timeout))
                or not 0 < self.sync_attempt_seconds <= 900 or not 0 <= self.sync_settle_seconds <= self.sync_attempt_seconds
                or not 0 < self.sync_call_timeout <= 600):
            raise ValueError("Invalid configuration sync recovery window")
        # How long drift with nothing busy must persist before a pre-write gate
        # gives up; busy switches and post-deploy waits keep sync_attempt_seconds.
        self.stable_drift_settle = (self.sync_attempt_seconds if stable_drift_settle_seconds is None
                                    else float(stable_drift_settle_seconds))
        if not math.isfinite(self.stable_drift_settle) or not 0 <= self.stable_drift_settle <= self.sync_attempt_seconds:
            raise ValueError("Invalid stable drift settle window")
        if recover_config_sync:
            owned_fabrics = {row.get("name") for row in registry["lab"].get("fabrics", {}).values()
                            if isinstance(row, dict) and row.get("lifecycle") in {"retained", "preserved"}}
            if not set(self.fabrics) <= owned_fabrics or switch_refs is None or self.journal_path is None:
                raise ValueError("Configuration sync recovery outside the retained lab scope")
        self.recover_config_sync = recover_config_sync
        if type(preexisting_connectivity_advisory) is not bool:
            raise ValueError("Invalid pre-existing connectivity alarm flag")
        # Lifecycle boundaries only: an alarm already active before this run, on a port
        # this run never wrote, cannot have been caused by it. Report it instead of
        # blocking. New alarms and alarms on written ports still block.
        self.preexisting_connectivity_advisory = preexisting_connectivity_advisory
        self.preexisting_alert_keys = None
        self.preexisting_connectivity_alerts = None
        self.written_interfaces = set()
        self.last_inventory_ids = set()
        self.clock, self.sleep = clock, sleep
        self.changed, self.candidates, self.verified, self.inspected = False, 0, 0, 0
        self.required_candidates, self.required_verified = 0, 0
        self.decisions = []
        self.readiness_incomplete = False
        self.connectivity_verified_fabrics = []
        self.remaining_connectivity_alerts = None
        self.connectivity_alerts = []
        self.connectivity_alerts_truncated = False
        self.api_failure = None

    def checkpoint(self, value):
        if isinstance(value, dict) and value.get("phase") == "before_change":
            self.written_interfaces.add((value.get("switchId"), self.normalized_alert_interface(value.get("interfaceName"))))
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

    def call(self, method, path, content=None, sync_ids=None, limit=None):
        self.api_failure = None
        http = None

        def rejection(reason, error_type=BaselineBlocked):
            operation = re.sub(r"/(fabrics|switches|interfaces)/[^/?]+", r"/\1/{id}", path.split("?", 1)[0])
            self.api_failure = {"method": method, "operation": operation,
                                "http_status": http if type(http) is int else None}
            return error_type(reason)

        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise BaselineBlocked("DEADLINE_EXCEEDED")
        if method != "get":
            self.checkpoint({"phase": "request", "method": method, "path": path, "content": content})
        budget = min(remaining, self.call_timeout if limit is None else limit)
        try:
            reply = self.request(method, path, content, budget)
        except RequestUnconfirmed as error:
            if method != "get":
                self.checkpoint({"phase": "response_unconfirmed", "method": method, "path": path, "reason": str(error)})
            # A call bounded by the run deadline is out of time, not transient.
            if budget >= remaining or self.clock() >= self.deadline:
                raise BaselineBlocked("DEADLINE_EXCEEDED") from error
            raise rejection(str(error), TransientRejection) from error
        if method != "get":
            self.checkpoint({"phase": "response", "method": method, "path": path,
                             "reply": {key: reply[key] for key in ("status", "current", "jsondata", "response", "failed") if isinstance(reply, dict) and key in reply}})
        if self.clock() >= self.deadline:
            raise BaselineBlocked("DEADLINE_EXCEEDED")
        http = reply.get("status") if isinstance(reply, dict) else None
        blocked = TransientRejection if type(http) is int and (http in {408, 429} or http >= 500) else BaselineBlocked
        if not isinstance(reply, dict) or reply.get("failed") or type(reply.get("status")) is not int:
            raise rejection("API_RESPONSE_UNVERIFIED", blocked)
        body = reply.get("jsondata", reply.get("current"))
        if reply["status"] not in ([200] if method == "get" else [200, 201, 202, 204, 207]):
            raise rejection("API_REQUEST_REJECTED", blocked)
        if len(json.dumps(body)) > 4 * 1024 * 1024:
            raise rejection("API_RESPONSE_TOO_LARGE")

        def validate(value, depth=0):
            if depth > 16:
                raise rejection("API_RESPONSE_UNVERIFIED")
            if isinstance(value, dict):
                if "code" in value or value.get("error") or value.get("errors") or value.get("errorCode") or value.get("error_code"):
                    raise rejection("API_REQUEST_REJECTED")
                status = value.get("status")
                if isinstance(status, str) and re.search(r"fail|error|denied|reject|refus|unsuccess|cancel", status, re.I):
                    raise rejection("API_REQUEST_REJECTED")
                for child in value.values():
                    validate(child, depth + 1)
            elif isinstance(value, list):
                if len(value) > 4096:
                    raise rejection("API_RESPONSE_TOO_LARGE")
                for child in value:
                    validate(child, depth + 1)

        validate(body)
        if sync_ids is not None:
            try:
                self.verify_sync_action(reply["status"], body, sync_ids)
            except BaselineBlocked as error:
                raise rejection(str(error)) from error
            return body
        admin_update = path.endswith('/interfaceActions/updateAdminState')
        # ND 4.3.1 may answer an interface deploy with HTTP 207 and no rows or
        # only a successful subset. That is insufficient, not contradictory,
        # evidence: every deploy caller proves the result by fresh readback.
        deploy = method == "post" and path.endswith("/interfaceActions/deploy") and reply["status"] == 207
        if method != "get" and (reply["status"] == 207 or admin_update):
            results = body.get("results", body.get("items")) if isinstance(body, dict) else None
            if deploy and (results is None or results == []):
                return body
            requested = content.get("interfaces", [content])
            expected = {interface_identity(row.get("switchId"), row.get("interfaceName")) for row in requested}
            if (not isinstance(results, list) or not results or None in expected
                    or (len(results) > len(expected) if deploy else len(results) != len(expected))):
                raise rejection("OPERATION_IDENTITY_UNVERIFIED")
            observed = set()
            for row in results:
                if (not isinstance(row, dict) or not isinstance(row.get("status"), str)
                        or row["status"].lower() not in {"success", "accepted", "pending", "inprogress", "queued"}):
                    raise rejection("OPERATION_IDENTITY_UNVERIFIED")
                identity = interface_identity(row.get("switchId"), row.get("interfaceName"))
                if identity is None or identity not in expected or identity in observed:
                    raise rejection("OPERATION_IDENTITY_UNVERIFIED")
                if admin_update and row.get('adminStatus') != 'down':
                    raise rejection('ADMIN_STATE_RESPONSE_UNVERIFIED')
                observed.add(identity)
        return body

    @staticmethod
    def verify_sync_action(http, body, requested):
        # Mirrors the lifecycle pre-delete contract: acceptance only permits
        # polling; fresh inventory must still prove every roster switch inSync.
        if body is None and http != 207:
            return
        if not isinstance(body, dict) or http == 207 and not body:
            raise BaselineBlocked("SYNC_ACTION_RESPONSE_UNVERIFIED")
        summary = body.get("status", "")
        if (not isinstance(summary, str) or len(summary) > 1024
                or SYNC_ACTION_FAILURE.search(re.sub(r"\[[^]]*\]", " ", summary))):
            raise BaselineBlocked("SYNC_ACTION_RESPONSE_UNVERIFIED")
        if "items" not in body:
            return
        items, observed = body["items"], set()
        if not isinstance(items, list) or not items:
            raise BaselineBlocked("SYNC_ACTION_RESPONSE_UNVERIFIED")
        for row in items:
            identity = row.get("switchId") if isinstance(row, dict) else None
            status = row.get("status") if isinstance(row, dict) else None
            if (not isinstance(identity, str) or identity not in requested or identity in observed
                    or not isinstance(status, str) or not status or len(status) > 1024
                    or SYNC_ACTION_FAILURE.search(status)):
                raise BaselineBlocked("SYNC_ACTION_RESPONSE_UNVERIFIED")
            observed.add(identity)

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

    def ready_switches(self, fabric, allow_pending=False, sync_statuses=None):
        prefix = "/api/v1/manage/fabrics/" + quote(fabric, safe="")
        inventory = self.rows(self.call("get", prefix + "/switches"), "switches")
        identities = [row.get("switchId") for row in inventory]
        if any(not isinstance(serial, str) or not serial for serial in identities) or len(set(identities)) != len(identities):
            raise BaselineBlocked("SWITCH_IDENTITY_UNVERIFIED")
        self.last_inventory_ids = set(identities)
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
            data = data if isinstance(data, dict) else {}
            expected_ip = target.get("seed_ip")
            expected_role = target.get("baseline_role")
            observed_role = node.get("switchRole")
            checks = {
                "fabricManagementIp": isinstance(expected_ip, str) and bool(expected_ip.strip())
                    and node.get("fabricManagementIp") == expected_ip,
                "switchRole": isinstance(expected_role, str) and bool(expected_role.strip())
                    and isinstance(observed_role, str) and bool(observed_role.strip())
                    and observed_role.lower().replace("_", "") == expected_role.lower().replace("_", ""),
                **{key: data.get(key) in ["normal", "Normal"]
                   for key in ("systemMode", "intendedSystemMode", "discoveredSystemMode")},
            }
            identity_ready = all(checks.values())
            if identity_ready and sync_statuses is not None:
                sync_statuses[target["serial"]] = data.get("configSyncStatus")
            if identity_ready and data.get("configSyncStatus") == "inSync":
                ready.append(target)
            elif allow_pending and identity_ready and data.get("configSyncStatus") == "pending":
                # Only the verified fabric-default update uses this polling
                # mode. Pending switches never become eligible for a write.
                continue
            elif (sync_statuses is not None and identity_ready
                  and data.get("configSyncStatus") in SYNC_BUSY_STATUSES | SYNC_DRIFT_STATUSES):
                # Lifecycle sync recovery only: identity, role and mode are
                # verified; the switch is still excluded from interface writes.
                continue
            else:
                self.readiness_incomplete = True
                failed_checks = [key for key, accepted in checks.items() if not accepted]
                if data.get("configSyncStatus") != "inSync":
                    failed_checks.append("configSyncStatus")
                self.decisions.append({"switch": target["name"], "decision": "SWITCH_READINESS_OR_IDENTITY_UNVERIFIED",
                                       "failed_checks": failed_checks})
                if self.apply:
                    raise BaselineBlocked("SWITCH_READINESS_OR_IDENTITY_UNVERIFIED")
        return prefix, ready

    def wait_for_fabric_sync(self, fabric, expected_serials):
        while self.clock() < self.deadline:
            _, ready = self.ready_switches(fabric, allow_pending=True)
            if {target['serial'] for target in ready} == expected_serials:
                return
            self.sleep(min(self.poll, max(0, self.deadline - self.clock())))
        raise BaselineBlocked('FABRIC_DEFAULT_SYNC_DEADLINE')

    def sync_snapshot(self, fabric, roster=None):
        # Judge only this fabric's snapshot. An earlier fabric's audit-only gap
        # stays recorded for the final verdict but must not skip this recovery.
        statuses, earlier_gap = {}, self.readiness_incomplete
        self.readiness_incomplete = False
        for attempt in range(3):
            try:
                prefix, ready = self.ready_switches(fabric, sync_statuses=statuses)
                break
            except TransientRejection as error:
                interval = max(self.poll, 1.0)
                if attempt == 2 or self.deadline - self.clock() <= interval:
                    raise
                self.decisions.append({"fabric": fabric, "decision": "SYNC_POLL_TRANSIENT_REJECTION",
                                       "attempt": attempt + 1, "reason": str(error),
                                       "api_failure": self.api_failure})
                statuses.clear()
                self.sleep(interval)
        if self.readiness_incomplete:
            raise BaselineBlocked("SWITCH_READINESS_OR_IDENTITY_UNVERIFIED")
        self.readiness_incomplete = earlier_gap
        if roster is not None and set(statuses) != roster:
            raise BaselineBlocked("FABRIC_SYNC_ROSTER_CHANGED")
        return prefix, ready, statuses

    def wait_for_stable_switches(self, fabric, after_deploy=False):
        # Poll only: never recalculate or redeploy to make an interface write eligible.
        # After this baseline's own deploy, idle pending/deployed is the normal settle
        # phase, so keep the full window there; the shorter settle gates only writes.
        settle = self.sync_attempt_seconds if after_deploy else self.stable_drift_settle
        snapshot = self.sync_snapshot(fabric)
        snapshot = self.await_sync(fabric, set(snapshot[2]), snapshot, settle)
        pending = {serial for serial, status in snapshot[2].items() if status != "inSync"}
        if pending:
            self.readiness_incomplete = True
            for name, target in self.registry["lab"]["switches"].items():
                if target["serial"] in pending:
                    self.decisions.append({"switch": name, "decision": "SWITCH_READINESS_OR_IDENTITY_UNVERIFIED",
                                           "failed_checks": ["configSyncStatus"]})
            raise BaselineBlocked("SWITCH_READINESS_OR_IDENTITY_UNVERIFIED")
        return snapshot[:2]

    def await_sync(self, fabric, roster, snapshot, settle_seconds):
        # Busy switches are never redeployed. Drift must persist with nothing
        # busy for settle_seconds so a just-accepted deploy is not misread.
        interval = max(self.poll, 1.0)
        window_end = min(self.deadline, self.clock() + self.sync_attempt_seconds)
        drift_since = None
        while True:
            statuses = snapshot[2]
            if all(status == "inSync" for status in statuses.values()):
                return snapshot
            busy = any(status in SYNC_BUSY_STATUSES for status in statuses.values())
            now = self.clock()
            drift_since = None if busy else (now if drift_since is None else drift_since)
            if not busy and now - drift_since >= settle_seconds:
                return snapshot
            if window_end - now <= interval:
                if busy:
                    raise BaselineBlocked("FABRIC_SYNC_IN_PROGRESS_TIMEOUT")
                return snapshot
            self.sleep(interval)
            snapshot = self.sync_snapshot(fabric, roster)

    def reconcile_fabric_sync(self, fabric):
        snapshot = self.sync_snapshot(fabric)
        roster = set(snapshot[2])
        names = {value["serial"]: name for name, value in self.registry["lab"]["switches"].items()}
        snapshot = self.await_sync(fabric, roster, snapshot, 0)
        attempt = 0
        while True:
            prefix, _, statuses = snapshot
            drift = sorted(serial for serial, status in statuses.items() if status != "inSync")
            if not drift:
                if attempt:
                    self.decisions.append({"fabric": fabric, "decision": "SYNC_RECOVERY_CONFIRMED", "attempts": attempt})
                return
            if attempt == SYNC_RECOVERY_ATTEMPTS:
                self.decisions.append({"fabric": fabric, "decision": "SYNC_RECOVERY_NOT_CONVERGED", "attempts": attempt,
                                       "switches": {names[serial]: statuses[serial] for serial in drift}})
                raise BaselineBlocked("FABRIC_SYNC_RECOVERY_NOT_CONVERGED")
            attempt += 1
            try:
                inventory = set(self.last_inventory_ids)
                self.changed = True
                self.call("post", prefix + "/actions/configSave", {}, sync_ids=inventory, limit=self.sync_call_timeout)
                # Recheck freeze, upgrade, identity, mode and roster before deploying.
                prefix, _, statuses = self.sync_snapshot(fabric, roster)
                targets = sorted(serial for serial, status in statuses.items() if status in SYNC_DRIFT_STATUSES)
                if targets and not any(status in SYNC_BUSY_STATUSES for status in statuses.values()):
                    self.call("post", prefix + "/switchActions/deploy", {"switchIds": targets}, sync_ids=set(targets),
                              limit=self.sync_call_timeout)
                    self.decisions.append({"fabric": fabric, "decision": "SYNC_RECOVERY_DEPLOY_REQUESTED",
                                           "attempt": attempt, "switches": [names[serial] for serial in targets]})
                else:
                    self.decisions.append({"fabric": fabric, "decision": "SYNC_RECOVERY_RECALCULATED", "attempt": attempt})
            except TransientRejection as error:
                self.decisions.append({"fabric": fabric, "decision": "SYNC_RECOVERY_TRANSIENT_REJECTION",
                                       "attempt": attempt, "reason": str(error)})
                if attempt == SYNC_RECOVERY_ATTEMPTS:
                    raise
            snapshot = self.await_sync(fabric, roster, self.sync_snapshot(fabric, roster), self.sync_settle_seconds)

    def linked_ports(self, fabric, parents=True):
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
                parent = physical_parent(name) if parents else physical_interface(name)
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
        return (isinstance(policy, dict) and required <= set(policy) <= set(defaults)
                and all(default_value_matches(key, value, defaults[key]) for key, value in policy.items()))

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
                             + "&fabricStatus=all&includeSuspendedAlerts=true&includeAnomalies=all")
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

    @staticmethod
    def normalized_alert_interface(value):
        if not isinstance(value, str):
            return None
        match = re.fullmatch(r"(?:ethernet|eth)([1-9][0-9]*/[1-9][0-9]*(?:/[1-9][0-9]*)?)", value, re.I)
        return "Ethernet" + match.group(1) if match else None

    def connectivity_alert_detail(self, fabric, row):
        text = row["anomalyString"]
        known_serials = [serial for serial in self.serial_names
                         if re.search(r"(?<![A-Za-z0-9])" + re.escape(serial) + r"(?![A-Za-z0-9])", text, re.I)]
        serial = row.get("switchId")
        switch = self.serial_names.get(serial) if isinstance(serial, str) else None
        if switch and any(value != serial for value in known_serials):
            switch = None
        elif switch is None and len(known_serials) == 1 and (serial is None or serial == known_serials[0]):
            switch = self.serial_names[known_serials[0]]

        text_interfaces = {
            "Ethernet" + value for value in re.findall(
                r"(?i)(?:ethernet|eth)\s*([1-9][0-9]*/[1-9][0-9]*(?:/[1-9][0-9]*)?)(?![0-9/.])", text)
        }
        entity_interface = self.normalized_alert_interface(row.get("entityName"))
        if entity_interface and text_interfaces and text_interfaces != {entity_interface}:
            interface = None
        elif entity_interface:
            interface = entity_interface
        else:
            interface = next(iter(text_interfaces)) if len(text_interfaces) == 1 else None

        matching = [item for item in reversed(self.decisions)
                    if switch is not None and interface is not None
                    and item.get("switch") == switch and item.get("interface") == interface]
        return {
            "fabric": fabric,
            "switch": switch or "unmapped",
            "interface": interface or "unknown",
            "baseline_decision": matching[0].get("decision") if matching else "OUT_OF_SCOPE",
        }

    def alert_key(self, fabric, row):
        text = row["anomalyString"]
        serial = row.get("switchId") if isinstance(row.get("switchId"), str) and row.get("switchId") else None
        if serial is None:
            known = [value for value in self.serial_names
                     if re.search(r"(?<![A-Za-z0-9])" + re.escape(value) + r"(?![A-Za-z0-9])", text, re.I)]
            serial = known[0] if len(known) == 1 else None
        interface = self.normalized_alert_interface(row.get("entityName"))
        if interface is None:
            found = set(re.findall(r"(?i)(?:ethernet|eth)\s*([1-9][0-9]*/[1-9][0-9]*(?:/[1-9][0-9]*)?)(?![0-9/.])", text))
            interface = "Ethernet" + found.pop() if len(found) == 1 else None
        return fabric, serial, interface, " ".join(text.lower().split())

    def snapshot_preexisting_alerts(self):
        self.preexisting_alert_keys = {
            self.alert_key(fabric, row) for fabric in self.fabrics for row in self.anomaly_rows(fabric)
            if not row["cleared"] and self.connectivity_warning(row)}

    def preexisting_untouched(self, fabric, row):
        if self.preexisting_alert_keys is None:
            return False
        key = self.alert_key(fabric, row)
        # An alarm without a provable switch/interface identity keeps blocking.
        return (key[1] is not None and key[2] is not None and key in self.preexisting_alert_keys
                and (key[1], key[2]) not in self.written_interfaces)

    def require_connectivity_clearance(self):
        counts, blocking = {}, {}
        details, advisory = [], []
        tagged = self.preexisting_alert_keys is not None
        for fabric in self.fabrics:
            active = [row for row in self.anomaly_rows(fabric)
                      if not row["cleared"] and self.connectivity_warning(row)]
            counts[fabric] = len(active)
            held = []
            for row in active:
                (advisory if self.preexisting_untouched(fabric, row) else held).append((fabric, row))
            blocking[fabric] = len(held)
            for _, row in held[:max(0, 12 - len(details))]:
                detail = self.connectivity_alert_detail(fabric, row)
                details.append(dict(detail, preexisting=False) if tagged else detail)
        for fabric, row in advisory[:max(0, 12 - len(details))]:
            details.append(dict(self.connectivity_alert_detail(fabric, row), preexisting=True))
        self.connectivity_verified_fabrics = list(counts)
        self.remaining_connectivity_alerts = sum(counts.values())
        self.preexisting_connectivity_alerts = len(advisory) if tagged else None
        self.connectivity_alerts = details
        self.connectivity_alerts_truncated = self.remaining_connectivity_alerts > len(details)
        if sum(blocking.values()):
            self.decisions.extend({"fabric": fabric, "decision": "CONNECTIVITY_INTERFACE_STATUS_ACTIVE",
                                   "remaining_alerts": count} for fabric, count in blocking.items() if count)
            raise BaselineBlocked("CONNECTIVITY_INTERFACE_STATUS_ACTIVE")

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
                    and without_readback_defaults(expected, detail.get("configData")) == expected
                    and isinstance(detail.get("operData"), dict)
                    and detail["operData"].get("adminStatus") == "down" and detail["operData"].get("operationalStatus") == "down" and clear):
                _, ready = self.ready_switches(fabric)
                if any(row["serial"] == target["serial"] for row in ready):
                    return
            self.sleep(min(self.poll, max(0, self.deadline - self.clock())))
        raise BaselineBlocked("VERIFICATION_DEADLINE")

    def required_detail(self, prefix, target, name):
        path = prefix + "/switches/" + quote(target["serial"], safe="") + "/interfaces/" + quote(name, safe="")
        detail = self.call("get", path)
        if (not isinstance(detail, dict) or detail.get("switchId") != target["serial"]
                or detail.get("interfaceName") != name or detail.get("interfaceType") != "ethernet"
                or not isinstance(detail.get("configData"), dict) or not isinstance(detail.get("operData"), dict)):
            raise BaselineBlocked("REQUIRED_INTERFACE_IDENTITY_UNVERIFIED")
        network = detail["configData"].get("networkOS")
        policy = network.get("policy") if isinstance(network, dict) else None
        if detail["configData"].get("mode") == "unknown" and not policy:
            return "REQUIRED_FREE_INTERFACE", detail, path
        if (not isinstance(policy, dict) or type(policy.get("adminState")) is not bool
                or not isinstance(network.get("networkOSType"), str)):
            raise BaselineBlocked("REQUIRED_INTERFACE_POLICY_UNVERIFIED")
        if policy["adminState"] and detail["operData"].get("adminStatus") == "up":
            return "REQUIRED_ADMIN_UP", detail, path
        return "REQUIRED_ADMIN_UP_PENDING", detail, path

    def apply_required_ports(self, plan):
        for fabric, target, name, original in plan:
            prefix, targets = self.wait_for_stable_switches(fabric)
            if not any(row["serial"] == target["serial"] for row in targets):
                raise BaselineBlocked("SWITCH_CHANGED_BEFORE_APPLY")
            _, detail, path = self.required_detail(prefix, target, name)
            if detail["configData"] != original:
                raise BaselineBlocked("INTERFACE_CHANGED_BEFORE_APPLY")
            expected = copy.deepcopy(original)
            expected["networkOS"]["policy"]["adminState"] = True
            self.checkpoint({"phase": "before_change", "fabric": fabric, "switchId": target["serial"],
                             "interfaceName": name, "before": detail})
            self.changed = True
            self.call("put", path, {"switchId": target["serial"], "interfaceName": name,
                                   "interfaceType": "ethernet", "configData": expected})
            self.call("post", prefix + "/interfaceActions/deploy",
                      {"interfaces": [{"switchId": target["serial"], "interfaceName": name}]})
            self.wait_for_stable_switches(fabric, after_deploy=True)
            while self.clock() < self.deadline:
                decision, current, _ = self.required_detail(prefix, target, name)
                readback = without_readback_defaults(expected, current["configData"])
                if readback != expected:
                    self.decisions.append({"switch": target["name"], "interface": name,
                                           "decision": "REQUIRED_INTERFACE_CONFIG_CHANGED", **readback_drift(expected, readback)})
                    raise BaselineBlocked("REQUIRED_INTERFACE_CONFIG_CHANGED")
                if decision == "REQUIRED_ADMIN_UP":
                    _, targets = self.ready_switches(fabric)
                    if any(row["serial"] == target["serial"] for row in targets):
                        self.required_verified += 1
                        break
                self.sleep(min(self.poll, max(0, self.deadline - self.clock())))
            else:
                raise BaselineBlocked("REQUIRED_INTERFACE_VERIFICATION_DEADLINE")

    def _current_batch_details(self, entries):
        snapshots = {}
        for fabric, target, name, expected in entries:
            key = (fabric, target['serial'])
            if key not in snapshots:
                prefix = '/api/v1/manage/fabrics/' + quote(fabric, safe='')
                snapshots[key] = self.interface_rows(prefix, target['serial'])
        details = []
        for fabric, target, name, expected in entries:
            rows = snapshots[(fabric, target['serial'])]
            matching = [row for row in rows if row['interfaceName'] == name]
            if len(matching) != 1:
                raise BaselineBlocked('INTERFACE_SCOPE_INCOMPLETE')
            detail = matching[0]
            if not isinstance(detail.get('configData'), dict) or not isinstance(detail.get('operData'), dict):
                path = ('/api/v1/manage/fabrics/' + quote(fabric, safe='') + '/switches/'
                        + quote(target['serial'], safe='') + '/interfaces/' + quote(name, safe=''))
                detail = self.call('get', path)
            details.append((fabric, target, name, expected, detail))
        return details

    @staticmethod
    def _shutdown_is_observed(target, name, expected, detail):
        return (isinstance(detail, dict) and detail.get('switchId') == target['serial']
                and detail.get('interfaceName') == name and detail.get('interfaceType') == 'ethernet'
                and detail.get('configData') == expected and isinstance(detail.get('operData'), dict)
                and detail['operData'].get('adminStatus') == 'down'
                and detail['operData'].get('operationalStatus') == 'down')

    def _verify_batch_configuration(self, entries):
        limit = min(self.deadline, self.clock() + 60)
        while self.clock() < limit:
            if all(self._shutdown_is_observed(target, name, expected, detail)
                   for _, target, name, expected, detail in self._current_batch_details(entries)):
                return
            self.sleep(min(self.poll, max(0, limit - self.clock())))
        raise BaselineBlocked('ADMIN_STATE_UPDATE_READBACK_UNVERIFIED')

    def _verify_batch_clearance(self, entries):
        fabrics = list(dict.fromkeys(row[0] for row in entries))
        while self.clock() < self.deadline:
            details = self._current_batch_details(entries)
            configured = all(self._shutdown_is_observed(target, name, expected, detail)
                             for _, target, name, expected, detail in details)
            warnings = {fabric: self.anomaly_rows(fabric) for fabric in fabrics}
            clear = not any(self.warning_matches(warning, target['serial'], name)
                            for fabric, target, name, _ in entries for warning in warnings[fabric]
                            if not warning['cleared'] and self.connectivity_warning(warning))
            if configured and clear:
                for fabric in fabrics:
                    _, ready = self.ready_switches(fabric)
                    serials = {target['serial'] for target in ready}
                    if not {target['serial'] for f, target, _, _ in entries if f == fabric} <= serials:
                        raise BaselineBlocked('SWITCH_CHANGED_DURING_VERIFICATION')
                self.verified += len(entries)
                return
            self.sleep(min(self.poll, max(0, self.deadline - self.clock())))
        raise BaselineBlocked('VERIFICATION_DEADLINE')

    def apply_batches(self, plan):
        grouped = {}
        for fabric, target, name, original in plan:
            grouped.setdefault(fabric, []).append((fabric, target, name, original))
        applied = []
        for fabric, selected in grouped.items():
            # Prove the API preserves exact intent on one port before applying
            # the remaining bounded batches. No alarm wait delays later ports.
            # ND deploy waits for the selected interfaces and can exceed the
            # bounded HTTP timeout on large requests. Keep each deploy small.
            batches = [selected[:1]] + [selected[i:i + 8] for i in range(1, len(selected), 8)]
            for batch in batches:
                prefix, ready = self.wait_for_stable_switches(fabric)
                serials = {target['serial'] for target in ready}
                snapshots = {}
                for _, target, _, _ in batch:
                    if target['serial'] not in snapshots:
                        snapshots[target['serial']] = self.interface_rows(prefix, target['serial'])
                linked = self.linked_ports(fabric)
                expected_entries, before_images = [], []
                for _, target, name, original in batch:
                    if target['serial'] not in serials:
                        raise BaselineBlocked('SWITCH_CHANGED_BEFORE_APPLY')
                    rows = snapshots[target['serial']]
                    matching = [row for row in rows if row['interfaceName'] == name]
                    if len(matching) != 1:
                        raise BaselineBlocked('INTERFACE_SCOPE_INCOMPLETE')
                    row = matching[0]
                    snapshot = row if isinstance(row.get('configData'), dict) and isinstance(row.get('operData'), dict) else None
                    decision, detail, _ = self.observe(prefix, target, name, rows, linked, detail=snapshot)
                    if decision != 'VERIFIED_UNUSED' or detail.get('configData') != original:
                        raise BaselineBlocked('INTERFACE_CHANGED_BEFORE_APPLY')
                    expected = copy.deepcopy(original)
                    expected['networkOS']['policy']['adminState'] = False
                    expected_entries.append((fabric, target, name, expected))
                    before_images.append((target, name, detail))
                # Recheck readiness and links immediately before the single
                # scoped mutation, including planned/missing physical links.
                _, ready = self.ready_switches(fabric)
                serials = {target['serial'] for target in ready}
                linked = self.linked_ports(fabric)
                if any(target['serial'] not in serials or (target['serial'], physical_parent(name)) in linked
                       for _, target, name, _ in expected_entries):
                    raise BaselineBlocked('TOPOLOGY_CHANGED_BEFORE_BATCH_APPLY')
                for target, name, detail in before_images:
                    self.checkpoint({'phase': 'before_change', 'fabric': fabric, 'switchId': target['serial'],
                                     'interfaceName': name, 'before': detail})
                content = {'interfaces': [{'switchId': target['serial'], 'interfaceName': name, 'adminState': 'shut'}
                                           for _, target, name, _ in expected_entries]}
                self.changed = True
                self.call('post', prefix + '/interfaceActions/updateAdminState', content)
                # updateAdminState persists ND intent; it does not deploy that
                # intent to the switch. Deploy exactly the approved identities.
                self.call('post', prefix + '/interfaceActions/deploy', {
                    'interfaces': [{'switchId': row['switchId'], 'interfaceName': row['interfaceName']}
                                   for row in content['interfaces']]})
                self.wait_for_stable_switches(fabric, after_deploy=True)
                self._verify_batch_configuration(expected_entries)
                applied.extend(expected_entries)
        self._verify_batch_clearance(applied)

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
            _, before_targets = self.wait_for_stable_switches(fabric)
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
            # ND temporarily marks compliance pending after the default-only
            # update. Wait for normal/inSync without a fabric-wide deploy.
            self.wait_for_fabric_sync(fabric, {target['serial'] for target in before_targets})
        self.fabric_defaults.append({"fabric": fabric, "hostInterfaceAdminState": management["hostInterfaceAdminState"]})
        if self.apply:
            self.ready_switches(fabric)

    def run(self):
        self.deadline = self.clock() + self.timeout
        reason = "AUDIT_COMPLETE" if not self.apply else "BASELINE_VERIFIED"
        failed = False
        plan = []
        required_plan = []
        try:
            if self.apply and self.preexisting_connectivity_advisory:
                # Before any write, including configuration sync recovery.
                self.snapshot_preexisting_alerts()
            seen = set()
            for fabric in self.fabrics:
                if self.recover_config_sync:
                    self.reconcile_fabric_sync(fabric)
                for attempt in range(3):
                    decision_start = len(self.decisions)
                    previous_incomplete = self.readiness_incomplete
                    readiness_error = None
                    try:
                        prefix, targets = self.ready_switches(fabric)
                    except BaselineBlocked as error:
                        if str(error) != "SWITCH_READINESS_OR_IDENTITY_UNVERIFIED":
                            raise
                        readiness_error = error
                    failures = self.decisions[decision_start:]
                    retryable = failures and all(row.get("failed_checks") == ["configSyncStatus"] for row in failures)
                    if not retryable or attempt == 2 or self.deadline - self.clock() <= self.poll:
                        if readiness_error is not None:
                            raise readiness_error
                        break
                    del self.decisions[decision_start:]
                    self.readiness_incomplete = previous_incomplete
                    self.sleep(self.poll)
                linked = self.linked_ports(fabric) if targets else set()
                required = (self.required_ports | self.linked_ports(fabric, parents=False)
                            if self.ensure_required_admin_up else set())
                for target in targets:
                    if target["serial"] in seen:
                        raise BaselineBlocked("DUPLICATE_SWITCH_MEMBERSHIP")
                    seen.add(target["serial"])
                    rows = self.interface_rows(prefix, target["serial"])
                    if self.ensure_required_admin_up:
                        present = {physical_interface(row["interfaceName"]) for row in rows
                                   if "." not in row["interfaceName"]}
                        if not {name for serial, name in required if serial == target["serial"]} <= present:
                            raise BaselineBlocked("REQUIRED_INTERFACE_SCOPE_INCOMPLETE")
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
                        elif (target["serial"], physical_interface(name)) in required:
                            decision, detail, _ = self.required_detail(prefix, target, name)
                            if decision == "REQUIRED_ADMIN_UP_PENDING":
                                required_plan.append((fabric, target, name, copy.deepcopy(detail["configData"])))
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
            self.required_candidates = len(required_plan)
            if self.apply:
                self.apply_required_ports(required_plan)
            batch_mode = self.apply and len(plan) > 1
            if batch_mode:
                self.apply_batches(plan)
            for fabric, target, name, original in plan if self.apply and not batch_mode else []:
                prefix, fresh_targets = self.wait_for_stable_switches(fabric)
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
                self.wait_for_stable_switches(fabric, after_deploy=True)
                self.verify(path, expected, fabric, target, name)
                self.verified += 1
            if self.apply:
                self.require_connectivity_clearance()
            if self.ensure_host_admin_down_default:
                for fabric in self.fabrics:
                    self.host_admin_default(fabric)
                if self.apply:
                    # Compliance polling can take several collector cycles;
                    # require fresh alarm evidence after that wait too.
                    self.require_connectivity_clearance()
        except BaselineBlocked as error:
            failed, reason = True, str(error)
        except Exception as error:
            # The type only: messages can echo controller payloads.
            self.decisions.append({"decision": "UNEXPECTED_ERROR", "error_type": type(error).__name__})
            failed, reason = True, "API_OR_SCHEMA_UNVERIFIED"
        return {"changed": self.changed, "failed": failed, "baseline_failed": failed, "msg": "NDP_INTERFACE_BASELINE " + reason,
                "candidates": self.candidates, "verified": self.verified, "inspected": self.inspected,
                "apply": self.apply, "decisions": self.decisions, "reason": reason,
                "api_failure": self.api_failure,
                "remaining_connectivity_alerts": self.remaining_connectivity_alerts,
                "preexisting_connectivity_alerts": self.preexisting_connectivity_alerts,
                "connectivity_alerts": self.connectivity_alerts,
                "connectivity_alerts_truncated": self.connectivity_alerts_truncated,
                "connectivity_verified_fabrics": self.connectivity_verified_fabrics,
                "fabric_defaults": self.fabric_defaults, "idle_reserved_ports": self.idle_reserved_ports,
                "required_candidates": self.required_candidates, "required_verified": self.required_verified}


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
                arguments["recover_config_sync"] = False
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
                except (bounds.CallExpired, TimeoutError) as error:
                    raise RequestUnconfirmed("API_CALL_TIMEOUT") from error
                except (PersistentConnectionError, AnsibleConnectionFailure) as error:
                    # The daemon reports its command timeout as a connection error.
                    timed_out = re.search(r"(?i)timed? ?out", str(error))
                    raise RequestUnconfirmed("API_CALL_TIMEOUT" if timed_out else "API_TRANSPORT_UNVERIFIED") from error
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
