"""Bounded batch discovery using the collection's existing nd_rest module."""
from contextlib import contextmanager
import math
import signal
import time
from urllib.parse import quote

from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils.connection import Connection, ConnectionError as PersistentConnectionError
from ansible.plugins.action import ActionBase


class CallExpired(Exception):
    pass


@contextmanager
def bounded_call(seconds):
    """Bound controller waiting without replacing an earlier Ansible alarm."""
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()
    own_deadline = started + seconds
    previous_deadline = started + previous_timer[0] if previous_timer[0] else None

    def expired(signum, frame):
        nonlocal previous_deadline
        if previous_deadline is not None and time.monotonic() >= previous_deadline:
            previous_deadline = previous_deadline + previous_timer[1] if previous_timer[1] else None
            if callable(previous_handler):
                previous_handler(signum, frame)
            elif previous_handler == signal.SIG_DFL:
                signal.signal(signal.SIGALRM, previous_handler)
                signal.raise_signal(signal.SIGALRM)
            remaining = own_deadline - time.monotonic()
            if remaining > 0:
                signal.setitimer(signal.ITIMER_REAL, min(remaining, previous_deadline - time.monotonic())
                                 if previous_deadline is not None else remaining)
                return
        raise CallExpired()

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(seconds, previous_timer[0]) if previous_timer[0] else seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_deadline is not None:
            signal.setitimer(signal.ITIMER_REAL, max(previous_deadline - time.monotonic(), 0.000001), previous_timer[1])


class DiscoveryGate:
    def __init__(self, seeds, protocols, request, timeout_seconds=900, call_timeout_seconds=60,
                 interval_seconds=20, retries=None, clock=time.monotonic, sleep=time.sleep):
        if (not isinstance(seeds, list) or not all(isinstance(row, dict) for row in seeds)
                or not isinstance(protocols, list)):
            raise ValueError("Invalid discovery inputs")
        self.seeds = {row["seed_ip"]: row for row in seeds}
        if len(self.seeds) != len(seeds) or not seeds or any(
                not isinstance(row.get(key), str) or not row[key]
                for row in seeds for key in ("seed_ip", "serial", "fabric")):
            raise ValueError("Invalid expected identities")
        self.protocols = list(dict.fromkeys(str(value).lower().replace("_", "-") for value in protocols))
        if not self.protocols or any(not isinstance(value, str) or not value for value in protocols):
            raise ValueError("Invalid protocols")
        self.request, self.clock, self.sleep = request, clock, sleep
        self.timeout = float(timeout_seconds)
        self.call_timeout = float(call_timeout_seconds)
        self.interval = float(interval_seconds)
        if (not all(math.isfinite(value) for value in (self.timeout, self.call_timeout, self.interval))
                or self.timeout <= 0 or self.call_timeout <= 0 or self.interval < 0):
            raise ValueError("Invalid deadline")
        self.timeout = min(self.timeout, 900.0)
        # Older Ansible renders an unset templated argument as an empty string.
        self.retries = None if retries is None or retries == "" else max(int(retries), 0)
        self.ready, self.permanent, self.status = {}, {ip: {} for ip in self.seeds}, {}
        self.calls = 0

    def result(self, reason):
        failed = reason != "READY"
        return {"changed": False, "failed": failed,
                "msg": ("NDP_SWITCH_REDISCOVER_UNREADY" if failed else "NDP_SWITCH_REDISCOVER_READY") + " reason=" + reason,
                "discovery_status": reason, "discovery_seconds": round(self.clock() - self.started, 3),
                "discovery_batches": self.calls, "protocol_by_seed": self.ready,
                "pending": [{"seed_ip": ip, "status": self.status.get(ip, "NOT_PROBED"),
                             "protocol_failures": self.permanent[ip]} for ip in self.seeds if ip not in self.ready]}

    def classify(self, response, batch, protocol):
        if not isinstance(response, dict):
            return "MALFORMED_RESPONSE"
        code = response.get("status", 0)
        if response.get("failed") or code != 200:
            for ip in batch:
                diagnostic = response.get("_discovery_status")
                self.status[ip] = diagnostic if diagnostic in ("API_TIMEOUT", "API_CONNECTION_ERROR") else (
                    "HTTP_" + str(code) if isinstance(code, int) else "API_ERROR")
                if code in (401, 403):
                    self.permanent[ip][protocol] = "AUTH_REJECTED"
            if code in (401, 403, 408, 421, 425, 429) or isinstance(code, int) and code >= 500 or response.get("_discovery_status"):
                return None
            return "API_REJECTED"
        body = response.get("current")
        if not isinstance(body, dict) or not isinstance(body.get("switches"), list):
            return "MALFORMED_RESPONSE"
        rows = {}
        serial_ips = {seed["serial"]: ip for ip, seed in self.seeds.items()}
        for row in body["switches"]:
            if not isinstance(row, dict):
                return "MALFORMED_RESPONSE"
            ip = row.get("ip") or row.get("seedIp")
            serial, status = row.get("serialNumber", ""), row.get("status", "")
            serial = "" if serial is None else serial
            status = "" if status is None else status
            if (not isinstance(ip, str) or not ip or not isinstance(serial, str)
                    or not isinstance(status, str) or (row.get("ip") and row.get("seedIp") and row["ip"] != row["seedIp"])):
                return "MALFORMED_RESPONSE"
            if ip in rows or (serial in serial_ips and serial_ips[serial] != ip):
                return "CONFLICTING_IDENTITY"
            rows[ip] = dict(row, serialNumber=serial, status=status)
        for ip in batch:
            row = rows.get(ip, {})
            serial, status = row.get("serialNumber", ""), row.get("status", "").lower()
            if serial and serial != self.seeds[ip]["serial"]:
                return "IDENTITY_MISMATCH"
            if status not in ("", "manageable", "ok", "alreadymanaged", "notreachable", "notreacheable",
                              "unreachable", "notauthorized", "unauthorized", "notmanageable"):
                self.status[ip] = "UNSUPPORTED_STATUS"
                return "UNSUPPORTED_STATUS"
            self.status[ip] = status or "IDENTITY_PENDING"
            if status in ("notauthorized", "unauthorized", "notmanageable"):
                self.permanent[ip][protocol] = status
            elif status in ("manageable", "ok", "alreadymanaged") and serial:
                self.ready[ip] = protocol
        return None

    def run(self):
        self.started = self.clock()
        deadline, cycle = self.started + self.timeout, 0
        while True:
            for protocol in self.protocols:
                fabrics = {}
                for ip, seed in self.seeds.items():
                    if ip not in self.ready and protocol not in self.permanent[ip]:
                        fabrics.setdefault(seed["fabric"], []).append(ip)
                for fabric, batch in fabrics.items():
                    remaining = deadline - self.clock()
                    if remaining <= 0:
                        return self.result("DEADLINE_EXCEEDED")
                    self.calls += 1
                    try:
                        response = self.request(fabric, batch, protocol, min(self.call_timeout, remaining))
                    except CallExpired:
                        response = {"failed": True, "status": 0, "_discovery_status": "API_TIMEOUT"}
                    if self.clock() >= deadline:
                        return self.result("DEADLINE_EXCEEDED")
                    reason = self.classify(response, batch, protocol)
                    if self.clock() >= deadline:
                        return self.result("DEADLINE_EXCEEDED")
                    if reason:
                        return self.result(reason)
                    if any(len(self.permanent[ip]) == len(self.protocols) for ip in self.seeds if ip not in self.ready):
                        return self.result("PERMANENT_DISCOVERY_FAILURE")
            if self.clock() >= deadline:
                return self.result("DEADLINE_EXCEEDED")
            if len(self.ready) == len(self.seeds):
                return self.result("READY")
            if any(len(self.permanent[ip]) == len(self.protocols) for ip in self.seeds if ip not in self.ready):
                return self.result("PERMANENT_DISCOVERY_FAILURE")
            if self.retries is not None and cycle >= self.retries:
                return self.result("RETRY_LIMIT")
            remaining = deadline - self.clock()
            if remaining <= 0:
                return self.result("DEADLINE_EXCEEDED")
            self.sleep(min(self.interval, remaining))
            cycle += 1


class ActionModule(ActionBase):
    _supports_check_mode = False

    def run(self, tmp=None, task_vars=None):
        super().run(tmp, task_vars)
        values = task_vars or {}
        credentials = self._templar.template({"username": values.get("nd_switch_username", values.get("switch_username")),
                                             "password": values.get("nd_switch_password", values.get("switch_password"))})
        username, password = credentials["username"], credentials["password"]

        def request(fabric, seeds, protocol, limit):
            content = {"seedIpCollection": seeds, "maxHop": 0, "platformType": "nx-os",
                       "snmpV3AuthProtocol": protocol, "username": username, "password": password}
            old_no_log = self._task.no_log
            self._task.no_log = True
            call_deadline = time.monotonic() + limit
            rpc = None
            previous_remote = previous_local = None
            try:
                with bounded_call(limit):
                    restore_allowed = True
                    try:
                        if getattr(self._connection, "_socket_path", None):
                            rpc = Connection(self._connection._socket_path)
                            previous_remote = rpc.get_option("persistent_command_timeout")
                            previous_local = self._connection.get_option("persistent_command_timeout")
                            command_timeout = max(1, int(call_deadline - time.monotonic()))
                            rpc.set_option("persistent_command_timeout", command_timeout)
                            self._connection.set_option("persistent_command_timeout", command_timeout)
                        return self._execute_module(module_name="cisco.nd.nd_rest", module_args={
                            "method": "post", "path": "/api/v1/manage/fabrics/" + quote(fabric, safe="") + "/actions/shallowDiscovery",
                            "content": content}, task_vars=values)
                    except (AnsibleConnectionFailure, PersistentConnectionError):
                        return {"failed": True, "status": 0, "_discovery_status": "API_CONNECTION_ERROR"}
                    except BaseException:
                        # Preserve cancellation/deadline/programming exceptions. A
                        # cleanup RPC must not replace them or consume more time.
                        restore_allowed = False
                        raise
                    finally:
                        if restore_allowed and rpc is not None and previous_remote is not None and time.monotonic() < call_deadline:
                            try:
                                rpc.set_option("persistent_command_timeout", previous_remote)
                            except (AnsibleConnectionFailure, PersistentConnectionError):
                                pass  # A dead daemon is reset by the next task's normal option setup.
                        if restore_allowed and previous_local is not None:
                            self._connection.set_option("persistent_command_timeout", previous_local)
            finally:
                self._task.no_log = old_no_log

        try:
            if not username or not password:
                raise ValueError("Missing credentials")
            gate = DiscoveryGate(request=request, **self._task.args)
        except (TypeError, ValueError, KeyError):
            return {"changed": False, "failed": True,
                    "msg": "NDP_SWITCH_REDISCOVER_UNREADY reason=INVALID_ARGUMENTS"}
        gate.started = time.monotonic()
        try:
            with bounded_call(gate.timeout):
                return gate.run()
        except CallExpired:
            return gate.result("DEADLINE_EXCEEDED")
