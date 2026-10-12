# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Read-only integration-test observer for breakout topology and policy intent.

This is intentionally not a module runner.  The playbook invokes the production
module and asserts its registered result separately.  This plugin then reads
interfaces and breakout policies through ``nd_rest`` and compares independent
observations against a caller-declared hardware footprint.  It does not import
the production module's classifier, resolver, endpoints or response handling.

The validator task MUST set ``check_mode: false``: ``nd_rest`` skips even GETs in
check mode.  All calls made here are GETs.  Observation calls are returned
separately so they are never included in the production module's API budget.

Arguments:
  fabric_name, switch_id: fabric name and already-resolved switch serial.
  fixture: control_parent, native_interfaces, profiles, optional guard_interfaces
    and interface_filter. A profile contains breakout_map, child_lanes mapping
    parent names to positive lane numbers, optional native_interfaces, and
    optional policy_maps (defaults to each declared child family's map).
  expected_profile: native or a fixture profile label.
  observe_only: acquire a strict scoped snapshot without a desired-state check.
  validate_only: validate the entire fixture schema locally, with no GETs or
    snapshot. Use this in setup BEFORE the first production mutation so a bad
    profile cannot prevent the subsequent independent observation or cleanup.
  baseline, unchanged: compare fresh state to a prior snapshot. Configured guard
    families and their policies are always compared when a baseline is supplied.
  retries, interval: GET-only settling, default 3 attempts separated by 1 second;
    at most 10 attempts and 60 seconds of total requested sleep.

Snapshots contain ``families[parent].native``, ``families[parent].children`` and
``policy_maps``. Missing collateral native ports are representable, not proof of
an error: some hardware removes them while the declared group is broken out.
All profiles are supplied BEFORE testing, never learned from the post-write
observation. A custom interface_filter must cover every full family in the
reserved footprint and guards; the default uses full-family wildcard clauses.
Policy MAP proves controller intent, not running configuration or link speed.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
import time
from collections import defaultdict
from os.path import commonprefix
from urllib.parse import quote, urlencode

from ansible.errors import AnsibleError
from ansible.plugins.action import ActionBase

_PARENT = re.compile(r"^Ethernet([1-9]\d*)/([1-9]\d*)$", re.IGNORECASE)
_PAGE_SIZE = 1000
_MAX_PAGES = 100


class ObservationError(ValueError):
    """Missing or ambiguous evidence must not become an absence assertion."""


def _parent(value):
    if not isinstance(value, str) or not _PARENT.fullmatch(value.strip()):
        raise ObservationError("Fixture interface names must be native Ethernet parents.")
    slot, port = _PARENT.fullmatch(value.strip()).groups()
    return "Ethernet%s/%s" % (slot, port)


def _parents(values, field, allow_empty=False):
    if not isinstance(values, list) or (not values and not allow_empty):
        raise ObservationError("%s must be a %slist of native parents." % (field, "nonempty " if not allow_empty else ""))
    names = [_parent(value) for value in values]
    if len(set(names)) != len(names):
        raise ObservationError("%s contains duplicate parents." % field)
    return sorted(names)


def _map(value):
    if not isinstance(value, str) or not value.strip():
        raise ObservationError("Every expected or observed breakout MAP must be a nonempty string.")
    return value.strip().lower()


def _prepare_fixture(raw):
    if not isinstance(raw, dict):
        raise ObservationError("fixture must be a dictionary.")
    native = _parents(raw.get("native_interfaces"), "fixture.native_interfaces")
    control = _parent(raw.get("control_parent"))
    if control not in native:
        raise ObservationError("control_parent must be in the reserved native_interfaces footprint.")
    guards = _parents(raw.get("guard_interfaces", []), "fixture.guard_interfaces", allow_empty=True)
    if set(guards) & set(native):
        raise ObservationError("guard_interfaces must be outside the reserved footprint.")
    profiles = raw.get("profiles", {})
    if not isinstance(profiles, dict):
        raise ObservationError("fixture.profiles must be a dictionary.")
    prepared = {}
    for label, profile in profiles.items():
        if not isinstance(label, str) or not label.strip() or label == "native" or not isinstance(profile, dict):
            raise ObservationError("Profile labels must be nonempty, non-native names with dictionary values.")
        breakout_map = _map(profile.get("breakout_map"))
        lanes = profile.get("child_lanes")
        if not isinstance(lanes, dict) or not lanes:
            raise ObservationError("Every breakout profile needs a nonempty child_lanes mapping.")
        children = {}
        for name, numbers in lanes.items():
            parent = _parent(name)
            if parent not in native or parent in children:
                raise ObservationError("child_lanes must uniquely name parents in the reserved footprint.")
            if not isinstance(numbers, list) or not numbers or any(not isinstance(lane, int) or isinstance(lane, bool) or lane < 1 for lane in numbers):
                raise ObservationError("child_lanes values must be nonempty lists of positive integer lanes.")
            if len(set(numbers)) != len(numbers):
                raise ObservationError("child_lanes contains duplicate lanes.")
            children[parent] = [parent + "/" + str(lane) for lane in sorted(numbers)]
        if control not in children:
            raise ObservationError("Every breakout profile must break out the control_parent.")
        retained = _parents(
            profile.get("native_interfaces", []),
            "profile.native_interfaces",
            allow_empty=True,
        )
        if not set(retained) <= set(native) or set(retained) & set(children):
            raise ObservationError("Retained native parents must be reserved and cannot also have children.")
        maps = profile.get("policy_maps", {parent: breakout_map for parent in children})
        if not isinstance(maps, dict):
            raise ObservationError("profile.policy_maps must be a dictionary.")
        policy_maps = {}
        for name, value in maps.items():
            parent = _parent(name)
            if parent not in native or parent in policy_maps:
                raise ObservationError("policy_maps must uniquely name parents in the reserved footprint.")
            policy_maps[parent] = _map(value)
        if policy_maps.get(control) != breakout_map:
            raise ObservationError("Every profile must verify the requested control_parent MAP.")
        prepared[label] = {
            "children": children,
            "native": retained,
            "policy_maps": policy_maps,
        }
    custom_filter = raw.get("interface_filter")
    if custom_filter is not None and (not isinstance(custom_filter, str) or not custom_filter.strip()):
        raise ObservationError("interface_filter must be a nonempty full-footprint query when supplied.")
    return {
        "control": control,
        "native": native,
        "guards": guards,
        "profiles": prepared,
        "interface_filter": custom_filter,
    }


def _families(rows, switch_id, parents):
    """Independent exact-match physical topology projection, without production imports."""
    wanted = {name.casefold(): name for name in parents}
    state = {name: {"native": False, "children": []} for name in sorted(parents)}
    seen = set()
    for row in rows:
        name = row.get("interfaceName")
        if not isinstance(name, str):
            raise ObservationError("Interface rows must contain a string interfaceName.")
        canonical = wanted.get(name.casefold())
        lane = None
        if canonical is None:
            base, separator, suffix = name.rpartition("/")
            canonical = wanted.get(base.casefold()) if separator and re.fullmatch(r"[1-9]\d*", suffix) else None
            lane = int(suffix) if canonical is not None else None
        if canonical is None:
            continue  # Prefix lookalikes, dotted subinterfaces and unrelated candidates.
        if row.get("switchId") != switch_id:
            raise ObservationError("Interface observation returned an unexpected switch identity for " + name + ".")
        identity = name.casefold()
        if identity in seen:
            raise ObservationError("Duplicate interface identity in complete observation: " + name + ".")
        seen.add(identity)
        if row.get("physicalInterface") is False:
            continue  # A ghost/config-only parent cannot prove native topology.
        if row.get("physicalInterface") is not True or row.get("fex") is not False:
            raise ObservationError("Incomplete physicalInterface/fex evidence or unsupported FEX row for " + name + ".")
        if lane is None:
            state[canonical]["native"] = True
        else:
            state[canonical]["children"].append(canonical + "/" + str(lane))
    for parent, family in state.items():
        family["children"].sort(key=lambda name: int(name.rsplit("/", 1)[1]))
        if family["native"] and family["children"]:
            raise ObservationError("Ambiguous native parent and physical children for " + parent + ".")
    return state


def _policy_maps(rows, switch_id, parents):
    wanted = {name.casefold(): name for name in parents}
    maps = {}
    seen_ids = set()
    for row in rows:
        if any(not isinstance(row.get(field), str) or not row[field].strip() for field in ("switchId", "entityName", "templateName", "policyId")):
            raise ObservationError("Policy rows need explicit switch, entity, template and policy identities.")
        name = row.get("entityName")
        parent = wanted.get(name.casefold()) if isinstance(name, str) else None
        if parent is None or str(row.get("templateName", "")).casefold() != "breakout_interface":
            continue
        if row.get("switchId") != switch_id:
            raise ObservationError("Policy observation returned an unexpected switch identity for " + name + ".")
        policy_id = row.get("policyId")
        if not isinstance(policy_id, str) or not policy_id.strip() or policy_id in seen_ids:
            raise ObservationError("Missing or duplicate breakout policy identity for " + name + ".")
        seen_ids.add(policy_id)
        if row.get("markDeleted") is True:
            continue
        if row.get("markDeleted") is not False or str(row.get("entityType", "")).casefold() != "interface":
            raise ObservationError("Incomplete active breakout policy evidence for " + name + ".")
        if parent in maps:
            raise ObservationError("Multiple active breakout policies for " + parent + ".")
        inputs = row.get("templateInputs")
        values = [value for key, value in inputs.items() if str(key).casefold() == "map"] if isinstance(inputs, dict) else []
        if len(values) != 1:
            raise ObservationError("Breakout policy must contain exactly one MAP for " + parent + ".")
        maps[parent] = _map(values[0])
    return dict(sorted(maps.items()))


def _compare(snapshot, fixture, profile, baseline=None, unchanged=False):
    differences = []
    if profile == "native":
        expected = {"children": {}, "native": fixture["native"], "policy_maps": {}}
    else:
        expected = fixture["profiles"][profile]
    for parent in fixture["native"]:
        family = snapshot["families"][parent]
        want = {
            "native": parent in expected["native"],
            "children": expected["children"].get(parent, []),
        }
        if family != want:
            differences.append(
                {
                    "check": "topology",
                    "interface": parent,
                    "expected": want,
                    "actual": family,
                }
            )
    actual_maps = {parent: value for parent, value in snapshot["policy_maps"].items() if parent in fixture["native"]}
    if actual_maps != expected["policy_maps"]:
        differences.append(
            {
                "check": "policy_maps",
                "expected": expected["policy_maps"],
                "actual": actual_maps,
            }
        )
    if baseline is not None:
        if unchanged and baseline != snapshot:
            differences.append({"check": "unchanged", "expected": baseline, "actual": snapshot})
        for parent in fixture["guards"]:
            if baseline["families"][parent] != snapshot["families"][parent]:
                differences.append(
                    {
                        "check": "guard_topology",
                        "interface": parent,
                        "expected": baseline["families"][parent],
                        "actual": snapshot["families"][parent],
                    }
                )
            if baseline["policy_maps"].get(parent) != snapshot["policy_maps"].get(parent):
                differences.append(
                    {
                        "check": "guard_policy",
                        "interface": parent,
                        "expected": baseline["policy_maps"].get(parent),
                        "actual": snapshot["policy_maps"].get(parent),
                    }
                )
    return differences


def _baseline(raw, switch_id, parents):
    if raw is None:
        return None
    if (
        not isinstance(raw, dict)
        or raw.get("switch_id") != switch_id
        or not isinstance(raw.get("families"), dict)
        or not isinstance(raw.get("policy_maps"), dict)
    ):
        raise ObservationError("baseline must be a snapshot for the same switch and complete footprint.")
    if set(raw["families"]) != set(parents) or not set(raw["policy_maps"]) <= set(parents):
        raise ObservationError("baseline families/policies must exactly cover the same fixture scope.")
    for parent, family in raw["families"].items():
        if not isinstance(family, dict) or type(family.get("native")) is not bool or not isinstance(family.get("children"), list):
            raise ObservationError("baseline family state is malformed for " + parent + ".")
        child_pattern = re.compile(re.escape(parent) + r"/[1-9]\d*$")
        children = family["children"]
        if any(not isinstance(name, str) or not child_pattern.fullmatch(name) for name in children) or len(set(children)) != len(children):
            raise ObservationError("baseline children must be unique exact members of " + parent + ".")
        if family["native"] and children:
            raise ObservationError("baseline has ambiguous parent and children for " + parent + ".")
    for value in raw["policy_maps"].values():
        if _map(value) != value:
            raise ObservationError("baseline MAP values must be normalized snapshot values.")
    return copy.deepcopy(raw)


class ActionModule(ActionBase):
    """Only GET through nd_rest; return independent fixture-scoped evidence."""

    def _pages(self, path, query, collection, task_vars, calls):
        offset = 0
        collected = []
        fingerprints = set()
        for _ in range(_MAX_PAGES):
            url = path + "?" + urlencode({**query, "max": _PAGE_SIZE, "offset": offset})
            call = {"method": "GET", "path": url, "collection": collection}
            calls.append(call)
            raw = self._execute_module(
                module_name="cisco.nd.nd_rest",
                module_args={"method": "GET", "path": url},
                task_vars=task_vars,
            )
            if not isinstance(raw, dict) or raw.get("failed") or raw.get("skipped"):
                raise ObservationError(
                    "Read-only observation failed or was skipped: " + str(raw.get("msg", "invalid nd_rest response") if isinstance(raw, dict) else raw)
                )
            call["status"] = raw.get("status")
            status = raw.get("status")
            if isinstance(status, bool) or not isinstance(status, int) or status != 200:
                raise ObservationError("GET observation must return explicit HTTP 200 evidence.")
            data = raw.get("current")
            if not isinstance(data, dict):
                raise ObservationError("nd_rest observation must return a current dictionary.")
            meta = data.get("meta", {})
            counts = meta.get("counts", {}) if isinstance(meta, dict) else None
            if not isinstance(counts, dict):
                raise ObservationError("Invalid observation pagination metadata.")
            for key in ("remaining", "total"):
                if key in counts and (not isinstance(counts[key], int) or isinstance(counts[key], bool) or counts[key] < 0):
                    raise ObservationError("Invalid observation pagination counts.")
            # Some controller builds omit an empty collection rather than
            # returning []. Accept only an initial, explicitly zero-count
            # envelope. Null/wrong-type arrays and incomplete/later pages are
            # never converted into evidence of absence.
            confirmed_empty = collection not in data and offset == 0 and counts.get("total") == 0 and counts.get("remaining") == 0
            rows = [] if confirmed_empty else data.get(collection)
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise ObservationError("Observation must contain a " + collection + " array of objects.")
            fingerprint = json.dumps(rows, sort_keys=True, separators=(",", ":"))
            if rows and fingerprint in fingerprints:
                raise ObservationError("Observation repeated a page; pagination is incomplete.")
            fingerprints.add(fingerprint)
            collected.extend(rows)
            if "total" in counts and offset + len(rows) > counts["total"]:
                raise ObservationError("Observation contains more rows than its declared total.")
            if "remaining" in counts and "total" in counts and offset + len(rows) + counts["remaining"] != counts["total"]:
                raise ObservationError("Observation pagination remaining and total disagree.")
            more = (
                counts["remaining"] > 0 if "remaining" in counts else (offset + len(rows) < counts["total"] if "total" in counts else len(rows) >= _PAGE_SIZE)
            )
            if not more:
                return collected
            if not rows:
                raise ObservationError("Observation ended before pagination completed.")
            offset += len(rows)
        raise ObservationError("Observation exceeded the pagination safety limit.")

    def _observe(self, fabric, switch_id, fixture, task_vars, calls):
        parents = sorted(fixture["native"] + fixture["guards"])
        base = "/api/v1/manage/fabrics/" + fabric + "/"
        # Wildcard summary filters are verified; summary OR filters are not.
        # Independent disjoint slot/leading-port-digit buckets stay narrow.
        if fixture["interface_filter"]:
            interface_filters = [fixture["interface_filter"]]
        else:
            buckets = defaultdict(list)
            for parent in parents:
                slot, port = _PARENT.fullmatch(parent).groups()
                buckets[(int(slot), port[0])].append(port)
            interface_filters = ["interfaceName:*Ethernet" + str(slot) + "/" + commonprefix(ports) + "*" for (slot, _), ports in sorted(buckets.items())]
        interfaces = []
        for interface_filter in interface_filters:
            interfaces.extend(
                self._pages(
                    base + "interfacesSummary",
                    {
                        "switchId": switch_id,
                        "includeAll": "true",
                        "filter": interface_filter,
                    },
                    "interfaces",
                    task_vars,
                    calls,
                )
            )
        families = _families(interfaces, switch_id, parents)
        policy_filter = " OR ".join("switchId:" + switch_id + " AND templateName:breakout_interface AND entityName:" + parent for parent in parents)
        policies = self._pages(base + "policies", {"filter": policy_filter}, "policies", task_vars, calls)
        return {
            "switch_id": switch_id,
            "families": families,
            "policy_maps": _policy_maps(policies, switch_id, parents),
        }

    def run(self, tmp=None, task_vars=None):
        result = super().run(tmp, task_vars)
        result.update(changed=False, checks=[], differences=[], observation_calls=[])
        task_vars = task_vars or {}
        try:
            args = self._task.args or {}
            allowed = {
                "fabric_name",
                "switch_id",
                "fixture",
                "expected_profile",
                "baseline",
                "unchanged",
                "observe_only",
                "validate_only",
                "retries",
                "interval",
            }
            if set(args) - allowed:
                raise ObservationError("Unknown validator arguments: " + ", ".join(sorted(set(args) - allowed)) + ".")
            fabric = args.get("fabric_name")
            switch_id = args.get("switch_id")
            if not isinstance(fabric, str) or not fabric.strip() or not isinstance(switch_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", switch_id):
                raise ObservationError("fabric_name and a nonempty switch serial switch_id are required.")
            try:
                ipaddress.ip_address(switch_id)
            except ValueError:
                pass
            else:
                raise ObservationError("Observer switch_id must be a serial, not a management IP address.")
            # Fabric is a URL path segment; unlike Lucene interface values it is encoded.
            fabric = quote(fabric.strip(), safe="")
            fixture = _prepare_fixture(args.get("fixture"))
            profile = args.get("expected_profile", "native")
            if not isinstance(profile, str) or profile not in {
                "native",
                *fixture["profiles"],
            }:
                raise ObservationError("expected_profile must be native or a configured profile label.")
            for flag in ("unchanged", "observe_only", "validate_only"):
                if type(args.get(flag, False)) is not bool:
                    raise ObservationError(flag + " must be a boolean.")
            observe_only = args.get("observe_only", False)
            validate_only = args.get("validate_only", False)
            unchanged = args.get("unchanged", False)
            baseline = _baseline(args.get("baseline"), switch_id, fixture["native"] + fixture["guards"])
            if unchanged and baseline is None:
                raise ObservationError("unchanged validation requires a baseline snapshot.")
            if fixture["guards"] and baseline is None and not observe_only and not validate_only:
                raise ObservationError("Configured guards require a baseline snapshot; capture one with observe_only first.")
            if observe_only and unchanged:
                raise ObservationError("observe_only cannot be combined with unchanged validation.")
            if validate_only and (observe_only or unchanged):
                raise ObservationError("validate_only cannot be combined with observe_only or unchanged.")
            retries = args.get("retries", 3)
            interval = args.get("interval", 1)
            if (
                not isinstance(retries, int)
                or isinstance(retries, bool)
                or not 1 <= retries <= 10
                or not isinstance(interval, (int, float))
                or isinstance(interval, bool)
                or not 0 <= interval <= 60
                or (retries - 1) * interval > 60
            ):
                raise ObservationError("retries/interval must request 1-10 attempts and at most 60 seconds total settling sleep.")
            if validate_only:
                result.update(failed=False, validated=True, checks=["fixture_schema"])
                return result
            if self._task.check_mode:
                raise ObservationError("Set check_mode: false on this GET-only validator task; nd_rest skips GETs in check mode.")
            for attempt in range(retries):
                snapshot = self._observe(fabric, switch_id, fixture, task_vars, result["observation_calls"])
                result["snapshot"] = snapshot
                result["attempts"] = attempt + 1
                differences = [] if observe_only else _compare(snapshot, fixture, profile, baseline, unchanged)
                result["differences"] = differences
                if not differences:
                    result["checks"] = ["strict_observation"] if observe_only else ["topology", "policy_maps"]
                    if not observe_only and unchanged:
                        result["checks"].append("unchanged")
                    if not observe_only and fixture["guards"]:
                        result["checks"].append("guards")
                    result["failed"] = False
                    return result
                if attempt + 1 < retries:
                    time.sleep(interval)
            result.update(
                failed=True,
                msg="Independent breakout topology/policy validation did not match the declared fixture profile.",
            )
        except (AnsibleError, ObservationError, TypeError, ValueError) as error:
            result.update(failed=True, msg=str(error))
        return result
