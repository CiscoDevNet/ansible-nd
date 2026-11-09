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
  whole_switch: read complete switch Ethernet topology and breakout policies;
    add outside_families and outside_policy_maps for nonreserved/non-guard scope.
  owned_interfaces: other reserved parent names validated by separate fixtures;
    exclude these from outside preservation checks (requires whole_switch).
  include_speeds: record each physical child's speed as numeric Gbps and compare
    it independently to the profile map (or optional child_speeds per parent).
  topology_only: retain policy diagnostics, but do not require reserved policy
    MAP equality. Guard and outside intent remain protected by the baseline.
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
import math
import re
import time
from collections import defaultdict
from os.path import commonprefix
from urllib.parse import quote, urlencode

from ansible.errors import AnsibleError
from ansible.plugins.action import ActionBase

_PARENT = re.compile(r"^Ethernet([1-9]\d*)/([1-9]\d*)$", re.IGNORECASE)
_MEMBER = re.compile(r"^Ethernet([1-9]\d*)/([1-9]\d*)(?:/([1-9]\d*))?$", re.IGNORECASE)
_PROFILE_MAP = re.compile(r"([1-9]\d*(?:\.\d+)?)g-([1-9]\d*)x", re.IGNORECASE)
_SPEED = re.compile(r"(\d+(?:\.\d+)?)\s*([mgt])(?:b(?:it)?(?:/s|ps)?)?", re.IGNORECASE)
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


def _speed(value):
    """Normalize explicitly unit-bearing controller speeds; never guess units."""
    matched = _SPEED.fullmatch(value.strip()) if isinstance(value, str) else None
    if matched is None or not math.isfinite(float(matched.group(1))) or float(matched.group(1)) <= 0:
        raise ObservationError("Physical child speed must contain a positive explicit Mbps/Gbps/Tbps value.")
    return float(matched.group(1)) * {"m": 0.001, "g": 1, "t": 1000}[matched.group(2).lower()]


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
        declared_speeds = profile.get("child_speeds", {})
        if not isinstance(declared_speeds, dict):
            raise ObservationError("profile.child_speeds must map parents to positive numeric Gbps.")
        speeds = {}
        for name, value in declared_speeds.items():
            parent = _parent(name)
            if (
                parent not in children
                or parent in speeds
                or isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ObservationError("profile.child_speeds must uniquely map child families to positive numeric Gbps.")
            speeds[parent] = value
        for parent in children:
            if parent not in speeds:
                match = _PROFILE_MAP.fullmatch(policy_maps.get(parent, breakout_map))
                if match is not None:
                    speeds[parent] = float(match.group(1))
        prepared[label] = {
            "children": children,
            "native": retained,
            "policy_maps": policy_maps,
            "child_speeds": speeds,
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


def _families(rows, switch_id, parents, include_speeds=False):
    """Independent exact-match physical topology projection, without production imports."""
    wanted = {name.casefold(): name for name in parents}
    state = {name: {"native": False, "children": []} for name in sorted(parents)}
    if include_speeds:
        for family in state.values():
            family["child_speeds"] = {}
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
            child = canonical + "/" + str(lane)
            state[canonical]["children"].append(child)
            if include_speeds:
                state[canonical]["child_speeds"][child] = _speed(row.get("speed"))
    for parent, family in state.items():
        family["children"].sort(key=lambda name: int(name.rsplit("/", 1)[1]))
        if family["native"] and family["children"]:
            raise ObservationError("Ambiguous native parent and physical children for " + parent + ".")
    return state


def _whole_parents(rows, switch_id):
    """Classify every physical Ethernet family before projecting reserved scope."""
    parents = set()
    for row in rows:
        name = row.get("interfaceName")
        if not isinstance(name, str):
            raise ObservationError("Interface rows must contain a string interfaceName.")
        match = _MEMBER.fullmatch(name)
        if match is None:
            continue
        if row.get("switchId") != switch_id:
            raise ObservationError("Interface observation returned an unexpected switch identity for " + name + ".")
        if row.get("physicalInterface") is False or row.get("fex") is True:
            continue
        if row.get("physicalInterface") is not True or row.get("fex") is not False:
            raise ObservationError("Incomplete physicalInterface/fex evidence for " + name + ".")
        parents.add("Ethernet%s/%s" % match.groups()[:2])
    return parents


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


def _compare(snapshot, fixture, profile, baseline=None, unchanged=False, include_speeds=False, topology_only=False):
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
        if include_speeds:
            children = expected["children"].get(parent, [])
            want["child_speeds"] = {child: expected["child_speeds"][parent] for child in children}
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
    if not topology_only and actual_maps != expected["policy_maps"]:
        differences.append(
            {
                "check": "policy_maps",
                "expected": expected["policy_maps"],
                "actual": actual_maps,
            }
        )
    if baseline is not None:
        prior = copy.deepcopy(baseline)
        current = copy.deepcopy(snapshot)
        if topology_only:
            for state in (prior, current):
                state["policy_maps"] = {parent: value for parent, value in state["policy_maps"].items() if parent not in fixture["native"]}
        if unchanged and prior != current:
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
        for field in ("outside_families", "outside_policy_maps"):
            if field in baseline and baseline[field] != snapshot.get(field):
                differences.append({"check": field, "expected": baseline[field], "actual": snapshot.get(field)})
    return differences


def _baseline(raw, switch_id, parents, include_speeds=False, whole_switch=False, owned_interfaces=None):
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
    if whole_switch and (not isinstance(raw.get("outside_families"), dict) or not isinstance(raw.get("outside_policy_maps"), dict)):
        raise ObservationError("whole_switch baseline must include outside_families and outside_policy_maps.")
    if whole_switch and raw.get("owned_interfaces", []) != (owned_interfaces or []):
        raise ObservationError("baseline owned_interfaces must match the current independent observer scope.")
    outside = raw.get("outside_families", {})
    outside_maps = raw.get("outside_policy_maps", {})
    if (
        not isinstance(outside, dict)
        or not isinstance(outside_maps, dict)
        or (set(outside) | set(outside_maps)) & (set(parents) | set(owned_interfaces or []))
    ):
        raise ObservationError("baseline outside scope must be a disjoint family/policy mapping.")
    for name in set(outside) | set(outside_maps):
        if _parent(name) != name:
            raise ObservationError("baseline outside parents must be canonical native Ethernet names.")
    for parent, family in {**raw["families"], **outside}.items():
        if not isinstance(family, dict) or not isinstance(family.get("native"), bool) or not isinstance(family.get("children"), list):
            raise ObservationError("baseline family state is malformed for " + parent + ".")
        child_pattern = re.compile(re.escape(parent) + r"/[1-9]\d*$")
        children = family["children"]
        if any(not isinstance(name, str) or not child_pattern.fullmatch(name) for name in children) or len(set(children)) != len(children):
            raise ObservationError("baseline children must be unique exact members of " + parent + ".")
        if family["native"] and children:
            raise ObservationError("baseline has ambiguous parent and children for " + parent + ".")
        if parent in outside and not children:
            raise ObservationError("baseline outside_families must contain only breakout families.")
        if include_speeds or "child_speeds" in family:
            speeds = family.get("child_speeds")
            if (
                not isinstance(speeds, dict)
                or set(speeds) != set(children)
                or any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0 for value in speeds.values())
            ):
                raise ObservationError("baseline child_speeds must cover exact children with positive numeric Gbps.")
    for value in list(raw["policy_maps"].values()) + list(outside_maps.values()):
        if _map(value) != value:
            raise ObservationError("baseline MAP values must be normalized snapshot values.")
    return copy.deepcopy(raw)


class ActionModule(ActionBase):
    """Only GET through nd_rest; return independent fixture-scoped evidence."""

    def _pages(self, path, query, collection, task_vars, calls):
        offset = 0
        collected = []
        fingerprints = set()
        declared_total = None
        for _unused_page in range(_MAX_PAGES):
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
            if "total" in counts:
                if declared_total is not None and declared_total != counts["total"]:
                    raise ObservationError("Observation pagination total changed between pages.")
                declared_total = counts["total"]
            fingerprint = json.dumps(rows, sort_keys=True, separators=(",", ":"))
            if rows and fingerprint in fingerprints:
                raise ObservationError("Observation repeated a page; pagination is incomplete.")
            fingerprints.add(fingerprint)
            collected.extend(rows)
            if declared_total is not None and offset + len(rows) > declared_total:
                raise ObservationError("Observation contains more rows than its declared total.")
            if "remaining" in counts and declared_total is not None and offset + len(rows) + counts["remaining"] != declared_total:
                raise ObservationError("Observation pagination remaining and total disagree.")
            more = (
                counts["remaining"] > 0
                if "remaining" in counts
                else (offset + len(rows) < declared_total if declared_total is not None else len(rows) >= _PAGE_SIZE)
            )
            if not more:
                return collected
            if not rows:
                raise ObservationError("Observation ended before pagination completed.")
            offset += len(rows)
        raise ObservationError("Observation exceeded the pagination safety limit.")

    def _observe(self, fabric, switch_id, fixture, task_vars, calls, whole_switch=False, include_speeds=False, owned_interfaces=None):
        parents = sorted(fixture["native"] + fixture["guards"])
        base = "/api/v1/manage/fabrics/" + fabric + "/"
        # Wildcard summary filters are verified; summary OR filters are not.
        # Independent disjoint slot/leading-port-digit buckets stay narrow.
        if whole_switch:
            interface_filters = ["interfaceType:ethernet"]
        elif fixture["interface_filter"]:
            interface_filters = [fixture["interface_filter"]]
        else:
            buckets = defaultdict(list)
            for parent in parents:
                slot, port = _PARENT.fullmatch(parent).groups()
                buckets[(int(slot), port[0])].append(port)
            interface_filters = [
                "interfaceName:*Ethernet" + str(slot) + "/" + commonprefix(ports) + "*" for (slot, _unused_prefix), ports in sorted(buckets.items())
            ]
        interfaces = []
        for interface_filter in interface_filters:
            interfaces.extend(
                self._pages(
                    base + "interfacesSummary",
                    {
                        "switchId": switch_id,
                        "includeAll": "true",
                        # The switchId query parameter also includes a vPC
                        # peer's rows. Filter the independently observed
                        # physical scope on the server as well.
                        "filter": f"{interface_filter} AND switchId:{switch_id}",
                    },
                    "interfaces",
                    task_vars,
                    calls,
                )
            )
        observed_parents = sorted(set(parents) | _whole_parents(interfaces, switch_id)) if whole_switch else parents
        all_families = _families(interfaces, switch_id, observed_parents, include_speeds)
        families = {parent: all_families[parent] for parent in parents}
        policy_filter = "switchId:" + switch_id + " AND templateName:breakout_interface"
        if not whole_switch:
            policy_filter = " OR ".join(policy_filter + " AND entityName:" + parent for parent in parents)
        policies = self._pages(base + "policies", {"filter": policy_filter}, "policies", task_vars, calls)
        policy_parents = set(parents)
        if whole_switch:
            policy_parents.update(
                _parent(row["entityName"]) for row in policies if isinstance(row.get("entityName"), str) and _PARENT.fullmatch(row["entityName"])
            )
        maps = _policy_maps(policies, switch_id, policy_parents)
        snapshot = {
            "switch_id": switch_id,
            "families": families,
            "policy_maps": {parent: value for parent, value in maps.items() if parent in parents},
        }
        if whole_switch:
            excluded = set(parents) | set(owned_interfaces or [])
            snapshot["owned_interfaces"] = owned_interfaces or []
            snapshot["outside_families"] = {parent: value for parent, value in all_families.items() if parent not in excluded and value["children"]}
            snapshot["outside_policy_maps"] = {parent: value for parent, value in maps.items() if parent not in excluded}
        return snapshot

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
                "whole_switch",
                "include_speeds",
                "topology_only",
                "owned_interfaces",
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
            for flag in ("unchanged", "observe_only", "validate_only", "whole_switch", "include_speeds", "topology_only"):
                if not isinstance(args.get(flag, False), bool):
                    raise ObservationError(flag + " must be a boolean.")
            observe_only = args.get("observe_only", False)
            validate_only = args.get("validate_only", False)
            unchanged = args.get("unchanged", False)
            whole_switch = args.get("whole_switch", False)
            include_speeds = args.get("include_speeds", False)
            topology_only = args.get("topology_only", False)
            owned_interfaces = _parents(args.get("owned_interfaces", []), "owned_interfaces", allow_empty=True)
            if owned_interfaces and not whole_switch:
                raise ObservationError("owned_interfaces requires whole_switch so other families remain observable.")
            if set(owned_interfaces) & set(fixture["guards"]):
                raise ObservationError("owned_interfaces cannot overlap protected guard_interfaces.")
            if include_speeds:
                for declared in fixture["profiles"].values():
                    if set(declared["child_speeds"]) != set(declared["children"]):
                        raise ObservationError("include_speeds requires a recognizable profile map or explicit child_speeds for every child family.")
            baseline = _baseline(args.get("baseline"), switch_id, fixture["native"] + fixture["guards"], include_speeds, whole_switch, owned_interfaces)
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
                snapshot = self._observe(fabric, switch_id, fixture, task_vars, result["observation_calls"], whole_switch, include_speeds, owned_interfaces)
                result["snapshot"] = snapshot
                result["attempts"] = attempt + 1
                differences = [] if observe_only else _compare(snapshot, fixture, profile, baseline, unchanged, include_speeds, topology_only)
                result["differences"] = differences
                if not differences:
                    result["checks"] = ["strict_observation"] if observe_only else ["topology"] + ([] if topology_only else ["policy_maps"])
                    if include_speeds and not observe_only:
                        result["checks"].append("child_speeds")
                    if whole_switch and baseline is not None and not observe_only:
                        result["checks"].append("outside_scope")
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
