#!/usr/bin/env python3
"""Static validation helpers for the prerequisite release."""
from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import re
import argparse
import sys

import yaml

ALLOWED_ROLES = {"leaf", "spine", "border", "edge_router", "preserve"}
RETAINED = {"VXLAN_EVPN_Fabric", "External_Connectivity_Fabric"}
PRESERVED = {"VXLAN_EVPN_Fabric_eBGP"}
PROTECTED = RETAINED | PRESERVED
ALLOWED_CONFIRMATION = {"confirmed", "pending", "rejected"}
ALLOWED_EXECUTION_STYLES = {"smoke_playbook", "integration_role", "standalone_integration"}
ALLOWED_DOMAINS = {
    "fabrics", "switches", "vpc_pairs", "physical_interfaces", "vpc_interfaces",
    "resource_allocations", "policies", "policy_groups", "vrfs", "networks",
    "l3outs", "acls", "prefix_lists", "route_maps", "vrf_lite",
}
# Inter-fabric link templates a profile may declare under `interfabric_links`.
# Mirrors ALLOWED_LINK_TEMPLATES in nd_prerequisite_orchestrator.py.
ALLOWED_LINK_TEMPLATES = {
    "ext_l3_dci_link",
}
REQUIRED_PROFILE_FIELDS = {
    "profile_id", "phase", "execution_style", "fabrics", "switches", "links",
    "vpc_pairs", "resources", "managed_domains", "runtime_vars", "timeouts",
    "restore", "confirmation",
}
CANONICAL_FABRICS = {
    "advanced": {"ref": "advanced", "name": "VXLAN_EVPN_Fabric", "type": "vxlanIbgp", "lifecycle": "retained"},
    "network_ebgp": {"ref": "network_ebgp", "name": "VXLAN_EVPN_Fabric_eBGP", "type": "vxlanEbgp", "lifecycle": "preserved"},
    "external": {"ref": "external", "name": "External_Connectivity_Fabric", "type": "externalConnectivity", "lifecycle": "retained"},
    "disposable_ibgp": {"ref": "disposable_ibgp", "name": "ANSIBLE_NIGHTLY_IBGP", "type": "vxlanIbgp", "lifecycle": "disposable"},
    "disposable_ebgp": {"ref": "disposable_ebgp", "name": "ANSIBLE_NIGHTLY_EBGP", "type": "vxlanEbgp", "lifecycle": "disposable"},
    "disposable_ai_ibgp": {"ref": "disposable_ai_ibgp", "name": "ANSIBLE_NIGHTLY_AI_IBGP", "type": "aimlVxlanIbgp", "lifecycle": "disposable"},
    "disposable_ai_ebgp": {"ref": "disposable_ai_ebgp", "name": "ANSIBLE_NIGHTLY_AI_EBGP", "type": "aimlVxlanEbgp", "lifecycle": "disposable"},
    "disposable_external": {"ref": "disposable_external", "name": "ANSIBLE_NIGHTLY_EXTERNAL", "type": "externalConnectivity", "lifecycle": "disposable"},
}
CANONICAL_SWITCHES = {
    "vxlan_leaf_1": {"baseline_fabric_ref": "advanced", "baseline_role": "leaf", "serial": "SERIAL00001", "seed_ip": "192.0.2.195"},
    "vxlan_leaf_2": {"baseline_fabric_ref": "advanced", "baseline_role": "leaf", "serial": "SERIAL00002", "seed_ip": "192.0.2.196"},
    "vxlan_spine_1": {"baseline_fabric_ref": "advanced", "baseline_role": "spine", "serial": "SERIAL00003", "seed_ip": "192.0.2.194"},
    "vxlan_border_1": {"baseline_fabric_ref": "advanced", "baseline_role": "border", "serial": "SERIAL00004", "seed_ip": "192.0.2.88"},
    "external_edge_1": {"baseline_fabric_ref": "external", "baseline_role": "edge_router", "serial": "SERIAL00005", "seed_ip": "192.0.2.89"},
    "external_edge_2": {"baseline_fabric_ref": "external", "baseline_role": "edge_router", "serial": "SERIAL00006", "seed_ip": "192.0.2.90"},
}
CANONICAL_RUNTIME_DEFAULTS = {
    "nd_test_fabric_switches": {
        "VXLAN_EVPN_Fabric": [
            {"name": "vxlan_leaf_1", "seed_ip": "192.0.2.195", "serial": "SERIAL00001", "role": "leaf"},
            {"name": "vxlan_leaf_2", "seed_ip": "192.0.2.196", "serial": "SERIAL00002", "role": "leaf"},
            {"name": "vxlan_spine_1", "seed_ip": "192.0.2.194", "serial": "SERIAL00003", "role": "spine"},
            {"name": "vxlan_border_1", "seed_ip": "192.0.2.88", "serial": "SERIAL00004", "role": "border"},
        ],
        "External_Connectivity_Fabric": [
            {"name": "external_edge_1", "seed_ip": "192.0.2.89", "serial": "SERIAL00005", "role": "edge_router"},
            {"name": "external_edge_2", "seed_ip": "192.0.2.90", "serial": "SERIAL00006", "role": "edge_router"},
        ],
    },
}
CANONICAL_INTERFACE_ALLOWLIST = {
    "vxlan_leaf_1": ["Ethernet1/1", "Ethernet1/2", "Ethernet1/3", "Ethernet1/4"],
    "vxlan_leaf_2": ["Ethernet1/1", "Ethernet1/2", "Ethernet1/3", "Ethernet1/4"],
    "vxlan_spine_1": [],
    "vxlan_border_1": ["Ethernet1/1", "Ethernet1/2"],
    "external_edge_1": ["Ethernet1/1", "Ethernet1/2"],
    "external_edge_2": [],
}


class ValidationError(ValueError):
    pass


def load_registry(path):
    data = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValidationError("profile registry must be a mapping")
    return data


def _confirmation_errors(label, confirmation):
    errors = []
    if not isinstance(confirmation, dict):
        return [f"{label}: confirmation must be a mapping"]
    status = confirmation.get("status")
    if status not in ALLOWED_CONFIRMATION:
        errors.append(f"{label}: unsupported confirmation status {status}")
    if status == "confirmed" and (not confirmation.get("owner") or not confirmation.get("evidence")):
        errors.append(f"{label}: confirmed contract requires owner and evidence")
    if status == "pending" and not confirmation.get("reasons"):
        errors.append(f"{label}: pending contract requires reasons")
    return errors


def expand_profile_executions(registry, profile_id):
    """Resolve one logical profile to its deterministic executable records."""
    profile = registry.get("profiles", {}).get(profile_id)
    if profile is None:
        raise ValidationError(f"unknown profile: {profile_id}")
    declared = registry.get("profile_executions", {}).get(profile_id)
    if declared:
        result = []
        for execution in declared:
            item = copy.deepcopy(execution)
            item.setdefault("profile_id", profile_id)
            item.setdefault("phase", profile.get("phase"))
            item.setdefault("execution_style", profile.get("execution_style"))
            result.append(item)
        return result
    return [{
        "execution_id": profile_id,
        "profile_id": profile_id,
        "phase": profile.get("phase"),
        "execution_style": profile.get("execution_style"),
        "fabric_refs": [item.get("ref") for item in profile.get("fabrics", [])],
        "confirmation": copy.deepcopy(profile.get("confirmation", {})),
    }]


def _has_unresolved(value):
    """True when a desired-state value still carries a placeholder or is unset."""
    if value is None:
        return True
    if isinstance(value, str):
        return "??" in value or "proposed" in value.lower()
    if isinstance(value, dict):
        return any(_has_unresolved(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_unresolved(item) for item in value)
    return False


def _execution_desired_state_errors(execution_id, execution):
    """Concrete-contract checks shared by confirmed executions and auto-confirm."""
    errors = []
    pair_mode = execution.get("pair_mode")
    if pair_mode is None:
        errors.append(f"{execution_id}: pair_mode is unresolved")
    elif pair_mode not in {"virtual", "physical"}:
        errors.append(f"{execution_id}: unsupported pair_mode")
    switch_refs = execution.get("switch_refs", [])
    if len(switch_refs) != 2 or len(set(switch_refs)) != 2:
        errors.append(f"{execution_id}: confirmed execution requires two distinct peers")
    desired_roles = execution.get("desired_roles", [])
    if len(desired_roles) != 2 or any(role not in ALLOWED_ROLES - {"preserve"} for role in desired_roles):
        errors.append(f"{execution_id}: confirmed execution requires two concrete roles")
    peer_links = execution.get("physical_peer_links", [])
    if pair_mode == "physical" and not peer_links:
        errors.append(f"{execution_id}: physical pair requires peer-link interfaces")
    if pair_mode == "virtual" and peer_links:
        errors.append(f"{execution_id}: virtual pair cannot have physical peer links")
    desired_text = json.dumps({key: execution.get(key) for key in ("fabric_ref", "switch_refs", "desired_roles", "pair_mode", "physical_peer_links")}).lower()
    if "??" in desired_text or "proposed" in desired_text:
        errors.append(f"{execution_id}: confirmed execution contains unresolved markers")
    return errors


def _profile_auto_confirm_errors(label, profile):
    """A pending profile auto-confirms only when its desired state is fully concrete."""
    desired = {key: profile.get(key) for key in ("fabrics", "switches", "links", "vpc_pairs", "resources", "runtime_vars")}
    if _has_unresolved(desired):
        return [f"{label}: auto-confirm blocked by unresolved desired state"]
    return []


def _accept_confirmation(label, confirmation, contract, allow_auto_confirm, *, is_execution):
    """Fail-closed gate: confirmed always; pending only under an explicit auto-confirm flag."""
    status = confirmation.get("status")
    if status == "confirmed":
        if not confirmation.get("owner") or not confirmation.get("evidence"):
            return [f"{label}: confirmed contract requires owner and evidence"]
        return []
    if status == "pending" and allow_auto_confirm:
        if is_execution:
            return _execution_desired_state_errors(label, contract)
        return _profile_auto_confirm_errors(label, contract)
    return [f"{label}: owner confirmation is {status or 'missing'}"]


def validate_selected_profiles(registry, selected_profiles, allow_auto_confirm=False):
    """Return fail-closed confirmation errors for selected profiles/executions.

    With allow_auto_confirm a pending contract runs only when its desired state is
    fully concrete; rejected or unresolved contracts still fail closed.
    """
    errors = []
    profiles = registry.get("profiles", {})
    execution_index = {
        execution["execution_id"]: execution
        for profile_id in profiles
        for execution in expand_profile_executions(registry, profile_id)
    }
    for selected in selected_profiles:
        if selected in profiles:
            confirmation = profiles[selected].get("confirmation", {})
            contract = profiles[selected]
            child_executions = registry.get("profile_executions", {}).get(selected, [])
            is_execution = False
        elif selected in execution_index:
            confirmation = execution_index[selected].get("confirmation", {})
            contract = execution_index[selected]
            child_executions = []
            is_execution = True
        else:
            errors.append(f"{selected}: unknown selected profile or execution")
            continue
        selection_errors = _accept_confirmation(selected, confirmation, contract, allow_auto_confirm, is_execution=is_execution)
        errors.extend(selection_errors)
        if selection_errors:
            continue
        for execution in child_executions:
            execution_id = execution.get("execution_id", selected)
            errors.extend(_accept_confirmation(execution_id, execution.get("confirmation", {}), execution, allow_auto_confirm, is_execution=True))
    return errors


def validate_registry(registry):
    errors = []
    if registry.get("schema_version") != 2:
        errors.append("schema_version must equal 2")
    if registry.get("runtime_defaults") != CANONICAL_RUNTIME_DEFAULTS:
        errors.append("runtime defaults must contain the exact canonical 4+2 fabric membership")
    lab = registry.get("lab", {})
    fabrics = lab.get("fabrics", {})
    switches = lab.get("switches", {})
    allowlist = lab.get("interface_allowlist", {})
    serials = [item.get("serial") for item in switches.values()]
    seed_ips = [item.get("seed_ip") for item in switches.values()]
    if len(serials) != len(set(serials)):
        errors.append("lab switch serials must be distinct")
    if len(seed_ips) != len(set(seed_ips)):
        errors.append("lab switch seed IPs must be distinct")
    if set(allowlist) != set(switches):
        errors.append("interface allowlist must name every lab switch exactly once")
    if fabrics != CANONICAL_FABRICS:
        errors.append("lab fabrics must match the exact canonical mapping")
    if switches != CANONICAL_SWITCHES:
        errors.append("lab switches must match the exact canonical mapping")
    if allowlist != CANONICAL_INTERFACE_ALLOWLIST:
        errors.append("interface allowlist must match the exact canonical mapping")
    retained_names = set(lab.get("retained_fabric_names", []))
    if retained_names != RETAINED:
        errors.append("retained fabric names do not match the protected lab contract")
    preserved_names = set(lab.get("preserved_fabric_names", []))
    if preserved_names != PRESERVED:
        errors.append("preserved fabric names do not match the protected lab contract")
    for fabric_ref, fabric in fabrics.items():
        if fabric.get("ref") != fabric_ref:
            errors.append(f"fabric {fabric_ref}: ref mismatch")
        name = fabric.get("name")
        lifecycle = fabric.get("lifecycle")
        if name in RETAINED and lifecycle != "retained":
            errors.append(f"fabric {fabric_ref}: retained fabric marked disposable")
        if name in PRESERVED and lifecycle != "preserved":
            errors.append(f"fabric {fabric_ref}: preserved fabric lifecycle mismatch")
        if lifecycle == "disposable" and (not isinstance(name, str) or not name.startswith("ANSIBLE_NIGHTLY_")):
            errors.append(f"fabric {fabric_ref}: disposable name is not namespaced")

    phase_order = registry.get("phase_order", [])
    phases = registry.get("phases", {})
    if not phase_order or set(phase_order) != set(phases):
        errors.append("phase_order and phases must name the same non-empty set")
    ordinals = [phases.get(name, {}).get("ordinal") for name in phase_order]
    if ordinals != list(range(1, len(phase_order) + 1)):
        errors.append("phase ordinals must follow phase_order")

    for profile_id, profile in registry.get("profiles", {}).items():
        missing = REQUIRED_PROFILE_FIELDS - set(profile)
        if missing:
            errors.append(f"{profile_id}: missing fields {sorted(missing)}")
        if profile.get("profile_id") != profile_id:
            errors.append(f"{profile_id}: profile_id mismatch")
        if profile.get("phase") not in phase_order[:-1]:
            errors.append(f"{profile_id}: unknown or terminal execution phase")
        if profile.get("execution_style") not in ALLOWED_EXECUTION_STYLES:
            errors.append(f"{profile_id}: unsupported execution style")
        members = profile.get("switches", {}).get("members", [])
        refs = [item.get("ref") for item in members]
        if len(refs) != len(set(refs)) or len(refs) != profile.get("switches", {}).get("required_count"):
            errors.append(f"{profile_id}: switch identities/count are invalid")
        for member in members:
            if member.get("ref") not in switches:
                errors.append(f"{profile_id}: unknown switch ref {member.get('ref')}")
            if member.get("desired_fabric_ref") not in fabrics:
                errors.append(f"{profile_id}: unknown desired fabric ref {member.get('desired_fabric_ref')}")
            if member.get("desired_role") not in ALLOWED_ROLES:
                errors.append(f"{profile_id}: unsupported role {member.get('desired_role')}")
        if "nd_test_fabric_switches" in profile.get("runtime_vars", {}):
            errors.append(f"{profile_id}: profile cannot override canonical fabric membership")
        for fabric in profile.get("fabrics", []):
            if fabric.get("ref") not in fabrics:
                errors.append(f"{profile_id}: unknown fabric ref {fabric.get('ref')}")
            elif fabric != CANONICAL_FABRICS[fabric.get("ref")]:
                errors.append(f"{profile_id}: profile fabric does not match canonical fabric")
            if fabric.get("name") in RETAINED and fabric.get("lifecycle") != "retained":
                errors.append(f"{profile_id}: retained fabric marked disposable")
            if fabric.get("name") in PRESERVED and fabric.get("lifecycle") != "preserved":
                errors.append(f"{profile_id}: preserved fabric lifecycle mismatch")
        for link in profile.get("links", []):
            switch_ref = link.get("switch_ref")
            interfaces = link.get("interfaces", [])
            if switch_ref not in switches:
                errors.append(f"{profile_id}: link uses unknown switch {switch_ref}")
            elif set(interfaces) - set(allowlist.get(switch_ref, [])):
                errors.append(f"{profile_id}: link uses an interface outside the allowlist")
            if link.get("admin_state") is not True or link.get("operational_state") != "when_reported_up":
                errors.append(f"{profile_id}: link readiness contract is invalid")
        for pair in profile.get("vpc_pairs", []):
            if pair.get("fabric_ref") not in fabrics:
                errors.append(f"{profile_id}: vPC uses unknown fabric")
            if set(pair.get("peer_refs", [])) - set(switches):
                errors.append(f"{profile_id}: vPC uses unknown peers")
            if pair.get("mode") == "virtual" and pair.get("physical_peer_links"):
                errors.append(f"{profile_id}: virtual vPC cannot declare physical peer links")
        for spec in profile.get("interfabric_links", []):
            if spec.get("template") not in ALLOWED_LINK_TEMPLATES:
                errors.append(f"{profile_id}: unsupported inter-fabric link template {spec.get('template')}")
            side_fabric_refs = []
            for side in ("src", "dst"):
                endpoint = spec.get(side)
                if not isinstance(endpoint, dict):
                    errors.append(f"{profile_id}: inter-fabric link missing {side} endpoint")
                    continue
                switch_ref = endpoint.get("switch_ref")
                if switch_ref not in switches:
                    errors.append(f"{profile_id}: inter-fabric link uses unknown switch {switch_ref}")
                    continue
                if endpoint.get("interface") not in allowlist.get(switch_ref, []):
                    errors.append(f"{profile_id}: inter-fabric link uses an interface outside the allowlist")
                side_fabric_refs.append(switches[switch_ref]["baseline_fabric_ref"])
            if len(side_fabric_refs) == 2 and side_fabric_refs[0] == side_fabric_refs[1]:
                errors.append(f"{profile_id}: inter-fabric link must span two different fabrics")
        unknown_domains = set(profile.get("managed_domains", [])) - ALLOWED_DOMAINS
        if unknown_domains:
            errors.append(f"{profile_id}: unsupported managed domains {sorted(unknown_domains)}")
        timeouts = profile.get("timeouts", {})
        if timeouts.get("poll_seconds") != 15 or timeouts.get("retries") not in {20, 40} or timeouts.get("max_consecutive_api_errors") != 3:
            errors.append(f"{profile_id}: timeout contract is invalid")
        if profile.get("restore") != {"target": "verified_phase_snapshot", "job": "verified_job_snapshot"}:
            errors.append(f"{profile_id}: restore contract is invalid")
        errors.extend(_confirmation_errors(profile_id, profile.get("confirmation")))

    execution_ids = []
    for profile_id, executions in registry.get("profile_executions", {}).items():
        if profile_id not in registry.get("profiles", {}):
            errors.append(f"{profile_id}: execution group has no profile")
            continue
        for execution in executions:
            execution_id = execution.get("execution_id")
            execution_ids.append(execution_id)
            if not isinstance(execution_id, str) or not execution_id.startswith(profile_id + "."):
                errors.append(f"{profile_id}: invalid execution id {execution_id}")
            if execution.get("fabric_ref") not in fabrics:
                errors.append(f"{execution_id}: unknown fabric ref")
            if set(execution.get("switch_refs", [])) - set(switches):
                errors.append(f"{execution_id}: unknown switch ref")
            errors.extend(_confirmation_errors(execution_id, execution.get("confirmation")))
            if execution.get("confirmation", {}).get("status") == "confirmed":
                errors.extend(_execution_desired_state_errors(execution_id, execution))
    if len(execution_ids) != len(set(execution_ids)):
        errors.append("profile execution IDs must be distinct")
    return errors


def jenkins_targets(text):
    result = {}
    for name in ("PLAYBOOK_FILES", "INTEGRATION_MODULES", "STANDALONE_INTEGRATION_MODULES"):
        match = re.search(rf"def\s+{name}\s*=\s*\[(.*?)\]", text, re.S)
        if not match:
            raise ValidationError(f"missing Jenkins target array: {name}")
        result[name] = [item for line in match.group(1).splitlines() for item in re.findall(r"'([A-Za-z0-9_.-]+)'", line.split("//", 1)[0])]
    return result


def validate_playbook_summary(path, profile):
    plays = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8")) or []
    actual = plays[0].get("vars", {}).get("nd_prerequisite") if plays else None
    wanted = {"profile": profile["profile_id"], "fabric_types": [item["type"] for item in profile["fabrics"]], "switch_count": profile["switches"]["required_count"], "switch_roles": [item["desired_role"] for item in profile["switches"]["members"]]}
    return [] if actual == wanted else [f"{path}: nd_prerequisite summary mismatch"]


FABRIC_MODULES = {
    "cisco.nd.nd_manage_fabric_external",
    "cisco.nd.nd_manage_fabric_ibgp_vxlan",
    "cisco.nd.nd_manage_fabric_ebgp_vxlan",
    "cisco.nd.nd_manage_fabric_ai_ibgp_vxlan",
    "cisco.nd.nd_manage_fabric_ai_ebgp_vxlan",
}


def _task_lists(tasks):
    if not isinstance(tasks, list):
        return
    yield tasks
    for task in tasks:
        if isinstance(task, dict):
            for key in ("block", "rescue", "always"):
                yield from _task_lists(task.get(key, []))


def validate_fabric_delete_guards(paths):
    """Reject retained-fabric deletes and deletes without an explicit namespace guard."""
    errors = []
    for raw_path in paths:
        path = pathlib.Path(raw_path)
        plays = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        top_tasks = [task for play in plays if isinstance(play, dict) for task in play.get("tasks", [])]
        for tasks in _task_lists(top_tasks):
            for index, task in enumerate(tasks):
                if not isinstance(task, dict):
                    continue
                module = next((name for name in FABRIC_MODULES if name in task), None)
                config = task.get(module, {}) if module else {}
                if not module or not isinstance(config, dict) or config.get("state") != "deleted":
                    continue
                serialized = json.dumps(config, sort_keys=True)
                if any(name in serialized for name in RETAINED):
                    errors.append(f"{path}: retained fabric in delete config")
                names = [
                    item.get("fabric_name")
                    for item in config.get("config", [])
                    if isinstance(item, dict) and isinstance(item.get("fabric_name"), str)
                ]
                statically_safe = bool(names) and all(
                    re.fullmatch(r"ANSIBLE_NIGHTLY_[A-Z0-9_]+", name) is not None
                    for name in names
                )
                previous = tasks[index - 1] if index else {}
                assertion = previous.get("ansible.builtin.assert", {}) if isinstance(previous, dict) else {}
                conditions = assertion.get("that", []) if isinstance(assertion, dict) else []
                conditions = [conditions] if isinstance(conditions, str) else conditions
                guard = " ".join(str(condition) for condition in conditions)
                variables = {
                    match.group(1)
                    for name in names
                    for match in [re.fullmatch(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}", name)]
                    if match
                }
                guarded_variable = False
                if len(variables) == 1:
                    variable = re.escape(next(iter(variables)))
                    namespace = re.compile(
                        rf"^{variable}\s+is\s+match\(\s*['\"]\^ANSIBLE_NIGHTLY_['\"]\s*\)$"
                    )
                    retained = re.compile(
                        rf"^{variable}\s+not\s+in\s+\[\s*['\"]VXLAN_EVPN_Fabric['\"]\s*,\s*['\"]External_Connectivity_Fabric['\"]\s*\]$"
                    )
                    normalized_conditions = [" ".join(str(condition).split()) for condition in conditions]
                    guarded_variable = (
                        any(namespace.fullmatch(condition) for condition in normalized_conditions)
                        and any(retained.fullmatch(condition) for condition in normalized_conditions)
                    )
                if not statically_safe and not guarded_variable:
                    errors.append(f"{path}: fabric delete lacks namespace/retained guard")
    return errors


READ_ONLY_FIELDS = {
    "operData", "status", "metadata", "createdOn", "lastModified", "uuid",
    "deploymentStatus", "configSyncStatus",
}


def _strip_read_only(value):
    if isinstance(value, dict):
        return {key: _strip_read_only(item) for key, item in value.items() if key not in READ_ONLY_FIELDS}
    if isinstance(value, list):
        return [_strip_read_only(item) for item in value]
    return value


def sanitize_interface_payload(payload, switch_id, admin_state, registry=None):
    current = payload.get("current", payload)
    name = current.get("interfaceName")
    if not name or not re.fullmatch(r"Ethernet\d+/\d+", name):
        raise ValidationError("physical interface name is absent or invalid")
    if not isinstance(registry, dict):
        raise ValidationError("validated registry is required for interface sanitization")
    registry_errors = validate_registry(registry)
    if registry_errors:
        raise ValidationError(f"registry failed validation: {registry_errors[0]}")
    matches = [
        ref
        for ref, switch in registry.get("lab", {}).get("switches", {}).items()
        if switch.get("serial") == switch_id
    ]
    if len(matches) != 1:
        raise ValidationError("switch is not registered exactly once")
    if name not in registry.get("lab", {}).get("interface_allowlist", {}).get(matches[0], []):
        raise ValidationError("physical interface is not allowlisted for the switch")
    policy = _strip_read_only(copy.deepcopy(current["configData"]["networkOS"]["policy"]))
    policy["adminState"] = bool(admin_state)
    return {"interfaceName": name, "switchId": switch_id, "configData": {"networkOS": {"policy": policy}}}


def normalized_equal(domain, before, after):
    if domain not in ALLOWED_DOMAINS:
        raise ValidationError(f"unsupported normalized domain: {domain}")
    def normalize(value):
        if isinstance(value, dict): return {key: normalize(item) for key, item in sorted(value.items()) if key not in {"createdOn", "lastModified", "status", "metadata", "uuid"}}
        if isinstance(value, list): return sorted((normalize(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
        return value
    return normalize(before) == normalize(after)


def validate_runtime_markers(data, expected_profile, expected_execution, expected_run_id):
    expected = {
        "nd_prerequisite_prepared": True,
        "nd_prerequisite_profile": expected_profile,
        "nd_prerequisite_execution_id": expected_execution,
        "nd_prerequisite_run_id": expected_run_id,
    }
    errors = [
        f"runtime marker {key} mismatch"
        for key, value in expected.items()
        if data.get(key) != value
    ]
    if not data.get("nd_prerequisite_phase_baseline_id"):
        errors.append("runtime marker nd_prerequisite_phase_baseline_id is missing")
    return errors


def validate_playbook_profile_coverage(paths, profiles):
    actual = {pathlib.Path(path).stem for path in paths}
    expected = {profile_id.removeprefix("smoke.") for profile_id in profiles if profile_id.startswith("smoke.")}
    errors = [f"smoke.{name}: smoke profile has no playbook" for name in sorted(expected - actual)]
    errors.extend(f"{name}: playbook has no smoke profile" for name in sorted(actual - expected))
    return errors


def _reject_symlink_components(path, label):
    absolute = pathlib.Path(path).absolute()
    for component in (absolute, *absolute.parents):
        if component.is_symlink():
            raise ValidationError(f"{label} contains a symlink: {component}")


def load_runtime_marker_file(path):
    path = pathlib.Path(path)
    _reject_symlink_components(path, "runtime marker path")
    if not path.is_file():
        raise ValidationError(f"runtime marker file is missing or not regular: {path}")
    if path.stat().st_mode & 0o777 != 0o600:
        raise ValidationError(f"runtime marker file mode is not 0600: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValidationError("runtime marker file must contain a mapping")
    return data


def write_checkpoint(root, label, output):
    root = pathlib.Path(root).resolve()
    files = [root / "Jenkinsfile_nd_jenkins_script"]
    files.extend(
        path
        for folder in ("tests", "playbooks", "consul", "docs/superpowers")
        for path in (root / folder).rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    report = {
        "label": label,
        "files": {
            path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(set(files))
            if path.exists() and path.is_file() and not path.is_symlink()
        },
    }
    output = pathlib.Path(output)
    _reject_symlink_components(output, "checkpoint path")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _reject_symlink_components(output, "checkpoint path")
    output.parent.chmod(0o700)
    if output.parent.stat().st_mode & 0o777 != 0o700:
        raise ValidationError("checkpoint parent mode is not 0700")
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output.chmod(0o600)
    if output.stat().st_mode & 0o777 != 0o600:
        raise ValidationError("checkpoint file mode is not 0600")


def validate_tree(
    root,
    jenkinsfile,
    allow_pending=False,
    allow_auto_confirm=False,
    runtime_marker_file=None,
    expected_profile=None,
    expected_execution=None,
    expected_run_id=None,
    static_only=False,
):
    root = pathlib.Path(root).resolve()
    registry = load_registry(root / "tests/nd_prerequisite_profiles.yaml")
    errors = validate_registry(registry)
    try:
        targets = jenkins_targets(pathlib.Path(jenkinsfile).read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        return errors + [str(exc)]

    selected = [f"smoke.{pathlib.Path(name).stem}" for name in targets["PLAYBOOK_FILES"]]
    selected.extend(f"integration.{name}" for name in targets["INTEGRATION_MODULES"])
    selected.extend(f"integration.{name}" for name in targets["STANDALONE_INTEGRATION_MODULES"])
    missing = [profile_id for profile_id in selected if profile_id not in registry.get("profiles", {})]
    errors.extend(f"{profile_id}: Jenkins target has no profile" for profile_id in missing)
    if not allow_pending:
        errors.extend(validate_selected_profiles(registry, [item for item in selected if item not in missing], allow_auto_confirm=allow_auto_confirm))

    playbooks = sorted((root / "playbooks").glob("*.yaml"))
    errors.extend(validate_playbook_profile_coverage(playbooks, registry.get("profiles", {})))
    for path in playbooks:
        profile_id = f"smoke.{path.stem}"
        profile = registry.get("profiles", {}).get(profile_id)
        if profile is None:
            errors.append(f"{path}: playbook has no smoke profile")
        else:
            errors.extend(validate_playbook_summary(path, profile))
    errors.extend(validate_fabric_delete_guards(playbooks))
    marker_expectations = (expected_profile, expected_execution, expected_run_id)
    if runtime_marker_file is not None:
        if not all(marker_expectations):
            errors.append("runtime marker validation requires profile, execution, and run ID")
        else:
            try:
                runtime_data = load_runtime_marker_file(runtime_marker_file)
            except ValidationError as exc:
                errors.append(str(exc))
            else:
                errors.extend(validate_runtime_markers(runtime_data, *marker_expectations))
    elif any(marker_expectations):
        errors.append("runtime marker expectations require a runtime marker file")
    elif not static_only:
        errors.append("runtime marker file is required unless static_only is true")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("--root", required=True)
    validate.add_argument("--jenkinsfile", required=True)
    validate.add_argument("--allow-pending", action="store_true")
    validate.add_argument("--allow-auto-confirm", action="store_true")
    validate.add_argument("--secret-scan", action="store_true")
    validate.add_argument("--runtime-marker-file")
    validate.add_argument("--expected-profile")
    validate.add_argument("--expected-execution")
    validate.add_argument("--expected-run-id")
    validate.add_argument("--static-only", action="store_true")
    checkpoint = sub.add_parser("checkpoint")
    checkpoint.add_argument("--root", required=True)
    checkpoint.add_argument("--label", required=True)
    checkpoint.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    if args.command == "validate":
        errors = validate_tree(
            args.root,
            args.jenkinsfile,
            allow_pending=args.allow_pending,
            allow_auto_confirm=args.allow_auto_confirm,
            runtime_marker_file=args.runtime_marker_file,
            expected_profile=args.expected_profile,
            expected_execution=args.expected_execution,
            expected_run_id=args.expected_run_id,
            static_only=args.static_only,
        )
        if args.secret_scan:
            root = pathlib.Path(args.root)
            for path in [root / "tests/nd_prerequisite_profiles.yaml", *sorted((root / "playbooks").glob("*.yaml"))]:
                text = path.read_text(encoding="utf-8")
                if re.search(r"(?im)^\s*(?:password|token|secret)\s*:\s*[^\s{]", text):
                    errors.append(f"{path}: possible literal secret")
        for error in errors:
            print(error, file=sys.stderr)
        return 1 if errors else 0
    if args.command == "checkpoint":
        write_checkpoint(args.root, args.label, args.output)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
