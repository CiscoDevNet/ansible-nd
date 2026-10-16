#!/usr/bin/env python3
"""Pure planning and recovery contracts for ND prerequisite orchestration."""
from __future__ import annotations

import argparse
import copy
import json
import os
import pathlib
import re
import sys

import yaml

from validate_nd_prerequisites import (
    load_registry,
    normalized_equal,
    validate_registry,
    validate_selected_profiles,
)


class OrchestrationError(RuntimeError):
    """Raised before an undeclared or unsafe operation can be executed."""


class UnavailableError(OrchestrationError):
    """The lab lacks a declared fabric/port/link/vPC substrate, so the module cannot meaningfully run."""


UNAVAILABLE_EXIT_CODE = 3


ALLOWED_OPERATIONS = {
    "create_disposable_fabric",
    "ensure_switch_membership",
    "membership_move",
    "change_role",
    "ensure_interface",
    "ensure_virtual_vpc",
    "ensure_bfd",
    "ensure_link",
    "verify_free_interfaces",
    "verify_logical_interface_namespace",
    "ensure_routed_parent",
    "ensure_routed_port_channel",
    "verify_resource",
}
# Inter-fabric link templates the planner may request via `ensure_link`. Kept to a
# strict allowlist so a profile can never ask for an arbitrary/unsafe link template.
# ND validates one template per L3Out connectivity type (live-probed on ND 4.3):
# routed -> ext_l3_dci_link, subInterface -> ext_fabric_setup, svi -> ext_l2_dci_link.
ALLOWED_LINK_TEMPLATES = {
    "ext_l3_dci_link",
    "ext_fabric_setup",
    "ext_l2_dci_link",
}
# cisco.nd.nd_manage_links policy_type that provisions each template.
LINK_POLICY_BY_TEMPLATE = {
    "ext_l3_dci_link": "layer3DciVrfLite",
    "ext_fabric_setup": "ebgpVrfLite",
    "ext_l2_dci_link": "layer2Dci",
}
LINK_PROVISIONING_MODES = {"api", "module_managed", "nd_manage_links"}
SERVER_MANAGED_FIELDS = {
    "createdOn", "lastModified", "status", "metadata", "uuid",
    "deploymentStatus", "configSyncStatus",
}
RESERVED_RUNTIME_KEYS = {
    "nd_prerequisite_prepared",
    "nd_prerequisite_run_id",
    "nd_prerequisite_profile",
    "nd_prerequisite_execution_id",
    "nd_prerequisite_phase_baseline_id",
}
CANONICAL_RUNTIME_KEYS = {"nd_test_fabric_switches"}
# Integration-only: the nightly runs integration modules exclusively, and the smoke
# switches/resource-manager profiles are verify/preserve-only (they never mutate
# switch topology), so no smoke profile belongs in this mutation allowlist.
SWITCH_TOPOLOGY_MUTATION_PROFILES = {
    "integration.nd_manage_fabric",
    "integration.nd_manage_switches",
    "integration.nd_resource_manager",
}


def _validated_registry(registry):
    errors = validate_registry(registry)
    if errors:
        raise OrchestrationError(f"registry validation failed: {errors[0]}")


def _confirmation_error(registry, selection, allow_auto_confirm=False):
    errors = validate_selected_profiles(registry, [selection], allow_auto_confirm=allow_auto_confirm)
    return errors[0] if errors else None


def resolve_execution(registry, execution_id, allow_auto_confirm=False):
    """Resolve and confirm one executable unit without inventing missing details."""
    _validated_registry(registry)
    profiles = registry["profiles"]
    execution_groups = registry.get("profile_executions", {})
    if execution_id in profiles:
        if execution_id in execution_groups:
            raise OrchestrationError(f"{execution_id} requires an explicit execution ID")
        profile_id = execution_id
        child = None
    else:
        child = next(
            (
                item
                for items in execution_groups.values()
                for item in items
                if item.get("execution_id") == execution_id
            ),
            None,
        )
        if child is None:
            raise OrchestrationError(f"unknown execution ID: {execution_id}")
        profile_id = next(
            profile
            for profile, items in execution_groups.items()
            if child in items
        )
    confirmation_error = _confirmation_error(registry, profile_id if child is None else execution_id, allow_auto_confirm=allow_auto_confirm)
    if confirmation_error:
        raise OrchestrationError(confirmation_error)
    if child is not None:
        parent = profiles[profile_id]["confirmation"]
        if allow_auto_confirm:
            if parent.get("status") == "rejected":
                raise OrchestrationError(f"{profile_id}: parent contract is rejected")
        elif parent.get("status") != "confirmed" or not parent.get("owner") or not parent.get("evidence"):
            raise OrchestrationError(f"{profile_id}: parent owner confirmation is not complete")
    return {
        "profile_id": profile_id,
        "execution_id": execution_id,
        "phase": profiles[profile_id]["phase"],
        "execution_style": profiles[profile_id]["execution_style"],
        "profile": copy.deepcopy(profiles[profile_id]),
        "execution": copy.deepcopy(child),
        "lab_switches": copy.deepcopy(registry["lab"]["switches"]),
        "runtime_defaults": copy.deepcopy(registry.get("runtime_defaults", {})),
    }


def build_phase_schedule(registry, selected_profiles, allow_auto_confirm=False):
    """Expand logical profiles and sort executions by the authoritative phase order."""
    _validated_registry(registry)
    selected = set(selected_profiles)
    known = set(registry["profiles"])
    known.update(
        item["execution_id"]
        for items in registry.get("profile_executions", {}).values()
        for item in items
    )
    unknown = selected - known
    if unknown:
        raise OrchestrationError(f"unknown selected profile or execution: {sorted(unknown)[0]}")

    ordered = []
    for profile_id in registry["profiles"]:
        children = registry.get("profile_executions", {}).get(profile_id, [])
        if children:
            child_ids = {item["execution_id"] for item in children}
            requested = children if profile_id in selected else [item for item in children if item["execution_id"] in selected]
            if profile_id in selected or selected & child_ids:
                for item in requested:
                    ordered.append(resolve_execution(registry, item["execution_id"], allow_auto_confirm=allow_auto_confirm))
        elif profile_id in selected:
            ordered.append(resolve_execution(registry, profile_id, allow_auto_confirm=allow_auto_confirm))

    phase_index = {name: index for index, name in enumerate(registry["phase_order"])}
    profile_index = {name: index for index, name in enumerate(registry["profiles"])}
    ordered.sort(key=lambda item: (phase_index[item["phase"]], profile_index[item["profile_id"]], item["execution_id"]))
    schedule = []
    for phase_id in registry["phase_order"]:
        phase_items = [item for item in ordered if item["phase"] == phase_id]
        if phase_items:
            schedule.append({
                "phase_id": phase_id,
                "ordinal": registry["phases"][phase_id]["ordinal"],
                "execution_ids": [item["execution_id"] for item in phase_items],
            })
    return schedule


def _current_fabric(current_state, fabric_ref):
    return current_state.get("fabrics", {}).get(fabric_ref)


def _pair_exists(current_state, fabric_ref, peer_refs, mode):
    wanted = set(peer_refs)
    return any(
        item.get("fabric_ref") == fabric_ref
        and set(item.get("peer_refs", [])) == wanted
        and item.get("mode") == mode
        for item in current_state.get("vpc_pairs", [])
    )


def _pair_present(current_state, fabric_ref, peer_refs):
    """True when the vPC pair exists in either peer-link mode."""
    wanted = set(peer_refs)
    return any(
        item.get("fabric_ref") == fabric_ref and set(item.get("peer_refs", [])) == wanted
        for item in current_state.get("vpc_pairs", [])
    )


def _link_exists(current_state, src, dst, template, policy_type=None):
    """True when a link of `template` already spans the two endpoints.

    `policy_type` additionally matches the nd_manage_links policy the capture records
    from configData.policyType (the manage links API does not populate templateName).

    Endpoints are compared unordered (a controller may report either switch as
    src) and by serial+interface, which the ND links GET exposes as
    src/dstSwitchId + src/dstInterfaceName. The template is matched against
    whichever field the controller populates (templateName or linkType); the
    discovered physical link (linkType 'ethisl') therefore never satisfies an
    ext_l3_dci_link requirement, which is exactly why the L3Out still fails 207
    while only that physical link is present.
    """
    wanted = frozenset({(src["serial"], src["interface"]), (dst["serial"], dst["interface"])})
    for item in current_state.get("links", []):
        if template not in {item.get("templateName"), item.get("linkType")} and not (
            policy_type and item.get("policyType") == policy_type
        ):
            continue
        endpoints = frozenset({
            (item.get("srcSwitchId"), item.get("srcInterfaceName")),
            (item.get("dstSwitchId"), item.get("dstInterfaceName")),
        })
        if endpoints == wanted:
            return True
    return False


def _casefold_lookup(mapping, key):
    if not isinstance(mapping, dict):
        return None
    wanted = str(key).lower()
    return next((value for name, value in mapping.items() if str(name).lower() == wanted), None)


def _physical_interface_state(current_state, switch_ref, interface):
    return _casefold_lookup(current_state.get("interfaces", {}).get(switch_ref, {}), interface)


def _logical_interface_state(current_state, switch_ref, interface):
    return _casefold_lookup(current_state.get("logical_interfaces", {}).get(switch_ref, {}), interface)


def _link_endpoints(link):
    endpoints = []
    for serial_key, interface_key in (
        ("srcSwitchId", "srcInterfaceName"),
        ("dstSwitchId", "dstInterfaceName"),
    ):
        if link.get(serial_key) and link.get(interface_key):
            endpoints.append((str(link[serial_key]), str(link[interface_key])))
    for side in ("sw1-info", "sw2-info"):
        side_data = link.get(side, {})
        if not isinstance(side_data, dict):
            continue
        serial = side_data.get("sw-serial-number") or side_data.get("serialNumber")
        interface = side_data.get("if-name") or side_data.get("interfaceName")
        if serial and interface:
            endpoints.append((str(serial), str(interface)))
    return endpoints


def _is_fabric_link(current_state, serial, interface):
    wanted = (str(serial).lower(), str(interface).lower())
    links = list(current_state.get("physical_links", [])) + list(current_state.get("links", []))
    return any(
        (endpoint[0].lower(), endpoint[1].lower()) == wanted
        for link in links
        if isinstance(link, dict)
        for endpoint in _link_endpoints(link)
    )


def _link_is_planned(link):
    """A planned (config-only) link has no cable behind it, so it never proves physical adjacency."""
    return (
        link.get("linkPlanned") is True
        or link.get("is-planned") is True
        or str(link.get("linkType") or link.get("link-type") or "").lower() == "lan_planned_link"
    )


def _link_is_up(link):
    # Captures that predate these flags carry neither key; an unknown state counts as present.
    return link.get("linkPresent") is not False and link.get("is-present") is not False


def _physical_link_present(current_state, src, dst, allow_down=False):
    """True when a captured, non-planned link joins the two endpoints in either order.

    `allow_down` accepts a link ND still lists but reports as not present (for example both
    ports administratively shut), which a later ensure_interface can recover.
    """
    wanted = frozenset({
        (str(src["serial"]).lower(), str(src["interface"]).lower()),
        (str(dst["serial"]).lower(), str(dst["interface"]).lower()),
    })
    links = list(current_state.get("physical_links", [])) + list(current_state.get("links", []))
    return any(
        frozenset((str(serial).lower(), str(interface).lower()) for serial, interface in _link_endpoints(link)) == wanted
        and not _link_is_planned(link)
        and (allow_down or _link_is_up(link))
        for link in links
        if isinstance(link, dict)
    )


def _interface_detail(current_state, switch_ref, interface):
    wanted = str(interface).lower()
    return next(
        (
            item
            for item in current_state.get("interface_details", {}).get(switch_ref, [])
            if isinstance(item, dict) and str(item.get("ifName", "")).lower() == wanted
        ),
        {},
    )


def _is_port_channel_member(current_state, switch_ref, interface, state):
    if state.get("port_channel_member") is True:
        return True
    detail = _interface_detail(current_state, switch_ref, interface)
    searchable = " ".join(
        str(value).lower()
        for value in (
            state.get("policy", ""),
            state.get("policy_type", ""),
            json.dumps(state.get("nv_pairs", {}), sort_keys=True),
            json.dumps(detail.get("underlayPolicies", []), sort_keys=True),
        )
    )
    return (
        ("port_channel" in searchable or "port-channel" in searchable)
        and "member" in searchable
    )


def _port_link_peers(current_state, serial, interface):
    """Every endpoint joined to this port by any captured link, discovered or logical."""
    local = (str(serial).lower(), str(interface).lower())
    peers = set()
    links = list(current_state.get("physical_links", [])) + list(current_state.get("links", []))
    for link in links:
        if not isinstance(link, dict):
            continue
        endpoints = {(str(s).lower(), str(i).lower()) for s, i in _link_endpoints(link)}
        if local in endpoints:
            peers |= endpoints - {local}
    return peers


def _assert_existing_link_port(registry, current_state, switch_ref, interface, existing_link):
    """The port must carry exactly the declared inter-fabric cable and no underlay link."""
    switches = registry["lab"]["switches"]
    peer_ref, peer_interface = existing_link["peer_switch_ref"], existing_link["peer_interface"]
    if switches[switch_ref]["baseline_fabric_ref"] == switches[peer_ref]["baseline_fabric_ref"]:
        raise OrchestrationError(
            f"existing link must join two fabrics, not an underlay link: "
            f"{switch_ref}/{interface} <-> {peer_ref}/{peer_interface}"
        )
    wanted = (switches[peer_ref]["serial"].lower(), str(peer_interface).lower())
    peers = _port_link_peers(current_state, switches[switch_ref]["serial"], interface)
    if wanted not in peers:
        raise UnavailableError(
            f"required existing link is absent in ND: {switch_ref}/{interface} <-> {peer_ref}/{peer_interface}"
        )
    if peers - {wanted}:
        raise UnavailableError(
            f"reserved interface carries another link besides {peer_ref}/{peer_interface}: {switch_ref}/{interface}"
        )


def _assert_free_interface(registry, current_state, switch_ref, interface, existing_link=None):
    state = _physical_interface_state(current_state, switch_ref, interface)
    if state is None:
        raise OrchestrationError(f"physical interface was not captured: {switch_ref}/{interface}")
    if state.get("exists", True) is not True:
        raise UnavailableError(f"required physical interface is missing: {switch_ref}/{interface}")
    serial = registry["lab"]["switches"][switch_ref]["serial"]
    if existing_link:
        _assert_existing_link_port(registry, current_state, switch_ref, interface, existing_link)
    elif _is_fabric_link(current_state, serial, interface):
        raise UnavailableError(f"reserved interface is a fabric link: {switch_ref}/{interface}")
    if _is_port_channel_member(current_state, switch_ref, interface, state):
        raise UnavailableError(f"reserved interface is a port-channel member: {switch_ref}/{interface}")
    return state


def _is_routed_ethernet(state):
    policy_values = {
        str(state.get("policy", "")).lower(),
        str(state.get("policy_type", "")).lower(),
    }
    return any(value == "routedhost" or value.startswith("int_routed_host") for value in policy_values)


# ND stamps this trunk-host intent on every untouched front-panel port (live-probed on all
# lab leaves), so it is the 'free port' state, not user intent. Any other value or extra key is.
# A port that was reset (interfaceActions/normalize or a per-interface PUT replace, which is how the
# prerequisite restore returns a routed parent) carries the whole int_trunk_host template with its
# default values persisted (live ND 4.3, 2026-10-08), so those defaults are the free state as well.
_DEFAULT_PORT_POLICIES = {"int_trunk_host", "trunkhost"}
_DEFAULT_PORT_NV = {
    "admin_state": "true", "allowed_vlans": "none", "bpduguard_enabled": "no",
    "enable_netflow": "false", "mark_deleted": "false", "mtu": "jumbo",
    "porttype_fast_enabled": "true", "ptp": "false", "speed": "auto",
    # Persisted by a reset only; absent on a never-touched port.
    "bpdufilter_enabled": "no", "cdp_enable": "true", "enable_errdisable_acl": "true",
    "enable_monitor": "false", "enable_orphan_port": "false", "enable_pfc": "false",
    "enable_qos": "false", "enable_storm_control": "false", "fec": "auto", "link_type": "auto",
    "negotiate_auto": "true", "port_duplex_mode": "auto", "storm_control_action": "no",
    "enablevlanmapping": "false",
}
_BOOKKEEPING_NV = {"intf_name", "policy_id", "serial_number", "priority", "fabric_name", "create_update"}


def _is_default_free_port(state):
    policy = str(state.get("policy") or state.get("policy_type") or "").lower()
    if policy not in _DEFAULT_PORT_POLICIES:
        return False
    nv_pairs = {
        str(key).lower(): str(value).strip().lower()
        for key, value in (state.get("nv_pairs") or {}).items()
        if str(value).strip()
    }
    if not nv_pairs:
        return False
    if set(nv_pairs) - _BOOKKEEPING_NV - set(_DEFAULT_PORT_NV):
        return False
    return all(nv_pairs.get(key, wanted) == wanted for key, wanted in _DEFAULT_PORT_NV.items())


def _port_channel_members(state):
    members = state.get("nv_pairs", {}).get("MEMBER_INTERFACES", "")
    if isinstance(members, list):
        return [str(item) for item in members if str(item).strip()]
    return [item.strip() for item in str(members or "").split(",") if item.strip()]



def _resolve_link_endpoints(registry, spec, label, *, require_distinct_fabrics):
    """Resolve a declared {src, dst} link spec to serial/interface endpoints from the lab registry."""
    endpoints = {}
    for side in ("src", "dst"):
        endpoint = spec.get(side)
        if not isinstance(endpoint, dict):
            raise OrchestrationError(f"{label} is missing its {side} endpoint")
        switch_ref = endpoint.get("switch_ref")
        registry_switch = registry["lab"]["switches"].get(switch_ref)
        if registry_switch is None:
            raise OrchestrationError(f"{label} references unknown switch: {switch_ref}")
        interface = endpoint.get("interface")
        if interface not in registry["lab"]["interface_allowlist"].get(switch_ref, []):
            raise OrchestrationError(f"undeclared {label} interface: {switch_ref}/{interface}")
        fabric_ref = registry_switch["baseline_fabric_ref"]
        endpoints[side] = {
            "fabric_ref": fabric_ref,
            "fabric_name": registry["lab"]["fabrics"][fabric_ref]["name"],
            "switch_ref": switch_ref,
            "switch_name": endpoint.get("switch_name", switch_ref),
            "serial": registry_switch["serial"],
            "interface": interface,
        }
    same_fabric = endpoints["src"]["fabric_ref"] == endpoints["dst"]["fabric_ref"]
    if require_distinct_fabrics and same_fabric:
        raise OrchestrationError(f"{label} must span two different fabrics")
    if not require_distinct_fabrics and not same_fabric:
        raise OrchestrationError(f"{label} must stay inside one fabric")
    return endpoints["src"], endpoints["dst"]


def _flat_scalar_map(value, label):
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or isinstance(item, (dict, list, tuple)) or item is None
        for key, item in value.items()
    ):
        raise OrchestrationError(f"{label} must be a flat map of scalar values")
    return dict(value)


def plan_topology_delta(registry, resolved_execution, current_state):
    """Return a deterministic allowlisted operation list for one confirmed execution."""
    _validated_registry(registry)
    profile = resolved_execution.get("profile")
    if not isinstance(profile, dict):
        raise OrchestrationError("resolved execution has no profile")
    if resolved_execution.get("profile_id") != profile.get("profile_id"):
        raise OrchestrationError("resolved execution/profile mismatch")
    switch_topology_mutation_allowed = profile["profile_id"] in SWITCH_TOPOLOGY_MUTATION_PROFILES
    operations = []

    for fabric in profile.get("fabrics", []):
        current = _current_fabric(current_state, fabric["ref"])
        if current is None:
            if fabric["lifecycle"] != "disposable":
                raise OrchestrationError(f"{fabric['lifecycle']} fabric {fabric['ref']} is missing")
            if not re.fullmatch(r"ANSIBLE_NIGHTLY_[A-Z0-9_]+", fabric["name"]):
                raise OrchestrationError("disposable fabric name is not safely namespaced")
            operations.append({
                "operation": "create_disposable_fabric",
                "fabric_ref": fabric["ref"],
                "name": fabric["name"],
                "fabric_type": fabric["type"],
            })
        elif current.get("name") != fabric["name"] or current.get("type") != fabric["type"]:
            raise OrchestrationError(f"fabric {fabric['ref']} identity or type mismatch")

    if profile.get("bfd_required"):
        advanced = _current_fabric(current_state, "advanced")
        if not advanced:
            raise OrchestrationError("BFD is required but the advanced fabric is absent")
        if advanced.get("bfd_enabled") is not True:
            operations.append({"operation": "ensure_bfd", "fabric_ref": "advanced"})

    for member in profile.get("switches", {}).get("members", []):
        switch_ref = member["ref"]
        registry_switch = registry["lab"]["switches"][switch_ref]
        current = current_state.get("switches", {}).get(switch_ref)
        if current is None:
            desired_role = member["desired_role"]
            if (
                member["desired_fabric_ref"] != registry_switch["baseline_fabric_ref"]
                or desired_role not in {"preserve", registry_switch["baseline_role"]}
            ):
                raise OrchestrationError(
                    f"missing switch {switch_ref} cannot be added outside its canonical baseline"
                )
            operations.append({
                "operation": "ensure_switch_membership",
                "switch_ref": switch_ref,
                "serial": registry_switch["serial"],
                "fabric_ref": registry_switch["baseline_fabric_ref"],
                "desired_role": registry_switch["baseline_role"],
            })
            continue
        if current.get("serial") != registry_switch["serial"] or current.get("seed_ip") != registry_switch["seed_ip"]:
            raise OrchestrationError(f"switch identity mismatch: {switch_ref}")
        desired_fabric = member["desired_fabric_ref"]
        moving = current.get("fabric_ref") != desired_fabric
        if moving:
            if not switch_topology_mutation_allowed:
                raise OrchestrationError(
                    f"{profile['profile_id']} is verify-only for switch topology; "
                    f"refusing membership change for {switch_ref}"
                )
            if not (
                switch_ref == "external_edge_1"
                and current.get("fabric_ref") == "external"
                and desired_fabric == "advanced"
                and profile["phase"] in {"borrowed_switch", "terminal_switch"}
            ):
                raise OrchestrationError(f"undeclared membership move: {switch_ref}")
            operations.append({
                "operation": "membership_move",
                "switch_ref": switch_ref,
                "serial": registry_switch["serial"],
                "source_fabric_ref": current["fabric_ref"],
                "destination_fabric_ref": desired_fabric,
                "desired_role": member["desired_role"],
            })
        elif member["desired_role"] != "preserve" and current.get("role") != member["desired_role"]:
            if not switch_topology_mutation_allowed:
                raise OrchestrationError(
                    f"{profile['profile_id']} is verify-only for switch topology; "
                    f"refusing role change for {switch_ref}"
                )
            operations.append({
                "operation": "change_role",
                "switch_ref": switch_ref,
                "serial": registry_switch["serial"],
                "fabric_ref": desired_fabric,
                "current_role": current.get("role"),
                "desired_role": member["desired_role"],
            })

    for link in profile.get("links", []):
        switch_ref = link["switch_ref"]
        allowlist = registry["lab"]["interface_allowlist"][switch_ref]
        current_interfaces = current_state.get("interfaces", {}).get(switch_ref, {})
        for interface in link["interfaces"]:
            if interface not in allowlist:
                raise OrchestrationError(f"undeclared interface: {switch_ref}/{interface}")
            current = current_interfaces.get(interface)
            if current is None:
                raise UnavailableError(f"required physical interface is missing: {switch_ref}/{interface}")
            if current.get("admin_state") is not True or current.get("operational_state") not in {None, "up"}:
                operations.append({
                    "operation": "ensure_interface",
                    "switch_ref": switch_ref,
                    "serial": registry["lab"]["switches"][switch_ref]["serial"],
                    "fabric_name": registry["lab"]["fabrics"][registry["lab"]["switches"][switch_ref]["baseline_fabric_ref"]]["name"],
                    "interface": interface,
                    "admin_state": True,
                    "operational_state": "when_reported_up",
                })

    for spec in profile.get("interfabric_links", []):
        template = spec.get("template")
        if template not in ALLOWED_LINK_TEMPLATES:
            raise OrchestrationError(f"undeclared inter-fabric link template: {template}")
        label = f"inter-fabric link {template}"
        src_endpoint, dst_endpoint = _resolve_link_endpoints(
            registry, spec, label, require_distinct_fabrics=True
        )
        endpoints = {"src": src_endpoint, "dst": dst_endpoint}
        provisioning = spec.get("provisioning", "api")
        if provisioning not in LINK_PROVISIONING_MODES:
            raise OrchestrationError(
                f"inter-fabric link {template} has unsupported provisioning mode: {provisioning}"
            )
        policy_type = None
        template_inputs = {}
        if provisioning == "nd_manage_links":
            policy_type = spec.get("policy_type")
            if policy_type != LINK_POLICY_BY_TEMPLATE[template]:
                raise OrchestrationError(
                    f"inter-fabric link {template} must use nd_manage_links policy "
                    f"{LINK_POLICY_BY_TEMPLATE[template]}, not {policy_type}"
                )
            template_inputs = _flat_scalar_map(
                spec.get("template_inputs", {}), f"inter-fabric link {template} template_inputs"
            )
        physical_present = _physical_link_present(current_state, endpoints["src"], endpoints["dst"])
        if spec.get("requires_physical", True) and not physical_present:
            raise UnavailableError(
                f"required physical link is missing: {endpoints['src']['switch_ref']}/{endpoints['src']['interface']} "
                f"<-> {endpoints['dst']['switch_ref']}/{endpoints['dst']['interface']}; cable these ports for {template}"
            )
        if _link_exists(current_state, endpoints["src"], endpoints["dst"], template, policy_type):
            continue
        operation = {
            "operation": "ensure_link",
            "template": template,
            "provisioning": provisioning,
            "requires_physical": bool(spec.get("requires_physical", True)),
            "src": endpoints["src"],
            "dst": endpoints["dst"],
        }
        if provisioning == "nd_manage_links":
            operation["policy_type"] = policy_type
            operation["template_inputs"] = template_inputs
            # No cable behind the pair: ND stores a planned link, which the restore journal removes again.
            operation["config_only"] = not _physical_link_present(
                current_state, endpoints["src"], endpoints["dst"], allow_down=True
            )
        nvpairs = spec.get("nvpairs")
        if nvpairs is not None:
            if not isinstance(nvpairs, dict) or any(
                not isinstance(key, str) or not isinstance(value, (str, int))
                for key, value in nvpairs.items()
            ):
                raise OrchestrationError(
                    f"inter-fabric link {template} nvpairs must be a flat string/int map"
                )
            operation["nvpairs"] = {str(key): str(value) for key, value in nvpairs.items()}
        operations.append(operation)

    for pair in profile.get("vpc_pairs", []):
        if pair.get("required_path") == "module_creates_pair":
            # The integration target creates the pair itself, so there is nothing to apply here;
            # the prerequisite is the cabled peer-link ND will pick up (ports admin-up via profile.links).
            if pair.get("mode") != "physical" or not pair.get("physical_peer_links"):
                raise OrchestrationError("a module-created vPC pair must declare its physical peer-link")
            if _pair_present(current_state, pair["fabric_ref"], pair["peer_refs"]):
                continue
            for link in pair["physical_peer_links"]:
                src_endpoint, dst_endpoint = _resolve_link_endpoints(
                    registry, link, "vPC peer-link", require_distinct_fabrics=False
                )
                if not _physical_link_present(current_state, src_endpoint, dst_endpoint, allow_down=True):
                    raise UnavailableError(
                        f"required physical vPC peer-link is missing: {src_endpoint['switch_ref']}/{src_endpoint['interface']} "
                        f"<-> {dst_endpoint['switch_ref']}/{dst_endpoint['interface']}; cable these ports"
                    )
            continue
        if pair.get("mode") != "virtual" or pair.get("physical_peer_links"):
            raise OrchestrationError("physical or unresolved vPC prerequisites are prohibited")
        if not _pair_exists(current_state, pair["fabric_ref"], pair["peer_refs"], "virtual"):
            if pair.get("required_path") == "existing_pair_no_create":
                raise UnavailableError(
                    f"required virtual vPC pair is absent and this profile forbids creation: "
                    f"{pair['fabric_ref']} {'/'.join(pair['peer_refs'])}"
                )
            operations.append({
                "operation": "ensure_virtual_vpc",
                "fabric_ref": pair["fabric_ref"],
                "peer_refs": list(pair["peer_refs"]),
                "physical_peer_links": [],
            })

    for resource in profile.get("resources", []):
        kind = resource.get("kind")
        if kind == "verify_free_interfaces":
            switch_ref = resource["switch_ref"]
            interfaces = list(resource["interfaces"])
            for interface in interfaces:
                _assert_free_interface(registry, current_state, switch_ref, interface)
            operations.append({
                "operation": "verify_free_interfaces",
                "switch_ref": switch_ref,
                "serial": registry["lab"]["switches"][switch_ref]["serial"],
                "interfaces": interfaces,
                "constraints": list(resource["constraints"]),
            })
            continue
        if kind == "verify_logical_interface_namespace":
            switch_ref = resource["switch_ref"]
            collisions = []
            for interface in resource["interfaces"]:
                state = _logical_interface_state(current_state, switch_ref, interface)
                if state is None:
                    raise OrchestrationError(
                        f"logical interface was not captured: {switch_ref}/{interface}"
                    )
                if state.get("exists") is not False:
                    collisions.append(interface)
            if collisions:
                raise OrchestrationError(
                    f"reserved logical interface namespace is in use on {switch_ref}: "
                    f"{', '.join(collisions)}"
                )
            operations.append({
                "operation": "verify_logical_interface_namespace",
                "switch_ref": switch_ref,
                "serial": registry["lab"]["switches"][switch_ref]["serial"],
                "interface_type": resource["interface_type"],
                "interfaces": list(resource["interfaces"]),
                "expected_state": "absent",
            })
            continue
        if kind == "ensure_routed_parent":
            switch_ref = resource["switch_ref"]
            interface = resource["interface"]
            state = _assert_free_interface(
                registry, current_state, switch_ref, interface, resource.get("existing_link")
            )
            if _is_routed_ethernet(state):
                continue
            if (state.get("configured") is True or state.get("policy")) and not _is_default_free_port(state):
                raise UnavailableError(
                    f"refusing to replace existing non-routed interface intent: "
                    f"{switch_ref}/{interface} ({state.get('policy') or state.get('policy_type')})"
                )
            switch = registry["lab"]["switches"][switch_ref]
            fabric_ref = switch["baseline_fabric_ref"]
            operations.append({
                "operation": "ensure_routed_parent",
                "switch_ref": switch_ref,
                "serial": switch["serial"],
                "switch_ip": switch["seed_ip"],
                "fabric_ref": fabric_ref,
                "fabric_name": registry["lab"]["fabrics"][fabric_ref]["name"],
                "interface": interface,
                "desired_policy": resource["desired_policy"],
            })
            continue
        if kind == "ensure_routed_port_channel":
            switch_ref = resource["switch_ref"]
            interface = resource["interface"]
            state = _logical_interface_state(current_state, switch_ref, interface)
            if state is None:
                raise OrchestrationError(
                    f"routed port-channel state was not captured: {switch_ref}/{interface}"
                )
            if state.get("exists") is True:
                policy = str(state.get("policy", ""))
                members = _port_channel_members(state)
                if policy != resource["desired_policy"]:
                    raise OrchestrationError(
                        f"refusing to replace existing non-routed port-channel intent: "
                        f"{switch_ref}/{interface} ({policy or 'unknown policy'})"
                    )
                if members != list(resource.get("member_interfaces", [])):
                    raise OrchestrationError(
                        f"reserved routed port-channel has unexpected members: "
                        f"{switch_ref}/{interface} ({', '.join(members)})"
                    )
                continue
            switch = registry["lab"]["switches"][switch_ref]
            fabric_ref = switch["baseline_fabric_ref"]
            operations.append({
                "operation": "ensure_routed_port_channel",
                "switch_ref": switch_ref,
                "serial": switch["serial"],
                "switch_ip": switch["seed_ip"],
                "fabric_ref": fabric_ref,
                "fabric_name": registry["lab"]["fabrics"][fabric_ref]["name"],
                "interface": interface,
                "desired_policy": resource["desired_policy"],
                "member_interfaces": list(resource.get("member_interfaces", [])),
            })
            continue
        if kind == "allocation_entity_tokens":
            values = resource.get("values", [])
            if not values or any(not isinstance(value, str) or not re.fullmatch(r"Ethernet\d+/\d+", value) for value in values):
                raise OrchestrationError("allocation entity tokens must be non-empty Ethernet interface identifiers")
            continue
        if kind == "disposable_fabric_matrix":
            fabric_types = resource.get("fabric_types", [])
            if resource.get("namespaced_only") is not True or not fabric_types:
                raise OrchestrationError("disposable fabric matrix must be namespaced and declare fabric types")
            continue
        operations.append({"operation": "verify_resource", "resource": copy.deepcopy(resource)})

    if any(item.get("operation") not in ALLOWED_OPERATIONS for item in operations):
        raise OrchestrationError("planner emitted an unsupported operation")
    return operations


def _normalize(value):
    if isinstance(value, dict):
        return {
            key: _normalize(item)
            for key, item in sorted(value.items())
            if key not in SERVER_MANAGED_FIELDS
        }
    if isinstance(value, list):
        normalized = [_normalize(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    return value


def _assert_no_credentials(value, path="root"):
    if isinstance(value, dict):
        for key, item in value.items():
            if re.search(r"password|credential|token|secret|username", str(key), re.I):
                raise OrchestrationError(f"credential-like field cannot be serialized: {path}.{key}")
            _assert_no_credentials(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_no_credentials(item, f"{path}[{index}]")


def snapshot_path(state_dir, level, *, phase_id=None, execution_id=None):
    state_dir = pathlib.Path(state_dir)
    if not state_dir.is_absolute() or ".nd-prerequisite-recovery" not in state_dir.parts:
        raise OrchestrationError("state directory must be absolute and below .nd-prerequisite-recovery")
    safe_id = re.compile(r"^[A-Za-z0-9_.-]+$")
    if level == "L0" and phase_id is None and execution_id is None:
        return state_dir / "L0" / "job.yaml"
    if level == "L1" and phase_id and execution_id is None and safe_id.fullmatch(phase_id):
        return state_dir / "L1" / f"{phase_id}.yaml"
    if (
        level == "L2"
        and phase_id
        and execution_id
        and safe_id.fullmatch(phase_id)
        and safe_id.fullmatch(execution_id)
    ):
        return state_dir / "L2" / phase_id / f"{execution_id}.yaml"
    raise OrchestrationError("invalid snapshot path arguments")


def build_snapshot(
    level,
    run_id,
    state,
    *,
    phase_id=None,
    profile_id=None,
    execution_id=None,
    parent_snapshot_id=None,
):
    if level not in {"L0", "L1", "L2"}:
        raise OrchestrationError(f"unsupported snapshot level: {level}")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", run_id):
        raise OrchestrationError("invalid run ID")
    if level == "L0" and any((phase_id, profile_id, execution_id, parent_snapshot_id)):
        raise OrchestrationError("L0 cannot have phase, target, or parent lineage")
    if level == "L1" and (not phase_id or not parent_snapshot_id or profile_id or execution_id):
        raise OrchestrationError("L1 requires phase and L0 parent only")
    if level == "L2" and not all((phase_id, profile_id, execution_id, parent_snapshot_id)):
        raise OrchestrationError("L2 requires phase, profile, execution, and L1 parent")
    _assert_no_credentials(state)
    identity = ":".join(str(item or "-") for item in (run_id, level, phase_id, profile_id, execution_id))
    return {
        "schema_version": 1,
        "snapshot_level": level,
        "snapshot_id": identity,
        "parent_snapshot_id": parent_snapshot_id,
        "run_id": run_id,
        "phase_id": phase_id,
        "profile_id": profile_id,
        "execution_id": execution_id,
        "state": _normalize(copy.deepcopy(state)),
        "created_by_prepare": {
            "fabrics": [], "vpc_pairs": [], "interfaces": [],
            "resources": [], "domain_objects": [],
        },
    }


def validate_snapshot_lineage(l0, l1, l2):
    errors = []
    if l0.get("snapshot_level") != "L0":
        errors.append("job snapshot is not L0")
    if l1.get("snapshot_level") != "L1":
        errors.append("phase snapshot is not L1")
    if l2.get("snapshot_level") != "L2":
        errors.append("target snapshot is not L2")
    if len({l0.get("run_id"), l1.get("run_id"), l2.get("run_id")}) != 1:
        errors.append("snapshot run IDs differ")
    if l1.get("parent_snapshot_id") != l0.get("snapshot_id"):
        errors.append("L1 parent does not match L0")
    if l2.get("parent_snapshot_id") != l1.get("snapshot_id"):
        errors.append("L2 parent does not match L1")
    if l2.get("phase_id") != l1.get("phase_id"):
        errors.append("L2 phase does not match L1")
    return errors


def _reject_symlink_components(path):
    absolute = pathlib.Path(path).absolute()
    for component in (absolute, *absolute.parents):
        if component.is_symlink():
            raise OrchestrationError(f"state path contains a symlink: {component}")


def _write_restricted(path, payload):
    path = pathlib.Path(path)
    if not path.is_absolute() or ".nd-prerequisite-recovery" not in path.parts:
        raise OrchestrationError("state path must be absolute and below .nd-prerequisite-recovery")
    _reject_symlink_components(path)
    protected_directories = []
    cursor = path.parent
    while True:
        protected_directories.append(cursor)
        if cursor.name == ".nd-prerequisite-recovery":
            break
        cursor = cursor.parent
    for directory in reversed(protected_directories):
        if directory.is_symlink():
            raise OrchestrationError(f"state path contains a symlink: {directory}")
        directory.mkdir(mode=0o700, exist_ok=True)
        directory.chmod(0o700)
    _reject_symlink_components(path)
    if path.exists():
        raise OrchestrationError(f"state file already exists: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise OrchestrationError(f"cannot safely create state file: {path}") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
    path.chmod(0o600)
    return path


def write_restricted_yaml(path, data):
    _assert_no_credentials(data)
    return _write_restricted(path, yaml.safe_dump(data, sort_keys=True).encode("utf-8"))


def write_restricted_json(path, data):
    _assert_no_credentials(data)
    return _write_restricted(path, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def runtime_vars_for_execution(resolved_execution, run_id, phase_baseline_id):
    if not run_id or not phase_baseline_id:
        raise OrchestrationError("fresh run and phase baseline IDs are required")
    profile = resolved_execution["profile"]
    if CANONICAL_RUNTIME_KEYS & set(profile.get("runtime_vars", {})):
        raise OrchestrationError("profile runtime variables collide with canonical topology")
    runtime = copy.deepcopy(resolved_execution.get("runtime_defaults", {}))
    runtime.update(copy.deepcopy(profile.get("runtime_vars", {})))
    if RESERVED_RUNTIME_KEYS & set(runtime):
        raise OrchestrationError("profile runtime variables collide with lifecycle markers")
    child = resolved_execution.get("execution")
    if child:
        fabric = next(item for item in profile["fabrics"] if item["ref"] == child["fabric_ref"])
        switches = child.get("switch_refs", [])
        runtime.update({
            "fabric_name": fabric["name"],
            "fabric_type": fabric["type"],
            "switch1_serial": switches[0] and next(
                item["serial"]
                for ref, item in _runtime_switch_registry(resolved_execution).items()
                if ref == switches[0]
            ),
            "switch2_serial": switches[1] and next(
                item["serial"]
                for ref, item in _runtime_switch_registry(resolved_execution).items()
                if ref == switches[1]
            ),
        })
    runtime.update({
        "nd_prerequisite_prepared": True,
        "nd_prerequisite_run_id": run_id,
        "nd_prerequisite_profile": resolved_execution["profile_id"],
        "nd_prerequisite_execution_id": resolved_execution["execution_id"],
        "nd_prerequisite_phase_baseline_id": phase_baseline_id,
    })
    _assert_no_credentials(runtime)
    return runtime


def _runtime_switch_registry(resolved_execution):
    """Return the exact non-secret lab identities embedded by resolver callers."""
    # The child-only runtime path is populated by resolve_execution below through
    # this private field; keeping it out of the serialized profile avoids drift.
    return resolved_execution.get("lab_switches", {})


def validate_api_status(status, object_failures=None):
    status = int(status)
    if status == 207:
        details = json.dumps(object_failures or [], sort_keys=True)
        raise OrchestrationError(f"HTTP 207 partial failure: {details}")
    if status < 200 or status >= 300:
        raise OrchestrationError(f"HTTP {status} API failure")
    return True


class ApiErrorTracker:
    def __init__(self, max_consecutive_errors=3):
        if max_consecutive_errors != 3:
            raise OrchestrationError("maximum consecutive API errors must equal 3")
        self.max_consecutive_errors = max_consecutive_errors
        self.consecutive_errors = 0

    def observe(self, *, success, status=None, object_failures=None):
        if success:
            if status is not None:
                validate_api_status(status, object_failures)
            self.consecutive_errors = 0
            return 0
        if status is not None and int(status) == 207:
            validate_api_status(status, object_failures)
        self.consecutive_errors += 1
        if self.consecutive_errors >= self.max_consecutive_errors:
            raise OrchestrationError(f"{self.consecutive_errors} consecutive API errors")
        return self.consecutive_errors


def _domain_value(state, domain):
    if domain in state:
        return state[domain]
    return state.get("managed_domains", {}).get(domain, [])


def evaluate_restore(before, after, domains):
    return [
        domain
        for domain in domains
        if not normalized_equal(domain, _domain_value(before, domain), _domain_value(after, domain))
    ]


def quarantine(state_dir, run_id, profile_id, mismatched_domains):
    state_dir = pathlib.Path(state_dir)
    _reject_symlink_components(state_dir)
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    _reject_symlink_components(state_dir)
    state_dir.chmod(0o700)
    report = {
        "run_id": run_id,
        "profile_id": profile_id,
        "mismatched_domains": list(mismatched_domains),
        "quarantined": True,
    }
    write_restricted_json(state_dir / "recovery-report.json", report)
    marker = _write_restricted(
        state_dir / "QUARANTINED",
        f"run_id={run_id} profile={profile_id}\n".encode("utf-8"),
    )
    return marker


def _load_state(path):
    if not path:
        return {}
    text = pathlib.Path(path).read_text(encoding="utf-8")
    if path.endswith((".yaml", ".yml")):
        return yaml.safe_load(text) or {}
    return json.loads(text)


def main(argv=None):
    """Offline planning CLI consumed by the Ansible prerequisite wrapper."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--registry", required=True)
    plan.add_argument("--execution-id", required=True)
    plan.add_argument("--state")
    plan.add_argument("--run-id")
    plan.add_argument("--phase-baseline-id")
    plan.add_argument("--allow-auto-confirm", action="store_true")
    schedule = sub.add_parser("schedule")
    schedule.add_argument("--registry", required=True)
    schedule.add_argument("--selected", required=True)
    schedule.add_argument("--allow-auto-confirm", action="store_true")
    registry_export = sub.add_parser("registry")
    registry_export.add_argument("--registry", required=True)
    args = parser.parse_args(argv)
    registry = load_registry(args.registry)
    try:
        if args.command == "registry":
            _validated_registry(registry)
            print(json.dumps(registry, indent=2, sort_keys=True))
            return 0
        if args.command == "plan":
            resolved = resolve_execution(registry, args.execution_id, allow_auto_confirm=args.allow_auto_confirm)
            output = {
                "resolved": {key: resolved[key] for key in ("profile_id", "execution_id", "phase", "execution_style")},
                "operations": plan_topology_delta(registry, resolved, _load_state(args.state)),
            }
            if args.run_id and args.phase_baseline_id:
                output["runtime_vars"] = runtime_vars_for_execution(resolved, args.run_id, args.phase_baseline_id)
            print(json.dumps(output, indent=2, sort_keys=True))
            return 0
        if args.command == "schedule":
            selected = [item for item in args.selected.split(",") if item]
            print(json.dumps(build_phase_schedule(registry, selected, allow_auto_confirm=args.allow_auto_confirm), indent=2, sort_keys=True))
            return 0
    except UnavailableError as exc:
        print(f"substrate unavailable: {exc}", file=sys.stderr)
        return UNAVAILABLE_EXIT_CODE
    except OrchestrationError as exc:
        print(f"orchestration error: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
