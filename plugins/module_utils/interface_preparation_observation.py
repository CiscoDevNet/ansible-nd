# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# SPDX-License-Identifier: GPL-3.0-or-later

"""Bounded, cache-only evidence for non-retiring L2 interface preparation.

The caller owns attachment intent. This module proves interface configuration
from the workflow's existing actual snapshot; it never queries or interprets a
Network and never sends a transport request.
"""

from __future__ import annotations

from hashlib import sha256
import json

from ansible_collections.cisco.nd.plugins.module_utils.interface_membership import (
    EthernetMembershipIndex,
    get_member_policy_descriptor_for_parent,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_member_interface import (
    normalize_port_channel_id,
    normalize_safe_member_updates,
    parse_member_interface_response,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import (
    InterfaceWorkflowPlanner,
    InterfaceWorkflowValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.interface_default_config import (
    ROUTED_SIBLING_RESET_FIELDS,
)

PREPARATION_TYPES = frozenset(
    {
        "ethernet_access",
        "ethernet_trunk_host",
        "port_channel_access",
        "port_channel_dot1q_tunnel_host",
        "port_channel_trunk_host",
        "vpc_access",
        "vpc_dot1q_tunnel",
        "vpc_trunk_host",
    }
)


def _policy(raw):
    config = raw.get("configData") or {}
    if not isinstance(config, dict):
        raise ValueError("Incomplete interface policy observation")
    network = config.get("networkOS") or {}
    if not isinstance(network, dict):
        raise ValueError("Incomplete interface policy observation")
    policy = network.get("policy") or {}
    if not isinstance(policy, dict):
        raise ValueError("Incomplete interface policy observation")
    return config, network, policy


def _model_policy(model):
    return model.config_data.network_os.policy


def _names(value):
    if value is None or value == "":
        return set()
    if isinstance(value, str):
        value = value.split(",")
    if not isinstance(value, (tuple, list)) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError("Incomplete aggregate member observation")
    return {item.strip().casefold() for item in value}


def _member_slots(domain):
    if domain == "port_channel":
        return (("ports", "ports"),)
    if domain == "vpc":
        return (
            ("peer1_member_ports", "peer1MemberPorts"),
            ("peer2_member_ports", "peer2MemberPorts"),
        )
    return ()


def _explicit_member_expectation(plan, resource, desired, serial):
    """Find the exact explicit Ethernet prerequisite, including unchanged retries."""
    if resource.adapter.ownership_domain != "ethernet":
        return None
    matches = [
        item
        for item in getattr(plan, "missing_member_verifications", ())
        if item.resource_index == resource.resource_index and item.switch_id == serial and item.interface_name.casefold() == desired.interface_name.casefold()
    ]
    if len(matches) > 1:
        raise ValueError("Explicit Ethernet preparation has ambiguous parent expectations")
    return matches[0] if matches else None


def _observe_explicit_member(*, plan, resource, desired, serial, expectation, membership, peers, snapshot, target, observations):
    """Prove actual aggregate ownership instead of projecting a host policy.

    An explicit Ethernet resource describes its prerequisite host mode and safe
    member properties. Once the parent is staged, its actual policy is a member
    policy; the host discriminator must never be reported as observed intent.
    """
    if membership is None:
        raise ValueError("Explicit Ethernet preparation has no aggregate ownership observation")
    if resource.state != "merged":
        raise ValueError("Explicit Ethernet member preparation requires merged intent")
    parents = [item for item in plan.resources if item.resource_index == expectation.parent_resource_index]
    if len(parents) != 1 or parents[0].adapter.ownership_domain not in {"port_channel", "vpc"}:
        raise ValueError("Explicit Ethernet preparation has no exact parent resource")
    parent = parents[0]
    candidates = [
        model
        for model in parent.proposed
        if snapshot.fabric_context.get_switch_id(model.switch_ip) == expectation.parent_switch_id
        and model.interface_name.casefold() == expectation.parent_name.casefold()
        and _model_policy(model).policy_type == expectation.parent_policy_type
    ]
    if len(candidates) != 1:
        raise ValueError("Explicit Ethernet preparation parent differs from requested intent")
    parent_model = candidates[0]
    parent_policy = _model_policy(parent_model)
    descriptor = get_member_policy_descriptor_for_parent(parent_policy.policy_type)
    expected_hosts = {"access": "accessHost", "trunk": "trunkHost"}
    if descriptor is None or descriptor.network_os != "nx-os" or descriptor.family not in expected_hosts:
        raise ValueError("Explicit Ethernet preparation has an unsupported parent policy")
    desired_policy = _model_policy(desired)
    if desired_policy.policy_type != expected_hosts[descriptor.family]:
        raise ValueError("Explicit Ethernet preparation host policy differs from its parent family")
    if parent.adapter.ownership_domain == "port_channel":
        if serial != expectation.parent_switch_id:
            raise ValueError("Explicit Ethernet preparation belongs to a different parent switch")
        names = parent_policy.ports
        port_channel_id = normalize_port_channel_id(parent_model.interface_name)
    else:
        primary = expectation.parent_switch_id
        if serial == primary:
            names = parent_policy.peer1_member_ports
            port_channel_id = normalize_port_channel_id(parent_policy.peer1_port_channel_id)
        elif peers.get(primary) == serial and peers.get(serial) == primary:
            names = parent_policy.peer2_member_ports
            port_channel_id = normalize_port_channel_id(parent_policy.peer2_port_channel_id)
        else:
            raise ValueError("Explicit Ethernet preparation has no exact reciprocal parent slot")
    if desired.interface_name.casefold() not in _names(names) or port_channel_id is None:
        raise ValueError("Explicit Ethernet preparation is absent from requested parent membership")
    ownership = membership.validate(serial, desired.interface_name)
    if (
        ownership.member.policy_type != expectation.expected_member_policy
        or ownership.member.policy_type != descriptor.policy_type
        or ownership.owner.switch_id != serial
        or ownership.owner.interface_name.casefold() != expectation.parent_name.casefold()
        or ownership.owner.policy_type != expectation.parent_policy_type
        or ownership.owner.port_channel_id != expectation.parent_port_channel_id
        or ownership.configured_port_channel_id != expectation.parent_port_channel_id
        or ownership.configured_port_channel_id != port_channel_id
        or descriptor.pair_aware
        and not ownership.pair_validated
    ):
        raise ValueError("Explicit Ethernet preparation has incorrect actual aggregate ownership")
    fields = desired_policy.model_fields_set - {"policy_type"}
    expected_values = normalize_safe_member_updates({field: getattr(desired_policy, field) for field in fields})
    observed = parse_member_interface_response(ownership.member.record)
    raw_policy = _policy(ownership.member.record)[2]
    normalize_safe_member_updates({"extra_config": raw_policy.get("extraConfig")})
    for field, expected in expected_values.items():
        alias = type(observed.policy).model_fields[field].alias or field
        if getattr(observed.policy, field) != expected or (isinstance(expected, bool) and not isinstance(raw_policy.get(alias), bool)):
            raise ValueError("Explicit Ethernet preparation member properties differ from requested intent")
    target["aggregate_member"] = {
        "parent_resource_index": parent.resource_index,
        "parent_switch_id": expectation.parent_switch_id,
        "owner_switch_id": ownership.owner.switch_id,
        "parent_interface_name": ownership.owner.interface_name,
        "parent_policy_type": ownership.owner.policy_type,
        "configured_port_channel_id": ownership.configured_port_channel_id,
        "policy_type": ownership.member.policy_type,
        "pair_validated": ownership.pair_validated,
    }
    observations.append(dict(ownership.owner.record))
    if ownership.peer_owner is not None:
        observations.append(dict(ownership.peer_owner.record))
        observations.extend(dict(item.record) for item in ownership.peer_members)
    target["observation_revision"] = sha256(json.dumps(observations, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    target["satisfied"] = True


def validate_preparation_plan(*, params, plan, snapshot):
    """Reject implicit member retirement before enabling any native writes."""
    if (params.get("config_actions") or {}).get("deploy", False):
        raise InterfaceWorkflowValidationError("Interface preparation requires config_actions.deploy=false")
    if not (params.get("verify") or {}).get("enabled", False):
        raise InterfaceWorkflowValidationError("Interface preparation requires verify.enabled=true")
    for resource in plan.resources:
        if resource.resource_type not in PREPARATION_TYPES or resource.state not in {
            "merged",
            "replaced",
        }:
            raise InterfaceWorkflowValidationError("Interface preparation accepts only explicit merged/replaced L2 interface targets")
        if any(
            getattr(
                model.config_data.network_os.network_os_type,
                "value",
                model.config_data.network_os.network_os_type,
            )
            != "nx-os"
            for model in resource.proposed
        ):
            raise InterfaceWorkflowValidationError("Interface preparation currently supports NX-OS targets only")
        if resource.operations.deletes or getattr(resource, "platform_deletes", ()):
            raise InterfaceWorkflowValidationError("Interface preparation cannot delete or reset omitted interfaces")
        slots = _member_slots(resource.adapter.ownership_domain)
        if not slots:
            continue
        models = [
            *resource.operations.creates,
            *resource.operations.updates,
            *(item.desired for item in resource.transitions),
        ]
        for model in models:
            serial = snapshot.fabric_context.get_switch_id(model.switch_ip)
            before = snapshot.cached_interface(serial, model.interface_name, original=True)
            if before is None:
                continue
            _config, _network, current = _policy(before)
            final = _model_policy(model)
            for model_field, wire_field in slots:
                if _names(current.get(wire_field)) - _names(getattr(final, model_field, None)):
                    raise InterfaceWorkflowValidationError(
                        f"Interface preparation would retire aggregate members on {serial}/{model.interface_name}; "
                        "defer this replacement until final interface processing"
                    )


def preparation_observation(*, params, plan, snapshot, request_sha256, check_mode=False, verified=False):
    """Observe requested targets and member ownership with zero extra reads.

    Only requested raw records are copied. Membership indexing is performed once
    across the complete clean switch snapshots already present in this workflow.
    No projected model or operational-up condition can establish readiness.
    """
    result = {
        "version": 1,
        "source": "native_actual_preparation_observation_v1",
        "observed": False,
        "complete": False,
        "all_satisfied": False,
        "request_sha256": request_sha256,
        "resources": [],
    }
    if snapshot is None:
        result["reason"] = "no_observed_snapshot"
        return result
    if (params.get("config_actions") or {}).get("deploy", False) or not (params.get("verify") or {}).get("enabled", False):
        result["reason"] = "preparation_requires_verified_staging"
        return result
    if plan.changed and (check_mode or not verified):
        result["reason"] = "preparation_not_observed_after_writes"
        return result
    if snapshot._overlay_baselines_by_switch:
        result["reason"] = "input_contains_planning_overlays"
        return result
    if any(resource.resource_type not in PREPARATION_TYPES or resource.state not in {"merged", "replaced"} for resource in plan.resources):
        result["reason"] = "unsupported_preparation_scope"
        return result
    known_peers = {}
    for resource in plan.resources:
        known_peers.update(getattr(resource.orchestrator, "_peer_serial_cache", {}))
    serials = set(plan.target_switch_ids)
    # Ordinary port-channels own local members even when their switch belongs
    # to a fabric vPC pair. Only explicit vPC resources require peer inventory;
    # shared topology metadata must not enlarge an unrelated local proof.
    paired_serials = {
        snapshot.fabric_context.get_switch_id(model.switch_ip)
        for resource in plan.resources
        if resource.adapter.ownership_domain == "vpc"
        for model in resource.proposed
    }
    paired_serials.update(known_peers[serial] for serial in tuple(paired_serials) if serial in known_peers)
    serials.update(paired_serials)
    peers = {serial: known_peers[serial] for serial in paired_serials if serial in known_peers}
    if any(not snapshot.has_switch(serial) for serial in serials):
        result["reason"] = "incomplete_clean_switch_observation"
        return result
    # Borrow clean native inventories read-only; do not copy every interface for
    # each target, replan the workflow, or lazily fetch a missing peer here.
    inventories = {serial: snapshot._interfaces_by_switch[serial] for serial in serials}
    try:
        membership = (
            EthernetMembershipIndex(inventories, peer_switch_ids=peers)
            if any(resource.adapter.ownership_domain in {"port_channel", "vpc"} for resource in plan.resources)
            else None
        )
        for resource in plan.resources:
            targets = []
            for desired in resource.proposed:
                serial = snapshot.fabric_context.get_switch_id(desired.switch_ip)
                target = {
                    "switch_id": serial,
                    "interface_name": desired.interface_name,
                    "satisfied": False,
                    "members": [],
                    "raw_routed_residue": False,
                    "switch_revision": snapshot.switch_revision(serial),
                }
                targets.append(target)
                raw = snapshot.cached_interface(serial, desired.interface_name)
                observations = [raw]
                target["observation_revision"] = sha256(json.dumps(observations, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                if raw is None:
                    target["reason"] = "interface_absent"
                    continue
                config, network, policy = _policy(raw)
                target["policy_type"] = policy.get("policyType")
                target["mode"] = config.get("mode")
                expectation = _explicit_member_expectation(plan, resource, desired, serial)
                if expectation is not None:
                    if (
                        raw.get("switchId") != serial
                        or str(raw.get("interfaceName") or "").casefold() != desired.interface_name.casefold()
                        or raw.get("interfaceType") != "ethernet"
                        or network.get("networkOSType") != "nx-os"
                    ):
                        raise ValueError("Explicit Ethernet preparation has an incorrect observed interface identity")
                    target["raw_routed_residue"] = bool(set(policy) & ROUTED_SIBLING_RESET_FIELDS)
                    if target["raw_routed_residue"]:
                        raise ValueError("Explicit Ethernet preparation contains conflicting routed policy fields")
                    _observe_explicit_member(
                        plan=plan,
                        resource=resource,
                        desired=desired,
                        serial=serial,
                        expectation=expectation,
                        membership=membership,
                        peers=peers,
                        snapshot=snapshot,
                        target=target,
                        observations=observations,
                    )
                    continue
                if (
                    raw.get("switchId") != serial
                    or str(raw.get("interfaceName") or "").casefold() != desired.interface_name.casefold()
                    or InterfaceWorkflowPlanner._canonical_interface_type(raw.get("interfaceType")) not in resource.adapter.interface_types
                    or network.get("networkOSType") != "nx-os"
                    or policy.get("policyType") not in resource.adapter.policy_types
                ):
                    target["reason"] = "identity_or_policy_mismatch"
                    continue
                target["raw_routed_residue"] = bool(set(policy) & ROUTED_SIBLING_RESET_FIELDS)
                if target["raw_routed_residue"]:
                    target["reason"] = "conflicting_routed_policy_fields"
                    continue
                current = resource.adapter.model_class.from_response(
                    dict(raw, switchIp=desired.switch_ip, interfaceType=InterfaceWorkflowPlanner._canonical_interface_type(raw.get("interfaceType")))
                )
                candidate = desired if resource.state == "merged" else desired.prepare_for_replacement(current)
                if not current.get_diff(candidate, exclude_unset=resource.state == "merged"):
                    target["reason"] = "desired_configuration_mismatch"
                    continue
                domain = resource.adapter.ownership_domain
                expected = _model_policy(desired)
                slots = _member_slots(domain)
                if domain == "vpc":
                    peer = peers.get(serial)
                    if not peer or peers.get(peer) != serial:
                        target["reason"] = "reciprocal_peer_unavailable"
                        continue
                    peer_raw = snapshot.cached_interface(peer, desired.interface_name)
                    if (
                        peer_raw is None
                        or peer_raw.get("switchId") != peer
                        or str(peer_raw.get("interfaceName") or "").casefold() != desired.interface_name.casefold()
                        or InterfaceWorkflowPlanner._canonical_interface_type(peer_raw.get("interfaceType")) != "vpc"
                        or policy.get("peerSwitchId") not in (None, "", peer)
                        or _policy(peer_raw)[2].get("peerSwitchId") not in (None, "", serial)
                        or EthernetMembershipIndex._vpc_parent_fingerprint(raw) != EthernetMembershipIndex._vpc_parent_fingerprint(peer_raw)
                    ):
                        target["reason"] = "peer_policy_mismatch"
                        continue
                    target["peer_switch_id"] = peer
                    target["peer_switch_revision"] = snapshot.switch_revision(peer)
                    observations.append(peer_raw)
                member_details = []
                target["member_policies"] = member_details
                for number, (model_field, wire_field) in enumerate(slots):
                    actual_members = _names(policy.get(wire_field))
                    requested_members = getattr(expected, model_field, None)
                    expected_members = actual_members if resource.state == "merged" and requested_members is None else _names(requested_members)
                    if expected_members != actual_members:
                        raise ValueError("Prepared aggregate membership differs from desired")
                    member_serial = target.get("peer_switch_id") if domain == "vpc" and number == 1 else serial
                    observed_names = []
                    for name in sorted(actual_members):
                        ownership = membership.validate(member_serial, name)
                        if ownership.owner.interface_name.casefold() != desired.interface_name.casefold():
                            raise ValueError("Prepared member belongs to a different aggregate")
                        if domain == "vpc" and not ownership.pair_validated:
                            raise ValueError("Prepared vPC member lacks pair-wide configuration proof")
                        member_details.append(
                            {
                                "switch_id": member_serial,
                                "interface_name": ownership.member.interface_name,
                                "policy_type": ownership.member.policy_type,
                                "configured_port_channel_id": ownership.configured_port_channel_id,
                            }
                        )
                        observed_names.append(ownership.member.interface_name)
                        observations.append(dict(ownership.member.record))
                    target["members" if number == 0 else "peer_members"] = sorted(observed_names)
                target["observation_revision"] = sha256(json.dumps(observations, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                target["satisfied"] = True
            result["resources"].append(
                {
                    "resource_index": resource.resource_index,
                    "type": resource.resource_type,
                    "state": resource.state,
                    "targets": targets,
                }
            )
        result["observed"] = True
        result["complete"] = True
        result["all_satisfied"] = all(target["satisfied"] for resource in result["resources"] for target in resource["targets"])
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        result["reason"] = "actual_preparation_observation_incomplete"
        result["error_type"] = type(error).__name__
    return result
