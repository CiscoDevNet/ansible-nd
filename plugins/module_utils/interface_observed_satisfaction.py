# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# SPDX-License-Identifier: GPL-3.0-or-later

"""Optional cache-only proof that an explicitly read-only plan is satisfied.

This is an observation receipt, never an apply/verify receipt. Unsupported or
unclassified observations decline the optimization without rejecting intent.
"""

from collections.abc import Mapping
from hashlib import sha256
import json

from ansible_collections.cisco.nd.plugins.module_utils.interface_family_adapters import INTERFACE_FAMILY_ADAPTERS
from ansible_collections.cisco.nd.plugins.module_utils.interface_membership import EthernetMembershipIndex
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_contract import desired_equality, request_sha256
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_member_interface import (
    get_member_policy_descriptor,
    normalize_port_channel_id,
    parse_member_interface_response,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import EthernetBaseOrchestrator

SAFE_FAMILIES = frozenset(
    {
        "ethernet_access",
        "ethernet_trunk_host",
        "ethernet_routed",
        "loopback",
        "port_channel_access",
        "port_channel_trunk_host",
        "port_channel_routed",
    }
)


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _strict_nested(raw, model, *, policy=False, parent_id=None):
    """Reject unknown config keys even where tolerant read models ignore them."""
    # Exact controller/receipt types are part of the validation contract.
    # pylint: disable=unidiomatic-typecheck
    if not isinstance(raw, Mapping) or not hasattr(type(model), "model_fields"):
        raise ValueError("Unmodeled nested configuration")
    aliases = {field.alias or name: name for name, field in type(model).model_fields.items()}
    defaults = getattr(model, "reverse_diff_defaults", {})
    for key, value in raw.items():
        if key not in aliases:
            if (
                policy
                and key == "portChannelId"
                and parent_id is not None
                and (type(value) is int and value == parent_id or type(value) is str and value in (str(parent_id), f"port-channel{parent_id}"))
            ):
                continue  # Exact native name/config ownership equality checked below.
            if policy and key == "ptp" and (value is False or type(value) is str and value == "false"):
                continue  # Qualified NX-OS inactive default echo only.
            if key in defaults and type(value) is type(defaults[key]) and value == defaults[key]:
                continue
            raise ValueError(f"Unclassified configuration field {type(model).__name__}.{key}")
        parsed = getattr(model, aliases[key])
        if isinstance(value, Mapping):
            _strict_nested(value, parsed, policy=key == "policy", parent_id=parent_id)
        elif isinstance(value, list):
            if not isinstance(parsed, list) or len(value) != len(parsed):
                raise ValueError("Unclassified nested list")
            for item, parsed_item in zip(value, parsed):
                if isinstance(item, Mapping):
                    _strict_nested(item, parsed_item)
                elif isinstance(item, list):
                    raise ValueError("Unqualified nested list")


def _strict_current(raw, adapter, context, *, parent_id=None):
    if raw.get("primaryInterface") not in (None, ""):
        raise ValueError("Unqualified top-level owner")
    enriched = dict(raw, switchIp=context.get_switch_ip(raw["switchId"]))
    model = adapter.model_class.from_response(enriched)
    _strict_nested(raw.get("configData"), model.config_data, parent_id=parent_id)


def _strict_member(raw):
    if raw.get("primaryInterface") not in (None, ""):
        raise ValueError("Unqualified member envelope owner")
    return parse_member_interface_response(raw)


def _strict_parent(raw, adapter, context, membership):
    # Exact controller/receipt types are part of the validation contract.
    # pylint: disable=unidiomatic-typecheck
    policy = raw["configData"]["networkOS"]["policy"]
    parent_id = None
    if "portChannelId" in policy:
        parent_id = normalize_port_channel_id(raw["interfaceName"])
        value = policy["portChannelId"]
        if (
            parent_id is None
            or normalize_port_channel_id(value) != parent_id
            or not (type(value) is int and value == parent_id or type(value) is str and value in (str(parent_id), f"port-channel{parent_id}"))
        ):
            raise ValueError("Parent configured channel ID differs from exact native name")
    _strict_current(raw, adapter, context, parent_id=parent_id)
    ports = EthernetMembershipIndex._valid_vpc_member_names(policy.get("ports"))
    if ports is None:
        raise ValueError("Incomplete aggregate member footprint")
    for port in ports:
        owner = membership.validate(raw["switchId"], port)
        if (
            owner.peer_owner is not None
            or owner.owner.switch_id != raw["switchId"]
            or owner.owner.interface_name.casefold() != raw["interfaceName"].casefold()
        ):
            raise ValueError("Aggregate member has a different observed owner")
        _strict_member(owner.member.record)


def observed_satisfaction(*, params, plan, snapshot, rest_send_factory, check_mode):
    """Return a complete no-op proof only from actual cached raw observations."""
    # Exact controller/receipt types are part of the validation contract.
    # pylint: disable=unidiomatic-typecheck
    proof = {
        "version": 1,
        "source": "native_read_only_preplan",
        "check_mode": bool(check_mode),
        "deploy": bool((params.get("config_actions") or {}).get("deploy", False)),
        "verify_enabled": bool((params.get("verify") or {}).get("enabled", False)),
        "request_sha256": request_sha256(params),
        "observed": True,
        "complete": False,
        "all_satisfied": False,
        "resources": [],
    }
    try:
        if not check_mode or proof["deploy"] or proof["verify_enabled"]:
            raise ValueError("Requires explicitly read-only preplan semantics")
        if plan.changed or plan.mutation_count != 0:
            raise ValueError("Plan contains a mutation")
        if snapshot is None or snapshot._overlay_baselines_by_switch:
            raise ValueError("Actual complete snapshot required, without planning overlays")
        if not plan.resources:
            raise ValueError("Nonempty exact resources required")
        raw_inventory = snapshot.clean_interfaces_by_switch
        context = snapshot.fabric_context
        membership = None
        parents_checked = set()
        raw_proofs = {}
        by_policy = {
            policy: adapter for adapter in INTERFACE_FAMILY_ADAPTERS.values() if adapter.resource_type in SAFE_FAMILIES for policy in adapter.policy_types
        }
        for resource in plan.resources:
            if resource.resource_type not in SAFE_FAMILIES or resource.state not in {"merged", "replaced", "deleted"}:
                raise ValueError("Unqualified family or state")
            if resource.transitions:
                raise ValueError("Policy transition is not a satisfied no-op")
            if resource.state == "deleted" and resource.adapter.ownership_domain != "ethernet":
                raise ValueError("Logical deletion retains ordinary readback and absence waits")
            models = [*resource.proposed, *resource.operations.deletes, *resource.platform_deletes]
            if not models:
                raise ValueError("Exact explicit target models required")
            for model in models:
                serial, name = context.get_switch_id(model.switch_ip), model.interface_name.casefold()
                if not snapshot.has_switch(serial):
                    raise ValueError("Target inventory is not complete")
                raw = raw_inventory.get(serial, {}).get(name)
                if not isinstance(raw, dict) or raw.get("switchId") != serial or str(raw.get("interfaceName") or "").casefold() != name:
                    raise ValueError("Exact currently observed target required")
                config = raw.get("configData") or {}
                network = config.get("networkOS") or {}
                policy = network.get("policy") or {}
                if network.get("networkOSType") != "nx-os":
                    raise ValueError("Initial proof qualifies NX-OS only")
                if raw.get("primaryInterface") not in (None, ""):
                    raise ValueError("Unqualified top-level owner")
                descriptor = get_member_policy_descriptor(policy.get("policyType"))
                if membership is None:
                    membership = EthernetMembershipIndex(raw_inventory)
                if raw.get("interfaceType") == "ethernet" and descriptor is None:
                    operational = raw.get("operData")
                    if operational is not None and not isinstance(operational, dict):
                        raise ValueError("Malformed physical operational envelope")
                    channel = (operational or {}).get("portChannelId")
                    if not (channel is None or type(channel) is int and channel in (-1, 0) or type(channel) is str and channel in ("-1", "0")):
                        raise ValueError("Standalone proof cannot accept operational membership")
                    if membership.claiming_parents(serial, name):
                        raise ValueError("Standalone target remains claimed by a parent")
                if resource.state == "deleted":
                    if (
                        not EthernetBaseOrchestrator._is_absent_delete_reset_target(raw)
                        or policy.get("adminState") is not True
                        or policy.get("mtu") != "jumbo"
                        or policy.get("extraConfig") not in (None, "")
                    ):
                        raise ValueError("Physical deletion is not an exact already-reset target")
                else:
                    if descriptor is not None:
                        if descriptor.pair_aware:
                            raise ValueError("vPC generated ownership is not qualified")
                        _strict_member(raw)
                        owner = membership.validate(serial, name)
                        parent_adapter = by_policy.get(owner.owner.policy_type)
                        if parent_adapter is None:
                            raise ValueError("Unknown parent ownership family")
                        parent_key = owner.owner.switch_id, owner.owner.interface_name.casefold()
                        if parent_key not in parents_checked:
                            _strict_parent(owner.owner.record, parent_adapter, context, membership)
                            parents_checked.add(parent_key)
                    else:
                        if resource.resource_type.startswith("port_channel_"):
                            if (serial, name) not in parents_checked:
                                _strict_parent(raw, resource.adapter, context, membership)
                                parents_checked.add((serial, name))
                        else:
                            _strict_current(raw, resource.adapter, context)
                raw_proofs[(serial, name)] = _digest(raw)
        equality = desired_equality(params=params, plan=plan, snapshot=snapshot, rest_send_factory=rest_send_factory, _physical_defaults=True)
        if equality.get("complete") is not True or equality.get("all_satisfied") is not True:
            proof["residual_reason"] = equality.get("reason")
            proof["residual_error_type"] = equality.get("error_type")
            raise ValueError("Native residual equality is incomplete or unsatisfied")
        for resource in equality["resources"]:
            for target in resource["targets"]:
                target["raw_observation_sha256"] = raw_proofs[(target["switch_id"], target["interface_name"].casefold())]
        proof.update(
            complete=True,
            all_satisfied=True,
            resources=equality["resources"],
            snapshot_sha256=_digest(raw_inventory),
            safety="native_planner_and_strict_raw_cached_residual_equality",
        )
    except Exception as exc:
        proof["reason"] = str(exc)
        proof["error_type"] = type(exc).__name__
    return proof
