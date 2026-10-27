# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Opt-in workflow receipts and cache-only desired-equality observations."""

from copy import copy, deepcopy
from hashlib import sha256
import json
from types import SimpleNamespace

from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import InterfaceStateSnapshot
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import InterfaceWorkflowPlanner

CONTRACT_VERSION = 1
CAPABILITIES = (
    "no_mutation_receipt_v1",
    "desired_equality_v1",
    "member_batching_switch_policy_v1",
    "member_batching_policy_v1",
    "member_batching_mixed_v1",
    "observed_noop_preplan_v1",
    "staged_deletions_v1",
)
# NaC checks these names from the selected base collection before passing a
# new module argument. Older collections can safely retain their old path.
EXECUTION_CONTRACT_VERSION = CONTRACT_VERSION
EXECUTION_CONTRACT_CAPABILITIES = frozenset(CAPABILITIES)


def workflow_options(params):
    supplied = params.get("execution_options") or {}
    options = {
        "contract_version": supplied.get("contract_version", CONTRACT_VERSION),
        "desired_equality": supplied.get("desired_equality", False),
        "member_batching": supplied.get("member_batching", "disabled"),
    }
    if supplied.get("observed_satisfaction") is True:
        options["observed_satisfaction"] = True
    return options


def _without_omit_placeholders(value):
    if isinstance(value, dict):
        return {key: _without_omit_placeholders(item) for key, item in value.items() if not (isinstance(item, str) and "__omit_place_holder__" in item)}
    if isinstance(value, list):
        return [_without_omit_placeholders(item) for item in value]
    return value


def request_projection(params):
    """Exact public intent and execution semantics, excluding diagnostics."""
    return {
        "fabric_name": params.get("fabric_name"),
        "resources": _without_omit_placeholders(params.get("resources") or []),
        "config_actions": {"deploy": bool((params.get("config_actions") or {}).get("deploy", False))},
        "verify": {"enabled": bool((params.get("verify") or {}).get("enabled", False))},
        "execution_options": workflow_options(params),
    }


def request_sha256(params):
    return sha256(
        json.dumps(request_projection(params), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    ).hexdigest()


def workflow_contract(params):
    desired = {"fabric_name": params.get("fabric_name"), "resources": params.get("resources") or []}
    return {
        "version": CONTRACT_VERSION,
        "capabilities": list(CAPABILITIES),
        "requested_options": workflow_options(params),
        "request_sha256": request_sha256(params),
        "desired_digest": sha256(json.dumps(desired, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    }


def write_receipt(senders, *, params=None):
    mutations = sum(sender.mutation_attempt_count for sender in senders)
    deployments = sum(sender.deployment_attempt_count for sender in senders)
    return {
        "version": CONTRACT_VERSION,
        "no_mutation_attempted": mutations == 0 and deployments == 0,
        "mutation_attempts": mutations,
        "deploy_attempts": deployments,
        "request_sha256": request_sha256(params) if params is not None else None,
    }


class UncachedObservation(RuntimeError):
    """A proof cannot replace another observer without an additional read."""


def desired_equality(*, params, plan, snapshot, rest_send_factory, _physical_defaults=False):
    """Replan only a detached copy of freshly observed complete inventories.

    Transport is forbidden here. Desired planning projections never modify the
    original observed snapshot. Unsupported/incomplete proof retains readback.
    """
    result = {
        "version": CONTRACT_VERSION,
        "observed": True,
        "complete": False,
        "all_satisfied": False,
        "resources": [],
        "request_sha256": request_sha256(params),
        "desired_digest": workflow_contract(params)["desired_digest"],
    }
    if snapshot is None:
        result["reason"] = "no_observed_snapshot"
        return result
    if snapshot._overlay_baselines_by_switch:
        result["reason"] = "input_contains_planning_overlays"
        return result
    # Pair-aware generated footprints need separate qualification before NaC
    # may use this proof to replace its existing readback and recovery guards.
    if any(resource.adapter.ownership_domain == "vpc" for resource in plan.resources):
        result["reason"] = "vpc_generated_footprint_not_qualified"
        return result
    if any(
        resource.state in {"deleted", "overridden"}
        and not (_physical_defaults and resource.state == "deleted" and resource.adapter.ownership_domain == "ethernet")
        for resource in plan.resources
    ):
        result["reason"] = "removal_proof_retains_targeted_recovery"
        return result

    def blocked(*args, **kwargs):
        raise UncachedObservation("Desired equality requires an uncached observation")

    def frozen_sender(values):
        sender = rest_send_factory(values)
        sender.commit = blocked
        return sender

    def frozen_context(context):
        context = copy(context)
        context._rest_send = frozen_sender({"fabric_name": plan.fabric_name, "check_mode": True})
        return context

    context = frozen_context(snapshot.fabric_context)
    observed = InterfaceStateSnapshot(fabric_name=plan.fabric_name, fabric_context=context, request=blocked)
    observed._interfaces_by_switch = deepcopy(snapshot.clean_interfaces_by_switch)
    observed._original_interfaces_by_switch = deepcopy(observed._interfaces_by_switch)
    observed._revisions_by_switch = dict(snapshot._revisions_by_switch)
    observed._interface_summaries_by_switch = deepcopy(snapshot._interface_summaries_by_switch)
    observed._topology_context = frozen_context(snapshot._topology_context) if snapshot._topology_context is not None else None
    observed._topology_pairs = deepcopy(snapshot._topology_pairs)
    observed._topology_generation = snapshot.topology_generation
    observed_inventory = deepcopy(observed.clean_interfaces_by_switch)
    # Keep the public input shape: Ethernet adapters require interface_names,
    # whereas model serialization uses the internal singular interface_name.
    resources = deepcopy(params.get("resources") or [])
    planner = InterfaceWorkflowPlanner(snapshot=observed, rest_send_factory=frozen_sender, run_capability_preflight=False)
    links = None
    ethernet_owner = None
    for resource in plan.resources:
        owner = resource.orchestrator
        while getattr(owner, "_fabric_link_cache_provider", None) is not None:
            owner = owner._fabric_link_cache_provider
        if resource.adapter.ownership_domain == "ethernet" and ethernet_owner is None:
            ethernet_owner = owner
        if getattr(owner, "_fabric_link_endpoints_cache", None) is not None and links is None:
            links = deepcopy(owner._fabric_link_endpoints_cache)

    def frozen_links():
        if links is None:
            return blocked()
        return deepcopy(links)

    planner._ethernet_link_cache_owner = SimpleNamespace(_fabric_link_endpoints=frozen_links)
    physical_removals = _physical_defaults and any(
        resource.state == "deleted" and resource.adapter.ownership_domain == "ethernet" for resource in plan.resources
    )
    if physical_removals:
        # The original read-only preplan already performed these preview reads.
        # Clone its typed provider and actual cache, bound to the same unmodified
        # snapshot epoch. Never invent an empty preview or fetch missing data.
        preview = getattr(ethernet_owner, "_reset_negotiation_fabric_preview", None)
        if (
            ethernet_owner is None
            or ethernet_owner.state_snapshot is not snapshot
            or not isinstance(preview, dict)
            or not preview
            or any(
                not isinstance(serial, str)
                or not serial
                or serial != serial.strip()
                or not isinstance(row, dict)
                or row.get("switchId") != serial
                or row.get("status") not in {"inSync", "outOfSync"}
                or any(
                    not isinstance(row.get(field), list) or any(not isinstance(line, str) for line in row[field])
                    for field in ("runningConfigs", "pendingConfigs", "expectedConfigs")
                )
                for serial, row in preview.items()
            )
        ):
            result["reason"] = "cached_reset_preview_unavailable_or_unqualified"
            return result
        frozen_owner = copy(ethernet_owner)
        frozen_owner.rest_send = frozen_sender({"fabric_name": plan.fabric_name, "check_mode": True})
        frozen_owner.results = None
        frozen_owner._fabric_context = context
        frozen_owner.interface_state_snapshot = observed
        frozen_owner._fabric_link_cache_provider = None
        frozen_owner._reset_negotiation_preview_cache_provider = None
        for attribute in (
            "_fabric_link_endpoints_cache",
            "_reset_negotiation_fabric_preview",
            "_reset_negotiation_fabric_blocks",
            "_reset_negotiation_interface_preview",
            "_reset_negotiation_preview_markers",
            "_reset_negotiation_preview_scope",
            "_reset_negotiation_preview_epoch",
        ):
            setattr(frozen_owner, attribute, deepcopy(getattr(ethernet_owner, attribute)))
        planner._ethernet_link_cache_owner = frozen_owner
    try:
        residual = planner.plan(resources)
        residual_by_resource = {}
        for resource in residual.resources:
            actions = {}
            for action, model in planner._iter_operations(resource):
                key = context.get_switch_id(model.switch_ip), model.interface_name.casefold()
                actions.setdefault(key, []).append(action)
            for transition in resource.transitions:
                key = transition.switch_id, transition.interface_name.casefold()
                actions.setdefault(key, []).append("transition")
            residual_by_resource[resource.resource_index] = actions
        for resource in plan.resources:
            targets = {}
            models = [*resource.proposed, *resource.operations.deletes, *resource.platform_deletes]
            for model in models:
                serial, name = context.get_switch_id(model.switch_ip), model.interface_name
                key = serial, name.casefold()
                if key in targets:
                    continue
                if not observed.has_switch(serial):
                    raise UncachedObservation("An exact target lacks complete observed inventory")
                raw = observed_inventory.get(serial, {}).get(name.casefold())
                identity_observed = (
                    raw is None
                    if resource.state == "deleted"
                    else (isinstance(raw, dict) and raw.get("switchId") == serial and str(raw.get("interfaceName") or "").casefold() == name.casefold())
                )
                # Physical deletion means a proved reset rather than absence.
                if resource.state == "deleted" and resource.adapter.ownership_domain == "ethernet":
                    identity_observed = isinstance(raw, dict) and raw.get("switchId") == serial
                actions = residual_by_resource.get(resource.resource_index, {}).get(key, [])
                targets[key] = {"switch_id": serial, "interface_name": name, "satisfied": identity_observed and not actions, "residual_actions": actions}
            result["resources"].append(
                {"resource_index": resource.resource_index, "type": resource.resource_type, "state": resource.state, "targets": list(targets.values())}
            )
        result["complete"] = True
        result["all_satisfied"] = residual.mutation_count == 0 and all(
            target["satisfied"] for resource in result["resources"] for target in resource["targets"]
        )
    except Exception as exc:
        result["reason"] = "cached_observation_incomplete"
        result["error_type"] = type(exc).__name__
    return result
