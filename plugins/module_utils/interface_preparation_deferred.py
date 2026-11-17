# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# SPDX-License-Identifier: GPL-3.0-or-later

"""Keep already-ready local aggregate membership changes in the final phase."""

from dataclasses import replace
from types import SimpleNamespace

from ansible_collections.cisco.nd.plugins.module_utils.interface_preparation_observation import _names, preparation_observation
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import InterfaceWorkflowValidationError
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection


def _with_ports(model, ports):
    policy = model.config_data.network_os.policy.model_copy(update={"ports": list(ports)})
    network = model.config_data.network_os.model_copy(update={"policy": policy})
    config = model.config_data.model_copy(update={"network_os": network})
    return model.model_copy(update={"config_data": config})


def observation_plan(plan, deferred):
    """Describe explicitly current membership, never future membership equality."""
    resources = []
    for resource in plan.resources:
        proposed = [deferred.get((resource.resource_index, model.get_identifier_value()), {}).get("observation_model", model) for model in resource.proposed]
        resources.append(replace(resource, proposed=NDConfigCollection(resource.adapter.model_class, proposed)))
    return SimpleNamespace(resources=tuple(resources), target_switch_ids=plan.target_switch_ids, changed=plan.changed)


def defer_ready_memberships(*, params, plan, snapshot, request_sha256):
    """Skip whole existing Po updates only when membership is their sole drift.

    The original complete native plan already validates desired member claims.
    Current members are additionally proved from actual cached intent before
    any write. No create, conversion, deletion, vPC retirement or unrelated
    property change gains deferral authority.
    """
    if (params.get("config_actions") or {}).get("deploy", False) or not (params.get("verify") or {}).get("enabled", False):
        raise InterfaceWorkflowValidationError("Deferred membership requires verified staging with deploy=false")
    if getattr(plan, "member_preparations", ()):
        raise InterfaceWorkflowValidationError("Deferred membership cannot share explicit member preparation work")
    deferred, proof_resources = {}, []
    for resource in plan.resources:
        if resource.resource_type not in {"port_channel_access", "port_channel_trunk_host"} or resource.state not in {"merged", "replaced"}:
            continue
        candidates = []
        for model in resource.operations.updates:
            current = resource.before.get(model.get_identifier_value())
            if current is None:
                continue
            old = current.config_data.network_os.policy.ports or []
            future = model.config_data.network_os.policy.ports or []
            if not _names(old) - _names(future):
                continue
            observed = _with_ports(model, old)
            if not current.get_diff(observed):
                continue  # Strict preparation guard still rejects this replacement.
            deferred[resource.resource_index, model.get_identifier_value()] = {
                "observation_model": observed,
                "desired_members": sorted(future),
                "switch_id": snapshot.fabric_context.get_switch_id(model.switch_ip),
                "interface_name": model.interface_name,
            }
            candidates.append(observed)
        if candidates:
            proof_resources.append(replace(resource, proposed=NDConfigCollection(resource.adapter.model_class, candidates)))
    if not deferred:
        return plan, deferred
    scope = tuple({snapshot.fabric_context.get_switch_id(model.switch_ip) for resource in proof_resources for model in resource.proposed})
    proof_plan = SimpleNamespace(resources=tuple(proof_resources), target_switch_ids=scope, changed=False)
    proof = preparation_observation(params=params, plan=proof_plan, snapshot=snapshot, request_sha256=request_sha256, verified=True)
    if not proof.get("observed") or not proof.get("complete") or not proof.get("all_satisfied"):
        raise InterfaceWorkflowValidationError("Existing aggregate current membership cannot establish safe deferred readiness")
    resources, removed_keys = [], set()
    for resource in plan.resources:
        keys = {identifier for index, identifier in deferred if index == resource.resource_index}
        if not keys:
            resources.append(resource)
            continue
        after = NDConfigCollection(
            resource.adapter.model_class,
            [resource.before.get(model.get_identifier_value()) if model.get_identifier_value() in keys else model for model in resource.operations.after],
        )
        updates = tuple(model for model in resource.operations.updates if model.get_identifier_value() not in keys)
        resources.append(replace(resource, operations=replace(resource.operations, updates=updates, after=after)))
        removed_keys.update(
            (resource.resource_index, "update", snapshot.fabric_context.get_switch_id(model.switch_ip), model.interface_name.casefold())
            for model in resource.operations.updates
            if model.get_identifier_value() in keys
        )
    layers = tuple(tuple(operation for operation in layer if operation.key not in removed_keys) for layer in plan.execution_layers)
    return replace(plan, resources=tuple(resources), execution_layers=tuple(layer for layer in layers if layer)), deferred


def annotate_deferred_readiness(proof, deferred):
    """Make current readiness distinct from desired future membership equality."""
    if not deferred:
        return proof
    by_target = {(index, item["switch_id"], item["interface_name"].casefold()): item for (index, _identifier), item in deferred.items()}
    for group in proof["resources"]:
        for target in group["targets"]:
            item = by_target.get((group["resource_index"], target["switch_id"], target["interface_name"].casefold()))
            if item is None:
                continue
            ready = target.get("satisfied") is True
            target.update(
                satisfied=False, ready=ready, disposition="deferred_membership", non_membership_satisfied=ready, desired_members=item["desired_members"]
            )
    proof["all_satisfied"] = all(target.get("satisfied") is True for group in proof["resources"] for target in group["targets"])
    proof["all_ready"] = (
        proof.get("observed") is True
        and proof.get("complete") is True
        and all(target.get("satisfied") is True or target.get("ready") is True for group in proof["resources"] for target in group["targets"])
    )
    return proof
