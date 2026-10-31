# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# SPDX-License-Identifier: GPL-3.0-or-later

"""Reuse the original actual no-op plan, including generated vPC intent."""

from hashlib import sha256
import json
from types import SimpleNamespace

from ansible_collections.cisco.nd.plugins.module_utils.interface_preparation_observation import _policy, preparation_observation
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import InterfaceWorkflowPlanner
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_member_interface import normalize_port_channel_id
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.interface_default_config import ROUTED_SIBLING_RESET_FIELDS


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def actual_noop_upserts(*, params, plan, snapshot, request_sha256, desired_digest):
    """Certify only original zero-mutation plans from their clean raw snapshot.

    The existing planner has already compared every ordinary requested target
    and performed its safety checks. vPC adds exact canonical peer/member and
    generated port-channel checks. No inventory clone, residual plan or request
    is needed; unsupported or incomplete facts preserve ordinary recovery.
    """
    result = {
        "version": 1,
        "source": "native_actual_noop_upserts_v1",
        "safety": "native_original_noop_plan_and_cached_vpc_footprint",
        "observed": False,
        "complete": False,
        "all_satisfied": False,
        "resources": [],
        "request_sha256": request_sha256,
        "desired_digest": desired_digest,
    }
    try:
        if (
            (params.get("config_actions") or {}).get("deploy", False)
            or not (params.get("verify") or {}).get("enabled", False)
            or plan.changed
            or type(plan.mutation_count) is not int
            or plan.mutation_count != 0
            or getattr(plan, "member_preparations", ())
            or not plan.resources
            or snapshot is None
            or snapshot._overlay_baselines_by_switch
        ):
            raise ValueError("Requires an actual original verified staging no-op plan")
        vpc_resources = []
        for resource in plan.resources:
            if (
                resource.state not in {"merged", "replaced"}
                or not list(resource.proposed)
                or resource.transitions
                or resource.operations.creates
                or resource.operations.updates
                or resource.operations.deletes
                or resource.platform_deletes
            ):
                raise ValueError("No-op proof cannot replace mutation or removal recovery")
            if resource.adapter.ownership_domain == "vpc":
                vpc_resources.append(resource)
        if not vpc_resources or any(not snapshot.has_switch(serial) for serial in plan.target_switch_ids):
            raise ValueError("Requires complete clean actual switch observations and vPC intent")

        def raw_record(serial, name, **_kwargs):
            return snapshot._interfaces_by_switch.get(serial, {}).get(name.casefold())

        # Borrow actual rows read-only rather than cloning switch inventories.
        view = SimpleNamespace(
            _interfaces_by_switch=snapshot._interfaces_by_switch,
            _overlay_baselines_by_switch=snapshot._overlay_baselines_by_switch,
            fabric_context=snapshot.fabric_context,
            cached_interface=raw_record,
            has_switch=snapshot.has_switch,
            switch_revision=snapshot.switch_revision,
        )
        vpc_serials = tuple({snapshot.fabric_context.get_switch_id(model.switch_ip) for resource in vpc_resources for model in resource.proposed})
        vpc_plan = SimpleNamespace(resources=tuple(vpc_resources), target_switch_ids=vpc_serials, changed=False)
        paired = preparation_observation(params=params, plan=vpc_plan, snapshot=view, request_sha256=request_sha256, verified=True)
        if not paired.get("observed") or not paired.get("complete") or not paired.get("all_satisfied"):
            raise ValueError("Actual vPC canonical peer/member equality is incomplete")
        pairs = {
            (group["resource_index"], item["switch_id"], item["interface_name"].casefold()): item for group in paired["resources"] for item in group["targets"]
        }
        for resource in plan.resources:
            targets = []
            for desired in resource.proposed:
                serial = snapshot.fabric_context.get_switch_id(desired.switch_ip)
                raw = raw_record(serial, desired.interface_name)
                if (
                    not snapshot.has_switch(serial)
                    or not isinstance(raw, dict)
                    or raw.get("switchId") != serial
                    or str(raw.get("interfaceName") or "").casefold() != desired.interface_name.casefold()
                    or InterfaceWorkflowPlanner._canonical_interface_type(raw.get("interfaceType")) not in resource.adapter.interface_types
                ):
                    raise ValueError("Original no-op target lacks exact raw identity")
                _config, network, policy = _policy(raw)
                if network.get("networkOSType") not in {"nx-os", "ios-xe"} or not isinstance(policy.get("policyType"), str):
                    raise ValueError("Original no-op target lacks configured policy")
                target = {
                    "switch_id": serial,
                    "interface_name": desired.interface_name,
                    "satisfied": True,
                    "residual_actions": [],
                    "raw_observation_sha256": _digest(raw),
                }
                if resource.adapter.ownership_domain == "vpc":
                    pair = dict(pairs[resource.resource_index, serial, desired.interface_name.casefold()])
                    generated = []
                    desired_policy = desired.config_data.network_os.policy
                    for number, owner in ((1, serial), (2, pair["peer_switch_id"])):
                        channel_id = normalize_port_channel_id(getattr(desired_policy, f"peer{number}_port_channel_id", None))
                        if channel_id is None:
                            raise ValueError("Generated vPC identity requires explicit configured channel IDs")
                        name = f"port-channel{channel_id}"
                        local = raw_record(owner, name)
                        if not isinstance(local, dict):
                            raise ValueError("Generated vPC port-channel is absent")
                        config, os_data, local_policy = _policy(local)
                        expected_policy = "accessVpcMember" if pair["mode"] == "access" else "trunkVpcMember"
                        if (
                            not snapshot.has_switch(owner)
                            or local.get("switchId") != owner
                            or str(local.get("interfaceName") or "").casefold() != name
                            or InterfaceWorkflowPlanner._canonical_interface_type(local.get("interfaceType")) != "portChannel"
                            or config.get("mode") != pair["mode"]
                            or os_data.get("networkOSType") != "nx-os"
                            or local_policy.get("policyType") != expected_policy
                            or str(local_policy.get("primaryInterface") or "").casefold() != desired.interface_name.casefold()
                            or normalize_port_channel_id(local_policy.get("portChannelId")) != channel_id
                            or set(local_policy) & ROUTED_SIBLING_RESET_FIELDS
                        ):
                            raise ValueError("Generated vPC port-channel does not match its exact configured owner")
                        fields = ("accessVlan",) if pair["mode"] == "access" else ("allowedVlans", "nativeVlan")
                        if any(str(local_policy.get(field)).casefold() != str(policy.get(field)).casefold() for field in fields):
                            raise ValueError("Generated vPC port-channel VLAN configuration differs from its canonical parent")
                        generated.append(
                            {
                                "switch_id": owner,
                                "interface_name": name,
                                "primary_interface": desired.interface_name,
                                "mode": config["mode"],
                                "policy_type": expected_policy,
                                "configured_port_channel_id": channel_id,
                                "raw_observation_sha256": _digest(local),
                            }
                        )
                    pair["generated_aggregates"] = generated
                    target["vpc"] = pair
                targets.append(target)
            result["resources"].append(
                {"resource_index": resource.resource_index, "type": resource.resource_type, "state": resource.state, "targets": targets}
            )
        result.update(observed=True, complete=True, all_satisfied=True)
    except (AttributeError, KeyError, TypeError, ValueError):
        result["reason"] = "actual_noop_upserts_incomplete"
    return result
