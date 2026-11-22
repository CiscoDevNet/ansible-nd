# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Explicit, guarded inventory preparation for newly named aggregate members.

The caller explicitly requests both Ethernet and aggregate resources. This helper
does not classify switches or invent Ethernet intent from aggregate member names.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import (
    FabricContext,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_family_adapters import (
    InterfaceWorkflowValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_membership import (
    EthernetMembershipIndex,
    get_member_policy_descriptor_for_parent,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_member_interface import (
    normalize_port_channel_id,
)

_FAMILIES = {
    "access": ("ethernet_access", "accessHost", "access"),
    "trunk": ("ethernet_trunk_host", "trunkHost", "trunk"),
    "routed": ("ethernet_routed", "routedHost", "routed"),
}


def _policy(record: Mapping[str, Any]) -> dict[str, Any]:
    config = record.get("configData")
    network = config.get("networkOS") if isinstance(config, dict) else None
    policy = network.get("policy") if isinstance(network, dict) else None
    if not isinstance(policy, dict):
        raise RuntimeError("Missing-member preparation requires a valid policy envelope.")
    return policy


def _check_metadata(context: FabricContext, switch_id: str) -> None:
    """Require fresh, positive scoped NX-OS identity, not a placeholder guess."""
    context.validate_for_mutation()
    records = [row for row in context.switches if isinstance(row, dict) and row.get("switchId") == switch_id]
    if len(records) != 1 or switch_id not in context.switch_map_by_id:
        raise RuntimeError(f"Missing-member preparation cannot prove exact fabric membership for {switch_id!r}.")
    record = records[0]
    additional = record.get("additionalData")
    if record.get("fabricName") != context.fabric_name or not isinstance(additional, dict) or additional.get("platformType") != "nx-os":
        raise RuntimeError(f"Missing-member preparation requires positive NX-OS fabric identity for {switch_id!r}.")


def _unowned_inventory_indexes(inventories: Any, index: EthernetMembershipIndex, target_ids: set[str], peer_ids: dict[str, str]):
    """Precompute scoped children and parent claims from one fresh inventory."""
    children, claims = set(), set()
    scope = target_ids | {peer_ids[switch_id] for switch_id in target_ids if switch_id in peer_ids}
    for owner_id in scope:
        for record in inventories[owner_id].values():
            record_name = str(record.get("interfaceName") or "").casefold()
            if owner_id in target_ids and record.get("interfaceType") == "subInterface":
                children.add((owner_id, record_name.rsplit(".", 1)[0]))
            if owner_id not in target_ids and record.get("interfaceType") != "vpc":
                continue
            config = record.get("configData")
            if not isinstance(config, dict) or not config.get("networkOS"):
                continue
            policy = _policy(record)
            memberships = {}
            for field in ("ports", "peer1MemberPorts", "peer2MemberPorts"):
                if field not in policy:
                    continue
                names = EthernetMembershipIndex._valid_vpc_member_names(policy[field])
                if names is None:
                    raise RuntimeError("Missing-member preparation refuses malformed parent membership lists.")
                memberships[field] = names
            if record.get("interfaceType") == "vpc":
                expected_peer = peer_ids.get(owner_id)
                declared_peer = policy.get("peerSwitchId")
                if expected_peer is None or declared_peer not in (None, "", expected_peer):
                    raise RuntimeError("Missing-member preparation refuses unresolved or conflicting parent peer identity.")
                # The index resolves pair-wide and local-first parent echoes
                # against actual switch-scoped members. An unproved orientation
                # deliberately keeps both slots, retaining conflicting evidence.
                fields = index._local_vpc_parent_member_fields(owner_id, record_name, policy)
                remote_fields = tuple(field for field in ("peer1MemberPorts", "peer2MemberPorts") if field not in fields)
                if len(fields) != 1:
                    remote_fields = ("peer1MemberPorts", "peer2MemberPorts")
                for field in remote_fields:
                    claims.update((expected_peer, name) for name in memberships.get(field, ()))
                fields = (*fields, "ports")
            else:
                fields = tuple(memberships)
            for field in fields:
                claims.update((owner_id, name) for name in memberships.get(field, ()))
    return children, claims


def _phase_links(orchestrator: Any, links: dict[int, Any]):
    """Reuse a provider's link evidence only inside this fresh validation call."""
    provider = getattr(orchestrator, "_fabric_link_cache_provider", None) or orchestrator
    key = id(provider)
    if key not in links:
        links[key] = orchestrator._fabric_link_endpoints()
    return links[key]


def _check_unowned(preparation: Any, index: EthernetMembershipIndex, children: Any, claims: Any, links: dict[int, Any]) -> None:
    """Refuse local/peer parent claims, child interfaces and fabric link intent."""
    switch_id, name = preparation.switch_id, preparation.interface_name.casefold()
    if index.get_member(switch_id, name) is not None or index.claiming_parents(switch_id, name):
        raise RuntimeError(f"Missing-member preparation refuses existing aggregate ownership for {switch_id}/{name}.")
    if (switch_id, name) in children:
        raise RuntimeError(f"Missing-member preparation refuses existing child interfaces for {switch_id}/{name}.")
    if (switch_id, name) in claims:
        raise RuntimeError(f"Missing-member preparation refuses a local or reciprocal parent claim for {switch_id}/{name}.")
    if (switch_id, name) in _phase_links(preparation.orchestrator, links):
        raise RuntimeError(f"Missing-member preparation refuses fabric-link endpoint {switch_id}/{name}.")


def _merge_peer_identity(peers: dict[str, str], switch_id: str, peer_id: str) -> None:
    previous = peers.get(switch_id)
    if previous is not None and previous != peer_id:
        raise RuntimeError("Missing-member preparation refuses conflicting reciprocal pair identities.")
    peers[switch_id] = peer_id


def _fresh_preparation_scope(preparations: Any, snapshot: Any):
    """Validate each distinct target/provider once and combine exact pair scope."""
    refresh_ids = {item.switch_id for item in preparations}
    checked_pairs, checked_metadata, orchestrators, peers = set(), set(), {}, {}
    for item in preparations:
        orchestrator = item.orchestrator
        orchestrators[id(orchestrator)] = orchestrator
        if orchestrator.deploy:
            raise RuntimeError("Missing-member preparation requires deployment disabled.")
        pair_key = id(orchestrator), item.switch_id
        if pair_key in checked_pairs:
            continue
        checked_pairs.add(pair_key)
        context = snapshot.topology_context(
            lambda orchestrator=orchestrator: FabricContext(rest_send=orchestrator.rest_send, fabric_name=snapshot.fabric_name)
        )
        if (id(context), item.switch_id) not in checked_metadata:
            _check_metadata(context, item.switch_id)
            checked_metadata.add((id(context), item.switch_id))
        peer_id = orchestrator._load_staged_detachment_peer(item.switch_id, load_peer_inventory=False)
        if peer_id is not None:
            if (id(context), peer_id) not in checked_metadata:
                _check_metadata(context, peer_id)
                checked_metadata.add((id(context), peer_id))
            refresh_ids.add(peer_id)
            _merge_peer_identity(peers, item.switch_id, peer_id)
            _merge_peer_identity(peers, peer_id, item.switch_id)
    for orchestrator in orchestrators.values():
        for switch_id, peer_id in orchestrator._member_peer_serial_cache.items():
            _merge_peer_identity(peers, switch_id, peer_id)
    return refresh_ids, peers, tuple(orchestrators.values())


def _check_prepared(preparation: Any, record: Any) -> None:
    if not isinstance(record, dict):
        raise RuntimeError("Prepared missing member is absent from fresh controller inventory.")
    config = record.get("configData")
    network = config.get("networkOS") if isinstance(config, dict) else None
    policy = _policy(record)
    descriptor = get_member_policy_descriptor_for_parent(preparation.parent_policy_type)
    if (
        descriptor is None
        or record.get("interfaceType") != "ethernet"
        or str(record.get("interfaceName") or "").casefold() != preparation.interface_name.casefold()
        or record.get("switchId") not in (None, preparation.switch_id)
        or not isinstance(network, dict)
        or network.get("networkOSType") != "nx-os"
        or config.get("mode") != descriptor.wire_mode
        or policy.get("policyType") != preparation.to_policy_type
    ):
        raise RuntimeError("Prepared missing member has an unexpected identity, host policy or mode.")
    for values in (config, policy):
        if any(values.get(key) not in (None, "") for key in ("primaryInterface", "portChannelId")):
            raise RuntimeError("Prepared missing member unexpectedly declares aggregate ownership.")
    oper = record.get("operData")
    if oper is not None:
        if not isinstance(oper, dict):
            raise RuntimeError("Prepared missing member has malformed operational evidence.")
        oper_id = oper.get("portChannelId")
        # Exact JSON integer evidence rejects False, which otherwise equals zero.
        if oper_id is not None and (type(oper_id) is not int or oper_id not in (-1, 0)):  # pylint: disable=unidiomatic-typecheck
            raise RuntimeError("Prepared missing member has positive or ambiguous operational membership.")
    desired_policy = preparation.model.to_payload()["configData"]["networkOS"]["policy"]
    policy_class = type(preparation.model.config_data.network_os.policy)
    actual_model = policy_class.from_response(policy)
    expected_model = policy_class.from_response(desired_policy)
    for field in expected_model.model_fields_set:
        alias = policy_class.model_fields[field].alias or field
        expected = getattr(expected_model, field)
        if alias not in policy or getattr(actual_model, field) != expected or (isinstance(expected, bool) and not isinstance(policy[alias], bool)):
            raise RuntimeError(f"Prepared missing member readback differs for minimum host field {alias!r}.")


def refresh_missing_preparations(preparations: Any, snapshot: Any, phase: str = "absent") -> tuple[dict[str, Any], ...]:
    """Prove fresh absence, prepared host mode, or exact resulting ownership.

    No writes occur here. Every call drops topology evidence and refreshes the
    complete target/reciprocal inventories before considering cached absence.
    """
    if phase not in {"absent", "prepared", "member"}:
        raise ValueError(f"Unknown missing-member preparation phase {phase!r}.")
    preparations = tuple(preparations)
    if not preparations:
        return ()
    keys = [(item.switch_id, item.interface_name.casefold()) for item in preparations]
    if len(set(keys)) != len(keys) or any(
        item.kind not in {"missing_inventory", "explicit_host_conversion"} or item.orchestrator is None for item in preparations
    ):
        raise RuntimeError("Missing-member preparation requires unique exact auxiliary receipts.")
    snapshot.invalidate_topology_evidence()
    refresh_ids, peer_ids, orchestrators = _fresh_preparation_scope(preparations, snapshot)
    snapshot.refresh(sorted(refresh_ids))
    if not all(snapshot.has_switch(switch_id) for switch_id in refresh_ids):
        raise RuntimeError("Missing-member preparation requires complete reciprocal inventories.")
    inventories = snapshot.clean_interfaces_by_switch
    index = EthernetMembershipIndex(inventories, peer_switch_ids=peer_ids)
    children, claims = _unowned_inventory_indexes(inventories, index, {item.switch_id for item in preparations}, peer_ids) if phase != "member" else ((), ())
    links, observed = {}, []
    for orchestrator in orchestrators:
        orchestrator._membership_index_cache = None
        orchestrator._membership_index_inventory_switches = frozenset()
    for item in preparations:
        orchestrator = item.orchestrator
        record = snapshot.cached_interface(item.switch_id, item.interface_name)
        if phase == "member":
            ownership = index.validate(item.switch_id, item.interface_name)
            if (
                ownership.member.policy_type != item.expected_member_policy
                or ownership.owner.interface_name.casefold() != item.parent_name.casefold()
                or ownership.owner.switch_id != item.switch_id
                or ownership.owner.policy_type != item.parent_policy_type
                or ownership.owner.port_channel_id != item.parent_port_channel_id
                or ownership.configured_port_channel_id != item.parent_port_channel_id
            ):
                raise RuntimeError("Prepared missing member has unexpected member policy or aggregate ownership after parent staging.")
            if (
                item.switch_id,
                item.interface_name.casefold(),
            ) in _phase_links(orchestrator, links):
                raise RuntimeError("Prepared missing member became a fabric-link endpoint.")
            observed.append(
                {
                    "resource_index": item.resource_index,
                    "type": item.resource_type,
                    "switch_id": item.switch_id,
                    "switch_ip": item.model.switch_ip,
                    "interface_name": item.interface_name,
                    "parent_resource_index": item.parent_resource_index,
                    "parent_switch_id": item.parent_switch_id,
                    "parent_interface_name": ownership.owner.interface_name,
                    "parent_policy_type": ownership.owner.policy_type,
                    "owner_switch_id": ownership.owner.switch_id,
                    "configured_port_channel_id": ownership.configured_port_channel_id,
                    "policy_type": ownership.member.policy_type,
                    "pair_validated": ownership.pair_validated,
                }
            )
            continue
        _check_unowned(item, index, children, claims, links)
        if phase == "absent":
            if item.kind == "missing_inventory":
                if record is not None:
                    raise RuntimeError("Missing-member preparation target appeared after planning; refusing stale absence.")
            else:
                shapes = {"accessHost": "access", "trunkHost": "trunk", "routedHost": "routed"}
                config = record.get("configData") if isinstance(record, Mapping) else None
                network = config.get("networkOS") if isinstance(config, Mapping) else None
                policy = network.get("policy") if isinstance(network, Mapping) else None
                if (
                    not isinstance(record, Mapping)
                    or record.get("interfaceType") != "ethernet"
                    or record.get("switchId") not in (None, item.switch_id)
                    or record.get("configData") != item.current.get("configData")
                    or not isinstance(policy, Mapping)
                    or policy.get("policyType") != item.from_policy_type
                    or item.from_policy_type not in shapes
                    or config.get("mode") != shapes[item.from_policy_type]
                    or network.get("networkOSType") != "nx-os"
                ):
                    raise RuntimeError("Explicit member host source changed or is not a supported unowned NX-OS host.")
                for values in (config, policy):
                    if any(values.get(key) not in (None, "") for key in ("primaryInterface", "portChannelId")):
                        raise RuntimeError("Explicit member host source unexpectedly declares aggregate ownership.")
                oper = record.get("operData")
                # Membership IDs require exact integers, including rejection of boolean aliases.
                if (
                    not isinstance(oper, Mapping)
                    or type(oper.get("portChannelId")) is not int  # pylint: disable=unidiomatic-typecheck
                    or oper["portChannelId"] not in (-1, 0)
                ):
                    raise RuntimeError("Explicit member host source has positive or ambiguous operational membership.")
        else:
            _check_prepared(item, record)
    return tuple(observed)


def _parent_id(planner: Any, claim: Any) -> int:
    descriptor = get_member_policy_descriptor_for_parent(planner._desired_policy_type(claim.parent))
    primary_id = planner.fabric_context.get_switch_id(claim.parent.switch_ip)
    if descriptor.pair_aware:
        field = "peer1_port_channel_id" if claim.member_identity.scope[0] == primary_id else "peer2_port_channel_id"
        value = getattr(planner._policy(claim.parent), field, None)
    else:
        value = claim.parent.interface_name
    result = normalize_port_channel_id(value)
    if result is None:
        raise InterfaceWorkflowValidationError("Missing-member preparation cannot resolve the exact parent port-channel ID.")
    return result


def _explicit_claims(planner: Any, resources: Any):
    """Bind explicit Ethernet requests to explicit complete aggregate membership."""
    resources = tuple(resources)
    if not any(resource.adapter.ownership_domain == "ethernet" and resource.state not in {"deleted", "gathered"} for resource in resources):
        return []
    explicit, claims = defaultdict(list), defaultdict(list)
    for resource in resources:
        if resource.adapter.ownership_domain == "ethernet" and resource.state not in {"deleted", "gathered"}:
            for model in resource.proposed:
                identity = planner._identity(resource.adapter, model)
                explicit[(identity.scope[0], identity.interface_name.casefold())].append((resource, model))
        if resource.adapter.ownership_domain not in {"port_channel", "vpc"} or resource.state not in {"merged", "replaced"}:
            continue
        actions = {model.get_identifier_value(): action for action, model in planner._iter_operations(resource)}
        for parent in resource.proposed:
            parent_policy = planner._desired_policy_type(parent)
            descriptor = get_member_policy_descriptor_for_parent(parent_policy)
            if descriptor is None or descriptor.network_os != "nx-os" or descriptor.family not in _FAMILIES:
                continue
            primary_id = planner.fabric_context.get_switch_id(parent.switch_ip)
            policy = planner._policy(parent)
            if descriptor.pair_aware:
                peers = [sid for sid in planner._vpc_pair_scope(parent.switch_ip) if sid != primary_id]
                if len(peers) != 1:
                    raise InterfaceWorkflowValidationError("Explicit member preparation requires one exact reciprocal vPC peer.")
                slots = ((primary_id, policy.peer1_member_ports), (peers[0], policy.peer2_member_ports))
            else:
                slots = ((primary_id, getattr(policy, "ports", None)),)
            for switch_id, names in slots:
                for name in planner._member_names(names):
                    claims[(switch_id, name.casefold())].append(
                        SimpleNamespace(
                            resource=resource,
                            parent=parent,
                            action=actions.get(parent.get_identifier_value(), "noop"),
                            member_identity=SimpleNamespace(scope=(switch_id,), interface_name=name.casefold()),
                            descriptor=descriptor,
                        )
                    )
    for key in explicit.keys() & claims.keys():
        if len(explicit[key]) != 1 or len(claims[key]) != 1:
            raise InterfaceWorkflowValidationError("Explicit member preparation refuses duplicate Ethernet or final parent claims.")
    return [(key, explicit[key][0], claims[key][0]) for key in sorted(explicit.keys() & claims.keys())]


def _safe_fields(resource: Any, model: Any) -> set[str]:
    """Allow member-safe values only; the parent owns VLAN, LACP and addressing."""
    fields, _values = resource.orchestrator._requested_member_updates(model)
    if fields - resource.orchestrator.PORT_CHANNEL_MODIFIABLE_FIELDS:
        raise InterfaceWorkflowValidationError(
            "Explicit aggregate member preparation permits only description, admin_state or safe extra_config on Ethernet resources."
        )
    if fields:
        resource.orchestrator.validate_new_member_patch_intent(model)
    return fields


def _expectation(planner: Any, key: Any, ethernet: Any, claim: Any):
    from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import InterfaceMemberPreparation

    resource, model = ethernet
    resource_type, host_policy, _mode = _FAMILIES[claim.descriptor.family]
    if resource.adapter.resource_type != resource_type or planner._desired_policy_type(model) != host_policy:
        raise InterfaceWorkflowValidationError("Explicit Ethernet policy must match its requested aggregate family.")
    if resource.state != "merged":
        raise InterfaceWorkflowValidationError("Explicit aggregate Ethernet member preparation requires state: merged.")
    fields = _safe_fields(resource, model)
    return InterfaceMemberPreparation(
        resource_index=resource.resource_index,
        resource_type=resource_type,
        source_action="create",
        switch_id=key[0],
        interface_name=model.interface_name,
        model=model,
        current={},
        from_policy_type=None,
        to_policy_type=host_policy,
        parent_resource_index=claim.resource.resource_index,
        parent_action=claim.action,
        parent_switch_id=planner.fabric_context.get_switch_id(claim.parent.switch_ip),
        parent_name=claim.parent.interface_name,
        parent_policy_type=planner._desired_policy_type(claim.parent),
        kind="missing_inventory",
        orchestrator=resource.orchestrator,
        requires_member_update=bool(fields),
        expected_member_policy=claim.descriptor.policy_type,
        parent_port_channel_id=_parent_id(planner, claim),
    )


def plan_missing_members(planner: Any, resources: Any):
    """Schedule explicit absent creates or minimal host conversions before parents."""
    resources = list(resources)
    preparations, by_resource = [], defaultdict(list)
    for key, ethernet, claim in _explicit_claims(planner, resources):
        resource, model = ethernet
        record = planner.snapshot.cached_interface(*key)
        try:
            proof = _expectation(planner, key, ethernet, claim)
        except (InterfaceWorkflowValidationError, RuntimeError, ValueError):
            # Ineligible simultaneous Ethernet/aggregate edits retain the
            # established conflict classification instead of gaining preparation.
            continue
        if any(
            item.resource_index == resource.resource_index and item.switch_id == key[0] and item.interface_name.casefold() == key[1]
            for item in planner._member_preparations
        ):
            continue  # The established physical safe-field conversion already owns it.
        creates = {item.get_identifier_value() for item in resource.operations.creates}
        transitions = {item.desired.get_identifier_value() for item in resource.transitions}
        identifier = model.get_identifier_value()
        if record is not None:
            if planner.snapshot.policy_type(record) == proof.to_policy_type:
                continue
            if identifier not in creates | transitions:
                continue
            raw = _policy(record)
            if raw.get("policyType") not in {"accessHost", "trunkHost", "routedHost"}:
                continue
            proof = replace(
                proof,
                kind="explicit_host_conversion",
                source_action="transition" if identifier in transitions else "create",
                from_policy_type=raw["policyType"],
                current=deepcopy(record),
            )
        elif identifier not in creates:
            raise InterfaceWorkflowValidationError("Explicit missing member has no exact Ethernet create operation.")
        if not planner.snapshot.has_switch(key[0]):
            raise InterfaceWorkflowValidationError("Explicit member preparation requires complete clean planning inventory.")
        if planner._memberships().claiming_parents(*key):
            raise InterfaceWorkflowValidationError(
                "Explicit member preparation refuses an already-claimed member missing or incompatible in controller inventory."
            )
        if claim.action not in {"create", "update"}:
            raise InterfaceWorkflowValidationError("An explicit Ethernet preparation requires an actual requested parent create or update.")
        preparations.append(proof)
        by_resource[resource.resource_index].append(proof)
    refresh_missing_preparations(preparations, planner.snapshot, phase="absent")
    rewritten = []
    for resource in resources:
        items = by_resource.get(resource.resource_index, [])
        if not items:
            rewritten.append(resource)
            continue
        prepared = {item.model.get_identifier_value() for item in items}
        rewritten.append(
            replace(
                resource,
                transitions=tuple(item for item in resource.transitions if item.desired.get_identifier_value() not in prepared),
                operations=replace(
                    resource.operations,
                    creates=tuple(model for model in resource.operations.creates if model.get_identifier_value() not in prepared),
                    updates=(*resource.operations.updates, *(item.model for item in items if item.requires_member_update)),
                ),
            )
        )
    planner._inventory_by_identity = planner.snapshot.interfaces_by_identity
    planner._membership_index = None
    return rewritten, tuple(preparations)


def explicit_member_expectations(planner: Any, resources: Any):
    """Retain exact parent/member expectations on retries and unchanged runs."""
    result = []
    for key, ethernet, claim in _explicit_claims(planner, resources):
        resource, model = ethernet
        # Existing physical/member workflows retain their established contracts.
        # Policy-only prerequisites and member-safe explicit intent share the
        # new verification path only when they name a matching NX-OS family.
        expected_type, host_policy, _mode = _FAMILIES[claim.descriptor.family]
        if resource.adapter.resource_type != expected_type or planner._desired_policy_type(model) != host_policy:
            continue
        fields, _values = resource.orchestrator._requested_member_updates(model)
        if fields - resource.orchestrator.PORT_CHANNEL_MODIFIABLE_FIELDS or resource.state != "merged":
            continue
        result.append(_expectation(planner, key, ethernet, claim))
    return tuple(result)
