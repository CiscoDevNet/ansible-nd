# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Read-only planning and cross-family conflict detection for interfaces."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.interface_family_adapters import (
    INTERFACE_FAMILY_ADAPTERS,
    InterfaceFamilyAdapter,
    InterfaceWorkflowValidationError,
    get_interface_family_adapter,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import InterfaceStateSnapshot
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_plan import NDStatePlan
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_trunk_host_interface import (
    EthernetTrunkHostInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results

RestSendFactory = Callable[[dict[str, Any]], RestSend]


@dataclass(frozen=True, order=True)
class InterfaceIdentity:
    """Canonical ownership identity independent of a family model's identifier."""

    scope_kind: str
    scope: tuple[str, ...]
    interface_name: str

    @property
    def label(self) -> str:
        """Return a compact identity for diagnostics."""
        return f"{self.scope_kind}[{','.join(self.scope)}]/{self.interface_name}"


@dataclass(frozen=True)
class InterfaceWorkflowConflict:
    """One deterministic conflict discovered across resource plans."""

    code: str
    identity: InterfaceIdentity
    resource_indices: tuple[int, ...]
    resource_types: tuple[str, ...]
    message: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the conflict for future aggregate module output."""
        return {
            "code": self.code,
            "identity": self.identity.label,
            "resource_indices": list(self.resource_indices),
            "resource_types": list(self.resource_types),
            "message": self.message,
        }


class InterfaceWorkflowConflictError(ValueError):
    """Raised after all compatible cross-family conflicts have been collected."""

    def __init__(self, conflicts: Iterable[InterfaceWorkflowConflict]) -> None:
        self.conflicts = tuple(conflicts)
        summary = "; ".join(conflict.message for conflict in self.conflicts)
        super().__init__(f"Interface workflow has {len(self.conflicts)} conflict(s): {summary}")


@dataclass(frozen=True)
class InterfaceResourcePlan:
    """Validated current state and pure operation plan for one resource group."""

    resource_index: int
    adapter: InterfaceFamilyAdapter
    state: str
    proposed: NDConfigCollection = field(repr=False, compare=False)
    before: NDConfigCollection = field(repr=False, compare=False)
    operations: NDStatePlan = field(repr=False, compare=False)
    orchestrator: NDBaseInterfaceOrchestrator = field(repr=False, compare=False)

    @property
    def resource_type(self) -> str:
        """Return the public resource discriminator."""
        return self.adapter.resource_type

    @property
    def changed(self) -> bool:
        """Return whether this group has a planned mutation."""
        return self.operations.changed

    def to_dict(self) -> dict[str, Any]:
        """Serialize the read-only plan using replayable model config."""
        return {
            "resource_index": self.resource_index,
            "type": self.resource_type,
            "module": self.adapter.module_name,
            "state": self.state,
            "changed": self.changed,
            "before": self.before.to_ansible_config(),
            "proposed": self.proposed.to_ansible_config(),
            "after": self.operations.after.to_ansible_config(),
            "created": [item.to_config() for item in self.operations.creates],
            "updated": [item.to_config() for item in self.operations.updates],
            "deleted": [item.to_config() for item in self.operations.deletes],
        }


@dataclass(frozen=True)
class InterfaceWorkflowPlan:
    """Complete mutation-free plan across all requested interface families."""

    fabric_name: str
    target_switch_ids: tuple[str, ...]
    resources: tuple[InterfaceResourcePlan, ...]
    request_stats: dict[str, int]

    @property
    def changed(self) -> bool:
        """Return whether any resource group has a planned mutation."""
        return any(resource.changed for resource in self.resources)

    @property
    def mutation_count(self) -> int:
        """Return the total planned mutation count."""
        return sum(resource.operations.mutation_count for resource in self.resources)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the aggregate read-only plan."""
        return {
            "fabric_name": self.fabric_name,
            "changed": self.changed,
            "mutation_count": self.mutation_count,
            "target_switch_ids": list(self.target_switch_ids),
            "resources": [resource.to_dict() for resource in self.resources],
            "request_stats": dict(self.request_stats),
        }


class InterfaceWorkflowPlanner:
    """Validate and plan all resource groups before any interface mutation."""

    _GROUP_KEYS = frozenset({"type", "state", "config"})

    def __init__(
        self,
        *,
        snapshot: InterfaceStateSnapshot,
        rest_send_factory: RestSendFactory | None = None,
        vpc_pair_by_switch_ip: Mapping[str, str | Iterable[str]] | None = None,
        run_capability_preflight: bool = False,
    ) -> None:
        self.snapshot = snapshot
        self.fabric_context = snapshot.fabric_context
        self.rest_send_factory = rest_send_factory or RestSend
        self.vpc_pair_by_switch_ip = dict(vpc_pair_by_switch_ip or {})
        self.run_capability_preflight = run_capability_preflight
        self._vpc_pair_scope_cache: dict[str, tuple[str, ...]] = {}

    def plan(self, resources: list[dict[str, Any]]) -> InterfaceWorkflowPlan:
        """Return a complete read-only plan or raise before any mutation method is called."""
        validated = self._validate_resource_groups(resources)
        target_switch_ids = self._target_switch_ids(validated)
        self.snapshot.load_switches(target_switch_ids)

        resource_plans: list[InterfaceResourcePlan] = []
        for resource_index, adapter, state, proposed in validated:
            try:
                params = {
                    "fabric_name": self.snapshot.fabric_name,
                    "state": state,
                    "config": proposed.to_ansible_config(),
                    "check_mode": True,
                }
                rest_send = self.rest_send_factory(params)
                results = Results()
                results.state = state
                results.check_mode = True
                orchestrator = adapter.build_orchestrator(rest_send=rest_send, snapshot=self.snapshot, results=results)
                before = adapter.existing_collection(orchestrator)
                operations = adapter.plan(before=before, proposed=proposed, state=state)
            except Exception as exc:
                raise InterfaceWorkflowValidationError(
                    f"resources[{resource_index}] type '{adapter.resource_type}' planning failed through {adapter.module_name}: {exc}"
                ) from exc
            resource_plans.append(
                InterfaceResourcePlan(
                    resource_index=resource_index,
                    adapter=adapter,
                    state=state,
                    proposed=proposed,
                    before=before,
                    operations=operations,
                    orchestrator=orchestrator,
                )
            )

        conflicts = self._find_conflicts(resource_plans)
        if conflicts:
            raise InterfaceWorkflowConflictError(conflicts)

        self._run_preflights(resource_plans)
        return InterfaceWorkflowPlan(
            fabric_name=self.snapshot.fabric_name,
            target_switch_ids=target_switch_ids,
            resources=tuple(resource_plans),
            request_stats=self.snapshot.request_stats,
        )

    def _validate_resource_groups(self, resources: list[dict[str, Any]]) -> list[tuple[int, InterfaceFamilyAdapter, str, NDConfigCollection]]:
        """Validate group envelopes and delegate each config to its family adapter."""
        if not isinstance(resources, list):
            raise InterfaceWorkflowValidationError("resources must be a list.")

        validated: list[tuple[int, InterfaceFamilyAdapter, str, NDConfigCollection]] = []
        for resource_index, resource in enumerate(resources):
            if not isinstance(resource, dict):
                raise InterfaceWorkflowValidationError(f"resources[{resource_index}] must be a dictionary.")
            unknown = set(resource) - self._GROUP_KEYS
            if unknown:
                raise InterfaceWorkflowValidationError(f"resources[{resource_index}] contains unsupported keys: {', '.join(sorted(unknown))}.")
            resource_type = resource.get("type")
            if not isinstance(resource_type, str) or not resource_type:
                raise InterfaceWorkflowValidationError(f"resources[{resource_index}].type must be a non-empty string.")
            if "config" not in resource:
                raise InterfaceWorkflowValidationError(f"resources[{resource_index}].config is required.")
            state = resource.get("state", "merged")
            if not isinstance(state, str):
                raise InterfaceWorkflowValidationError(f"resources[{resource_index}].state must be a string.")
            adapter = get_interface_family_adapter(resource_type)
            proposed = adapter.validate_config(resource["config"], state, resource_index)
            validated.append((resource_index, adapter, state, proposed))
        return validated

    def _target_switch_ids(self, validated: list[tuple[int, InterfaceFamilyAdapter, str, NDConfigCollection]]) -> tuple[str, ...]:
        """Resolve the union of configured switches, expanding override to the fabric."""
        fabric_wide = any(state == "overridden" for _index, _adapter, state, _proposed in validated)
        switch_ids: list[str] = []
        for resource_index, adapter, _state, proposed in validated:
            for item in proposed:
                switch_ip = getattr(item, "switch_ip", None)
                try:
                    switch_id = self.fabric_context.get_switch_id(switch_ip)
                except Exception as exc:
                    raise InterfaceWorkflowValidationError(
                        f"resources[{resource_index}] type '{adapter.resource_type}' cannot resolve switch_ip '{switch_ip}': {exc}"
                    ) from exc
                switch_ids.append(switch_id)
                if adapter.ownership_domain == "vpc":
                    switch_ids.extend(self._vpc_pair_scope(switch_ip))
        if fabric_wide:
            return tuple(dict.fromkeys(self.fabric_context.switch_map.values()))
        return tuple(dict.fromkeys(switch_ids))

    def _vpc_pair_scope(self, switch_ip: str) -> tuple[str, ...]:
        """Return an unordered pair of switch IDs, or a primary-only fallback."""
        if switch_ip in self._vpc_pair_scope_cache:
            return self._vpc_pair_scope_cache[switch_ip]

        primary_id = self.fabric_context.get_switch_id(switch_ip)
        configured = self.vpc_pair_by_switch_ip.get(switch_ip)
        if configured is None:
            scope = (primary_id,)
        else:
            tokens = [switch_ip]
            tokens.extend([configured] if isinstance(configured, str) else list(configured))
            resolved: set[str] = set()
            for token in tokens:
                if token in self.fabric_context.switch_map:
                    resolved.add(self.fabric_context.switch_map[token])
                elif token in self.fabric_context.switch_map_by_id:
                    resolved.add(token)
                else:
                    raise InterfaceWorkflowValidationError(f"vPC pair context for switch_ip '{switch_ip}' contains unknown switch '{token}'.")
            if len(resolved) != 2:
                raise InterfaceWorkflowValidationError(
                    f"vPC pair context for switch_ip '{switch_ip}' must resolve to exactly two switches; got {sorted(resolved)}."
                )
            scope = tuple(sorted(resolved))
        self._vpc_pair_scope_cache[switch_ip] = scope
        return scope

    def _identity(self, adapter: InterfaceFamilyAdapter, item: NDBaseModel) -> InterfaceIdentity:
        """Build a switch- or pair-scoped global ownership identity."""
        switch_ip = getattr(item, "switch_ip")
        interface_name = getattr(item, "interface_name").lower()
        if adapter.ownership_domain == "vpc":
            return InterfaceIdentity("vpc_pair", self._vpc_pair_scope(switch_ip), interface_name)
        return InterfaceIdentity("switch", (self.fabric_context.get_switch_id(switch_ip),), interface_name)

    @staticmethod
    def _iter_operations(resource: InterfaceResourcePlan) -> Iterable[tuple[str, NDBaseModel]]:
        """Yield action/model pairs in deterministic execution order."""
        for item in resource.operations.updates:
            yield "update", item
        for item in resource.operations.creates:
            yield "create", item
        for item in resource.operations.deletes:
            yield "delete", item

    def _find_conflicts(self, resources: list[InterfaceResourcePlan]) -> tuple[InterfaceWorkflowConflict, ...]:
        """Collect ownership, action, transition, and member dependency conflicts."""
        conflicts: list[InterfaceWorkflowConflict] = []
        seen_conflicts: set[tuple[str, InterfaceIdentity, tuple[int, ...]]] = set()

        def add(
            code: str,
            identity: InterfaceIdentity,
            participants: Iterable[InterfaceResourcePlan],
            message: str,
        ) -> None:
            unique = {participant.resource_index: participant for participant in participants}
            ordered = tuple(unique[index] for index in sorted(unique))
            indices = tuple(participant.resource_index for participant in ordered)
            key = (code, identity, indices)
            if key in seen_conflicts:
                return
            seen_conflicts.add(key)
            conflicts.append(
                InterfaceWorkflowConflict(
                    code=code,
                    identity=identity,
                    resource_indices=indices,
                    resource_types=tuple(participant.resource_type for participant in ordered),
                    message=message,
                )
            )

        desired_claims: dict[InterfaceIdentity, list[InterfaceResourcePlan]] = defaultdict(list)
        for resource in resources:
            if resource.state == "deleted":
                continue
            for item in resource.proposed:
                desired_claims[self._identity(resource.adapter, item)].append(resource)

        for identity, participants in desired_claims.items():
            indices = sorted({participant.resource_index for participant in participants})
            if len(indices) > 1:
                add(
                    "duplicate_ownership",
                    identity,
                    participants,
                    f"{identity.label} is claimed by multiple resource groups {indices}.",
                )

        actions: dict[InterfaceIdentity, list[tuple[InterfaceResourcePlan, str]]] = defaultdict(list)
        for resource in resources:
            for action, item in self._iter_operations(resource):
                actions[self._identity(resource.adapter, item)].append((resource, action))

        for identity, entries in actions.items():
            participants = [resource for resource, _action in entries]
            indices = sorted({participant.resource_index for participant in participants})
            if len(indices) < 2:
                continue
            action_names = {action for _resource, action in entries}
            if "delete" in action_names and action_names - {"delete"}:
                add(
                    "delete_write_collision",
                    identity,
                    participants,
                    f"{identity.label} is deleted and created or updated by resource groups {indices}.",
                )
            else:
                add(
                    "duplicate_mutation",
                    identity,
                    participants,
                    f"{identity.label} has overlapping mutations from resource groups {indices}.",
                )

        for resource in resources:
            if resource.state != "overridden":
                continue
            for item in resource.operations.deletes:
                identity = self._identity(resource.adapter, item)
                other_claims = [claim for claim in desired_claims.get(identity, []) if claim.resource_index != resource.resource_index]
                if other_claims:
                    add(
                        "overridden_ownership",
                        identity,
                        [resource, *other_claims],
                        f"resources[{resource.resource_index}] overridden deletion of {identity.label} conflicts with another desired group.",
                    )

        self._find_existing_policy_conflicts(resources, add)
        self._find_member_conflicts(resources, actions, add)
        return tuple(conflicts)

    def _find_existing_policy_conflicts(self, resources: list[InterfaceResourcePlan], add: Callable[..., None]) -> None:
        """Reject creates that would collide with a sibling or unmanaged current policy."""
        inventory = self.snapshot.interfaces_by_identity
        policy_owner = {policy_type: adapter.resource_type for adapter in INTERFACE_FAMILY_ADAPTERS.values() for policy_type in adapter.policy_types}
        for resource in resources:
            for item in resource.operations.creates:
                switch_ip = getattr(item, "switch_ip")
                switch_id = self.fabric_context.get_switch_id(switch_ip)
                interface_name = getattr(item, "interface_name").lower()
                scope = self._vpc_pair_scope(switch_ip) if resource.adapter.ownership_domain == "vpc" else (switch_id,)
                current_records = [inventory[(candidate_id, interface_name)] for candidate_id in scope if (candidate_id, interface_name) in inventory]
                for current in current_records:
                    if current.get("interfaceType") not in resource.adapter.interface_types:
                        continue
                    policy_type = InterfaceStateSnapshot.policy_type(current)
                    if policy_type == "trunkHost" and EthernetTrunkHostInterfaceOrchestrator._is_unconfigured_default(current):
                        continue
                    if policy_type in resource.adapter.policy_types:
                        continue
                    identity = self._identity(resource.adapter, item)
                    owner = policy_owner.get(policy_type, "an unmanaged controller policy")
                    add(
                        "existing_policy_ownership",
                        identity,
                        [resource],
                        f"resources[{resource.resource_index}] type '{resource.resource_type}' would create {identity.label}, but current "
                        f"policyType '{policy_type}' is owned by {owner}; an explicit transition plan is required.",
                    )

    @staticmethod
    def _policy(model: NDBaseModel) -> Any | None:
        """Return a model's nested interface policy, if present."""
        config_data = getattr(model, "config_data", None)
        network_os = getattr(config_data, "network_os", None) if config_data is not None else None
        return getattr(network_os, "policy", None) if network_os is not None else None

    def _new_member_claims(self, resource: InterfaceResourcePlan) -> Iterable[tuple[InterfaceIdentity, InterfaceIdentity]]:
        """Yield newly attached physical member and owning logical identities."""
        if resource.adapter.ownership_domain not in {"port_channel", "vpc"}:
            return
        for _action, item in self._iter_operations(resource):
            if _action == "delete":
                continue
            policy = self._policy(item)
            if policy is None:
                continue
            previous = resource.before.get(item.get_identifier_value())
            previous_policy = self._policy(previous) if previous is not None else None
            logical_identity = self._identity(resource.adapter, item)
            switch_ip = getattr(item, "switch_ip")
            primary_id = self.fabric_context.get_switch_id(switch_ip)

            if resource.adapter.ownership_domain == "port_channel":
                final_members = set(getattr(policy, "ports", None) or [])
                previous_members = set(getattr(previous_policy, "ports", None) or []) if previous_policy is not None else set()
                for member in sorted(final_members - previous_members):
                    yield InterfaceIdentity("switch", (primary_id,), member.lower()), logical_identity
                continue

            pair_scope = self._vpc_pair_scope(switch_ip)
            peer_ids = [switch_id for switch_id in pair_scope if switch_id != primary_id]
            member_fields = (("peer1_member_ports", primary_id),)
            if len(peer_ids) == 1:
                member_fields += (("peer2_member_ports", peer_ids[0]),)
            for field_name, switch_id in member_fields:
                final_members = set(getattr(policy, field_name, None) or [])
                previous_members = set(getattr(previous_policy, field_name, None) or []) if previous_policy is not None else set()
                for member in sorted(final_members - previous_members):
                    yield InterfaceIdentity("switch", (switch_id,), member.lower()), logical_identity

    def _find_member_conflicts(
        self,
        resources: list[InterfaceResourcePlan],
        actions: dict[InterfaceIdentity, list[tuple[InterfaceResourcePlan, str]]],
        add: Callable[..., None],
    ) -> None:
        """Reject duplicate member ownership and simultaneous Ethernet/member edits."""
        claims: dict[InterfaceIdentity, list[tuple[InterfaceResourcePlan, InterfaceIdentity]]] = defaultdict(list)
        ethernet_actions: dict[InterfaceIdentity, list[InterfaceResourcePlan]] = defaultdict(list)
        for identity, entries in actions.items():
            for resource, _action in entries:
                if resource.adapter.ownership_domain == "ethernet":
                    ethernet_actions[identity].append(resource)
        for resource in resources:
            for member_identity, logical_identity in self._new_member_claims(resource):
                claims[member_identity].append((resource, logical_identity))

        for member_identity, entries in claims.items():
            logical_identities = {logical_identity for _resource, logical_identity in entries}
            participants = [resource for resource, _logical_identity in entries]
            if len(logical_identities) > 1:
                add(
                    "duplicate_member_ownership",
                    member_identity,
                    participants,
                    f"Physical member {member_identity.label} is newly assigned to multiple aggregate interfaces.",
                )
            ethernet_participants = ethernet_actions.get(member_identity, [])
            if ethernet_participants:
                add(
                    "ethernet_member_collision",
                    member_identity,
                    [*participants, *ethernet_participants],
                    f"Physical member {member_identity.label} is mutated as Ethernet while being newly attached to an aggregate interface.",
                )

    def _run_preflights(self, resources: list[InterfaceResourcePlan]) -> None:
        """Run local create guards and optional API-backed capability checks after conflicts."""
        for resource in resources:
            if resource.state == "deleted":
                continue
            try:
                resource.orchestrator.preflight_create(resource.operations.creates)
                if self.run_capability_preflight:
                    resource.orchestrator.preflight(list(resource.proposed))
            except Exception as exc:
                raise InterfaceWorkflowValidationError(
                    f"resources[{resource.resource_index}] type '{resource.resource_type}' preflight failed: {exc}"
                ) from exc
