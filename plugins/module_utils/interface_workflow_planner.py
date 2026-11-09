# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Read-only planning and cross-family conflict detection for interfaces."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass, field, replace
from hashlib import sha256
import json
import re
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.interface_family_adapters import (
    INTERFACE_FAMILY_ADAPTERS,
    InterfaceDeleteStrategy,
    InterfaceFamilyAdapter,
    InterfaceWorkflowValidationError,
    get_interface_family_adapter,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_membership import (
    EthernetMembershipIndex,
    MembershipValidationError,
    ParentMembershipClaim,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import InterfaceStateSnapshot
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_common import normalize_ethernet_interface_name
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_member_interface import (
    get_member_policy_descriptor,
    get_member_policy_descriptor_for_parent,
    normalize_port_channel_id,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_plan import NDStatePlan
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import EthernetBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_routed_interface import EthernetRoutedInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_trunk_host_interface import (
    EthernetTrunkHostInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vpc_interface_base import (
    VpcInterfaceBaseOrchestrator,
    VpcDeletionPreviewPeer,
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
class InterfacePolicyTransition:
    """One implicit destination-family policy replacement planned by the workflow."""

    desired: NDBaseModel = field(repr=False, compare=False)
    current: dict[str, Any] = field(repr=False, compare=False)
    switch_ip: str
    switch_id: str
    interface_name: str
    from_policy_type: str
    to_policy_type: str
    current_records: tuple[tuple[str, dict[str, Any]], ...] = field(default=(), repr=False, compare=False)

    @property
    def target(self) -> tuple[str, str]:
        """Return the controller interface-action identity."""
        return self.interface_name, self.switch_id

    def to_dict(self) -> dict[str, Any]:
        """Serialize auditable transition metadata without exposing raw controller state."""
        return {
            "action": "transition",
            "switch_ip": self.switch_ip,
            "switch_id": self.switch_id,
            "interface_name": self.interface_name,
            "from_policy_type": self.from_policy_type,
            "to_policy_type": self.to_policy_type,
        }


@dataclass(frozen=True)
class _PolicyRewriteCandidate:
    """Internal foreign-policy operation awaiting shared safety validation."""

    resource_index: int
    desired: NDBaseModel = field(repr=False, compare=False)
    current_records: tuple[tuple[str, dict[str, Any]], ...] = field(repr=False, compare=False)


@dataclass(frozen=True)
class _AggregateMemberClaim:
    """Projected current/final ownership of one physical aggregate member."""

    resource: InterfaceResourcePlan = field(repr=False, compare=False)
    action: str
    parent: NDBaseModel = field(repr=False, compare=False)
    member_identity: InterfaceIdentity
    owner_identity: InterfaceIdentity
    current: bool
    final: bool


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
    transitions: tuple[InterfacePolicyTransition, ...] = field(default=(), repr=False, compare=False)
    platform_deletes: tuple[NDBaseModel, ...] = field(default=(), repr=False, compare=False)

    @property
    def resource_type(self) -> str:
        """Return the public resource discriminator."""
        return self.adapter.resource_type

    @property
    def changed(self) -> bool:
        """Return whether this group has a planned mutation."""
        return bool(self.transitions) or self.operations.changed

    @property
    def mutation_count(self) -> int:
        """Return ordinary operations plus explicit policy transitions."""
        return len(self.transitions) + self.operations.mutation_count

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
            "transitions": [transition.to_dict() for transition in self.transitions],
            "created": [item.to_config() for item in self.operations.creates],
            "updated": [item.to_config() for item in self.operations.updates],
            "deleted": [item.to_config() for item in self.operations.deletes],
        }


@dataclass(frozen=True)
class InterfaceWorkflowOperation:
    """One mutation node in the dependency-aware workflow schedule."""

    resource_index: int
    resource_type: str
    action: str
    switch_id: str
    interface_name: str
    model: NDBaseModel = field(repr=False, compare=False)
    refresh_before: bool = field(default=False, repr=False, compare=False)

    @property
    def key(self) -> tuple[int, str, str, str]:
        """Return the stable graph and executor lookup key."""

        return self.resource_index, self.action, self.switch_id, self.interface_name.casefold()


@dataclass(frozen=True)
class InterfaceMemberPreparation:
    """One standalone host-policy prerequisite for a later member-safe update.

    This is auxiliary execution work, not a second public resource operation.
    The requested Ethernet update is complete only after its exact parent is
    staged and the authentic member receives the caller's safe properties.
    """

    resource_index: int
    resource_type: str
    source_action: str
    switch_id: str
    interface_name: str
    model: NDBaseModel = field(repr=False, compare=False)
    current: dict[str, Any] = field(repr=False, compare=False)
    from_policy_type: str
    to_policy_type: str
    parent_resource_index: int
    parent_action: str
    parent_switch_id: str
    parent_name: str
    parent_policy_type: str

    @property
    def key(self) -> tuple[int, str, str, str]:
        return self.resource_index, "prepare_member", self.switch_id, self.interface_name.casefold()

    @property
    def parent_key(self) -> tuple[int, str, str, str]:
        return self.parent_resource_index, self.parent_action, self.parent_switch_id, self.parent_name.casefold()

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_index": self.resource_index,
            "type": self.resource_type,
            "action": "prepare_member",
            "source_action": self.source_action,
            "switch_ip": getattr(self.model, "switch_ip"),
            "switch_id": self.switch_id,
            "interface_name": self.interface_name,
            "from_policy_type": self.from_policy_type,
            "to_policy_type": self.to_policy_type,
            "parent_resource_index": self.parent_resource_index,
            "parent_interface_name": self.parent_name,
            "parent_policy_type": self.parent_policy_type,
        }


@dataclass(frozen=True)
class VpcStagedDeletionProof:
    """Exact pending two-peer delete preview, distinct from generic staging."""

    resource_index: int
    resource_type: str
    switch_id: str
    interface_name: str
    peer_switch_ids: tuple[str, str]
    peer_footprints: tuple[VpcDeletionPreviewPeer, ...]


@dataclass(frozen=True)
class LogicalStagedDeletionProof:
    """One exact current logical tombstone with a validated scoped preview."""

    resource_index: int
    resource_type: str
    switch_id: str
    interface_name: str
    raw_observation_sha256: str
    member_interfaces: tuple[str, ...] = ()


@dataclass(frozen=True)
class InterfaceWorkflowPlan:
    """Complete mutation-free plan across all requested interface families."""

    fabric_name: str
    target_switch_ids: tuple[str, ...]
    resources: tuple[InterfaceResourcePlan, ...]
    request_stats: dict[str, int]
    staged_delete_targets: tuple[tuple[str, str], ...] = ()
    auxiliary_orchestrators: tuple[NDBaseInterfaceOrchestrator, ...] = field(default=(), repr=False, compare=False)
    execution_layers: tuple[tuple[InterfaceWorkflowOperation, ...], ...] = field(default=(), repr=False, compare=False)
    parent_deployment_barriers: tuple[InterfaceWorkflowOperation, ...] = field(default=(), repr=False, compare=False)
    vpc_staged_deletions: tuple[VpcStagedDeletionProof, ...] = ()
    logical_staged_deletions: tuple[LogicalStagedDeletionProof, ...] = ()
    member_preparations: tuple[InterfaceMemberPreparation, ...] = field(default=(), repr=False, compare=False)

    @property
    def changed(self) -> bool:
        """Return whether any resource group has a planned mutation."""
        return any(resource.changed for resource in self.resources)

    @property
    def mutation_count(self) -> int:
        """Return the total planned mutation count."""
        return sum(resource.mutation_count for resource in self.resources) + len(self.member_preparations)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the aggregate read-only plan."""
        return {
            "fabric_name": self.fabric_name,
            "changed": self.changed,
            "mutation_count": self.mutation_count,
            "target_switch_ids": list(self.target_switch_ids),
            "resources": [resource.to_dict() for resource in self.resources],
            "member_preparations": [preparation.to_dict() for preparation in self.member_preparations],
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
        self._vpc_peer_serial_cache: dict[str, str] | None = None
        self._inventory_by_identity: dict[tuple[str, str], dict[str, Any]] | None = None
        self._membership_index: EthernetMembershipIndex | None = None
        self._ethernet_link_cache_owner: EthernetBaseOrchestrator | None = None
        self._staged_delete_targets: list[tuple[str, str]] = []
        self._vpc_staged_deletions: list[VpcStagedDeletionProof] = []
        self._logical_staged_deletions: list[LogicalStagedDeletionProof] = []
        self._converged_vpc_delete_targets: set[tuple[str, str]] = set()
        self._staged_parent_member_cache: dict[tuple[str, str], set[str] | None] = {}
        self._staged_parent_member_commands_cache: dict[tuple[str, str], dict[str, set[str]]] = {}
        self._member_preparations: list[InterfaceMemberPreparation] = []

    def plan(self, resources: list[dict[str, Any]]) -> InterfaceWorkflowPlan:
        """Return a complete read-only plan or raise before any mutation method is called."""
        validated = self._validate_resource_groups(resources)
        target_switch_ids = self._target_switch_ids(validated)
        self.snapshot.load_switches(target_switch_ids)
        self._inventory_by_identity = self.snapshot.interfaces_by_identity
        self._membership_index = None
        self._staged_delete_targets = []
        self._vpc_staged_deletions = []
        self._logical_staged_deletions = []
        self._converged_vpc_delete_targets = set()
        self._staged_parent_member_cache = {}
        self._staged_parent_member_commands_cache = {}
        self._member_preparations = []

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
                if isinstance(orchestrator, VpcInterfaceBaseOrchestrator):
                    orchestrator.share_peer_serial_cache(self._shared_vpc_peer_serial_cache())
                if isinstance(orchestrator, EthernetBaseOrchestrator):
                    self._register_ethernet_orchestrator(orchestrator)
                before = self._existing_collection(adapter, orchestrator, proposed)
                planning_before = self._planning_before_for_policy_transitions(adapter=adapter, before=before, proposed=proposed, state=state)
                operations = adapter.plan(before=planning_before, proposed=proposed, state=state)
                if planning_before is not before:
                    operations = replace(operations, before=before)
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

        for resource in resource_plans:
            if resource.state == "deleted" and isinstance(resource.orchestrator, EthernetBaseOrchestrator):
                resource.orchestrator.register_reset_negotiation_preview_scope(resource.proposed)
        resource_plans = self._rewrite_policy_operations(resource_plans)
        resource_plans = self._split_member_preparations(resource_plans)
        conflicts = self._find_conflicts(resource_plans)
        if conflicts:
            raise InterfaceWorkflowConflictError(conflicts)

        execution_layers = self._build_execution_layers(resource_plans)
        parent_deployment_barriers = self._parent_deployment_barriers(resource_plans, execution_layers)
        self._apply_preflight_projections(resource_plans)
        self._run_preflights(resource_plans)
        auxiliary_orchestrators: tuple[NDBaseInterfaceOrchestrator, ...] = ()
        request_stats = dict(self.snapshot.request_stats)
        request_stats["fabric_link_gets"] = self._fabric_link_gets([*(resource.orchestrator for resource in resource_plans), *auxiliary_orchestrators])
        return InterfaceWorkflowPlan(
            fabric_name=self.snapshot.fabric_name,
            target_switch_ids=target_switch_ids,
            resources=tuple(resource_plans),
            request_stats=request_stats,
            staged_delete_targets=tuple(dict.fromkeys(self._staged_delete_targets)),
            vpc_staged_deletions=tuple(dict.fromkeys(self._vpc_staged_deletions)),
            logical_staged_deletions=tuple(dict.fromkeys(self._logical_staged_deletions)),
            auxiliary_orchestrators=auxiliary_orchestrators,
            execution_layers=execution_layers,
            member_preparations=tuple(self._member_preparations),
            parent_deployment_barriers=parent_deployment_barriers,
        )

    def _validate_resource_groups(self, resources: list[dict[str, Any]]) -> list[tuple[int, InterfaceFamilyAdapter, str, NDConfigCollection]]:
        """Validate group envelopes and delegate each config to its family adapter."""
        if not isinstance(resources, list):
            raise InterfaceWorkflowValidationError("resources must be a list.")

        validated: list[tuple[int, InterfaceFamilyAdapter, str, NDConfigCollection]] = []
        groups_by_type: dict[str, list[tuple[int, str]]] = {}
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
            groups_by_type.setdefault(adapter.resource_type, []).append((resource_index, state))
        for resource_type, groups in groups_by_type.items():
            if len(groups) > 1 and any(state == "overridden" for _index, state in groups):
                indices = ", ".join(f"resources[{index}]" for index, _state in groups)
                raise InterfaceWorkflowValidationError(
                    f"Repeated type '{resource_type}' with state 'overridden' in {indices} is not supported. "
                    "Put all desired interfaces of this type in one overridden group's config list."
                )
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

    def _inventory(self) -> Mapping[tuple[str, str], dict[str, Any]]:
        """Return the once-materialized raw inventory index for this plan."""
        if self._inventory_by_identity is None:
            self._inventory_by_identity = self.snapshot.interfaces_by_identity
        return self._inventory_by_identity

    def _memberships(self) -> EthernetMembershipIndex:
        """Return one ownership index built from the complete shared snapshot."""

        if self._membership_index is None:
            self._membership_index = EthernetMembershipIndex(
                self.snapshot.clean_interfaces_by_switch,
                peer_switch_ids=self._shared_vpc_peer_serial_cache(),
            )
        return self._membership_index

    def _shared_vpc_peer_serial_cache(self) -> dict[str, str]:
        """Return both directions of each controller-proven vPC pair."""
        if self._vpc_peer_serial_cache is None:
            cache: dict[str, str] = {}
            for switch_ip in self.vpc_pair_by_switch_ip:
                scope = self._vpc_pair_scope(switch_ip)
                if len(scope) == 2:
                    first, second = scope
                    for switch_id, peer_id in ((first, second), (second, first)):
                        previous_peer = cache.get(switch_id)
                        if previous_peer is not None and previous_peer != peer_id:
                            raise InterfaceWorkflowValidationError(
                                f"Conflicting vPC pair context for switch '{switch_id}': '{previous_peer}' and '{peer_id}'."
                            )
                        cache[switch_id] = peer_id
            self._vpc_peer_serial_cache = cache
        return self._vpc_peer_serial_cache

    @classmethod
    def pair_scoped_vpc_collection(
        cls,
        *,
        inventory: Mapping[tuple[str, str], dict[str, Any]],
        adapter: InterfaceFamilyAdapter,
        orchestrator: NDBaseInterfaceOrchestrator,
        proposed: NDConfigCollection,
    ) -> NDConfigCollection:
        """Select one stable representative per authoritative vPC pair and interface name."""
        context = orchestrator.fabric_context
        peer_by_switch = getattr(orchestrator, "_peer_serial_cache", {})
        scopes_by_switch_id: dict[str, tuple[str, ...]] = {}
        for switch_id, peer_id in peer_by_switch.items():
            scope = tuple(sorted((switch_id, peer_id)))
            scopes_by_switch_id[switch_id] = scope
            scopes_by_switch_id[peer_id] = scope

        preferred_switch_by_key = {}
        for item in proposed:
            primary_id = context.get_switch_id(getattr(item, "switch_ip"))
            scope = scopes_by_switch_id.get(primary_id, (primary_id,))
            preferred_switch_by_key[(scope, getattr(item, "interface_name").lower())] = primary_id

        selected: dict[tuple[tuple[str, ...], str], tuple[tuple[int, str], str, dict[str, Any]]] = {}
        for (switch_id, interface_name), current in inventory.items():
            if cls._canonical_interface_type(current.get("interfaceType")) != "vpc":
                continue
            if InterfaceStateSnapshot.policy_type(current) not in adapter.policy_types:
                continue
            scope = scopes_by_switch_id.get(switch_id, (switch_id,))
            key = (scope, interface_name)
            preferred_switch = preferred_switch_by_key.get(key)
            rank = (0 if switch_id == preferred_switch else 1, switch_id)
            existing = selected.get(key)
            if existing is None or rank < existing[0]:
                selected[key] = (rank, switch_id, current)

        response: list[dict[str, Any]] = []
        for key in sorted(selected):
            _rank, switch_id, current = selected[key]
            enriched = deepcopy(current)
            enriched["switchIp"] = context.get_switch_ip(switch_id)
            response.append(enriched)
        return NDConfigCollection.from_api_response(response_data=response, model_class=adapter.model_class)

    def _existing_collection(
        self,
        adapter: InterfaceFamilyAdapter,
        orchestrator: NDBaseInterfaceOrchestrator,
        proposed: NDConfigCollection,
    ) -> NDConfigCollection:
        """Select pair-scoped vPC state without name-global query deduplication."""
        if adapter.ownership_domain == "ethernet" and orchestrator.rest_send.params.get("state") == "deleted":
            # A filtered default must not manufacture a successful reset after
            # model parsing silently omits an unmodeled controller field.
            inventory = self._inventory()
            for desired in proposed:
                switch_id = self.fabric_context.get_switch_id(getattr(desired, "switch_ip"))
                name = getattr(desired, "interface_name")
                raw = inventory.get((switch_id, name.casefold()))
                if not isinstance(raw, dict) or self._wire_network_os_type(raw) != "nx-os" or InterfaceStateSnapshot.policy_type(raw) != "trunkHost":
                    continue
                unsupported = EthernetTrunkHostInterfaceOrchestrator.unsupported_nx_reset_fields(raw)
                if unsupported:
                    raise InterfaceWorkflowValidationError(
                        f"Cannot prove or reset NX trunk interface '{name}' on switch '{switch_id}' "
                        f"with unsupported observed configuration fields: {', '.join(unsupported)}."
                    )
        if adapter.ownership_domain != "vpc":
            return adapter.existing_collection(orchestrator)

        orchestrator.validate_prerequisites()
        return self.pair_scoped_vpc_collection(inventory=self._inventory(), adapter=adapter, orchestrator=orchestrator, proposed=proposed)

    @classmethod
    def _desired_policy_type(cls, model: NDBaseModel) -> str | None:
        """Return the destination model's frozen wire policy discriminator."""
        policy = cls._policy(model)
        policy_type = getattr(policy, "policy_type", None) if policy is not None else None
        value = getattr(policy_type, "value", policy_type)
        return value if isinstance(value, str) and value else None

    @classmethod
    def _planning_before_for_policy_transitions(
        cls,
        *,
        adapter: InterfaceFamilyAdapter,
        before: NDConfigCollection,
        proposed: NDConfigCollection,
        state: str,
    ) -> NDConfigCollection:
        """Hide same-identity policy-union mismatches from the ordinary state planner.

        The shared state planner must not field-merge different branches of a discriminated union. For adapters that
        explicitly opt in, temporarily removing those current identities makes the ordinary planner emit create
        candidates. The workflow rewrite phase then converts the candidates to safety-checked destination-family PUT
        transitions while the resource plan retains the complete observed before collection.
        """
        if not adapter.supports_intra_family_policy_transitions or state not in adapter.transition_states:
            return before

        transition_identifiers = []
        for desired in proposed:
            identifier = desired.get_identifier_value()
            current = before.get(identifier)
            if current is None:
                continue
            current_policy_type = cls._desired_policy_type(current)
            desired_policy_type = cls._desired_policy_type(desired)
            if current_policy_type is None or desired_policy_type is None or current_policy_type == desired_policy_type:
                continue
            transition_identifiers.append(identifier)

        if not transition_identifiers:
            return before
        planning_before = before.copy()
        planning_before.delete_many(transition_identifiers)
        return planning_before

    @classmethod
    def _desired_network_os_type(cls, model: NDBaseModel) -> str | None:
        """Return the destination model's frozen network-OS discriminator."""
        config_data = getattr(model, "config_data", None)
        network_os = getattr(config_data, "network_os", None) if config_data is not None else None
        network_os_type = getattr(network_os, "network_os_type", None) if network_os is not None else None
        value = getattr(network_os_type, "value", network_os_type)
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _wire_policy(current: Mapping[str, Any]) -> dict[str, Any]:
        """Return one raw interface policy dictionary."""
        config_data = current.get("configData") or {}
        network_os = config_data.get("networkOS") or {} if isinstance(config_data, Mapping) else {}
        policy = network_os.get("policy") or {} if isinstance(network_os, Mapping) else {}
        return dict(policy) if isinstance(policy, Mapping) else {}

    @staticmethod
    def _wire_network_os_type(current: Mapping[str, Any]) -> str | None:
        """Return one raw interface network-OS discriminator."""
        config_data = current.get("configData") or {}
        network_os = config_data.get("networkOS") or {} if isinstance(config_data, Mapping) else {}
        value = network_os.get("networkOSType") if isinstance(network_os, Mapping) else None
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _desired_mode(model: NDBaseModel) -> str | None:
        """Return the destination model's structural mode discriminator."""
        config_data = getattr(model, "config_data", None)
        value = getattr(config_data, "mode", None) if config_data is not None else None
        value = getattr(value, "value", value)
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _wire_mode(current: Mapping[str, Any]) -> str | None:
        """Return one raw interface mode discriminator."""
        config_data = current.get("configData") or {}
        value = config_data.get("mode") if isinstance(config_data, Mapping) else None
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _canonical_interface_type(value: Any) -> Any:
        """Normalize known raw/summary interface-type aliases."""
        return {"switchVirtualInterface": "svi"}.get(value, value)

    @staticmethod
    def _vpc_record_fingerprint(current: Mapping[str, Any], local_switch_id: str | None = None, peer_switch_id: str | None = None) -> Any:
        """Return configured vPC state, optionally binding peer fields to physical switch IDs.

        TODO(4.3.1) vpc-interface-orientation-tracks-url-switch: Recheck the
        defensive identical-orientation case before removing this allowance.
        Observed per-interface GETs orient peer1 to the switch in the URL and
        peer2 to its peer; ``_vpc_records_match`` accepts those reciprocal echoes.
        Identically oriented copies are accepted defensively, but have not been
        confirmed by a retained wire capture. Member-port spelling and ordering
        are only presentation differences.
        """

        def scrub(value: Any) -> Any:
            if isinstance(value, Mapping):
                ignored = {"switchId", "peerSwitchId", "policyId"}
                normalized = {}
                for key, item in value.items():
                    if key in ignored:
                        continue
                    normalized_item = scrub(item)
                    if key.endswith("MemberPorts") and isinstance(item, list) and all(isinstance(member, str) for member in item):
                        normalized_item = tuple(sorted(member.strip().lower() for member in item))
                    if local_switch_id and peer_switch_id and key.startswith(("peer1", "peer2")) and len(key) > 5 and key[5].isupper():
                        bound_switch_id = local_switch_id if key.startswith("peer1") else peer_switch_id
                        key = f"peer:{bound_switch_id}:{key[5:]}"
                    normalized[key] = normalized_item
                return normalized
            if isinstance(value, list):
                return [scrub(item) for item in value]
            return value

        return scrub(deepcopy(current.get("configData") or {}))

    @classmethod
    def _vpc_records_match(cls, primary_id: str, primary: Mapping[str, Any], peer_id: str, peer: Mapping[str, Any]) -> bool:
        """Accept identical records defensively or a verified switch-local reciprocal peer-field echo."""
        if cls._vpc_record_fingerprint(primary) == cls._vpc_record_fingerprint(peer):
            return True
        return cls._vpc_record_fingerprint(primary, primary_id, peer_id) == cls._vpc_record_fingerprint(peer, peer_id, primary_id)

    def _current_records(
        self,
        adapter: InterfaceFamilyAdapter,
        model: NDBaseModel,
        inventory: Mapping[tuple[str, str], dict[str, Any]],
    ) -> tuple[tuple[str, dict[str, Any]], ...]:
        """Return raw current records, requiring coherent two-peer state for vPC."""
        switch_ip = getattr(model, "switch_ip")
        primary_id = self.fabric_context.get_switch_id(switch_ip)
        interface_name = getattr(model, "interface_name").lower()
        if not adapter.safety.requires_pair_consistency:
            current = inventory.get((primary_id, interface_name))
            return () if current is None else ((primary_id, current),)

        scope = self._vpc_pair_scope(switch_ip)
        label = f"{switch_ip}/{getattr(model, 'interface_name')}"
        if len(scope) != 2:
            raise InterfaceWorkflowValidationError(f"{label} requires an authoritative two-switch vPC pair; resolved scope is {list(scope)}.")
        present = tuple((switch_id, inventory[(switch_id, interface_name)]) for switch_id in scope if (switch_id, interface_name) in inventory)
        if not present:
            return ()
        if len(present) != 2:
            missing = sorted(set(scope) - {switch_id for switch_id, _current in present})
            raise InterfaceWorkflowValidationError(f"{label} has inconsistent vPC pair state: the interface record is missing on peer(s) {missing}.")

        for switch_id, current in present:
            peer_ids = [candidate for candidate in scope if candidate != switch_id]
            expected_peer_id = peer_ids[0]
            configured_peer_id = self._wire_policy(current).get("peerSwitchId")
            if configured_peer_id is not None and configured_peer_id != expected_peer_id:
                raise InterfaceWorkflowValidationError(
                    f"{label} has inconsistent vPC pair records: switch {switch_id} reports peerSwitchId "
                    f"{configured_peer_id!r}, expected {expected_peer_id!r} from authoritative pair inventory."
                )

        interface_types = {current.get("interfaceType") for _switch_id, current in present}
        policy_types = {InterfaceStateSnapshot.policy_type(current) for _switch_id, current in present}
        pair_matches = self._vpc_records_match(present[0][0], present[0][1], present[1][0], present[1][1])
        if len(interface_types) != 1 or len(policy_types) != 1 or not pair_matches:
            raise InterfaceWorkflowValidationError(
                f"{label} has inconsistent vPC pair records: interfaceType={sorted(str(value) for value in interface_types)}, "
                f"policyType={sorted(str(value) for value in policy_types)}, or configured policy data differs between peers."
            )
        return present

    @staticmethod
    def _children_by_parent(
        inventory: Mapping[tuple[str, str], dict[str, Any]],
    ) -> dict[tuple[str, str], tuple[str, ...]]:
        """Index current subinterfaces by switch and structural parent."""
        collected: dict[tuple[str, str], list[str]] = defaultdict(list)
        for (switch_id, candidate_name), current in inventory.items():
            if current.get("interfaceType") != "subInterface" or "." not in candidate_name:
                continue
            parent_name = candidate_name.rsplit(".", 1)[0]
            collected[(switch_id, parent_name)].append(str(current.get("interfaceName") or candidate_name))
        return {identity: tuple(sorted(names, key=str.lower)) for identity, names in collected.items()}

    def _children_after_planned_deletes(
        self,
        inventory: Mapping[tuple[str, str], dict[str, Any]],
        resources: Iterable[InterfaceResourcePlan],
    ) -> dict[tuple[str, str], tuple[str, ...]]:
        """Return current child topology after applying explicit child deletes.

        A ``deleted`` resource can target a structurally matching policy owned by
        another subinterface family.  That policy-independent delete is rewritten
        into ``operations.deletes`` later in this planning pass, so include the
        explicit proposal here as well.  Any unsafe delete still fails its normal
        structural and summary preflight before a plan can execute.
        """

        children = {identity: list(names) for identity, names in self._children_by_parent(inventory).items()}
        for resource in resources:
            if resource.adapter.ownership_domain != "subinterface":
                continue
            delete_models = list(resource.operations.deletes)
            if resource.state == "deleted":
                delete_models.extend(resource.proposed)
            for model in delete_models:
                child_name = getattr(model, "interface_name")
                if "." not in child_name:
                    continue
                switch_id = self.fabric_context.get_switch_id(getattr(model, "switch_ip"))
                parent_identity = switch_id, child_name.rsplit(".", 1)[0].casefold()
                child_key = child_name.casefold()
                children[parent_identity] = [name for name in children.get(parent_identity, []) if name.casefold() != child_key]
        return {identity: tuple(names) for identity, names in children.items() if names}

    @staticmethod
    def _is_unconfigured_ethernet_default(
        adapter: InterfaceFamilyAdapter,
        current_records: tuple[tuple[str, dict[str, Any]], ...],
    ) -> bool:
        """Return whether one physical port is already at the fabric default."""
        if adapter.delete_strategy != InterfaceDeleteStrategy.NORMALIZE or len(current_records) != 1:
            return False
        current = current_records[0][1]
        policy_type = InterfaceStateSnapshot.policy_type(current)
        if policy_type == "trunkHost":
            return EthernetTrunkHostInterfaceOrchestrator._is_unconfigured_default(current)
        if policy_type == "iosXeTrunkHost":
            return EthernetTrunkHostInterfaceOrchestrator._is_unconfigured_default(current)
        if policy_type == "iosXeRoutedHost":
            return EthernetRoutedInterfaceOrchestrator._is_unconfigured_default(current)
        return False

    def _platform_delete_models(
        self,
        resource: InterfaceResourcePlan,
        operations: NDStatePlan,
        inventory: Mapping[tuple[str, str], dict[str, Any]],
    ) -> tuple[NDBaseModel, ...]:
        """Build same-family IOS-XE proxy models for physical deletes requiring a platform reset."""
        if resource.adapter.ownership_domain != "ethernet":
            return ()
        model_class = resource.adapter.model_class
        platform_deletes: list[NDBaseModel] = []
        for desired in operations.deletes:
            switch_id = self.fabric_context.get_switch_id(getattr(desired, "switch_ip"))
            current = inventory.get((switch_id, getattr(desired, "interface_name").lower()))
            if self._wire_network_os_type(current or {}) != "ios-xe":
                continue
            platform_deletes.append(
                model_class(
                    switch_ip=getattr(desired, "switch_ip"),
                    interface_name=getattr(desired, "interface_name"),
                    config_data={"network_os": {"network_os_type": "ios-xe"}},
                )
            )
        return tuple(platform_deletes)

    def _port_channel_delete_model(
        self,
        resource: InterfaceResourcePlan,
        desired: NDBaseModel,
        current_records: tuple[tuple[str, dict[str, Any]], ...],
    ) -> NDBaseModel:
        """Keep the observed IOS-XE type and members when planning an explicit port-channel delete.

        An identifier-only delete proposal has no network OS discriminator. The
        shared port-channel orchestrator needs that discriminator to use the
        switch-canonical ``Port-channel<N>`` identity for both remove and deploy.
        Prefer the parsed current model so its member context is preserved;
        cross-policy deletes have no selected-family model, so use only the
        controller-observed platform to construct their delete proxy.
        """
        if resource.adapter.ownership_domain != "port_channel":
            return desired
        switch_id = self.fabric_context.get_switch_id(getattr(desired, "switch_ip"))
        current = dict(current_records).get(switch_id)
        if self._wire_network_os_type(current or {}) != "ios-xe":
            return desired
        existing = resource.before.get(desired.get_identifier_value())
        network_os = getattr(getattr(existing, "config_data", None), "network_os", None)
        if getattr(network_os, "network_os_type", None) == "ios-xe":
            return existing
        return resource.adapter.model_class(
            switch_ip=getattr(desired, "switch_ip"),
            interface_name=getattr(desired, "interface_name"),
            config_data={"network_os": {"network_os_type": "ios-xe"}},
        )

    def _register_ethernet_orchestrator(self, orchestrator: EthernetBaseOrchestrator) -> None:
        """Share one lazy fabric-link cache across every Ethernet family in this workflow."""
        orchestrator.enable_bounded_workflow_reset_evidence()
        if self._ethernet_link_cache_owner is None:
            self._ethernet_link_cache_owner = orchestrator
            return
        orchestrator.share_fabric_link_cache(self._ethernet_link_cache_owner)

    @staticmethod
    def _fabric_link_gets(orchestrators: Iterable[NDBaseInterfaceOrchestrator]) -> int:
        """Count unique routed fabric-link GET responses used by safety preflight."""
        count = 0
        seen: set[int] = set()
        for orchestrator in orchestrators:
            rest_send = orchestrator.rest_send
            if id(rest_send) in seen:
                continue
            seen.add(id(rest_send))
            for response in rest_send.responses:
                method = getattr(response.get("METHOD"), "value", response.get("METHOD"))
                path = str(response.get("REQUEST_PATH") or "")
                if str(method).upper() == "GET" and "/links" in path:
                    count += 1
        return count

    def _dependency_errors(
        self,
        *,
        resource: InterfaceResourcePlan,
        desired: NDBaseModel,
        current_records: tuple[tuple[str, dict[str, Any]], ...],
        children_by_parent: Mapping[tuple[str, str], tuple[str, ...]],
        action: str,
        check_membership: bool = True,
    ) -> list[str]:
        """Return current topology conditions that make an operation unsafe."""
        label = f"resources[{resource.resource_index}] {getattr(desired, 'switch_ip')}/{getattr(desired, 'interface_name')}"
        errors: list[str] = []
        if check_membership and resource.adapter.ownership_domain == "ethernet" and current_records:
            port_channel_id = self._effective_port_channel_id(current_records[0][1])
            if port_channel_id is not None:
                errors.append(f"{label} cannot {action} while it is a member of port-channel {port_channel_id}. Remove the membership first.")
        if resource.adapter.safety.guards_child_subinterfaces:
            switch_ids = {switch_id for switch_id, _current in current_records}
            if not switch_ids:
                switch_ids.add(self.fabric_context.get_switch_id(getattr(desired, "switch_ip")))
            parent_name = getattr(desired, "interface_name").lower()
            for switch_id in sorted(switch_ids):
                children = children_by_parent.get((switch_id, parent_name), ())
                if children:
                    errors.append(
                        f"{label} cannot {action} while child subinterfaces exist on switch {switch_id}: {', '.join(children)}. "
                        "Remove the child subinterfaces first."
                    )
        return errors

    @staticmethod
    def _member_names(value: Any) -> tuple[str, ...]:
        """Return canonical physical member names while preserving duplicates."""
        if value is None:
            return ()
        values = value.split(",") if isinstance(value, str) else value
        if not isinstance(values, Iterable) or isinstance(values, (bytes, Mapping)):
            return ()
        return tuple(member.strip().lower() for item in values if isinstance(item, str) and (member := item.strip()))

    def _duplicate_member_errors(self, resource: InterfaceResourcePlan) -> list[str]:
        """Reject duplicate final members within one aggregate interface."""
        if not resource.adapter.safety.owns_physical_members:
            return []
        errors: list[str] = []
        for action, item in self._iter_operations(resource):
            if action == "delete":
                continue
            policy = self._policy(item)
            if policy is None:
                continue
            fields = ("ports",) if resource.adapter.ownership_domain == "port_channel" else ("peer1_member_ports", "peer2_member_ports")
            for field_name in fields:
                members = self._member_names(getattr(policy, field_name, None))
                seen: set[str] = set()
                duplicates = sorted({member for member in members if member in seen or seen.add(member)})
                if duplicates:
                    errors.append(
                        f"resources[{resource.resource_index}] {getattr(item, 'switch_ip')}/"
                        f"{getattr(item, 'interface_name')} contains duplicate {field_name}: {duplicates}."
                    )
        return errors

    def _structural_collision(
        self,
        resource: InterfaceResourcePlan,
        desired: NDBaseModel,
        current_records: tuple[tuple[str, dict[str, Any]], ...],
    ) -> InterfaceWorkflowConflict:
        """Build a structured same-name/different-kind collision."""
        identity = self._identity(resource.adapter, desired)
        current_types = sorted({str(current.get("interfaceType")) for _switch_id, current in current_records})
        expected = sorted(resource.adapter.interface_types)
        return InterfaceWorkflowConflict(
            code="structural_type_collision",
            identity=identity,
            resource_indices=(resource.resource_index,),
            resource_types=(resource.resource_type,),
            message=(
                f"resources[{resource.resource_index}] type '{resource.resource_type}' targets {identity.label}, but an existing "
                f"same-name record has structural interfaceType {current_types}; expected {expected}."
            ),
        )

    @staticmethod
    def _current_logical_delete_expected_absence(preview, name, preview_member_interfaces, member_running_commands):
        """Accept only an exact removed header and already validated member CLI.

        Manage renders the removed parent as one red strike-through HTML block.
        Remaining expected physical blocks must equal their final pending
        blocks. Unknown HTML, another logical header, extra/missing members or
        commands cannot turn a staged deletion into an absence proof.
        """
        # Exact controller/receipt types are part of the validation contract.
        # pylint: disable=unidiomatic-typecheck
        configs = preview["configurationDiffs"][0]["combinedConfigs"]
        expected = next(item for item in configs if item["configType"].strip().casefold() == "expected")
        text, lines = expected.get("config"), expected.get("lines")
        if text == "" and type(lines) is int and lines == 0:
            return True  # Earlier API shape: no expected target CLI.
        if not isinstance(text, str) or type(lines) is not int or lines <= 0:
            return False
        struck = re.match(r"<font color='red'><strike>(.*?)</strike></font>", text, re.IGNORECASE | re.DOTALL)
        if struck is None or "<" in struck.group(1) or ">" in struck.group(1):
            return False
        removed = [line.strip() for line in struck.group(1).splitlines() if line.strip()]
        header = f"interface {name}".casefold()
        if not removed or removed[0].casefold() != header:
            return False
        running = next(item for item in configs if item["configType"].strip().casefold() == "running")
        running_lines = [line.strip() for line in running["config"].splitlines() if line.strip()]
        if len(removed) != 1:
            # ND may reorder the old loopback commands and render its implicit
            # no-shutdown default inside the removed block. No other command
            # can be added or omitted from that exact current running intent.
            if (
                not running_lines
                or running_lines[0].casefold() != header
                or len(set(removed)) != len(removed)
                or not set(running_lines[1:]) <= set(removed[1:])
                or set(removed[1:]) - set(running_lines[1:]) - {"no shutdown"}
            ):
                return False
        remainder = text[struck.end() :]
        if "<" in remainder or ">" in remainder:
            return False
        expected_lines = [line.strip().casefold() for line in remainder.splitlines() if line.strip()]
        if not preview_member_interfaces:
            return not expected_lines
        pending = next(item for item in configs if item["configType"].strip().casefold() == "pending")
        pending_lines = [line.strip().casefold() for line in pending["config"].splitlines() if line.strip()]

        def blocks(values, *, pending=False):
            result, member = {}, None
            for line in values:
                match = re.fullmatch(r"interface (ethernet[0-9/]+)", line)
                if match is not None:
                    member = match.group(1)
                    if not pending and member in result:
                        return None
                    if not pending or member not in result:
                        result[member] = []
                elif pending and line == "configure terminal":
                    continue
                elif member is None:
                    return None
                else:
                    result[member].append(line)
            return result

        final_pending = blocks(pending_lines[1:], pending=True)
        actual_expected = blocks(expected_lines)
        members = {member.casefold() for member in preview_member_interfaces}
        if (
            final_pending is None
            or actual_expected is None
            or set(final_pending) != set(actual_expected)
            or set(final_pending) != members
            or set(member_running_commands) != members
        ):
            return False
        for member in members:
            # Apply only commands the existing pending/member validator has
            # already admitted, to this exact independently observed running
            # member block. ND reorders expected CLI and can leave an existing
            # routed MTU unchanged until a later explicit default correction.
            resulting = set(member_running_commands[member])
            for command in final_pending[member]:
                group = re.fullmatch(r"no channel-group ([0-9]+) force mode active", command)
                if group is not None:
                    resulting.discard(f"channel-group {group.group(1)} mode active")
                    resulting.discard(f"channel-group {group.group(1)} force mode active")
                elif command in {"no shutdown", "no switchport"}:
                    resulting.discard(command[3:])
                    resulting.add(command)
                elif command.startswith("no "):
                    resulting.discard(command[3:])
                else:
                    # These admitted CLI commands replace one current value.
                    for prefix in ("mtu ", "switchport mode ", "switchport trunk allowed vlan ", "spanning-tree port type "):
                        if command.startswith(prefix):
                            resulting = {old for old in resulting if not old.startswith(prefix)}
                    resulting.discard("no " + command)
                    if command == "switchport":
                        resulting.discard("no switchport")
                    resulting.add(command)
            expected_commands = actual_expected[member]
            if (
                len(set(expected_commands)) != len(expected_commands)
                or not resulting <= set(expected_commands)
                or set(expected_commands) - resulting - {"no shutdown"}
                or any(command.startswith("channel-group ") for command in expected_commands)
            ):
                return False
        return True

    def _record_current_logical_deletion(
        self, resource, current, preview, name, switch_id, *, member_interfaces=(), preview_member_interfaces=(), member_running_commands=None
    ):
        """Publish a strict current observation, never a historical write receipt.

        Existing replay behavior stays conservative on its own terms. This
        additional proof is withheld when unknown policy fields or incomplete
        expected CLI prevent an independent caller from requalifying staging.
        """
        config = current.get("configData")
        if not isinstance(config, dict) or set(config) != {"networkOS"}:
            return
        network_os = config["networkOS"]
        if not isinstance(network_os, dict) or set(network_os) != {"networkOSType", "policy"} or network_os["networkOSType"] != "nx-os":
            return
        policy = network_os["policy"]
        if (
            not isinstance(policy, dict)
            or set(policy) not in ({"policyType", "templateName"}, {"policyType", "templateName", "templateConfig"})
            or policy.get("policyType") != "userDefined"
            or policy.get("templateName") != "interface_delete"
        ):
            return
        if "templateConfig" in policy:
            template = policy["templateConfig"]
            if not isinstance(template, dict) or not (template == {} or (set(template) == {"ReadOnlyOnEdit"} and template["ReadOnlyOnEdit"] is True)):
                return
        rows = preview.get("configurationDiffs")
        if not isinstance(rows, list) or len(rows) != 1:
            return
        configs = rows[0].get("combinedConfigs")
        if not isinstance(configs, list) or len(configs) != 3:
            return
        by_type = {}
        for item in configs:
            if not isinstance(item, dict) or not isinstance(item.get("configType"), str):
                return
            kind = item["configType"].strip().casefold()
            if kind not in {"running", "pending", "expected"} or kind in by_type:
                return
            by_type[kind] = item
        if not self._current_logical_delete_expected_absence(preview, name, preview_member_interfaces, member_running_commands or {}):
            return
        self._logical_staged_deletions.append(
            LogicalStagedDeletionProof(
                resource_index=resource.resource_index,
                resource_type=resource.resource_type,
                switch_id=switch_id,
                interface_name=name,
                raw_observation_sha256=sha256(
                    json.dumps(current, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
                ).hexdigest(),
                member_interfaces=tuple(member_interfaces),
            )
        )

    def _staged_subinterface_delete_echo(
        self,
        resource: InterfaceResourcePlan,
        desired: NDBaseModel,
        current_records: tuple[tuple[str, dict[str, Any]], ...],
    ) -> bool:
        """Recognize only an exact, preview-proven child deletion tombstone.

        TODO(4.2.1) staged-subinterface-delete-echo: Recheck this tombstone
        shape before changing the preview-proven exception.
        ND 4.2.1 and 4.3.1 can retype a deleted managed subinterface as structural
        ``ethernet`` while retaining a ``userDefined/interface_delete`` row.
        The row alone is not ownership proof: require the one-child preview to
        show the matching running header and no other pending command before
        allowing the already-staged deletion to be deployed.
        """

        if resource.state != "deleted" or resource.adapter.resource_type not in {"subinterface_managed", "subinterface_unmanaged"}:
            return False
        if len(current_records) != 1:
            return False
        switch_id, current = current_records[0]
        name = getattr(desired, "interface_name")
        policy = self._wire_policy(current)
        if (
            str(current.get("interfaceType") or "").casefold() != "ethernet"
            or str(current.get("interfaceName") or "").casefold() != name.casefold()
            or current.get("switchId") != switch_id
            or policy.get("policyType") != "userDefined"
            or policy.get("templateName") != "interface_delete"
        ):
            return False
        preview = resource.orchestrator._preview_interfaces({"interfaces": [{"interfaceName": name, "switchId": switch_id}]})
        pending_pairs, error = resource.orchestrator._pending_preview_pairs(preview, [(name, switch_id)])
        expected_pair = resource.orchestrator._normalized_interface_pair(name, switch_id)
        if error is not None or pending_pairs != {expected_pair}:
            return False
        row = preview["configurationDiffs"][0]
        configs = row["combinedConfigs"]
        running = [item.get("config") for item in configs if item["configType"].strip().lower() == "running"]
        pending = [item.get("config") for item in configs if item["configType"].strip().lower() == "pending"]
        if len(running) != 1 or len(pending) != 1 or not isinstance(running[0], str) or not isinstance(pending[0], str):
            return False
        running_headers = [line.strip().casefold() for line in running[0].splitlines() if line.strip().casefold().startswith("interface ")]
        pending_lines = [line.strip().casefold() for line in pending[0].splitlines() if line.strip()]
        expected_delete = f"no interface {name.casefold()}"
        if running_headers != [f"interface {name.casefold()}"] or pending_lines not in ([expected_delete], [expected_delete, "configure terminal"]):
            return False
        self._record_current_logical_deletion(resource, current, preview, name, switch_id)
        self._staged_delete_targets.append((name, switch_id))
        return True

    def _proven_vpc_discovery_echo(
        self,
        resource: InterfaceResourcePlan,
        desired: NDBaseModel,
        inventory: Mapping[tuple[str, str], dict[str, Any]],
    ) -> bool:
        """Classify a policy-less vPC echo only with exact two-peer preview proof."""

        if resource.state not in {"deleted", "merged", "replaced"} or resource.adapter.ownership_domain != "vpc":
            return False
        orchestrator = resource.orchestrator
        if not isinstance(orchestrator, VpcInterfaceBaseOrchestrator):
            return False
        switch_ip = getattr(desired, "switch_ip")
        primary_id = self.fabric_context.get_switch_id(switch_ip)
        scope = self._vpc_pair_scope(switch_ip)
        if len(scope) != 2:
            return False
        name = getattr(desired, "interface_name")
        present = [(switch_id, inventory[(switch_id, name.casefold())]) for switch_id in scope if (switch_id, name.casefold()) in inventory]
        if not present or any(current.get("switchId") != switch_id or not orchestrator._can_replay_absent_delete(current) for switch_id, current in present):
            return False
        preview = orchestrator._preview_interfaces({"interfaces": [{"interfaceName": name, "switchId": primary_id}]})
        expected_pairs = [(name, switch_id) for switch_id in scope]
        pending_pairs, error = orchestrator._pending_preview_pairs(preview, expected_pairs)
        expected_normalized = {orchestrator._normalized_interface_pair(*pair) for pair in expected_pairs}
        if error is not None:
            return False
        if not pending_pairs:
            # ND can retain a one-sided, policy-less discovery echo after a
            # deployed delete. Accept it as converged only when *both* exact
            # peer previews prove the interface is not discovered and have no
            # pending or expected CLI. An empty preview or ordinary running
            # config is not enough to waive pair consistency.
            sentinel = "interface is not discovered. current configuration is not available"
            for row in preview["configurationDiffs"]:
                configs = row["combinedConfigs"]
                by_type = {
                    kind: [item.get("config") for item in configs if item["configType"].strip().casefold() == kind]
                    for kind in ("running", "pending", "expected")
                }
                if (
                    len(by_type["running"]) != 1
                    or not isinstance(by_type["running"][0], str)
                    or by_type["running"][0].strip().casefold() != sentinel
                    or by_type["pending"] != [""]
                    or by_type["expected"] != [""]
                ):
                    return False
            self._converged_vpc_delete_targets.add((name.casefold(), primary_id))
            return True
        if pending_pairs != expected_normalized:
            return False
        if resource.state != "deleted":
            # A staged deletion is not an absent parent for a new create.
            return False
        try:
            footprints = orchestrator._validate_absent_vpc_delete_preview(
                preview,
                name,
                primary_id,
                next(switch_id for switch_id in scope if switch_id != primary_id),
            )
        except RuntimeError:
            return False
        self._staged_delete_targets.append((name, primary_id))
        self._vpc_staged_deletions.append(
            VpcStagedDeletionProof(
                resource_index=resource.resource_index,
                resource_type=resource.resource_type,
                switch_id=primary_id,
                interface_name=name,
                peer_switch_ids=scope,
                peer_footprints=footprints,
            )
        )
        return True

    def _staged_parent_running_members(
        self,
        orchestrator: NDBaseInterfaceOrchestrator,
        switch_id: str,
        po_id: str,
        inventory: Mapping[tuple[str, str], dict[str, Any]],
    ) -> set[str] | None:
        """Prove member ownership from the exact staged parent, not ND's cleared operData."""

        key = (switch_id, po_id)
        if key in self._staged_parent_member_cache:
            return self._staged_parent_member_cache[key]
        self._staged_parent_member_cache[key] = None
        name = f"port-channel{po_id}"
        parent = inventory.get((switch_id, name)) or {}
        policy = self._wire_policy(parent)
        if (
            self._canonical_interface_type(parent.get("interfaceType")) != "portChannel"
            or parent.get("switchId") != switch_id
            or self._wire_network_os_type(parent) != "nx-os"
            or policy.get("policyType") != "userDefined"
            or policy.get("templateName") != "interface_delete"
        ):
            return None
        preview = orchestrator._preview_interfaces({"interfaces": [{"interfaceName": name, "switchId": switch_id}]})
        pending_pairs, error = orchestrator._pending_preview_pairs(preview, [(name, switch_id)])
        if error is not None or pending_pairs != {orchestrator._normalized_interface_pair(name, switch_id)}:
            return None
        configs = preview["configurationDiffs"][0]["combinedConfigs"]
        running = [item.get("config") for item in configs if item["configType"].strip().casefold() == "running"]
        pending = [item.get("config") for item in configs if item["configType"].strip().casefold() == "pending"]
        if len(running) != 1 or len(pending) != 1 or not isinstance(running[0], str) or not isinstance(pending[0], str):
            return None
        running_lines = [line.strip().casefold() for line in running[0].splitlines() if line.strip()]
        pending_lines = [line.strip().casefold() for line in pending[0].splitlines() if line.strip()]
        if not running_lines or running_lines[0] != f"interface {name}" or not pending_lines or pending_lines[0] != f"no interface {name}":
            return None
        members: set[str] = set()
        member_commands: dict[str, set[str]] = defaultdict(set)
        current_member = None
        for line in running_lines[1:]:
            if (header := re.fullmatch(r"interface (ethernet[0-9/]+)", line)) is not None:
                current_member = header.group(1)
            elif line.startswith("interface "):
                current_member = None
            elif current_member is not None:
                member_commands[current_member].add(line)
                if (group := re.fullmatch(r"channel-group ([0-9]+) (?:force )?mode active", line)) is not None:
                    if group.group(1) != po_id:
                        return None
                    members.add(current_member)
        self._staged_parent_member_commands_cache[key] = {member: member_commands[member] for member in members}
        self._staged_parent_member_cache[key] = members
        return members

    def _staged_logical_delete_echo(
        self,
        resource: InterfaceResourcePlan,
        desired: NDBaseModel,
        current_records: tuple[tuple[str, dict[str, Any]], ...],
        inventory: Mapping[tuple[str, str], dict[str, Any]],
        requested_po_ids: set[tuple[str, str]],
    ) -> bool:
        """Replay only exact NX-OS logical deletions already staged by ND.

        A deployed logical delete can leave a ``userDefined/interface_delete``
        tombstone until its switch-side CLI is deployed. A port-channel preview
        may also reset members of other port-channels in the same delete task;
        every such member must be owned by a parent explicitly requested here.
        """

        family = resource.adapter.resource_type
        if resource.state != "deleted" or family not in {"svi", "loopback", "port_channel_access", "port_channel_trunk_host", "port_channel_routed"}:
            return False
        if len(current_records) != 1:
            return False
        switch_id, current = current_records[0]
        name = getattr(desired, "interface_name")
        policy = self._wire_policy(current)
        if (
            str(current.get("interfaceName") or "").casefold() != name.casefold()
            or current.get("switchId") != switch_id
            or self._canonical_interface_type(current.get("interfaceType")) not in resource.adapter.interface_types
            or self._wire_network_os_type(current) != "nx-os"
            or policy.get("policyType") != "userDefined"
            or policy.get("templateName") != "interface_delete"
        ):
            return False
        orchestrator = resource.orchestrator
        preview = orchestrator._preview_interfaces({"interfaces": [{"interfaceName": name, "switchId": switch_id}]})
        pending_pairs, error = orchestrator._pending_preview_pairs(preview, [(name, switch_id)])
        if error is not None or pending_pairs != {orchestrator._normalized_interface_pair(name, switch_id)}:
            return False
        row = preview["configurationDiffs"][0]
        configs = row["combinedConfigs"]
        running = [item.get("config") for item in configs if item["configType"].strip().lower() == "running"]
        pending = [item.get("config") for item in configs if item["configType"].strip().lower() == "pending"]
        if len(running) != 1 or len(pending) != 1 or not isinstance(running[0], str) or not isinstance(pending[0], str):
            return False
        running_lines = [line.strip().casefold() for line in running[0].splitlines() if line.strip()]
        pending_lines = [line.strip().casefold() for line in pending[0].splitlines() if line.strip()]
        if not running_lines or running_lines[0] != f"interface {name.casefold()}":
            return False
        if not pending_lines or pending_lines[0] != f"no interface {name.casefold()}":
            return False

        member_interfaces: tuple[str, ...] = ()
        preview_member_interfaces: tuple[str, ...] = ()
        preview_member_running_commands: dict[str, set[str]] = {}
        if family == "svi":
            svi_id = re.fullmatch(r"vlan([0-9]+)", name, re.IGNORECASE)
            allowed = {"configure terminal"}
            if svi_id is not None:
                allowed.add(f"no vlan {svi_id.group(1)}")
            if any(line not in allowed for line in pending_lines[1:]):
                return False
        elif family == "loopback":
            if any(line != "configure terminal" for line in pending_lines[1:]):
                return False
        else:
            parent_match = re.fullmatch(r"port-channel([0-9]+)", name, re.IGNORECASE)
            if parent_match is None:
                return False
            own_po_id = parent_match.group(1)
            # ND may clear operData.portChannelId as soon as deletion is staged,
            # while the exact parent preview still shows the switch running
            # config with its member attached. Keep that running CLI as a
            # narrow fallback for proving ownership of a member reset.
            running_member_groups: dict[str, str] = {}
            running_member_commands: dict[str, set[str]] = defaultdict(set)
            running_member = None
            for line in running_lines[1:]:
                if (header := re.fullmatch(r"interface (ethernet[0-9/]+)", line)) is not None:
                    running_member = header.group(1)
                elif line.startswith("interface "):
                    running_member = None
                elif running_member is not None:
                    running_member_commands[running_member].add(line)
                    if (group := re.fullmatch(r"channel-group ([0-9]+) (?:force )?mode active", line)) is not None:
                        previous_group = running_member_groups.get(running_member)
                        if previous_group is not None and previous_group != group.group(1):
                            return False
                        running_member_groups[running_member] = group.group(1)

            current_member = None
            current_po_id = None
            seen_members: set[str] = set()
            proven_members: set[str] = set()
            pending_member_owners: dict[str, str] = {}
            for line in pending_lines[1:]:
                if line == "configure terminal":
                    continue
                if (member := re.fullmatch(r"interface (ethernet[0-9/]+)", line)) is not None:
                    current_member = member.group(1)
                    seen_members.add(current_member)
                    raw_member = inventory.get((switch_id, current_member)) or {}
                    if raw_member.get("interfaceType") != "ethernet" or raw_member.get("switchId", switch_id) != switch_id:
                        return False
                    operational_po_id = str((raw_member.get("operData") or {}).get("portChannelId"))
                    current_po_id = pending_member_owners.get(current_member)
                    if current_po_id is None:
                        current_po_id = operational_po_id if operational_po_id not in {"-1", "0", "None", ""} else None
                    running_po_id = running_member_groups.get(current_member)
                    if running_po_id is not None and current_po_id is not None and running_po_id != current_po_id:
                        return False
                    current_po_id = current_po_id or running_po_id
                    if current_po_id is not None and (switch_id, current_po_id) not in requested_po_ids:
                        return False
                    continue
                if current_member is None:
                    return False
                if line.startswith("no channel-group "):
                    group = re.fullmatch(r"no channel-group ([0-9]+) force mode active", line)
                    if group is None:
                        return False
                    declared_po_id = group.group(1)
                    if (switch_id, declared_po_id) not in requested_po_ids or (current_po_id is not None and declared_po_id != current_po_id):
                        return False
                    # A requested ID alone is not proof that a different
                    # parent's removal is staged. Require its own tombstone
                    # and exact preview even when operData still names it.
                    if current_po_id is None or declared_po_id != own_po_id:
                        parent_members = self._staged_parent_running_members(orchestrator, switch_id, declared_po_id, inventory)
                        if parent_members is None or current_member not in parent_members:
                            return False
                    current_po_id = declared_po_id
                    pending_member_owners[current_member] = current_po_id
                    proven_members.add(current_member)
                    continue
                prior_commands = (
                    running_member_commands.get(current_member, set())
                    if current_po_id == own_po_id
                    else self._staged_parent_member_commands_cache.get((switch_id, current_po_id), {}).get(current_member, set())
                )
                remove_known_member_setting = (
                    current_member in proven_members
                    and line[3:] in prior_commands
                    and (
                        re.fullmatch(r"no mtu ([0-9]+)", line) is not None
                        and 576 <= int(line.split()[-1]) <= 9216
                        or re.fullmatch(r"no switchport (?:mode trunk|trunk allowed vlan [0-9,-]+)", line) is not None
                    )
                )
                raw_member = inventory.get((switch_id, current_member)) or {}
                routed_default_command = (
                    line == "no switchport"
                    and current_member in proven_members
                    and (raw_member.get("configData") or {}).get("mode") == "routed"
                    and self._wire_network_os_type(raw_member) == "nx-os"
                    and self._wire_policy(raw_member).get("policyType") == "routedHost"
                )
                allowed_member_command = (
                    remove_known_member_setting
                    or routed_default_command
                    or re.fullmatch(
                        r"no (?:storm-control (?:action .+|(?:broadcast|multicast|unicast) level .+)"
                        r"|switchport (?:access vlan|trunk native vlan) [0-9]+|switchport monitor"
                        r"|lacp (?:rate fast|port-priority [0-9]+)|description .+"
                        r"|duplex (?:full|half|auto)|speed [0-9]+"
                        r"|spanning-tree (?:bpdufilter|bpduguard) (?:enable|disable)"
                        r"|load-interval counter [0-9]+ [0-9]+)",
                        line,
                    )
                    or re.fullmatch(r"switchport(?: mode trunk| trunk allowed vlan none)?", line)
                    or re.fullmatch(r"mtu [0-9]+", line)
                    or line in {"spanning-tree port type edge trunk", "no shutdown", "cdp enable"}
                )
                if not allowed_member_command:
                    return False
            if seen_members != proven_members:
                return False
            # Publish only members independently named by BOTH this current
            # parent's running channel-group and its pending removal. A saved
            # historical member list is never authority for later correction.
            member_interfaces = tuple(
                sorted(
                    normalize_ethernet_interface_name(member)
                    for member, owner in pending_member_owners.items()
                    if owner == own_po_id and running_member_groups.get(member) == own_po_id
                )
            )
            preview_member_interfaces = tuple(sorted(seen_members))
            for member in seen_members:
                owner = pending_member_owners[member]
                if owner == own_po_id:
                    if running_member_groups.get(member) == owner:
                        preview_member_running_commands[member] = running_member_commands[member]
                else:
                    commands = self._staged_parent_member_commands_cache.get((switch_id, owner), {}).get(member)
                    if commands is not None:
                        preview_member_running_commands[member] = commands

        self._record_current_logical_deletion(
            resource,
            current,
            preview,
            name,
            switch_id,
            member_interfaces=member_interfaces,
            preview_member_interfaces=preview_member_interfaces,
            member_running_commands=preview_member_running_commands,
        )
        self._staged_delete_targets.append((name, switch_id))
        return True

    def _candidate_safety_errors(
        self,
        *,
        candidate: _PolicyRewriteCandidate,
        resource: InterfaceResourcePlan,
        summaries: Mapping[tuple[str, str], dict[str, Any]],
        action: str,
    ) -> list[str]:
        """Validate raw/summary agreement and controller eligibility."""
        desired_policy_type = self._desired_policy_type(candidate.desired)
        desired_network_os_type = self._desired_network_os_type(candidate.desired)
        label = f"resources[{resource.resource_index}] {getattr(candidate.desired, 'switch_ip')}/" f"{getattr(candidate.desired, 'interface_name')}"
        errors: list[str] = []
        if action == "transition":
            if desired_policy_type is None:
                return [f"{label} cannot {action} without a destination policy type."]
            if desired_network_os_type is None:
                return [f"{label} cannot {action} without a destination network-OS type."]

        for switch_id, current in candidate.current_records:
            interface_name = getattr(candidate.desired, "interface_name").lower()
            summary = summaries.get((switch_id, interface_name))
            if summary is None:
                errors.append(f"{label} cannot {action}: interfacesSummary has no exact row for {switch_id}/{interface_name}.")
                continue

            current_type = current.get("interfaceType")
            current_policy_type = InterfaceStateSnapshot.policy_type(current)
            summary_type = self._canonical_interface_type(summary.get("interfaceType"))
            current_type = self._canonical_interface_type(current_type)
            summary_policy_type = summary.get("policyType")
            current_network_os_type = self._wire_network_os_type(current)
            if summary.get("switchId") not in (None, switch_id):
                errors.append(f"{label} cannot {action}: interfacesSummary returned the wrong switch identity for {switch_id}.")
            if summary_type != current_type or summary_policy_type != current_policy_type:
                errors.append(
                    f"{label} cannot {action}: raw and summary records disagree on switch {switch_id} "
                    f"(interfaceType {current_type!r}/{summary_type!r}, policyType {current_policy_type!r}/{summary_policy_type!r})."
                )
            if current_policy_type is None:
                errors.append(f"{label} cannot {action}: the current policy type is missing on switch {switch_id}.")
            if action == "transition" and current_network_os_type != desired_network_os_type:
                errors.append(
                    f"{label} cannot {action}: current networkOSType {current_network_os_type!r} on switch {switch_id} "
                    f"is incompatible with destination {desired_network_os_type!r}."
                )

            blockers: list[str] = []
            if summary.get("editAllowed") is not True:
                blockers.append("editAllowed is not true")
            if summary.get("rbacAccessible") is not True:
                blockers.append("rbacAccessible is not true")
            if summary.get("blockConfig") is not False:
                blockers.append("blockConfig is not false")
            if summary.get("markDeleted") is not False:
                blockers.append("markDeleted is not false")
            if summary.get("hasDeletedOverlay") is not False:
                blockers.append("hasDeletedOverlay is not false")
            if action == "transition" or resource.adapter.delete_strategy == InterfaceDeleteStrategy.NORMALIZE:
                if summary.get("policyChangeSupported") is not True:
                    blockers.append("policyChangeSupported is not true")
            elif summary.get("deletable") is not True:
                blockers.append("deletable is not true")
            if blockers:
                reason = summary.get("editBlockReason")
                reason_suffix = f"; editBlockReason={reason!r}" if reason else ""
                errors.append(f"{label} cannot {action} on switch {switch_id}: {', '.join(blockers)}{reason_suffix}.")
        return errors

    def _rewrite_policy_operations(self, resources: list[InterfaceResourcePlan]) -> list[InterfaceResourcePlan]:
        """Plan implicit transitions and explicit policy-independent deletes."""
        inventory = self._inventory()
        children_by_parent = self._children_after_planned_deletes(inventory, resources)
        resources_by_index = {resource.resource_index: resource for resource in resources}
        creates_by_index = {resource.resource_index: list(resource.operations.creates) for resource in resources}
        deletes_by_index = {resource.resource_index: list(resource.operations.deletes) for resource in resources}
        transitions_by_index: dict[int, list[InterfacePolicyTransition]] = defaultdict(list)
        transition_candidates: list[_PolicyRewriteCandidate] = []
        delete_candidates: list[_PolicyRewriteCandidate] = []
        summary_identities: set[tuple[str, str]] = set()
        structural_collisions: list[InterfaceWorkflowConflict] = []
        errors: list[str] = []
        pair_validation_failures: set[tuple[int, Any]] = set()
        requested_po_ids: set[tuple[str, str]] = set()
        for resource in resources:
            if resource.state == "deleted" and resource.adapter.resource_type.startswith("port_channel_"):
                for desired in resource.proposed:
                    match = re.fullmatch(r"port-channel([0-9]+)", getattr(desired, "interface_name"), re.IGNORECASE)
                    if match is not None:
                        requested_po_ids.add((self.fabric_context.get_switch_id(getattr(desired, "switch_ip")), match.group(1)))

        for resource in resources:
            errors.extend(self._duplicate_member_errors(resource))
            if resource.adapter.safety.guards_child_subinterfaces:
                parent_writes: list[tuple[str, NDBaseModel]] = [("update", desired) for desired in resource.operations.updates]
                if resource.state not in resource.adapter.transition_states:
                    parent_writes.extend(("create", desired) for desired in resource.operations.creates)
                for action, desired in parent_writes:
                    current_records = self._current_records(resource.adapter, desired, inventory)
                    errors.extend(
                        self._dependency_errors(
                            resource=resource,
                            desired=desired,
                            current_records=current_records,
                            children_by_parent=children_by_parent,
                            action=action,
                            check_membership=False,
                        )
                    )
            if resource.state == "overridden" and resource.adapter.safety.guards_child_subinterfaces:
                for desired in resource.operations.deletes:
                    current_records = self._current_records(resource.adapter, desired, inventory)
                    errors.extend(
                        self._dependency_errors(
                            resource=resource,
                            desired=desired,
                            current_records=current_records,
                            children_by_parent=children_by_parent,
                            action="override-delete or reset",
                        )
                    )

            if resource.adapter.safety.requires_pair_consistency:
                checked: set[Any] = set()
                for desired in (*resource.proposed, *resource.operations.deletes):
                    identifier = desired.get_identifier_value()
                    if identifier in checked:
                        continue
                    checked.add(identifier)
                    try:
                        self._current_records(resource.adapter, desired, inventory)
                    except InterfaceWorkflowValidationError as exc:
                        if self._proven_vpc_discovery_echo(resource, desired, inventory):
                            continue
                        errors.append(f"resources[{resource.resource_index}] {exc}")
                        pair_validation_failures.add((resource.resource_index, identifier))

            if resource.state in resource.adapter.transition_states:
                retained_creates: list[NDBaseModel] = []
                for desired in resource.operations.creates:
                    if (resource.resource_index, desired.get_identifier_value()) in pair_validation_failures:
                        continue
                    if resource.adapter.ownership_domain == "vpc":
                        vpc_key = getattr(desired, "interface_name").casefold(), self.fabric_context.get_switch_id(getattr(desired, "switch_ip"))
                        if vpc_key in self._converged_vpc_delete_targets or self._proven_vpc_discovery_echo(resource, desired, inventory):
                            retained_creates.append(desired)
                            continue
                    try:
                        current_records = self._current_records(resource.adapter, desired, inventory)
                    except InterfaceWorkflowValidationError as exc:
                        errors.append(f"resources[{resource.resource_index}] {exc}")
                        continue
                    if not current_records:
                        retained_creates.append(desired)
                        continue
                    current_types = {self._canonical_interface_type(current.get("interfaceType")) for _switch_id, current in current_records}
                    if not current_types.issubset(resource.adapter.interface_types):
                        structural_collisions.append(self._structural_collision(resource, desired, current_records))
                        continue
                    default_ethernet = self._is_unconfigured_ethernet_default(resource.adapter, current_records)
                    errors.extend(
                        self._dependency_errors(
                            resource=resource,
                            desired=desired,
                            current_records=current_records,
                            children_by_parent=children_by_parent,
                            action="change policy",
                        )
                    )
                    if default_ethernet:
                        retained_creates.append(desired)
                        continue
                    current_policy_type = InterfaceStateSnapshot.policy_type(current_records[0][1])
                    if current_policy_type == self._desired_policy_type(desired):
                        retained_creates.append(desired)
                        continue
                    candidate = _PolicyRewriteCandidate(resource.resource_index, desired, current_records)
                    transition_candidates.append(candidate)
                    summary_identities.update((switch_id, getattr(desired, "interface_name")) for switch_id, _current in current_records)
                creates_by_index[resource.resource_index] = retained_creates

            if resource.state != "deleted":
                continue
            deletes_by_index[resource.resource_index] = []
            for desired in resource.proposed:
                if (resource.resource_index, desired.get_identifier_value()) in pair_validation_failures:
                    continue
                desired_target = getattr(desired, "interface_name"), self.fabric_context.get_switch_id(getattr(desired, "switch_ip"))
                if (desired_target[0].casefold(), desired_target[1]) in self._converged_vpc_delete_targets:
                    continue
                if desired_target in self._staged_delete_targets:
                    continue
                if self._proven_vpc_discovery_echo(resource, desired, inventory):
                    continue
                try:
                    current_records = self._current_records(resource.adapter, desired, inventory)
                except InterfaceWorkflowValidationError as exc:
                    errors.append(f"resources[{resource.resource_index}] {exc}")
                    continue
                if not current_records:
                    continue
                if self._staged_logical_delete_echo(resource, desired, current_records, inventory, requested_po_ids):
                    continue
                current_types = {self._canonical_interface_type(current.get("interfaceType")) for _switch_id, current in current_records}
                if not current_types.issubset(resource.adapter.interface_types):
                    if self._staged_subinterface_delete_echo(resource, desired, current_records):
                        continue
                    structural_collisions.append(self._structural_collision(resource, desired, current_records))
                    continue
                repair_reset = (
                    isinstance(resource.orchestrator, EthernetBaseOrchestrator)
                    and len(current_records) == 1
                    and resource.orchestrator.requires_reset_auto_negotiation(desired, current_records[0][1])
                )
                if self._is_unconfigured_ethernet_default(resource.adapter, current_records) and not repair_reset:
                    continue
                errors.extend(
                    self._dependency_errors(
                        resource=resource,
                        desired=desired,
                        current_records=current_records,
                        children_by_parent=children_by_parent,
                        action="delete or reset",
                    )
                )
                current_policy_type = InterfaceStateSnapshot.policy_type(current_records[0][1])
                if current_policy_type in resource.adapter.policy_types:
                    deletes_by_index[resource.resource_index].append(self._port_channel_delete_model(resource, desired, current_records))
                    continue
                candidate = _PolicyRewriteCandidate(resource.resource_index, desired, current_records)
                delete_candidates.append(candidate)
                summary_identities.update((switch_id, getattr(desired, "interface_name")) for switch_id, _current in current_records)

        if structural_collisions:
            raise InterfaceWorkflowConflictError(structural_collisions)
        if errors:
            raise InterfaceWorkflowValidationError("Interface policy operation validation failed: " + "; ".join(errors))

        summaries = self.snapshot.load_interface_summaries(summary_identities) if summary_identities else {}
        for action, candidates in (("transition", transition_candidates), ("delete or reset", delete_candidates)):
            for candidate in candidates:
                resource = resources_by_index[candidate.resource_index]
                errors.extend(
                    self._candidate_safety_errors(
                        candidate=candidate,
                        resource=resource,
                        summaries=summaries,
                        action=action,
                    )
                )
        if errors:
            raise InterfaceWorkflowValidationError("Interface policy safety validation failed: " + "; ".join(errors))

        for candidate in transition_candidates:
            resource = resources_by_index[candidate.resource_index]
            primary_id = self.fabric_context.get_switch_id(getattr(candidate.desired, "switch_ip"))
            current_by_switch = dict(candidate.current_records)
            current = current_by_switch.get(primary_id)
            if current is None:
                raise InterfaceWorkflowValidationError(
                    f"resources[{resource.resource_index}] cannot transition {getattr(candidate.desired, 'interface_name')}: "
                    f"the configured primary switch {primary_id} has no current record."
                )
            from_policy_type = InterfaceStateSnapshot.policy_type(current)
            to_policy_type = self._desired_policy_type(candidate.desired)
            if from_policy_type is None or to_policy_type is None:
                raise InterfaceWorkflowValidationError(f"resources[{resource.resource_index}] cannot transition without source and destination policy types.")
            transitions_by_index[resource.resource_index].append(
                InterfacePolicyTransition(
                    desired=candidate.desired,
                    current=current,
                    switch_ip=getattr(candidate.desired, "switch_ip"),
                    switch_id=primary_id,
                    interface_name=getattr(candidate.desired, "interface_name"),
                    from_policy_type=from_policy_type,
                    to_policy_type=to_policy_type,
                    current_records=candidate.current_records,
                )
            )
        for candidate in delete_candidates:
            resource = resources_by_index[candidate.resource_index]
            deletes_by_index[candidate.resource_index].append(self._port_channel_delete_model(resource, candidate.desired, candidate.current_records))

        updated_resources: list[InterfaceResourcePlan] = []
        for resource in resources:
            operations = replace(
                resource.operations,
                creates=tuple(creates_by_index[resource.resource_index]),
                deletes=tuple(deletes_by_index[resource.resource_index]),
            )
            updated_resources.append(
                replace(
                    resource,
                    operations=operations,
                    transitions=tuple(transitions_by_index[resource.resource_index]),
                    platform_deletes=self._platform_delete_models(resource, operations, inventory),
                )
            )
        return updated_resources

    @staticmethod
    def _iter_operations(resource: InterfaceResourcePlan) -> Iterable[tuple[str, NDBaseModel]]:
        """Yield action/model pairs in deterministic execution order."""
        for transition in resource.transitions:
            yield "transition", transition.desired
        for item in resource.operations.updates:
            yield "update", item
        for item in resource.operations.creates:
            yield "create", item
        for item in resource.operations.deletes:
            yield "delete", item

    def _split_member_preparations(self, resources: list[InterfaceResourcePlan]) -> list[InterfaceResourcePlan]:
        """Split standalone conversion from the final caller member update.

        Only explicit safe-field merged intent and one newly owning ordinary
        NX-OS port-channel qualify. Every existing membership, fabric link,
        child and host-policy guard remains authoritative.
        """
        claims: dict[InterfaceIdentity, list[_AggregateMemberClaim]] = defaultdict(list)
        for resource in resources:
            for claim in self._aggregate_member_claims(resource):
                claims[claim.member_identity].append(claim)
        rewritten = []
        for resource in resources:
            orchestrator = resource.orchestrator
            if resource.state != "merged" or not isinstance(orchestrator, EthernetBaseOrchestrator):
                rewritten.append(resource)
                continue
            preparation_switches = set()
            for explicit in resource.proposed:
                identity = self._identity(resource.adapter, explicit)
                final_claims = [claim for claim in claims.get(identity, ()) if claim.final]
                if (
                    len(final_claims) == 1
                    and not final_claims[0].current
                    and final_claims[0].action in {"create", "update"}
                    and final_claims[0].resource.adapter.ownership_domain == "port_channel"
                ):
                    preparation_switches.add(identity.scope[0])
            for switch_id in sorted(preparation_switches):
                peer_id = orchestrator._load_staged_detachment_peer(switch_id)
                if peer_id is not None:
                    self.snapshot.load_switch(peer_id)
                    cache = self._shared_vpc_peer_serial_cache()
                    for owner, peer in ((switch_id, peer_id), (peer_id, switch_id)):
                        if owner in cache and cache[owner] != peer:
                            raise InterfaceWorkflowValidationError("New member preparation has contradictory reciprocal peer evidence.")
                        cache[owner] = peer
            self._inventory_by_identity = self.snapshot.interfaces_by_identity
            self._membership_index = None
            prepares = []
            for action, model in self._iter_operations(resource):
                if action not in {"create", "transition"}:
                    continue
                identity = self._identity(resource.adapter, model)
                final_claims = [claim for claim in claims.get(identity, ()) if claim.final]
                if len(final_claims) != 1:
                    continue
                claim = final_claims[0]
                if claim.current or claim.action not in {"create", "update"} or claim.resource.adapter.ownership_domain != "port_channel":
                    continue
                descriptor = get_member_policy_descriptor_for_parent(self._desired_policy_type(claim.parent))
                if descriptor is None or descriptor.network_os != "nx-os" or descriptor.pair_aware or descriptor.family != orchestrator.MEMBER_FAMILY:
                    continue
                expected_host = orchestrator.MEMBER_PLANNING_SHAPES[(descriptor.family, descriptor.network_os)][1]
                current = self._inventory().get((identity.scope[0], identity.interface_name))
                if not isinstance(current, Mapping) or InterfaceStateSnapshot.policy_type(current) == expected_host:
                    continue
                if self._desired_policy_type(model) != expected_host or self._current_claims(identity):
                    continue
                explicit = resource.proposed.get(model.get_identifier_value())
                if explicit is None:
                    continue
                try:
                    orchestrator.validate_new_member_patch_intent(explicit)
                    orchestrator.validate_new_member_preparation(explicit, expected_current=current)
                except (RuntimeError, ValueError):
                    continue
                preparation = InterfaceMemberPreparation(
                    resource_index=resource.resource_index,
                    resource_type=resource.resource_type,
                    source_action=action,
                    switch_id=identity.scope[0],
                    interface_name=getattr(explicit, "interface_name"),
                    model=explicit,
                    current=deepcopy(current),
                    from_policy_type=InterfaceStateSnapshot.policy_type(current),
                    to_policy_type=expected_host,
                    parent_resource_index=claim.resource.resource_index,
                    parent_action=claim.action,
                    parent_switch_id=identity.scope[0],
                    parent_name=getattr(claim.parent, "interface_name"),
                    parent_policy_type=self._desired_policy_type(claim.parent),
                )
                prepares.append(preparation)
            prepared_ids = {preparation.model.get_identifier_value() for preparation in prepares}
            operation_ids = {model.get_identifier_value() for _action, model in self._iter_operations(resource)}
            retained_updates = []
            for explicit in resource.proposed:
                if explicit.get_identifier_value() in operation_ids:
                    continue
                identity = self._identity(resource.adapter, explicit)
                if self._new_member_patch_claim(identity, (resource, "update", explicit), claims.get(identity, [])) is not None:
                    retained_updates.append(explicit)
            if not prepared_ids and not retained_updates:
                rewritten.append(resource)
                continue
            self._member_preparations.extend(prepares)
            rewritten.append(
                replace(
                    resource,
                    operations=replace(
                        resource.operations,
                        creates=tuple(model for model in resource.operations.creates if model.get_identifier_value() not in prepared_ids),
                        updates=(*resource.operations.updates, *(preparation.model for preparation in prepares), *retained_updates),
                    ),
                    transitions=tuple(transition for transition in resource.transitions if transition.desired.get_identifier_value() not in prepared_ids),
                )
            )
        return rewritten

    def _operation_node(self, resource: InterfaceResourcePlan, action: str, model: NDBaseModel) -> InterfaceWorkflowOperation:
        """Build one immutable execution-graph node from a planned mutation."""

        return InterfaceWorkflowOperation(
            resource_index=resource.resource_index,
            resource_type=resource.resource_type,
            action=action,
            switch_id=self.fabric_context.get_switch_id(getattr(model, "switch_ip")),
            interface_name=getattr(model, "interface_name"),
            model=model,
        )

    @staticmethod
    def _operation_priority(operation: InterfaceWorkflowOperation) -> tuple[int, int, str, str]:
        """Prefer the legacy safe phase order when no dependency says otherwise."""

        action_order = {"delete": 0, "prepare_member": 1, "transition": 2, "update": 3, "create": 4}
        return (
            action_order[operation.action],
            operation.resource_index,
            operation.switch_id,
            operation.interface_name.casefold(),
        )

    def _build_execution_layers(
        self,
        resources: list[InterfaceResourcePlan],
    ) -> tuple[tuple[InterfaceWorkflowOperation, ...], ...]:
        """Topologically order mutations while retaining phase-sized batching.

        Every emitted layer contains one action kind.  Among currently ready
        operations, the scheduler prefers delete, transition, update, then
        create, preserving the workflow's historical ordering unless an exact
        parent/child or parent/member dependency requires an exception.
        """

        operations = [self._operation_node(resource, action, model) for resource in resources for action, model in self._iter_operations(resource)]
        operations.extend(
            InterfaceWorkflowOperation(
                resource_index=preparation.resource_index,
                resource_type=preparation.resource_type,
                action="prepare_member",
                switch_id=preparation.switch_id,
                interface_name=preparation.interface_name,
                model=preparation.model,
            )
            for preparation in self._member_preparations
        )
        by_key = {operation.key: operation for operation in operations}
        if len(by_key) != len(operations):
            raise InterfaceWorkflowValidationError("Interface execution graph contains duplicate operation identities.")

        edges, refresh_before = self._dependency_edges(resources, by_key)
        for key in refresh_before:
            by_key[key] = replace(by_key[key], refresh_before=True)
        successors: dict[tuple[int, str, str, str], set[tuple[int, str, str, str]]] = {key: set() for key in by_key}
        indegree = {key: 0 for key in by_key}
        for predecessor, successor in edges:
            if predecessor == successor or successor in successors[predecessor]:
                continue
            successors[predecessor].add(successor)
            indegree[successor] += 1

        layers: list[tuple[InterfaceWorkflowOperation, ...]] = []
        remaining = set(by_key)
        while remaining:
            ready = [by_key[key] for key in remaining if indegree[key] == 0]
            if not ready:
                cycle = sorted(f"resources[{key[0]}] {key[1]} {key[2]}/{key[3]}" for key in remaining)
                raise InterfaceWorkflowValidationError("Interface execution dependencies contain a cycle: " + ", ".join(cycle))
            minimum_action = min(self._operation_priority(operation)[0] for operation in ready)
            selected = tuple(
                sorted(
                    (operation for operation in ready if self._operation_priority(operation)[0] == minimum_action),
                    key=self._operation_priority,
                )
            )
            layers.append(selected)
            for operation in selected:
                remaining.remove(operation.key)
                for successor in successors[operation.key]:
                    indegree[successor] -= 1
        return tuple(layers)

    def _dependency_edges(
        self,
        resources: list[InterfaceResourcePlan],
        operations: Mapping[tuple[int, str, str, str], InterfaceWorkflowOperation],
    ) -> tuple[
        set[tuple[tuple[int, str, str, str], tuple[int, str, str, str]]],
        set[tuple[int, str, str, str]],
    ]:
        """Return mutation-order constraints and member updates needing fresh state."""

        edges: set[tuple[tuple[int, str, str, str], tuple[int, str, str, str]]] = set()
        refresh_before: set[tuple[int, str, str, str]] = set()
        planned_parents = self._planned_parent_operations(resources)
        for preparation in self._member_preparations:
            update_key = preparation.resource_index, "update", preparation.switch_id, preparation.interface_name.casefold()
            if preparation.key not in operations or preparation.parent_key not in operations or update_key not in operations:
                raise InterfaceWorkflowValidationError("A member preparation is missing its exact preparation, parent or final update operation.")
            edges.add((preparation.key, preparation.parent_key))
            edges.add((preparation.parent_key, update_key))
            refresh_before.add(update_key)
        for resource in resources:
            if resource.adapter.ownership_domain != "subinterface":
                continue
            for child_action, child_model in self._iter_operations(resource):
                child_name = getattr(child_model, "interface_name")
                if "." not in child_name:
                    continue
                switch_id = self.fabric_context.get_switch_id(getattr(child_model, "switch_ip"))
                child_key = resource.resource_index, child_action, switch_id, child_name.casefold()
                if child_key not in operations:
                    continue
                parent_identity = InterfaceIdentity("switch", (switch_id,), child_name.rsplit(".", 1)[0].casefold())
                for parent_resource, parent_action, parent_model in planned_parents.get(parent_identity, []):
                    parent_key = (
                        parent_resource.resource_index,
                        parent_action,
                        switch_id,
                        getattr(parent_model, "interface_name").casefold(),
                    )
                    if parent_key not in operations:
                        continue
                    if child_action == "delete":
                        edges.add((child_key, parent_key))
                    else:
                        edges.add((parent_key, child_key))

        aggregate_claims: dict[InterfaceIdentity, list[_AggregateMemberClaim]] = defaultdict(list)
        ethernet_operations: dict[InterfaceIdentity, list[tuple[InterfaceResourcePlan, str, NDBaseModel]]] = defaultdict(list)
        for resource in resources:
            if resource.adapter.ownership_domain == "ethernet":
                for action, model in self._iter_operations(resource):
                    ethernet_operations[self._identity(resource.adapter, model)].append((resource, action, model))
            for claim in self._aggregate_member_claims(resource):
                aggregate_claims[claim.member_identity].append(claim)

        for member_identity, ethernet_entries in ethernet_operations.items():
            member_claims = aggregate_claims.get(member_identity, [])
            if not member_claims:
                continue
            for ethernet_entry in ethernet_entries:
                interaction = self._ethernet_aggregate_interaction(
                    member_identity=member_identity,
                    ethernet_entry=ethernet_entry,
                    aggregate_claims=member_claims,
                )
                if interaction is None:
                    continue
                ethernet_resource, ethernet_action, ethernet_model = ethernet_entry
                ethernet_key = self._operation_node(ethernet_resource, ethernet_action, ethernet_model).key
                for claim in member_claims:
                    if not claim.final:
                        continue
                    parent_key = self._operation_node(claim.resource, claim.action, claim.parent).key
                    if ethernet_key not in operations or parent_key not in operations:
                        continue
                    if interaction == "required_host_conversion":
                        edges.add((ethernet_key, parent_key))
                    else:
                        edges.add((parent_key, ethernet_key))
                        # Parent PUTs can update controller-derived member fields
                        # such as portChannelMode/copyDescription.  The later
                        # member-safe PUT must reconstruct from a post-parent row,
                        # never from the planning snapshot.
                        refresh_before.add(ethernet_key)
        return edges, refresh_before

    def _parent_deployment_barriers(
        self,
        resources: list[InterfaceResourcePlan],
        layers: tuple[tuple[InterfaceWorkflowOperation, ...], ...],
    ) -> tuple[InterfaceWorkflowOperation, ...]:
        """Identify parent writes whose children need fresh routed discovery."""

        operations = {operation.key: operation for layer in layers for operation in layer}
        planned_parents = self._planned_parent_operations(resources)
        inventory = self._inventory()
        barriers: dict[tuple[int, str, str, str], InterfaceWorkflowOperation] = {}
        for resource in resources:
            if resource.adapter.ownership_domain != "subinterface":
                continue
            for child_action, child_model in self._iter_operations(resource):
                if child_action == "delete":
                    continue
                child_name = getattr(child_model, "interface_name")
                if "." not in child_name:
                    continue
                switch_id = self.fabric_context.get_switch_id(getattr(child_model, "switch_ip"))
                parent_name = child_name.rsplit(".", 1)[0].casefold()
                parent_identity = InterfaceIdentity("switch", (switch_id,), parent_name)
                parent = inventory.get((switch_id, parent_name))
                operational_mode = (parent.get("operData") or {}).get("mode") if parent else None
                configured_parent_ready = (
                    parent is not None
                    and self._routed_parent_contract_error(
                        interface_type=self._canonical_interface_type(parent.get("interfaceType")),
                        mode=self._wire_mode(parent),
                        policy_type=InterfaceStateSnapshot.policy_type(parent),
                        network_os_type=self._wire_network_os_type(parent),
                        child_network_os_type=self._desired_network_os_type(child_model),
                    )
                    is None
                )
                if configured_parent_ready and operational_mode == "routed":
                    continue
                for parent_resource, parent_action, parent_model in planned_parents.get(parent_identity, ()):
                    if parent_action == "delete":
                        continue
                    key = (
                        parent_resource.resource_index,
                        parent_action,
                        switch_id,
                        getattr(parent_model, "interface_name").casefold(),
                    )
                    if key in operations:
                        barriers[key] = operations[key]
        return tuple(sorted(barriers.values(), key=self._operation_priority))

    def _apply_preflight_projections(self, resources: list[InterfaceResourcePlan]) -> None:
        """Project only registry-required host conversions into the shared safety view.

        IOS-XE port-channel preflight validates the member's current host mode.
        When this same workflow has already proven and scheduled that exact
        conversion before the attach, its post-conversion payload is the safe
        state against which the parent preflight must run. No member-policy
        overlay is synthesized here.
        """

        aggregate_claims: dict[InterfaceIdentity, list[_AggregateMemberClaim]] = defaultdict(list)
        ethernet_operations: dict[InterfaceIdentity, list[tuple[InterfaceResourcePlan, str, NDBaseModel]]] = defaultdict(list)
        for resource in resources:
            if resource.adapter.ownership_domain == "ethernet":
                for action, model in self._iter_operations(resource):
                    ethernet_operations[self._identity(resource.adapter, model)].append((resource, action, model))
            for claim in self._aggregate_member_claims(resource):
                aggregate_claims[claim.member_identity].append(claim)

        overlays: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for preparation in self._member_preparations:
            payload = preparation.model.to_payload()
            payload["switchId"] = preparation.switch_id
            overlays[preparation.switch_id].append(payload)
        for member_identity, ethernet_entries in ethernet_operations.items():
            claims = aggregate_claims.get(member_identity, [])
            for ethernet_entry in ethernet_entries:
                if (
                    self._ethernet_aggregate_interaction(
                        member_identity=member_identity,
                        ethernet_entry=ethernet_entry,
                        aggregate_claims=claims,
                    )
                    != "required_host_conversion"
                ):
                    continue
                _resource, _action, model = ethernet_entry
                payload = model.to_payload()
                payload["switchId"] = member_identity.scope[0]
                overlays[member_identity.scope[0]].append(payload)

        for switch_id, upserts in overlays.items():
            self.snapshot.apply_overlay(switch_id, upserts=upserts)

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

        # A delete is a declaration of desired absence even when its sibling's
        # identical merged/replaced declaration produces no mutation. Compare
        # declarations, not only the later operation ledger.
        for resource in resources:
            if resource.state != "deleted":
                continue
            for item in resource.proposed:
                identity = self._identity(resource.adapter, item)
                other_claims = [claim for claim in desired_claims.get(identity, []) if claim.resource_index != resource.resource_index]
                if other_claims:
                    add(
                        "delete_desired_collision",
                        identity,
                        [resource, *other_claims],
                        f"resources[{resource.resource_index}] explicitly deletes {identity.label} while another group declares it desired.",
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

        self._find_subinterface_parent_prerequisite_conflicts(resources, add)
        self._find_existing_policy_conflicts(resources, add)
        self._find_member_conflicts(resources, add)
        return tuple(conflicts)

    def _planned_parent_operations(
        self,
        resources: Iterable[InterfaceResourcePlan],
    ) -> dict[InterfaceIdentity, list[tuple[InterfaceResourcePlan, str, NDBaseModel]]]:
        """Index mutations of physical and port-channel subinterface parents."""

        parent_writes: dict[InterfaceIdentity, list[tuple[InterfaceResourcePlan, str, NDBaseModel]]] = defaultdict(list)
        for resource in resources:
            if not resource.adapter.safety.guards_child_subinterfaces:
                continue
            for action, item in self._iter_operations(resource):
                switch_id = self.fabric_context.get_switch_id(getattr(item, "switch_ip"))
                parent_identity = InterfaceIdentity("switch", (switch_id,), getattr(item, "interface_name").lower())
                parent_writes[parent_identity].append((resource, action, item))
        return parent_writes

    @staticmethod
    def _routed_parent_contract_error(
        *,
        interface_type: Any,
        mode: Any,
        policy_type: Any,
        network_os_type: Any,
        child_network_os_type: str | None,
    ) -> str | None:
        """Return why a parent cannot host the child, or ``None`` when compatible."""

        contracts = {
            ("ethernet", "routedHost"): "nx-os",
            ("ethernet", "iosXeRoutedHost"): "ios-xe",
            ("portChannel", "l3Po"): "nx-os",
            ("portChannel", "iosXeL3PortChannel"): "ios-xe",
        }
        expected_network_os = contracts.get((interface_type, policy_type))
        if expected_network_os is None:
            expected_policies = sorted(policy for (candidate_type, policy), _network_os in contracts.items() if candidate_type == interface_type)
            if not expected_policies:
                return f"the parent has structural interfaceType {interface_type!r}, expected 'ethernet' or 'portChannel'"
            return f"the parent policyType is {policy_type!r}, expected one of {expected_policies}"
        if mode != "routed":
            return f"the parent mode is {mode!r}, expected 'routed'"
        if network_os_type != expected_network_os:
            return f"the parent policyType {policy_type!r} requires networkOSType {expected_network_os!r}, " f"but the parent reports {network_os_type!r}"
        if child_network_os_type is not None and child_network_os_type != expected_network_os:
            return f"the child network_os_type is {child_network_os_type!r}, but parent policyType {policy_type!r} " f"requires {expected_network_os!r}"
        return None

    def _find_subinterface_parent_prerequisite_conflicts(
        self,
        resources: list[InterfaceResourcePlan],
        add: Callable[..., None],
    ) -> None:
        """Require every written subinterface to have a compatible current or planned routed parent."""
        inventory = self._inventory()
        planned_parents = self._planned_parent_operations(resources)
        for resource in resources:
            if resource.adapter.ownership_domain != "subinterface":
                continue
            for action, item in self._iter_operations(resource):
                if action == "delete":
                    continue
                switch_id = self.fabric_context.get_switch_id(getattr(item, "switch_ip"))
                child_name = getattr(item, "interface_name")
                parent_name = child_name.rsplit(".", 1)[0].lower()
                parent_identity = InterfaceIdentity("switch", (switch_id,), parent_name)
                child_network_os_type = self._desired_network_os_type(item)
                parent_operations = planned_parents.get(parent_identity, [])
                if parent_operations:
                    parent_resource, parent_action, parent_model = parent_operations[0]
                    if parent_action == "delete":
                        reason = "the same workflow deletes the parent"
                    else:
                        parent_interface_type = next(iter(parent_resource.adapter.interface_types), None)
                        reason = self._routed_parent_contract_error(
                            interface_type=parent_interface_type,
                            mode=self._desired_mode(parent_model),
                            policy_type=self._desired_policy_type(parent_model),
                            network_os_type=self._desired_network_os_type(parent_model),
                            child_network_os_type=child_network_os_type,
                        )
                    if reason is None:
                        continue
                    participants = [parent_resource, resource]
                else:
                    participants = [resource]
                    current = inventory.get((switch_id, parent_name))
                    if current is None:
                        reason = "the parent does not exist in current controller inventory"
                    else:
                        reason = self._routed_parent_contract_error(
                            interface_type=self._canonical_interface_type(current.get("interfaceType")),
                            mode=self._wire_mode(current),
                            policy_type=InterfaceStateSnapshot.policy_type(current),
                            network_os_type=self._wire_network_os_type(current),
                            child_network_os_type=child_network_os_type,
                        )
                        if reason is None and str((current.get("operData") or {}).get("mode") or "").casefold() != "routed":
                            reason = (
                                "the parent is configured as routed but is not operationally discovered as routed; "
                                "deploy the parent in a separate task and wait for routed discovery before creating the child"
                            )
                    if reason is None:
                        continue
                add(
                    "subinterface_parent_prerequisite",
                    parent_identity,
                    participants,
                    f"Subinterface {switch_id}/{child_name} cannot perform action '{action}': {reason}. "
                    "Configure a compatible routed parent before the child operation.",
                )

    def _find_existing_policy_conflicts(self, resources: list[InterfaceResourcePlan], add: Callable[..., None]) -> None:
        """Reject creates that would collide with a sibling or unmanaged current policy."""
        inventory = self._inventory()
        policy_owner = {policy_type: adapter.resource_type for adapter in INTERFACE_FAMILY_ADAPTERS.values() for policy_type in adapter.policy_types}
        for resource in resources:
            for item in resource.operations.creates:
                switch_ip = getattr(item, "switch_ip")
                switch_id = self.fabric_context.get_switch_id(switch_ip)
                interface_name = getattr(item, "interface_name").lower()
                if resource.adapter.ownership_domain == "vpc" and (interface_name, switch_id) in self._converged_vpc_delete_targets:
                    # The exact two-peer preview proved this policy-less raw
                    # echo is absent from both devices and has no pending CLI.
                    continue
                scope = self._vpc_pair_scope(switch_ip) if resource.adapter.ownership_domain == "vpc" else (switch_id,)
                current_records = [inventory[(candidate_id, interface_name)] for candidate_id in scope if (candidate_id, interface_name) in inventory]
                for current in current_records:
                    if self._canonical_interface_type(current.get("interfaceType")) not in resource.adapter.interface_types:
                        identity = self._identity(resource.adapter, item)
                        add(
                            "structural_type_collision",
                            identity,
                            [resource],
                            f"resources[{resource.resource_index}] type '{resource.resource_type}' targets {identity.label}, but the "
                            f"same-name record has structural interfaceType {current.get('interfaceType')!r}; "
                            f"expected {sorted(resource.adapter.interface_types)}.",
                        )
                        continue
                    if resource.adapter.ownership_domain == "loopback" and resource.state in {"merged", "replaced"}:
                        # The standalone family excludes policyless discovery
                        # rows from its managed inventory and uses normal create
                        # requests. Preserve that behavior without extra policy
                        # checks, summary reads, or transition rewriting.
                        continue
                    policy_type = InterfaceStateSnapshot.policy_type(current)
                    if self._is_unconfigured_ethernet_default(resource.adapter, ((switch_id, current),)):
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
                        f"policyType '{policy_type}' is owned by {owner}; implicit policy transitions are supported only for "
                        f"{sorted(resource.adapter.transition_states)}, not state '{resource.state}'.",
                    )

    @staticmethod
    def _policy(model: NDBaseModel) -> Any | None:
        """Return a model's nested interface policy, if present."""
        config_data = getattr(model, "config_data", None)
        network_os = getattr(config_data, "network_os", None) if config_data is not None else None
        return getattr(network_os, "policy", None) if network_os is not None else None

    @classmethod
    def _configured_port_channel_id(cls, current: Mapping[str, Any] | None) -> int | None:
        """Return configured membership when ND operational data is stale."""
        if current is None:
            return None
        policy = cls._wire_policy(current)
        policy_type = policy.get("policyType")
        primary_interface = policy.get("primaryInterface")
        has_member_policy = isinstance(policy_type, str) and "pomember" in policy_type.lower()
        has_primary = isinstance(primary_interface, str) and bool(primary_interface.strip())
        if not has_member_policy and not has_primary:
            return None
        return normalize_port_channel_id(policy.get("portChannelId"))

    @classmethod
    def _effective_port_channel_id(cls, current: Mapping[str, Any] | None) -> int | None:
        """Prefer operational membership, then use the configured member-policy signal."""
        oper_data = current.get("operData") if isinstance(current, Mapping) else None
        operational_id = normalize_port_channel_id(oper_data.get("portChannelId")) if isinstance(oper_data, Mapping) else None
        return operational_id if operational_id is not None else cls._configured_port_channel_id(current)

    def _claim_identity(self, claim: ParentMembershipClaim) -> InterfaceIdentity:
        """Convert one authoritative membership-index claim to workflow identity."""

        if self._canonical_interface_type(claim.interface_type) != "vpc":
            return InterfaceIdentity("switch", (claim.switch_id,), claim.interface_name.casefold())
        policy = self._wire_policy(claim.record)
        peer_id = self._shared_vpc_peer_serial_cache().get(claim.switch_id)
        if peer_id is None:
            configured_peer_id = policy.get("peerSwitchId")
            if isinstance(configured_peer_id, str) and configured_peer_id and configured_peer_id != claim.switch_id:
                peer_id = configured_peer_id
        scope = tuple(sorted((claim.switch_id, peer_id))) if peer_id is not None else (claim.switch_id,)
        return InterfaceIdentity("vpc_pair", scope, claim.interface_name.casefold())

    def _claim_port_channel_ids(self, claim: ParentMembershipClaim) -> set[int]:
        """Return parent IDs associated with the exact fields that claim a member."""

        policy = self._wire_policy(claim.record)
        values: list[Any] = []
        if self._canonical_interface_type(claim.interface_type) == "portChannel":
            values.append(policy.get("portChannelId") or claim.interface_name)
        else:
            if "peer1MemberPorts" in claim.claim_fields:
                values.append(policy.get("peer1PortChannelId"))
            if "peer2MemberPorts" in claim.claim_fields:
                values.append(policy.get("peer2PortChannelId"))
        return {normalized for value in values if (normalized := normalize_port_channel_id(value)) is not None}

    def _current_claims(
        self,
        member_identity: InterfaceIdentity,
    ) -> tuple[tuple[ParentMembershipClaim, InterfaceIdentity, set[int]], ...]:
        """Return indexed parent claims with workflow identities and expected IDs."""

        switch_id = member_identity.scope[0]
        return tuple(
            (claim, self._claim_identity(claim), self._claim_port_channel_ids(claim))
            for claim in self._memberships().claiming_parents(switch_id, member_identity.interface_name)
        )

    def _aggregate_member_claims(self, resource: InterfaceResourcePlan) -> Iterable[_AggregateMemberClaim]:
        """Yield current and projected physical membership for aggregate mutations."""
        if not resource.adapter.safety.owns_physical_members:
            return

        inventory = self._inventory()
        for action, item in self._iter_operations(resource):
            final_policy = self._policy(item) if action != "delete" else None
            logical_identity = self._identity(resource.adapter, item)
            switch_ip = getattr(item, "switch_ip")
            primary_id = self.fabric_context.get_switch_id(switch_ip)
            interface_name = getattr(item, "interface_name").lower()
            current = inventory.get((primary_id, interface_name))
            current_policy = self._wire_policy(current or {})

            if resource.adapter.ownership_domain == "port_channel":
                current_members = set(self._member_names(current_policy.get("ports")))
                final_members = set(self._member_names(getattr(final_policy, "ports", None))) if final_policy is not None else set()
                for member in sorted(current_members | final_members, key=str.lower):
                    yield _AggregateMemberClaim(
                        resource=resource,
                        action=action,
                        parent=item,
                        member_identity=InterfaceIdentity("switch", (primary_id,), member),
                        owner_identity=logical_identity,
                        current=member in current_members,
                        final=member in final_members,
                    )
                continue

            pair_scope = self._vpc_pair_scope(switch_ip)
            peer_ids = [switch_id for switch_id in pair_scope if switch_id != primary_id]
            member_fields: tuple[tuple[str, str, str], ...] = (("peer1_member_ports", "peer1MemberPorts", primary_id),)
            if len(peer_ids) == 1:
                member_fields += (("peer2_member_ports", "peer2MemberPorts", peer_ids[0]),)
            for model_field, wire_field, switch_id in member_fields:
                current_members = set(self._member_names(current_policy.get(wire_field)))
                final_members = set(self._member_names(getattr(final_policy, model_field, None))) if final_policy is not None else set()
                for member in sorted(current_members | final_members, key=str.lower):
                    yield _AggregateMemberClaim(
                        resource=resource,
                        action=action,
                        parent=item,
                        member_identity=InterfaceIdentity("switch", (switch_id,), member),
                        owner_identity=logical_identity,
                        current=member in current_members,
                        final=member in final_members,
                    )

    def _validated_member_owner_identity(self, member_identity: InterfaceIdentity) -> InterfaceIdentity | None:
        """Return the owner proven by PR #561's membership service, if valid."""

        try:
            ownership = self._memberships().validate(member_identity.scope[0], member_identity.interface_name)
        except MembershipValidationError:
            return None
        owner_name = ownership.owner.interface_name.casefold()
        owner_switch_id = ownership.owner.switch_id
        for claim, owner_identity, _ids in self._current_claims(member_identity):
            if claim.switch_id == owner_switch_id and claim.interface_name.casefold() == owner_name:
                return owner_identity
        return None

    def _ethernet_aggregate_interaction(
        self,
        *,
        member_identity: InterfaceIdentity,
        ethernet_entry: tuple[InterfaceResourcePlan, str, NDBaseModel],
        aggregate_claims: list[_AggregateMemberClaim],
    ) -> str | None:
        """Classify a safe same-workflow parent/member interaction."""

        resource, action, model = ethernet_entry
        if not isinstance(resource.orchestrator, EthernetBaseOrchestrator) or action == "delete":
            return None
        final_claims = [claim for claim in aggregate_claims if claim.final]
        if len({claim.owner_identity for claim in final_claims}) != 1:
            return None

        current_member = self._memberships().get_member(member_identity.scope[0], member_identity.interface_name)
        if action == "update" and current_member is not None and current_member.descriptor is not None:
            validated_owner = self._validated_member_owner_identity(member_identity)
            if validated_owner is None:
                return None
            matching = [claim for claim in final_claims if claim.owner_identity == validated_owner]
            final_descriptors = {get_member_policy_descriptor_for_parent(self._desired_policy_type(claim.parent)) for claim in matching}
            if matching and any(claim.current for claim in matching) and final_descriptors == {current_member.descriptor}:
                return "safe_member_update"
            return None

        if self._new_member_patch_claim(member_identity, ethernet_entry, aggregate_claims) is not None:
            return "new_member_safe_update"

        if current_member is not None or self._current_claims(member_identity):
            return None
        current = self._inventory().get((member_identity.scope[0], member_identity.interface_name))
        if self._effective_port_channel_id(current) is not None:
            return None
        desired_policy_type = self._desired_policy_type(model)
        for claim in final_claims:
            if claim.current:
                continue
            descriptor = get_member_policy_descriptor_for_parent(self._desired_policy_type(claim.parent))
            if descriptor is not None and descriptor.required_host_policy_type == desired_policy_type:
                return "required_host_conversion"
        return None

    def _new_member_patch_claim(
        self,
        member_identity: InterfaceIdentity,
        ethernet_entry: tuple[InterfaceResourcePlan, str, NDBaseModel],
        aggregate_claims: list[_AggregateMemberClaim],
    ) -> _AggregateMemberClaim | None:
        """Qualify a safe patch that must wait for an explicit new NX-OS owner.

        This grants ordering only. The executor must refresh after the parent
        write and prove authentic membership before a member-preserving PUT.
        No policy conversion, existing ownership, vPC, or unsafe field is
        inferred from desired state.
        """
        resource, action, model = ethernet_entry
        orchestrator = resource.orchestrator
        if not isinstance(orchestrator, EthernetBaseOrchestrator) or action != "update" or resource.state != "merged":
            return None
        final_claims = [claim for claim in aggregate_claims if claim.final]
        if len(final_claims) != 1:
            return None
        claim = final_claims[0]
        if claim.current or claim.action not in {"create", "update"} or claim.resource.adapter.ownership_domain != "port_channel":
            return None
        descriptor = get_member_policy_descriptor_for_parent(self._desired_policy_type(claim.parent))
        if descriptor is None or descriptor.network_os != "nx-os" or descriptor.pair_aware or descriptor.family != orchestrator.MEMBER_FAMILY:
            return None
        if self._memberships().get_member(member_identity.scope[0], member_identity.interface_name) is not None or self._current_claims(member_identity):
            return None
        current = self._inventory().get((member_identity.scope[0], member_identity.interface_name))
        if not isinstance(current, Mapping) or current.get("interfaceType") != "ethernet" or self._effective_port_channel_id(current) is not None:
            return None
        expected_host = orchestrator.MEMBER_PLANNING_SHAPES[(descriptor.family, descriptor.network_os)][1]
        prepared = next(
            (
                preparation
                for preparation in self._member_preparations
                if preparation.resource_index == resource.resource_index
                and preparation.switch_id == member_identity.scope[0]
                and preparation.interface_name.casefold() == member_identity.interface_name
                and preparation.parent_key == self._operation_node(claim.resource, claim.action, claim.parent).key
            ),
            None,
        )
        if (InterfaceStateSnapshot.policy_type(current) != expected_host and prepared is None) or self._desired_policy_type(model) != expected_host:
            return None
        explicit = resource.proposed.get(model.get_identifier_value())
        if explicit is None:
            return None
        try:
            orchestrator.validate_new_member_patch_intent(explicit)
            if prepared is None:
                orchestrator.validate_new_member_preparation(explicit, expected_current=current)
        except (RuntimeError, ValueError):
            return None
        return claim

    def _find_member_conflicts(
        self,
        resources: list[InterfaceResourcePlan],
        add: Callable[..., None],
    ) -> None:
        """Reject duplicate member ownership and simultaneous Ethernet/member edits."""
        claims: dict[InterfaceIdentity, list[_AggregateMemberClaim]] = defaultdict(list)
        ethernet_actions: dict[
            InterfaceIdentity,
            list[tuple[InterfaceResourcePlan, str, NDBaseModel]],
        ] = defaultdict(list)
        inventory = self._inventory()
        for resource in resources:
            if resource.adapter.ownership_domain == "ethernet":
                for action, item in self._iter_operations(resource):
                    ethernet_actions[self._identity(resource.adapter, item)].append((resource, action, item))
        for resource in resources:
            for claim in self._aggregate_member_claims(resource):
                claims[claim.member_identity].append(claim)

        for member_identity, entries in claims.items():
            logical_identities = {claim.owner_identity for claim in entries}
            participants = [claim.resource for claim in entries]
            if len(logical_identities) > 1:
                add(
                    "duplicate_member_ownership",
                    member_identity,
                    participants,
                    f"Physical member {member_identity.label} is a current or final member of multiple aggregate interfaces.",
                )
            indexed_claims = self._current_claims(member_identity)
            existing_owners = {owner for _claim, owner, _ids in indexed_claims}
            ethernet = inventory.get((member_identity.scope[0], member_identity.interface_name))
            indexed_member = self._memberships().get_member(member_identity.scope[0], member_identity.interface_name)
            if indexed_member is not None:
                try:
                    ownership = self._memberships().validate(member_identity.scope[0], member_identity.interface_name)
                except MembershipValidationError as exc:
                    add(
                        "member_ownership_validation",
                        member_identity,
                        participants,
                        f"Physical member {member_identity.label} failed authoritative membership validation: {exc}.",
                    )
                else:
                    validated_owner = next(
                        (
                            owner
                            for claim, owner, _ids in indexed_claims
                            if claim.switch_id == ownership.owner.switch_id and claim.interface_name.casefold() == ownership.owner.interface_name.casefold()
                        ),
                        None,
                    )
                    if validated_owner not in logical_identities:
                        add(
                            "existing_member_ownership",
                            member_identity,
                            participants,
                            f"Physical member {member_identity.label} is owned by aggregate interface "
                            f"{ownership.owner.interface_name!r}, not by the requested aggregate.",
                        )
            else:
                foreign_owners = existing_owners - logical_identities
                if foreign_owners:
                    add(
                        "existing_member_ownership",
                        member_identity,
                        participants,
                        f"Physical member {member_identity.label} is already owned by aggregate interface(s) "
                        f"{sorted(owner.label for owner in foreign_owners)}.",
                    )
                port_channel_id = self._effective_port_channel_id(ethernet)
                if port_channel_id is None:
                    matching_owners = set()
                    expected_ids = set()
                else:
                    matching_owners = existing_owners.intersection(logical_identities)
                    expected_ids = {expected_id for _claim, owner, owner_ids in indexed_claims if owner in matching_owners for expected_id in owner_ids}
                if port_channel_id is not None and (not matching_owners or not expected_ids):
                    add(
                        "operational_member_ownership",
                        member_identity,
                        participants,
                        f"Physical member {member_identity.label} reports operational port-channel membership "
                        f"{port_channel_id}, but no matching aggregate owner and ID can be proven from raw inventory.",
                    )
                elif port_channel_id is not None and port_channel_id not in expected_ids:
                    add(
                        "operational_member_mismatch",
                        member_identity,
                        participants,
                        f"Physical member {member_identity.label} reports operational port-channel membership "
                        f"{port_channel_id}, but its matching aggregate owner expects {sorted(expected_ids)}.",
                    )
            ethernet_entries = ethernet_actions.get(member_identity, [])
            if ethernet_entries:
                unsafe_entries = [
                    entry
                    for entry in ethernet_entries
                    if self._ethernet_aggregate_interaction(
                        member_identity=member_identity,
                        ethernet_entry=entry,
                        aggregate_claims=entries,
                    )
                    is None
                ]
                if unsafe_entries:
                    add(
                        "ethernet_member_collision",
                        member_identity,
                        [*participants, *(resource for resource, _action, _item in unsafe_entries)],
                        f"Physical member {member_identity.label} is mutated as Ethernet while protected as a current or final aggregate member.",
                    )

        for member_identity, ethernet_entries in ethernet_actions.items():
            if member_identity in claims:
                continue
            indexed_claims = self._current_claims(member_identity)
            existing_owners = {owner for _claim, owner, _ids in indexed_claims}
            ethernet = inventory.get((member_identity.scope[0], member_identity.interface_name))
            configured_id = self._configured_port_channel_id(ethernet)
            oper_data = ethernet.get("operData") if isinstance(ethernet, Mapping) else None
            operational_id = normalize_port_channel_id(oper_data.get("portChannelId")) if isinstance(oper_data, Mapping) else None
            if not existing_owners and configured_id is None and operational_id is None:
                continue

            protected: list[InterfaceResourcePlan] = []
            for resource, action, item in ethernet_entries:
                if action != "update":
                    protected.append(resource)
                    continue
                if not isinstance(resource.orchestrator, EthernetBaseOrchestrator):
                    protected.append(resource)
                    continue
                policy_type = InterfaceStateSnapshot.policy_type(ethernet or {})
                # A same-family UPDATE is decided by PR #561's authoritative
                # member service during preflight. Let it produce the precise
                # inconsistent-operational, orphan, wrong-family, or safe-field
                # result. A host-policy row that a cached parent still claims is
                # not an authentic member and remains protected here.
                if existing_owners and get_member_policy_descriptor(policy_type) is None:
                    protected.append(resource)
            if protected:
                add(
                    "ethernet_member_collision",
                    member_identity,
                    protected,
                    f"Physical member {member_identity.label} is mutated as Ethernet while owned by current aggregate "
                    f"interface(s) {sorted(owner.label for owner in existing_owners)}.",
                )

    def _run_preflights(self, resources: list[InterfaceResourcePlan]) -> None:
        """Run explicit-delete, local create, and optional API-backed capability guards after conflicts."""
        aggregate_claims: dict[InterfaceIdentity, list[_AggregateMemberClaim]] = defaultdict(list)
        for parent_resource in resources:
            for claim in self._aggregate_member_claims(parent_resource):
                aggregate_claims[claim.member_identity].append(claim)
        for resource in resources:
            try:
                if resource.state == "deleted":
                    resource.orchestrator.preflight_delete(list(resource.operations.deletes))
                    if resource.platform_deletes:
                        resource.orchestrator.preflight_delete(list(resource.platform_deletes))
                    continue
                if isinstance(resource.orchestrator, EthernetBaseOrchestrator):
                    update_identifiers = {model.get_identifier_value() for model in resource.operations.updates}
                    explicit_updates = [model for model in resource.proposed if model.get_identifier_value() in update_identifiers]
                    resource.orchestrator.prepare_member_update_intents(explicit_updates)
                    for model in explicit_updates:
                        identity = self._identity(resource.adapter, model)
                        claim = self._new_member_patch_claim(identity, (resource, "update", model), aggregate_claims.get(identity, []))
                        if claim is not None:
                            resource.orchestrator.prepare_new_member_patch_intent(
                                model,
                                parent_switch_id=claim.owner_identity.scope[0],
                                parent_name=getattr(claim.parent, "interface_name"),
                                parent_policy_type=self._desired_policy_type(claim.parent),
                            )
                create_candidates = [*resource.operations.creates, *(transition.desired for transition in resource.transitions)]
                create_candidates.extend(
                    preparation.model for preparation in self._member_preparations if preparation.resource_index == resource.resource_index
                )
                resource.orchestrator.preflight_create(create_candidates)
                mutation_candidates = [
                    *(transition.desired for transition in resource.transitions),
                    *resource.operations.updates,
                    *resource.operations.creates,
                ]
                resource.orchestrator.preflight_safety(mutation_candidates)
                if self.run_capability_preflight:
                    resource.orchestrator.validate_switches_capable(mutation_candidates)
                # The removal guard compares the complete desired set, including
                # unchanged retained interfaces, against existing inventory.
                resource.orchestrator._check_overridden_removals_discovered(list(resource.proposed))
            except Exception as exc:
                raise InterfaceWorkflowValidationError(
                    f"resources[{resource.resource_index}] type '{resource.resource_type}' preflight failed: {exc}"
                ) from exc
