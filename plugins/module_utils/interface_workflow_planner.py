# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Read-only planning and cross-family conflict detection for interfaces."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass, field, replace
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
class InterfaceWorkflowPlan:
    """Complete mutation-free plan across all requested interface families."""

    fabric_name: str
    target_switch_ids: tuple[str, ...]
    resources: tuple[InterfaceResourcePlan, ...]
    request_stats: dict[str, int]
    auxiliary_orchestrators: tuple[NDBaseInterfaceOrchestrator, ...] = field(default=(), repr=False, compare=False)
    execution_layers: tuple[tuple[InterfaceWorkflowOperation, ...], ...] = field(default=(), repr=False, compare=False)
    parent_deployment_barriers: tuple[InterfaceWorkflowOperation, ...] = field(default=(), repr=False, compare=False)

    @property
    def changed(self) -> bool:
        """Return whether any resource group has a planned mutation."""
        return any(resource.changed for resource in self.resources)

    @property
    def mutation_count(self) -> int:
        """Return the total planned mutation count."""
        return sum(resource.mutation_count for resource in self.resources)

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
        self._vpc_peer_serial_cache: dict[str, str] | None = None
        self._inventory_by_identity: dict[tuple[str, str], dict[str, Any]] | None = None
        self._membership_index: EthernetMembershipIndex | None = None
        self._ethernet_link_cache_owner: EthernetBaseOrchestrator | None = None

    def plan(self, resources: list[dict[str, Any]]) -> InterfaceWorkflowPlan:
        """Return a complete read-only plan or raise before any mutation method is called."""
        validated = self._validate_resource_groups(resources)
        target_switch_ids = self._target_switch_ids(validated)
        self.snapshot.load_switches(target_switch_ids)
        self._inventory_by_identity = self.snapshot.interfaces_by_identity
        self._membership_index = None

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

        resource_plans = self._rewrite_policy_operations(resource_plans)
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
            auxiliary_orchestrators=auxiliary_orchestrators,
            execution_layers=execution_layers,
            parent_deployment_barriers=parent_deployment_barriers,
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

        Some ND echoes preserve the original peer1/peer2 orientation; ND 4.3.1 can instead
        echo peer1 as the reporting switch and peer2 as its peer. Both forms are compared
        explicitly by ``_vpc_records_match``. Member-port spelling and ordering are only
        presentation differences.
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
        """Accept identical echoes or a verified reciprocal local/remote peer-field echo."""
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

    def _register_ethernet_orchestrator(self, orchestrator: EthernetBaseOrchestrator) -> None:
        """Share one lazy fabric-link cache across every Ethernet family in this workflow."""
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
                        errors.append(f"resources[{resource.resource_index}] {exc}")
                        pair_validation_failures.add((resource.resource_index, identifier))

            if resource.state in resource.adapter.transition_states:
                retained_creates: list[NDBaseModel] = []
                for desired in resource.operations.creates:
                    if (resource.resource_index, desired.get_identifier_value()) in pair_validation_failures:
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
                try:
                    current_records = self._current_records(resource.adapter, desired, inventory)
                except InterfaceWorkflowValidationError as exc:
                    errors.append(f"resources[{resource.resource_index}] {exc}")
                    continue
                if not current_records:
                    continue
                current_types = {self._canonical_interface_type(current.get("interfaceType")) for _switch_id, current in current_records}
                if not current_types.issubset(resource.adapter.interface_types):
                    structural_collisions.append(self._structural_collision(resource, desired, current_records))
                    continue
                if self._is_unconfigured_ethernet_default(resource.adapter, current_records):
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
                    deletes_by_index[resource.resource_index].append(desired)
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
            deletes_by_index[candidate.resource_index].append(candidate.desired)

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

        action_order = {"delete": 0, "transition": 1, "update": 2, "create": 3}
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
                create_candidates = [*resource.operations.creates, *(transition.desired for transition in resource.transitions)]
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
