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
from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import InterfaceStateSnapshot
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_plan import NDStatePlan
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import EthernetBaseOrchestrator
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

    def plan(self, resources: list[dict[str, Any]]) -> InterfaceWorkflowPlan:
        """Return a complete read-only plan or raise before any mutation method is called."""
        validated = self._validate_resource_groups(resources)
        target_switch_ids = self._target_switch_ids(validated)
        self.snapshot.load_switches(target_switch_ids)
        self._inventory_by_identity = self.snapshot.interfaces_by_identity

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
                before = self._existing_collection(adapter, orchestrator, proposed)
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

        resource_plans = self._rewrite_policy_operations(resource_plans)
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

    def _validate_resource_groups(
        self, resources: list[dict[str, Any]]
    ) -> list[tuple[int, InterfaceFamilyAdapter, str, NDConfigCollection]]:
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

    def _target_switch_ids(
        self, validated: list[tuple[int, InterfaceFamilyAdapter, str, NDConfigCollection]]
    ) -> tuple[str, ...]:
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

    def _vpc_pair_scopes_by_switch_id(self) -> dict[str, tuple[str, ...]]:
        """Return authoritative pair scopes indexed by either member switch ID."""
        scopes: dict[str, tuple[str, ...]] = {}
        for switch_ip in self.vpc_pair_by_switch_ip:
            scope = self._vpc_pair_scope(switch_ip)
            if len(scope) == 2:
                for switch_id in scope:
                    scopes[switch_id] = scope
        return scopes

    def _shared_vpc_peer_serial_cache(self) -> dict[str, str]:
        """Return one authoritative peer cache shared by all workflow vPC orchestrators."""
        if self._vpc_peer_serial_cache is None:
            cache: dict[str, str] = {}
            for switch_ip in self.vpc_pair_by_switch_ip:
                primary_id = self.fabric_context.get_switch_id(switch_ip)
                scope = self._vpc_pair_scope(switch_ip)
                if len(scope) == 2:
                    cache[primary_id] = next(switch_id for switch_id in scope if switch_id != primary_id)
            self._vpc_peer_serial_cache = cache
        return self._vpc_peer_serial_cache

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
        scopes_by_switch_id = self._vpc_pair_scopes_by_switch_id()
        preferred_switch_by_key = {
            (
                self._vpc_pair_scope(getattr(item, "switch_ip")),
                getattr(item, "interface_name").lower(),
            ): self.fabric_context.get_switch_id(getattr(item, "switch_ip"))
            for item in proposed
        }
        selected: dict[tuple[tuple[str, ...], str], tuple[tuple[int, str], str, dict[str, Any]]] = {}
        for (switch_id, interface_name), current in self._inventory().items():
            if self._canonical_interface_type(current.get("interfaceType")) != "vpc":
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
            enriched["switchIp"] = self.fabric_context.get_switch_ip(switch_id)
            response.append(enriched)
        return NDConfigCollection.from_api_response(response_data=response, model_class=adapter.model_class)

    @classmethod
    def _desired_policy_type(cls, model: NDBaseModel) -> str | None:
        """Return the destination model's frozen wire policy discriminator."""
        policy = cls._policy(model)
        policy_type = getattr(policy, "policy_type", None) if policy is not None else None
        value = getattr(policy_type, "value", policy_type)
        return value if isinstance(value, str) and value else None

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
    def _canonical_interface_type(value: Any) -> Any:
        """Normalize known raw/summary interface-type aliases."""
        return {"switchVirtualInterface": "svi"}.get(value, value)

    @classmethod
    def _vpc_record_fingerprint(
        cls,
        current: Mapping[str, Any],
        switch_id: str,
        scope: tuple[str, ...],
    ) -> Any:
        """Return peer-independent configured vPC state for pair comparison."""

        peer_ids = [candidate for candidate in scope if candidate != switch_id]
        peer_id = peer_ids[0] if len(peer_ids) == 1 else None

        def scrub(value: Any) -> Any:
            if isinstance(value, Mapping):
                ignored = {"switchId", "peerSwitchId", "policyId"}
                normalized = {}
                for key, item in value.items():
                    if key in ignored:
                        continue
                    normalized_key = key
                    if key.startswith("peer1") and len(key) > 5:
                        normalized_key = f"peer[{switch_id}]{key[5:]}"
                    elif peer_id is not None and key.startswith("peer2") and len(key) > 5:
                        normalized_key = f"peer[{peer_id}]{key[5:]}"
                    normalized_item = scrub(item)
                    if key.endswith("MemberPorts") and isinstance(item, list) and all(isinstance(member, str) for member in item):
                        normalized_item = tuple(sorted(member.strip().lower() for member in item))
                    normalized[normalized_key] = normalized_item
                return normalized
            if isinstance(value, list):
                return [scrub(item) for item in value]
            return value

        return scrub(deepcopy(current.get("configData") or {}))

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
            raise InterfaceWorkflowValidationError(
                f"{label} requires an authoritative two-switch vPC pair; resolved scope is {list(scope)}."
            )
        present = tuple((switch_id, inventory[(switch_id, interface_name)]) for switch_id in scope if (switch_id, interface_name) in inventory)
        if not present:
            return ()
        if len(present) != 2:
            missing = sorted(set(scope) - {switch_id for switch_id, _current in present})
            raise InterfaceWorkflowValidationError(
                f"{label} has inconsistent vPC pair state: the interface record is missing on peer(s) {missing}."
            )

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
        fingerprints = [self._vpc_record_fingerprint(current, switch_id, scope) for switch_id, current in present]
        if len(interface_types) != 1 or len(policy_types) != 1 or fingerprints[0] != fingerprints[1]:
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

    @staticmethod
    def _is_unconfigured_ethernet_default(
        adapter: InterfaceFamilyAdapter,
        current_records: tuple[tuple[str, dict[str, Any]], ...],
    ) -> bool:
        """Return whether one physical port is already at the fabric default."""
        return (
            adapter.delete_strategy == InterfaceDeleteStrategy.NORMALIZE
            and len(current_records) == 1
            and InterfaceStateSnapshot.policy_type(current_records[0][1]) == "trunkHost"
            and EthernetTrunkHostInterfaceOrchestrator._is_unconfigured_default(current_records[0][1])
        )

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
                errors.append(
                    f"{label} cannot {action} while it is a member of port-channel {port_channel_id}. Remove the membership first."
                )
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
        return tuple(
            member.strip().lower()
            for item in values
            if isinstance(item, str) and (member := item.strip())
        )

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
            fields = (
                ("ports",)
                if resource.adapter.ownership_domain == "port_channel"
                else ("peer1_member_ports", "peer2_member_ports")
            )
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
        label = (
            f"resources[{resource.resource_index}] {getattr(candidate.desired, 'switch_ip')}/"
            f"{getattr(candidate.desired, 'interface_name')}"
        )
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
        children_by_parent = self._children_by_parent(inventory)
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
            if isinstance(resource.orchestrator, EthernetBaseOrchestrator):
                for desired in resource.operations.updates:
                    switch_id = self.fabric_context.get_switch_id(getattr(desired, "switch_ip"))
                    current = inventory.get((switch_id, getattr(desired, "interface_name").lower()))
                    try:
                        resource.orchestrator._check_port_channel_restrictions(
                            desired,
                            self._ethernet_membership_record(current),
                        )
                    except Exception as exc:
                        errors.append(
                            f"resources[{resource.resource_index}] cannot update "
                            f"{getattr(desired, 'switch_ip')}/{getattr(desired, 'interface_name')}: {exc}"
                        )
            if resource.adapter.safety.guards_child_subinterfaces:
                parent_writes: list[tuple[str, NDBaseModel]] = [
                    ("update", desired)
                    for desired in resource.operations.updates
                ]
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
                    current_types = {
                        self._canonical_interface_type(current.get("interfaceType"))
                        for _switch_id, current in current_records
                    }
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
                    if current_policy_type in resource.adapter.policy_types:
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
                current_types = {
                    self._canonical_interface_type(current.get("interfaceType"))
                    for _switch_id, current in current_records
                }
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
                raise InterfaceWorkflowValidationError(
                    f"resources[{resource.resource_index}] cannot transition without source and destination policy types."
                )
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

        self._find_parent_subinterface_conflicts(resources, add)
        self._find_subinterface_parent_prerequisite_conflicts(resources, add)
        self._find_existing_policy_conflicts(resources, add)
        self._find_member_conflicts(resources, add)
        return tuple(conflicts)

    def _find_parent_subinterface_conflicts(self, resources: list[InterfaceResourcePlan], add: Callable[..., None]) -> None:
        """Reject any parent mutation combined with a child mutation."""
        parent_writes: dict[InterfaceIdentity, list[InterfaceResourcePlan]] = defaultdict(list)
        for resource in resources:
            if not resource.adapter.safety.guards_child_subinterfaces:
                continue
            for _action, item in self._iter_operations(resource):
                switch_id = self.fabric_context.get_switch_id(getattr(item, "switch_ip"))
                parent_identity = InterfaceIdentity("switch", (switch_id,), getattr(item, "interface_name").lower())
                parent_writes[parent_identity].append(resource)

        for resource in resources:
            if resource.adapter.ownership_domain != "subinterface":
                continue
            for action, item in self._iter_operations(resource):
                child_name = getattr(item, "interface_name")
                if "." not in child_name:
                    continue
                switch_id = self.fabric_context.get_switch_id(getattr(item, "switch_ip"))
                parent_identity = InterfaceIdentity("switch", (switch_id,), child_name.rsplit(".", 1)[0].lower())
                parent_resources = parent_writes.get(parent_identity, [])
                if not parent_resources:
                    continue
                add(
                    "parent_subinterface_collision",
                    parent_identity,
                    [*parent_resources, resource],
                    f"{parent_identity.label} is mutated while child subinterface '{child_name}' has action '{action}'; "
                    "split parent and child operations into separate workflows.",
                )

    def _find_subinterface_parent_prerequisite_conflicts(
        self,
        resources: list[InterfaceResourcePlan],
        add: Callable[..., None],
    ) -> None:
        """Require every written subinterface to have an existing routed parent."""
        inventory = self._inventory()
        routed_policy_by_type = {
            "ethernet": "routedHost",
            "portChannel": "l3PortChannel",
        }
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
                current = inventory.get((switch_id, parent_name))
                if current is None:
                    reason = "the parent does not exist in current controller inventory"
                else:
                    interface_type = self._canonical_interface_type(current.get("interfaceType"))
                    required_policy = routed_policy_by_type.get(interface_type)
                    if required_policy is None:
                        reason = (
                            f"the parent has structural interfaceType {current.get('interfaceType')!r}, "
                            "expected 'ethernet' or 'portChannel'"
                        )
                    else:
                        policy_type = InterfaceStateSnapshot.policy_type(current)
                        if policy_type == required_policy:
                            continue
                        reason = (
                            f"the parent policyType is {policy_type!r}, "
                            f"expected routed policy {required_policy!r}"
                        )
                add(
                    "subinterface_parent_prerequisite",
                    parent_identity,
                    [resource],
                    f"Subinterface {switch_id}/{child_name} cannot perform action '{action}': {reason}. "
                    "Configure the routed parent in a separate completed workflow first.",
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
                        f"policyType '{policy_type}' is owned by {owner}; implicit policy transitions are supported only for "
                        f"{sorted(resource.adapter.transition_states)}, not state '{resource.state}'.",
                    )

    @staticmethod
    def _policy(model: NDBaseModel) -> Any | None:
        """Return a model's nested interface policy, if present."""
        config_data = getattr(model, "config_data", None)
        network_os = getattr(config_data, "network_os", None) if config_data is not None else None
        return getattr(network_os, "policy", None) if network_os is not None else None

    @staticmethod
    def _positive_port_channel_id(value: Any) -> int | None:
        """Return a positive numeric port-channel identifier."""
        if isinstance(value, int) and value > 0:
            return value
        if isinstance(value, str):
            candidate = value.lower().removeprefix("port-channel")
            if candidate.isdigit() and int(candidate) > 0:
                return int(candidate)
        return None

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
        return cls._positive_port_channel_id(policy.get("portChannelId"))

    @classmethod
    def _effective_port_channel_id(cls, current: Mapping[str, Any] | None) -> int | None:
        """Prefer operational membership, then use the configured member-policy signal."""
        operational_id = EthernetTrunkHostInterfaceOrchestrator._existing_port_channel_id(current)
        return operational_id if operational_id is not None else cls._configured_port_channel_id(current)

    @classmethod
    def _ethernet_membership_record(cls, current: dict[str, Any] | None) -> dict[str, Any] | None:
        """Expose configured membership to the existing whitelist checker."""
        if current is None or EthernetTrunkHostInterfaceOrchestrator._existing_port_channel_id(current) is not None:
            return current
        configured_id = cls._configured_port_channel_id(current)
        if configured_id is None:
            return current
        effective = deepcopy(current)
        effective["operData"] = {**(effective.get("operData") or {}), "portChannelId": configured_id}
        return effective

    def _current_member_owners(
        self,
    ) -> tuple[
        dict[InterfaceIdentity, set[InterfaceIdentity]],
        dict[InterfaceIdentity, dict[InterfaceIdentity, set[int]]],
    ]:
        """Index aggregate owners and their expected operational port-channel IDs."""
        owners: dict[InterfaceIdentity, set[InterfaceIdentity]] = defaultdict(set)
        owner_ids: dict[InterfaceIdentity, dict[InterfaceIdentity, set[int]]] = defaultdict(lambda: defaultdict(set))
        known_vpc_scope: dict[str, tuple[str, ...]] = {}
        for switch_ip in self.vpc_pair_by_switch_ip:
            scope = self._vpc_pair_scope(switch_ip)
            if len(scope) == 2:
                for switch_id in scope:
                    known_vpc_scope[switch_id] = scope

        def register(member: InterfaceIdentity, owner: InterfaceIdentity, port_channel_id: Any) -> None:
            owners[member].add(owner)
            if (normalized_id := self._positive_port_channel_id(port_channel_id)) is not None:
                owner_ids[member][owner].add(normalized_id)

        for (switch_id, interface_name), current in self._inventory().items():
            interface_type = self._canonical_interface_type(current.get("interfaceType"))
            policy = self._wire_policy(current)
            if interface_type == "portChannel":
                owner = InterfaceIdentity("switch", (switch_id,), interface_name)
                port_channel_id = self._positive_port_channel_id(policy.get("portChannelId"))
                if port_channel_id is None:
                    port_channel_id = self._positive_port_channel_id(interface_name)
                for member in self._member_names(policy.get("ports")):
                    register(InterfaceIdentity("switch", (switch_id,), member), owner, port_channel_id)
                continue
            if interface_type != "vpc":
                continue

            configured_peer_id = policy.get("peerSwitchId")
            authoritative_scope = known_vpc_scope.get(switch_id)
            if authoritative_scope is not None:
                peer_id = next(candidate for candidate in authoritative_scope if candidate != switch_id)
                if configured_peer_id is not None and configured_peer_id != peer_id:
                    raise InterfaceWorkflowValidationError(
                        f"Raw vPC owner {switch_id}/{interface_name} reports peerSwitchId {configured_peer_id!r}, "
                        f"expected {peer_id!r} from authoritative pair inventory."
                    )
                scope = authoritative_scope
            else:
                peer_id = configured_peer_id
                has_raw_peer = isinstance(peer_id, str) and bool(peer_id) and peer_id != switch_id
                scope = tuple(sorted((switch_id, peer_id))) if has_raw_peer else (switch_id,)

            has_peer = isinstance(peer_id, str) and bool(peer_id) and peer_id != switch_id
            owner = InterfaceIdentity("vpc_pair", scope, interface_name)
            for member in self._member_names(policy.get("peer1MemberPorts")):
                register(
                    InterfaceIdentity("switch", (switch_id,), member),
                    owner,
                    policy.get("peer1PortChannelId"),
                )
            if has_peer:
                for member in self._member_names(policy.get("peer2MemberPorts")):
                    register(
                        InterfaceIdentity("switch", (peer_id,), member),
                        owner,
                        policy.get("peer2PortChannelId"),
                    )
        return owners, owner_ids

    def _protected_member_claims(self, resource: InterfaceResourcePlan) -> Iterable[tuple[InterfaceIdentity, InterfaceIdentity]]:
        """Yield current and final physical members protected by one aggregate action."""
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
                    yield InterfaceIdentity("switch", (primary_id,), member), logical_identity
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
                    yield InterfaceIdentity("switch", (switch_id,), member), logical_identity

    def _find_member_conflicts(
        self,
        resources: list[InterfaceResourcePlan],
        add: Callable[..., None],
    ) -> None:
        """Reject duplicate member ownership and simultaneous Ethernet/member edits."""
        claims: dict[InterfaceIdentity, list[tuple[InterfaceResourcePlan, InterfaceIdentity]]] = defaultdict(list)
        ethernet_actions: dict[
            InterfaceIdentity,
            list[tuple[InterfaceResourcePlan, str, NDBaseModel]],
        ] = defaultdict(list)
        current_owners, current_owner_ids = self._current_member_owners()
        inventory = self._inventory()
        for resource in resources:
            if resource.adapter.ownership_domain == "ethernet":
                for action, item in self._iter_operations(resource):
                    ethernet_actions[self._identity(resource.adapter, item)].append((resource, action, item))
        for resource in resources:
            for member_identity, logical_identity in self._protected_member_claims(resource):
                claims[member_identity].append((resource, logical_identity))

        for member_identity, entries in claims.items():
            logical_identities = {logical_identity for _resource, logical_identity in entries}
            participants = [resource for resource, _logical_identity in entries]
            if len(logical_identities) > 1:
                add(
                    "duplicate_member_ownership",
                    member_identity,
                    participants,
                    f"Physical member {member_identity.label} is a current or final member of multiple aggregate interfaces.",
                )
            existing_owners = current_owners.get(member_identity, set())
            foreign_owners = existing_owners - logical_identities
            if foreign_owners:
                add(
                    "existing_member_ownership",
                    member_identity,
                    participants,
                    f"Physical member {member_identity.label} is already owned by aggregate interface(s) "
                    f"{sorted(owner.label for owner in foreign_owners)}.",
                )
            ethernet = inventory.get((member_identity.scope[0], member_identity.interface_name))
            port_channel_id = self._effective_port_channel_id(ethernet)
            if port_channel_id is not None:
                matching_owners = existing_owners.intersection(logical_identities)
                expected_ids = {
                    expected_id
                    for owner in matching_owners
                    for expected_id in current_owner_ids.get(member_identity, {}).get(owner, set())
                }
                if not matching_owners or not expected_ids:
                    add(
                        "operational_member_ownership",
                        member_identity,
                        participants,
                        f"Physical member {member_identity.label} reports operational port-channel membership "
                        f"{port_channel_id}, but no matching aggregate owner and ID can be proven from raw inventory.",
                    )
                elif port_channel_id not in expected_ids:
                    add(
                        "operational_member_mismatch",
                        member_identity,
                        participants,
                        f"Physical member {member_identity.label} reports operational port-channel membership "
                        f"{port_channel_id}, but its matching aggregate owner expects {sorted(expected_ids)}.",
                    )
            ethernet_entries = ethernet_actions.get(member_identity, [])
            if ethernet_entries:
                add(
                    "ethernet_member_collision",
                    member_identity,
                    [*participants, *(resource for resource, _action, _item in ethernet_entries)],
                    f"Physical member {member_identity.label} is mutated as Ethernet while protected as a current or final aggregate member.",
                )

        for member_identity, ethernet_entries in ethernet_actions.items():
            if member_identity in claims:
                continue
            existing_owners = current_owners.get(member_identity, set())
            ethernet = inventory.get((member_identity.scope[0], member_identity.interface_name))
            configured_id = self._configured_port_channel_id(ethernet)
            operational_id = EthernetTrunkHostInterfaceOrchestrator._existing_port_channel_id(ethernet)
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
                membership_record = self._ethernet_membership_record(ethernet)
                if membership_record is ethernet and operational_id is None:
                    expected_ids = {
                        expected_id
                        for owner in existing_owners
                        for expected_id in current_owner_ids.get(member_identity, {}).get(owner, set())
                    }
                    membership_record = deepcopy(ethernet) if ethernet is not None else {}
                    membership_record["operData"] = {
                        **(membership_record.get("operData") or {}),
                        "portChannelId": min(expected_ids) if expected_ids else 1,
                    }
                try:
                    resource.orchestrator._check_port_channel_restrictions(item, membership_record)
                except Exception:
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
        """Run local create guards and optional API-backed capability checks after conflicts."""
        for resource in resources:
            if resource.state == "deleted":
                continue
            try:
                create_candidates = [*resource.operations.creates, *(transition.desired for transition in resource.transitions)]
                resource.orchestrator.preflight_create(create_candidates)
                if self.run_capability_preflight:
                    resource.orchestrator.preflight(list(resource.proposed))
            except Exception as exc:
                raise InterfaceWorkflowValidationError(
                    f"resources[{resource.resource_index}] type '{resource.resource_type}' preflight failed: {exc}"
                ) from exc
