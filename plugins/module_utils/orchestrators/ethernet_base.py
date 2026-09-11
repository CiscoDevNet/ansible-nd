# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# pyright: reportAttributeAccessIssue=false
# ModelType is NDBaseModel which lacks interface-specific fields (switch_ip,
# interface_name, config_data). Concrete subclasses always bind ModelType to a
# model that provides these fields, so the accesses are safe at runtime.

"""
Base orchestrator for ethernet interface modules on Nexus Dashboard.

This module provides `EthernetBaseOrchestrator`, which implements shared CRUD operations
for all ethernet interface types (accessHost, trunkHost, routed, etc.) via the ND Manage
Interfaces API. Type-specific orchestrators inherit from this base and provide their own
`model_class` and `_managed_policy_types()`.

Inherits shared interface lifecycle operations (deploy queuing, fabric validation, switch
resolution) from `NDBaseInterfaceOrchestrator` and adds ethernet-specific functionality:
- Normalize-based deletion (physical interfaces cannot be deleted via remove/DELETE)
- Port-channel membership enforcement with a whitelisted field set
- Fabric-wide `query_all()` with per-type policy filtering
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Sequence
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, ClassVar

logger = logging.getLogger(__name__)

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_vpc_pair import (
    EpVpcPairGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesNormalize,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_membership import (
    EthernetMembershipIndex,
    MissingPeerInventoryError,
    MissingPeerIdentityError,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_member_interface import (
    MemberPolicyDisposition,
    build_member_update_payload,
    classify_member_policy,
    get_member_policy_descriptor,
    normalize_safe_member_updates,
    parse_member_interface_response,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.interface_default_config import (
    InterfaceDefaultConfig,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import (
    NDBaseInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import (
    ResponseType,
)

ModelType = NDBaseModel


@dataclass(frozen=True)
class MemberUpdateIntent:
    """Original caller intent retained while the state machine merges a planning projection."""

    requested_state: str
    effective_state: str
    requested_fields: frozenset[str]
    requested_values: dict[str, Any]


class EthernetBaseOrchestrator(NDBaseInterfaceOrchestrator[ModelType]):
    """
    # Summary

    Base orchestrator for ethernet interface CRUD operations on Nexus Dashboard.

    Provides shared logic for all ethernet interface types. Subclasses must set `model_class` and implement
    `_managed_policy_types()` to define which policy types they manage.

    Supports configuring interfaces across multiple switches in a single task. Each config item
    includes a `switch_ip` that is resolved to a `switchId` via `FabricContext`.

    Mutation methods (`create`, `update`) enforce port-channel membership restrictions and queue deploys
    for bulk execution. Call `deploy_pending` after all mutations are complete.

    ## Raises

    ### RuntimeError

    - Via `validate_prerequisites` if the fabric does not exist or is in deployment-freeze mode.
    - Via `_resolve_switch_id` if no switch matches the given IP in the fabric.
    - Via `_check_port_channel_restrictions` if a non-whitelisted field is modified on a port-channel member.
    - Via `create` if the create API request fails.
    - Via `update` if the update API request fails.
    - Via `remove_pending` if the bulk normalize API request fails.
    - Via `deploy_pending` if the bulk deploy API request fails.
    - Via `query_one` if the query API request fails.
    - Via `query_all` if the query API request fails.
    """

    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() uses bulk normalize
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesPost
    # TODO(4.2.1) physical-interface-delete-unsupported
    # Physical ethernet interfaces cannot be deleted: interfaceActions/remove silently no-ops and the per-interface
    # DELETE returns HTTP 500, so delete is implemented as interfaceActions/normalize with the full int_trunk_host
    # template body (InterfaceDefaultConfig), which resets the interface and drops it from type-specific query filters.
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesNormalize

    PORT_CHANNEL_MODIFIABLE_FIELDS: ClassVar[set[str]] = {
        "description",
        "admin_state",
        "extra_config",
    }
    MEMBER_FAMILY: ClassVar[str] = ""
    MEMBER_PLANNING_SHAPES: ClassVar[dict[tuple[str, str], tuple[str, str]]] = {
        ("access", "nx-os"): ("access", "accessHost"),
        ("trunk", "nx-os"): ("trunk", "trunkHost"),
        ("routed", "nx-os"): ("routed", "routedHost"),
        ("routed", "ios-xe"): ("routed", "iosXeRoutedHost"),
    }
    MEMBER_SAFE_FIELD_ALIASES: ClassVar[dict[str, str]] = {
        "admin_state": "adminState",
        "description": "description",
        "extra_config": "extraConfig",
    }

    # Policy types a create/update may OVERWRITE on an existing interface: the host-facing ethernet policy types a user can create
    # through the ND 4.2.1 create-side OpenAPI discriminators (`createInterfaceEthernet{Trunk,Access,Routed,Pvlan,Dot1qTunnel,
    # Unmanaged}{Nexus,Xe}Type`, `policyType` mappings), minus `userDefined` and minus the fabric-provisioned types those mappings also
    # list for IOS-XE (`iosXeNumbered`, `csrMultisiteIfcMember`, `iosXeInternalL3PoMember`, the stackwise link types). Everything
    # else on the wire (`numbered`, `unnumbered`, `vrfLiteLinkMember`, `multiSiteLinkMember`, `vpcPeerKeepAlive`, `mplsUplink`, ...)
    # is fabric-owned link intent that ND stamps on the interface itself (lab-verified 2026-09-03, ND 4.2.1: SITE1 leaf->spine links
    # carry `numbered`, the BGW VRF-Lite member `vrfLiteLinkMember`, the multisite underlay member `multiSiteLinkMember`), and a
    # mistyped `interface_name` must not be able to replace it. See `_check_fabric_ownership` (PR #550 review).
    CONVERTIBLE_POLICY_TYPES: ClassVar[frozenset[str]] = frozenset(
        {
            # NX-OS trunk / access / pvlan / dot1q-tunnel / monitor
            "trunkHost",
            "classicHost",
            "ipfmTrunkHost",
            "dataBrokerHost",
            "dataBrokerPoMember",
            "accessHost",
            "ipfmAccessHost",
            "pvlanHost",
            "dot1qTunnelHost",
            "monitor",
            # NX-OS routed
            "routedHost",
            "endPointLocator",
            "ipfmL3Port",
            "dataBrokerL3Host",
            # IOS-XE host-facing
            "iosXeTrunkHost",
            "iosXeAccess",
            "iosXeMonitor",
            "iosXeRoutedHost",
        }
    )

    def model_post_init(self, __context) -> None:
        """
        # Summary

        Initialize ethernet-specific mutable private state after Pydantic model construction. Extends
        `NDBaseInterfaceOrchestrator.model_post_init` to add the normalize and reset queues (initialized
        the same way as the sibling `_pending_deploys` / `_pending_removes` queues).

        ## Raises

        None
        """
        super().model_post_init(__context)
        self._pending_normalizes: list[tuple[str, str]] = []
        self._pending_resets: list[tuple[str, str]] = []
        self._member_records: dict[tuple[str, str], dict] = {}
        self._member_intents: dict[tuple[str, str], MemberUpdateIntent] = {}
        self._validated_member_ownership: dict[tuple[str, str], Any] = {}
        self._membership_index_cache = None
        self._membership_index_inventory_switches: frozenset[str] = frozenset()
        self._member_peer_serial_cache: dict[str, str] = {}

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator. Subclasses must override this method
        to return their specific policy types (e.g., `{"accessHost"}` for the access orchestrator).

        ## Raises

        ### NotImplementedError

        - Always, if not overridden by a subclass.
        """
        raise NotImplementedError("Subclasses must implement _managed_policy_types()")

    def _queue_normalize(self, interface_name: str, switch_id: str) -> None:
        """
        # Summary

        Queue an `(interface_name, switch_id)` pair for deferred normalization. Call `remove_pending` after all mutations
        are complete to normalize in bulk via `interfaceActions/normalize`.

        ## Raises

        None
        """
        pair = (interface_name, switch_id)
        if pair not in self._pending_normalizes:
            self._pending_normalizes.append(pair)

    def _queue_reset(self, interface_name: str, switch_id: str) -> None:
        """
        # Summary

        Queue an `(interface_name, switch_id)` pair for deferred per-interface PUT-as-replace reset. Used when the existing
        wire state carries one of `InterfaceDefaultConfig.UNRESETTABLE_FIELDS` (`bandwidth`, `debounceLinkupTimer`,
        `inheritBandwidth`) — the normalize endpoint cannot clear those, so the orchestrator falls back to a per-interface
        PUT with a minimal body that lets ND apply schema defaults. Call `remove_pending` after all mutations are complete
        to flush the queue.

        ## Raises

        None
        """
        pair = (interface_name, switch_id)
        if pair not in self._pending_resets:
            self._pending_resets.append(pair)

    @staticmethod
    def _has_unresettable_fields(existing_data: dict | None) -> bool:
        """
        # Summary

        Return `True` if the interface's existing wire policy carries any field in `InterfaceDefaultConfig.UNRESETTABLE_FIELDS`
        with a non-null value. These fields persist across `interfaceActions/normalize` because ND's validator rejects 0/null
        on them; the orchestrator routes such interfaces to the PUT-as-replace path on `state: deleted` so they actually clear.

        ## Raises

        None
        """
        if existing_data is None:
            return False
        policy = existing_data.get("configData", {}).get("networkOS", {}).get("policy") or {}
        return any(policy.get(field) is not None for field in InterfaceDefaultConfig.UNRESETTABLE_FIELDS)

    def _existing_interface(self, interface_name: str, switch_id: str) -> dict | None:
        """
        # Summary

        Return the current wire-state dict for `interface_name` on `switch_id`, or `None` when the
        interface is absent from the switch inventory. Backed by the `_switch_interfaces` cache, so
        repeated lookups across `create` / `update` / `create_bulk` add no further requests.

        ## Raises

        ### RuntimeError

        - Via `_switch_interfaces` if the interface-list API request fails.
        """
        return self._switch_interfaces(switch_id).get(interface_name.lower())

    def _canonical_task_interface_name(self, switch_ip: str, interface_name: str) -> str:
        """Normalize a task interface name through the concrete host model.

        Discovery runs before the state machine creates its proposed collection, but member
        projections must still match abbreviations such as e1/24 and gi3 to the controller's
        canonical names. Identifier-only construction invokes the same field validator used
        later by planning.
        """
        try:
            identity = self.model_class.from_config(
                {"switch_ip": switch_ip, "interface_name": interface_name},
                context={"state": "deleted"},
            )
            return identity.interface_name
        except Exception:  # Invalid input is reported by normal proposed-model validation.
            return interface_name

    def _named_member_targets(self) -> set[tuple[str, str]]:
        """Return canonical (switch_ip, lower_name) targets explicitly named by the task."""
        targets: set[tuple[str, str]] = set()
        params = self.rest_send.params if self.rest_send and self.rest_send.params else {}
        for item in params.get("config") or []:
            if not isinstance(item, dict):
                continue
            switch_ip = item.get("switch_ip")
            interface_name = item.get("interface_name")
            if not isinstance(switch_ip, str) or not isinstance(interface_name, str):
                continue
            canonical = self._canonical_task_interface_name(switch_ip, interface_name)
            targets.add((switch_ip, canonical.lower()))
        return targets

    def _member_planning_projection(self, member_record: dict, switch_ip: str) -> dict:
        """Return a host-shaped, read-only planning projection for one authentic member.

        The state machine can only compare instances of the public host model. Projecting the
        member's identity and three safe properties lets it classify a named member as UPDATE,
        while the untouched authentic record remains in _member_records for payload
        construction. Membership metadata is deliberately absent from this projection.
        """
        member = parse_member_interface_response(member_record)
        descriptor = member.descriptor
        shape = self.MEMBER_PLANNING_SHAPES.get((descriptor.family, descriptor.network_os))
        if shape is None:
            raise RuntimeError(
                f"No host planning shape is registered for member policy '{descriptor.policy_type}' " f"({descriptor.family}/{descriptor.network_os})."
            )
        mode, projected_policy_type = shape
        projected_policy: dict[str, Any] = {"policyType": projected_policy_type}
        for field_name, alias in self.MEMBER_SAFE_FIELD_ALIASES.items():
            value = getattr(member.policy, field_name, None)
            # A defaults-only routed response may echo description as an empty string,
            # while the public routed-host input model accepts only non-empty descriptions.
            if descriptor.family == "routed" and field_name == "description" and value == "":
                continue
            if value is not None:
                projected_policy[alias] = value
        return {
            "switchIp": switch_ip,
            "interfaceName": member.interface_name,
            "interfaceType": "ethernet",
            "configData": {
                "mode": mode,
                "networkOS": {
                    "networkOSType": descriptor.network_os,
                    "policy": projected_policy,
                },
            },
        }

    def _append_named_member_projections(self, result: list[dict]) -> list[dict]:
        """Append compatible real members explicitly named by a mutating task.

        Omitted members never enter the public host-family scope, including under overridden.
        Gathered remains host-only. Concrete orchestrators call this after their normal
        default-interface filters so a safe-only projection is never discarded as a default.
        """
        params = self.rest_send.params if self.rest_send and self.rest_send.params else {}
        if params.get("state") == "gathered" or not self.MEMBER_FAMILY:
            return result
        named = self._named_member_targets()
        if not named:
            return result

        projected = list(result)
        projected_keys = {(item.get("switchIp"), str(item.get("interfaceName", "")).lower()) for item in projected if isinstance(item, dict)}
        for switch_ip, switch_id in self._switches_to_query().items():
            for lower_name, record in self._switch_interfaces(switch_id).items():
                task_key = (switch_ip, lower_name)
                if task_key not in named or task_key in projected_keys:
                    continue
                policy_type = self._existing_policy_type(record)
                disposition = classify_member_policy(policy_type)
                descriptor = get_member_policy_descriptor(policy_type)
                if descriptor is not None and descriptor.family == self.MEMBER_FAMILY:
                    member_key = (switch_id, lower_name)
                    self._member_records[member_key] = record
                    projected.append(self._member_planning_projection(record, switch_ip))
                    projected_keys.add(task_key)
                    continue
                # A delete cannot safely normalize any member policy, including a
                # protected or wrong-family one. Add identity only so the generic
                # delete planner routes it through preflight_delete, which inspects
                # the authentic cached record and fails before a write.
                if params.get("state") == "deleted" and disposition != MemberPolicyDisposition.NOT_MEMBER:
                    projected.append(
                        {
                            "switchIp": switch_ip,
                            "interfaceName": record.get("interfaceName"),
                            "interfaceType": "ethernet",
                        }
                    )
                    projected_keys.add(task_key)
        return projected

    @staticmethod
    def _requested_member_updates(
        model_instance: ModelType,
    ) -> tuple[frozenset[str], dict[str, Any]]:
        """Extract exactly the policy fields explicitly supplied by the caller."""
        config_data = getattr(model_instance, "config_data", None)
        network_os = getattr(config_data, "network_os", None)
        policy = getattr(network_os, "policy", None)
        if policy is None:
            return frozenset(), {}
        requested_fields = frozenset(field for field in policy.model_fields_set if field != "policy_type")
        requested_values = {field: getattr(policy, field) for field in requested_fields}
        return requested_fields, requested_values

    @staticmethod
    def _member_key(switch_id: str, interface_name: str) -> tuple[str, str]:
        """Return the canonical key shared by member records, intents, and ownership."""
        return switch_id, interface_name.lower()

    def _cache_member_peer_switch_id(
        self,
        switch_id: str,
        peer_switch_id: str,
        *,
        source: str,
    ) -> str:
        """Validate and cache one reciprocal vPC switch-pair relationship."""
        if not isinstance(peer_switch_id, str) or not peer_switch_id:
            raise RuntimeError(f"{source} for switch {switch_id!r} is missing a valid " f"peerSwitchId; received {peer_switch_id!r}.")
        if peer_switch_id == switch_id:
            raise RuntimeError(f"{source} for switch {switch_id!r} points to itself.")

        cached_peer = self._member_peer_serial_cache.get(switch_id)
        if cached_peer is not None and cached_peer != peer_switch_id:
            raise RuntimeError(f"Conflicting vPC pair evidence for switch {switch_id!r}: " f"{cached_peer!r} and {peer_switch_id!r}.")
        reciprocal = self._member_peer_serial_cache.get(peer_switch_id)
        if reciprocal is not None and reciprocal != switch_id:
            raise RuntimeError(f"Cached vPC pair evidence for peer {peer_switch_id!r} resolves " f"{reciprocal!r}, not {switch_id!r}.")
        for owner, peer in self._member_peer_serial_cache.items():
            if peer == peer_switch_id and owner != switch_id:
                raise RuntimeError(f"Cached vPC pair evidence assigns peer {peer_switch_id!r} " f"to both {owner!r} and {switch_id!r}.")

        self._member_peer_serial_cache[switch_id] = peer_switch_id
        self._member_peer_serial_cache[peer_switch_id] = switch_id
        return peer_switch_id

    def _resolve_member_peer_switch_id(self, switch_id: str) -> str:
        """Resolve one omitted vPC peer through the established cached pair endpoint."""

        cached = self._member_peer_serial_cache.get(switch_id)
        if cached is not None:
            return cached
        endpoint = EpVpcPairGet()
        endpoint.fabric_name = self.fabric_name
        endpoint.switch_id = switch_id
        result = self._request(
            path=endpoint.path,
            verb=endpoint.verb,
            not_found_ok=True,
        )
        if not isinstance(result, dict) or not result:
            raise RuntimeError(f"Cannot resolve the vPC peer for switch {switch_id!r}: the " "vpcPair endpoint returned no pair evidence.")
        record_switch_id = result.get("switchId")
        if record_switch_id not in (None, switch_id):
            raise RuntimeError(f"vPC pair evidence requested for switch {switch_id!r} declares " f"switchId {record_switch_id!r}.")
        peer_switch_id = result.get("peerSwitchId")
        if not isinstance(peer_switch_id, str) or not peer_switch_id:
            raise RuntimeError(f"vPC pair evidence for switch {switch_id!r} is missing a valid " f"peerSwitchId; received {result!r}.")
        return self._cache_member_peer_switch_id(
            switch_id,
            peer_switch_id,
            source="vPC pair endpoint evidence",
        )

    @staticmethod
    def _interface_policy(record: dict[str, Any]) -> dict[str, Any] | None:
        """Return one interface record's policy mapping when its envelope is valid."""
        config_data = record.get("configData")
        if not isinstance(config_data, dict):
            return None
        network_os = config_data.get("networkOS")
        if not isinstance(network_os, dict):
            return None
        policy = network_os.get("policy")
        return policy if isinstance(policy, dict) else None

    def _pair_aware_member_parent(
        self,
        switch_id: str,
        member_record: dict[str, Any],
    ) -> tuple[str, dict[str, Any], dict[str, Any]] | None:
        """Return a compatible cached vPC parent for one named member routing hint."""
        policy = self._interface_policy(member_record)
        if policy is None:
            return None
        descriptor = get_member_policy_descriptor(policy.get("policyType"))
        if descriptor is None or not descriptor.pair_aware:
            return None
        parent_name = policy.get("primaryInterface")
        if not isinstance(parent_name, str) or not parent_name:
            return None
        parent_record = self._switch_interfaces_cache.get(switch_id, {}).get(parent_name.lower())
        if not isinstance(parent_record, dict):
            return None
        parent_policy = self._interface_policy(parent_record)
        parent_config = parent_record.get("configData")
        parent_network_os = parent_config.get("networkOS") if isinstance(parent_config, dict) else None
        if (
            parent_record.get("interfaceType") != descriptor.parent_interface_type
            or not isinstance(parent_policy, dict)
            or parent_policy.get("policyType") not in descriptor.parent_policy_types
            or not isinstance(parent_network_os, dict)
            or parent_config.get("mode") != descriptor.parent_wire_mode
            or parent_network_os.get("networkOSType") != descriptor.parent_network_os
        ):
            return None
        return parent_name, parent_record, parent_policy

    def _prefetch_named_member_peer_inventories(self) -> None:
        """Prefetch every unique vPC peer needed by explicitly named members.

        Pair relationships are all resolved and checked before any peer inventory
        request. This lets one membership index validate arbitrarily many pairs and
        also keeps conflicting or malformed pair evidence fail-closed before writes.
        """
        pairs: set[frozenset[str]] = set()
        seen_parents: set[tuple[str, str]] = set()
        for (switch_id, _member_name), member_record in sorted(self._member_records.items()):
            parent = self._pair_aware_member_parent(switch_id, member_record)
            if parent is None:
                continue
            parent_name, _parent_record, parent_policy = parent
            parent_key = (switch_id, parent_name.lower())
            if parent_key in seen_parents:
                continue
            seen_parents.add(parent_key)

            peer_switch_id = parent_policy.get("peerSwitchId")
            if peer_switch_id in (None, ""):
                peer_switch_id = self._resolve_member_peer_switch_id(switch_id)
            else:
                peer_switch_id = self._cache_member_peer_switch_id(
                    switch_id,
                    peer_switch_id,
                    source=f"vPC parent {parent_name!r}",
                )
            pairs.add(frozenset((switch_id, peer_switch_id)))

        for pair in sorted(tuple(sorted(pair)) for pair in pairs):
            for switch_id in pair:
                if switch_id not in self._switch_interfaces_cache:
                    self._switch_interfaces(switch_id)

    def _membership_index(self) -> EthernetMembershipIndex:
        """Return the index built from cached inventories and vPC pair evidence."""
        inventory_switches = frozenset(self._switch_interfaces_cache)
        if self._membership_index_cache is not None and inventory_switches != self._membership_index_inventory_switches:
            # Direct orchestrator callers can load another switch after an earlier
            # safe PUT. The PUT itself does not invalidate ownership, but an index
            # predating a newly cached inventory cannot validate that switch.
            self._membership_index_cache = None
        if self._membership_index_cache is None:
            self._prefetch_named_member_peer_inventories()
            self._membership_index_cache = EthernetMembershipIndex(
                self._switch_interfaces_cache,
                peer_switch_ids=self._member_peer_serial_cache,
            )
            self._membership_index_inventory_switches = frozenset(self._switch_interfaces_cache)
        return self._membership_index_cache

    def _validate_member_ownership(self, switch_id: str, interface_name: str):
        """Validate ownership with at most one cached pair and peer-inventory GET."""
        try:
            try:
                return self._membership_index().validate(switch_id, interface_name)
            except MissingPeerIdentityError as exc:
                # A schema-valid parent echo may omit peerSwitchId. Reuse the
                # vPC modules' authoritative per-switch vpcPair endpoint and
                # retain both orientations so every member of the pair shares it.
                self._resolve_member_peer_switch_id(exc.switch_id)
                self._membership_index_cache = None
                return self._membership_index().validate(switch_id, interface_name)
        except MissingPeerInventoryError as exc:
            # The per-switch interface cache guarantees one peer inventory GET,
            # shared by every later member in the same module invocation.
            self._switch_interfaces(exc.peer_switch_id)
            self._membership_index_cache = None
            return self._membership_index().validate(switch_id, interface_name)

    @staticmethod
    def _desired_network_os(model_instance: ModelType) -> str | None:
        """Return the public host model's requested network OS discriminator."""
        config_data = getattr(model_instance, "config_data", None)
        network_os = getattr(config_data, "network_os", None)
        return getattr(network_os, "network_os_type", None)

    def _prepare_member_intent(self, model_instance: ModelType, existing_data: dict | None) -> bool:
        """Validate a real member target and retain its original explicit safe-field intent.

        Returns True only for an exact supported member policy. Unknown, protected,
        wrong-family, replacement-state, and ambiguous ownership cases fail closed.
        """
        policy_type = self._existing_policy_type(existing_data)
        disposition = classify_member_policy(policy_type)
        if disposition == MemberPolicyDisposition.NOT_MEMBER:
            return False
        if existing_data is None:
            raise AssertionError("Member classification requires an existing interface record")

        descriptor = get_member_policy_descriptor(policy_type)
        if descriptor is None:
            raise RuntimeError(
                f"Interface {model_instance.interface_name} on switch {model_instance.switch_ip} "
                f"uses protected or unsupported member policy '{policy_type}'."
            )
        if descriptor.family != self.MEMBER_FAMILY:
            raise RuntimeError(
                f"Interface {model_instance.interface_name} uses member policy '{policy_type}' "
                f"from the '{descriptor.family}' family; the '{self.MEMBER_FAMILY}' ethernet "
                f"module cannot modify it."
            )

        desired_network_os = self._desired_network_os(model_instance)
        if desired_network_os is not None and desired_network_os != descriptor.network_os:
            raise RuntimeError(
                f"Interface {model_instance.interface_name} uses member policy '{policy_type}' "
                f"for network OS '{descriptor.network_os}', but the task requested "
                f"'{desired_network_os}'."
            )

        state = self.rest_send.params.get("state") if self.rest_send and self.rest_send.params else None
        if state != "merged":
            raise RuntimeError(
                f"Interface {model_instance.interface_name} uses port-channel member policy "
                f"'{policy_type}'. Standalone ethernet modules support member-safe updates only "
                f"with state: merged; requested state: {state}."
            )

        requested_fields, requested_values = self._requested_member_updates(model_instance)
        non_safe = requested_fields - self.PORT_CHANNEL_MODIFIABLE_FIELDS
        if non_safe:
            raise RuntimeError(
                f"Interface {model_instance.interface_name} is a port-channel member. "
                f"The following explicitly requested fields cannot be modified: "
                f"{sorted(non_safe)}. Only these fields can be modified: "
                f"{sorted(self.PORT_CHANNEL_MODIFIABLE_FIELDS)}."
            )
        # Performs value normalization and rejects membership-changing extra_config.
        requested_values = normalize_safe_member_updates(requested_values)

        switch_id = self._resolve_switch_id(model_instance.switch_ip)
        key = self._member_key(switch_id, model_instance.interface_name)
        # query_all() already records every named member for state-machine use.
        # Direct update() callers reach this method without that discovery pass;
        # register the authentic record now so peer prefetch precedes index build.
        self._member_records[key] = existing_data
        ownership = self._validate_member_ownership(switch_id, model_instance.interface_name)
        if descriptor.pair_aware and not ownership.pair_validated:
            raise RuntimeError(f"Pair-aware ownership validation did not complete for vPC member " f"{model_instance.interface_name}.")

        self._validated_member_ownership[key] = ownership
        self._member_intents[key] = MemberUpdateIntent(
            requested_state=state,
            effective_state="merged",
            requested_fields=requested_fields,
            requested_values=requested_values,
        )
        return True

    def _check_port_channel_restrictions(self, model_instance: ModelType, existing_data: dict | None = None) -> None:
        """
        # Summary

        Check if the interface is a port-channel member and validate that only whitelisted fields are being modified.
        If the interface is a port-channel member and non-whitelisted fields are being changed, raise `RuntimeError`.

        A field is treated as a "change" only when the proposed value differs from the corresponding value in the
        existing wire-state policy. This matters for `state: merged`, where the state machine passes the post-merge
        model (which carries every existing wire field) — flagging every non-None field would block legitimate
        whitelisted-only changes.

        Under `state: replaced` / `overridden` the proposed model is the user's config as-is, and a field it omits is a
        removal: the PUT body omits it and ND resets it to the template default. Such a removal counts as a change
        whenever the existing value is not already that default — the existing policy's `to_reverse_diff_dict` strips
        default-valued keys with the same `reverse_diff_defaults` scrub `NDBaseModel.get_diff` uses — so a
        description-only replacement of a member carrying `ip`/`prefix`/`mtu` is rejected instead of silently clearing
        them (PR #550 review).

        ## Raises

        ### RuntimeError

        - If the interface is a port-channel member and non-whitelisted fields are being modified or removed.
        """
        port_channel_id = self._existing_port_channel_id(existing_data)
        if port_channel_id is None:
            return
        policy_type = self._existing_policy_type(existing_data)
        if classify_member_policy(policy_type) == MemberPolicyDisposition.NOT_MEMBER:
            raise RuntimeError(
                f"Interface {model_instance.interface_name} has operational port-channel "
                f"membership {port_channel_id}, but its configured policy is "
                f"'{policy_type}'. Refusing a host-policy write because membership evidence "
                f"is inconsistent; reconcile the parent port-channel first."
            )

        if model_instance.config_data is None:
            return

        # existing_data is guaranteed non-None here (the helper returns None for a None input).
        if existing_data is None:
            raise AssertionError("existing_data is None despite _existing_port_channel_id returning a value")
        existing_policy = existing_data.get("configData", {}).get("networkOS", {}).get("policy") or {}

        policy = model_instance.config_data.network_os.policy if model_instance.config_data.network_os else None
        if policy is None:
            return

        # Parse the wire policy through the same model so both sides share identical Pydantic coercion before
        # comparison. Comparing the model's typed value (e.g. float 50.0 for a storm-control level, int 10 for
        # access_vlan) directly against the raw wire value (which ND may echo as int 50 or str "50"/"10") would
        # flag an unchanged field as modified (50.0 != "50") and wrongly raise on an idempotent re-run of a
        # port-channel member. from_response() applies the same coercion ND data already round-trips through in
        # query_all, so a value the model could not represent would have failed there first.
        existing_model = type(policy).from_response(existing_policy)

        state = self.rest_send.params.get("state") if self.rest_send and self.rest_send.params else None
        removal_state = state in ("replaced", "overridden")
        # Aliased dump of the existing policy with default-valued keys stripped: any alias still present is a
        # user-configured value that an omitted proposed field would clear under replaced/overridden.
        existing_configured = existing_model.to_reverse_diff_dict() if removal_state else {}

        changed_fields = set()
        for field_name, field_info in type(policy).model_fields.items():
            if field_name == "policy_type":
                continue
            proposed_value = getattr(policy, field_name)
            if proposed_value is None:
                if removal_state and (field_info.alias or field_name) in existing_configured:
                    changed_fields.add(field_name)
                continue
            if proposed_value != getattr(existing_model, field_name):
                changed_fields.add(field_name)

        non_whitelisted = changed_fields - self.PORT_CHANNEL_MODIFIABLE_FIELDS
        if non_whitelisted:
            raise RuntimeError(
                f"Interface {model_instance.interface_name} is a member of port-channel {port_channel_id}. "
                f"The following fields cannot be modified on port-channel members: {sorted(non_whitelisted)}. "
                f"Only these fields can be modified: {sorted(self.PORT_CHANNEL_MODIFIABLE_FIELDS)}."
            )

    @staticmethod
    def _existing_policy_type(existing_data: dict | None) -> str | None:
        """
        # Summary

        Return the `configData.networkOS.policy.policyType` of an interface's current wire state, or `None` when the interface is
        absent from the inventory or carries no policy.

        ## Raises

        None
        """
        if not isinstance(existing_data, dict):
            return None
        policy = ((existing_data.get("configData") or {}).get("networkOS") or {}).get("policy") or {}
        policy_type = policy.get("policyType")
        return policy_type if isinstance(policy_type, str) and policy_type else None

    def _check_fabric_ownership(self, model_instance: ModelType, existing_data: dict | None) -> None:
        """
        # Summary

        Refuse to create/update an interface whose CURRENT wire policy is fabric-owned. The type-specific `query_all` filters keep
        system routed policy types (`numbered`, `multiSiteLinkMember`, `vrfLiteLinkMember`, ...) out of `before[]`, but that alone only
        protects them from `state: overridden`: an interface the task names explicitly is invisible to the state machine, classified as
        a create, and the bulk POST would replace the fabric link's intent with the host policy (PR #550 review). This guard inspects
        the unfiltered per-switch inventory before any POST/PUT and allows the write only when the existing policy type is one a user
        can create (`CONVERTIBLE_POLICY_TYPES`, e.g. trunkHost -> routedHost) or when the interface has no policy at all.

        Subclasses extend this for ownership that policy type alone cannot express (the routed orchestrator adds a fabric-link check
        for IOS-XE, whose fabric links can carry a plain `iosXeRoutedHost`).

        ## Raises

        ### RuntimeError

        - If the existing wire policy type is not in `CONVERTIBLE_POLICY_TYPES`.
        """
        existing_type = self._existing_policy_type(existing_data)
        disposition = classify_member_policy(existing_type)
        if disposition != MemberPolicyDisposition.NOT_MEMBER:
            if get_member_policy_descriptor(existing_type) is None:
                raise RuntimeError(
                    f"Interface {model_instance.interface_name} on switch {model_instance.switch_ip} is owned by the fabric "
                    f"(system policy '{existing_type}'). Refusing to overwrite it with policy "
                    f"'{self._desired_policy_type(model_instance)}'. Only explicitly supported user-owned member policies "
                    f"can use the dedicated member-safe update path."
                )
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            key = self._member_key(switch_id, model_instance.interface_name)
            if key in self._validated_member_ownership:
                return
            raise RuntimeError(
                f"Interface {model_instance.interface_name} on switch "
                f"{model_instance.switch_ip} uses member policy '{existing_type}', but "
                f"the dedicated member ownership and safe-field checks have not passed."
            )
        if existing_type is None or existing_type in self.CONVERTIBLE_POLICY_TYPES:
            return
        raise RuntimeError(
            f"Interface {model_instance.interface_name} on switch {model_instance.switch_ip} is owned by the fabric "
            f"(system policy '{existing_type}'). Refusing to overwrite it with policy '{self._desired_policy_type(model_instance)}'. "
            f"Only interfaces carrying a user-managed host policy can be converted; fabric links must be changed through the fabric "
            f"link workflow, not an interface module."
        )

    @staticmethod
    def _desired_policy_type(model_instance: ModelType) -> str | None:
        """
        # Summary

        Return the `policy_type` the proposed model carries (`config_data.network_os.policy.policy_type`), or `None` when the model has
        no policy. Used only for error reporting.

        ## Raises

        None
        """
        config_data = getattr(model_instance, "config_data", None)
        network_os = getattr(config_data, "network_os", None)
        policy = getattr(network_os, "policy", None)
        policy_type = getattr(policy, "policy_type", None)
        return getattr(policy_type, "value", policy_type)

    def preflight(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Extend the shared interface preflight (switch resolution, capability opt-in) with the fabric-ownership and port-channel
        membership guards, so a `--check` run rejects an overwrite of a fabric-owned interface or a prohibited change to a
        port-channel member exactly like a normal run would inside `create`/`update` (PR #550 review). Each interface's current wire
        state comes from the per-switch `interfaceList` cache that `query_all` already populated, so no additional requests are
        issued. Non-mutating: the mutation itself re-runs the same guards against the same cached state.

        ## Raises

        ### RuntimeError

        - Propagated from `NDBaseInterfaceOrchestrator.preflight` (unresolvable `switch_ip`, capability preflight).
        - If any proposed interface currently carries a fabric-owned policy (`_check_fabric_ownership`).
        - If any proposed interface is a port-channel member and a non-whitelisted field would be modified.
        - If the interface-list query used to resolve port-channel membership fails.
        """
        super().preflight(model_instances)
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing_data = self._existing_interface(model_instance.interface_name, switch_id)
            member_target = self._prepare_member_intent(model_instance, existing_data)
            self._check_fabric_ownership(model_instance, existing_data)
            if not member_target:
                self._check_port_channel_restrictions(model_instance, existing_data)

    def preflight_delete(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Pre-delete validation run by `NDStateMachine` for `state: deleted` before `delete`/`delete_bulk` — which are skipped
        in `--check` mode — so a dry run fails on an unresolvable `switch_ip` or on an explicitly named port-channel member
        exactly like a normal run would (PR #550 review). Wire state comes from the per-switch `interfaceList` cache
        `query_all` populated; no additional requests. The fabric-wide `overridden` delete set is not routed through this
        hook: `delete_bulk` skips port-channel members silently there.

        ## Raises

        ### RuntimeError

        - If one or more `switch_ip` values do not match any switch in the fabric.
        - If any named interface is a port-channel member.
        - If the interface-list query used to resolve port-channel membership fails.
        """
        self._require_resolvable_switches(model_instances)
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing_data = self._existing_interface(model_instance.interface_name, switch_id)
            self._check_port_channel_delete_restriction(model_instance, existing_data)

    @staticmethod
    def _existing_port_channel_id(existing_data: dict | None) -> int | None:
        """
        # Summary

        Return the `portChannelId` value from the interface's `operData`, or `None` when the interface is
        not a port-channel member.

        ND 4.2.1 (lab-verified): every ethernet interface carries `operData.portChannelId`. `-1` means the
        interface is not a member of any port-channel; any other integer is the parent port-channel's ID.
        The field is NOT present in `configData.networkOS.policy` — looking there always returns `None`
        and was the cause of the membership check silently never firing.

        Only a positive integer is treated as membership (NX-OS port-channel IDs are 1-4096). `None`, the
        `-1` sentinel, `0`, and any negative value all return `None`, so every caller can check membership
        uniformly with `is None` / `is not None` and a `0`/non-positive value can never be mistaken for a
        real port-channel by a truthiness test.

        ## Raises

        None
        """
        if existing_data is None:
            return None
        pc_id = existing_data.get("operData", {}).get("portChannelId")
        if not isinstance(pc_id, int) or pc_id < 1:
            return None
        return pc_id

    def _check_port_channel_delete_restriction(self, model_instance: ModelType, existing_data: dict | None) -> None:
        """
        # Summary

        Refuse to normalize an interface that is currently a port-channel member. Normalizing resets the
        interface to the `int_trunk_host` template, which silently strips the channel-group membership
        and detaches the interface from its port-channel — a destructive change that an unsuspecting user
        asking to delete an access-interface configuration almost certainly did not intend.

        ## Raises

        ### RuntimeError

        - If the existing wire state shows the interface is a port-channel member.
        """
        policy_type = self._existing_policy_type(existing_data)
        disposition = classify_member_policy(policy_type)
        if disposition != MemberPolicyDisposition.NOT_MEMBER:
            configured_id = None
            if get_member_policy_descriptor(policy_type) is not None and existing_data is not None:
                try:
                    configured_id = parse_member_interface_response(existing_data).normalized_port_channel_id
                except ValueError:
                    configured_id = None
            owner = f"port-channel {configured_id}" if configured_id is not None else f"member policy '{policy_type}'"
            raise RuntimeError(
                f"Interface {model_instance.interface_name} is a member of {owner}. "
                f"Refusing to normalize a port-channel member (this would strip its "
                f"channel-group membership). Remove it from the parent first."
            )
        port_channel_id = self._existing_port_channel_id(existing_data)
        if port_channel_id is not None:
            raise RuntimeError(
                f"Interface {model_instance.interface_name} is a member of port-channel {port_channel_id}. "
                f"Refusing to normalize a port-channel member (this would strip its channel-group membership). "
                f"Remove the interface from the port-channel first, then re-run the delete."
            )

    def remove_pending(self) -> ResponseType | None:
        """
        # Summary

        Flush deferred delete-side work. Interfaces queued via `_queue_normalize` are reset in a single bulk
        `interfaceActions/normalize` POST using the `int_trunk_host` template; interfaces queued via `_queue_reset`
        (those whose wire state carries an unresettable Class C field) are reset one-at-a-time via PUT-as-replace.
        After both paths run, the interfaces share `policyType: "trunkHost"` and are invisible to subsequent
        `query_all()` calls on the type-specific filters.

        Physical ethernet interfaces cannot be deleted via `interfaceActions/remove` (silently does nothing for
        physical interfaces) or `DELETE` (returns 500). The normalize endpoint works when given the full
        `int_trunk_host` template defaults with `mode: "trunk"` and `policyType: "trunkHost"`. The PUT path is
        required for `bandwidth` / `debounceLinkupTimer` / `inheritBandwidth` because ND's validator rejects 0/null
        on those three fields, so the normalize template cannot drive them back to default.

        Both queues are drained pair by pair as the controller accepts each reset, so after a failure they hold exactly the
        pairs whose reset was rejected or never attempted (see `_normalize_interfaces` for the mixed HTTP 207 case).

        ## Raises

        ### RuntimeError

        - If a bulk normalize request fails (raised by `_normalize_interfaces` naming the rejected, accepted, and not-attempted
          interfaces); the message additionally names any per-interface resets that were consequently not attempted.
        - If a per-interface PUT reset fails (raised by `_reset_interfaces` with partial-state detail).
        """
        if not self._pending_normalizes and not self._pending_resets:
            return None
        results: list = []
        if self._pending_normalizes:
            try:
                results.extend(self._normalize_interfaces())
            except RuntimeError as e:
                not_attempted = [name for name, switch_id in self._pending_resets]
                if not_attempted:
                    raise RuntimeError(f"{e} Per-interface resets were not attempted: {not_attempted}.") from e
                raise
        if self._pending_resets:
            # `_reset_interfaces` raises a RuntimeError carrying precise partial-state detail on failure; let it
            # propagate unwrapped rather than re-interpolate the full (now-stale) pending list as an "everything failed" message.
            reset_results = self._reset_interfaces()
            self._pending_resets = []
            results.extend(reset_results)
        return results

    def _normalize_groups(self) -> list[list[tuple[str, str]]]:
        """
        # Summary

        Split the normalize queue into the request groups `_normalize_interfaces` sends. The normalize 207 response identifies each
        result only by interface `name` (no switch), so a mixed 207 can only be correlated back to `(interface_name, switch_id)` pairs
        when no name repeats within a request. When every queued name is unique the whole queue is one group (one POST, the common
        case); when the same name is queued on more than one switch the queue is grouped per switch (queue order preserved), which
        makes every response item unambiguous at the cost of one POST per switch.

        ## Raises

        None
        """
        names = [name.lower() for name, _switch_id in self._pending_normalizes]
        if len(set(names)) == len(names):
            return [list(self._pending_normalizes)]
        groups: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for pair in self._pending_normalizes:
            groups[pair[1]].append(pair)
        return list(groups.values())

    def _normalize_interfaces(self) -> list[ResponseType]:
        """
        # Summary

        Normalize the queued interfaces via `interfaceActions/normalize` using the `InterfaceDefaultConfig` model (the full
        `int_trunk_host` template defaults), one POST per `_normalize_groups` group, dequeuing each group from `_pending_normalizes`
        as the controller accepts it.

        The endpoint answers HTTP 207 with an independent `results[]` status per interface, so a request can reset one interface and
        reject another. On a failed request, the members the response reports as an exact `success` (`_accepted_multistatus_names`;
        vault `multi-status-207-status-field-inconsistent`) are dequeued — their reset IS on the controller, and the module's
        failure-path finalizer (`deploy_accepted_mutations`) must ship it rather than strand it staged, where a retry would filter
        the interface out (its intent is already `trunkHost`) and never deploy it (PR #550 review). Rejected, status-less, and
        unknown-status members stay queued as unsent. Fail-fast across groups: after a failed group the remaining groups are not
        attempted and stay queued.

        ## Raises

        ### RuntimeError

        - If a normalize request fails. The message names the interfaces the controller rejected, the ones it accepted from the same
          request (whose deploy stays queued), and the ones not attempted.
        """
        api_endpoint = EpManageInterfacesNormalize()
        api_endpoint.fabric_name = self.fabric_name
        results: list[ResponseType] = []
        groups = self._normalize_groups()
        for index, group in enumerate(groups):
            payload = InterfaceDefaultConfig.to_normalize_payload(group)
            try:
                results.append(self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload))
            except Exception as e:
                accepted = self._dequeue_accepted_normalizes(group)
                rejected = [name for name, switch_id in group if (name, switch_id) in self._pending_normalizes]
                not_attempted = [name for later in groups[index + 1 :] for name, _switch_id in later]
                msg = f"Bulk normalize failed for {rejected}: {e}."
                if accepted:
                    msg += f" The controller accepted {accepted} from the same request; their deploy stays queued."
                else:
                    msg += " None of these interfaces were reset."
                if not_attempted:
                    msg += f" Not attempted: {not_attempted}."
                raise RuntimeError(msg) from e
            for pair in group:
                self._pending_normalizes.remove(pair)
        return results

    def _dequeue_accepted_normalizes(self, group: list[tuple[str, str]]) -> list[str]:
        """
        # Summary

        After a failed normalize request for `group`, dequeue from `_pending_normalizes` every member the most recent response reported
        as an exact `success` (HTTP 207 Multi-Status only; see `_accepted_multistatus_names`) and return their names in request order.
        Names are unique within a group by construction (`_normalize_groups`), so a response `name` maps to exactly one pair. Returns an
        empty list when the failure was not a partial 207.

        ## Raises

        None
        """
        accepted_names = self._accepted_multistatus_names()
        accepted: list[str] = []
        for interface_name, switch_id in group:
            if interface_name.lower() in accepted_names:
                self._pending_normalizes.remove((interface_name, switch_id))
                accepted.append(interface_name)
        return accepted

    def _reset_interfaces(self) -> list[ResponseType]:
        """
        # Summary

        Reset queued interfaces one-at-a-time via PUT-as-replace using the minimal `InterfaceDefaultConfig.to_reset_payload`
        body. There is no bulk PUT equivalent — this path runs only for interfaces whose wire state carries an unresettable
        Class C field (`bandwidth`, `debounceLinkupTimer`, `inheritBandwidth`), so the request count stays low in practice.

        Fail-fast: on the first PUT failure the remaining interfaces are not attempted. ND has no rollback for a per-interface
        PUT, so interfaces reset before the failure stay at fabric default; the raised error names which interfaces
        succeeded, which one failed, and which were not attempted so the user can reconcile the partial state.

        ## Raises

        ### RuntimeError

        - If a per-interface PUT request fails. The message names the failed interface, the interfaces successfully reset
          before it (now at fabric default, not rolled back), and the interfaces not attempted.
        """
        results: list[ResponseType] = []
        succeeded: list[str] = []
        # Iterate over a snapshot: each pair is dequeued as soon as its PUT succeeds, so after a failure the queue holds exactly
        # the failed and not-attempted pairs and the failure-path finalizer (`_unsent_delete_pairs`) never deploys them.
        pending = list(self._pending_resets)
        for index, (interface_name, switch_id) in enumerate(pending):
            api_endpoint = self._configure_endpoint(self.update_endpoint(), switch_sn=switch_id)
            api_endpoint.set_identifiers(interface_name)
            payload = InterfaceDefaultConfig.to_reset_payload(interface_name, switch_id)
            try:
                results.append(self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload))
            except Exception as e:
                not_attempted = [name for name, switch_id in pending[index + 1 :]]
                raise RuntimeError(
                    f"Reset failed at {interface_name} on {switch_id}: {e}. "
                    f"Successfully reset before failure: {succeeded or 'none'}. "
                    f"Not attempted: {not_attempted or 'none'}. "
                    f"Interfaces reset before the failure are now at fabric default and were not rolled back."
                ) from e
            succeeded.append(interface_name)
            self._pending_resets.remove((interface_name, switch_id))
        return results

    def _unsent_delete_pairs(self) -> set[tuple[str, str]]:
        """
        # Summary

        Extend the base set of not-yet-accepted delete pairs with ethernet's deferred queues: the bulk normalize queue (dequeued
        per request group as the controller accepts it, and per exact-success member on a mixed HTTP 207) and the per-interface
        reset queue (dequeued pair by pair as each PUT succeeds). See `NDBaseInterfaceOrchestrator._unsent_delete_pairs` /
        `deploy_accepted_mutations`.

        ## Raises

        None
        """
        return super()._unsent_delete_pairs() | set(self._pending_normalizes) | set(self._pending_resets)

    def create(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Create an ethernet interface configuration. Resolves `switch_ip` from the model instance, fetches the
        interface's current wire state to enforce the fabric-ownership and port-channel membership guards, injects `switchId`,
        and wraps the payload in an `interfaces` array. Queues a deploy for later bulk execution via `deploy_pending`.

        An `existing_data` keyword argument, when supplied, overrides the fetched wire state (used by tests).

        ## Raises

        ### RuntimeError

        - If the interface currently carries a fabric-owned policy (`_check_fabric_ownership`).
        - If the interface is a port-channel member and non-whitelisted fields are being modified.
        - If the interface-list query used to resolve port-channel membership fails.
        - If the create API request fails.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing_data = kwargs.get("existing_data") or self._existing_interface(model_instance.interface_name, switch_id)
            existing_policy_type = self._existing_policy_type(existing_data)
            if classify_member_policy(existing_policy_type) != MemberPolicyDisposition.NOT_MEMBER:
                raise RuntimeError(
                    f"Interface {model_instance.interface_name} already exists with member "
                    f"policy '{existing_policy_type}'; a member must never be sent through "
                    f"the create endpoint."
                )
            self._check_fabric_ownership(model_instance, existing_data)
            self._check_port_channel_restrictions(model_instance, existing_data)
            api_endpoint = self._configure_endpoint(self.create_endpoint(), switch_sn=switch_id)
            payload = model_instance.to_payload()
            payload["switchId"] = switch_id
            request_body = {"interfaces": [payload]}
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=request_body)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return result
        except Exception as e:
            raise RuntimeError(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def _update_member(self, model_instance: ModelType, switch_id: str, existing_data: dict) -> ResponseType:
        """PUT a validated member-policy payload without changing its membership.

        The original explicit caller fields were captured in preflight before the state
        machine merged its host-shaped planning projection. Direct orchestrator callers are
        also safe: when no intent exists yet, the same validation is performed here.
        """
        key = self._member_key(switch_id, model_instance.interface_name)
        if key not in self._member_intents:
            self._prepare_member_intent(model_instance, existing_data)
        self._check_fabric_ownership(model_instance, existing_data)

        intent = self._member_intents.get(key)
        ownership = self._validated_member_ownership.get(key)
        if intent is None or ownership is None:
            raise RuntimeError(f"Member-safe intent or ownership proof is missing for " f"{model_instance.interface_name} on switch {switch_id}.")
        api_endpoint = self._configure_endpoint(self.update_endpoint(), switch_sn=switch_id)
        api_endpoint.set_identifiers(model_instance.interface_name)
        payload = build_member_update_payload(
            existing_data,
            intent.requested_values,
            switch_id=switch_id,
            pair_validated=bool(ownership.pair_validated),
        )
        result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)

        # Keep discovery coherent without a post-write GET. Only configData changed; retain
        # operational evidence and other response metadata from the cached record.
        updated_record = deepcopy(existing_data)
        updated_record["switchId"] = switch_id
        updated_record["configData"] = deepcopy(payload["configData"])
        self._switch_interfaces_cache[switch_id][model_instance.interface_name.lower()] = updated_record
        self._member_records[key] = updated_record
        # The safe overlay cannot change member policy, primaryInterface, port-channel
        # identity, or parent membership lists. Retain the cached ownership index and
        # its proofs across later member PUTs in this invocation.
        self._queue_deploy(model_instance.interface_name, switch_id)
        return result

    def update(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Update an ethernet interface configuration. Resolves `switch_ip` from the model instance, fetches the
        interface's current wire state to enforce the fabric-ownership and port-channel membership guards, injects
        `switchId` into the payload. Queues a deploy for later bulk execution via `deploy_pending`.

        An `existing_data` keyword argument, when supplied, overrides the fetched wire state (used by tests).

        ## Raises

        ### RuntimeError

        - If the interface currently carries a fabric-owned policy (`_check_fabric_ownership`).
        - If the interface is a port-channel member and non-whitelisted fields are being modified.
        - If the interface-list query used to resolve port-channel membership fails.
        - If the update API request fails.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing_data = kwargs.get("existing_data") or self._existing_interface(model_instance.interface_name, switch_id)
            existing_policy_type = self._existing_policy_type(existing_data)
            if get_member_policy_descriptor(existing_policy_type) is not None:
                if existing_data is None:
                    raise AssertionError("Member update requires existing interface data")
                return self._update_member(model_instance, switch_id, existing_data)
            self._check_fabric_ownership(model_instance, existing_data)
            self._check_port_channel_restrictions(model_instance, existing_data)
            api_endpoint = self._configure_endpoint(self.update_endpoint(), switch_sn=switch_id)
            api_endpoint.set_identifiers(model_instance.interface_name)
            payload = model_instance.to_payload()
            payload["switchId"] = switch_id
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return result
        except Exception as e:
            raise RuntimeError(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Queue an ethernet interface for normalization to the fabric default `int_trunk_host` template. The actual
        normalize API call is deferred to `remove_pending()` for bulk execution via `interfaceActions/normalize`.

        After normalization, the interface has `policyType: "trunkHost"` which removes it from the type-specific
        filters in `query_all()`, making it invisible to this orchestrator on subsequent runs.

        A deploy is also queued to push the normalized config to the switch.

        Refuses to act on a port-channel member: normalizing would strip the channel-group membership and silently
        detach the interface from its port-channel, which is almost never the intent behind a delete request.

        An `existing_data` keyword argument, when supplied, overrides the fetched wire state (used by tests).

        ## Raises

        ### RuntimeError

        - If switch IP resolution fails.
        - If the interface-list query used to resolve port-channel membership fails.
        - If the interface is a port-channel member.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing_data = kwargs.get("existing_data") or self._existing_interface(model_instance.interface_name, switch_id)
            self._check_port_channel_delete_restriction(model_instance, existing_data)
            if self._has_unresettable_fields(existing_data):
                self._queue_reset(model_instance.interface_name, switch_id)
            else:
                self._queue_normalize(model_instance.interface_name, switch_id)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return {}
        except Exception as e:
            raise RuntimeError(f"Delete failed for {model_instance.get_identifier_value()}: {e}") from e

    def create_bulk(self, model_instances: list[ModelType], **kwargs) -> ResponseType:
        """
        # Summary

        Create multiple ethernet interfaces in bulk. Groups interfaces by switch and sends one POST per switch with all
        interfaces in the `interfaces` array, reducing API calls from N to one-per-switch. Each interface's current wire
        state is fetched (one cached `interfaceList` GET per switch) to enforce the fabric-ownership and port-channel
        membership guards — every guard runs before the first POST, so a fabric-owned target anywhere in the batch fails
        the whole batch with nothing written. Queues deploys for all created interfaces for later bulk execution via
        `deploy_pending`.

        A per-switch POST can fail with HTTP 207 Multi-Status while the controller still accepted some of the group's
        interfaces (`DATA.results[]` items reporting an exact `success`). Those accepted interfaces are queued for deploy
        before the error propagates, so the module's failure-path finalizer (`deploy_accepted_mutations`) ships them
        rather than leaving them staged; a retry would otherwise classify them as unchanged and never deploy them
        (PR #550 review). Only an exact `success` is trusted — see `_accepted_multistatus_names`.

        An `existing_data` keyword argument, when supplied, overrides the fetched wire state (used by tests).

        ## Raises

        ### RuntimeError

        - If any interface currently carries a fabric-owned policy (`_check_fabric_ownership`).
        - If any interface is a port-channel member and non-whitelisted fields are being modified.
        - If the interface-list query used to resolve port-channel membership fails.
        - If any create API request fails. When the failing response was a 207 that accepted part of the group, the
          message names the accepted interfaces.
        """
        try:
            groups: dict[str, list[tuple[str, dict]]] = defaultdict(list)
            for model_instance in model_instances:
                switch_id = self._resolve_switch_id(model_instance.switch_ip)
                existing_data = kwargs.get("existing_data") or self._existing_interface(model_instance.interface_name, switch_id)
                existing_policy_type = self._existing_policy_type(existing_data)
                if classify_member_policy(existing_policy_type) != MemberPolicyDisposition.NOT_MEMBER:
                    raise RuntimeError(
                        f"Interface {model_instance.interface_name} already exists with member "
                        f"policy '{existing_policy_type}'; a member must never be sent through "
                        f"the bulk create endpoint."
                    )
                self._check_fabric_ownership(model_instance, existing_data)
                self._check_port_channel_restrictions(model_instance, existing_data)
                payload = model_instance.to_payload()
                payload["switchId"] = switch_id
                groups[switch_id].append((model_instance.interface_name, payload))

            results = []
            for switch_id, items in groups.items():
                results.append(self._post_bulk_group(switch_id, items))
                for interface_name, payload in items:
                    self._queue_deploy(interface_name, switch_id)
            return results
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

    def _post_bulk_group(self, switch_id: str, items: list[tuple[str, dict]]) -> ResponseType:
        """
        # Summary

        Send one per-switch bulk create POST for `items` (`(interface_name, payload)` pairs). On failure, queue a deploy for every
        interface the response reported as accepted (partial HTTP 207, see `_queue_accepted_bulk_items`) before re-raising, naming
        the accepted subset in the error when there is one.

        ## Raises

        ### Exception

        - Propagated from `_request` when the POST fails (wrapped in `RuntimeError` naming the accepted subset when the failing
          207 accepted part of the group).
        """
        # Guarded at runtime by @requires_bulk_support("supports_bulk_create")
        api_endpoint = self._configure_endpoint(self.create_bulk_endpoint(), switch_sn=switch_id)  # pyright: ignore[reportOptionalCall]
        request_body = {"interfaces": [payload for _interface_name, payload in items]}
        try:
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=request_body)
        except Exception as e:
            accepted = self._queue_accepted_bulk_items(items, switch_id)
            if accepted:
                raise RuntimeError(f"{e}. The controller accepted {accepted} from the same request; their deploy stays queued.") from e
            raise

    def _queue_accepted_bulk_items(self, items: list[tuple[str, dict]], switch_id: str) -> list[str]:
        """
        # Summary

        After a failed per-switch bulk POST, queue a deploy for every interface in `items` that the most recent response
        reported as an exact `success` (HTTP 207 Multi-Status only; see `_accepted_multistatus_names`). Returns the accepted
        interface names in request order (empty when the failure was not a partial 207).

        ## Raises

        None
        """
        accepted_names = self._accepted_multistatus_names()
        accepted: list[str] = []
        for interface_name, _payload in items:
            if interface_name.lower() in accepted_names:
                self._queue_deploy(interface_name, switch_id)
                accepted.append(interface_name)
        return accepted

    def delete_bulk(self, model_instances: list[ModelType], **kwargs) -> None:
        """
        # Summary

        Queue multiple ethernet interfaces for deferred bulk normalization and deployment. Each interface is queued
        for normalization via `remove_pending` (which resets it to the `int_trunk_host` template) and deployment via
        `deploy_pending`. No API calls are made until those methods are called after `manage_state` completes.

        Port-channel members are handled per-state:

        - `state: overridden` — silently skipped (logged at INFO). Fabric-wide convergence should not require the
          user to explicitly list every PC member in the access config just to keep them attached to their bundle.
        - any other state (i.e. user-named `state: deleted` items) — fails fast with `RuntimeError`. The user
          asked for this interface by name, so we refuse loudly rather than silently strip the channel-group
          membership.

        ## Raises

        ### RuntimeError

        - If switch IP resolution fails for any interface.
        - If the interface-list query used to resolve port-channel membership fails.
        - If any interface in the batch is a port-channel member AND `state` is not `overridden`.
        """
        state = self.rest_send.params.get("state") if self.rest_send and self.rest_send.params else None
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing_data = kwargs.get("existing_data") or self._existing_interface(model_instance.interface_name, switch_id)
            policy_type = self._existing_policy_type(existing_data)
            member_disposition = classify_member_policy(policy_type)
            port_channel_id = self._existing_port_channel_id(existing_data)
            if member_disposition != MemberPolicyDisposition.NOT_MEMBER or port_channel_id is not None:
                if state == "overridden":
                    owner = port_channel_id if port_channel_id is not None else policy_type
                    logger.info(
                        "Skipping port-channel member %s on switch %s (owner %s) during state:overridden",
                        model_instance.interface_name,
                        model_instance.switch_ip,
                        owner,
                    )
                    continue
                self._check_port_channel_delete_restriction(model_instance, existing_data)
            if self._has_unresettable_fields(existing_data):
                self._queue_reset(model_instance.interface_name, switch_id)
            else:
                self._queue_normalize(model_instance.interface_name, switch_id)
            self._queue_deploy(model_instance.interface_name, switch_id)

    def query_one(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Query a single ethernet interface by name on a specific switch.

        ## Raises

        ### RuntimeError

        - If the query API request fails.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            api_endpoint = self._configure_endpoint(self.query_one_endpoint(), switch_sn=switch_id)
            api_endpoint.set_identifiers(model_instance.interface_name)
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb)
        except Exception as e:
            raise RuntimeError(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self, model_instance: ModelType | None = None, **kwargs) -> ResponseType:
        """
        # Summary

        Validate the fabric context and query interfaces, filtering for ethernet interfaces with policy types
        managed by this orchestrator (as defined by `_managed_policy_types()`).

        The set of switches queried is determined by `_switches_to_query`: fabric-wide for `state: overridden`,
        and limited to switches named in the user config for all other states.

        Compatible port-channel members are projected into mutating-state results only when explicitly named by
        the task. Omitted members remain outside family and overridden scope, and gathered remains host-only.
        `delete_bulk` also skips members so fabric-wide convergence cannot detach them from their port-channels.

        Runs `validate_prerequisites` on first call to ensure the fabric exists and is modifiable before returning any data.

        Each returned interface dict is enriched with a `switch_ip` field so that the model can be constructed
        with the composite identifier `(switch_ip, interface_name)`.

        ## Raises

        ### RuntimeError

        - If the fabric does not exist on the target ND node.
        - If the fabric is in deployment-freeze mode.
        - If the query API request fails.
        """
        managed_types = self._managed_policy_types()
        try:
            self.validate_prerequisites()
            all_interfaces = []
            for switch_ip, switch_id in self._switches_to_query().items():
                interfaces = list(self._switch_interfaces(switch_id).values())
                ethernet_interfaces = [iface for iface in interfaces if iface.get("interfaceType") == "ethernet"]
                managed = [
                    iface
                    for iface in ethernet_interfaces
                    if iface.get("configData", {}).get("networkOS", {}).get("policy", {}).get("policyType") in managed_types
                ]
                for iface in managed:
                    iface["switchIp"] = switch_ip
                all_interfaces.extend(managed)
            return all_interfaces
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e
