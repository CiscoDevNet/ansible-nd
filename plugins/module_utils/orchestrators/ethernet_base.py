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
from typing import ClassVar

logger = logging.getLogger(__name__)

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesNormalize,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_common import normalize_ethernet_interface_name
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.interface_default_config import InterfaceDefaultConfig
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

ModelType = NDBaseModel


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

    ## IOS-XE contract (shared by every ethernet module; issues #447, #534, #535)

    - `create_bulk` groups by `(switch_id, policy_type)`, never by switch alone (issue #409).
    - Under `state: overridden`, IOS-XE interfaces are merge-only: `query_all` drops every `ios-xe` interface the task does not
      name, so the state machine never computes delete intent for them, and `delete_bulk` skips any that still arrive.
    - An IOS-XE interface the user names under `state: deleted` is reset by a per-interface PUT carrying a defaults-only policy
      (`_xe_reset_payload`, built from `XE_RESET_MODE` / `XE_RESET_POLICY_TYPE`), flushed by `remove_pending` ahead of the NX-OS
      normalize/reset queues and tracked in `_pending_xe_resets`. `interfaceActions/normalize` cannot be used: its body is the
      NX-shaped `int_trunk_host` template. Subclasses hook `_check_xe_delete_guard` to refuse an XE target before it is queued.

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

    PORT_CHANNEL_MODIFIABLE_FIELDS: ClassVar[set[str]] = {"description", "admin_state", "extra_config"}

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

    # The defaults-only policy an IOS-XE interface is reset to under `state: deleted` (`_xe_reset_payload`). The host-facing
    # modules use the XE mirror of the NX-OS normalize target (`int_trunk_host` -> `iosXeTrunkHost`), so a reset Catalyst port
    # lands on the unconfigured-default trunk signature and leaves both the access and trunk modules' managed scope. The routed
    # module overrides both to `routed` / `iosXeRoutedHost` (lab-verified on C8000V; see its class docstring).
    XE_RESET_MODE: ClassVar[str] = "trunk"
    XE_RESET_POLICY_TYPE: ClassVar[str] = "iosXeTrunkHost"

    def model_post_init(self, __context) -> None:
        """
        # Summary

        Initialize ethernet-specific mutable private state after Pydantic model construction. Extends
        `NDBaseInterfaceOrchestrator.model_post_init` to add the normalize, reset, and IOS-XE reset queues (initialized
        the same way as the sibling `_pending_deploys` / `_pending_removes` queues).

        ## Raises

        None
        """
        super().model_post_init(__context)
        self._pending_normalizes: list[tuple[str, str]] = []
        self._pending_resets: list[tuple[str, str]] = []
        self._pending_xe_resets: list[tuple[str, str]] = []

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

    def _queue_xe_reset(self, interface_name: str, switch_id: str) -> None:
        """
        # Summary

        Queue an IOS-XE interface for deferred per-interface reset via `remove_pending`. Deduplicates on the
        `(interface_name, switch_id)` pair like the sibling queues.

        ## Raises

        None
        """
        pair = (interface_name, switch_id)
        if pair not in self._pending_xe_resets:
            self._pending_xe_resets.append(pair)

    @classmethod
    def _xe_reset_payload(cls, interface_name: str, switch_id: str) -> dict:
        """
        # Summary

        Build the per-interface PUT body that resets an IOS-XE interface to its fabric default: a defaults-only
        `XE_RESET_POLICY_TYPE` policy in `XE_RESET_MODE` with no `mtu` key. ND injects the schema defaults (`mtu: 1500`,
        `speed: "auto"`, ...) on the echo, landing the interface on the unconfigured-default signature so it leaves the module's
        managed scope.

        ## Raises

        None
        """
        # TODO(4.2.1) c8000v-rejects-per-port-mtu
        # interfaceActions/normalize is structurally unusable for IOS-XE: its body requires mtu (schema validation
        # rejects an mtu-less body) and C8000V rejects the per-port mtu it carries. The lab-verified reset recipe is
        # this per-interface PUT with mtu omitted (HTTP 204; probe 2026-07-27). The same mtu-less body is used for the
        # host-facing Catalyst reset target pending lab verification on a Cat9k (issues #534 / #535).
        return {
            "interfaceName": interface_name,
            "interfaceType": "ethernet",
            "switchId": switch_id,
            "configData": {
                "mode": cls.XE_RESET_MODE,
                "networkOS": {"networkOSType": "ios-xe", "policy": {"policyType": cls.XE_RESET_POLICY_TYPE, "adminState": True}},
            },
        }

    def _check_xe_delete_guard(self, model_instance: ModelType) -> None:
        """
        # Summary

        Hook run for every IOS-XE interface about to be queued for the XE reset path (`delete`, `delete_bulk`). The base
        implementation is a no-op; the routed orchestrator overrides it with its fabric-link endpoint check.

        ## Raises

        None
        """

    @staticmethod
    def _is_ios_xe(iface: dict) -> bool:
        """
        # Summary

        Return `True` when the interface API response carries `configData.networkOS.networkOSType == "ios-xe"`.

        ## Raises

        None
        """
        return ((iface.get("configData") or {}).get("networkOS") or {}).get("networkOSType") == "ios-xe"

    @staticmethod
    def _model_is_ios_xe(model_instance: ModelType) -> bool:
        """
        # Summary

        Return `True` when the model's `config_data.network_os.network_os_type` is `ios-xe`.

        ## Raises

        None
        """
        network_os = getattr(getattr(model_instance, "config_data", None), "network_os", None)
        return getattr(network_os, "network_os_type", None) == "ios-xe"

    def _named_interfaces(self) -> set[tuple[str, str]]:
        """
        # Summary

        Return the `(switch_ip, interface_name)` pairs named in the task config, with interface names canonicalized by the
        same normalizer the models use so abbreviated or re-cased names match the wire form. The modules that take an
        `interface_names` list expand it to per-interface `interface_name` items before the orchestrator runs.

        ## Raises

        None
        """
        config = self.rest_send.params.get("config") if self.rest_send and self.rest_send.params else None
        named: set[tuple[str, str]] = set()
        for item in config or []:
            if not isinstance(item, dict):
                continue
            switch_ip = item.get("switch_ip")
            interface_name = item.get("interface_name")
            if isinstance(switch_ip, str) and isinstance(interface_name, str):
                named.add((switch_ip, normalize_ethernet_interface_name(interface_name)))
        return named

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
            self._check_fabric_ownership(model_instance, existing_data)
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

        Flush deferred delete-side work. IOS-XE interfaces queued via `_queue_xe_reset` are reset first, one-at-a-time via
        per-interface PUT with the `_xe_reset_payload` body (`_xe_reset_interfaces`). Interfaces queued via `_queue_normalize`
        are then reset in a single bulk `interfaceActions/normalize` POST using the `int_trunk_host` template; interfaces queued
        via `_queue_reset` (those whose wire state carries an unresettable Class C field) are reset one-at-a-time via
        PUT-as-replace. After all paths run, the NX-OS interfaces share `policyType: "trunkHost"` (and the IOS-XE ones
        `XE_RESET_POLICY_TYPE`) and are invisible to subsequent `query_all()` calls on the type-specific filters.

        Fail-fast across the stages: an XE reset failure stops before the NX-OS queues are attempted.

        Physical ethernet interfaces cannot be deleted via `interfaceActions/remove` (silently does nothing for
        physical interfaces) or `DELETE` (returns 500). The normalize endpoint works when given the full
        `int_trunk_host` template defaults with `mode: "trunk"` and `policyType: "trunkHost"`. The PUT path is
        required for `bandwidth` / `debounceLinkupTimer` / `inheritBandwidth` because ND's validator rejects 0/null
        on those three fields, so the normalize template cannot drive them back to default.

        Both queues are drained pair by pair as the controller accepts each reset, so after a failure they hold exactly the
        pairs whose reset was rejected or never attempted (see `_normalize_interfaces` for the mixed HTTP 207 case).

        ## Raises

        ### RuntimeError

        - If an IOS-XE reset PUT fails (raised by `_xe_reset_interfaces` with partial-state detail).
        - If a bulk normalize request fails (raised by `_normalize_interfaces` naming the rejected, accepted, and not-attempted
          interfaces); the message additionally names any per-interface resets that were consequently not attempted.
        - If a per-interface PUT reset fails (raised by `_reset_interfaces` with partial-state detail).
        """
        if not self._pending_normalizes and not self._pending_resets and not self._pending_xe_resets:
            return None
        results: list = []
        if self._pending_xe_resets:
            results.extend(self._xe_reset_interfaces())
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

    def _xe_reset_interfaces(self) -> list[ResponseType]:
        """
        # Summary

        Reset queued IOS-XE interfaces one-at-a-time via per-interface PUT with the `_xe_reset_payload` body. There is no bulk
        equivalent for IOS-XE (`interfaceActions/normalize` carries the NX-shaped `int_trunk_host` body).

        Fail-fast: on the first PUT failure the remaining XE interfaces are not attempted. ND has no rollback for a per-interface
        PUT, so interfaces reset before the failure stay at fabric default; the raised error names which XE interfaces succeeded,
        which one failed, and which were not attempted so the user can reconcile the partial state.

        ## Raises

        ### RuntimeError

        - If an XE reset PUT request fails (with partial-state detail as described above).
        """
        results: list[ResponseType] = []
        succeeded: list[str] = []
        # Iterate over a snapshot: each pair is dequeued as soon as its PUT succeeds, so after a failure the queue holds exactly
        # the failed and not-attempted pairs and the failure-path finalizer (`_unsent_delete_pairs`) never deploys them.
        pending = list(self._pending_xe_resets)
        for index, (interface_name, switch_id) in enumerate(pending):
            api_endpoint = self._configure_endpoint(self.update_endpoint(), switch_sn=switch_id)
            api_endpoint.set_identifiers(interface_name)
            payload = self._xe_reset_payload(interface_name, switch_id)
            try:
                results.append(self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload))
            except Exception as e:
                not_attempted = [name for name, _switch_id in pending[index + 1 :]]
                raise RuntimeError(
                    f"IOS-XE reset failed at {interface_name} on {switch_id}: {e}. "
                    f"Successfully reset before failure: {succeeded or 'none'}. "
                    f"Not attempted: {not_attempted or 'none'}. "
                    f"Interfaces reset before the failure are now at fabric default and were not rolled back."
                ) from e
            succeeded.append(interface_name)
            self._pending_xe_resets.remove((interface_name, switch_id))
        return results

    def _unsent_delete_pairs(self) -> set[tuple[str, str]]:
        """
        # Summary

        Extend the base set of not-yet-accepted delete pairs with ethernet's deferred queues: the bulk normalize queue (dequeued
        per request group as the controller accepts it, and per exact-success member on a mixed HTTP 207), the per-interface
        reset queue, and the IOS-XE reset queue (both dequeued pair by pair as each PUT succeeds). See
        `NDBaseInterfaceOrchestrator._unsent_delete_pairs` / `deploy_accepted_mutations`.

        ## Raises

        None
        """
        return super()._unsent_delete_pairs() | set(self._pending_normalizes) | set(self._pending_resets) | set(self._pending_xe_resets)

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
        An IOS-XE interface is instead queued for the per-interface XE reset PUT (`_queue_xe_reset`) after the
        `_check_xe_delete_guard` hook.

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
            if self._model_is_ios_xe(model_instance):
                self._check_xe_delete_guard(model_instance)
                self._queue_xe_reset(model_instance.interface_name, switch_id)
                self._queue_deploy(model_instance.interface_name, switch_id)
                return {}
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

        Create multiple ethernet interfaces in bulk. Groups interfaces by `(switch_id, policy_type)` and sends one POST per
        group with the group's interfaces in the `interfaces` array, reducing API calls from N to one-per-group (ND rejects a
        mixed-policyType array; issue #409). Each interface's current wire state is fetched (one cached `interfaceList` GET per
        switch) to enforce the fabric-ownership and port-channel membership guards — every guard runs before the first POST, so
        a fabric-owned target anywhere in the batch fails the whole batch with nothing written. Queues deploys for all created
        interfaces for later bulk execution via `deploy_pending`.

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
            groups = self._group_by_switch_and_policy_type(model_instances, **kwargs)
            results = []
            for (switch_id, _policy_type), items in groups.items():
                results.append(self._post_bulk_group(switch_id, items))
                for interface_name, _payload in items:
                    self._queue_deploy(interface_name, switch_id)
            return results
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

    def _group_by_switch_and_policy_type(self, model_instances: list[ModelType], **kwargs) -> dict[tuple[str, str | None], list[tuple[str, dict]]]:
        """
        # Summary

        Build the bulk-create groups: resolve each model's `switch_ip` to a `switchId`, run the fabric-ownership and port-channel
        guards against its current wire state, inject the `switchId` into the payload, and group the resulting
        `(interface_name, payload)` items by `(switch_id, policy_type)`. Group insertion order follows the first model of each group.

        ## Raises

        ### RuntimeError

        - Via `_resolve_switch_id`, `_check_fabric_ownership`, or `_check_port_channel_restrictions`.
        """
        # TODO(4.2.1) bulk-interface-create-rejects-mixed-policy-types
        # ND rejects an interfaces[] array mixing policyType values (207 with a single failed item; nothing is
        # created), even though the create schema allows mixed arrays. One POST per (switch, policyType) (issue #409).
        groups: dict[tuple[str, str | None], list[tuple[str, dict]]] = defaultdict(list)
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing_data = kwargs.get("existing_data") or self._existing_interface(model_instance.interface_name, switch_id)
            self._check_fabric_ownership(model_instance, existing_data)
            self._check_port_channel_restrictions(model_instance, existing_data)
            payload = model_instance.to_payload()
            payload["switchId"] = switch_id
            groups[(switch_id, self._desired_policy_type(model_instance))].append((model_instance.interface_name, payload))
        return groups

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

        Queue multiple ethernet interfaces for deferred bulk normalization and deployment. Each NX-OS interface is queued
        for normalization via `remove_pending` (which resets it to the `int_trunk_host` template) and deployment via
        `deploy_pending`. No API calls are made until those methods are called after `manage_state` completes.

        IOS-XE interfaces are routed per state: under `state: overridden` they are skipped (merge-only, logged at INFO);
        otherwise (a user-named `state: deleted` item) they pass the `_check_xe_delete_guard` hook and are queued for the
        XE reset path (`_queue_xe_reset`) plus deploy — never the family normalize.

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
        - Propagated from `_check_xe_delete_guard` for an IOS-XE interface a subclass refuses to reset.
        """
        state = self.rest_send.params.get("state") if self.rest_send and self.rest_send.params else None
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            if self._model_is_ios_xe(model_instance):
                if state == "overridden":
                    logger.info(
                        "Skipping IOS-XE interface %s on switch %s during state:overridden (IOS-XE interfaces are merge-only)",
                        model_instance.interface_name,
                        model_instance.switch_ip,
                    )
                    continue
                self._check_xe_delete_guard(model_instance)
                self._queue_xe_reset(model_instance.interface_name, switch_id)
                self._queue_deploy(model_instance.interface_name, switch_id)
                continue
            existing_data = kwargs.get("existing_data") or self._existing_interface(model_instance.interface_name, switch_id)
            port_channel_id = self._existing_port_channel_id(existing_data)
            if port_channel_id is not None:
                if state == "overridden":
                    logger.info(
                        "Skipping port-channel member %s on switch %s (member of port-channel %s) during state:overridden",
                        model_instance.interface_name,
                        model_instance.switch_ip,
                        port_channel_id,
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

        Under `state: overridden`, IOS-XE interfaces that are not named in the task config are dropped (IOS-XE is merge-only:
        a Catalyst or C8000V port can carry fabric-link intent with no ownership marker on the interface record, so a fabric-wide
        delete set must never include one). This happens at query scope — not merely at delete time — so the state machine never
        computes delete intent for them and the module's changed/diff reporting stays truthful.

        Port-channel member interfaces are included in the results (they exist on the switch and need to be visible
        for port-channel restriction checks in `create` / `update`). `delete_bulk` skips PC members when invoked
        under `state: overridden` so fabric-wide convergence does not detach interfaces from their port-channels.

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
            if self.rest_send.params.get("state") == "overridden":
                named = self._named_interfaces()
                all_interfaces = [
                    iface for iface in all_interfaces if not self._is_ios_xe(iface) or (iface.get("switchIp"), iface.get("interfaceName")) in named
                ]
            return all_interfaces
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e
