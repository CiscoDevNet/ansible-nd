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

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_vpc_pair import EpVpcPairGet
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesNormalize,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_links import EpManageLinksListGet
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
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_common import normalize_ethernet_interface_name
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_trunk_host_interface import XeEthernetTrunkHostPolicyModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.interface_default_config import (
    InterfaceDefaultConfig,
    InterfaceDefaultPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

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

    ## IOS-XE contract (shared by every ethernet module; issues #447, #534, #535)

    - `create_bulk` groups by `(switch_id, policy_type)`, never by switch alone (issue #409).
    - Under `state: overridden`, IOS-XE interfaces are merge-only: `query_all` drops every `ios-xe` interface the task does not
      name, so the state machine never computes delete intent for them, and `delete_bulk` skips any that still arrive.
    - An IOS-XE interface the user names under `state: deleted` is reset by a per-interface PUT carrying a defaults-only policy
      (`_xe_reset_payload`, built from `XE_RESET_MODE` / `XE_RESET_POLICY_TYPE`), flushed by `remove_pending` ahead of the NX-OS
      normalize/reset queues and tracked in `_pending_xe_resets`. `interfaceActions/normalize` cannot be used: its body is the
      NX-shaped `int_trunk_host` template. `_check_xe_fabric_link` refuses an XE fabric-link endpoint before it is queued.
    - IOS-XE fabric ownership is not visible on the interface record: a fabric-link endpoint can read as a plain defaults-only
      `iosXeRoutedHost` (lab-verified 2026-09-03: WAN1 `GigabitEthernet3`, endpoint of the ISN->SITE2 `ebgpVrfLite` link), which
      is in `CONVERTIBLE_POLICY_TYPES`. So `_check_fabric_ownership` (create/update/preflight) and the XE delete path additionally
      consult the fabric's links (`_fabric_link_endpoints`, `GET /api/v1/manage/links?fabricName=`, fetched once per run and only
      when an IOS-XE interface is written) and refuse an endpoint of a link carrying an ND link policy. This applies to EVERY
      host-facing module, not only routed: an access or trunk task naming a Catalyst uplink would otherwise replace the link's
      intent with `iosXeAccess` / `iosXeTrunkHost` and deploy it (PR #558 review).

    ## Raises

    ### RuntimeError

    - Via `validate_prerequisites` if the fabric does not exist, or is in deployment-freeze mode for a state
      that mutates configuration.
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
        ("access", "ios-xe"): ("access", "iosXeAccess"),
        ("trunk", "nx-os"): ("trunk", "trunkHost"),
        ("trunk", "ios-xe"): ("trunk", "iosXeTrunkHost"),
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

    # The defaults-only policy an IOS-XE interface is reset to under `state: deleted` (`_xe_reset_payload`). The host-facing
    # modules use the XE mirror of the NX-OS normalize target (`int_trunk_host` -> `iosXeTrunkHost`), so a reset Catalyst port
    # lands on the unconfigured-default trunk signature and leaves both the access and trunk modules' managed scope. The routed
    # module overrides both to `routed` / `iosXeRoutedHost` (lab-verified on C8000V; see its class docstring).
    XE_RESET_MODE: ClassVar[str] = "trunk"
    XE_RESET_POLICY_TYPE: ClassVar[str] = "iosXeTrunkHost"
    # TODO(4.3.1) ethernet-create-required-fields-431
    # ND 4.3.1 rejects the XE reset PUT unless it carries the policy's template-required fields (`allowedVlans`, `mtu` for
    # iosXeTrunkHost; `mtu` for iosXeRoutedHost), where 4.2.1 accepted the defaults-only body and injected them on the echo.
    # Lab-verified 2026-09-14 on the CAMPUS1 Catalyst 9000v (400 without, 204 with). Sourced from the XE policy model's
    # `payload_defaults` so the reset body and the create body share one table; the values are the template defaults, so the
    # reset lands on the same unconfigured-default signature on both releases.
    XE_RESET_POLICY_DEFAULTS: ClassVar[dict[str, Any]] = XeEthernetTrunkHostPolicyModel.payload_defaults

    def model_post_init(self, __context) -> None:
        """
        # Summary

        Initialize ethernet-specific mutable private state after Pydantic model construction. Extends
        `NDBaseInterfaceOrchestrator.model_post_init` to add the normalize, reset, and IOS-XE reset queues (initialized
        the same way as the sibling `_pending_deploys` / `_pending_removes` queues) and the lazily populated fabric-link
        endpoint cache (`_fabric_link_endpoints_cache`, `None` until `_fabric_link_endpoints` first fetches the links).

        ## Raises

        None
        """
        super().model_post_init(__context)
        self._pending_normalizes: list[tuple[str, str]] = []
        self._pending_resets: list[tuple[str, str]] = []
        self._pending_xe_resets: list[tuple[str, str]] = []
        self._fabric_link_endpoints_cache: dict[tuple[str, str], dict] | None = None
        # Flipped for the rest of the run once the controller rejects the template's empty `description` (ND 4.3.1); see
        # `_post_normalize`.
        self._normalize_omits_description: bool = False
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
        `XE_RESET_POLICY_TYPE` policy in `XE_RESET_MODE` carrying only `adminState` plus the template-required fields in
        `XE_RESET_POLICY_DEFAULTS`. ND injects the remaining schema defaults (`speed: "auto"`, ...) on the echo, landing the
        interface on the unconfigured-default signature so it leaves the module's managed scope.

        ## Raises

        None
        """
        # TODO(4.2.1) c8000v-rejects-per-port-mtu
        # interfaceActions/normalize is structurally unusable for IOS-XE: its body requires mtu (schema validation
        # rejects an mtu-less body) and C8000V rejects the per-port mtu it carries. The lab-verified reset recipe is
        # this per-interface PUT (HTTP 204; probe 2026-07-27 with mtu omitted). ND 4.3.1 now requires the template-required
        # fields on this PUT too (`XE_RESET_POLICY_DEFAULTS`, issue #564); the C8000V rejection was observed on the normalize
        # template only, and create/update PUTs carrying mtu succeeded on it in the same 2026-07-27 session.
        return {
            "interfaceName": interface_name,
            "interfaceType": "ethernet",
            "switchId": switch_id,
            "configData": {
                "mode": cls.XE_RESET_MODE,
                "networkOS": {
                    "networkOSType": "ios-xe",
                    "policy": {"policyType": cls.XE_RESET_POLICY_TYPE, "adminState": True, **cls.XE_RESET_POLICY_DEFAULTS},
                },
            },
        }

    def _fabric_link_endpoints(self) -> dict[tuple[str, str], dict]:
        """
        # Summary

        Return the `(switch_id, lower-cased interface_name)` endpoints of every link in the fabric that carries an ND link policy
        (`configData.policyType`, e.g. `numbered`, `ebgpVrfLite`, `multisiteUnderlay`), each mapped to its link record. Links without a
        policy are discovered-only neighbor adjacencies (lab-verified 2026-09-03: leaf->ToR uplinks, vPC peer links) with no ND intent
        on the interface, so they do not make an interface fabric-owned. Both ends of a link are indexed, so a link another fabric
        owns that terminates on this fabric's switch is found under this fabric's listing.

        Fetched at most once per module run via `GET /api/v1/manage/links?fabricName=`, following `meta.counts.remaining` pagination
        with `offset`. A fabric with no links (HTTP 404 or an empty `links[]`) yields an empty map.

        ## Raises

        ### RuntimeError

        - Via `_request` if the links query fails with a non-404 status.
        """
        if self._fabric_link_endpoints_cache is not None:
            return self._fabric_link_endpoints_cache
        endpoints: dict[tuple[str, str], dict] = {}
        offset = 0
        while True:
            api_endpoint = EpManageLinksListGet()
            api_endpoint.endpoint_params.fabric_name = self.fabric_name
            if offset:
                api_endpoint.endpoint_params.offset = offset
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            links = result.get("links") if isinstance(result, dict) else None
            links = links if isinstance(links, list) else []
            for link in links:
                if not isinstance(link, dict):
                    continue
                if not (link.get("configData") or {}).get("policyType"):
                    continue
                for side in ("src", "dst"):
                    switch_id = link.get(f"{side}SwitchId")
                    interface_name = link.get(f"{side}InterfaceName")
                    if isinstance(switch_id, str) and isinstance(interface_name, str):
                        endpoints[(switch_id, interface_name.lower())] = link
            meta = (result.get("meta") or result.get("metadata") or {}) if isinstance(result, dict) else {}
            remaining = (meta.get("counts") or {}).get("remaining")
            if not links or not isinstance(remaining, int) or remaining <= 0:
                break
            offset += len(links)
        self._fabric_link_endpoints_cache = endpoints
        return endpoints

    def _check_xe_fabric_link(self, model_instance: ModelType, existing_data: dict | None = None) -> None:
        """
        # Summary

        Refuse to write an IOS-XE interface that is an endpoint of a fabric link carrying an ND link policy. Such an interface is
        fabric-owned even when its own record reads as a plain `iosXeRoutedHost` (see the class docstring), so policy type alone cannot
        express its ownership and the fabric links are consulted (`_fabric_link_endpoints`, fetched once per run). Shared by the
        create/update guard (`_check_fabric_ownership`) and the delete path (`preflight_delete`, `delete`, `delete_bulk`): the XE reset
        PUT would rewrite the endpoint's interface record underneath the link just like a host-policy overwrite would (PR #550 and
        PR #558 reviews). No-op for non-IOS-XE models, so NX-OS-only runs never fetch the links.

        ## Raises

        ### RuntimeError

        - If the IOS-XE interface is an endpoint of a fabric link that carries an ND link policy.
        - Via `_fabric_link_endpoints` if the links query fails.
        """
        if not self._model_is_ios_xe(model_instance) and not (existing_data is not None and self._is_ios_xe(existing_data)):
            return
        switch_ip = str(getattr(model_instance, "switch_ip", "") or "")
        interface_name = str(getattr(model_instance, "interface_name", "") or "")
        switch_id = self._resolve_switch_id(switch_ip)
        link = self._fabric_link_endpoints().get((switch_id, interface_name.lower()))
        if link is None:
            return
        raise RuntimeError(
            f"Interface {interface_name} on switch {switch_ip} is an endpoint of fabric link "
            f"{link.get('linkId')} ({(link.get('configData') or {}).get('policyType')}: {link.get('srcSwitchName')} "
            f"{link.get('srcInterfaceName')} -> {link.get('dstSwitchName')} {link.get('dstInterfaceName')}). Refusing to overwrite "
            f"fabric-owned intent with policy '{self._desired_policy_type(model_instance)}'; fabric links must be changed through "
            f"the fabric link workflow, not an interface module."
        )

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

    def _host_policy_replay_is_noop(self, model_instance: ModelType, existing_data: dict | None) -> bool:
        """Return whether host-shaped intent would leave the current wire policy unchanged.

        Contradictory controller evidence (a host policy plus an operational
        port-channel ID) must normally fail closed.  Fabric-wide overridden
        input can nevertheless contain an exact replay of an unrelated
        bystander so that it is preserved while another interface is reset.
        With deployment disabled, that exact replay causes no controller
        write and is safe to let the state machine classify as ``no_diff``.

        Any parsing or comparison uncertainty returns ``False`` so the caller
        retains the fail-closed behavior.
        """
        if existing_data is None:
            return False
        try:
            response = deepcopy(existing_data)
            response.setdefault("switchIp", model_instance.switch_ip)
            response.setdefault("interfaceName", model_instance.interface_name)
            existing_model = self.model_class.from_response(response)
            state = self.rest_send.params.get("state") if self.rest_send and self.rest_send.params else None
            exclude_unset = state == "merged"
            candidate = model_instance
            if not exclude_unset:
                candidate = model_instance.prepare_for_replacement(existing_model)
            return existing_model.get_diff(candidate, exclude_unset=exclude_unset)
        except Exception:  # pylint: disable=broad-exception-caught
            return False

    def _check_port_channel_restrictions(
        self,
        model_instance: ModelType,
        existing_data: dict | None = None,
        *,
        allow_unchanged: bool = False,
    ) -> None:
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
            if allow_unchanged and not self.deploy and self._host_policy_replay_is_noop(model_instance, existing_data):
                return
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

        Policy type alone cannot express IOS-XE ownership (a fabric-link endpoint can read as a plain `iosXeRoutedHost`, which is
        convertible), so an IOS-XE target that passes the policy-type check is additionally checked against the fabric's links
        (`_check_xe_fabric_link`). NX-OS targets never fetch the links: ND stamps a system policy type on every NX-OS link member.

        ## Raises

        ### RuntimeError

        - If the existing wire policy type is not in `CONVERTIBLE_POLICY_TYPES`.
        - Propagated from `_check_xe_fabric_link` (IOS-XE fabric-link endpoint, or links query failure).
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
            self._check_xe_fabric_link(model_instance, existing_data)
            return
        raise RuntimeError(
            f"Interface {model_instance.interface_name} on switch {model_instance.switch_ip} is owned by the fabric "
            f"(system policy '{existing_type}'). Refusing to overwrite it with policy '{self._desired_policy_type(model_instance)}'. "
            f"Only interfaces carrying a user-managed host policy can be converted; fabric links must be changed through the fabric "
            f"link workflow, not an interface module."
        )

    @classmethod
    def _is_absent_delete_reset_target(cls, existing_data: dict) -> bool:
        """Trust replay only for the exact defaults-only policy left by an ethernet reset.

        A different host policy can have pending CLI too, but an absent delete from
        this module has no authority to deploy it. Unknown or non-default fields
        fail closed rather than being mistaken for a completed reset.
        """

        config_data = existing_data.get("configData") or {}
        network_os = config_data.get("networkOS") or {}
        policy = network_os.get("policy") or {}
        if existing_data.get("interfaceType") != "ethernet" or not isinstance(policy, dict):
            return False
        network_os_type = network_os.get("networkOSType")
        policy_type = policy.get("policyType")
        if network_os_type == "nx-os" and policy_type == "trunkHost" and config_data.get("mode") == "trunk":
            defaults = InterfaceDefaultPolicyModel().model_dump(by_alias=True)
        elif network_os_type == "ios-xe" and policy_type == cls.XE_RESET_POLICY_TYPE and config_data.get("mode") == cls.XE_RESET_MODE:
            defaults = XeEthernetTrunkHostPolicyModel.reverse_diff_defaults
        else:
            return False
        # TODO(4.3.1) interface-get-field-normalization
        # ND 4.3.1 echoes these two NX-OS reset defaults with string values
        # (live-verified on a normalized access port on 2026-10-06). Permit
        # only the exact default values; non-default or unknown fields still
        # prevent an absent task from deploying another policy's pending CLI.
        return all(
            key == "policyType"
            or (key == "description" and value in (None, ""))
            or (network_os_type == "nx-os" and key == "accessVlan" and value in (1, "1"))
            or (network_os_type == "nx-os" and key == "ptp" and value in (False, "false"))
            or (key in defaults and value == defaults[key])
            for key, value in policy.items()
        )

    def _can_replay_absent_delete(self, existing_data: dict | None) -> bool:
        """Replay only exact ethernet reset echoes, never another policy's staged CLI."""

        return existing_data is not None and self._is_absent_delete_reset_target(existing_data)

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
                self._check_port_channel_restrictions(model_instance, existing_data, allow_unchanged=True)

    def preflight_delete(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Pre-delete validation run by `NDStateMachine` for `state: deleted` before `delete`/`delete_bulk` — which are skipped
        in `--check` mode — so a dry run fails on an unresolvable `switch_ip`, on an explicitly named port-channel member, or on an
        IOS-XE fabric-link endpoint exactly like a normal run would (PR #550 review). Wire state comes from the per-switch
        `interfaceList` cache `query_all` populated; the only additional request is the once-per-run links GET, and only when an
        IOS-XE interface is named. The fabric-wide `overridden` delete set is not routed through this hook: `delete_bulk` skips
        port-channel members and IOS-XE interfaces silently there.

        For an existing NX-OS interface, the state machine builds the delete set from `before[]`, and `query_all` already keeps the
        system policy types out of it. An absent target is checked against the raw inventory before any deploy replay. An IOS-XE
        fabric-link endpoint reads as a plain `iosXeRoutedHost` and passes that
        filter in the routed module, so it must be refused here (`_check_xe_fabric_link`). Even when a defaults-only endpoint is
        scoped out of `query_all`, an explicitly named `state: deleted` target reaches this hook through the state machine's absent
        target path. The guard therefore checks those names too, including the defaults-only fabric-link endpoints left by ND
        fabric provisioning (lab-verified 2026-09-08: WAN1 GigabitEthernet3, ISN->SITE2 `ebgpVrfLite`).

        ## Raises

        ### RuntimeError

        - If one or more `switch_ip` values do not match any switch in the fabric.
        - If any named interface is a port-channel member.
        - If the interface-list query used to resolve port-channel membership fails.
        - Propagated from `_check_xe_fabric_link` (IOS-XE fabric-link endpoint, or links query failure).
        """
        self._require_resolvable_switches(model_instances)
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing_data = self._existing_interface(model_instance.interface_name, switch_id)
            self._check_port_channel_delete_restriction(model_instance, existing_data, switch_id=switch_id)
            self._check_xe_fabric_link(model_instance, existing_data)

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

    def _port_channel_delete_restriction(
        self,
        model_instance: ModelType,
        existing_data: dict | None,
        *,
        switch_id: str,
    ) -> str | None:
        """Return the intent-first reason an ethernet delete must be refused.

        Configured intent is authoritative.  A supported member policy is
        protected immediately.  Otherwise the complete cached switch inventory
        is consulted for a parent port-channel or vPC claim before operational
        data is considered.  A recognized user-managed host policy with no
        parent claim is safe to reset even when ND still echoes a stale positive
        ``operData.portChannelId``.

        Unknown/protected member-like policies and unexplained positive
        operational membership remain fail-closed.
        """

        policy_type = self._existing_policy_type(existing_data)
        descriptor = get_member_policy_descriptor(policy_type)
        if descriptor is not None:
            configured_id = None
            if existing_data is not None:
                try:
                    configured_id = parse_member_interface_response(existing_data).normalized_port_channel_id
                except ValueError:
                    configured_id = None
            owner = f"port-channel {configured_id}" if configured_id is not None else f"member policy '{policy_type}'"
            return (
                f"Interface {model_instance.interface_name} is a member of {owner}. "
                "Refusing to normalize a port-channel member (this would strip its "
                "channel-group membership). Remove it from the parent first."
            )

        # State-machine and normal orchestrator flows populate this cache through
        # query_all() / _existing_interface() before deletion.  ``existing_data``
        # is also a documented synthetic test override; when such a direct caller
        # supplies it without a cache, classify only the supplied evidence rather
        # than issuing a surprising extra request.
        parent_claims = (
            self._membership_index().claiming_parents(switch_id, model_instance.interface_name) if switch_id in self._switch_interfaces_cache else ()
        )
        if parent_claims:
            parents = ", ".join(sorted(f"{claim.interface_name} ({claim.interface_type}, policy {claim.policy_type!r})" for claim in parent_claims))
            return (
                f"Interface {model_instance.interface_name} is still claimed by parent intent: {parents}. "
                "Refusing to normalize it because that would strip its channel-group membership. "
                "Remove it from the parent and wait for intent reconciliation before retrying."
            )

        disposition = classify_member_policy(policy_type)
        if disposition != MemberPolicyDisposition.NOT_MEMBER:
            return (
                f"Interface {model_instance.interface_name} uses protected or unsupported member policy "
                f"'{policy_type}'. Refusing to normalize it without a modeled ownership contract; "
                "reconcile the parent port-channel first."
            )

        port_channel_id = self._existing_port_channel_id(existing_data)
        if port_channel_id is None:
            return None
        if policy_type in self.CONVERTIBLE_POLICY_TYPES:
            logger.info(
                "Allowing delete of host-policy interface %s on switch %s despite stale operational port-channel %s; "
                "the cached intent contains no parent claim",
                model_instance.interface_name,
                switch_id,
                port_channel_id,
            )
            return None
        return (
            f"Interface {model_instance.interface_name} reports operational membership in port-channel "
            f"{port_channel_id}, but its configured policy is {policy_type!r} and no parent intent claim was found. "
            "Refusing to normalize inconsistent ownership evidence; reconcile the parent and retry."
        )

    def _check_port_channel_delete_restriction(
        self,
        model_instance: ModelType,
        existing_data: dict | None,
        *,
        switch_id: str | None = None,
    ) -> None:
        """
        # Summary

        Apply the shared intent-first deletion classifier and refuse unsafe
        normalization.  Current member policy and parent intent take precedence;
        stale positive operational membership does not override a recognized host
        policy after the parent claim has disappeared.

        ## Raises

        ### RuntimeError

        - If configured or parent intent still claims membership.
        - If member-like or operational evidence is inconsistent and cannot be
          proven safe.
        """
        resolved_switch_id = switch_id or self._resolve_switch_id(model_instance.switch_ip)
        restriction = self._port_channel_delete_restriction(
            model_instance,
            existing_data,
            switch_id=resolved_switch_id,
        )
        if restriction is not None:
            raise RuntimeError(restriction)

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
        attempted and stay queued. Each group is sent by `_post_normalize`, which resends once without `description` when ND 4.3.1
        rejects the template's empty string.

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
            try:
                results.append(self._post_normalize(api_endpoint, group))
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

    def _post_normalize(self, api_endpoint: EpManageInterfacesNormalize, group: list[tuple[str, str]]) -> ResponseType:
        """
        # Summary

        POST one normalize group and return the response `DATA`. The first attempt of a run sends the full `int_trunk_host` template,
        including `description: ""`, which is what ND 4.2.1 needs to clear a description (4.2.1 leaves an omitted field untouched).
        ND 4.3.1 enforces the spec's `interfaceDescription` minLength 1 and rejects that body outright with HTTP 400
        `Error at /configData/networkOS/policy/description: minimum string length is 1`, while it does reset an omitted field. On that
        exact rejection the group is resent once without `description`, and `_normalize_omits_description` stays set so later groups
        in the run skip the failing attempt. Lab-verified on 4.2.1.10 and 4.3.1.175 (2026-09-11); vault
        `empty-interface-description-accepted`. Any other failure, and a failure of the resend, propagates unchanged so the caller's
        partial-success bookkeeping is unaffected: a 400 rejects the whole request, so nothing in the group was accepted by the first
        attempt.

        ## Raises

        ### Exception

        - If the normalize request fails for any reason other than the ND 4.3.1 empty-description rejection, or if the resend fails.
        """
        payload = InterfaceDefaultConfig.to_normalize_payload(group, omit_description=self._normalize_omits_description)
        response_count = self.rest_send.response_count
        try:
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
        except Exception:
            if not self._normalize_omits_description and self._rejected_empty_description(response_count):
                self._normalize_omits_description = True
                payload = InterfaceDefaultConfig.to_normalize_payload(group, omit_description=True)
                return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
            raise

    def _rejected_empty_description(self, response_count: int) -> bool:
        """
        # Summary

        Return `True` if the most recent response is a fresh HTTP 400 whose schema errors name `/configData/networkOS/policy/description`
        with `minimum string length`, i.e. ND 4.3.1 refusing the template's empty description. `response_count` is
        `rest_send.response_count` before the request: `RestSend` keeps the previous `response_current` when the sender raises (issue #554),
        so the response is only read when the count grew. The count is read, never the copying `responses` list, because this runs once
        per normalize group and the history holds one inventory response per switch (PR #563 review).

        ## Raises

        None
        """
        if self.rest_send.response_count <= response_count:
            return False
        response = self.rest_send.response_current
        if response.get("RETURN_CODE") != 400:
            return False
        data = response.get("DATA")
        errors = data.get("errors") if isinstance(data, dict) else None
        if not isinstance(errors, list):
            return False
        for error in errors:
            detail = str(error.get("description", "")) if isinstance(error, dict) else ""
            if "/policy/description" in detail and "minimum string length" in detail:
                return True
        return False

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
        An IOS-XE interface is instead queued for the per-interface XE reset PUT (`_queue_xe_reset`) after the
        fabric-link endpoint check (`_check_xe_fabric_link`).

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
        - Propagated from `_check_xe_fabric_link` for an IOS-XE interface that is a fabric-link endpoint.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing_data = kwargs.get("existing_data") or self._existing_interface(model_instance.interface_name, switch_id)
            self._check_port_channel_delete_restriction(model_instance, existing_data, switch_id=switch_id)
            if self._model_is_ios_xe(model_instance):
                self._check_xe_fabric_link(model_instance)
                self._queue_xe_reset(model_instance.interface_name, switch_id)
                self._queue_deploy(model_instance.interface_name, switch_id)
                return {}
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
            groups = self.bulk_create_groups(model_instances, **kwargs)
            results = []
            for group_key, items in groups.items():
                results.append(self._post_bulk_create_group(group_key, items))
            return results
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

    def _prepare_bulk_item(self, model_instance: ModelType, switch_id: str, **kwargs) -> None:
        """
        # Summary

        Run Ethernet's ownership and member guards before the shared bulk grouping serializes an item. Every item is prepared before
        the first POST, preserving the batch's fail-before-write behavior.

        ## Raises

        ### RuntimeError

        - Via `_check_fabric_ownership` or `_check_port_channel_restrictions`.
        """
        existing_data = kwargs.get("existing_data") or self._existing_interface(model_instance.interface_name, switch_id)
        existing_policy_type = self._existing_policy_type(existing_data)
        if classify_member_policy(existing_policy_type) != MemberPolicyDisposition.NOT_MEMBER:
            raise RuntimeError(
                f"Interface {model_instance.interface_name} already exists with member "
                f"policy '{existing_policy_type}'; a member must never be sent through "
                "the create endpoint."
            )
        self._check_fabric_ownership(model_instance, existing_data)
        self._check_port_channel_restrictions(model_instance, existing_data)

    def delete_bulk(self, model_instances: list[ModelType], **kwargs) -> None:
        """
        # Summary

        Queue multiple ethernet interfaces for deferred bulk normalization and deployment. Each NX-OS interface is queued
        for normalization via `remove_pending` (which resets it to the `int_trunk_host` template) and deployment via
        `deploy_pending`. No API calls are made until those methods are called after `manage_state` completes.

        IOS-XE interfaces are routed per state: under `state: overridden` they are skipped (merge-only, logged at INFO);
        otherwise (a user-named `state: deleted` item) they pass the fabric-link endpoint check (`_check_xe_fabric_link`) and are queued for the
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
        - Propagated from `_check_xe_fabric_link` for an IOS-XE interface that is a fabric-link endpoint.
        """
        state = self.rest_send.params.get("state") if self.rest_send and self.rest_send.params else None
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            if self._model_is_ios_xe(model_instance) and state == "overridden":
                logger.info(
                    "Skipping IOS-XE interface %s on switch %s during state:overridden (IOS-XE interfaces are merge-only)",
                    model_instance.interface_name,
                    model_instance.switch_ip,
                )
                continue
            existing_data = kwargs.get("existing_data") or self._existing_interface(model_instance.interface_name, switch_id)
            restriction = self._port_channel_delete_restriction(
                model_instance,
                existing_data,
                switch_id=switch_id,
            )
            if restriction is not None:
                if state == "overridden":
                    logger.info(
                        "Skipping protected interface %s on switch %s during state:overridden: %s",
                        model_instance.interface_name,
                        model_instance.switch_ip,
                        restriction,
                    )
                    continue
                raise RuntimeError(restriction)
            if self._model_is_ios_xe(model_instance):
                self._check_xe_fabric_link(model_instance)
                self._queue_xe_reset(model_instance.interface_name, switch_id)
                self._queue_deploy(model_instance.interface_name, switch_id)
                continue
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

    def query_all(self, model_instance: ModelType | None = None, gathered_filters: list[dict] | None = None, **kwargs) -> ResponseType:
        """
        # Summary

        Validate the fabric context and query interfaces, filtering for ethernet interfaces with policy types
        managed by this orchestrator (as defined by `_managed_policy_types()`).

        For management states, switches are determined by `_switches_to_query`: fabric-wide for
        `state: overridden`, config-scoped for others. For `state: gathered`, the query plan is
        built from gathered filters via `_build_gathered_query_plan`.

        Under `state: overridden`, IOS-XE interfaces that are not named in the task config are dropped (IOS-XE is merge-only:
        a Catalyst or C8000V port can carry fabric-link intent with no ownership marker on the interface record, so a fabric-wide
        delete set must never include one). This happens at query scope — not merely at delete time — so the state machine never
        computes delete intent for them and the module's changed/diff reporting stays truthful.

        Compatible port-channel members are projected into mutating-state results only when explicitly named by
        the task. Omitted members remain outside family and overridden scope, and gathered remains host-only.
        `delete_bulk` also skips members so fabric-wide convergence cannot detach them from their port-channels.

        Runs `validate_prerequisites` on first call to ensure the fabric exists and is modifiable before returning any data.

        Each returned interface dict is enriched with a `switch_ip` field so that the model can be constructed
        with the composite identifier `(switch_ip, interface_name)`.

        ## Raises

        ### RuntimeError

        - If the fabric does not exist on the target ND node.
        - If the fabric is in deployment-freeze mode and the state mutates configuration.
        - If the query API request fails.
        """
        managed_types = self._managed_policy_types()
        try:
            self.validate_prerequisites()

            if gathered_filters is not None and self.gathered_lucene_spec is not None:
                return self._query_all_for_gathered(gathered_filters, managed_types)

            return self._query_all_for_management_states(managed_types)
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e

    def _query_all_for_management_states(self, managed_types: set[str]) -> list[dict]:
        """
        # Summary

        Preserve the existing list-all behaviour used by merged, replaced, overridden, and deleted states.

        ## Raises

        ### RuntimeError
        - Via `_switch_interfaces` if the interface-list API request fails.
        """
        all_interfaces = []
        for switch_ip, switch_id in self._switches_to_query().items():
            interfaces = list(self._switch_interfaces(switch_id).values())
            ethernet_interfaces = [iface for iface in interfaces if iface.get("interfaceType") == "ethernet"]
            managed = [
                iface for iface in ethernet_interfaces if iface.get("configData", {}).get("networkOS", {}).get("policy", {}).get("policyType") in managed_types
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

    def _query_all_for_gathered(self, gathered_filters: list[dict], managed_types: set[str]) -> list[dict]:
        """
        # Summary

        Run server-filtered gathered requests using Lucene expressions built from the orchestrator's
        ``gathered_lucene_spec``. Each expression targets one switch with one Lucene filter. Results
        are post-filtered by ``policyType`` and enriched with ``switchIp``.

        ## Raises

        ### ValueError

        - Via `_build_gathered_query_plan` if a filter references a non-existent switch_ip.

        ### RuntimeError

        - Via `_query_interfaces_with_lucene` if pagination limits are exceeded.
        """
        query_plan = self._build_gathered_query_plan(gathered_filters)

        all_interfaces = []
        for switch_ip, (switch_id, expressions) in query_plan.items():
            for expression in sorted(expressions):
                candidates = self._query_interfaces_with_lucene(
                    switch_id=switch_id,
                    expression=expression,
                )
                managed = [
                    iface for iface in candidates if iface.get("configData", {}).get("networkOS", {}).get("policy", {}).get("policyType") in managed_types
                ]
                for iface in managed:
                    iface["switchIp"] = switch_ip
                all_interfaces.extend(managed)

        return all_interfaces
