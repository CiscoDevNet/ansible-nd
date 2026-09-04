# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Ethernet routed-mode interface orchestrator for Nexus Dashboard (issue #447).

This module provides `EthernetRoutedInterfaceOrchestrator`, which manages CRUD operations for
ethernet routed-mode interfaces. It inherits all shared ethernet logic from `EthernetBaseOrchestrator`
(including the normalize-based delete for physical interfaces and the port-channel-membership guards)
and only defines the model class and managed policy types.

L3 routed IS supported on VXLAN fabrics: the GUI create wizard's "0 capable switches" is the unpublished
`capableSwitches` endpoint's create-wizard semantics surfacing in the UI, not a mode-capability verdict —
both the per-interface PUT and the bulk POST accept `routedHost` on a VXLAN leaf (lab-verified 2026-07-27).
"""

from __future__ import annotations

import logging
from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_links import EpManageLinksListGet
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    EthernetRoutedPolicyTypeEnum,
    XeEthernetRoutedPolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_routed_interface import (
    EthernetRoutedInterfaceModel,
    NexusEthernetRoutedPolicyModel,
    XeEthernetRoutedPolicyModel,
    normalize_ethernet_interface_name,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.policy_base import InterfacePolicyStrictBase
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import EthernetBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

logger = logging.getLogger(__name__)

# Policy model per managed policy type. The unconfigured-default signature used by `query_all`'s scope filter is derived
# from each model's `reverse_diff_defaults` table (the schema-sourced template defaults, in dumped form) so the query
# filter and the replaced/overridden reverse pass share one source of truth.
_POLICY_MODELS: dict[str, type[InterfacePolicyStrictBase]] = {
    "routedHost": NexusEthernetRoutedPolicyModel,
    "iosXeRoutedHost": XeEthernetRoutedPolicyModel,
}

# TODO(4.2.1) interface-get-undocumented-ptp-field
# Read-only keys ND 4.2.1 injects into GET responses that the template does not declare (`ptp` is absent from
# `intRoutedHostTemplate`). The models drop them on read, so they cannot live in `reverse_diff_defaults`; the query
# filter still has to recognize them at their injected value as part of an unconfigured default.
_ND_INJECTED_READ_KEY_DEFAULTS: dict[str, dict] = {
    "routedHost": {"ptp": False},
}


class EthernetRoutedInterfaceOrchestrator(EthernetBaseOrchestrator):
    """
    # Summary

    Orchestrator for ethernet routed-mode interface CRUD operations on Nexus Dashboard.

    Inherits all shared ethernet logic from `EthernetBaseOrchestrator`. Defines `model_class` as
    `EthernetRoutedInterfaceModel` and manages the `routedHost` (NX-OS) and `iosXeRoutedHost` (IOS-XE)
    policy types.

    The managed-set filter in `query_all` (via `_managed_policy_types`) is this module's underlay-safety
    boundary: the wire carries many system routed policy types (`numbered` fabric links, `multiSiteLinkMember`,
    `vrfLiteLinkMember`, `vpcPeerKeepAlive`, `mplsUplink`, `csrMultisiteIfcMember`, ...) that share
    `configData.mode: "routed"` with the managed types. Filtering by policy type — never by mode — keeps
    fabric underlay intent out of `before[]`, so `state: overridden` cannot bulldoze it. Treat any loosening
    of this filter as review-blocking.

    The filter alone does not protect a fabric link the task names EXPLICITLY (a mistyped `interface_name`): the
    state machine cannot see it, classifies it as a create, and the bulk POST would replace the link's intent
    (PR #550 review). `EthernetBaseOrchestrator._check_fabric_ownership` closes that gap for NX-OS by inspecting the
    unfiltered wire policy before any write (only `CONVERTIBLE_POLICY_TYPES` may be overwritten). IOS-XE needs one
    more source of truth: a C8000V fabric link can carry a plain `iosXeRoutedHost` with no ownership marker on the
    interface record (lab-verified 2026-09-03: WAN1 `GigabitEthernet3`, endpoint of the ISN->SITE2 `ebgpVrfLite`
    link, reads as a defaults-only `iosXeRoutedHost`), so `_check_fabric_ownership` here additionally consults the
    fabric's links (`GET /api/v1/manage/links?fabricName=`, fetched once per run and only when an IOS-XE interface is
    written) and refuses an interface that is an endpoint of a link carrying an ND link policy.

    Like `EthernetTrunkHostInterfaceOrchestrator`, this orchestrator filters unconfigured fabric defaults out of
    `query_all` - but for the opposite reason. ND's fabric default interface policy is ROLE-DEPENDENT
    (lab-verified 2026-07-27): leaf free ports default to `trunkHost`, while EVERY unused port on a
    borderGateway defaults to a defaults-only `routedHost` (and core-router IOS-XE ports to `iosXeRoutedHost`).
    Without the `_is_unconfigured_default` filter, all of those ports would land in `before[]` and
    `state: overridden` would normalize every unused port on the switch. Treat any loosening of this filter
    as review-blocking, alongside the managed-set filter above. The one carve-out is an interface the task
    names explicitly: a defaults-only routed interface whose `(switch_ip, interface_name)` appears in the
    config is retained, so "make this port routed with all defaults" converges on the second run instead of
    re-creating forever, and a defaults-only borderGateway port named in the task is matched rather than
    re-created (PR #550 review). Unnamed defaults stay excluded, so the `overridden` blast radius is unchanged.

    A mode flip (trunk -> routed) needs no special handling: a trunk-intent interface is invisible to
    `before[]` (not in the managed set), so the state machine classifies the task as a create, and the
    create POST rewrites the intent to routed (lab-verified 2026-07-27).

    HTTP 207 handling is inherited: `NdV1Strategy` classifies any non-exact-success `results[]` item as a
    failure, and `EthernetBaseOrchestrator.create_bulk` queues the exact-success members of a failed
    per-switch group for deploy so the module's failure-path finalizer ships them instead of stranding them
    staged. Per-switch bulk groups are single-policy-type by construction in this module's initial scope
    (each switch runs one network OS); the feature-gated follow-up branches (`endPointLocator`, `ipfmL3Port`,
    `dataBrokerL3Host`) must adopt per-(switch, policy_type) grouping when they land.

    ## Raises

    ### RuntimeError

    - Via inherited methods. See `EthernetBaseOrchestrator` for full details.
    """

    model_class: ClassVar[type[NDBaseModel]] = EthernetRoutedInterfaceModel

    # TODO(4.2.1) capable-switches-empty-for-ethernet-on-vxlan
    # Deliberate opt-OUT of the capability preflight (both ClassVars ""): the unpublished capableSwitches
    # endpoint returns an empty switches[] for EVERY ethernet mode (trunk, access, routed) on a VXLAN fabric —
    # it answers "where can the GUI wizard create an interface of this type" (physical ports already exist,
    # so: nowhere), not "which switches support this mode" — while the write paths for routedHost succeed.
    # Opting in with ("ethernet", "routed") would veto every switch for an operation the API accepts.
    interface_type: ClassVar[str] = ""
    interface_mode: ClassVar[str] = ""

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator: the union of the NX-OS
        (`routedHost`) and IOS-XE (`iosXeRoutedHost`) managed routed policy types. System routed policy types and
        `userDefined` are excluded — see the class docstring's underlay-safety note.

        ## Raises

        None
        """
        return {e.value for e in EthernetRoutedPolicyTypeEnum} | {e.value for e in XeEthernetRoutedPolicyTypeEnum}

    def model_post_init(self, __context) -> None:
        """
        # Summary

        Initialize the routed-specific mutable state after Pydantic model construction. Extends
        `EthernetBaseOrchestrator.model_post_init` (normalize/reset queues) with `_pending_xe_resets`, initialized the
        same way as the sibling queues, and the lazily populated fabric-link endpoint cache (`_fabric_link_endpoints_cache`,
        `None` until `_fabric_link_endpoints` first fetches the links).

        ## Raises

        None
        """
        super().model_post_init(__context)
        self._pending_xe_resets: list[tuple[str, str]] = []
        self._fabric_link_endpoints_cache: dict[tuple[str, str], dict] | None = None

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

    def _check_fabric_ownership(self, model_instance: NDBaseModel, existing_data: dict | None) -> None:
        """
        # Summary

        Extend `EthernetBaseOrchestrator._check_fabric_ownership` (wire policy type must be user-convertible) with a fabric-link
        endpoint check for IOS-XE targets: an interface that is an endpoint of a link carrying an ND link policy is fabric-owned even
        when its own record reads as a plain `iosXeRoutedHost` (see the class docstring). NX-OS targets rely on the policy-type guard
        alone — ND stamps a system policy type on every NX-OS link member — so NX-OS-only runs never fetch the links.

        ## Raises

        ### RuntimeError

        - Propagated from `EthernetBaseOrchestrator._check_fabric_ownership` (fabric-owned wire policy type).
        - If an IOS-XE interface is an endpoint of a fabric link that carries an ND link policy.
        - Via `_fabric_link_endpoints` if the links query fails.
        """
        super()._check_fabric_ownership(model_instance, existing_data)
        network_os = getattr(getattr(model_instance, "config_data", None), "network_os", None)
        if getattr(network_os, "network_os_type", None) != "ios-xe":
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
    def _xe_reset_payload(interface_name: str, switch_id: str) -> dict:
        """
        # Summary

        Build the per-interface PUT body that resets an IOS-XE routed interface to its fabric default: a defaults-only
        `iosXeRoutedHost` policy with no `mtu` key. ND injects the schema defaults (`mtu: 1500`, `speed: "auto"`) on the
        echo, landing the interface on the unconfigured-default signature so it leaves this module's managed scope.

        ## Raises

        None
        """
        # TODO(4.2.1) c8000v-rejects-per-port-mtu
        # interfaceActions/normalize is structurally unusable for IOS-XE: its body requires mtu (schema validation
        # rejects an mtu-less body) and C8000V rejects the per-port mtu it carries. The lab-verified reset recipe is
        # this per-interface PUT with mtu omitted (HTTP 204; probe 2026-07-27).
        return {
            "interfaceName": interface_name,
            "interfaceType": "ethernet",
            "switchId": switch_id,
            "configData": {
                "mode": "routed",
                "networkOS": {"networkOSType": "ios-xe", "policy": {"policyType": "iosXeRoutedHost", "adminState": True}},
            },
        }

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

    def delete_bulk(self, model_instances: list, **kwargs) -> None:
        """
        # Summary

        Queue interfaces for deferred reset with per-OS routing:

        - Under `state: overridden`, IOS-XE interfaces are merge-only: the fabric-wide overridden delete set never
          includes an `ios-xe` interface, because IOS-XE fabric links can carry plain configured `iosXeRoutedHost`
          with no intent-side ownership marker (lab-verified 2026-07-27: WAN1's multisite link) — a policy-type-scoped
          delete set would strip real fabric links. Skipped interfaces are logged at INFO.
        - IOS-XE interfaces the user names explicitly under `state: deleted` are queued for the XE reset path
          (per-interface PUT via `remove_pending`) plus deploy — never the family normalize, whose body is
          structurally unusable on C8000V (see `_xe_reset_payload`).
        - NX-OS interfaces delegate unchanged to `EthernetBaseOrchestrator.delete_bulk` (port-channel guards,
          normalize/reset queueing).

        ## Raises

        ### RuntimeError

        - Propagated from `EthernetBaseOrchestrator.delete_bulk` (switch resolution, port-channel restrictions,
          interface-list query failures) or from `_resolve_switch_id` for IOS-XE items.
        """
        state = self.rest_send.params.get("state") if self.rest_send and self.rest_send.params else None
        nx_instances: list = []
        for model_instance in model_instances:
            network_os = model_instance.config_data.network_os if model_instance.config_data else None
            if network_os is not None and network_os.network_os_type == "ios-xe":
                if state == "overridden":
                    logger.info(
                        "Skipping IOS-XE interface %s on switch %s during state:overridden (IOS-XE interfaces are merge-only)",
                        model_instance.interface_name,
                        model_instance.switch_ip,
                    )
                    continue
                switch_id = self._resolve_switch_id(model_instance.switch_ip)
                self._queue_xe_reset(model_instance.interface_name, switch_id)
                self._queue_deploy(model_instance.interface_name, switch_id)
                continue
            nx_instances.append(model_instance)
        super().delete_bulk(nx_instances, **kwargs)

    def remove_pending(self) -> list:
        """
        # Summary

        Flush deferred delete-side work: reset queued IOS-XE interfaces one-at-a-time via per-interface PUT with the
        C8000V-safe `_xe_reset_payload` body, then delegate to `EthernetBaseOrchestrator.remove_pending` for the NX-OS
        normalize/reset queues.

        Fail-fast: on the first XE PUT failure the remaining XE interfaces (and the NX-OS queues) are not attempted.
        ND has no rollback for a per-interface PUT, so interfaces reset before the failure stay at fabric default; the
        raised error names which XE interfaces succeeded, which one failed, and which were not attempted so the user
        can reconcile the partial state.

        ## Raises

        ### RuntimeError

        - If an XE reset PUT request fails (with partial-state detail as described above).
        - Propagated from `EthernetBaseOrchestrator.remove_pending` on NX-OS normalize/reset failure.
        """
        results: list = []
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
        base_results = super().remove_pending()
        if isinstance(base_results, list):
            results.extend(base_results)
        return results

    def _unsent_delete_pairs(self) -> set[tuple[str, str]]:
        """
        # Summary

        Extend the ethernet set of not-yet-accepted delete pairs with the IOS-XE reset queue (dequeued pair by pair as each reset
        PUT succeeds), so the failure-path finalizer never deploys an XE interface whose reset failed or was never attempted.

        ## Raises

        None
        """
        return super()._unsent_delete_pairs() | set(self._pending_xe_resets)

    @staticmethod
    def _unconfigured_default_signature(policy_type: str) -> dict | None:
        """
        # Summary

        Return the wire-form unconfigured-default signature for a managed `policy_type`: the policy model's
        `reverse_diff_defaults` table merged with the ND-injected read keys the model never declares, or `None` when the
        policy type is not managed by this orchestrator.

        ## Raises

        None
        """
        policy_cls = _POLICY_MODELS.get(policy_type)
        if policy_cls is None:
            return None
        return {**policy_cls.reverse_diff_defaults, **_ND_INJECTED_READ_KEY_DEFAULTS.get(policy_type, {})}

    @staticmethod
    def _is_unconfigured_default(iface: dict) -> bool:
        """
        # Summary

        Return `True` if the given interface API response represents an unconfigured fabric-default routed interface:
        every key in its policy is either `policyType` or matches the wire-form schema default for that policy type
        (`_unconfigured_default_signature`). Any other key present (`ip`, `prefix`, `description`, `routingTag`,
        `vrfInterface`, ...) or any non-default value means the interface is user-configured and stays in scope.

        On switches whose fabric default interface policy is routed (borderGateway NX-OS ports, core-router IOS-XE
        ports), this predicate is the only thing keeping every unused port out of `before[]` — see the class docstring.

        ## Raises

        None
        """
        policy = ((iface.get("configData") or {}).get("networkOS") or {}).get("policy") or {}
        policy_type = policy.get("policyType")
        if not isinstance(policy_type, str):
            return False
        defaults = EthernetRoutedInterfaceOrchestrator._unconfigured_default_signature(policy_type)
        if defaults is None:
            return False
        for key, value in policy.items():
            if key == "policyType":
                continue
            if key not in defaults or value != defaults[key]:
                return False
        return True

    def _named_interfaces(self) -> set[tuple[str, str]]:
        """
        # Summary

        Return the `(switch_ip, interface_name)` pairs named in the task config, with interface names canonicalized by the
        same normalizer the model uses so abbreviated or re-cased names match the wire form.

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

    def query_all(self, model_instance: NDBaseModel | None = None, **kwargs) -> ResponseType:
        """
        # Summary

        Query all managed routed interfaces in the fabric via the base orchestrator, then apply two scope filters:

        1. Drop interfaces matching an unconfigured fabric-default signature UNLESS the task names them, keeping
           default-routed free ports (borderGateway / core-router fabric defaults) out of `before[]` so `state: overridden`
           converges only user-configured interfaces and idempotency holds across re-runs. A named defaults-only interface
           is retained so an explicit "routed with all defaults" intent converges (second run `changed: false`) and a
           named defaults-only borderGateway port is matched rather than re-created (PR #550 review). The one exception is
           a named defaults-only IOS-XE interface under `state: deleted`: the XE reset (`_xe_reset_payload`) lands exactly
           on that signature, so the interface is already at its reset target and stays out of scope — otherwise every
           `deleted` run would re-reset it and report a change. NX-OS keeps it in scope there because the NX reset target
           is the `trunkHost` template, a real mode flip away from a defaults-only `routedHost`.
        2. Under `state: overridden`, drop IOS-XE interfaces that are not named in the task config (XE merge-only).
           This must happen at query scope — not merely at delete time — so the state machine never computes delete
           intent for them and the module's changed/diff reporting stays truthful.

        ## Raises

        ### RuntimeError

        - Propagated from `EthernetBaseOrchestrator.query_all` on query failure.
        """
        result = super().query_all(model_instance=model_instance, **kwargs)
        if not isinstance(result, list):
            return result
        named = self._named_interfaces()
        state = self.rest_send.params.get("state") if self.rest_send and self.rest_send.params else None

        def in_scope(iface: dict) -> bool:
            if not self._is_unconfigured_default(iface):
                return True
            if (iface.get("switchIp"), iface.get("interfaceName")) not in named:
                return False
            return not (state == "deleted" and self._is_ios_xe(iface))

        result = [iface for iface in result if in_scope(iface)]
        if state == "overridden":
            result = [iface for iface in result if not self._is_ios_xe(iface) or (iface.get("switchIp"), iface.get("interfaceName")) in named]
        return result

    @staticmethod
    def _is_ios_xe(iface: dict) -> bool:
        """
        # Summary

        Return `True` when the interface API response carries `configData.networkOS.networkOSType == "ios-xe"`.

        ## Raises

        None
        """
        return ((iface.get("configData") or {}).get("networkOS") or {}).get("networkOSType") == "ios-xe"
