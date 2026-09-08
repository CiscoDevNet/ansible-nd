# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# pyright: reportAttributeAccessIssue=false
# ModelType is NDBaseModel which lacks interface-specific fields (switch_ip,
# interface_name, config_data). Concrete subclasses always bind ModelType to a
# model that provides these fields, so the accesses are safe at runtime.

"""
Base orchestrator for vPC interface modules on Nexus Dashboard.

This module provides `VpcInterfaceBaseOrchestrator`, which implements shared CRUD operations for all vPC interface
types (`accessVpcHost`, `trunkVpcHost`, etc.) via the ND Manage Interfaces API. Type-specific orchestrators
inherit from this base and provide their own `model_class` and `_managed_policy_types()`.

Inherits shared interface lifecycle operations (deploy queuing, fabric validation, switch resolution) from
`NDBaseInterfaceOrchestrator` and adds vPC-specific functionality:

- Peer-serial auto-resolution: each create/update reads the per-switch `vpcPair` endpoint to obtain the peer
  serial, then injects it as `peerSwitchId` in the payload. Results are cached per orchestrator instance so
  bulk operations make at most one lookup per primary switch.
- Standard remove-based deletion (vPC interfaces are virtual and deletable).
- Fabric-wide `query_all()` filtered by `interfaceType: "vpc"` and per-type policy filtering.

A vPC interface spans two switches in a vPC pair; the user supplies one peer's management IP as `switch_ip`.
If the supplied switch is not in a vPC pair the orchestrator raises a clear `RuntimeError` instructing the
user to create the pair first via `nd_manage_vpc_pair`.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_vpc_pair import (
    EpVpcPairGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesDelete,
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import requires_bulk_support
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

ModelType = NDBaseModel


class VpcInterfaceBaseOrchestrator(NDBaseInterfaceOrchestrator[ModelType]):
    """
    # Summary

    Base orchestrator for vPC interface CRUD operations on Nexus Dashboard.

    Provides shared logic for all vPC interface types. Subclasses must set `model_class` and implement
    `_managed_policy_types()` to define which policy types they manage.

    Each create/update reads the `vpcPair` record for the primary switch to obtain the peer serial, which is
    then injected as `peerSwitchId` in the payload. Lookups are cached per orchestrator instance.

    Mutation methods (`create`, `update`) queue deploys for bulk execution. `delete` issues an immediate
    per-interface `DELETE /interfaces/{name}` (the bulk `interfaceActions/remove` endpoint rejects vPC interfaces;
    see the `TODO(4.2.1)` below) and queues a deploy. Call `deploy_pending` after all mutations are complete.

    ## Raises

    ### RuntimeError

    - Via `validate_prerequisites` if the fabric does not exist or is in deployment-freeze mode.
    - Via `_resolve_switch_id` if no switch matches the given IP in the fabric.
    - Via `_resolve_peer_switch_id` if the switch is not in a vPC pair.
    - Via `create` if the create API request fails.
    - Via `update` if the update API request fails.
    - Via `remove_pending` if the bulk remove API request fails.
    - Via `deploy_pending` if the bulk deploy API request fails.
    - Via `query_one` if the query API request fails.
    - Via `query_all` if the query API request fails.
    """

    # TODO(4.2.1) vpc-interface-bulk-delete-silent-fail
    # The bulk `/api/v1/manage/fabrics/{fabric}/interfaceActions/remove` endpoint returns
    # `{"status":"Failed","message":"Invalid Interface"}` inside a 207 for vPC interfaces (lab-verified). The
    # per-interface `DELETE /interfaces/{name}` endpoint works (returns 204). We therefore disable bulk delete and
    # use the per-interface DELETE via `delete_endpoint`.
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = False

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = None

    def model_post_init(self, __context) -> None:
        """
        # Summary

        Initialize mutable private state. Extends `NDBaseInterfaceOrchestrator.model_post_init` with a
        per-instance peer-serial cache so bulk operations make at most one `vpcPair` GET per primary switch.

        ## Raises

        None
        """
        super().model_post_init(__context)
        self._peer_serial_cache: dict[str, str] = {}

    def preflight(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Run the shared interface preflight, then reject a config that lists the same `interface_name` under both peers of one vPC
        pair. With the composite `(switch_ip, interface_name)` identity (issue #356) such a config parses as two proposed items that
        target a single ND resource; failing fast here (the state machine runs `preflight` before any mutation, in check mode too)
        prevents a double-write against one interface. Pair resolution runs ONLY for names that appear more than once, so runs with
        unique names — the common case — issue no additional requests; the duplicate path costs one cached `vpcPair` GET per distinct
        primary switch, reused later by create/update.

        ## Raises

        ### RuntimeError

        - If two (or more) proposed items share an `interface_name` and resolve to the same vPC pair.
        - Propagated from `super().preflight` / `_resolve_switch_id` / `_resolve_peer_switch_id` (unresolvable switch, missing pair).
        """
        super().preflight(model_instances)
        items_by_name: dict[str, list[ModelType]] = {}
        for model_instance in model_instances:
            items_by_name.setdefault(model_instance.interface_name, []).append(model_instance)
        offenders: list[str] = []
        for name, items in items_by_name.items():
            if len(items) < 2:
                continue
            switch_ips_by_pair: dict[frozenset[str], list[str]] = {}
            for item in items:
                switch_id = self._resolve_switch_id(item.switch_ip)
                peer_serial = self._resolve_peer_switch_id(item.switch_ip, switch_id)
                switch_ips_by_pair.setdefault(frozenset({switch_id, peer_serial}), []).append(item.switch_ip)
            for switch_ips in switch_ips_by_pair.values():
                if len(switch_ips) > 1:
                    offenders.append(
                        f"{name} is listed for multiple peers ({', '.join(sorted(switch_ips))}) of the same vPC pair; list it once, under either peer"
                    )
        if offenders:
            raise RuntimeError(f"Invalid vPC config in fabric '{self.fabric_name}': " + "; ".join(sorted(offenders)))

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator. Subclasses must override this method
        to return their specific policy types (e.g., `{"accessVpcHost"}` for the access orchestrator).

        ## Raises

        ### NotImplementedError

        - Always, if not overridden by a subclass.
        """
        raise NotImplementedError("Subclasses must implement _managed_policy_types()")

    def _resolve_peer_switch_id(self, switch_ip: str, primary_serial: str) -> str:
        """
        # Summary

        Resolve the peer switch's serial number for the vPC pair containing `primary_serial`. Reads the per-switch
        `vpcPair` endpoint. Caches the result per orchestrator instance so bulk operations issue at most one lookup
        per primary switch.

        ## Raises

        ### RuntimeError

        - If the switch is not in a vPC pair (the `vpcPair` GET returns 404 / empty body).
        - If the `vpcPair` GET returns success but omits `peerSwitchId`.
        """
        cached = self._peer_serial_cache.get(primary_serial)
        if cached:
            return cached
        api_endpoint = EpVpcPairGet()
        api_endpoint.fabric_name = self.fabric_name
        api_endpoint.switch_id = primary_serial
        result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
        if not result:
            raise RuntimeError(
                f"Switch {switch_ip} (serial {primary_serial}) is not in a vPC pair; "
                f"create the pair via nd_manage_vpc_pair before configuring vPC interfaces."
            )
        peer_serial = result.get("peerSwitchId")
        if not peer_serial:
            raise RuntimeError(f"vPC pair record for switch {switch_ip} (serial {primary_serial}) is missing 'peerSwitchId'; " f"received: {result!r}")
        self._peer_serial_cache[primary_serial] = peer_serial
        return peer_serial

    def _inject_peer_switch_id(self, payload: dict, peer_serial: str) -> dict:
        """
        # Summary

        Inject `peerSwitchId` into the nested `configData.networkOS.policy` block of an interface payload. Every vPC
        interface requires a peer serial, so a payload without a `policy` block is structurally invalid and is rejected
        here rather than silently sent to ND as a one-sided vPC.

        ## Raises

        ### RuntimeError

        - If the payload has no `configData.networkOS.policy` block to inject `peerSwitchId` into.
        """
        policy = (payload.get("configData") or {}).get("networkOS", {}).get("policy")
        if policy is None:
            raise RuntimeError(
                f"vPC interface payload is missing the 'configData.networkOS.policy' block required to inject 'peerSwitchId'; received: {payload!r}"
            )
        policy["peerSwitchId"] = peer_serial
        return payload

    def create(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Create a vPC interface configuration. Resolves `switch_ip` to a primary serial, resolves the peer serial via
        the vPC pair record, injects both into the payload, and POSTs the wrapped `interfaces` array. Queues a deploy
        for later bulk execution via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If the create API request fails.
        - If the primary switch is not in a vPC pair.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            peer_serial = self._resolve_peer_switch_id(model_instance.switch_ip, switch_id)
            api_endpoint = self._configure_endpoint(self.create_endpoint(), switch_sn=switch_id)
            payload = model_instance.to_payload()
            payload["switchId"] = switch_id
            self._inject_peer_switch_id(payload, peer_serial)
            request_body = {"interfaces": [payload]}
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=request_body)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return result
        except Exception as e:
            raise RuntimeError(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Update a vPC interface configuration. Resolves `switch_ip` to a primary serial, resolves the peer serial via
        the vPC pair record, injects both into the payload, and PUTs the updated configuration. Queues a deploy for
        later bulk execution via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If the update API request fails.
        - If the primary switch is not in a vPC pair.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            peer_serial = self._resolve_peer_switch_id(model_instance.switch_ip, switch_id)
            api_endpoint = self._configure_endpoint(self.update_endpoint(), switch_sn=switch_id)
            api_endpoint.set_identifiers(model_instance.interface_name)
            payload = model_instance.to_payload()
            payload["switchId"] = switch_id
            self._inject_peer_switch_id(payload, peer_serial)
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return result
        except Exception as e:
            raise RuntimeError(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: ModelType, **kwargs) -> None:
        """
        # Summary

        Delete a vPC interface immediately via the per-interface `DELETE /interfaces/{name}` endpoint, then queue
        a deploy for later bulk execution via `deploy_pending`. The DELETE returns 204 on success; a subsequent GET
        returns 404. The deploy pushes the removal to both peers and reverts member interfaces to their fabric
        default configuration.

        ## Raises

        ### RuntimeError

        - If the DELETE API request fails.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            api_endpoint = self._configure_endpoint(self.delete_endpoint(), switch_sn=switch_id)
            api_endpoint.set_identifiers(model_instance.interface_name)
            self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            self._queue_deploy(model_instance.interface_name, switch_id)
        except Exception as e:
            raise RuntimeError(f"Delete failed for {model_instance.get_identifier_value()}: {e}") from e

    @requires_bulk_support("supports_bulk_create")
    def create_bulk(self, model_instances: list[ModelType], **kwargs) -> ResponseType:
        """
        # Summary

        Create multiple vPC interfaces in bulk. Groups by primary switch, resolves the peer serial once per group, and
        sends one POST per primary switch with all vPC interfaces in the `interfaces` array. Queues deploys for all
        created interfaces for later bulk execution via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If any create API request fails.
        - If any primary switch is not in a vPC pair.
        """
        try:
            groups: dict[str, list[tuple[str, dict]]] = defaultdict(list)
            for model_instance in model_instances:
                switch_id = self._resolve_switch_id(model_instance.switch_ip)
                peer_serial = self._resolve_peer_switch_id(model_instance.switch_ip, switch_id)
                payload = model_instance.to_payload()
                payload["switchId"] = switch_id
                self._inject_peer_switch_id(payload, peer_serial)
                groups[switch_id].append((model_instance.interface_name, payload))

            results = []
            for switch_id, items in groups.items():
                # Guarded at runtime by @requires_bulk_support("supports_bulk_create")
                api_endpoint = self._configure_endpoint(self.create_bulk_endpoint(), switch_sn=switch_id)  # pyright: ignore[reportOptionalCall]
                request_body = {"interfaces": [payload for interface_name, payload in items]}
                result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=request_body)
                results.append(result)
                for interface_name, payload in items:
                    self._queue_deploy(interface_name, switch_id)
            return results
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

    def query_one(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Query a single vPC interface by name on a specific switch.

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

    def _configured_switch_ips_by_interface_name(self) -> dict[str, set[str]]:
        """
        # Summary

        Map each config `interface_name` to the set of user-supplied `switch_ip` values. A vPC interface spans two peers and ND returns
        it on both; `query_all` uses this to keep the peer copy whose IP the user actually configured, so the existing state's composite
        identifier `(switch_ip, interface_name)` matches the proposed identifier and the run stays idempotent regardless of which peer
        the user names. A set (not a single IP) because the same name may legally appear on multiple pairs (issue #356). Keys are
        canonical (lowercase) names — see `_canonical_interface_name`.

        ## Raises

        None
        """
        mapping: dict[str, set[str]] = {}
        for item in self.rest_send.params.get("config") or []:
            name = item.get("interface_name")
            switch_ip = item.get("switch_ip")
            if name and switch_ip:
                mapping.setdefault(self._canonical_interface_name(name), set()).add(switch_ip)
        return mapping

    @staticmethod
    def _canonical_interface_name(name: str) -> str:
        """
        # Summary

        Return the canonical (lowercase) form of a vPC interface name. The vPC models lowercase `interface_name` on validation
        (`VPC501` -> `vpc501`, matching what ND echoes), but `query_all` reads the user config raw from `rest_send.params`, so both
        the configured names and the response names must pass through this one canonicalizer before they are compared; otherwise a
        mixed-case config never matches its own echo and the dedup falls back to the wrong peer (PR #411 review).

        ## Raises

        None
        """
        return name.lower()

    @staticmethod
    def _policy_type(iface: dict) -> str | None:
        """
        # Summary

        Return `configData.networkOS.policy.policyType` for an interface dict, tolerating a missing or null value at
        any level of the nested chain (ND occasionally returns `configData: null`).

        ## Raises

        None
        """
        config_data = iface.get("configData") or {}
        network_os = config_data.get("networkOS") or {}
        policy = network_os.get("policy") or {}
        return policy.get("policyType")

    def _pair_key(self, iface: dict, switch_ip: str, switch_id: str) -> frozenset[str]:
        """
        # Summary

        Return the unordered vPC pair discriminator for an interface record: `frozenset({switchId, peerSwitchId})`. The two peer copies
        of one vPC interface carry the same set (only the orientation swaps), while same-name interfaces on different pairs carry
        disjoint sets (issue #356).

        When the echo omits `peerSwitchId` (the OpenAPI schema does not mark it required, so this is a schema-valid shape) the peer is
        resolved from the authoritative `vpcPair` endpoint via `_resolve_peer_switch_id` (cached per switch, so the degraded path costs
        at most one extra GET per switch). A per-switch singleton key is NOT an acceptable fallback: if even one of the two peer echoes
        lacked the field, the copies would key on `{A}` vs `{A, B}`, both would survive dedup, and `state: overridden` would delete the
        pair-wide interface through the "unconfigured" peer (PR #411 review). If the pair cannot be resolved, this raises and
        `query_all` fails closed before any override deletion can be computed.

        ## Raises

        ### RuntimeError

        - Propagated from `_resolve_peer_switch_id` when `peerSwitchId` is absent and the switch is not in a vPC pair (or the
          `vpcPair` record itself omits `peerSwitchId`).
        """
        config_data = iface.get("configData") or {}
        network_os = config_data.get("networkOS") or {}
        policy = network_os.get("policy") or {}
        peer_switch_id = policy.get("peerSwitchId") or self._resolve_peer_switch_id(switch_ip, switch_id)
        return frozenset({switch_id, peer_switch_id})

    def _managed_vpc_interfaces(self, switch_ip: str, switch_id: str, managed_types: set[str]) -> list[dict]:
        """
        # Summary

        Fetch one switch's interface list and return the vPC interfaces whose policy type this orchestrator manages,
        each enriched with the `switchIp` of the switch it was read from. Tolerates a missing body (`not_found_ok`) and
        a non-dict body (the `isinstance` guard) without raising.

        ## Raises

        ### Exception

        - If the interface-list request fails (propagated to `query_all`'s wrapper).
        """
        api_endpoint = self._configure_endpoint(self.query_all_endpoint(), switch_sn=switch_id)
        result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
        interfaces = result.get("interfaces", []) or [] if isinstance(result, dict) else []
        managed = [iface for iface in interfaces if iface.get("interfaceType") == "vpc" and self._policy_type(iface) in managed_types]
        for iface in managed:
            iface["switchIp"] = switch_ip
        return managed

    def query_all(self, model_instance: ModelType | None = None, **kwargs) -> ResponseType:
        """
        # Summary

        Validate the fabric context and query interfaces, filtering for vPC interfaces with policy types managed by
        this orchestrator (as defined by `_managed_policy_types()`).

        The set of switches queried is determined by `_switches_to_query`: fabric-wide for `state: overridden`, and
        limited to switches named in the user config for all other states.

        Runs `validate_prerequisites` on first call to ensure the fabric exists and is modifiable before returning any data.

        Each returned interface dict is enriched with a `switchIp` field so that the model can be constructed with the
        composite identifier `(switch_ip, interface_name)`.

        Dedup is keyed on `(interfaceName, frozenset({switchId, peerSwitchId}))`, not `interfaceName` alone, so that two vPC pairs in
        the same fabric may legally reuse the same vPC interface name (issue #356). An echo that omits `peerSwitchId` has its pair
        resolved from the `vpcPair` endpoint; if that fails the whole query fails closed (see `_pair_key`).

        ## Raises

        ### RuntimeError

        - If the fabric does not exist on the target ND node.
        - If the fabric is in deployment-freeze mode.
        - If the query API request fails.
        - If an interface echo omits `peerSwitchId` and its switch's vPC pair cannot be resolved.
        """
        managed_types = self._managed_policy_types()
        try:
            self.validate_prerequisites()
            configured_ips_by_name = self._configured_switch_ips_by_interface_name()
            # TODO(4.2.1) vpc-interface-dual-peer-duplicate
            # ND returns each vPC interface TWICE — once per peer switch — with identical configData. Dedupe on
            # (interfaceName, frozenset({switchId, peerSwitchId})): one pair's two copies share the unordered set and
            # collapse, while same-name interfaces on DIFFERENT pairs have disjoint sets and stay distinct (two pairs
            # may legally reuse a vPC id — the vpcId pool is devicePair-scoped; issue #356). When the interface is in
            # the user config, keep the peer whose switchIp the user supplied so idempotency holds regardless of which
            # peer they name; otherwise keep the alphabetically-lower switchId for a stable representative. Names are
            # canonicalized (lowercase) on both sides so a mixed-case config still matches its echo. Without this
            # dedupe, `_manage_override_deletions` would see the peer-side copy as "not in proposed" and queue a
            # spurious delete.
            interfaces_by_key: dict[tuple[str, frozenset[str]], tuple[str, dict]] = {}
            for switch_ip, switch_id in self._switches_to_query().items():
                for iface in self._managed_vpc_interfaces(switch_ip, switch_id, managed_types):
                    raw_name = iface.get("interfaceName")
                    if raw_name is None:
                        continue
                    name = self._canonical_interface_name(raw_name)
                    key = (name, self._pair_key(iface, switch_ip, switch_id))
                    existing = interfaces_by_key.get(key)
                    if self._prefers_candidate(name, switch_id, switch_ip, existing, configured_ips_by_name):
                        interfaces_by_key[key] = (switch_id, iface)
            return [entry[1] for entry in interfaces_by_key.values()]
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e

    @staticmethod
    def _prefers_candidate(
        name: str,
        switch_id: str,
        switch_ip: str,
        existing: tuple[str, dict] | None,
        configured_ips_by_name: dict[str, set[str]],
    ) -> bool:
        """
        # Summary

        Decide whether a newly-seen per-peer copy of a vPC interface should replace the one already kept for its dedup key. Prefer the
        peer whose `switch_ip` the user configured (idempotency); when neither peer is the configured one (or the interface is not in
        config, e.g. an `overridden` deletion candidate), prefer the alphabetically-lower `switch_id` for a stable representative. The
        two candidates for one key are always the two peers of one pair (issue #356 keys dedup on the unordered pair set).

        ## Raises

        None
        """
        if existing is None:
            return True
        configured_ips = configured_ips_by_name.get(name, set())
        if configured_ips:
            if switch_ip in configured_ips:
                return True
            if existing[1].get("switchIp") in configured_ips:
                return False
        return switch_id < existing[0]
