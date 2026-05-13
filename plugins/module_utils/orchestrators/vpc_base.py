# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# pyright: reportAttributeAccessIssue=false
# ModelType is NDBaseModel which lacks interface-specific fields (switch_ip,
# interface_name, config_data). Concrete subclasses always bind ModelType to a
# model that provides these fields, so the accesses are safe at runtime.

"""
Base orchestrator for vPC interface modules on Nexus Dashboard.

This module provides `VpcBaseOrchestrator`, which implements shared CRUD operations for all vPC interface
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
user to create the pair first via `nd_vpc_pair`.
"""

from __future__ import annotations

from collections import defaultdict
from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabric_switch_vpc_pair import (
    EpManageFabricSwitchVpcPairGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesDelete,
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

ModelType = NDBaseModel


class VpcBaseOrchestrator(NDBaseInterfaceOrchestrator[ModelType]):
    """
    # Summary

    Base orchestrator for vPC interface CRUD operations on Nexus Dashboard.

    Provides shared logic for all vPC interface types. Subclasses must set `model_class` and implement
    `_managed_policy_types()` to define which policy types they manage.

    Each create/update reads the `vpcPair` record for the primary switch to obtain the peer serial, which is
    then injected as `peerSwitchId` in the payload. Lookups are cached per orchestrator instance.

    Mutation methods (`create`, `update`) queue deploys for bulk execution. `delete` queues vPC interfaces for
    bulk removal via `interfaceActions/remove` and bulk deploy. Call `remove_pending` and `deploy_pending` after
    all mutations are complete.

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

    # TODO(4.2.1) The bulk `/api/v1/manage/fabrics/{fabric}/interfaceActions/remove` endpoint returns
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
        api_endpoint = EpManageFabricSwitchVpcPairGet()
        api_endpoint.fabric_name = self.fabric_name
        api_endpoint.switch_sn = primary_serial
        result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
        if not result:
            raise RuntimeError(
                f"Switch {switch_ip} (serial {primary_serial}) is not in a vPC pair; " f"create the pair via nd_vpc_pair before configuring vPC interfaces."
            )
        peer_serial = result.get("peerSwitchId")
        if not peer_serial:
            raise RuntimeError(f"vPC pair record for switch {switch_ip} (serial {primary_serial}) is missing 'peerSwitchId'; " f"received: {result!r}")
        self._peer_serial_cache[primary_serial] = peer_serial
        return peer_serial

    def _inject_peer_switch_id(self, payload: dict, peer_serial: str) -> dict:
        """
        # Summary

        Inject `peerSwitchId` into the nested `configData.networkOS.policy` block of an interface payload. The model
        already nests `peer_switch_id` under `policy`, so this just sets the value if not already present.

        ## Raises

        None
        """
        policy = payload.get("configData", {}).get("networkOS", {}).get("policy")
        if policy is not None:
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

    def query_all(self, model_instance: ModelType | None = None, **kwargs) -> ResponseType:
        """
        # Summary

        Validate the fabric context and query all interfaces across ALL switches in the fabric, filtering for
        vPC interfaces with policy types managed by this orchestrator (as defined by `_managed_policy_types()`).

        Runs `validate_prerequisites` on first call to ensure the fabric exists and is modifiable before returning any data.

        Each returned interface dict is enriched with a `switch_ip` field so that the model has routing context.
        vPC interfaces are de-duplicated by `interfaceName` (ND returns each vPC twice — once per peer); the entry
        with the alphabetically-lower `switchId` is kept as the canonical representative.

        ## Raises

        ### RuntimeError

        - If the fabric does not exist on the target ND node.
        - If the fabric is in deployment-freeze mode.
        - If the query API request fails.
        """
        managed_types = self._managed_policy_types()
        try:
            self.validate_prerequisites()
            # TODO(4.2.1) ND returns each vPC interface TWICE — once per peer switch — with identical configData.
            # Dedupe by interfaceName, keeping the entry whose URL-path `switchId` is alphabetically lower so the
            # chosen representative is stable across runs. Without this dedupe, `_manage_override_deletions` would
            # see the peer-side copy as "not in proposed" and queue a spurious delete.
            interfaces_by_name: dict[str, tuple[str, dict]] = {}
            for switch_ip, switch_id in self.fabric_context.switch_map.items():
                api_endpoint = self._configure_endpoint(self.query_all_endpoint(), switch_sn=switch_id)
                result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
                if not result:
                    continue
                interfaces = result.get("interfaces", []) or []
                vpc_interfaces = [iface for iface in interfaces if iface.get("interfaceType") == "vpc"]
                managed = [
                    iface for iface in vpc_interfaces if iface.get("configData", {}).get("networkOS", {}).get("policy", {}).get("policyType") in managed_types
                ]
                for iface in managed:
                    iface["switchIp"] = switch_ip
                    name = iface.get("interfaceName")
                    if name is None:
                        continue
                    existing = interfaces_by_name.get(name)
                    if existing is None or switch_id < existing[0]:
                        interfaces_by_name[name] = (switch_id, iface)
            return [entry for _, entry in interfaces_by_name.values()]
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e
