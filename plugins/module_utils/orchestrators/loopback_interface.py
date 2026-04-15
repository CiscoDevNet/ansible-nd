# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Loopback interface orchestrator for Nexus Dashboard.

This module provides `LoopbackInterfaceOrchestrator`, which implements CRUD operations
for loopback interfaces via the ND Manage Interfaces API. Supports configuring interfaces
across multiple switches in a single task.

Each mutation operation (create, update, delete) is followed by a deploy call to persist
changes to the switch. Deploy and remove operations are batched per-switch and executed
in bulk after all mutations are complete.

Uses `FabricContext` for pre-flight validation (fabric existence, deployment-freeze check)
and switch IP-to-serial resolution. The model structure mirrors the API payload, so the
orchestrator only needs to inject `switchId` and filter `query_all` results by interface type.
"""

from __future__ import annotations

from collections import defaultdict
from typing import ClassVar, List, Optional, Type

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
    EpManageInterfacesRemove,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import (
    LOOPBACK_POLICY_TYPE_MAPPING,
    LoopbackInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class LoopbackInterfaceOrchestrator(NDBaseInterfaceOrchestrator[LoopbackInterfaceModel]):
    """
    # Summary

    Orchestrator for loopback interface CRUD operations on Nexus Dashboard.

    Supports configuring interfaces across multiple switches in a single task. Each config item
    includes a `switch_ip` that is resolved to a `switchId` via `FabricContext`.

    Overrides the base orchestrator to handle the ND interfaces API, which requires `fabric_name` and `switch_sn`
    on every endpoint, injects `switchId` into payloads, and defers deploy calls for bulk execution.

    Mutation methods (`create`, `update`) queue deploys instead of executing them immediately. Call `deploy_pending`
    after all mutations are complete to deploy all changes in a single API call. `delete` queues interfaces for bulk
    removal via `remove_pending`.

    For `state: overridden`, `query_all` queries ALL switches in the fabric to enable fabric-wide convergence.

    Uses `FabricContext` for pre-flight validation and switch resolution.

    ## Raises

    ### RuntimeError

    - Via `validate_prerequisites` if the fabric does not exist or is in deployment-freeze mode.
    - Via `_resolve_switch_id` if no switch matches the given IP in the fabric.
    - Via `create` if the create API request fails.
    - Via `update` if the update API request fails.
    - Via `remove_pending` if the bulk remove API request fails.
    - Via `deploy_pending` if the bulk deploy API request fails.
    - Via `query_one` if the query API request fails.
    - Via `query_all` if the query API request fails.
    """

    model_class: ClassVar[Type[NDBaseModel]] = LoopbackInterfaceModel
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True

    create_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: Type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() uses bulk remove
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesListGet
    create_bulk_endpoint: Optional[Type[NDEndpointBaseModel]] = EpManageInterfacesPost
    delete_bulk_endpoint: Optional[Type[NDEndpointBaseModel]] = EpManageInterfacesRemove

    def create(self, model_instance: LoopbackInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Create a loopback interface. Resolves `switch_ip` from the model instance, injects `switchId`, and wraps the payload
        in an `interfaces` array. Queues a deploy for later bulk execution via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If the create API request fails.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            api_endpoint = self._configure_endpoint(self.create_endpoint(), switch_sn=switch_id)
            payload = model_instance.to_payload()
            payload["switchId"] = switch_id
            request_body = {"interfaces": [payload]}
            result = self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=request_body)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return result
        except Exception as e:
            raise RuntimeError(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: LoopbackInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Update a loopback interface. Resolves `switch_ip` from the model instance, injects `switchId` into the payload.
        Queues a deploy for later bulk execution via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If the update API request fails.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            api_endpoint = self._configure_endpoint(self.update_endpoint(), switch_sn=switch_id)
            api_endpoint.set_identifiers(model_instance.interface_name)
            payload = model_instance.to_payload()
            payload["switchId"] = switch_id
            result = self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=payload)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return result
        except Exception as e:
            raise RuntimeError(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: LoopbackInterfaceModel, **kwargs) -> None:
        """
        # Summary

        Queue a loopback interface for deferred bulk removal via `remove_pending` and bulk deploy via `deploy_pending`.
        The remove deletes the interface from ND's config; the deploy pushes that removal to the switch.

        No API calls are made until `remove_pending` and `deploy_pending` are called after all mutations are complete.

        ## Raises

        None
        """
        switch_id = self._resolve_switch_id(model_instance.switch_ip)
        self._queue_remove(model_instance.interface_name, switch_id)
        self._queue_deploy(model_instance.interface_name, switch_id)

    def create_bulk(self, model_instances: List[LoopbackInterfaceModel], **kwargs) -> ResponseType:
        """
        # Summary

        Create multiple loopback interfaces in bulk. Groups interfaces by switch and sends one POST per switch with all
        interfaces in the `interfaces` array, reducing API calls from N to one-per-switch. Queues deploys for all created
        interfaces for later bulk execution via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If any create API request fails.
        """
        try:
            groups: dict[str, list[tuple[str, dict]]] = defaultdict(list)
            for model_instance in model_instances:
                switch_id = self._resolve_switch_id(model_instance.switch_ip)
                payload = model_instance.to_payload()
                payload["switchId"] = switch_id
                groups[switch_id].append((model_instance.interface_name, payload))

            results = []
            for switch_id, items in groups.items():
                # Guarded at runtime by @requires_bulk_support("supports_bulk_create")
                api_endpoint = self._configure_endpoint(self.create_bulk_endpoint(), switch_sn=switch_id)  # pyright: ignore[reportOptionalCall]
                request_body = {"interfaces": [payload for interface_name, payload in items]}
                result = self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=request_body)
                results.append(result)
                for interface_name, payload in items:
                    self._queue_deploy(interface_name, switch_id)
            return results
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

    def delete_bulk(self, model_instances: List[LoopbackInterfaceModel], **kwargs) -> None:
        """
        # Summary

        Queue multiple loopback interfaces for deferred bulk removal and deployment. Each interface is queued for removal
        via `remove_pending` and deployment via `deploy_pending`. No API calls are made until those methods are called
        after `manage_state` completes.

        ## Raises

        None
        """
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            self._queue_remove(model_instance.interface_name, switch_id)
            self._queue_deploy(model_instance.interface_name, switch_id)

    def query_one(self, model_instance: LoopbackInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Query a single loopback interface by name on a specific switch.

        ## Raises

        ### RuntimeError

        - If the query API request fails.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            api_endpoint = self._configure_endpoint(self.query_one_endpoint(), switch_sn=switch_id)
            api_endpoint.set_identifiers(model_instance.interface_name)
            return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb)
        except Exception as e:
            raise RuntimeError(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self, model_instance: Optional[NDBaseModel] = None, **kwargs) -> ResponseType:
        """
        # Summary

        Validate the fabric context and query all interfaces across ALL switches in the fabric, filtering for user-managed
        loopback interfaces only.

        System-provisioned loopbacks (e.g. Loopback0 routing, Loopback1 VTEP with `policyType: "underlayLoopback"`) are excluded because they are managed by ND
        during initial switch role configuration and cannot be deleted or modified by this module.

        Runs `validate_prerequisites` on first call to ensure the fabric exists and is modifiable before returning any data.

        Each returned interface dict is enriched with a `switch_ip` field so that `LoopbackInterfaceModel` can be constructed
        with the composite identifier `(switch_ip, interface_name)`.

        ## Raises

        ### RuntimeError

        - If the fabric does not exist on the target ND node.
        - If the fabric is in deployment-freeze mode.
        - If the query API request fails.
        """
        managed_policy_types = set(LOOPBACK_POLICY_TYPE_MAPPING.data.values())
        try:
            self.validate_prerequisites()
            all_loopbacks = []
            for switch_ip, switch_id in self.fabric_context.switch_map.items():
                api_endpoint = self._configure_endpoint(self.query_all_endpoint(), switch_sn=switch_id)
                result = self.sender.query_obj(api_endpoint.path)
                if not result:
                    continue
                interfaces = result.get("interfaces", []) or []
                loopbacks = [iface for iface in interfaces if iface.get("interfaceType") == "loopback"]
                managed = [lb for lb in loopbacks if lb.get("configData", {}).get("networkOS", {}).get("policy", {}).get("policyType") in managed_policy_types]
                for iface in managed:
                    iface["switchIp"] = switch_ip
                all_loopbacks.extend(managed)
            return all_loopbacks
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e
