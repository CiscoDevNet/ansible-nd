# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# pyright: reportAttributeAccessIssue=false
# ModelType is NDBaseModel which lacks interface-specific fields (switch_ip,
# interface_name, config_data). Concrete subclasses always bind ModelType to a
# model that provides these fields, so the accesses are safe at runtime.

"""
Base orchestrator for port-channel interface modules on Nexus Dashboard.

This module provides `PortChannelBaseOrchestrator`, which implements shared CRUD operations
for all port-channel interface types (accessPoHost, trunkPoHost, etc.) via the ND Manage
Interfaces API. Type-specific orchestrators inherit from this base and provide their own
`model_class` and `_managed_policy_types()`.

Inherits shared interface lifecycle operations (deploy queuing, fabric validation, switch
resolution) from `NDBaseInterfaceOrchestrator` and adds port-channel-specific functionality:
- Standard remove-based deletion (port-channels are virtual interfaces and are deletable)
- Fabric-wide `query_all()` filtered by `interfaceType: "portChannel"` and per-type policy filtering

Member ethernet interfaces are not managed by this orchestrator — the port-channel policy is the
single source of truth for member configuration via the `ports` list. Member field restrictions
on standalone ethernet modules are enforced separately by the ethernet orchestrators.
"""

from __future__ import annotations

from collections import defaultdict
from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
    EpManageInterfacesRemove,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

ModelType = NDBaseModel


class PortChannelBaseOrchestrator(NDBaseInterfaceOrchestrator[ModelType]):
    """
    # Summary

    Base orchestrator for port-channel interface CRUD operations on Nexus Dashboard.

    Provides shared logic for all port-channel interface types. Subclasses must set `model_class` and implement
    `_managed_policy_types()` to define which policy types they manage.

    Supports configuring port-channels across multiple switches in a single task. Each config item includes a
    `switch_ip` that is resolved to a `switchId` via `FabricContext`.

    Mutation methods (`create`, `update`) queue deploys for bulk execution. `delete` queues port-channels for
    bulk removal via `interfaceActions/remove` and bulk deploy. Call `remove_pending` and `deploy_pending` after
    all mutations are complete.

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

    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() uses bulk remove
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesRemove

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator. Subclasses must override this method
        to return their specific policy types (e.g., `{"accessPoHost"}` for the access orchestrator).

        ## Raises

        ### NotImplementedError

        - Always, if not overridden by a subclass.
        """
        raise NotImplementedError("Subclasses must implement _managed_policy_types()")

    def create(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Create a port-channel interface configuration. Resolves `switch_ip` from the model instance, injects `switchId`,
        and wraps the payload in an `interfaces` array. Queues a deploy for later bulk execution via `deploy_pending`.

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
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=request_body)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return result
        except Exception as e:
            raise RuntimeError(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Update a port-channel interface configuration. Resolves `switch_ip` from the model instance, injects `switchId`
        into the payload. Queues a deploy for later bulk execution via `deploy_pending`.

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
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return result
        except Exception as e:
            raise RuntimeError(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: ModelType, **kwargs) -> None:
        """
        # Summary

        Queue a port-channel interface for deferred bulk removal via `remove_pending` and bulk deploy via
        `deploy_pending`. The remove deletes the port-channel from ND's config; the deploy pushes that removal
        to the switch and reverts member interfaces to their fabric default configuration.

        No API calls are made until `remove_pending` and `deploy_pending` are called after all mutations are complete.

        ## Raises

        None
        """
        switch_id = self._resolve_switch_id(model_instance.switch_ip)
        self._queue_remove(model_instance.interface_name, switch_id)
        self._queue_deploy(model_instance.interface_name, switch_id)

    def create_bulk(self, model_instances: list[ModelType], **kwargs) -> ResponseType:
        """
        # Summary

        Create multiple port-channel interfaces in bulk. Groups port-channels by switch and sends one POST per switch
        with all port-channels in the `interfaces` array, reducing API calls from N to one-per-switch. Queues deploys
        for all created port-channels for later bulk execution via `deploy_pending`.

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
                result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=request_body)
                results.append(result)
                for interface_name, payload in items:
                    self._queue_deploy(interface_name, switch_id)
            return results
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

    def delete_bulk(self, model_instances: list[ModelType], **kwargs) -> None:
        """
        # Summary

        Queue multiple port-channel interfaces for deferred bulk removal and deployment. Each port-channel is queued
        for removal via `remove_pending` and deployment via `deploy_pending`. No API calls are made until those methods
        are called after `manage_state` completes.

        ## Raises

        None
        """
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            self._queue_remove(model_instance.interface_name, switch_id)
            self._queue_deploy(model_instance.interface_name, switch_id)

    def query_one(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Query a single port-channel interface by name on a specific switch.

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
        port-channel interfaces with policy types managed by this orchestrator (as defined by `_managed_policy_types()`).

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
            all_port_channels = []
            for switch_ip, switch_id in self.fabric_context.switch_map.items():
                api_endpoint = self._configure_endpoint(self.query_all_endpoint(), switch_sn=switch_id)
                result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
                if not result:
                    continue
                interfaces = result.get("interfaces", []) or []
                port_channels = [iface for iface in interfaces if iface.get("interfaceType") == "portChannel"]
                managed = [
                    iface for iface in port_channels if iface.get("configData", {}).get("networkOS", {}).get("policy", {}).get("policyType") in managed_types
                ]
                for iface in managed:
                    iface["switchIp"] = switch_ip
                all_port_channels.extend(managed)
            return all_port_channels
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e
