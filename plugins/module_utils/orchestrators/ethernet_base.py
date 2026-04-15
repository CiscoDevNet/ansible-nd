# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

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

from collections import defaultdict
from typing import ClassVar, List, Optional, Set, Type

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesNormalize,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
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

    create_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: Type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() uses bulk normalize
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesListGet
    create_bulk_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesPost
    delete_bulk_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesNormalize

    PORT_CHANNEL_MODIFIABLE_FIELDS: ClassVar[Set[str]] = {"description", "admin_state", "extra_config"}

    _pending_normalizes: list[tuple[str, str]] = []

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

    def _check_port_channel_restrictions(self, model_instance: ModelType, existing_data: Optional[dict] = None) -> None:
        """
        # Summary

        Check if the interface is a port-channel member and validate that only whitelisted fields are being modified.
        If the interface is a port-channel member and non-whitelisted fields are being changed, raise `RuntimeError`.

        ## Raises

        ### RuntimeError

        - If the interface is a port-channel member and non-whitelisted fields are being modified.
        """
        if existing_data is None:
            return

        port_channel_id = existing_data.get("configData", {}).get("networkOS", {}).get("policy", {}).get("portChannelId")
        if not port_channel_id:
            return

        if model_instance.config_data is None:
            return

        policy = model_instance.config_data.network_os.policy if model_instance.config_data.network_os else None
        if policy is None:
            return

        changed_fields = set()
        for field_name in policy.model_fields:
            value = getattr(policy, field_name)
            if value is not None and field_name != "policy_type":
                changed_fields.add(field_name)

        non_whitelisted = changed_fields - self.PORT_CHANNEL_MODIFIABLE_FIELDS
        if non_whitelisted:
            raise RuntimeError(
                f"Interface {model_instance.interface_name} is a member of port-channel {port_channel_id}. "
                f"The following fields cannot be modified on port-channel members: {sorted(non_whitelisted)}. "
                f"Only these fields can be modified: {sorted(self.PORT_CHANNEL_MODIFIABLE_FIELDS)}."
            )

    def remove_pending(self) -> ResponseType | None:
        """
        # Summary

        Normalize all queued interface configurations in a single bulk API call via `interfaceActions/normalize`,
        resetting them to the fabric default `int_trunk_host` template. This changes the interfaces to
        `policyType: "trunkHost"`, which removes them from the type-specific filters in `query_all()`.

        Physical ethernet interfaces cannot be deleted via `interfaceActions/remove` (silently does nothing for
        physical interfaces) or `DELETE` (returns 500). The normalize endpoint works when given the full
        `int_trunk_host` template defaults with `mode: "trunk"` and `policyType: "trunkHost"`.

        Clears the pending queue after normalization.

        ## Raises

        ### RuntimeError

        - If the normalize API request fails.
        """
        if not self._pending_normalizes:
            return None
        try:
            result = self._normalize_interfaces()
            self._pending_normalizes = []
            return result
        except Exception as e:
            raise RuntimeError(f"Bulk normalize failed for interfaces {self._pending_normalizes}: {e}") from e

    def _normalize_interfaces(self) -> ResponseType:
        """
        # Summary

        Normalize queued interfaces via `interfaceActions/normalize` using the `InterfaceDefaultConfig` model
        which provides the full `int_trunk_host` template defaults.

        ## Raises

        ### Exception

        - If the normalize API request fails (propagated to caller).
        """
        api_endpoint = EpManageInterfacesNormalize()
        api_endpoint.fabric_name = self.fabric_name
        payload = InterfaceDefaultConfig.to_normalize_payload(self._pending_normalizes)
        return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=payload)

    def create(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Create an ethernet interface configuration. Resolves `switch_ip` from the model instance, checks port-channel
        membership restrictions, injects `switchId`, and wraps the payload in an `interfaces` array. Queues a deploy
        for later bulk execution via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If the interface is a port-channel member and non-whitelisted fields are being modified.
        - If the create API request fails.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            self._check_port_channel_restrictions(model_instance, kwargs.get("existing_data"))
            api_endpoint = self._configure_endpoint(self.create_endpoint(), switch_sn=switch_id)
            payload = model_instance.to_payload()
            payload["switchId"] = switch_id
            request_body = {"interfaces": [payload]}
            result = self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=request_body)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return result
        except Exception as e:
            raise RuntimeError(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Update an ethernet interface configuration. Resolves `switch_ip` from the model instance, checks port-channel
        membership restrictions, injects `switchId` into the payload. Queues a deploy for later bulk execution
        via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If the interface is a port-channel member and non-whitelisted fields are being modified.
        - If the update API request fails.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            self._check_port_channel_restrictions(model_instance, kwargs.get("existing_data"))
            api_endpoint = self._configure_endpoint(self.update_endpoint(), switch_sn=switch_id)
            api_endpoint.set_identifiers(model_instance.interface_name)
            payload = model_instance.to_payload()
            payload["switchId"] = switch_id
            result = self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=payload)
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

        ## Raises

        ### RuntimeError

        - If switch IP resolution fails.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            self._queue_normalize(model_instance.interface_name, switch_id)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return {}
        except Exception as e:
            raise RuntimeError(f"Delete failed for {model_instance.get_identifier_value()}: {e}") from e

    def create_bulk(self, model_instances: List[ModelType], **kwargs) -> ResponseType:
        """
        # Summary

        Create multiple ethernet interfaces in bulk. Groups interfaces by switch and sends one POST per switch with all
        interfaces in the `interfaces` array, reducing API calls from N to one-per-switch. Port-channel membership
        restrictions are checked for each interface. Queues deploys for all created interfaces for later bulk execution
        via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If any interface is a port-channel member and non-whitelisted fields are being modified.
        - If any create API request fails.
        """
        try:
            groups: dict[str, list[tuple[str, dict]]] = defaultdict(list)
            for model_instance in model_instances:
                switch_id = self._resolve_switch_id(model_instance.switch_ip)
                self._check_port_channel_restrictions(model_instance, kwargs.get("existing_data"))
                payload = model_instance.to_payload()
                payload["switchId"] = switch_id
                groups[switch_id].append((model_instance.interface_name, payload))

            results = []
            for switch_id, items in groups.items():
                api_endpoint = self._configure_endpoint(self.create_bulk_endpoint(), switch_sn=switch_id)
                request_body = {"interfaces": [payload for interface_name, payload in items]}
                result = self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=request_body)
                results.append(result)
                for interface_name, payload in items:
                    self._queue_deploy(interface_name, switch_id)
            return results
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

    def delete_bulk(self, model_instances: List[ModelType], **kwargs) -> None:
        """
        # Summary

        Queue multiple ethernet interfaces for deferred bulk normalization and deployment. Each interface is queued
        for normalization via `remove_pending` (which resets it to the `int_trunk_host` template) and deployment via
        `deploy_pending`. No API calls are made until those methods are called after `manage_state` completes.

        ## Raises

        None
        """
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
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
            return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb)
        except Exception as e:
            raise RuntimeError(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self, model_instance: Optional[ModelType] = None, **kwargs) -> ResponseType:
        """
        # Summary

        Validate the fabric context and query all interfaces across ALL switches in the fabric, filtering for
        ethernet interfaces with policy types managed by this orchestrator (as defined by `_managed_policy_types()`).

        Port-channel member interfaces are included in the results (they exist on the switch and need to be visible
        for port-channel restriction checks), but `state: overridden` handling in the state machine should skip them.

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
            for switch_ip, switch_id in self.fabric_context.switch_map.items():
                api_endpoint = self._configure_endpoint(self.query_all_endpoint(), switch_sn=switch_id)
                result = self.sender.query_obj(api_endpoint.path)
                if not result:
                    continue
                interfaces = result.get("interfaces", []) or []
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
