# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Base orchestrator for ethernet interface modules on Nexus Dashboard.

This module provides `EthernetBaseOrchestrator`, which implements shared CRUD operations
for all ethernet interface types (accessHost, trunkHost, routed, etc.) via the ND Manage
Interfaces API. Type-specific orchestrators inherit from this base and provide their own
`model_class` and `_managed_policy_types()`.

Shared functionality includes:
- Switch IP-to-serial resolution via `FabricContext`
- Pre-flight fabric validation
- Deferred bulk deploy and remove operations
- Port-channel membership enforcement with a whitelisted field set
- Fabric-wide `query_all()` with per-type policy filtering
"""

from __future__ import annotations

from typing import ClassVar, Optional, Set, Type

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesDeploy,
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesNormalize,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.interface_default_config import InterfaceDefaultConfig
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

ModelType = NDBaseModel


class EthernetBaseOrchestrator(NDBaseOrchestrator[ModelType]):
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
    - Via `remove_pending` if the bulk remove API request fails.
    - Via `deploy_pending` if the bulk deploy API request fails.
    - Via `query_one` if the query API request fails.
    - Via `query_all` if the query API request fails.
    """

    create_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: Type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() uses bulk normalize
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesListGet

    deploy: bool = True

    PORT_CHANNEL_MODIFIABLE_FIELDS: ClassVar[Set[str]] = {"description", "admin_state", "extra_config"}

    _fabric_context: Optional[FabricContext] = None
    _pending_deploys: list[tuple[str, str]] = []
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

    @property
    def fabric_name(self) -> str:
        """
        # Summary

        Return `fabric_name` from module params.

        ## Raises

        None
        """
        return self.sender.params.get("fabric_name")

    @property
    def fabric_context(self) -> FabricContext:
        """
        # Summary

        Return a lazily-initialized `FabricContext` for this orchestrator's fabric.

        ## Raises

        None
        """
        if self._fabric_context is None:
            self._fabric_context = FabricContext(sender=self.sender, fabric_name=self.fabric_name)
        return self._fabric_context

    def _resolve_switch_id(self, switch_ip: str) -> str:
        """
        # Summary

        Resolve a `switch_ip` to its `switchId` via `FabricContext`.

        ## Raises

        ### RuntimeError

        - If no switch matches the given IP in the fabric.
        """
        return self.fabric_context.get_switch_id(switch_ip)

    def validate_prerequisites(self) -> None:
        """
        # Summary

        Run pre-flight validation before any CRUD operations. Checks that the fabric exists and is modifiable.

        ## Raises

        ### RuntimeError

        - If the fabric does not exist on the target ND node.
        - If the fabric is in deployment-freeze mode.
        """
        self.fabric_context.validate_for_mutation()

    def _configure_endpoint(self, api_endpoint, switch_sn: str):
        """
        # Summary

        Set `fabric_name` and `switch_sn` on an endpoint instance before path generation.

        ## Raises

        None
        """
        api_endpoint.fabric_name = self.fabric_name
        api_endpoint.switch_sn = switch_sn
        return api_endpoint

    def _queue_deploy(self, interface_name: str, switch_id: str) -> None:
        """
        # Summary

        Queue an `(interface_name, switch_id)` pair for deferred deployment. Call `deploy_pending` after all mutations
        are complete to deploy in bulk.

        ## Raises

        None
        """
        pair = (interface_name, switch_id)
        if pair not in self._pending_deploys:
            self._pending_deploys.append(pair)

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

    def deploy_pending(self) -> ResponseType | None:
        """
        # Summary

        Deploy all queued interface configurations in a single API call via `interfaceActions/deploy`. Clears the pending
        queue after deployment.

        When `deploy` is `False`, returns `None` without making any API call.

        ## Raises

        ### RuntimeError

        - If the deploy API request fails.
        """
        if not self.deploy or not self._pending_deploys:
            return None
        try:
            result = self._deploy_interfaces()
            self._pending_deploys = []
            return result
        except Exception as e:
            raise RuntimeError(f"Bulk deploy failed for interfaces {self._pending_deploys}: {e}") from e

    def _deploy_interfaces(self) -> ResponseType:
        """
        # Summary

        Deploy queued interfaces via `interfaceActions/deploy`. Sends the explicit list of `{interfaceName, switchId}` pairs.

        ## Raises

        ### Exception

        - If the deploy API request fails (propagated to caller).
        """
        api_endpoint = EpManageInterfacesDeploy()
        api_endpoint.fabric_name = self.fabric_name
        payload = {"interfaces": [{"interfaceName": name, "switchId": switch_id} for name, switch_id in self._pending_deploys]}
        return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=payload)

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
