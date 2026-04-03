# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Loopback interface orchestrator for Nexus Dashboard.

This module provides `LoopbackInterfaceOrchestrator`, which implements CRUD operations
for loopback interfaces via the ND Manage Interfaces API. Each mutation operation
(create, update, delete) is followed by a deploy call to persist changes to the switch.

Uses `FabricContext` for pre-flight validation (fabric existence, deployment-freeze check)
and switch IP-to-serial resolution. The model structure mirrors the API payload, so the
orchestrator only needs to inject `switchId` and filter `query_all` results by interface type.
"""

from __future__ import annotations

from typing import ClassVar, Optional, Type

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesDeploy,
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
    EpManageInterfacesRemove,
)
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import (
    LOOPBACK_POLICY_TYPE_MAPPING,
    LoopbackInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class LoopbackInterfaceOrchestrator(NDBaseOrchestrator[LoopbackInterfaceModel]):
    """
    # Summary

    Orchestrator for loopback interface CRUD operations on Nexus Dashboard.

    Overrides the base orchestrator to handle the ND interfaces API, which requires `fabric_name` and `switch_sn`
    on every endpoint, injects `switchId` into payloads, and defers deploy calls for bulk execution.

    Mutation methods (`create`, `update`) queue deploys instead of executing them immediately. Call `deploy_pending`
    after all mutations are complete to deploy all changes in a single API call. `delete` queues interfaces for bulk
    removal via `remove_pending`.

    Uses `FabricContext` for pre-flight validation and switch resolution.

    ## Raises

    ### RuntimeError

    - Via `validate` if the fabric does not exist or is in deployment-freeze mode.
    - Via `validate` if no switch matches the given IP in the fabric.
    - Via `create` if the create API request fails.
    - Via `update` if the update API request fails.
    - Via `remove_pending` if the bulk remove API request fails.
    - Via `deploy_pending` if the bulk deploy API request fails.
    - Via `query_one` if the query API request fails.
    - Via `query_all` if the query API request fails.
    """

    model_class: ClassVar[Type[NDBaseModel]] = LoopbackInterfaceModel

    create_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: Type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() uses bulk remove
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageInterfacesListGet

    deploy: bool = True

    _fabric_context: Optional[FabricContext] = None
    _pending_deploys: list[str] = []
    _pending_removes: list[str] = []

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

    @property
    def switch_id(self) -> str:
        """
        # Summary

        Return `switchId` resolved from the `switch_ip` module param via `FabricContext`.

        ## Raises

        ### RuntimeError

        - If no switch matches the given IP in the fabric.
        """
        switch_ip = self.sender.params.get("switch_ip")
        return self.fabric_context.get_switch_id(switch_ip)

    def validate_prerequisites(self) -> None:
        """
        # Summary

        Run pre-flight validation before any CRUD operations. Checks that the fabric exists and is modifiable, and that
        the target switch exists in the fabric.

        ## Raises

        ### RuntimeError

        - If the fabric does not exist on the target ND node.
        - If the fabric is in deployment-freeze mode.
        - If no switch matches the given `switch_ip` in the fabric.
        """
        self.fabric_context.validate_for_mutation()
        # Eagerly resolve switch_id to fail fast if the switch IP is invalid
        result = self.switch_id  # pylint: disable=unused-variable

    def _configure_endpoint(self, api_endpoint):
        """
        # Summary

        Set `fabric_name` and `switch_sn` on an endpoint instance before path generation.

        ## Raises

        None
        """
        api_endpoint.fabric_name = self.fabric_name
        api_endpoint.switch_sn = self.switch_id
        return api_endpoint

    def _queue_deploy(self, interface_name: str) -> None:
        """
        # Summary

        Queue an interface name for deferred deployment. Call `deploy_pending` after all mutations are complete to deploy in bulk.

        ## Raises

        None
        """
        if interface_name not in self._pending_deploys:
            self._pending_deploys.append(interface_name)

    def _queue_remove(self, interface_name: str) -> None:
        """
        # Summary

        Queue an interface name for deferred bulk removal. Call `remove_pending` after all mutations are complete to remove in bulk.

        ## Raises

        None
        """
        if interface_name not in self._pending_removes:
            self._pending_removes.append(interface_name)

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
        payload = {"interfaces": [{"interfaceName": name, "switchId": self.switch_id} for name in self._pending_deploys]}
        return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=payload)

    def remove_pending(self) -> ResponseType | None:
        """
        # Summary

        Remove all queued interfaces in a single API call via `interfaceActions/remove`. Clears the pending queue after removal.

        Returns `None` without making any API call if the queue is empty.

        ## Raises

        ### RuntimeError

        - If the remove API request fails.
        """
        if not self._pending_removes:
            return None
        try:
            result = self._remove_interfaces()
            self._pending_removes = []
            return result
        except Exception as e:
            raise RuntimeError(f"Bulk remove failed for interfaces {self._pending_removes}: {e}") from e

    def _remove_interfaces(self) -> ResponseType:
        """
        # Summary

        Remove queued interfaces via `interfaceActions/remove`. Sends the explicit list of `{interfaceName, switchId}` pairs.

        ## Raises

        ### Exception

        - If the remove API request fails (propagated to caller).
        """
        api_endpoint = EpManageInterfacesRemove()
        api_endpoint.fabric_name = self.fabric_name
        payload = {"interfaces": [{"interfaceName": name, "switchId": self.switch_id} for name in self._pending_removes]}
        return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=payload)

    def create(self, model_instance: LoopbackInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Create a loopback interface. Injects `switchId` and wraps the payload in an `interfaces` array. Queues a deploy for later
        bulk execution via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If the create API request fails.
        """
        try:
            api_endpoint = self._configure_endpoint(self.create_endpoint())
            payload = model_instance.to_payload()
            payload["switchId"] = self.switch_id
            request_body = {"interfaces": [payload]}
            result = self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=request_body)
            self._queue_deploy(model_instance.interface_name)
            return result
        except Exception as e:
            raise RuntimeError(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: LoopbackInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Update a loopback interface. Injects `switchId` into the payload. Queues a deploy for later bulk execution via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If the update API request fails.
        """
        try:
            api_endpoint = self._configure_endpoint(self.update_endpoint())
            api_endpoint.set_identifiers(model_instance.interface_name)
            payload = model_instance.to_payload()
            payload["switchId"] = self.switch_id
            result = self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=payload)
            self._queue_deploy(model_instance.interface_name)
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
        self._queue_remove(model_instance.interface_name)
        self._queue_deploy(model_instance.interface_name)

    def query_one(self, model_instance: LoopbackInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Query a single loopback interface by name.

        ## Raises

        ### RuntimeError

        - If the query API request fails.
        """
        try:
            api_endpoint = self._configure_endpoint(self.query_one_endpoint())
            api_endpoint.set_identifiers(model_instance.interface_name)
            return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb)
        except Exception as e:
            raise RuntimeError(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self, model_instance: Optional[NDBaseModel] = None, **kwargs) -> ResponseType:
        """
        # Summary

        Validate the fabric context and query all interfaces on the switch, filtering for user-managed loopback interfaces only.

        System-provisioned loopbacks (e.g. Loopback0 routing, Loopback1 VTEP with `policyType: "underlayLoopback"`) are excluded because they are managed by ND
        during initial switch role configuration and cannot be deleted or modified by this module.

        Runs `validate` on first call to ensure the fabric exists, is modifiable, and the target switch is reachable
        before returning any data.

        ## Raises

        ### RuntimeError

        - If the fabric does not exist on the target ND node.
        - If the fabric is in deployment-freeze mode.
        - If no switch matches the given `switch_ip` in the fabric.
        - If the query API request fails.
        """
        managed_policy_types = set(LOOPBACK_POLICY_TYPE_MAPPING.data.values())
        try:
            self.validate_prerequisites()
            api_endpoint = self._configure_endpoint(self.query_all_endpoint())
            result = self.sender.query_obj(api_endpoint.path)
            if not result:
                return []
            interfaces = result.get("interfaces", []) or []
            loopbacks = [iface for iface in interfaces if iface.get("interfaceType") == "loopback"]
            return [lb for lb in loopbacks if lb.get("configData", {}).get("networkOS", {}).get("policy", {}).get("policyType") in managed_policy_types]
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e
