# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Managed L3 subinterface orchestrator for Nexus Dashboard.

This module provides `SubinterfaceManagedInterfaceOrchestrator`, which implements CRUD operations for managed L3
subinterfaces (`interfaceType: "subInterface"`, `policyType: "subinterface"`, `mode: "managed"`) via the ND Manage
Interfaces API. Supports configuring subinterfaces across multiple switches in a single task.

Each mutation operation (create, update, delete) is followed by a deploy call to persist changes to the switch.
Deploy and remove operations are batched per-switch and executed in bulk after all mutations are complete.

Subinterfaces are logical and support both `interfaceActions/remove` (bulk delete) and `interfaceActions/deploy`
(bulk deploy), so `state: deleted` queues both and lets the standard `remove_pending` + `deploy_pending` flow
handle the work (the same pattern used by `nd_interface_svi`, unlike physical ethernet which must use normalize).
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
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import SubinterfaceManagedPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.subinterface_managed_interface import SubinterfaceManagedInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class SubinterfaceManagedInterfaceOrchestrator(NDBaseInterfaceOrchestrator[SubinterfaceManagedInterfaceModel]):
    """
    # Summary

    Orchestrator for managed L3 subinterface CRUD operations on Nexus Dashboard.

    Supports configuring subinterfaces across multiple switches in a single task. Each config item includes a
    `switch_ip` that is resolved to a `switchId` via `FabricContext`.

    Mutation methods (`create`, `update`) queue deploys instead of executing them immediately. Call `deploy_pending`
    after all mutations are complete to deploy all changes in a single API call. `delete` queues subinterfaces for
    bulk removal via `remove_pending`.

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

    model_class: ClassVar[type[NDBaseModel]] = SubinterfaceManagedInterfaceModel
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True

    # TODO(4.2.1) ND returns HTTP 207 Multi-Status on subinterface POST with per-item `status: "failed"` when the parent
    # interface is not in routed mode (or other policy validation fails). Our RestSend response_handler treats 207 as
    # success and returns the body without raising, so without this check the orchestrator would silently report
    # "changed" when nothing was actually created. Remove this workaround once CiscoDevNet/ansible-nd#295 lands the
    # 207-aware response handling at the RestSend layer.
    @staticmethod
    def _raise_on_multi_status_failures(response: ResponseType) -> None:
        """
        # Summary

        Inspect a 207 Multi-Status body and raise if any item carries `status: "failed"` or `status: "error"`.

        ## Raises

        ### RuntimeError

        - If `response["results"]` contains any item with `status` in `("failed", "error")`.
        """
        if not isinstance(response, dict):
            return
        results = response.get("results") or []
        failed = [r for r in results if isinstance(r, dict) and r.get("status") in ("failed", "error")]
        if failed:
            summary = "; ".join(f"{r.get('name')}: {r.get('message')}" for r in failed)
            raise RuntimeError(f"ND rejected {len(failed)} interface(s): {summary}")

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() uses bulk remove
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesRemove

    def create(self, model_instance: SubinterfaceManagedInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Create a managed L3 subinterface. Resolves `switch_ip` from the model instance, injects `switchId`, and wraps
        the payload in an `interfaces` array. Queues a deploy for later bulk execution via `deploy_pending`.

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
            self._raise_on_multi_status_failures(result)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return result
        except Exception as e:
            raise RuntimeError(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: SubinterfaceManagedInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Update a managed L3 subinterface. Resolves `switch_ip` from the model instance, injects `switchId` into the
        payload. Queues a deploy for later bulk execution via `deploy_pending`.

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

    def delete(self, model_instance: SubinterfaceManagedInterfaceModel, **kwargs) -> None:
        """
        # Summary

        Queue a managed L3 subinterface for deferred bulk removal via `remove_pending` and bulk deploy via
        `deploy_pending`. The remove deletes the subinterface from ND's config; the subsequent deploy pushes that
        removal to the switch.

        No API calls are made until `remove_pending` and `deploy_pending` are called after all mutations are complete.

        ## Raises

        None
        """
        switch_id = self._resolve_switch_id(model_instance.switch_ip)
        self._queue_remove(model_instance.interface_name, switch_id)
        self._queue_deploy(model_instance.interface_name, switch_id)

    def create_bulk(self, model_instances: list[SubinterfaceManagedInterfaceModel], **kwargs) -> ResponseType:
        """
        # Summary

        Create multiple managed L3 subinterfaces in bulk. Groups subinterfaces by switch and sends one POST per
        switch with all subinterfaces in the `interfaces` array, reducing API calls from N to one-per-switch. Queues
        deploys for all created subinterfaces for later bulk execution via `deploy_pending`.

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
                api_endpoint = self._configure_endpoint(self.create_bulk_endpoint(), switch_sn=switch_id)  # pyright: ignore[reportOptionalCall]
                request_body = {"interfaces": [payload for interface_name, payload in items]}
                result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=request_body)
                self._raise_on_multi_status_failures(result)
                results.append(result)
                for interface_name, payload in items:
                    self._queue_deploy(interface_name, switch_id)
            return results
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

    def delete_bulk(self, model_instances: list[SubinterfaceManagedInterfaceModel], **kwargs) -> None:
        """
        # Summary

        Queue multiple managed L3 subinterfaces for deferred bulk removal and deployment. No API calls are made until
        `remove_pending` and `deploy_pending` are called after `manage_state` completes.

        ## Raises

        None
        """
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            self._queue_remove(model_instance.interface_name, switch_id)
            self._queue_deploy(model_instance.interface_name, switch_id)

    def query_one(self, model_instance: SubinterfaceManagedInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Query a single managed L3 subinterface by name on a specific switch.

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

    def query_all(self, model_instance: NDBaseModel | None = None, **kwargs) -> ResponseType:
        """
        # Summary

        Validate the fabric context and query all interfaces across ALL switches in the fabric, filtering for
        subinterfaces with `interfaceType: "subInterface"` and `policyType: "subinterface"` (managed variant). The
        unmanaged variant (`monitorSubinterface`) is managed by a separate orchestrator and is excluded here.

        Runs `validate_prerequisites` on first call to ensure the fabric exists and is modifiable before returning
        any data.

        Each returned interface dict is enriched with a `switch_ip` field so that
        `SubinterfaceManagedInterfaceModel` can be constructed with the composite identifier
        `(switch_ip, interface_name)`.

        ## Raises

        ### RuntimeError

        - If the fabric does not exist on the target ND node.
        - If the fabric is in deployment-freeze mode.
        - If the query API request fails.
        """
        managed_policy_types = {e.value for e in SubinterfaceManagedPolicyTypeEnum}
        try:
            self.validate_prerequisites()
            all_subifs = []
            for switch_ip, switch_id in self.fabric_context.switch_map.items():
                api_endpoint = self._configure_endpoint(self.query_all_endpoint(), switch_sn=switch_id)
                result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
                if not isinstance(result, dict):
                    continue
                interfaces = result.get("interfaces", []) or []
                subifs = [iface for iface in interfaces if iface.get("interfaceType") == "subInterface"]
                managed = [
                    iface for iface in subifs if iface.get("configData", {}).get("networkOS", {}).get("policy", {}).get("policyType") in managed_policy_types
                ]
                for iface in managed:
                    iface["switchIp"] = switch_ip
                all_subifs.extend(managed)
            return all_subifs
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e
