# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unmanaged L3 subinterface orchestrator for Nexus Dashboard.

Implements CRUD for the unmanaged variant of L3 subinterfaces
(`interfaceType: "subInterface"`, `mode: "unmanaged"`, `policyType: "monitorSubinterface"`).

Mirrors `SubinterfaceManagedInterfaceOrchestrator` in structure; differences:
- `model_class` is `SubinterfaceUnmanagedInterfaceModel`
- `query_all` filters for `policyType in {monitorSubinterface}`
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
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import SubinterfaceUnmanagedPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.subinterface_unmanaged_interface import SubinterfaceUnmanagedInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class SubinterfaceUnmanagedInterfaceOrchestrator(NDBaseInterfaceOrchestrator[SubinterfaceUnmanagedInterfaceModel]):
    """
    # Summary

    Orchestrator for unmanaged L3 subinterface CRUD on Nexus Dashboard. See
    `SubinterfaceManagedInterfaceOrchestrator` for the architectural notes; this is its sibling for the
    `monitorSubinterface` policy.

    ## Raises

    ### RuntimeError

    - On any failed API request or 207 multi-status with a non-success per-item entry.
    """

    model_class: ClassVar[type[NDBaseModel]] = SubinterfaceUnmanagedInterfaceModel
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() uses bulk remove
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesRemove

    # TODO ND returns HTTP 207 Multi-Status on subinterface POST with per-item `status: "failed"` when the parent
    # interface is not in routed mode (or other policy validation fails). Our RestSend response_handler treats 207
    # as success and returns the body without raising. Remove this workaround once CiscoDevNet/ansible-nd#295 lands
    # the 207-aware response handling at the RestSend layer.
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

    def create(self, model_instance: SubinterfaceUnmanagedInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Create an unmanaged L3 subinterface. Resolves `switch_ip` from the model instance, injects `switchId`,
        wraps the payload in an `interfaces` array, and queues a deploy for later bulk execution.

        ## Raises

        ### RuntimeError

        - If the create API request fails.
        - If the 207 response contains any per-item `status` of `failed` or `error`.
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

    def update(self, model_instance: SubinterfaceUnmanagedInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Update an unmanaged L3 subinterface. Resolves `switch_ip` from the model instance, injects `switchId` into the
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

    def delete(self, model_instance: SubinterfaceUnmanagedInterfaceModel, **kwargs) -> None:
        """
        # Summary

        Queue an unmanaged L3 subinterface for deferred bulk removal via `remove_pending` and bulk deploy via
        `deploy_pending`. The remove deletes the subinterface from ND's config; the subsequent deploy pushes that
        removal to the switch.

        No API calls are made until `remove_pending` and `deploy_pending` are called after all mutations are complete.

        ## Raises

        None
        """
        switch_id = self._resolve_switch_id(model_instance.switch_ip)
        self._queue_remove(model_instance.interface_name, switch_id)
        self._queue_deploy(model_instance.interface_name, switch_id)
