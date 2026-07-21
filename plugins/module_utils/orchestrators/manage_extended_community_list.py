# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_extended_community_lists import (
    EpManageExtendedCommunityListsBulkDelete,
    EpManageExtendedCommunityListsDelete,
    EpManageExtendedCommunityListsGet,
    EpManageExtendedCommunityListsListGet,
    EpManageExtendedCommunityListsPost,
    EpManageExtendedCommunityListsPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_extended_community_list.manage_extended_community_list import (
    ExtendedCommunityListModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class ManageExtendedCommunityListOrchestrator(NDBaseOrchestrator[ExtendedCommunityListModel]):
    """
    Orchestrator for extended community list CRUD operations on Nexus Dashboard.

    Extended community lists are created and deleted in bulk via dedicated
    API endpoints:
    - Create: POST /fabrics/{fabricName}/extendedCommunityLists
              body: {"extendedCommunityLists": [...]}
    - Delete: POST /fabrics/{fabricName}/extendedCommunityListActions/remove
              body: {"extendedCommunityListNames": [...]}

    The ``fabric_name`` is not part of ExtendedCommunityListModel; it is
    injected here and assigned to every endpoint instance before use.
    """

    model_class: ClassVar[type[NDBaseModel]] = ExtendedCommunityListModel

    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True

    # Satisfy NDBaseOrchestrator.validate_bulk_endpoints
    create_endpoint: type[NDEndpointBaseModel] = EpManageExtendedCommunityListsPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageExtendedCommunityListsPut
    delete_endpoint: type[NDEndpointBaseModel] = EpManageExtendedCommunityListsDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageExtendedCommunityListsGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageExtendedCommunityListsListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] = EpManageExtendedCommunityListsPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] = EpManageExtendedCommunityListsBulkDelete

    _fabric_context: FabricContext | None = None

    @property
    def fabric_name(self) -> str:
        """
        # Summary

        Return `fabric_name` from module params.

        ## Raises

        None
        """
        return self.rest_send.params.get("fabric_name")

    @property
    def fabric_context(self) -> FabricContext:
        """
        # Summary

        Return a lazily initialized `FabricContext` for this orchestrator's fabric.

        ## Raises

        None
        """
        if self._fabric_context is None:
            self._fabric_context = FabricContext(rest_send=self.rest_send, fabric_name=self.fabric_name)
        return self._fabric_context

    def validate_prerequisites(self) -> None:
        """
        # Summary

        Validate that the target fabric exists, is local, and is not deployment-frozen.

        ## Raises

        ### RuntimeError

        - If the fabric cannot be safely mutated.
        """
        self.fabric_context.validate_for_mutation()

    def _configure_endpoint(self, api_endpoint: NDEndpointBaseModel) -> NDEndpointBaseModel:
        """
        # Summary

        Set `fabric_name` on an endpoint instance before path generation.

        ## Raises

        None
        """
        api_endpoint.fabric_name = self.fabric_name
        return api_endpoint

    @staticmethod
    def _raise_on_207_action_errors(result: Any) -> None:
        """
        # Summary

        Inspect a bulk create/delete response and raise when any per-item status is not `success`.

        ## Raises

        ### RuntimeError

        - If a `results` item is missing `status` or reports a non-success status.
        """
        if not isinstance(result, dict):
            return
        items = result.get("results")
        if not isinstance(items, list):
            return
        failures = [item for item in items if isinstance(item, dict) and item.get("status") != "success"]
        if failures:
            details = ", ".join(f"{item.get('name')}: {item.get('status')} - {item.get('message')}" for item in failures)
            raise RuntimeError(f"Per-item failures in extended community list response: {details}")

    @staticmethod
    def _validate_write_model(model_instance: ExtendedCommunityListModel) -> None:
        """
        # Summary

        Require the fields Nexus Dashboard needs for create/update bodies while still allowing
        name-only models for deletes.

        ## Raises

        ### RuntimeError

        - If `type` or `entries` is omitted for a write operation.
        """
        missing = []
        if model_instance.type is None:
            missing.append("type")
        if not model_instance.entries:
            missing.append("entries")
        if missing:
            raise RuntimeError(f"extended community list '{model_instance.name}' requires {', '.join(missing)} for create/update operations.")

    def create(self, model_instance: ExtendedCommunityListModel, **kwargs) -> ResponseType:
        """Delegate single create to bulk create."""
        return self.create_bulk([model_instance], **kwargs)

    def create_bulk(self, model_instances: list[ExtendedCommunityListModel], **kwargs) -> ResponseType:
        """
        Bulk-create extended community lists.

        POST /fabrics/{fabricName}/extendedCommunityLists
        Body: {"extendedCommunityLists": [...]}
        """
        try:
            for model_instance in model_instances:
                self._validate_write_model(model_instance)
            ep = self._configure_endpoint(self.create_bulk_endpoint())
            payload = {"extendedCommunityLists": [m.to_payload() for m in model_instances]}
            result = self._request(path=ep.path, verb=ep.verb, data=payload)
            self._raise_on_207_action_errors(result)
            return result
        except Exception as e:
            names = [m.name for m in model_instances]
            raise RuntimeError(f"Bulk create failed for {names}: {e}") from e

    def update(self, model_instance: ExtendedCommunityListModel, **kwargs) -> ResponseType:
        """Update a single extended community list by name."""
        try:
            self._validate_write_model(model_instance)
            ep = self._configure_endpoint(self.update_endpoint())
            ep.set_identifiers(model_instance.get_identifier_value())
            return self._request(path=ep.path, verb=ep.verb, data=model_instance.to_payload())
        except Exception as e:
            raise RuntimeError(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: ExtendedCommunityListModel, **kwargs) -> ResponseType:
        """Delegate single delete to bulk delete."""
        return self.delete_bulk([model_instance], **kwargs)

    def delete_bulk(self, model_instances: list[ExtendedCommunityListModel], **kwargs) -> ResponseType:
        """
        Bulk-delete extended community lists by name.

        POST /fabrics/{fabricName}/extendedCommunityListActions/remove
        Body: {"extendedCommunityListNames": [...]}
        """
        try:
            ep = self._configure_endpoint(self.delete_bulk_endpoint())
            payload = {"extendedCommunityListNames": [m.name for m in model_instances]}
            result = self._request(path=ep.path, verb=ep.verb, data=payload)
            self._raise_on_207_action_errors(result)
            return result
        except Exception as e:
            names = [m.name for m in model_instances]
            raise RuntimeError(f"Bulk delete failed for {names}: {e}") from e

    def query_one(self, model_instance: ExtendedCommunityListModel, **kwargs) -> ResponseType:
        """Retrieve a single extended community list by name."""
        try:
            ep = self._configure_endpoint(self.query_one_endpoint())
            ep.set_identifiers(model_instance.get_identifier_value())
            return self._request(path=ep.path, verb=ep.verb)
        except Exception as e:
            raise RuntimeError(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self, model_instance: ExtendedCommunityListModel | None = None, **kwargs) -> ResponseType:
        """
        Retrieve all extended community lists for the fabric.

        Extracts the ``extendedCommunityLists`` wrapper key from the list response.
        """
        try:
            self.validate_prerequisites()
            ep = self._configure_endpoint(self.query_all_endpoint())
            result = self._request(path=ep.path, verb=ep.verb, not_found_ok=True)
            if isinstance(result, dict):
                return result.get("extendedCommunityLists", []) or []
            return []
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e
