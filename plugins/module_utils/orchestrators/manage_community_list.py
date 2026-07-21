# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_community_lists import (
    EpManageCommunityListsBulkDelete,
    EpManageCommunityListsDelete,
    EpManageCommunityListsGet,
    EpManageCommunityListsListGet,
    EpManageCommunityListsPost,
    EpManageCommunityListsPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_community_list.manage_community_list import CommunityListModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

_FAILURE_STATUSES = frozenset({"failed", "failure", "error"})


class ManageCommunityListOrchestrator(NDBaseOrchestrator[CommunityListModel]):
    """
    Orchestrator for community list CRUD operations on Nexus Dashboard.

    Community lists are created and deleted in bulk via dedicated API endpoints:
    - Create: POST /fabrics/{fabricName}/communityLists with {"communityLists": [...]}
    - Delete: POST /fabrics/{fabricName}/communityListActions/remove with
      {"communityListNames": [...]}

    The ``fabric_name`` is not part of the CommunityListModel; it is injected
    here and assigned to every endpoint instance before use.
    """

    model_class: ClassVar[type[NDBaseModel]] = CommunityListModel

    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    query_all_page_size: ClassVar[int] = 100
    query_all_max_pages: ClassVar[int] = 10000

    # Stub assignments satisfy NDBaseOrchestrator.validate_bulk_endpoints
    create_endpoint: type[NDEndpointBaseModel] = EpManageCommunityListsPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageCommunityListsPut
    delete_endpoint: type[NDEndpointBaseModel] = EpManageCommunityListsDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageCommunityListsGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageCommunityListsListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] = EpManageCommunityListsPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] = EpManageCommunityListsBulkDelete

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
    def cluster_name(self) -> str | None:
        """Return the optional target cluster name from module params."""
        return self.rest_send.params.get("cluster_name")

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

    def preflight(self, model_instances: list[CommunityListModel]) -> None:
        """Validate that the target fabric can be mutated before writes."""
        if model_instances:
            self.fabric_context.validate_for_mutation()

    def _configure_endpoint(self, api_endpoint: NDEndpointBaseModel) -> NDEndpointBaseModel:
        """
        # Summary

        Set `fabric_name` on an endpoint instance before path generation.

        ## Raises

        None
        """
        api_endpoint.fabric_name = self.fabric_name
        params = getattr(api_endpoint, "endpoint_params", None)
        if self.cluster_name and params is not None and hasattr(params, "cluster_name"):
            params.cluster_name = self.cluster_name
        return api_endpoint

    @staticmethod
    def _raise_on_207_action_errors(result: Any) -> None:
        """
        # Summary

        Inspect a bulk create/delete response and raise on explicit per-item failure tokens.

        ## Raises

        ### RuntimeError

        - If a `results` item reports failed, failure, or error.
        """
        if not isinstance(result, dict):
            return
        items = result.get("results")
        if not isinstance(items, list):
            return
        failures = [
            item
            for item in items
            if isinstance(item, dict) and str(item.get("status") or "").lower() in _FAILURE_STATUSES
        ]
        if failures:
            details = ", ".join(f"{item.get('name')}: {item.get('status')} - {item.get('message')}" for item in failures)
            raise RuntimeError(f"Per-item failures in community list response: {details}")

    @staticmethod
    def _validate_write_model(model_instance: CommunityListModel) -> None:
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
            raise RuntimeError(f"community list '{model_instance.name}' requires {', '.join(missing)} for create/update operations.")

    def create(self, model_instance: CommunityListModel, **kwargs) -> ResponseType:
        """Delegate single create to bulk create."""
        return self.create_bulk([model_instance], **kwargs)

    def create_bulk(self, model_instances: list[CommunityListModel], **kwargs) -> ResponseType:
        """
        Bulk-create community lists.

        POST /fabrics/{fabricName}/communityLists
        Body: {"communityLists": [...]}
        """
        try:
            for model_instance in model_instances:
                self._validate_write_model(model_instance)
            ep = self._configure_endpoint(self.create_bulk_endpoint())
            payload = {"communityLists": [m.to_payload() for m in model_instances]}
            result = self._request(path=ep.path, verb=ep.verb, data=payload, operation_type=OperationType.CREATE)
            self._raise_on_207_action_errors(result)
            return result
        except Exception as e:
            names = [m.name for m in model_instances]
            raise RuntimeError(f"Bulk create failed for {names}: {e}") from e

    def update(self, model_instance: CommunityListModel, **kwargs) -> ResponseType:
        """Update a single community list by name."""
        try:
            self._validate_write_model(model_instance)
            ep = self._configure_endpoint(self.update_endpoint())
            ep.set_identifiers(model_instance.get_identifier_value())
            return self._request(
                path=ep.path,
                verb=ep.verb,
                data=model_instance.to_payload(),
                operation_type=OperationType.UPDATE,
            )
        except Exception as e:
            raise RuntimeError(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: CommunityListModel, **kwargs) -> ResponseType:
        """Delegate single delete to bulk delete."""
        return self.delete_bulk([model_instance], **kwargs)

    def delete_bulk(self, model_instances: list[CommunityListModel], **kwargs) -> ResponseType:
        """
        Bulk-delete community lists by name.

        POST /fabrics/{fabricName}/communityListActions/remove
        Body: {"communityListNames": [...]}
        """
        try:
            ep = self._configure_endpoint(self.delete_bulk_endpoint())
            payload = {"communityListNames": [m.get_identifier_value() for m in model_instances]}
            result = self._request(path=ep.path, verb=ep.verb, data=payload, operation_type=OperationType.DELETE)
            self._raise_on_207_action_errors(result)
            return result
        except Exception as e:
            names = [m.name for m in model_instances]
            raise RuntimeError(f"Bulk delete failed for {names}: {e}") from e

    def query_one(self, model_instance: CommunityListModel, **kwargs) -> ResponseType:
        """Retrieve a single community list by name."""
        try:
            ep = self._configure_endpoint(self.query_one_endpoint())
            ep.set_identifiers(model_instance.get_identifier_value())
            return self._request(path=ep.path, verb=ep.verb)
        except Exception as e:
            raise RuntimeError(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self, model_instance: CommunityListModel | None = None, **kwargs) -> ResponseType:
        """
        Retrieve all community lists for the fabric.

        Extracts the ``communityLists`` wrapper key from the list response.
        """
        try:
            collected: list[dict] = []
            seen: set[str] = set()
            offset = 0
            pages_fetched = 0
            while pages_fetched < self.query_all_max_pages:
                pages_fetched += 1
                ep = self._configure_endpoint(self.query_all_endpoint())
                ep.lucene_params.max = self.query_all_page_size
                ep.lucene_params.offset = offset
                result = self._request(path=ep.path, verb=ep.verb, not_found_ok=True)
                page = result.get("communityLists", []) or [] if isinstance(result, dict) else (result or [])
                if not page:
                    break

                new_rows = 0
                for row in page:
                    name = row.get("name") if isinstance(row, dict) else None
                    if name is not None:
                        if name in seen:
                            continue
                        seen.add(name)
                    collected.append(row)
                    new_rows += 1

                if len(page) < self.query_all_page_size or new_rows == 0:
                    break
                offset += self.query_all_page_size
            return collected
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e
