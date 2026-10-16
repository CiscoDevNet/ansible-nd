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
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_extended_community_list.manage_extended_community_list import ExtendedCommunityListModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import GatheredLuceneSpec, build_lucene_expressions

_FAILURE_STATUSES = frozenset({"failed", "failure", "error"})
_GATHERED_QUERY_MAX_EXPRESSIONS = 3


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
    query_all_page_size: ClassVar[int] = 100
    query_all_max_pages: ClassVar[int] = 100

    # Satisfy NDBaseOrchestrator.validate_bulk_endpoints
    create_endpoint: type[NDEndpointBaseModel] = EpManageExtendedCommunityListsPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageExtendedCommunityListsPut
    delete_endpoint: type[NDEndpointBaseModel] = EpManageExtendedCommunityListsDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageExtendedCommunityListsGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageExtendedCommunityListsListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] = EpManageExtendedCommunityListsPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] = EpManageExtendedCommunityListsBulkDelete

    supports_gathered_server_filtering: ClassVar[bool] = True
    gathered_lucene_spec: ClassVar[GatheredLuceneSpec] = GatheredLuceneSpec(
        base_terms=(),
        field_map={
            ("type",): "type",
        },
    )

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

    def preflight(self, model_instances: list[ExtendedCommunityListModel]) -> None:
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
        failures = [item for item in items if isinstance(item, dict) and str(item.get("status") or "").lower() in _FAILURE_STATUSES]
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
            result = self._request(path=ep.path, verb=ep.verb, data=payload, operation_type=OperationType.CREATE)
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
            return self._request(
                path=ep.path,
                verb=ep.verb,
                data=model_instance.to_payload(),
                operation_type=OperationType.UPDATE,
            )
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
            payload = {"extendedCommunityListNames": [m.get_identifier_value() for m in model_instances]}
            result = self._request(path=ep.path, verb=ep.verb, data=payload, operation_type=OperationType.DELETE)
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

    def query_all(self, model_instance: ExtendedCommunityListModel | None = None, gathered_filters=None, **kwargs) -> ResponseType:
        """
        Retrieve all extended community lists for the fabric.

        When ``gathered_filters`` is not None, routes to the gathered path
        which uses safe type-based Lucene reduction and leaves name matching
        to the shared local filter.
        """
        try:
            if gathered_filters is not None:
                return self._query_all_for_gathered(gathered_filters)
            return self._query_all_for_management_states()
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e

    def _query_all_for_management_states(self, expression: str | None = None) -> list[dict]:
        """Fetch all extended community lists with pagination, optionally filtered by Lucene expression."""
        collected: list[dict] = []
        seen: set[tuple[str | None, str]] = set()
        offset = 0
        pages_fetched = 0
        while pages_fetched < self.query_all_max_pages:
            pages_fetched += 1
            ep = self._configure_endpoint(self.query_all_endpoint())
            ep.lucene_params.max = self.query_all_page_size
            ep.lucene_params.offset = offset
            if expression is not None:
                ep.lucene_params.filter = expression
            result = self._request(path=ep.path, verb=ep.verb, not_found_ok=True)
            page = result.get("extendedCommunityLists", []) or [] if isinstance(result, dict) else (result or [])
            if not page:
                break

            new_rows = 0
            for row in page:
                name = row.get("name") if isinstance(row, dict) else None
                if name is not None:
                    key = (row.get("tenantName"), name)
                    if key in seen:
                        continue
                    seen.add(key)
                collected.append(row)
                new_rows += 1

            if not self._has_next_page(result, len(page), offset):
                break
            if new_rows == 0:
                raise RuntimeError("Pagination did not advance while the controller reported additional extended community lists.")
            offset += len(page)
        else:
            raise RuntimeError(
                f"Pagination limit reached ({self.query_all_max_pages} pages, "
                f"{len(collected)} extended community lists collected). Results may be incomplete."
            )
        return collected

    def _has_next_page(self, result: object, page_count: int, offset: int) -> bool:
        """Return whether controller metadata or page size indicates another page."""
        if page_count == 0:
            return False
        if isinstance(result, dict):
            counts = (result.get("meta") or {}).get("counts") or {}
            try:
                total = int(counts["total"])
            except (KeyError, TypeError, ValueError):
                total = None
            if total is not None:
                return offset + page_count < total
            try:
                remaining = int(counts["remaining"])
            except (KeyError, TypeError, ValueError):
                remaining = None
            if remaining is not None:
                return remaining > 0
        return page_count == self.query_all_page_size

    def _query_all_for_gathered(self, gathered_filters=None) -> list[dict]:
        """
        Fetch extended community lists for gathered state, optionally filtered by name and type.

        Type-only server filtering is safe because the API type value matches the
        normalized Ansible value. Name criteria remain local: tenant-scoped API
        names are qualified as ``tenant~name`` on the wire but normalized to a
        bare name in gathered output, so an exact server-side name query could
        omit valid tenant-scoped matches.
        """
        filter_items = gathered_filters or [{}]
        results: list[dict] = []
        seen: set[tuple[str | None, str]] = set()
        lucene_filters = [{"type": item["type"]} for item in filter_items if item.get("type") not in (None, "")]
        expressions = build_lucene_expressions(lucene_filters, spec=self.gathered_lucene_spec) if len(lucene_filters) == len(filter_items) else []
        if len(expressions) > _GATHERED_QUERY_MAX_EXPRESSIONS:
            expressions = []

        if expressions:
            for expression in expressions:
                for item in self._query_all_for_management_states(expression):
                    name = item.get("name") if isinstance(item, dict) else None
                    key = (item.get("tenantName"), name) if name is not None else None
                    if key is not None and key not in seen:
                        seen.add(key)
                        results.append(item)
        else:
            for item in self._query_all_for_management_states():
                name = item.get("name") if isinstance(item, dict) else None
                key = (item.get("tenantName"), name) if name is not None else None
                if key is not None and key not in seen:
                    seen.add(key)
                    results.append(item)

        return results
