# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_route_maps import (
    EpManageRouteMapsDelete,
    EpManageRouteMapsBulkDelete,
    EpManageRouteMapsGet,
    EpManageRouteMapsListGet,
    EpManageRouteMapsPost,
    EpManageRouteMapsPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_route_map.manage_route_map import RouteMapModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

# Per-item ``status`` values in a 207 Multi-Status body that count as a failure. Anything else --
# ``success``, missing, empty, or future progress tokens -- is tolerated so informational rows do
# not surface as spurious errors. Mirrors the ACL orchestrator's denylist approach.
_FAILURE_STATUSES = frozenset({"failed", "failure", "error"})

# camelCase wrapper key used in route-map list responses and bulk-create request bodies.
_LIST_KEY = "routeMaps"


class ManageRouteMapOrchestrator(NDBaseOrchestrator[RouteMapModel]):
    """
    Orchestrator for Route Map CRUD operations.

    This orchestrator manages route maps for a single fabric identified by
    ``fabric_name``.  Because the API only supports bulk-create
    (``POST /routeMaps`` with ``{"routeMaps": [...]}``) and bulk-delete
    (``POST /routeMapActions/remove`` with ``{"routeMapNames": [...]}``)
    those two operations are implemented as custom ``create_bulk`` /
    ``delete_bulk`` methods.  Individual updates are performed via the
    standard ``PUT /routeMaps/{routeMapName}`` endpoint.

    The fabric scope is read from the top-level module parameter
    ``fabric_name`` via ``rest_send.params``.
    """

    model_class: ClassVar[type[NDBaseModel]] = RouteMapModel

    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    query_all_page_size: ClassVar[int] = 100
    query_all_max_pages: ClassVar[int] = 10000

    # Standard endpoint references (single-item operations)
    create_endpoint: type[NDEndpointBaseModel] = EpManageRouteMapsPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageRouteMapsPut
    delete_endpoint: type[NDEndpointBaseModel] = EpManageRouteMapsDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageRouteMapsGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageRouteMapsListGet

    # Bulk endpoint references
    create_bulk_endpoint: type[NDEndpointBaseModel] = EpManageRouteMapsPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] = EpManageRouteMapsBulkDelete

    _fabric_context: FabricContext | None = None

    @property
    def fabric_name(self) -> str:
        """Return the fabric name from module params."""
        return self.rest_send.params.get("fabric_name")

    @property
    def cluster_name(self) -> str | None:
        """Return the optional target cluster name from module params."""
        return self.rest_send.params.get("cluster_name")

    @property
    def fabric_context(self) -> FabricContext:
        """Return a lazily-created fabric context for pre-flight checks."""
        if self._fabric_context is None:
            self._fabric_context = FabricContext(rest_send=self.rest_send, fabric_name=self.fabric_name)
        return self._fabric_context

    def _configure_endpoint(self, api_endpoint):
        """Set module-scoped endpoint values before path generation."""
        api_endpoint.fabric_name = self.fabric_name
        params = getattr(api_endpoint, "endpoint_params", None)
        if self.cluster_name and params is not None and hasattr(params, "cluster_name"):
            params.cluster_name = self.cluster_name
        return api_endpoint

    def preflight(self, model_instances: list[RouteMapModel]) -> None:
        """Validate that the target fabric can be mutated before writes."""
        if model_instances:
            self.fabric_context.validate_for_mutation()

    @staticmethod
    def _raise_on_bulk_errors(result: ResponseType, action: str) -> None:
        """Raise when a 207 bulk response contains failed per-item results."""
        if not isinstance(result, dict):
            return
        failures = []
        for item in result.get("results", []):
            if not isinstance(item, dict):
                continue
            status = str(item.get("status") or "").lower()
            if status in _FAILURE_STATUSES:
                failures.append(item)
        if not failures:
            return
        details = []
        for item in failures:
            name = item.get("name") or "<unknown>"
            status = item.get("status") or "<unknown>"
            message = item.get("message") or "no message"
            details.append(f"{name}: {status}: {message}")
        raise RuntimeError(f"Route map bulk {action} failed for {', '.join(details)}")

    # -------------------------------------------------------------------------
    # Query helpers
    # -------------------------------------------------------------------------

    def query_all(self) -> ResponseType:
        """
        List all route maps for the configured fabric.

        The list endpoint paginates, so this walks the collection with
        ``max``/``offset`` until a page arrives short or empty. A ``seen`` set
        de-duplicates by route-map name so an ignored offset cannot loop
        forever, and ``query_all_max_pages`` bounds the walk as a final safety
        net.
        """
        try:
            page_size = self.query_all_page_size
            collected: list[dict] = []
            seen: set[str] = set()
            offset = 0
            pages_fetched = 0
            while pages_fetched < self.query_all_max_pages:
                pages_fetched += 1
                api_endpoint = self._configure_endpoint(self.query_all_endpoint())
                api_endpoint.lucene_params.max = page_size
                api_endpoint.lucene_params.offset = offset
                result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
                page = result.get(_LIST_KEY, []) or [] if isinstance(result, dict) else (result or [])
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

                if len(page) < page_size or new_rows == 0:
                    break
                offset += page_size
            return collected
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e

    def query_one(self, model_instance: RouteMapModel, **kwargs) -> ResponseType:
        """Retrieve a single route map by name."""
        try:
            api_endpoint = self._configure_endpoint(self.query_one_endpoint())
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb)
        except Exception as e:
            raise Exception(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    # -------------------------------------------------------------------------
    # Write operations -- single item
    # -------------------------------------------------------------------------

    def create(self, model_instance: RouteMapModel, **kwargs) -> ResponseType:
        """
        Create a single route map via the bulk-create endpoint.

        Wraps the single model payload in ``{"routeMaps": [...]}``.
        """
        try:
            return self.create_bulk([model_instance])
        except Exception as e:
            raise Exception(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: RouteMapModel, **kwargs) -> ResponseType:
        """Update an existing route map via the PUT endpoint."""
        try:
            api_endpoint = self._configure_endpoint(self.update_endpoint())
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=model_instance.to_payload(), operation_type=OperationType.UPDATE)
        except Exception as e:
            raise Exception(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: RouteMapModel, **kwargs) -> ResponseType:
        """
        Delete a single route map via the bulk-delete endpoint.

        Wraps the single name in ``{"routeMapNames": [...]}``.
        """
        try:
            return self.delete_bulk([model_instance])
        except Exception as e:
            raise Exception(f"Delete failed for {model_instance.get_identifier_value()}: {e}") from e

    # -------------------------------------------------------------------------
    # Write operations -- bulk
    # -------------------------------------------------------------------------

    def create_bulk(self, model_instances: list[RouteMapModel], **kwargs) -> ResponseType:
        """
        Bulk-create route maps.

        Sends ``POST /fabrics/{fabricName}/routeMaps`` with body:
        ``{"routeMaps": [<RouteMap payload>, ...]}``.
        """
        try:
            api_endpoint = self._configure_endpoint(self.create_bulk_endpoint())
            payload = {_LIST_KEY: [item.to_payload() for item in model_instances]}
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload, operation_type=OperationType.CREATE)
            self._raise_on_bulk_errors(result, "create")
            return result
        except Exception as e:
            raise Exception(f"Bulk create failed: {e}") from e

    def delete_bulk(self, model_instances: list[RouteMapModel], **kwargs) -> ResponseType:
        """
        Bulk-delete route maps.

        Sends ``POST /fabrics/{fabricName}/routeMapActions/remove`` with body:
        ``{"routeMapNames": ["name1", "name2", ...]}``.
        """
        try:
            api_endpoint = self._configure_endpoint(self.delete_bulk_endpoint())
            route_map_names = [item.get_identifier_value() for item in model_instances]
            payload = {"routeMapNames": route_map_names}
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload, operation_type=OperationType.DELETE)
            self._raise_on_bulk_errors(result, "delete")
            return result
        except Exception as e:
            raise Exception(f"Bulk delete failed: {e}") from e
