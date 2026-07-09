# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import ClassVar, List, Type

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

    model_class: ClassVar[Type[NDBaseModel]] = RouteMapModel

    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True

    # Standard endpoint references (single-item operations)
    create_endpoint: Type[NDEndpointBaseModel] = EpManageRouteMapsPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageRouteMapsPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageRouteMapsDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageRouteMapsGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageRouteMapsListGet

    # Bulk endpoint references
    create_bulk_endpoint: Type[NDEndpointBaseModel] = EpManageRouteMapsPost
    delete_bulk_endpoint: Type[NDEndpointBaseModel] = EpManageRouteMapsBulkDelete

    _fabric_context: FabricContext | None = None

    @property
    def fabric_name(self) -> str:
        """Return the fabric name from module params."""
        return self.rest_send.params.get("fabric_name")

    @property
    def fabric_context(self) -> FabricContext:
        """Return a lazily-created fabric context for pre-flight checks."""
        if self._fabric_context is None:
            self._fabric_context = FabricContext(rest_send=self.rest_send, fabric_name=self.fabric_name)
        return self._fabric_context

    def _configure_endpoint(self, api_endpoint):
        """Set fabric_name on a route-map endpoint before path generation."""
        api_endpoint.fabric_name = self.fabric_name
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
        failures = [item for item in result.get("results", []) if isinstance(item, dict) and item.get("status") not in (None, "", "success")]
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

        The API response is wrapped under the ``"routeMaps"`` key; this method
        extracts and returns the list directly.
        """
        try:
            api_endpoint = self._configure_endpoint(self.query_all_endpoint())
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            return result.get("routeMaps", []) or []
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

    def create_bulk(self, model_instances: List[RouteMapModel], **kwargs) -> ResponseType:
        """
        Bulk-create route maps.

        Sends ``POST /fabrics/{fabricName}/routeMaps`` with body:
        ``{"routeMaps": [<RouteMap payload>, ...]}``.
        """
        try:
            api_endpoint = self._configure_endpoint(self.create_bulk_endpoint())
            payload = {"routeMaps": [item.to_payload() for item in model_instances]}
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload, operation_type=OperationType.CREATE)
            self._raise_on_bulk_errors(result, "create")
            return result
        except Exception as e:
            raise Exception(f"Bulk create failed: {e}") from e

    def delete_bulk(self, model_instances: List[RouteMapModel], **kwargs) -> ResponseType:
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
