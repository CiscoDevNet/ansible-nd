# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_prefix_lists import (
    EpManageIpv4PrefixListsBulkDelete,
    EpManageIpv4PrefixListsDelete,
    EpManageIpv4PrefixListsGet,
    EpManageIpv4PrefixListsListGet,
    EpManageIpv4PrefixListsPost,
    EpManageIpv4PrefixListsPut,
    EpManageIpv6PrefixListsBulkDelete,
    EpManageIpv6PrefixListsDelete,
    EpManageIpv6PrefixListsGet,
    EpManageIpv6PrefixListsListGet,
    EpManageIpv6PrefixListsPost,
    EpManageIpv6PrefixListsPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_prefix_list.manage_prefix_list import PrefixListModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

_QUERY_PAGE_SIZE = 100
_SCOPED_QUERY_MAX_IDENTIFIERS = 8

# Single source of truth for everything that differs between the two address families: the endpoint
# classes plus the camelCase wrapper keys used in request/response bodies. Centralising this here
# keeps every CRUD/bulk method address-family agnostic (no scattered ``"ipv4..." if v == "ipv4"``).
_VERSION_CONFIG: dict[str, dict[str, Any]] = {
    "ipv4": {
        "get": EpManageIpv4PrefixListsGet,
        "list": EpManageIpv4PrefixListsListGet,
        "post": EpManageIpv4PrefixListsPost,
        "put": EpManageIpv4PrefixListsPut,
        "delete": EpManageIpv4PrefixListsDelete,
        "bulk_delete": EpManageIpv4PrefixListsBulkDelete,
        "list_key": "ipv4PrefixLists",
        "names_key": "ipv4PrefixListNames",
    },
    "ipv6": {
        "get": EpManageIpv6PrefixListsGet,
        "list": EpManageIpv6PrefixListsListGet,
        "post": EpManageIpv6PrefixListsPost,
        "put": EpManageIpv6PrefixListsPut,
        "delete": EpManageIpv6PrefixListsDelete,
        "bulk_delete": EpManageIpv6PrefixListsBulkDelete,
        "list_key": "ipv6PrefixLists",
        "names_key": "ipv6PrefixListNames",
    },
}


class ManagePrefixListOrchestrator(NDBaseOrchestrator[PrefixListModel]):
    """
    Orchestrator for Prefix List (IPv4 and IPv6) CRUD operations.

    Both IPv4 and IPv6 prefix lists are managed through a single orchestrator.
    The ``ip_version`` field on the model selects the address-family endpoints
    and payload keys from ``_VERSION_CONFIG`` for each operation.

    **Creation and deletion** are performed via bulk API endpoints, which return
    HTTP 207 Multi-Status with a per-item ``results`` array:
    - IPv4 create: ``POST /fabrics/{fabricName}/ipv4PrefixLists``
      with ``{"ipv4PrefixLists": [...]}``.
    - IPv6 create: ``POST /fabrics/{fabricName}/ipv6PrefixLists``
      with ``{"ipv6PrefixLists": [...]}``.
    - IPv4 bulk delete: ``POST /fabrics/{fabricName}/ipv4PrefixListActions/remove``
      with ``{"ipv4PrefixListNames": [...]}``.
    - IPv6 bulk delete: ``POST /fabrics/{fabricName}/ipv6PrefixListActions/remove``
      with ``{"ipv6PrefixListNames": [...]}``.

    The controller answers these bulk calls with 207 Multi-Status even when some items
    fail; ``NdV1Strategy`` inspects the per-item ``results`` array and marks the request
    failed on any failing item, so partial failures surface as errors from ``_request``
    rather than being silently reported as success.

    ``query_all`` fetches both IPv4 and IPv6 prefix lists and injects the
    ``ipVersion`` key into each raw API response dict so ``PrefixListModel``
    can deserialise them correctly.

    Tenant-scoped prefix lists are modeled with bare ``name`` plus ``tenant_name`` for
    Ansible config, and with the API's fully qualified ``"<tenantName>~<name>"`` form
    for item lookups, updates, and bulk deletes.

    The ``fabric_name`` field is read from ``rest_send.params`` (populated by
    ``NDStateMachine`` from the validated module params).
    """

    model_class: ClassVar[type[NDBaseModel]] = PrefixListModel

    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True

    # Required by NDBaseOrchestrator, but every operation is overridden below to route by
    # ``ip_version`` via ``_VERSION_CONFIG``. These defaults only satisfy the base contract;
    # the IPv4 classes are arbitrary placeholders and are never invoked directly.
    create_endpoint: type[NDEndpointBaseModel] = EpManageIpv4PrefixListsPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageIpv4PrefixListsPut
    delete_endpoint: type[NDEndpointBaseModel] = EpManageIpv4PrefixListsDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageIpv4PrefixListsGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageIpv4PrefixListsListGet

    create_bulk_endpoint: type[NDEndpointBaseModel] = EpManageIpv4PrefixListsPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] = EpManageIpv4PrefixListsBulkDelete

    @property
    def fabric_name(self) -> str:
        """
        Return ``fabric_name`` from the module params.

        ``ManagePrefixListOrchestrator`` extends the generic ``NDBaseOrchestrator`` -- prefix lists
        are fabric-scoped but not switch-scoped, so the interface base's switch/deploy machinery is
        unnecessary. The generic base does not expose ``fabric_name``, so it is surfaced here from
        ``rest_send.params``, mirroring ``NDBaseInterfaceOrchestrator.fabric_name``.
        """
        return self.rest_send.params.get("fabric_name")

    @property
    def cluster_name(self) -> str | None:
        """
        Return optional ``cluster_name`` from module params.

        The Manage prefix-list API exposes ``clusterName`` on every operation.
        Keeping this as a top-level module parameter lets the orchestrator apply
        the same query parameter consistently to list, item, create, update, and
        bulk-delete endpoints.
        """
        return self.rest_send.params.get("cluster_name")

    def _config_for_version(self, version: str) -> dict[str, Any]:
        """Return the endpoint classes and payload keys for the given ip_version, failing fast on unknown values."""
        try:
            return _VERSION_CONFIG[version]
        except KeyError:
            raise ValueError(f"Unsupported ip_version '{version}'. Expected 'ipv4' or 'ipv6'.") from None

    def _split_by_ip_version(self, model_instances: list[PrefixListModel]) -> dict[str, list[PrefixListModel]]:
        """Split model instances into ipv4/ipv6 buckets and fail fast on unsupported versions."""
        grouped: dict[str, list[PrefixListModel]] = {"ipv4": [], "ipv6": []}
        for model in model_instances:
            version = str(model.ip_version)
            if version in grouped:
                grouped[version].append(model)
            else:
                raise ValueError(f"Unsupported ip_version '{version}' for prefix list '{model.name}'. Expected 'ipv4' or 'ipv6'.")
        return grouped

    def _configure_endpoint(
        self,
        api_endpoint: NDEndpointBaseModel,
        max_records: int | None = None,
        offset: int | None = None,
    ) -> NDEndpointBaseModel:
        """Attach shared fabric and query parameters before endpoint path generation."""
        api_endpoint.fabric_name = self.fabric_name
        endpoint_params = getattr(api_endpoint, "endpoint_params", None)
        if endpoint_params is None:
            return api_endpoint
        if self.cluster_name is not None and hasattr(endpoint_params, "cluster_name"):
            endpoint_params.cluster_name = self.cluster_name
        if max_records is not None and hasattr(endpoint_params, "max"):
            endpoint_params.max = max_records
        if offset is not None and hasattr(endpoint_params, "offset"):
            endpoint_params.offset = offset
        lucene_params = getattr(api_endpoint, "lucene_params", None)
        if lucene_params is not None:
            if max_records is not None:
                lucene_params.max = max_records
            if offset is not None:
                lucene_params.offset = offset
        return api_endpoint

    @staticmethod
    def _coerce_int(value: Any) -> int | None:
        """Return ``value`` as int when possible, otherwise ``None``."""
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _raw_items_from_params(params: dict[str, Any]) -> list[dict[str, Any]]:
        """Return module ``config`` as a list of dictionaries."""
        config = params.get("config") or []
        if isinstance(config, dict):
            config = [config]
        return [item for item in config if isinstance(item, dict)]

    def _proposed_identifiers(self) -> list[tuple[str, str | None, str]]:
        """Return unique ``(ip_version, tenant_name, name)`` identifiers from raw module config."""
        identifiers: list[tuple[str, str | None, str]] = []
        seen: set[tuple[str, str | None, str]] = set()
        for item in self._raw_items_from_params(self.rest_send.params):
            version = item.get("ip_version", item.get("ipVersion"))
            name = item.get("name")
            if version is None or name is None:
                continue
            tenant_name = item.get("tenant_name", item.get("tenantName"))
            normalized = (str(version), tenant_name, str(name))
            if normalized not in seen:
                seen.add(normalized)
                identifiers.append(normalized)
        return identifiers

    def _should_use_scoped_query(self, identifiers: list[tuple[str, str | None, str]]) -> bool:
        """Return whether initialization can query only proposed prefix-list identities."""
        state = self.rest_send.params.get("state")
        return state in {"merged", "replaced", "deleted"} and 0 < len(identifiers) <= _SCOPED_QUERY_MAX_IDENTIFIERS

    def _query_one_existing(self, version: str, tenant_name: str | None, name: str) -> dict[str, Any] | None:
        """Fetch one existing prefix list, returning ``None`` when it is absent."""
        config = self._config_for_version(version)
        api_endpoint = self._configure_endpoint(config["get"]())
        api_endpoint.set_identifiers((version, tenant_name, name))
        result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
        if not result:
            return None
        result["ipVersion"] = version
        if tenant_name is not None:
            result.setdefault("tenantName", tenant_name)
        return result

    def _query_proposed_existing(self, identifiers: list[tuple[str, str | None, str]]) -> list[dict[str, Any]]:
        """Fetch only the existing prefix lists named by module ``config``."""
        results: list[dict[str, Any]] = []
        for version, tenant_name, name in identifiers:
            item = self._query_one_existing(version, tenant_name, name)
            if item is not None:
                results.append(item)
        return results

    def _has_next_page(self, result: dict[str, Any], page_count: int, offset: int) -> bool:
        """Determine whether another offset/max page should be fetched."""
        if page_count == 0:
            return False
        meta = result.get("meta") or {}
        counts = meta.get("counts") or {}
        total = self._coerce_int(counts.get("total"))
        if total is not None:
            return offset + page_count < total
        remaining = self._coerce_int(counts.get("remaining"))
        if remaining is not None:
            return remaining > 0
        return page_count == _QUERY_PAGE_SIZE

    def _query_all_for_version(self, version: str) -> list[dict[str, Any]]:
        """Fetch all prefix lists for one address family using explicit offset/max pagination."""
        config = self._config_for_version(version)
        results: list[dict[str, Any]] = []
        offset = 0
        while True:
            api_endpoint = self._configure_endpoint(config["list"](), max_records=_QUERY_PAGE_SIZE, offset=offset)
            raw = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            if not raw:
                break
            page = raw.get(config["list_key"], []) or []
            for item in page:
                item["ipVersion"] = version
                results.append(item)
            if not self._has_next_page(raw, len(page), offset):
                break
            offset += len(page)
        return results

    def _bulk_create_for_version(self, version: str, items: list[PrefixListModel]) -> ResponseType:
        """Send a single bulk-create request for all items of the given ip_version."""
        config = self._config_for_version(version)
        api_endpoint = self._configure_endpoint(config["post"]())
        payload = {config["list_key"]: [item.to_payload() for item in items]}
        return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload, operation_type=OperationType.CREATE)

    def _bulk_delete_for_version(self, version: str, names: list[str]) -> ResponseType:
        """Send a single bulk-delete request for the given prefix list names."""
        config = self._config_for_version(version)
        api_endpoint = self._configure_endpoint(config["bulk_delete"]())
        payload = {config["names_key"]: names}
        return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload, operation_type=OperationType.DELETE)

    def create(self, model_instance: PrefixListModel, **kwargs) -> ResponseType:
        """Create a single prefix list via the bulk endpoint."""
        try:
            return self.create_bulk([model_instance])
        except Exception as e:
            raise Exception(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: PrefixListModel, **kwargs) -> ResponseType:
        """Update an existing prefix list via the PUT endpoint."""
        try:
            config = self._config_for_version(str(model_instance.ip_version))
            api_endpoint = self._configure_endpoint(config["put"]())
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            payload = model_instance.to_payload()
            if model_instance.tenant_name is not None:
                payload["name"] = model_instance.api_name
            if self.rest_send.params.get("state") in {"replaced", "overridden"} and model_instance.description is None:
                payload["description"] = ""
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload, operation_type=OperationType.UPDATE)
        except Exception as e:
            raise Exception(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: PrefixListModel, **kwargs) -> ResponseType:
        """Delete a single prefix list via the bulk-delete endpoint."""
        try:
            return self.delete_bulk([model_instance])
        except Exception as e:
            raise Exception(f"Delete failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_one(self, model_instance: PrefixListModel, **kwargs) -> ResponseType:
        """Retrieve a single prefix list by name and ip_version."""
        try:
            config = self._config_for_version(str(model_instance.ip_version))
            api_endpoint = self._configure_endpoint(config["get"]())
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb)
            if result:
                result["ipVersion"] = str(model_instance.ip_version)
                if model_instance.tenant_name is not None:
                    result.setdefault("tenantName", model_instance.tenant_name)
            return result
        except Exception as e:
            raise Exception(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self) -> ResponseType:
        """
        Fetch all IPv4 and IPv6 prefix lists and combine them into a single list.

        The ``ipVersion`` key is injected into each raw response dict so that
        ``PrefixListModel.from_response()`` can populate the ``ip_version`` field.
        """
        try:
            PrefixListModel.validate_config_for_state(self._raw_items_from_params(self.rest_send.params), self.rest_send.params.get("state", ""))

            proposed_identifiers = self._proposed_identifiers()
            if self._should_use_scoped_query(proposed_identifiers):
                return self._query_proposed_existing(proposed_identifiers)

            results = []
            for version in _VERSION_CONFIG:
                results.extend(self._query_all_for_version(version))
            return results
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e

    def create_bulk(self, model_instances: list[PrefixListModel], **kwargs) -> ResponseType:
        """
        Bulk-create prefix lists, split by ip_version.

        Items are grouped into IPv4 and IPv6 subsets, each sent in a separate API
        request. Each 207 response body is checked for per-item failures.
        """
        try:
            grouped = self._split_by_ip_version(model_instances)
            result = {}
            for version, items in grouped.items():
                if items:
                    result[version] = self._bulk_create_for_version(version, items)
            return result
        except Exception as e:
            raise Exception(f"Bulk create failed: {e}") from e

    def delete_bulk(self, model_instances: list[PrefixListModel], **kwargs) -> ResponseType:
        """
        Bulk-delete prefix lists, split by ip_version.

        Names are grouped into IPv4 and IPv6 subsets, each sent in a separate API
        request. Each 207 response body is checked for per-item failures.
        """
        try:
            grouped = self._split_by_ip_version(model_instances)
            result = {}
            for version, models in grouped.items():
                if models:
                    result[version] = self._bulk_delete_for_version(version, [m.api_name for m in models])
            return result
        except Exception as e:
            raise Exception(f"Bulk delete failed: {e}") from e
