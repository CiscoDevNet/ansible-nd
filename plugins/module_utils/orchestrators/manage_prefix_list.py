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
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_prefix_list.manage_prefix_list import PrefixListModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

# Per-item ``status`` values in a 207 Multi-Status body that count as a failure. Anything else --
# ``success``, missing, empty, or future progress tokens -- is tolerated so informational rows do
# not surface as spurious errors. Mirrors the maintenance_mode orchestrator's denylist approach.
_FAILURE_STATUSES = frozenset({"failed", "failure", "error"})

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

    Because the controller answers these bulk calls with 207 (which ``ResponseHandler``
    treats as transport success), every bulk response body is inspected per item; any
    entry whose ``status`` is in ``_FAILURE_STATUSES`` raises with the offending prefix
    list names, so partial failures are not silently reported as success.

    ``query_all`` fetches both IPv4 and IPv6 prefix lists and injects the
    ``ipVersion`` key into each raw API response dict so ``PrefixListModel``
    can deserialise them correctly.

    .. note::
       Tenant-scoped prefix lists are not yet fully supported for idempotency. The
       create payload carries a bare ``name`` plus ``tenantName``, but the controller
       returns (and keys delete/update on) the composite ``"<tenantName>~<name>"``.
       Until that round-trip is normalised, use prefix lists in the default tenant.

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

    def _config_for_version(self, version: str) -> dict[str, Any]:
        """Return the endpoint classes and payload keys for the given ip_version, failing fast on unknown values."""
        try:
            return _VERSION_CONFIG[version]
        except KeyError:
            raise ValueError(f"Unsupported ip_version '{version}'. Expected 'ipv4' or 'ipv6'.") from None

    def _endpoint_classes_for_version(self, version: str) -> dict[str, Any]:
        """Backwards-compatible accessor returning the per-version config (endpoint classes + payload keys)."""
        return self._config_for_version(version)

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

    @staticmethod
    def _raise_on_207_failures(result: Any, operation: str) -> None:
        """
        Inspect a 207 Multi-Status bulk response body. If any per-item ``status`` is in
        ``_FAILURE_STATUSES``, raise with the offending prefix list names and messages so partial
        failures are not silently swallowed (the controller returns 207 even when some items fail).
        """
        if not isinstance(result, dict):
            return
        items = result.get("results")
        if not isinstance(items, list) or not items:
            return
        failures: list[str] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status") or "").lower()
            if status not in _FAILURE_STATUSES:
                continue
            name = item.get("name") or "?"
            message = item.get("message") or "unknown error"
            failures.append(f"{name}: {message}")
        if failures:
            raise Exception(f"prefix list {operation} reported per-item failures: {'; '.join(failures)}")

    def _bulk_create_for_version(self, version: str, items: list[PrefixListModel]) -> ResponseType:
        """Send a single bulk-create request for all items of the given ip_version and check the 207 body."""
        config = self._config_for_version(version)
        api_endpoint = config["post"]()
        api_endpoint.fabric_name = self.fabric_name
        payload = {config["list_key"]: [item.to_payload() for item in items]}
        result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
        self._raise_on_207_failures(result, "create")
        return result

    def _bulk_delete_for_version(self, version: str, names: list[str]) -> ResponseType:
        """Send a single bulk-delete request for the given prefix list names and check the 207 body."""
        config = self._config_for_version(version)
        api_endpoint = config["bulk_delete"]()
        api_endpoint.fabric_name = self.fabric_name
        payload = {config["names_key"]: names}
        result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
        self._raise_on_207_failures(result, "delete")
        return result

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
            api_endpoint = config["put"]()
            api_endpoint.fabric_name = self.fabric_name
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=model_instance.to_payload())
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
            api_endpoint = config["get"]()
            api_endpoint.fabric_name = self.fabric_name
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb)
        except Exception as e:
            raise Exception(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self) -> ResponseType:
        """
        Fetch all IPv4 and IPv6 prefix lists and combine them into a single list.

        The ``ipVersion`` key is injected into each raw response dict so that
        ``PrefixListModel.from_response()`` can populate the ``ip_version`` field.
        """
        try:
            results = []
            for version, config in _VERSION_CONFIG.items():
                api_endpoint = config["list"]()
                api_endpoint.fabric_name = self.fabric_name
                raw = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
                for item in raw.get(config["list_key"], []) or []:
                    item["ipVersion"] = version
                    results.append(item)
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
                    result[version] = self._bulk_delete_for_version(version, [m.name for m in models])
            return result
        except Exception as e:
            raise Exception(f"Bulk delete failed: {e}") from e
