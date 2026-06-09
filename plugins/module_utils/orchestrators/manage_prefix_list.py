# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import ClassVar, Dict, List, Type

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
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


class ManagePrefixListOrchestrator(NDBaseOrchestrator[PrefixListModel]):
    """
    Orchestrator for Prefix List (IPv4 and IPv6) CRUD operations.

    Both IPv4 and IPv6 prefix lists are managed through a single orchestrator.
    The ``ip_version`` field on the model determines which set of API endpoints
    to use for each operation.

    **Creation and deletion** are performed via bulk API endpoints:
    - IPv4 create: ``POST /fabrics/{fabricName}/ipv4PrefixLists``
      with ``{"ipv4PrefixLists": [...]}``.
    - IPv6 create: ``POST /fabrics/{fabricName}/ipv6PrefixLists``
      with ``{"ipv6PrefixLists": [...]}``.
    - IPv4 bulk delete: ``POST /fabrics/{fabricName}/ipv4PrefixListActions/remove``
      with ``{"ipv4PrefixListNames": [...]}``.
    - IPv6 bulk delete: ``POST /fabrics/{fabricName}/ipv6PrefixListActions/remove``
      with ``{"ipv6PrefixListNames": [...]}``.

    ``query_all`` fetches both IPv4 and IPv6 prefix lists and injects the
    ``ipVersion`` key into each raw API response dict so ``PrefixListModel``
    can deserialise them correctly.

    The ``fabric_name`` field must be supplied at construction time:

    ```python
    orchestrator = ManagePrefixListOrchestrator(
        rest_send=rest_send,
        fabric_name="my-fabric",
    )
    ```
    """

    model_class: ClassVar[Type[NDBaseModel]] = PrefixListModel

    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True

    # Fabric context
    fabric_name: str = Field(description="Name of the fabric that owns these prefix lists.")

    # Required stubs -- the orchestrator overrides every operation, so these
    # just need to satisfy NDBaseOrchestrator's required fields.
    create_endpoint: Type[NDEndpointBaseModel] = EpManageIpv4PrefixListsPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageIpv4PrefixListsPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageIpv4PrefixListsDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageIpv4PrefixListsGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageIpv4PrefixListsListGet

    create_bulk_endpoint: Type[NDEndpointBaseModel] = EpManageIpv4PrefixListsPost
    delete_bulk_endpoint: Type[NDEndpointBaseModel] = EpManageIpv4PrefixListsBulkDelete

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _endpoint_classes_for_version(self, version: str) -> Dict[str, Type[NDEndpointBaseModel]]:
        """Return the correct endpoint class mapping for the given ip_version."""
        if version == "ipv4":
            return {
                "get": EpManageIpv4PrefixListsGet,
                "list": EpManageIpv4PrefixListsListGet,
                "post": EpManageIpv4PrefixListsPost,
                "put": EpManageIpv4PrefixListsPut,
                "delete": EpManageIpv4PrefixListsDelete,
                "bulk_delete": EpManageIpv4PrefixListsBulkDelete,
            }
        else:
            return {
                "get": EpManageIpv6PrefixListsGet,
                "list": EpManageIpv6PrefixListsListGet,
                "post": EpManageIpv6PrefixListsPost,
                "put": EpManageIpv6PrefixListsPut,
                "delete": EpManageIpv6PrefixListsDelete,
                "bulk_delete": EpManageIpv6PrefixListsBulkDelete,
            }

    def _bulk_create_for_version(self, version: str, items: List[PrefixListModel]) -> ResponseType:
        """Send a single bulk-create request for all items of the given ip_version."""
        eps = self._endpoint_classes_for_version(version)
        api_endpoint = eps["post"]()
        api_endpoint.fabric_name = self.fabric_name
        list_key = "ipv4PrefixLists" if version == "ipv4" else "ipv6PrefixLists"
        payload = {list_key: [item.to_payload() for item in items]}
        return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)

    def _bulk_delete_for_version(self, version: str, names: List[str]) -> ResponseType:
        """Send a single bulk-delete request for the given prefix list names."""
        eps = self._endpoint_classes_for_version(version)
        api_endpoint = eps["bulk_delete"]()
        api_endpoint.fabric_name = self.fabric_name
        names_key = "ipv4PrefixListNames" if version == "ipv4" else "ipv6PrefixListNames"
        payload = {names_key: names}
        return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)

    # -------------------------------------------------------------------------
    # Query helpers
    # -------------------------------------------------------------------------

    def query_all(self) -> ResponseType:
        """
        Fetch all IPv4 and IPv6 prefix lists and combine them into a single list.

        The ``ipVersion`` key is injected into each raw response dict so that
        ``PrefixListModel.from_response()`` can populate the ``ip_version`` field.
        """
        try:
            results = []
            for version in ("ipv4", "ipv6"):
                eps = self._endpoint_classes_for_version(version)
                api_endpoint = eps["list"]()
                api_endpoint.fabric_name = self.fabric_name
                raw = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
                list_key = "ipv4PrefixLists" if version == "ipv4" else "ipv6PrefixLists"
                for item in raw.get(list_key, []) or []:
                    item["ipVersion"] = version
                    results.append(item)
            return results
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e

    def query_one(self, model_instance: PrefixListModel, **kwargs) -> ResponseType:
        """Retrieve a single prefix list by name and ip_version."""
        try:
            version = str(model_instance.ip_version)
            eps = self._endpoint_classes_for_version(version)
            api_endpoint = eps["get"]()
            api_endpoint.fabric_name = self.fabric_name
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb)
        except Exception as e:
            raise Exception(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    # -------------------------------------------------------------------------
    # Write operations -- single item (delegate to bulk)
    # -------------------------------------------------------------------------

    def create(self, model_instance: PrefixListModel, **kwargs) -> ResponseType:
        """Create a single prefix list via the bulk endpoint."""
        try:
            return self.create_bulk([model_instance])
        except Exception as e:
            raise Exception(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: PrefixListModel, **kwargs) -> ResponseType:
        """Update an existing prefix list via the PUT endpoint."""
        try:
            version = str(model_instance.ip_version)
            eps = self._endpoint_classes_for_version(version)
            api_endpoint = eps["put"]()
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

    # -------------------------------------------------------------------------
    # Write operations -- bulk
    # -------------------------------------------------------------------------

    def create_bulk(self, model_instances: List[PrefixListModel], **kwargs) -> ResponseType:
        """
        Bulk-create prefix lists, split by ip_version.

        Items are grouped into IPv4 and IPv6 subsets, each sent in a
        separate API request.
        """
        try:
            ipv4_items = [m for m in model_instances if str(m.ip_version) == "ipv4"]
            ipv6_items = [m for m in model_instances if str(m.ip_version) == "ipv6"]
            result = {}
            if ipv4_items:
                result["ipv4"] = self._bulk_create_for_version("ipv4", ipv4_items)
            if ipv6_items:
                result["ipv6"] = self._bulk_create_for_version("ipv6", ipv6_items)
            return result
        except Exception as e:
            raise Exception(f"Bulk create failed: {e}") from e

    def delete_bulk(self, model_instances: List[PrefixListModel], **kwargs) -> ResponseType:
        """
        Bulk-delete prefix lists, split by ip_version.

        Names are grouped into IPv4 and IPv6 subsets, each sent in a
        separate API request.
        """
        try:
            ipv4_names = [m.name for m in model_instances if str(m.ip_version) == "ipv4"]
            ipv6_names = [m.name for m in model_instances if str(m.ip_version) == "ipv6"]
            result = {}
            if ipv4_names:
                result["ipv4"] = self._bulk_delete_for_version("ipv4", ipv4_names)
            if ipv6_names:
                result["ipv6"] = self._bulk_delete_for_version("ipv6", ipv6_names)
            return result
        except Exception as e:
            raise Exception(f"Bulk delete failed: {e}") from e
