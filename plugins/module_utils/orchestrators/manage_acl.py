# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Slawomir Kaszlikowski

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_acl import (
    EpManageAclsBulkDelete,
    EpManageAclsDelete,
    EpManageAclsGet,
    EpManageAclsListGet,
    EpManageAclsPost,
    EpManageAclsPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.acl.acl import AclModel
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

# camelCase wrapper keys used in ACL request/response bodies.
_LIST_KEY = "accessControlLists"
_NAMES_KEY = "accessControlListNames"


class ManageAclOrchestrator(NDBaseOrchestrator[AclModel]):
    """
    Orchestrator for Access Control List (ACL) CRUD operations.

    IPv4 and IPv6 ACLs share a single API namespace
    (``/fabrics/{fabricName}/accessControlLists``) and are distinguished by the
    ``type`` body field, so a single set of endpoints serves both families.

    **Creation and deletion** are performed via bulk API endpoints, which return
    HTTP 207 Multi-Status with a per-item ``results`` array:
    - create: ``POST /fabrics/{fabricName}/accessControlLists``
      with ``{"accessControlLists": [...]}``.
    - bulk delete: ``POST /fabrics/{fabricName}/accessControlListActions/remove``
      with ``{"accessControlListNames": [...]}``.

    The controller answers these bulk calls with 207 Multi-Status even when some
    items fail; ``NdV1Strategy`` inspects the per-item ``results`` array and marks
    the request failed on any failing item, so partial failures surface as errors
    from ``_request`` rather than being silently reported as success.

    The ``fabric_name`` field is read from ``rest_send.params`` (populated by
    ``NDStateMachine`` from the validated module params).
    """

    model_class: ClassVar[type[NDBaseModel]] = AclModel

    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    query_all_page_size: ClassVar[int] = 100
    query_all_max_pages: ClassVar[int] = 10000

    create_endpoint: type[NDEndpointBaseModel] = EpManageAclsPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageAclsPut
    delete_endpoint: type[NDEndpointBaseModel] = EpManageAclsDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageAclsGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageAclsListGet

    create_bulk_endpoint: type[NDEndpointBaseModel] = EpManageAclsPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] = EpManageAclsBulkDelete

    @property
    def fabric_name(self) -> str:
        """
        Return ``fabric_name`` from the module params.

        ACLs are fabric-scoped but not switch-scoped, so the generic
        ``NDBaseOrchestrator`` base is sufficient; it does not expose
        ``fabric_name``, so it is surfaced here from ``rest_send.params``,
        mirroring ``ManagePrefixListOrchestrator.fabric_name``.
        """
        return self.rest_send.params.get("fabric_name")

    def create(self, model_instance: AclModel, **kwargs) -> ResponseType:
        """Create a single ACL via the bulk endpoint."""
        try:
            return self.create_bulk([model_instance])
        except Exception as e:
            raise Exception(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: AclModel, **kwargs) -> ResponseType:
        """Update an existing ACL via the PUT endpoint."""
        try:
            api_endpoint = self.update_endpoint()
            api_endpoint.fabric_name = self.fabric_name
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=model_instance.to_payload())
        except Exception as e:
            raise Exception(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: AclModel, **kwargs) -> ResponseType:
        """Delete a single ACL via the bulk-delete endpoint."""
        try:
            return self.delete_bulk([model_instance])
        except Exception as e:
            raise Exception(f"Delete failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_one(self, model_instance: AclModel, **kwargs) -> ResponseType:
        """Retrieve a single ACL by name."""
        try:
            api_endpoint = self.query_one_endpoint()
            api_endpoint.fabric_name = self.fabric_name
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb)
        except Exception as e:
            raise Exception(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self, model_instance: AclModel = None, **kwargs) -> ResponseType:
        """
        Fetch all ACLs for the fabric and return them as a list of API dicts.

        The list endpoint paginates, so this walks the collection with ``max``/``offset`` until a page
        arrives short (fewer rows than ``query_all_page_size``) or empty. A
        ``seen`` set de-duplicates by ACL name so an offset the controller
        ignores cannot loop forever, and ``query_all_max_pages`` bounds the walk
        as a final safety net.
        """
        try:
            page_size = self.query_all_page_size
            collected: list[dict] = []
            seen: set = set()
            offset = 0
            pages_fetched = 0
            while pages_fetched < self.query_all_max_pages:
                pages_fetched += 1
                api_endpoint = self.query_all_endpoint()
                api_endpoint.fabric_name = self.fabric_name
                api_endpoint.endpoint_params.max = page_size
                api_endpoint.endpoint_params.offset = offset
                raw = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
                page = raw.get(_LIST_KEY, []) or [] if isinstance(raw, dict) else (raw or [])
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

                # A short page is the last page; a full page of only duplicates
                # means the controller is not honoring ``offset`` -- stop either way.
                if len(page) < page_size or new_rows == 0:
                    break
                offset += page_size
            return collected
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e

    def create_bulk(self, model_instances: list[AclModel], **kwargs) -> ResponseType:
        """Bulk-create ACLs in a single request."""
        try:
            api_endpoint = self.create_bulk_endpoint()
            api_endpoint.fabric_name = self.fabric_name
            payload = {_LIST_KEY: [item.to_payload() for item in model_instances]}
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
        except Exception as e:
            raise Exception(f"Bulk create failed: {e}") from e

    def delete_bulk(self, model_instances: list[AclModel], **kwargs) -> ResponseType:
        """Bulk-delete ACLs in a single request."""
        try:
            api_endpoint = self.delete_bulk_endpoint()
            api_endpoint.fabric_name = self.fabric_name
            payload = {_NAMES_KEY: [item.name for item in model_instances]}
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
        except Exception as e:
            raise Exception(f"Bulk delete failed: {e}") from e
