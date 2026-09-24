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
from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import (
    GatheredLuceneSpec,
    build_lucene_expressions,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.acl.acl import AclModel
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

# camelCase wrapper keys used in ACL request/response bodies.
_LIST_KEY = "accessControlLists"
_NAMES_KEY = "accessControlListNames"

_GATHERED_QUERY_MAX_EXPRESSIONS = 3


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

    supports_gathered_server_filtering: ClassVar[bool] = True
    gathered_lucene_spec: ClassVar[GatheredLuceneSpec] = GatheredLuceneSpec(
        base_terms=(),
        field_map={
            ("name",): "name",
        },
    )

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

    def query_all(
        self,
        model_instance: AclModel | None = None,
        gathered_filters=None,
        **kwargs,
    ) -> ResponseType:
        """
        Query ACLs from the fabric.

        Management states retain the existing unfiltered paginated query.
        Gathered state may use safe server-side name filters before the complete
        filter is applied locally by NDStateMachine.
        """
        try:
            if gathered_filters is not None:
                return self._query_all_for_gathered(gathered_filters)

            return self._query_all_for_management_states()
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e

    def _query_all_for_management_states(
        self,
        expression: str | None = None,
    ) -> list[dict]:
        """
        Fetch all ACLs for the fabric and return them as a list of API dicts.

        The list endpoint paginates, so this walks the collection with ``max``/``offset`` until a page
        arrives short (fewer rows than ``query_all_page_size``) or empty. A
        ``seen`` set de-duplicates by ACL name so an offset the controller
        ignores cannot loop forever, and ``query_all_max_pages`` bounds the walk
        as a final safety net.
        """
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
            if expression is not None:
                api_endpoint.endpoint_params.filter = expression
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

            if not self._has_next_page(raw, len(page), offset, page_size):
                break
            if new_rows == 0:
                raise RuntimeError("Pagination did not advance while the controller reported additional ACLs.")
            offset += len(page)
        else:
            raise RuntimeError(f"Pagination limit reached ({self.query_all_max_pages} pages, " f"{len(collected)} ACLs collected). Results may be incomplete.")
        return collected

    @staticmethod
    def _has_next_page(result: object, page_count: int, offset: int, page_size: int) -> bool:
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
        return page_count == page_size

    def _query_all_for_gathered(
        self,
        gathered_filters: list[dict] | None = None,
    ) -> list[dict]:
        """
        Fetch candidate ACLs for gathered-state filtering.

        Only safe, unquoted names are sent to the controller. Type-only filters,
        unsafe names, and unfiltered gathered requests use a complete collection
        scan. NDStateMachine always applies the full exact filter locally.
        """
        filter_items = gathered_filters or [{}]

        # Multiple filter items have OR semantics. If any item has no name, that
        # item can potentially match ACLs anywhere in the collection. Restricting
        # the server query to names from the other items would lose valid results.
        if any(not filter_item.get("name") for filter_item in filter_items):
            return self._query_all_for_management_states()

        expressions = build_lucene_expressions(
            filter_items,
            spec=self.gathered_lucene_spec,
        )

        # The ACL endpoint returns no results for quoted filter values. Names
        # containing '-' or '~' are quoted by the generic safe formatter, so use a
        # complete scan and exact local filtering for those names.
        if not expressions or any('"' in expression for expression in expressions):
            return self._query_all_for_management_states()

        if len(expressions) > _GATHERED_QUERY_MAX_EXPRESSIONS:
            return self._query_all_for_management_states()

        collected: list[dict] = []
        seen: set[str] = set()

        # One request per expression provides OR semantics without relying on the
        # endpoint's unsupported Lucene OR operator.
        for expression in expressions:
            for row in self._query_all_for_management_states(expression):
                name = row.get("name") if isinstance(row, dict) else None

                if name is not None:
                    if name in seen:
                        continue
                    seen.add(name)

                collected.append(row)

        return collected

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
