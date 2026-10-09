# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
L3Out orchestrator for Nexus Dashboard.

This module provides `L3OutOrchestrator`, which implements CRUD operations
for L3Outs (Layer-3 Outs) via the ND Manage L3Outs API. L3Outs provide
connectivity between ND-managed fabrics and external networks.

Key features:
- Supports bulk create via {"l3Outs": [...]} envelope
- Fabric-scoped queries via ?fabricName= query parameter
- Attach/detach operations with retry logic for eventual consistency
"""

from __future__ import absolute_import, division, print_function

import time
from ipaddress import ip_address
from typing import Any, ClassVar, Dict, List, Optional, Type

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_l3out import (
    EpManageL3OutAttach,
    EpManageL3OutBulkDelete,
    EpManageL3OutDelete,
    EpManageL3OutGet,
    EpManageL3OutPost,
    EpManageL3OutPut,
    EpManageL3OutsGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import (
    FabricContext,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.l3out.l3out import (
    L3OutModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    NDBaseOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import (
    ResponseType,
)

_LIST_KEY = "l3Outs"


class L3OutOrchestrator(NDBaseOrchestrator[L3OutModel]):
    """
    Orchestrator for L3Out operations on Nexus Dashboard.

    L3Outs provide connectivity between ND-managed fabrics and external networks.
    They support multiple connectivity types (routed, subInterface, svi) and
    routing protocols (BGP, static).

    This orchestrator:
    - Overrides create() to wrap payloads in {"l3Outs": [...]} envelope
    - Overrides query_all() to filter by fabric via query parameter
    - Provides attach_l3outs() for deploy/undeploy operations
    - Resolves switch management IPs to serial numbers via FabricContext
    """

    model_class: ClassVar[Type[NDBaseModel]] = L3OutModel
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True

    query_all_page_size: ClassVar[int] = 100
    query_all_max_pages: ClassVar[int] = 100

    # CRUD endpoints
    create_endpoint: Type[NDEndpointBaseModel] = EpManageL3OutPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageL3OutPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageL3OutDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageL3OutGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageL3OutsGet

    # Bulk endpoints
    create_bulk_endpoint: Optional[Type[NDEndpointBaseModel]] = EpManageL3OutPost
    delete_bulk_endpoint: Optional[Type[NDEndpointBaseModel]] = EpManageL3OutBulkDelete

    # Private: fabric context cache for switch_id resolution
    _fabric_contexts: Dict[str, FabricContext] = None

    def model_post_init(self, __context) -> None:
        """Initialize mutable private attributes after model construction."""
        self._fabric_contexts: Dict[str, FabricContext] = {}

    @property
    def fabric_name(self) -> str:
        """Return fabric name from module params."""
        return self.rest_send.params.get("fabric_name")

    # -------------------------------------------------------------------------
    # Switch ID Resolution
    # -------------------------------------------------------------------------

    def _get_fabric_context(self, fabric_name: str) -> FabricContext:
        """
        Return a cached FabricContext for the given fabric.

        FabricContext lazily loads switch maps on first access, so creating
        one is cheap until resolution is actually needed.
        """
        if fabric_name not in self._fabric_contexts:
            self._fabric_contexts[fabric_name] = FabricContext(rest_send=self.rest_send, fabric_name=fabric_name)
        return self._fabric_contexts[fabric_name]

    @staticmethod
    def _is_ip_address(value: str) -> bool:
        """Return True if value is a valid IPv4 or IPv6 address."""
        try:
            ip_address(value)
            return True
        except ValueError:
            return False

    def _resolve_switch_id(self, fabric_name: str, switch_id_or_ip: str) -> str:
        """
        Resolve a switch_id value to a serial number.

        If the value is a valid IP address, resolve it via FabricContext.
        Otherwise, return the value as-is (assumed to be a serial number).

        Args:
            fabric_name: Fabric to resolve against.
            switch_id_or_ip: Serial number or management IP address.

        Returns:
            Switch serial number (switchId).

        Raises:
            RuntimeError: If the IP cannot be resolved in the given fabric.
        """
        if self._is_ip_address(switch_id_or_ip):
            ctx = self._get_fabric_context(fabric_name)
            return ctx.get_switch_id(switch_id_or_ip)
        return switch_id_or_ip

    def _resolve_links(self, model_instance: L3OutModel) -> None:
        """
        Resolve switch_id values in all links from IP addresses to serial numbers.

        Mutates the model in-place. switch1_details resolves against fabric1_name,
        switch2_details resolves against fabric2_name.

        If connectivity_details or links are not present, this is a no-op.
        """
        conn = model_instance.connectivity_details
        if not conn or not conn.links:
            return

        fabric1 = model_instance.fabric1_name or self.fabric_name
        fabric2 = model_instance.fabric2_name or self.fabric_name

        for link in conn.links:
            if link.switch1_details and self._is_ip_address(link.switch1_details.switch_id):
                link.switch1_details.switch_id = self._resolve_switch_id(fabric1, link.switch1_details.switch_id)
            if link.switch2_details and self._is_ip_address(link.switch2_details.switch_id):
                link.switch2_details.switch_id = self._resolve_switch_id(fabric2, link.switch2_details.switch_id)

    @staticmethod
    def _validate_bulk_response(result: ResponseType, operation: str) -> None:
        """
        Validate a GenericBulkResponse (HTTP 207 multi-status) for per-item failures.

        The ND L3Out API can return HTTP 200/207 with individual items marked as
        failed in the response body. This method raises RuntimeError if any item
        has status "failed" or a statusCode >= 400.

        Args:
            result: API response dict (GenericBulkResponse format).
            operation: Human-readable operation name for error messages.
        """
        if not result or not isinstance(result, dict):
            return

        items = result.get("results", result.get("DATA", {}).get("results", []))
        if not items or not isinstance(items, list):
            return

        failed_items = []
        for item in items:
            if not isinstance(item, dict):
                continue
            status = item.get("status", "")
            status_code = item.get("statusCode", 200)
            if status == "failed" or (isinstance(status_code, int) and status_code >= 400):
                name = item.get("name", item.get("l3OutName", "unknown"))
                message = item.get("message", "No details provided")
                failed_items.append(f"'{name}': {message}")

        if failed_items:
            raise RuntimeError(f"{operation} partially failed. " f"Failed items: {'; '.join(failed_items)}")

    def create(self, model_instance: L3OutModel, **kwargs) -> ResponseType:
        """
        Create an L3Out.

        The L3Out API expects payloads wrapped in {"l3Outs": [...]} envelope.
        Resolves any management IP addresses in switch_id fields before sending.
        """
        try:
            self._resolve_links(model_instance)
            api_endpoint = self.create_endpoint()
            payload = model_instance.to_payload()
            request_body = {"l3Outs": [payload]}
            result = self._request(
                path=api_endpoint.path,
                verb=api_endpoint.verb,
                data=request_body,
                operation_type=OperationType.CREATE,
            )
            self._validate_bulk_response(result, "Create L3Out")
            return result
        except Exception as e:
            raise RuntimeError(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def create_bulk(self, model_instances: List[L3OutModel], **kwargs) -> ResponseType:
        """
        Create multiple L3Outs in a single API call.

        All L3Outs are wrapped in a single {"l3Outs": [...]} envelope.
        Resolves any management IP addresses in switch_id fields before sending.
        """
        try:
            for model_instance in model_instances:
                self._resolve_links(model_instance)
            api_endpoint = self.create_bulk_endpoint()
            payloads = [m.to_payload() for m in model_instances]
            request_body = {"l3Outs": payloads}
            result = self._request(
                path=api_endpoint.path,
                verb=api_endpoint.verb,
                data=request_body,
                operation_type=OperationType.CREATE,
            )
            self._validate_bulk_response(result, "Bulk create L3Outs")
            return result
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

    def update(self, model_instance: L3OutModel, **kwargs) -> ResponseType:
        """
        Update an existing L3Out.

        Resolves any management IP addresses in switch_id fields before sending.
        """
        try:
            self._resolve_links(model_instance)
            api_endpoint = self.update_endpoint()
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self._request(
                path=api_endpoint.path,
                verb=api_endpoint.verb,
                data=model_instance.to_payload(),
                operation_type=OperationType.UPDATE,
            )
        except Exception as e:
            raise RuntimeError(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: L3OutModel, **kwargs) -> ResponseType:
        """
        Delete an L3Out.
        """
        try:
            api_endpoint = self.delete_endpoint()
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self._request(
                path=api_endpoint.path,
                verb=api_endpoint.verb,
                operation_type=OperationType.DELETE,
            )
        except Exception as e:
            raise RuntimeError(f"Delete failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete_bulk(self, model_instances: List[L3OutModel], **kwargs) -> ResponseType:
        """
        Delete multiple L3Outs in a single API call.

        Uses POST /l3OutActions/remove with {"l3OutNames": [...]}.
        """
        try:
            api_endpoint = self.delete_bulk_endpoint()
            l3out_names = [m.get_identifier_value() for m in model_instances]
            request_body = {"l3OutNames": l3out_names}
            result = self._request(
                path=api_endpoint.path,
                verb=api_endpoint.verb,
                data=request_body,
                operation_type=OperationType.DELETE,
            )
            self._validate_bulk_response(result, "Bulk delete L3Outs")
            return result
        except Exception as e:
            raise RuntimeError(f"Bulk delete failed: {e}") from e

    def query_one(self, model_instance: L3OutModel, **kwargs) -> ResponseType:
        """
        Query a single L3Out by name.
        """
        try:
            api_endpoint = self.query_one_endpoint()
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self._request(
                path=api_endpoint.path,
                verb=api_endpoint.verb,
            )
        except Exception as e:
            raise RuntimeError(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self, model_instance: Optional[NDBaseModel] = None, **kwargs) -> ResponseType:
        """
        Query L3Outs filtered by fabric name.

        The fabric name is obtained from module parameters and set on the list
        endpoint, which renders it as the ``fabricName`` query parameter.

        Gathered state retrieves the complete collection through bounded
        ``max``/``offset`` pagination. Management states retain their existing
        single-request collection query.

        ``model_instance`` and ``kwargs`` are accepted for compatibility with the
        common orchestrator interface and are not used by this collection query.

        Returns:
            A list of L3Out dictionaries returned by Nexus Dashboard.

        Raises:
            RuntimeError: If the controller query or gathered pagination fails.
        """
        try:
            if self.rest_send.params.get("state") == "gathered":
                return self._query_all_for_gathered()

            return self._query_all_for_management_states()

        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e

    def _query_all_for_management_states(self) -> ResponseType:
        """
        Query L3Outs for merged, replaced, and deleted states.

        This preserves the established management-state workflow: one collection
        request scoped by ``fabricName``, without adding explicit ``max`` or
        ``offset`` parameters.

        Returns:
            The ``l3Outs`` list unwrapped from the controller response. An empty
            list is returned when the response contains no L3Outs.
        """
        api_endpoint = self.query_all_endpoint()
        api_endpoint.fabric_name = self.fabric_name

        result = self._request(
            path=api_endpoint.path,
            verb=api_endpoint.verb,
            not_found_ok=True,
        )

        return result.get(_LIST_KEY, []) or []

    def _query_all_for_gathered(self) -> list[dict[str, Any]]:
        """
        Query the complete L3Out collection for gathered state.

        Requests consecutive pages using ``max`` and ``offset``. Pagination
        continues according to controller-provided ``meta.counts.total`` or
        ``meta.counts.remaining`` values. When usable metadata is unavailable, a
        full page indicates that another page may exist.

        Results are deduplicated by L3Out name, which is the model's identifier.
        Duplicate-only pages are treated as a pagination failure when the
        controller reports additional results. A maximum-page limit prevents an
        inconsistent controller response from causing an unbounded loop.

        Returns:
            A list containing every unique L3Out associated with the configured
            fabric.

        Raises:
            RuntimeError: If the response has an invalid shape, pagination does
                not advance, or the configured page limit is reached.
        """
        page_size = self.query_all_page_size
        collected: list[dict[str, Any]] = []
        seen_names: set[str] = set()
        offset = 0
        pages_fetched = 0

        while pages_fetched < self.query_all_max_pages:
            pages_fetched += 1

            api_endpoint = self.query_all_endpoint()
            api_endpoint.fabric_name = self.fabric_name
            api_endpoint.endpoint_params.max = page_size
            api_endpoint.endpoint_params.offset = offset

            result = self._request(
                path=api_endpoint.path,
                verb=api_endpoint.verb,
                not_found_ok=True,
            )

            if result is None:
                page = []
            elif isinstance(result, dict):
                raw_page = result.get(_LIST_KEY)
                page = [] if raw_page is None else raw_page
            else:
                raise RuntimeError(f"The List L3Outs endpoint returned an unexpected response type: {type(result).__name__}.")

            if not isinstance(page, list):
                raise RuntimeError(f"The List L3Outs endpoint returned an invalid '{_LIST_KEY}' value; expected a list.")

            has_next_page = self._has_next_page(
                result=result,
                page_count=len(page),
                offset=offset,
                page_size=page_size,
            )

            if not page:
                if has_next_page:
                    raise RuntimeError("The List L3Outs endpoint returned an empty page while the controller reported additional results.")
                break

            new_rows = 0

            for row in page:
                if not isinstance(row, dict):
                    raise RuntimeError("The List L3Outs endpoint returned a non-object entry.")

                name = row.get("name")
                if not isinstance(name, str) or not name:
                    raise RuntimeError("The List L3Outs endpoint returned an entry without a valid L3Out name.")

                if name in seen_names:
                    continue

                seen_names.add(name)
                collected.append(row)
                new_rows += 1

            if not has_next_page:
                break

            if new_rows == 0:
                raise RuntimeError("L3Out pagination did not advance while the controller reported additional results.")

            offset += len(page)

        else:
            raise RuntimeError(
                f"L3Out pagination reached the safety limit of "
                f"{self.query_all_max_pages} pages after collecting "
                f"{len(collected)} L3Outs. Results may be incomplete."
            )

        return collected

    @staticmethod
    def _has_next_page(result: object, page_count: int, offset: int, page_size: int) -> bool:
        """
        Determine whether another L3Out collection page must be requested.

        Controller metadata takes precedence over page-length inference. ``total``
        is evaluated first because it can be compared with the current offset and
        returned record count. ``remaining`` is used when ``total`` is absent or
        invalid. When neither value is usable, a page containing exactly
        ``page_size`` records indicates that another request is required.

        Args:
            result: Raw response returned by the List L3Outs endpoint.
            page_count: Number of L3Out records in the current page.
            offset: Offset used to request the current page.
            page_size: Maximum number of records requested per page.

        Returns:
            ``True`` when another page should be requested; otherwise ``False``.
        """

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

        return page_count > 0 and page_count == page_size

    def attach_l3outs(
        self,
        attachments: List[Dict[str, Any]],
        max_retries: int = 3,
        retry_delay: int = 2,
    ) -> Dict:
        """
        Attach or detach L3Outs.

        Due to ND eventual consistency, newly created L3Outs may not be
        immediately available for attachment. This method retries with a
        delay if a 404 "not found" error is encountered.

        Args:
            attachments: List of dicts with 'name' and 'attach' keys.
                        Example: [{"name": "L3Out1", "attach": True}]
            max_retries: Maximum number of retry attempts for 404 errors.
            retry_delay: Seconds to wait between retries.

        Returns:
            API response dict.
        """
        if not attachments:
            return {}

        api_endpoint = EpManageL3OutAttach()
        data = {"attachments": attachments}

        for attempt in range(max_retries + 1):
            try:
                result = self._request(
                    path=api_endpoint.path,
                    verb=api_endpoint.verb,
                    data=data,
                    operation_type=OperationType.UPDATE,
                )

                # Check for failures in 207 Multi-Status response
                if result:
                    items = result.get("results", result.get("attachments", []))
                    if isinstance(result, list):
                        items = result

                    not_found_names = []
                    for item in items:
                        if isinstance(item, dict):
                            status = item.get("status", "")
                            message = item.get("message", "")
                            status_code = item.get("statusCode", 200)

                            # Check for "not found" failures that might be timing-related
                            if status == "failed" and "not found" in message.lower():
                                not_found_names.append(item.get("name", "unknown"))
                            elif status_code >= 400:
                                raise RuntimeError(f"Failed to attach/detach L3Out " f"'{item.get('name', 'unknown')}': {item}")

                    # If we have "not found" errors and more retries, wait and retry
                    if not_found_names and attempt < max_retries:
                        time.sleep(retry_delay)
                        continue

                    # Final attempt or no not-found errors - check for failures
                    if not_found_names:
                        raise RuntimeError(f"L3Out(s) not found after {max_retries} retries: " f"{', '.join(not_found_names)}")

                return result or {}

            except Exception as e:
                error_msg = str(e)
                # Retry on 404 errors (L3Out not found due to eventual consistency)
                if "404" in error_msg or "not found" in error_msg.lower():
                    if attempt < max_retries:
                        time.sleep(retry_delay)
                        continue
                raise

        # Should not reach here, but just in case
        raise RuntimeError(f"Attach operation failed after {max_retries + 1} attempts")
