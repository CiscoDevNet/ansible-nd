# Copyright: (c) 2026, Slawomir Kaszlikowski

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
L3Out orchestrator for Nexus Dashboard.

This module provides `L3OutOrchestrator`, which implements CRUD operations
for L3Outs (Layer-3 Outs) via the ND Manage L3Outs API. L3Outs provide
connectivity between NDFC-managed fabrics and external networks.

Key features:
- Supports bulk create via {"l3Outs": [...]} envelope
- Fabric-scoped queries via ?fabricName= query parameter
- Attach/detach operations with retry logic for eventual consistency
"""

from __future__ import absolute_import, division, print_function

import time
from typing import Any, ClassVar, Dict, List, Optional, Type

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_l3out import (
    EpManageL3OutAttach,
    EpManageL3OutDelete,
    EpManageL3OutGet,
    EpManageL3OutPost,
    EpManageL3OutPut,
    EpManageL3OutsGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
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
    """

    model_class: ClassVar[Type[NDBaseModel]] = L3OutModel
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = False

    # CRUD endpoints
    create_endpoint: Type[NDEndpointBaseModel] = EpManageL3OutPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageL3OutPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageL3OutDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageL3OutGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageL3OutsGet

    # Bulk endpoints
    create_bulk_endpoint: Optional[Type[NDEndpointBaseModel]] = EpManageL3OutPost

    @property
    def fabric_name(self) -> str:
        """Return fabric name from module params."""
        return self.rest_send.params.get("fabric")

    def create(self, model_instance: L3OutModel, **kwargs) -> ResponseType:
        """
        Create an L3Out.

        The L3Out API expects payloads wrapped in {"l3Outs": [...]} envelope.
        """
        try:
            api_endpoint = self.create_endpoint()
            payload = model_instance.to_payload()
            request_body = {"l3Outs": [payload]}
            return self._request(
                path=api_endpoint.path,
                verb=api_endpoint.verb,
                data=request_body,
                operation_type=OperationType.CREATE,
            )
        except Exception as e:
            raise RuntimeError(
                f"Create failed for {model_instance.get_identifier_value()}: {e}"
            ) from e

    def create_bulk(self, model_instances: List[L3OutModel], **kwargs) -> ResponseType:
        """
        Create multiple L3Outs in a single API call.

        All L3Outs are wrapped in a single {"l3Outs": [...]} envelope.
        """
        try:
            api_endpoint = self.create_bulk_endpoint()
            payloads = [m.to_payload() for m in model_instances]
            request_body = {"l3Outs": payloads}
            return self._request(
                path=api_endpoint.path,
                verb=api_endpoint.verb,
                data=request_body,
                operation_type=OperationType.CREATE,
            )
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

    def update(self, model_instance: L3OutModel, **kwargs) -> ResponseType:
        """
        Update an existing L3Out.
        """
        try:
            api_endpoint = self.update_endpoint()
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self._request(
                path=api_endpoint.path,
                verb=api_endpoint.verb,
                data=model_instance.to_payload(),
                operation_type=OperationType.UPDATE,
            )
        except Exception as e:
            raise RuntimeError(
                f"Update failed for {model_instance.get_identifier_value()}: {e}"
            ) from e

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
            raise RuntimeError(
                f"Delete failed for {model_instance.get_identifier_value()}: {e}"
            ) from e

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
            raise RuntimeError(
                f"Query failed for {model_instance.get_identifier_value()}: {e}"
            ) from e

    def query_all(
        self, model_instance: Optional[NDBaseModel] = None, **kwargs
    ) -> ResponseType:
        """
        Query all L3Outs, filtered by fabric name.

        The fabric name is obtained from module params (self.rest_send.params["fabric"]).
        L3Outs are filtered via the ?fabricName= query parameter.

        Returns:
            List of L3Out dicts from the API response.
        """
        try:
            api_endpoint = self.query_all_endpoint()
            # Add fabric name as query parameter
            path = f"{api_endpoint.path}?fabricName={self.fabric_name}"

            result = self._request(
                path=path,
                verb=api_endpoint.verb,
                not_found_ok=True,
            )

            # Unwrap the l3Outs array from the response envelope
            return result.get("l3Outs", []) or []

        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e

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
                                raise RuntimeError(
                                    f"Failed to attach/detach L3Out "
                                    f"'{item.get('name', 'unknown')}': {item}"
                                )

                    # If we have "not found" errors and more retries, wait and retry
                    if not_found_names and attempt < max_retries:
                        time.sleep(retry_delay)
                        continue

                    # Final attempt or no not-found errors - check for failures
                    if not_found_names:
                        raise RuntimeError(
                            f"L3Out(s) not found after {max_retries} retries: "
                            f"{', '.join(not_found_names)}"
                        )

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
        raise RuntimeError(
            f"Attach operation failed after {max_retries + 1} attempts"
        )
