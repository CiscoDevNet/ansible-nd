# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
ResourcesResponseModel - Response model for list-all-resources endpoint.

 COMPOSITE model: contains list[ResourceGetUpdatedModel].

Endpoint: GET /fabrics/{fabricName}/resources
"""

from __future__ import annotations

from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_request_model import (
    FabricScope,
    DeviceScope,
    DeviceInterfaceScope,
    LinkScope,
    DevicePairScope,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field


class ResourceManagerResponse(NDNestedModel):  # noqa: F811
    """
    Individual resource allocation response item for POST /fabrics/{fabricName}/resources.

    Composite: scope_details field is a scope-model union discriminated
    by scopeType.
    """

    identifiers: ClassVar[list[str]] = []

    pool_name: str | None = Field(
        default=None,
        alias="poolName",
        description="Pool under which the resource is allocated",
    )
    scope_details: FabricScope | DeviceScope | DeviceInterfaceScope | LinkScope | DevicePairScope | None = Field(
        default=None,
        alias="scopeDetails",
        description="Scope details; discriminated by scopeType",
    )
    is_pre_allocated: bool | None = Field(
        default=False,
        alias="isPreAllocated",
        description="true if the resource is pre-allocated",
    )
    entity_name: str | None = Field(
        default=None,
        alias="entityName",
        description="Name by which the resource is allocated",
    )
    resource_value: str | None = Field(
        default=None,
        alias="resourceValue",
        description="The allocated resource value",
    )
    resource_id: int | None = Field(
        default=None,
        alias="resourceId",
        description="Unique identifier of the allocated resource",
    )
    vrf_name: str | None = Field(
        default="default",
        alias="vrfName",
        description="VRF name for the resource",
    )
    create_timestamp: str | None = Field(
        default=None,
        alias="createTimestamp",
        description="Timestamp when the resource was allocated",
    )
    status: str | None = Field(
        default=None,
        description="Status of the resource create request",
    )
    message: str | None = Field(
        default=None,
        description="Additional details describing a resource create failure",
    )


class ResourcesManagerBatchResponse(NDBaseModel):
    """
    Response body for POST /fabrics/{fabricName}/resources (batch create).

    Composite: contains list[ResourceManagerResponse].
    """

    identifiers: ClassVar[list[str]] = []

    resources: list[ResourceManagerResponse] = Field(default_factory=list, description="Resource data entries")
    meta: dict[str, Any] | None = Field(default=None, description="Response metadata")

    @classmethod
    def from_response(cls, response: Any) -> "ResourcesManagerBatchResponse":
        """Create instance from a raw API response dict.

        Accepts the raw dict returned by nd.request() for the batch POST
        endpoint.  If the response already has a ``resources`` key it is
        validated directly; a bare list is wrapped automatically.
        """
        if isinstance(response, list):
            return cls.model_validate({"resources": response})
        if isinstance(response, dict):
            return cls.model_validate(response)
        return cls(resources=[])
