# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Community Lists endpoint models.

This module contains endpoint definitions for community list operations
in the ND Manage API.

## Endpoints

- `EpManageCommunityListsGet` - Get a specific community list by name
  (GET /api/v1/manage/fabrics/{fabricName}/communityLists/{communityListName})
- `EpManageCommunityListsListGet` - List all community lists for a fabric
  (GET /api/v1/manage/fabrics/{fabricName}/communityLists)
- `EpManageCommunityListsPost` - Bulk create community lists
  (POST /api/v1/manage/fabrics/{fabricName}/communityLists)
- `EpManageCommunityListsPut` - Update a specific community list
  (PUT /api/v1/manage/fabrics/{fabricName}/communityLists/{communityListName})
- `EpManageCommunityListsDelete` - Delete a specific community list
  (DELETE /api/v1/manage/fabrics/{fabricName}/communityLists/{communityListName})
- `EpManageCommunityListsBulkDelete` - Bulk delete community lists via action endpoint
  (POST /api/v1/manage/fabrics/{fabricName}/communityListActions/remove)
"""

from __future__ import annotations

from typing import ClassVar, Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ConfigDict, Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import ClusterNameMixin, CommunityListNameMixin, FabricNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import CompositeQueryParams, EndpointQueryParams, LuceneQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class CommunityListsEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """Query parameters common to community list endpoints."""

    model_config = ConfigDict(extra="forbid")


class _EpManageCommunityListsBase(FabricNameMixin, CommunityListNameMixin, NDEndpointBaseModel):
    """
    Base class for ND Manage Community Lists endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics/{fabricName}/communityLists endpoint.

    Subclasses may override:
    - ``_require_community_list_name``: set to ``False`` for collection-level
      endpoints (list, bulk create) that do not include the list name in the path.
    """

    _require_community_list_name: ClassVar[bool] = True

    endpoint_params: CommunityListsEndpointParams = Field(
        default_factory=CommunityListsEndpointParams,
        description="Endpoint-specific query parameters",
    )

    def set_identifiers(self, identifier: IdentifierKey = None):
        """Assign the community list name from the model identifier."""
        self.community_list_name = identifier

    @property
    def path(self) -> str:
        """
        Build the endpoint path for community list operations.

        Raises:
            ValueError: if ``fabric_name`` is not set.
            ValueError: if ``community_list_name`` is required but not set.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        if self._require_community_list_name and self.community_list_name is None:
            raise ValueError(f"{type(self).__name__}.path: community_list_name must be set before accessing path.")
        segments = ["fabrics", quote(self.fabric_name, safe=""), "communityLists"]
        if self._require_community_list_name and self.community_list_name is not None:
            segments.append(quote(self.community_list_name, safe=""))
        base_path = BasePath.path(*segments)
        query_params = CompositeQueryParams().add(self.endpoint_params)
        lucene_params = getattr(self, "lucene_params", None)
        if lucene_params is not None:
            query_params.add(lucene_params)
        query_string = query_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path


class EpManageCommunityListsGet(_EpManageCommunityListsBase):
    """
    ND Manage Community Lists GET Endpoint.

    Retrieves details for a specific community list by name.

    Path: GET /api/v1/manage/fabrics/{fabricName}/communityLists/{communityListName}
    """

    class_name: Literal["EpManageCommunityListsGet"] = Field(
        default="EpManageCommunityListsGet",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpManageCommunityListsListGet(_EpManageCommunityListsBase):
    """
    ND Manage Community Lists List GET Endpoint.

    Retrieves all community lists for a given fabric.

    Path: GET /api/v1/manage/fabrics/{fabricName}/communityLists
    """

    _require_community_list_name: ClassVar[bool] = False

    class_name: Literal["EpManageCommunityListsListGet"] = Field(
        default="EpManageCommunityListsListGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    lucene_params: LuceneQueryParams = Field(default_factory=LuceneQueryParams, description="Lucene-style query parameters for filtering")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpManageCommunityListsPost(_EpManageCommunityListsBase):
    """
    ND Manage Community Lists POST Endpoint.

    Bulk-creates one or more community lists.
    Request body: ``{"communityLists": [...]}``

    Path: POST /api/v1/manage/fabrics/{fabricName}/communityLists
    """

    _require_community_list_name: ClassVar[bool] = False

    class_name: Literal["EpManageCommunityListsPost"] = Field(
        default="EpManageCommunityListsPost",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class EpManageCommunityListsPut(_EpManageCommunityListsBase):
    """
    ND Manage Community Lists PUT Endpoint.

    Updates an existing community list.

    Path: PUT /api/v1/manage/fabrics/{fabricName}/communityLists/{communityListName}
    """

    class_name: Literal["EpManageCommunityListsPut"] = Field(
        default="EpManageCommunityListsPut",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.PUT


class EpManageCommunityListsDelete(_EpManageCommunityListsBase):
    """
    ND Manage Community Lists DELETE Endpoint.

    Deletes a specific community list by name.

    Path: DELETE /api/v1/manage/fabrics/{fabricName}/communityLists/{communityListName}
    """

    class_name: Literal["EpManageCommunityListsDelete"] = Field(
        default="EpManageCommunityListsDelete",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.DELETE


class _EpManageCommunityListsBulkDeleteBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for the community list bulk-delete action endpoint.

    Path: /api/v1/manage/fabrics/{fabricName}/communityListActions/remove
    """

    endpoint_params: CommunityListsEndpointParams = Field(
        default_factory=CommunityListsEndpointParams,
        description="Endpoint-specific query parameters",
    )

    def set_identifiers(self, identifier: IdentifierKey = None):
        """No-op: bulk delete endpoint has no per-resource identifier in the path."""

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        base_path = BasePath.path("fabrics", quote(self.fabric_name, safe=""), "communityListActions", "remove")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path


class EpManageCommunityListsBulkDelete(_EpManageCommunityListsBulkDeleteBase):
    """
    ND Manage Community Lists Bulk Delete Endpoint.

    Bulk-deletes community lists by name.
    Request body: ``{"communityListNames": [...]}``

    Path: POST /api/v1/manage/fabrics/{fabricName}/communityListActions/remove
    """

    class_name: Literal["EpManageCommunityListsBulkDelete"] = Field(
        default="EpManageCommunityListsBulkDelete",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
