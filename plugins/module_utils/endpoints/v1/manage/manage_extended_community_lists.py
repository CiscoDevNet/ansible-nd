# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Extended Community Lists endpoint models.

This module contains endpoint definitions for extended community list operations
in the ND Manage API.

## Endpoints

- `EpManageExtendedCommunityListsGet` - Get a specific extended community list by name
  (GET /api/v1/manage/fabrics/{fabricName}/extendedCommunityLists/{extendedCommunityListName})
- `EpManageExtendedCommunityListsListGet` - List all extended community lists for a fabric
  (GET /api/v1/manage/fabrics/{fabricName}/extendedCommunityLists)
- `EpManageExtendedCommunityListsPost` - Bulk create extended community lists
  (POST /api/v1/manage/fabrics/{fabricName}/extendedCommunityLists)
- `EpManageExtendedCommunityListsPut` - Update a specific extended community list
  (PUT /api/v1/manage/fabrics/{fabricName}/extendedCommunityLists/{extendedCommunityListName})
- `EpManageExtendedCommunityListsDelete` - Delete a specific extended community list
  (DELETE /api/v1/manage/fabrics/{fabricName}/extendedCommunityLists/{extendedCommunityListName})
- `EpManageExtendedCommunityListsBulkDelete` - Bulk delete via action endpoint
  (POST /api/v1/manage/fabrics/{fabricName}/extendedCommunityListActions/remove)
"""

from __future__ import annotations

from typing import ClassVar, Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ConfigDict, Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import ClusterNameMixin, ExtendedCommunityListNameMixin, FabricNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import CompositeQueryParams, EndpointQueryParams, LuceneQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class ExtendedCommunityListsEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """Query parameters common to extended community list endpoints."""

    model_config = ConfigDict(extra="forbid")


class _EpManageExtendedCommunityListsBase(FabricNameMixin, ExtendedCommunityListNameMixin, NDEndpointBaseModel):
    """
    Base class for ND Manage Extended Community Lists endpoints.

    Provides common path-building logic for all HTTP methods on the
    /api/v1/manage/fabrics/{fabricName}/extendedCommunityLists endpoint.

    Subclasses may override:
    - ``_require_extended_community_list_name``: set to ``False`` for
      collection-level endpoints (list, bulk create) that do not include
      the list name in the path.
    """

    _require_extended_community_list_name: ClassVar[bool] = True

    endpoint_params: ExtendedCommunityListsEndpointParams = Field(
        default_factory=ExtendedCommunityListsEndpointParams,
        description="Endpoint-specific query parameters",
    )

    def set_identifiers(self, identifier: IdentifierKey = None):
        """Assign the extended community list name from the model identifier."""
        self.extended_community_list_name = identifier

    @property
    def path(self) -> str:
        """
        Build the endpoint path for extended community list operations.

        Raises:
            ValueError: if ``fabric_name`` is not set.
            ValueError: if ``extended_community_list_name`` is required but not set.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        if self._require_extended_community_list_name and self.extended_community_list_name is None:
            raise ValueError(f"{type(self).__name__}.path: extended_community_list_name must be set before accessing path.")
        segments = ["fabrics", quote(self.fabric_name, safe=""), "extendedCommunityLists"]
        if self._require_extended_community_list_name and self.extended_community_list_name is not None:
            segments.append(quote(self.extended_community_list_name, safe=""))
        base_path = BasePath.path(*segments)
        query_params = CompositeQueryParams().add(self.endpoint_params)
        lucene_params = getattr(self, "lucene_params", None)
        if lucene_params is not None:
            query_params.add(lucene_params)
        query_string = query_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path


class EpManageExtendedCommunityListsGet(_EpManageExtendedCommunityListsBase):
    """
    ND Manage Extended Community Lists GET Endpoint.

    Retrieves details for a specific extended community list by name.

    Path: GET /api/v1/manage/fabrics/{fabricName}/extendedCommunityLists/{extendedCommunityListName}
    """

    class_name: Literal["EpManageExtendedCommunityListsGet"] = Field(
        default="EpManageExtendedCommunityListsGet",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpManageExtendedCommunityListsListGet(_EpManageExtendedCommunityListsBase):
    """
    ND Manage Extended Community Lists List GET Endpoint.

    Retrieves all extended community lists for a given fabric.

    Path: GET /api/v1/manage/fabrics/{fabricName}/extendedCommunityLists
    """

    _require_extended_community_list_name: ClassVar[bool] = False

    class_name: Literal["EpManageExtendedCommunityListsListGet"] = Field(
        default="EpManageExtendedCommunityListsListGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    lucene_params: LuceneQueryParams = Field(default_factory=LuceneQueryParams, description="Lucene-style query parameters for filtering")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpManageExtendedCommunityListsPost(_EpManageExtendedCommunityListsBase):
    """
    ND Manage Extended Community Lists POST Endpoint.

    Bulk-creates one or more extended community lists.
    Request body: ``{"extendedCommunityLists": [...]}``

    Path: POST /api/v1/manage/fabrics/{fabricName}/extendedCommunityLists
    """

    _require_extended_community_list_name: ClassVar[bool] = False

    class_name: Literal["EpManageExtendedCommunityListsPost"] = Field(
        default="EpManageExtendedCommunityListsPost",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class EpManageExtendedCommunityListsPut(_EpManageExtendedCommunityListsBase):
    """
    ND Manage Extended Community Lists PUT Endpoint.

    Updates an existing extended community list.

    Path: PUT /api/v1/manage/fabrics/{fabricName}/extendedCommunityLists/{extendedCommunityListName}
    """

    class_name: Literal["EpManageExtendedCommunityListsPut"] = Field(
        default="EpManageExtendedCommunityListsPut",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.PUT


class EpManageExtendedCommunityListsDelete(_EpManageExtendedCommunityListsBase):
    """
    ND Manage Extended Community Lists DELETE Endpoint.

    Deletes a specific extended community list by name.

    Path: DELETE /api/v1/manage/fabrics/{fabricName}/extendedCommunityLists/{extendedCommunityListName}
    """

    class_name: Literal["EpManageExtendedCommunityListsDelete"] = Field(
        default="EpManageExtendedCommunityListsDelete",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.DELETE


class _EpManageExtendedCommunityListsBulkDeleteBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base for the extended community list bulk-delete action endpoint.

    Path: /api/v1/manage/fabrics/{fabricName}/extendedCommunityListActions/remove
    """

    endpoint_params: ExtendedCommunityListsEndpointParams = Field(
        default_factory=ExtendedCommunityListsEndpointParams,
        description="Endpoint-specific query parameters",
    )

    def set_identifiers(self, identifier: IdentifierKey = None):
        """No-op: bulk delete endpoint has no per-resource identifier in the path."""

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        base_path = BasePath.path("fabrics", quote(self.fabric_name, safe=""), "extendedCommunityListActions", "remove")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path


class EpManageExtendedCommunityListsBulkDelete(_EpManageExtendedCommunityListsBulkDeleteBase):
    """
    ND Manage Extended Community Lists Bulk Delete Endpoint.

    Bulk-deletes extended community lists by name.
    Request body: ``{"extendedCommunityListNames": [...]}``

    Path: POST /api/v1/manage/fabrics/{fabricName}/extendedCommunityListActions/remove
    """

    class_name: Literal["EpManageExtendedCommunityListsBulkDelete"] = Field(
        default="EpManageExtendedCommunityListsBulkDelete",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
