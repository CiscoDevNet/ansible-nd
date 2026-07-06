# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Slawomir Kaszlikowski

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Access Control List (ACL) endpoint models.

IPv4 and IPv6 ACLs share a single API namespace and are distinguished by the
``type`` body field, so a single family of endpoints covers both.

## Endpoints

- ``EpManageAclsGet`` - Get a specific ACL by name
  (GET /api/v1/manage/fabrics/{fabricName}/accessControlLists/{aclName})
- ``EpManageAclsListGet`` - List all ACLs for a fabric
  (GET /api/v1/manage/fabrics/{fabricName}/accessControlLists)
- ``EpManageAclsPost`` - Bulk-create ACLs
  (POST /api/v1/manage/fabrics/{fabricName}/accessControlLists)
- ``EpManageAclsPut`` - Update a specific ACL
  (PUT /api/v1/manage/fabrics/{fabricName}/accessControlLists/{aclName})
- ``EpManageAclsDelete`` - Delete a specific ACL
  (DELETE /api/v1/manage/fabrics/{fabricName}/accessControlLists/{aclName})
- ``EpManageAclsBulkDelete`` - Bulk-delete ACLs
  (POST /api/v1/manage/fabrics/{fabricName}/accessControlListActions/remove)
"""

from __future__ import annotations

from typing import ClassVar, Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import AclNameMixin, FabricNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import EndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class AclsEndpointParams(EndpointQueryParams):
    """Query parameters shared by single-item ACL endpoints."""

    cluster_name: str | None = Field(
        default=None,
        min_length=1,
        description="Name of the target Nexus Dashboard cluster to execute this API, in a multi-cluster deployment",
    )


class AclsListEndpointParams(EndpointQueryParams):
    """Query parameters for the ACL collection (list) endpoint."""

    cluster_name: str | None = Field(
        default=None,
        min_length=1,
        description="Name of the target Nexus Dashboard cluster to execute this API, in a multi-cluster deployment",
    )

    filter: str | None = Field(
        default=None,
        description="Lucene format filter - Filter the response based on this filter field",
    )

    max: int | None = Field(
        default=None,
        ge=1,
        description="Number of records to return",
    )

    offset: int | None = Field(
        default=None,
        ge=0,
        description="Number of records to skip for pagination",
    )

    sort: str | None = Field(
        default=None,
        description="Sort the records by the declared fields in either ascending (default) or descending (:desc) order",
    )


class _EpManageAclsBase(AclNameMixin, FabricNameMixin, NDEndpointBaseModel):
    """
    Shared base for ACL item and collection endpoints.

    Path: ``/api/v1/manage/fabrics/{fabricName}/accessControlLists[/{aclName}]``.

    Subclasses set ``_require_acl_name = False`` for collection-level operations
    (list, bulk-create). ``verb`` is intentionally left abstract so this base
    stays abstract and requires no ``class_name``.
    """

    _collection_segment: ClassVar[str] = "accessControlLists"
    _require_acl_name: ClassVar[bool] = True

    endpoint_params: EndpointQueryParams = Field(default_factory=EndpointQueryParams, description="Endpoint-specific query parameters")

    def set_identifiers(self, identifier: IdentifierKey = None) -> None:
        """Accept either a plain name or a tuple and assign the ACL name."""
        if isinstance(identifier, tuple):
            self.acl_name = identifier[0]
        else:
            self.acl_name = identifier

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        if self._require_acl_name and self.acl_name is None:
            raise ValueError(f"{type(self).__name__}.path: acl_name must be set before accessing path.")
        segments = ["fabrics", quote(self.fabric_name, safe=""), self._collection_segment]
        if self.acl_name is not None:
            segments.append(quote(self.acl_name, safe=""))
        base = BasePath.path(*segments)
        qs = self.endpoint_params.to_query_string()
        return f"{base}?{qs}" if qs else base


class EpManageAclsGet(_EpManageAclsBase):
    """GET /api/v1/manage/fabrics/{fabricName}/accessControlLists/{aclName}"""

    class_name: Literal["EpManageAclsGet"] = Field(default="EpManageAclsGet", description="Class name for backward compatibility")
    endpoint_params: AclsEndpointParams = Field(default_factory=AclsEndpointParams)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageAclsListGet(_EpManageAclsBase):
    """GET /api/v1/manage/fabrics/{fabricName}/accessControlLists"""

    _require_acl_name: ClassVar[bool] = False

    class_name: Literal["EpManageAclsListGet"] = Field(default="EpManageAclsListGet", description="Class name for backward compatibility")
    endpoint_params: AclsListEndpointParams = Field(default_factory=AclsListEndpointParams)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageAclsPost(_EpManageAclsBase):
    """POST /api/v1/manage/fabrics/{fabricName}/accessControlLists (bulk-create)"""

    _require_acl_name: ClassVar[bool] = False

    class_name: Literal["EpManageAclsPost"] = Field(default="EpManageAclsPost", description="Class name for backward compatibility")
    endpoint_params: AclsEndpointParams = Field(default_factory=AclsEndpointParams)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageAclsPut(_EpManageAclsBase):
    """PUT /api/v1/manage/fabrics/{fabricName}/accessControlLists/{aclName}"""

    class_name: Literal["EpManageAclsPut"] = Field(default="EpManageAclsPut", description="Class name for backward compatibility")
    endpoint_params: AclsEndpointParams = Field(default_factory=AclsEndpointParams)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT


class EpManageAclsDelete(_EpManageAclsBase):
    """DELETE /api/v1/manage/fabrics/{fabricName}/accessControlLists/{aclName}"""

    class_name: Literal["EpManageAclsDelete"] = Field(default="EpManageAclsDelete", description="Class name for backward compatibility")
    endpoint_params: AclsEndpointParams = Field(default_factory=AclsEndpointParams)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE


class EpManageAclsBulkDelete(FabricNameMixin, NDEndpointBaseModel):
    """
    POST /api/v1/manage/fabrics/{fabricName}/accessControlListActions/remove

    Bulk-delete ACLs. Request body: ``{"accessControlListNames": ["name1", ...]}``.
    """

    _action_segment: ClassVar[str] = "accessControlListActions"

    class_name: Literal["EpManageAclsBulkDelete"] = Field(default="EpManageAclsBulkDelete", description="Class name for backward compatibility")

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        return BasePath.path("fabrics", quote(self.fabric_name, safe=""), self._action_segment, "remove")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST
