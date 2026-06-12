# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Prefix Lists endpoint models (IPv4 and IPv6).

This module contains endpoint definitions for prefix-list operations
in the ND Manage API, covering both IPv4 and IPv6 prefix lists.

## IPv4 Endpoints

- `EpManageIpv4PrefixListsGet` - Get a specific IPv4 prefix list by name
  (GET /api/v1/manage/fabrics/{fabricName}/ipv4PrefixLists/{ipv4PrefixListName})
- `EpManageIpv4PrefixListsListGet` - List all IPv4 prefix lists for a fabric
  (GET /api/v1/manage/fabrics/{fabricName}/ipv4PrefixLists)
- `EpManageIpv4PrefixListsPost` - Bulk-create IPv4 prefix lists
  (POST /api/v1/manage/fabrics/{fabricName}/ipv4PrefixLists)
- `EpManageIpv4PrefixListsPut` - Update a specific IPv4 prefix list
  (PUT /api/v1/manage/fabrics/{fabricName}/ipv4PrefixLists/{ipv4PrefixListName})
- `EpManageIpv4PrefixListsDelete` - Delete a specific IPv4 prefix list
  (DELETE /api/v1/manage/fabrics/{fabricName}/ipv4PrefixLists/{ipv4PrefixListName})
- `EpManageIpv4PrefixListsBulkDelete` - Bulk-delete IPv4 prefix lists
  (POST /api/v1/manage/fabrics/{fabricName}/ipv4PrefixListActions/remove)

## IPv6 Endpoints

- `EpManageIpv6PrefixListsGet` - Get a specific IPv6 prefix list by name
  (GET /api/v1/manage/fabrics/{fabricName}/ipv6PrefixLists/{ipv6PrefixListName})
- `EpManageIpv6PrefixListsListGet` - List all IPv6 prefix lists for a fabric
  (GET /api/v1/manage/fabrics/{fabricName}/ipv6PrefixLists)
- `EpManageIpv6PrefixListsPost` - Bulk-create IPv6 prefix lists
  (POST /api/v1/manage/fabrics/{fabricName}/ipv6PrefixLists)
- `EpManageIpv6PrefixListsPut` - Update a specific IPv6 prefix list
  (PUT /api/v1/manage/fabrics/{fabricName}/ipv6PrefixLists/{ipv6PrefixListName})
- `EpManageIpv6PrefixListsDelete` - Delete a specific IPv6 prefix list
  (DELETE /api/v1/manage/fabrics/{fabricName}/ipv6PrefixLists/{ipv6PrefixListName})
- `EpManageIpv6PrefixListsBulkDelete` - Bulk-delete IPv6 prefix lists
  (POST /api/v1/manage/fabrics/{fabricName}/ipv6PrefixListActions/remove)
"""

from __future__ import annotations

__metaclass__ = type

from typing import ClassVar, Literal, Optional
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin, PrefixListNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import EndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class PrefixListsEndpointParams(EndpointQueryParams):
    """
    Query parameters shared by single-item prefix list endpoints.

    - cluster_name: Name of the target Nexus Dashboard cluster (multi-cluster deployments)
    """

    cluster_name: Optional[str] = Field(
        default=None,
        min_length=1,
        description="Name of the target Nexus Dashboard cluster to execute this API, in a multi-cluster deployment",
    )


class PrefixListsListEndpointParams(EndpointQueryParams):
    """
    Query parameters for prefix list collection (list) endpoints.

    - cluster_name: multi-cluster target cluster name
    - filter: Lucene-format filter string
    - max: maximum number of records
    - offset: records to skip for pagination
    - sort: sort field with optional ``:desc`` suffix
    """

    cluster_name: Optional[str] = Field(
        default=None,
        min_length=1,
        description="Name of the target Nexus Dashboard cluster to execute this API, in a multi-cluster deployment",
    )

    filter: Optional[str] = Field(
        default=None,
        description="Lucene format filter - Filter the response based on this filter field",
    )

    max: Optional[int] = Field(
        default=None,
        ge=1,
        description="Number of records to return",
    )

    offset: Optional[int] = Field(
        default=None,
        ge=0,
        description="Number of records to skip for pagination",
    )

    sort: Optional[str] = Field(
        default=None,
        description="Sort the records by the declared fields in either ascending (default) or descending (:desc) order",
    )


# IPv4 base class
class _EpManageIpv4PrefixListsBase(PrefixListNameMixin, FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for IPv4 prefix list endpoints.

    Path: ``/api/v1/manage/fabrics/{fabricName}/ipv4PrefixLists[/{name}]``

    Subclasses set ``_require_prefix_list_name = False`` for collection-level
    operations (list, bulk-create).
    """

    _require_prefix_list_name: ClassVar[bool] = True

    endpoint_params: EndpointQueryParams = Field(default_factory=EndpointQueryParams, description="Endpoint-specific query parameters")

    def set_identifiers(self, identifier: IdentifierKey = None) -> None:
        """
        Accept either a plain name or a composite tuple ``("ipv4", name)``
        and assign the prefix list name.
        """
        if isinstance(identifier, tuple):
            self.prefix_list_name = identifier[1]
        else:
            self.prefix_list_name = identifier

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        if self._require_prefix_list_name and self.prefix_list_name is None:
            raise ValueError(f"{type(self).__name__}.path: prefix_list_name must be set before accessing path.")
        segments = ["fabrics"]
        if self.fabric_name is not None:
            segments.append(quote(self.fabric_name, safe=""))
        segments.append("ipv4PrefixLists")
        if self.prefix_list_name is not None:
            segments.append(quote(self.prefix_list_name, safe=""))
        base = BasePath.path(*segments)
        qs = self.endpoint_params.to_query_string()
        return f"{base}?{qs}" if qs else base


class EpManageIpv4PrefixListsGet(_EpManageIpv4PrefixListsBase):
    """
    GET /api/v1/manage/fabrics/{fabricName}/ipv4PrefixLists/{ipv4PrefixListName}

    Retrieve a specific IPv4 prefix list by name.
    """

    class_name: Literal["EpManageIpv4PrefixListsGet"] = Field(default="EpManageIpv4PrefixListsGet", description="Class name for backward compatibility")
    endpoint_params: PrefixListsEndpointParams = Field(default_factory=PrefixListsEndpointParams)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageIpv4PrefixListsListGet(_EpManageIpv4PrefixListsBase):
    """
    GET /api/v1/manage/fabrics/{fabricName}/ipv4PrefixLists

    List all IPv4 prefix lists for a fabric.
    """

    _require_prefix_list_name: ClassVar[bool] = False

    class_name: Literal["EpManageIpv4PrefixListsListGet"] = Field(
        default="EpManageIpv4PrefixListsListGet", description="Class name for backward compatibility"
    )
    endpoint_params: PrefixListsListEndpointParams = Field(default_factory=PrefixListsListEndpointParams)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageIpv4PrefixListsPost(_EpManageIpv4PrefixListsBase):
    """
    POST /api/v1/manage/fabrics/{fabricName}/ipv4PrefixLists

    Bulk-create IPv4 prefix lists.
    Request body: ``{"ipv4PrefixLists": [...]}``.
    """

    _require_prefix_list_name: ClassVar[bool] = False

    class_name: Literal["EpManageIpv4PrefixListsPost"] = Field(default="EpManageIpv4PrefixListsPost", description="Class name for backward compatibility")
    endpoint_params: PrefixListsEndpointParams = Field(default_factory=PrefixListsEndpointParams)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageIpv4PrefixListsPut(_EpManageIpv4PrefixListsBase):
    """
    PUT /api/v1/manage/fabrics/{fabricName}/ipv4PrefixLists/{ipv4PrefixListName}

    Update a specific IPv4 prefix list.
    Request body: ``ipv4PrefixListItem`` schema.
    """

    class_name: Literal["EpManageIpv4PrefixListsPut"] = Field(default="EpManageIpv4PrefixListsPut", description="Class name for backward compatibility")
    endpoint_params: PrefixListsEndpointParams = Field(default_factory=PrefixListsEndpointParams)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT


class EpManageIpv4PrefixListsDelete(_EpManageIpv4PrefixListsBase):
    """
    DELETE /api/v1/manage/fabrics/{fabricName}/ipv4PrefixLists/{ipv4PrefixListName}

    Delete a specific IPv4 prefix list.
    """

    class_name: Literal["EpManageIpv4PrefixListsDelete"] = Field(default="EpManageIpv4PrefixListsDelete", description="Class name for backward compatibility")
    endpoint_params: PrefixListsEndpointParams = Field(default_factory=PrefixListsEndpointParams)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE


class EpManageIpv4PrefixListsBulkDelete(FabricNameMixin, NDEndpointBaseModel):
    """
    POST /api/v1/manage/fabrics/{fabricName}/ipv4PrefixListActions/remove

    Bulk-delete IPv4 prefix lists.
    Request body: ``{"ipv4PrefixListNames": ["name1", ...]}``.
    """

    class_name: Literal["EpManageIpv4PrefixListsBulkDelete"] = Field(
        default="EpManageIpv4PrefixListsBulkDelete", description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        return BasePath.path("fabrics", quote(self.fabric_name, safe=""), "ipv4PrefixListActions", "remove")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


# IPv6 base class
class _EpManageIpv6PrefixListsBase(PrefixListNameMixin, FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for IPv6 prefix list endpoints.

    Path: ``/api/v1/manage/fabrics/{fabricName}/ipv6PrefixLists[/{name}]``
    """

    _require_prefix_list_name: ClassVar[bool] = True

    endpoint_params: EndpointQueryParams = Field(default_factory=EndpointQueryParams, description="Endpoint-specific query parameters")

    def set_identifiers(self, identifier: IdentifierKey = None) -> None:
        """
        Accept either a plain name or a composite tuple ``("ipv6", name)``
        and assign the prefix list name.
        """
        if isinstance(identifier, tuple):
            self.prefix_list_name = identifier[1]
        else:
            self.prefix_list_name = identifier

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        if self._require_prefix_list_name and self.prefix_list_name is None:
            raise ValueError(f"{type(self).__name__}.path: prefix_list_name must be set before accessing path.")
        segments = ["fabrics"]
        if self.fabric_name is not None:
            segments.append(quote(self.fabric_name, safe=""))
        segments.append("ipv6PrefixLists")
        if self.prefix_list_name is not None:
            segments.append(quote(self.prefix_list_name, safe=""))
        base = BasePath.path(*segments)
        qs = self.endpoint_params.to_query_string()
        return f"{base}?{qs}" if qs else base


class EpManageIpv6PrefixListsGet(_EpManageIpv6PrefixListsBase):
    """
    GET /api/v1/manage/fabrics/{fabricName}/ipv6PrefixLists/{ipv6PrefixListName}

    Retrieve a specific IPv6 prefix list by name.
    """

    class_name: Literal["EpManageIpv6PrefixListsGet"] = Field(default="EpManageIpv6PrefixListsGet", description="Class name for backward compatibility")
    endpoint_params: PrefixListsEndpointParams = Field(default_factory=PrefixListsEndpointParams)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageIpv6PrefixListsListGet(_EpManageIpv6PrefixListsBase):
    """
    GET /api/v1/manage/fabrics/{fabricName}/ipv6PrefixLists

    List all IPv6 prefix lists for a fabric.
    """

    _require_prefix_list_name: ClassVar[bool] = False

    class_name: Literal["EpManageIpv6PrefixListsListGet"] = Field(
        default="EpManageIpv6PrefixListsListGet", description="Class name for backward compatibility"
    )
    endpoint_params: PrefixListsListEndpointParams = Field(default_factory=PrefixListsListEndpointParams)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageIpv6PrefixListsPost(_EpManageIpv6PrefixListsBase):
    """
    POST /api/v1/manage/fabrics/{fabricName}/ipv6PrefixLists

    Bulk-create IPv6 prefix lists.
    Request body: ``{"ipv6PrefixLists": [...]}``.
    """

    _require_prefix_list_name: ClassVar[bool] = False

    class_name: Literal["EpManageIpv6PrefixListsPost"] = Field(default="EpManageIpv6PrefixListsPost", description="Class name for backward compatibility")
    endpoint_params: PrefixListsEndpointParams = Field(default_factory=PrefixListsEndpointParams)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageIpv6PrefixListsPut(_EpManageIpv6PrefixListsBase):
    """
    PUT /api/v1/manage/fabrics/{fabricName}/ipv6PrefixLists/{ipv6PrefixListName}

    Update a specific IPv6 prefix list.
    Request body: ``ipv6PrefixListItem`` schema.
    """

    class_name: Literal["EpManageIpv6PrefixListsPut"] = Field(default="EpManageIpv6PrefixListsPut", description="Class name for backward compatibility")
    endpoint_params: PrefixListsEndpointParams = Field(default_factory=PrefixListsEndpointParams)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT


class EpManageIpv6PrefixListsDelete(_EpManageIpv6PrefixListsBase):
    """
    DELETE /api/v1/manage/fabrics/{fabricName}/ipv6PrefixLists/{ipv6PrefixListName}

    Delete a specific IPv6 prefix list.
    """

    class_name: Literal["EpManageIpv6PrefixListsDelete"] = Field(default="EpManageIpv6PrefixListsDelete", description="Class name for backward compatibility")
    endpoint_params: PrefixListsEndpointParams = Field(default_factory=PrefixListsEndpointParams)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE


class EpManageIpv6PrefixListsBulkDelete(FabricNameMixin, NDEndpointBaseModel):
    """
    POST /api/v1/manage/fabrics/{fabricName}/ipv6PrefixListActions/remove

    Bulk-delete IPv6 prefix lists.
    Request body: ``{"ipv6PrefixListNames": ["name1", ...]}``.
    """

    class_name: Literal["EpManageIpv6PrefixListsBulkDelete"] = Field(
        default="EpManageIpv6PrefixListsBulkDelete", description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        return BasePath.path("fabrics", quote(self.fabric_name, safe=""), "ipv6PrefixListActions", "remove")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST
