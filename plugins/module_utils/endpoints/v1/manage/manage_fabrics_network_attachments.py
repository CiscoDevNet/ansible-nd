# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric Network Attachments endpoint models.

Endpoints covered:
- Attach/detach networks
- Export network attachments via CSV
- Import network attachments via CSV
- List/query network attachments
"""

from __future__ import annotations

__author__ = "Akshayanat C S"

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    ClusterNameMixin,
    FabricNameMixin,
    FilterMixin,
    MaxMixin,
    OffsetMixin,
    TicketIdMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class NetworkAttachmentsTicketEndpointParams(ClusterNameMixin, TicketIdMixin, EndpointQueryParams):
    """Query parameters for attachment mutation endpoints with optional ticketId."""


class NetworkAttachmentsNoParamsEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """Query parameters for attachment endpoints with only optional clusterName."""


class NetworkAttachmentsQueryEndpointParams(ClusterNameMixin, FilterMixin, MaxMixin, OffsetMixin, EndpointQueryParams):
    """Query parameters for network attachment query."""

    sort: str | None = Field(default=None, min_length=1, description="Sort field and direction")
    is_consolidated: bool | None = Field(
        default=None,
        alias="isConsolidated",
        description="Return interface ranges instead of individual interface names",
    )
    include_all: bool | None = Field(
        default=None,
        alias="includeAll",
        description="Include attachments that were never attached",
    )


class _EpManageFabricsNetworkAttachmentsBase(FabricNameMixin, NDEndpointBaseModel):
    """Base class for /api/v1/manage/fabrics/{fabricName}/networkAttachments."""

    @property
    def _base_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "networkAttachments")


class EpManageFabricsNetworkAttachmentsPost(_EpManageFabricsNetworkAttachmentsBase):
    """POST /fabrics/{fabricName}/networkAttachments."""

    class_name: Literal["EpManageFabricsNetworkAttachmentsPost"] = Field(
        default="EpManageFabricsNetworkAttachmentsPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: NetworkAttachmentsTicketEndpointParams = Field(default_factory=NetworkAttachmentsTicketEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageFabricsNetworkAttachmentsExportPost(_EpManageFabricsNetworkAttachmentsBase):
    """POST /fabrics/{fabricName}/networkAttachment/export."""

    class_name: Literal["EpManageFabricsNetworkAttachmentsExportPost"] = Field(
        default="EpManageFabricsNetworkAttachmentsExportPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: NetworkAttachmentsNoParamsEndpointParams = Field(default_factory=NetworkAttachmentsNoParamsEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        path = BasePath.path("fabrics", self.fabric_name, "networkAttachment", "export")
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageFabricsNetworkAttachmentsImportPost(_EpManageFabricsNetworkAttachmentsBase):
    """POST /fabrics/{fabricName}/networkAttachments/import."""

    class_name: Literal["EpManageFabricsNetworkAttachmentsImportPost"] = Field(
        default="EpManageFabricsNetworkAttachmentsImportPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: NetworkAttachmentsTicketEndpointParams = Field(default_factory=NetworkAttachmentsTicketEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        path = f"{self._base_path}/import"
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageFabricsNetworkAttachmentsQueryPost(_EpManageFabricsNetworkAttachmentsBase):
    """POST /fabrics/{fabricName}/networkAttachments/query."""

    class_name: Literal["EpManageFabricsNetworkAttachmentsQueryPost"] = Field(
        default="EpManageFabricsNetworkAttachmentsQueryPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: NetworkAttachmentsQueryEndpointParams = Field(default_factory=NetworkAttachmentsQueryEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        path = f"{self._base_path}/query"
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST
