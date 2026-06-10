# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    DstClusterNameMixin,
    FabricNameMixin,
    LinkUuidMixin,
    SrcClusterNameMixin,
    TicketIdMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import UrlEncodedEndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

from .base_path import BasePath


class LinksGetParams(FabricNameMixin, SrcClusterNameMixin, DstClusterNameMixin, UrlEncodedEndpointQueryParams):
    """URL-encoded query params for GET /links (multi cluster): fabricName, srcClusterName, dstClusterName."""


class LinkMutateParams(TicketIdMixin, UrlEncodedEndpointQueryParams):
    """URL-encoded query params for link create/update/delete (multi cluster): ticketId."""


class LinksGet(NDEndpointBaseModel):
    """GET /api/v1/manage/links for multi cluster scope."""

    class_name: Literal["LinksGet"] = Field(default="LinksGet", frozen=True, description="Class name for backward compatibility")
    endpoint_params: LinksGetParams = Field(default_factory=LinksGetParams, description="Endpoint-specific query parameters")

    @property
    def path(self) -> str:
        base = BasePath.path("links")
        query_string = self.endpoint_params.to_query_string()
        return "{0}?{1}".format(base, query_string) if query_string else base

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class LinksPost(NDEndpointBaseModel):
    """POST /api/v1/manage/links for bulk create (multi cluster)."""

    class_name: Literal["LinksPost"] = Field(default="LinksPost", frozen=True, description="Class name for backward compatibility")
    endpoint_params: LinkMutateParams = Field(default_factory=LinkMutateParams, description="Endpoint-specific query parameters")

    @property
    def path(self) -> str:
        base = BasePath.path("links")
        query_string = self.endpoint_params.to_query_string()
        return "{0}?{1}".format(base, query_string) if query_string else base

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class LinkPut(LinkUuidMixin, NDEndpointBaseModel):
    """PUT /api/v1/manage/links/{linkId} for single update (multi cluster; linkId set via link_uuid)."""

    class_name: Literal["LinkPut"] = Field(default="LinkPut", frozen=True, description="Class name for backward compatibility")
    endpoint_params: LinkMutateParams = Field(default_factory=LinkMutateParams, description="Endpoint-specific query parameters")

    @property
    def path(self) -> str:
        base = BasePath.path("links", self.link_uuid) if self.link_uuid else BasePath.path("links")
        query_string = self.endpoint_params.to_query_string()
        return "{0}?{1}".format(base, query_string) if query_string else base

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT
