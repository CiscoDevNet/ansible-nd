# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    DstClusterNameMixin,
    LinkUuidMixin,
    SrcClusterNameMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

from .base_path import BasePath


class LinksGet(SrcClusterNameMixin, DstClusterNameMixin, NDEndpointBaseModel):
    """GET /api/v1/manage/links for multi cluster scope."""

    class_name: Literal["LinksGet"] = Field(default="LinksGet", frozen=True, description="Class name for backward compatibility")

    @property
    def path(self) -> str:
        return BasePath.path("links")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class LinksPost(NDEndpointBaseModel):
    """POST /api/v1/manage/links for bulk create (multi cluster)."""

    class_name: Literal["LinksPost"] = Field(default="LinksPost", frozen=True, description="Class name for backward compatibility")

    @property
    def path(self) -> str:
        return BasePath.path("links")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class LinkPut(LinkUuidMixin, NDEndpointBaseModel):
    """PUT /api/v1/manage/links/{linkId} for single update (multi cluster)."""

    class_name: Literal["LinkPut"] = Field(default="LinkPut", frozen=True, description="Class name for backward compatibility")

    @property
    def path(self) -> str:
        return BasePath.path("links")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT
