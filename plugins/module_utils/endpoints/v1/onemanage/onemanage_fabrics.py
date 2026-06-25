# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND onemanage fabrics endpoint models.
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class EpOneManageFabricsGet(NDEndpointBaseModel):
    """GET /appcenter/cisco/ndfc/api/v1/onemanage/fabrics."""

    class_name: Literal["EpOneManageFabricsGet"] = Field(
        default="EpOneManageFabricsGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    proxy_path: str = Field(default="", description="Optional ND proxy prefix")

    @property
    def path(self) -> str:
        return BasePath.path("fabrics", proxy_path=self.proxy_path)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET
