# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Endpoint model for /resource-manager/reserve-id.
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.lan_fabric_base_path import (
    ResourceManagerBasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class EpResourceManagerReserveIdPost(NDEndpointBaseModel):
    class_name: Literal["EpResourceManagerReserveIdPost"] = Field(
        default="EpResourceManagerReserveIdPost",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return ResourceManagerBasePath.path("reserve-id")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


EpTopDownResourceManagerReserveIdPost = EpResourceManagerReserveIdPost
