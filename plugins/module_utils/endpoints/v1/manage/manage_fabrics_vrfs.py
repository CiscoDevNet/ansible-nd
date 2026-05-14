# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Endpoint models for /top-down/fabrics/{fabric_name}/vrfs.
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    FabricNameMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.lan_fabric_base_path import (
    TopDownBasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class _EpFabricVrfsBase(FabricNameMixin, NDEndpointBaseModel):
    def set_identifiers(self, identifier: IdentifierKey = None):
        self.fabric_name = identifier

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")

        return TopDownBasePath.path("fabrics", quote(self.fabric_name, safe=""), "vrfs")


class EpFabricVrfsGet(_EpFabricVrfsBase):
    class_name: Literal["EpFabricVrfsGet"] = Field(
        default="EpFabricVrfsGet",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpFabricVrfsPost(_EpFabricVrfsBase):
    class_name: Literal["EpFabricVrfsPost"] = Field(
        default="EpFabricVrfsPost",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


EpTopDownFabricsVrfsGet = EpFabricVrfsGet
EpTopDownFabricsVrfsPost = EpFabricVrfsPost
