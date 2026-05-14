# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Endpoint models for /top-down/fabrics/{fabric_name}/vrfs/attachments.
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


class _EpFabricVrfsAttachmentsBase(FabricNameMixin, NDEndpointBaseModel):
    def set_identifiers(self, identifier: IdentifierKey = None):
        self.fabric_name = identifier

    @property
    def _attachments_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        return TopDownBasePath.path("fabrics", quote(self.fabric_name, safe=""), "vrfs", "attachments")


class EpFabricVrfsAttachmentsGet(_EpFabricVrfsAttachmentsBase):
    class_name: Literal["EpFabricVrfsAttachmentsGet"] = Field(
        default="EpFabricVrfsAttachmentsGet",
        frozen=True,
        description="Class name for backward compatibility",
    )

    vrf_names: str = Field(
        min_length=1,
        description="Comma-separated VRF names for vrf-names query parameter.",
    )

    @property
    def path(self) -> str:
        return "{0}?vrf-names={1}".format(self._attachments_path, quote(self.vrf_names, safe=""))

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpFabricVrfsAttachmentsPost(_EpFabricVrfsAttachmentsBase):
    class_name: Literal["EpFabricVrfsAttachmentsPost"] = Field(
        default="EpFabricVrfsAttachmentsPost",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return self._attachments_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


EpTopDownFabricsVrfsAttachmentsGet = EpFabricVrfsAttachmentsGet
EpTopDownFabricsVrfsAttachmentsPost = EpFabricVrfsAttachmentsPost
