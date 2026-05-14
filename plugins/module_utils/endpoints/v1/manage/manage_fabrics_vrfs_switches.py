# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Endpoint model for /top-down/fabrics/{fabric_name}/vrfs/switches.
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


class EpFabricVrfsSwitchesGet(FabricNameMixin, NDEndpointBaseModel):
    class_name: Literal["EpFabricVrfsSwitchesGet"] = Field(
        default="EpFabricVrfsSwitchesGet",
        frozen=True,
        description="Class name for backward compatibility",
    )

    vrf_names: str = Field(
        min_length=1,
        description="Comma-separated VRF names for vrf-names query parameter.",
    )
    serial_numbers: str = Field(
        min_length=1,
        description="Comma-separated switch serial numbers for serial-numbers query parameter.",
    )

    def set_identifiers(self, identifier: IdentifierKey = None):
        self.fabric_name = identifier

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")

        base_path = TopDownBasePath.path("fabrics", quote(self.fabric_name, safe=""), "vrfs", "switches")
        return "{0}?vrf-names={1}&serial-numbers={2}".format(
            base_path,
            quote(self.vrf_names, safe=""),
            quote(self.serial_numbers, safe=""),
        )

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


EpTopDownFabricsVrfsSwitchesGet = EpFabricVrfsSwitchesGet
