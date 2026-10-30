# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import SPEED_CHOICES, InterfaceDescriptionsMixin, LinkTemplateBase, con, pd


class IpfmNumberedTemplateInputs(InterfaceDescriptionsMixin, LinkTemplateBase):
    """Inputs for the IPFM numbered intra-fabric policy in ND 4.2 and later."""

    policy_type_marker: Literal["ipfmNumbered"] = Field(default="ipfmNumbered", exclude=True)

    interface_admin_state: bool | None = Field(default=None, alias="interfaceAdminState", json_schema_extra=pd(True))
    interface_vrf: str | None = Field(default=None, alias="interfaceVrf", json_schema_extra=con(required=True))
    src_ip: str | None = Field(default=None, alias="srcIp", json_schema_extra=con(required=True))
    dst_ip: str | None = Field(default=None, alias="dstIp", json_schema_extra=con(required=True))
    speed: str | None = Field(default=None, alias="speed", json_schema_extra=con(choices=SPEED_CHOICES, omit_if_unset=True))
    bandwidth_capacity_percentage: int | None = Field(default=None, alias="bandwidthCapacityPercentage", json_schema_extra=pd(5, minimum=0, maximum=100))
    mtu: int | None = Field(default=None, alias="mtu", json_schema_extra=pd(9216, minimum=576, maximum=9216, required=True))
