# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import (
    SPEED_CHOICES,
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
    pd,
)


class IosXeNumberedTemplateInputs(
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
):
    """Template inputs for policy_type=iosXeNumbered (IOS-XE intra-fabric numbered link).

    ND emits this policy for a normal Campus (vxlanCampus) intra-fabric link, so it
    is modeled as a first-class supported type. Note the IOS-XE MTU range differs
    from NX-OS (default 9198, not 9216).
    """

    policy_type_marker: Literal["iosXeNumbered"] = Field(default="iosXeNumbered", exclude=True)

    interface_admin_state: bool | None = Field(default=None, alias="interfaceAdminState", json_schema_extra=pd(True))
    src_ip: str | None = Field(default=None, alias="srcIp")
    dst_ip: str | None = Field(default=None, alias="dstIp")
    speed: str | None = Field(default=None, alias="speed", json_schema_extra=pd("auto", choices=SPEED_CHOICES))
    mtu: int | None = Field(default=None, alias="mtu", json_schema_extra=pd(9198, minimum=1500, maximum=9198))
