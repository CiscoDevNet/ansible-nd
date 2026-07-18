# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import InterfaceDescriptionsMixin, LinkTemplateBase, pd


class VpcPeerKeepaliveTemplateInputs(
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
):
    """Template inputs for policy_type=vpcPeerKeepalive (vPC peer heartbeat link)."""

    policy_type_marker: Literal["vpcPeerKeepalive"] = Field(default="vpcPeerKeepalive", exclude=True)

    src_ip: str | None = Field(default=None, alias="srcIp")
    dst_ip: str | None = Field(default=None, alias="dstIp")
    src_ipv6: str | None = Field(default=None, alias="srcIpv6")
    dst_ipv6: str | None = Field(default=None, alias="dstIpv6")

    interface_vrf: str | None = Field(default=None, alias="interfaceVrf")

    interface_admin_state: bool | None = Field(default=None, alias="interfaceAdminState", json_schema_extra=pd(True))
    mtu: int | None = Field(default=None, alias="mtu", json_schema_extra=pd(9216))
