# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import SPEED_CHOICES, LinkTemplateBase, con


class VxlanAciMultisiteUnderlayTemplateInputs(LinkTemplateBase):
    """VXLAN to ACI multisite underlay inputs for both supported ND releases.

    ND 4.3.1 replaces the freeform interface-config fields with ``speed``.
    Release metadata keeps those fields out of requests for the other API era.
    Speed has no documented default and is omitted unless explicitly supplied.
    """

    policy_type_marker: Literal["vxlanAciMultisiteUnderlay"] = Field(default="vxlanAciMultisiteUnderlay", exclude=True)

    src_ebgp_asn: str | None = Field(default=None, alias="srcEbgpAsn", json_schema_extra=con(required=True))
    dst_ebgp_asn: str | None = Field(default=None, alias="dstEbgpAsn", json_schema_extra=con(required=True))
    src_ip_address_mask: str | None = Field(default=None, alias="srcIpAddressMask")
    dst_ip_address: str | None = Field(default=None, alias="dstIpAddress")
    src_ipv6_address_mask: str | None = Field(default=None, alias="srcIpv6AddressMask")
    dst_ipv6_address: str | None = Field(default=None, alias="dstIpv6Address")
    src_interface_description: str | None = Field(default=None, alias="srcInterfaceDescription", json_schema_extra=con(max_length=254))
    dst_interface_description: str | None = Field(default=None, alias="dstInterfaceDescription", json_schema_extra=con(max_length=254))
    src_interface_config: str | None = Field(default=None, alias="srcInterfaceConfig", json_schema_extra=con(max_nd_version=(4, 2)))
    dst_interface_config: str | None = Field(default=None, alias="dstInterfaceConfig", json_schema_extra=con(max_nd_version=(4, 2)))
    speed: str | None = Field(default=None, alias="speed", json_schema_extra=con(choices=SPEED_CHOICES, min_nd_version=(4, 3), omit_if_unset=True))
