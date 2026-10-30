# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import InterfaceDescriptionsMixin, LinkTemplateBase, MacsecFullMixin, QkdMixin, TtagMixin, pd


class OspfVrfLiteTemplateInputs(
    InterfaceDescriptionsMixin,
    MacsecFullMixin,
    QkdMixin,
    TtagMixin,
    LinkTemplateBase,
):
    """OSPF VRF Lite inputs shared by the ND 4.2.1 and 4.3.1 schemas."""

    policy_type_marker: Literal["ospfVrfLite"] = Field(default="ospfVrfLite", exclude=True)

    src_ip_address_mask: str | None = Field(default=None, alias="srcIpAddressMask")
    dst_ip_address: str | None = Field(default=None, alias="dstIpAddress")
    src_ipv6_address_mask: str | None = Field(default=None, alias="srcIpv6AddressMask")
    dst_ipv6_address: str | None = Field(default=None, alias="dstIpv6Address")
    link_mtu: int | None = Field(default=None, alias="linkMtu", json_schema_extra=pd(9216, minimum=576, maximum=9216))
    auto_gen_config_peer: bool | None = Field(default=None, alias="autoGenConfigPeer", json_schema_extra=pd(False))
    template_config_gen_peer: str | None = Field(default=None, alias="templateConfigGenPeer", json_schema_extra=pd("Ext_VRF_Lite_Jython"))
