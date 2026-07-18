# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import (
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
    MacsecFullMixin,
    NetflowMixin,
    QkdMixin,
    TtagMixin,
    pd,
)


class Layer3DciVrfLiteTemplateInputs(
    InterfaceDescriptionsMixin,
    MacsecFullMixin,
    QkdMixin,
    TtagMixin,
    NetflowMixin,
    LinkTemplateBase,
):
    """Template inputs for policy_type=layer3DciVrfLite (VRF lite stitched DCI link)."""

    policy_type_marker: Literal["layer3DciVrfLite"] = Field(default="layer3DciVrfLite", exclude=True)

    src_ip_address_mask: str | None = Field(default=None, alias="srcIpAddressMask")
    dst_ip_address_mask: str | None = Field(default=None, alias="dstIpAddressMask")
    src_ipv6_address_mask: str | None = Field(default=None, alias="srcIpv6AddressMask")
    dst_ipv6_address_mask: str | None = Field(default=None, alias="dstIpv6AddressMask")

    src_vrf_name: str | None = Field(default=None, alias="srcVrfName")
    dst_vrf_name: str | None = Field(default=None, alias="dstVrfName")

    link_mtu: int | None = Field(default=None, alias="linkMtu", json_schema_extra=pd(9216))
    speed: str | None = Field(default=None, alias="speed", json_schema_extra=pd("auto"))

    ip_redirects: bool | None = Field(default=None, alias="ipRedirects", json_schema_extra=pd(False))
    ipv4_pim: bool | None = Field(default=None, alias="ipv4Pim", json_schema_extra=pd(False))
    ipv6_pim: bool | None = Field(default=None, alias="ipv6Pim", json_schema_extra=pd(False))
