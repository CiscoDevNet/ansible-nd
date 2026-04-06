# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import (
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
    MacsecFullMixin,
    NetflowMixin,
    QkdMixin,
    TtagMixin,
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

    src_ip_address_mask: Optional[str] = Field(default=None, alias="srcIpAddressMask")
    dst_ip_address_mask: Optional[str] = Field(default=None, alias="dstIpAddressMask")
    src_ipv6_address_mask: Optional[str] = Field(default=None, alias="srcIpv6AddressMask")
    dst_ipv6_address_mask: Optional[str] = Field(default=None, alias="dstIpv6AddressMask")

    src_vrf_name: Optional[str] = Field(default=None, alias="srcVrfName")
    dst_vrf_name: Optional[str] = Field(default=None, alias="dstVrfName")

    link_mtu: Optional[int] = Field(default=None, alias="linkMtu")
    speed: Optional[str] = Field(default=None, alias="speed")

    ip_redirects: Optional[bool] = Field(default=None, alias="ipRedirects")
    ipv4_pim: Optional[bool] = Field(default=None, alias="ipv4Pim")
    ipv6_pim: Optional[bool] = Field(default=None, alias="ipv6Pim")
