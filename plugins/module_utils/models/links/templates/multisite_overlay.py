# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import EbgpPasswordMixin, LinkTemplateBase


class MultisiteOverlayTemplateInputs(EbgpPasswordMixin, LinkTemplateBase):
    """Template inputs for policy_type=multisiteOverlay (BGW overlay eBGP session)."""

    policy_type_marker: Literal["multisiteOverlay"] = Field(default="multisiteOverlay", exclude=True)

    src_ebgp_asn: Optional[str] = Field(default=None, alias="srcEbgpAsn")
    dst_ebgp_asn: Optional[str] = Field(default=None, alias="dstEbgpAsn")
    src_ip_address: Optional[str] = Field(default=None, alias="srcIpAddress")
    dst_ip_address: Optional[str] = Field(default=None, alias="dstIpAddress")
    ebgp_multihop: Optional[int] = Field(default=None, alias="ebgpMultihop")

    ipv4_trm: Optional[bool] = Field(default=None, alias="ipv4Trm")
    ipv6_trm: Optional[bool] = Field(default=None, alias="ipv6Trm")

    redistribute_route_server: Optional[bool] = Field(default=None, alias="redistributeRouteServer")
    route_server_routing_tag: Optional[str] = Field(default=None, alias="routeServerRoutingTag")
    skip_config_generation: Optional[bool] = Field(default=None, alias="skipConfigGeneration")

    src_interface_description: Optional[str] = Field(default=None, alias="srcInterfaceDescription")
    dst_interface_description: Optional[str] = Field(default=None, alias="dstInterfaceDescription")

    macsec_cipher_suite: Optional[str] = Field(default=None, alias="macsecCipherSuite")
