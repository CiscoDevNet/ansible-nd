# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import EbgpPasswordMixin, LinkTemplateBase


class MultisiteOverlayTemplateInputs(EbgpPasswordMixin, LinkTemplateBase):
    """Template inputs for policy_type=multisiteOverlay (BGW overlay eBGP session)."""

    policy_type_marker: Literal["multisiteOverlay"] = Field(default="multisiteOverlay", exclude=True)

    src_ebgp_asn: str | None = Field(default=None, alias="srcEbgpAsn")
    dst_ebgp_asn: str | None = Field(default=None, alias="dstEbgpAsn")
    src_ip_address: str | None = Field(default=None, alias="srcIpAddress")
    dst_ip_address: str | None = Field(default=None, alias="dstIpAddress")
    ebgp_multihop: int | None = Field(default=None, alias="ebgpMultihop")

    ipv4_trm: bool | None = Field(default=None, alias="ipv4Trm")
    ipv6_trm: bool | None = Field(default=None, alias="ipv6Trm")

    redistribute_route_server: bool | None = Field(default=None, alias="redistributeRouteServer")
    route_server_routing_tag: str | None = Field(default=None, alias="routeServerRoutingTag")
    skip_config_generation: bool | None = Field(default=None, alias="skipConfigGeneration")

    src_interface_description: str | None = Field(default=None, alias="srcInterfaceDescription")
    dst_interface_description: str | None = Field(default=None, alias="dstInterfaceDescription")

    macsec_cipher_suite: str | None = Field(default=None, alias="macsecCipherSuite")
