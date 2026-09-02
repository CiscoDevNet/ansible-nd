# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import (
    EbgpPasswordMixin,
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
    MacsecFullMixin,
    QkdMixin,
    con,
    pd,
)


class MultisiteOverlayTemplateInputs(
    InterfaceDescriptionsMixin,
    MacsecFullMixin,
    QkdMixin,
    EbgpPasswordMixin,
    LinkTemplateBase,
):
    """Template inputs for policy_type=multisiteOverlay (BGW overlay eBGP session).

    Composes the MACsec, QKD and interface-description mixins so the full OpenAPI
    ``multisiteOverlayConfig`` shape (macsec/qkd/interface-config fields) is modeled;
    previously these were absent, so a controller read of such a link was
    misclassified as unsupported.
    """

    policy_type_marker: Literal["multisiteOverlay"] = Field(default="multisiteOverlay", exclude=True)

    src_ebgp_asn: str | None = Field(default=None, alias="srcEbgpAsn", json_schema_extra=con(required=True))
    dst_ebgp_asn: str | None = Field(default=None, alias="dstEbgpAsn", json_schema_extra=con(required=True))
    src_ip_address: str | None = Field(default=None, alias="srcIpAddress", json_schema_extra=con(required=True))
    dst_ip_address: str | None = Field(default=None, alias="dstIpAddress", json_schema_extra=con(required=True))
    ebgp_multihop: int | None = Field(default=None, alias="ebgpMultihop", json_schema_extra=pd(5, minimum=2, maximum=255))

    ipv4_trm: bool | None = Field(default=None, alias="ipv4Trm", json_schema_extra=pd(False))
    ipv6_trm: bool | None = Field(default=None, alias="ipv6Trm", json_schema_extra=pd(False))

    redistribute_route_server: bool | None = Field(default=None, alias="redistributeRouteServer", json_schema_extra=pd(False))
    route_server_routing_tag: str | None = Field(default=None, alias="routeServerRoutingTag")
    skip_config_generation: bool | None = Field(default=None, alias="skipConfigGeneration", json_schema_extra=pd(False))
