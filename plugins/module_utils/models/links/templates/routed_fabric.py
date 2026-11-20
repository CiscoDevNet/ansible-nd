# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import InterfaceDescriptionsMixin, LinkTemplateBase, con, pd


class RoutedFabricTemplateInputs(InterfaceDescriptionsMixin, LinkTemplateBase):
    """External routed-fabric handoff; the API policy ID is ``routedFabric``."""

    policy_type_marker: Literal["routedFabric"] = Field(default="routedFabric", exclude=True)

    src_ip_address_mask: str | None = Field(default=None, alias="srcIpAddressMask")
    dst_ip_address: str | None = Field(default=None, alias="dstIpAddress")
    src_ipv6_address_mask: str | None = Field(default=None, alias="srcIpv6AddressMask")
    dst_ipv6_address: str | None = Field(default=None, alias="dstIpv6Address")
    src_ebgp_asn: str | None = Field(default=None, alias="srcEbgpAsn", json_schema_extra=con(required=True))
    dst_ebgp_asn: str | None = Field(default=None, alias="dstEbgpAsn", json_schema_extra=con(required=True))
    ebgp_maximum_paths: int | None = Field(default=None, alias="ebgpMaximumPaths", json_schema_extra=pd(64, minimum=1, maximum=64, required=True))
    link_mtu: int | None = Field(default=None, alias="linkMtu", json_schema_extra=pd(9216, minimum=576, maximum=9216))
    default_route_configuration: bool | None = Field(default=None, alias="defaultRouteConfiguration", json_schema_extra=pd(False))
