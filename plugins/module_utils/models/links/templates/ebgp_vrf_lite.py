# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import (
    BGP_AUTH_KEY_ENCRYPTION_CHOICES,
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
    MacsecFullMixin,
    QkdMixin,
    TtagMixin,
    con,
    pd,
)


class EbgpVrfLiteTemplateInputs(
    InterfaceDescriptionsMixin,
    MacsecFullMixin,
    QkdMixin,
    TtagMixin,
    LinkTemplateBase,
):
    """Template inputs for policy_type=ebgpVrfLite (eBGP peering over VRF lite link)."""

    policy_type_marker: Literal["ebgpVrfLite"] = Field(default="ebgpVrfLite", exclude=True)

    src_ebgp_asn: str | None = Field(default=None, alias="srcEbgpAsn", json_schema_extra=con(required=True))
    dst_ebgp_asn: str | None = Field(default=None, alias="dstEbgpAsn", json_schema_extra=con(required=True))

    src_ip_address_mask: str | None = Field(default=None, alias="srcIpAddressMask")
    src_ipv6_address_mask: str | None = Field(default=None, alias="srcIpv6AddressMask")
    dst_ip_address: str | None = Field(default=None, alias="dstIpAddress")
    dst_ipv6_address: str | None = Field(default=None, alias="dstIpv6Address")

    link_mtu: int | None = Field(default=None, alias="linkMtu", json_schema_extra=pd(9216, minimum=576, maximum=9216))
    routing_tag: str | None = Field(default=None, alias="routingTag")

    auto_gen_config_default_vrf: bool | None = Field(default=None, alias="autoGenConfigDefaultVrf", json_schema_extra=pd(False))
    auto_gen_config_nx_peer_default_vrf: bool | None = Field(default=None, alias="autoGenConfigNxPeerDefaultVrf", json_schema_extra=pd(False))
    auto_gen_config_peer: bool | None = Field(default=None, alias="autoGenConfigPeer", json_schema_extra=pd(False))

    dci_tracking: bool | None = Field(default=None, alias="dciTracking", json_schema_extra=pd(False))

    default_vrf_ebgp_neighbor_password: str | None = Field(default=None, alias="defaultVrfEbgpNeighborPassword", json_schema_extra={"secret": True})
    default_vrf_ebgp_password_key_encryption_type: str | None = Field(
        default=None, alias="defaultVrfEbgpPasswordKeyEncryptionType", json_schema_extra=pd("3des", choices=BGP_AUTH_KEY_ENCRYPTION_CHOICES)
    )
    redistrib_ebgp_route_map_name: str | None = Field(default=None, alias="redistribEbgpRouteMapName")
    template_config_gen_peer: str | None = Field(default=None, alias="templateConfigGenPeer", json_schema_extra=pd("Ext_VRF_Lite_Jython"))
    vrf_name_nx_peer_switch: str | None = Field(default=None, alias="vrfNameNxPeerSwitch")
