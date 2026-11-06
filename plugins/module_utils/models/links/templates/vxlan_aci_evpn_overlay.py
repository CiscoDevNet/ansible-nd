# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import LinkTemplateBase, con, pd


class VxlanAciEvpnOverlayTemplateInputs(LinkTemplateBase):
    """VXLAN to ACI EVPN overlay inputs with explicit release field ownership.

    Both releases require the four peering identity fields. ND 4.2.1 adds
    interface configuration and MACsec/QKD settings, while ND 4.3.1 instead
    declares multihop and route-server controls. These groups cannot share the
    unscoped interface/security mixins because requests must use their release's
    schema rather than automatically emitting the complete union.
    """

    policy_type_marker: Literal["vxlanAciEvpnOverlay"] = Field(default="vxlanAciEvpnOverlay", exclude=True)

    src_ebgp_asn: str | None = Field(default=None, alias="srcEbgpAsn", json_schema_extra=con(required=True))
    dst_ebgp_asn: str | None = Field(default=None, alias="dstEbgpAsn", json_schema_extra=con(required=True))
    src_ip_address: str | None = Field(default=None, alias="srcIpAddress", json_schema_extra=con(required=True))
    dst_ip_address: str | None = Field(default=None, alias="dstIpAddress", json_schema_extra=con(required=True))

    src_interface_description: str | None = Field(default=None, alias="srcInterfaceDescription", json_schema_extra=con(max_length=254, max_nd_version=(4, 2)))
    dst_interface_description: str | None = Field(default=None, alias="dstInterfaceDescription", json_schema_extra=con(max_length=254, max_nd_version=(4, 2)))
    src_interface_config: str | None = Field(default=None, alias="srcInterfaceConfig", json_schema_extra=con(max_nd_version=(4, 2)))
    dst_interface_config: str | None = Field(default=None, alias="dstInterfaceConfig", json_schema_extra=con(max_nd_version=(4, 2)))
    macsec: bool | None = Field(default=None, alias="macsec", json_schema_extra=pd(False, max_nd_version=(4, 2)))
    src_macsec_key_chain_prefix: str | None = Field(default=None, alias="srcMacsecKeyChainPrefix", json_schema_extra=con(max_nd_version=(4, 2)))
    dst_macsec_key_chain_prefix: str | None = Field(default=None, alias="dstMacsecKeyChainPrefix", json_schema_extra=con(max_nd_version=(4, 2)))
    qkd: bool | None = Field(default=None, alias="qkd", json_schema_extra=pd(False, max_nd_version=(4, 2)))
    override_fabric_macsec: bool | None = Field(default=None, alias="overrideFabricMacsec", json_schema_extra=pd(False, max_nd_version=(4, 2)))
    macsec_cipher_suite: str | None = Field(default=None, alias="macsecCipherSuite", json_schema_extra=con(max_nd_version=(4, 2)))
    macsec_primary_key_string: str | None = Field(default=None, alias="macsecPrimaryKeyString", json_schema_extra=con(secret=True, max_nd_version=(4, 2)))
    macsec_primary_cryptographic_algorithm: str | None = Field(
        default=None, alias="macsecPrimaryCryptographicAlgorithm", json_schema_extra=con(max_nd_version=(4, 2))
    )
    macsec_fallback_key_string: str | None = Field(default=None, alias="macsecFallbackKeyString", json_schema_extra=con(secret=True, max_nd_version=(4, 2)))
    macsec_fallback_cryptographic_algorithm: str | None = Field(
        default=None, alias="macsecFallbackCryptographicAlgorithm", json_schema_extra=con(max_nd_version=(4, 2))
    )
    src_qkd_profile_name: str | None = Field(default=None, alias="srcQkdProfileName", json_schema_extra=con(max_length=63, max_nd_version=(4, 2)))
    src_kme_server_ip: str | None = Field(default=None, alias="srcKmeServerIp", json_schema_extra=con(max_nd_version=(4, 2)))
    src_kme_server_port_number: int | None = Field(
        default=None, alias="srcKmeServerPortNumber", json_schema_extra=con(minimum=0, maximum=65535, max_nd_version=(4, 2))
    )
    src_trustpoint_label: str | None = Field(default=None, alias="srcTrustpointLabel", json_schema_extra=con(max_length=64, max_nd_version=(4, 2)))
    dst_qkd_profile_name: str | None = Field(default=None, alias="dstQkdProfileName", json_schema_extra=con(max_length=63, max_nd_version=(4, 2)))
    dst_kme_server_ip: str | None = Field(default=None, alias="dstKmeServerIp", json_schema_extra=con(max_nd_version=(4, 2)))
    dst_kme_server_port_number: int | None = Field(
        default=None, alias="dstKmeServerPortNumber", json_schema_extra=con(minimum=0, maximum=65535, max_nd_version=(4, 2))
    )
    dst_trustpoint_label: str | None = Field(default=None, alias="dstTrustpointLabel", json_schema_extra=con(max_length=64, max_nd_version=(4, 2)))
    ignore_certificate: bool | None = Field(default=None, alias="ignoreCertificate", json_schema_extra=pd(False, max_nd_version=(4, 2)))

    ebgp_multihop: int | None = Field(default=None, alias="ebgpMultihop", json_schema_extra=pd(5, minimum=2, maximum=255, min_nd_version=(4, 3)))
    redistribute_route_server: bool | None = Field(default=None, alias="redistributeRouteServer", json_schema_extra=pd(False, min_nd_version=(4, 3)))
    route_server_routing_tag: str | None = Field(default=None, alias="routeServerRoutingTag", json_schema_extra=con(min_nd_version=(4, 3)))
