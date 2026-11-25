# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import BGP_AUTH_KEY_ENCRYPTION_CHOICES, SPEED_CHOICES, InterfaceDescriptionsMixin, LinkTemplateBase, TtagMixin, con, pd


class MultisiteUnderlayInterFabricGroupTemplateInputs(InterfaceDescriptionsMixin, TtagMixin, LinkTemplateBase):
    """ND 4.3 multisite underlay between separate fabric groups."""

    minimum_nd_version: ClassVar[tuple[int, int] | None] = (4, 3)
    policy_type_marker: Literal["multisiteUnderlayInterFabricGroup"] = Field(default="multisiteUnderlayInterFabricGroup", exclude=True)

    src_ip_address_mask: str | None = Field(default=None, alias="srcIpAddressMask")
    dst_ip_address: str | None = Field(default=None, alias="dstIpAddress")
    src_ipv6_address_mask: str | None = Field(default=None, alias="srcIpv6AddressMask")
    dst_ipv6_address: str | None = Field(default=None, alias="dstIpv6Address")
    src_ebgp_asn: str | None = Field(default=None, alias="srcEbgpAsn", json_schema_extra=con(required=True))
    dst_ebgp_asn: str | None = Field(default=None, alias="dstEbgpAsn", json_schema_extra=con(required=True))
    ebgp_maximum_paths: int | None = Field(default=None, alias="ebgpMaximumPaths", json_schema_extra=pd(64, minimum=1, maximum=64))
    routing_tag: str | None = Field(default=None, alias="routingTag")
    link_mtu: int | None = Field(default=None, alias="linkMtu", json_schema_extra=pd(9216, minimum=576, maximum=9216))
    speed: str | None = Field(default=None, alias="speed", json_schema_extra=con(choices=SPEED_CHOICES, omit_if_unset=True))
    dci_tracking_direction: str | None = Field(
        default=None, alias="dciTrackingDirection", json_schema_extra=pd("source", choices=("source", "destination"), required=True)
    )
    enable_ebgp_password: bool | None = Field(default=None, alias="enableEbgpPassword", json_schema_extra=pd(False))
    ebgp_password: str | None = Field(default=None, alias="ebgpPassword", json_schema_extra={"secret": True})
    ebgp_auth_key_encryption_type: str | None = Field(
        default=None, alias="ebgpAuthKeyEncryptionType", json_schema_extra=pd("3des", choices=BGP_AUTH_KEY_ENCRYPTION_CHOICES)
    )
    ebgp_log_neighbor_change: bool | None = Field(default=None, alias="ebgpLogNeighborChange", json_schema_extra=pd(False))
    ebgp_bfd: bool | None = Field(default=None, alias="ebgpBfd", json_schema_extra=pd(False))
    ebgp_send_comboth: bool | None = Field(default=None, alias="ebgpSendComboth", json_schema_extra=pd(False))
