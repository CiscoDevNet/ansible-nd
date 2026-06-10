# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import (
    EbgpPasswordMixin,
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
    TtagMixin,
)


class MultisiteUnderlayTemplateInputs(
    InterfaceDescriptionsMixin,
    EbgpPasswordMixin,
    TtagMixin,
    LinkTemplateBase,
):
    """Template inputs for policy_type=multisiteUnderlay (BGW underlay reachability)."""

    policy_type_marker: Literal["multisiteUnderlay"] = Field(default="multisiteUnderlay", exclude=True)

    src_ebgp_asn: str | None = Field(default=None, alias="srcEbgpAsn")
    dst_ebgp_asn: str | None = Field(default=None, alias="dstEbgpAsn")
    ebgp_bfd: bool | None = Field(default=None, alias="ebgpBfd")
    ebgp_log_neighbor_change: bool | None = Field(default=None, alias="ebgpLogNeighborChange")
    ebgp_maximum_paths: int | None = Field(default=None, alias="ebgpMaximumPaths")
    ebgp_send_comboth: bool | None = Field(default=None, alias="ebgpSendComboth")

    src_ip_address_mask: str | None = Field(default=None, alias="srcIpAddressMask")
    src_ipv6_address_mask: str | None = Field(default=None, alias="srcIpv6AddressMask")
    dst_ip_address: str | None = Field(default=None, alias="dstIpAddress")
    dst_ipv6_address: str | None = Field(default=None, alias="dstIpv6Address")

    link_mtu: int | None = Field(default=None, alias="linkMtu")
    speed: str | None = Field(default=None, alias="speed")
    routing_tag: str | None = Field(default=None, alias="routingTag")

    dci_tracking_enable_flag: bool | None = Field(default=None, alias="dciTrackingEnableFlag")
