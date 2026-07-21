# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import (
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
    TtagMixin,
    con,
    pd,
)

MPLS_FABRIC_TYPE_CHOICES = ("mplsLdp", "mplsSr")
DCI_ROUTING_PROTOCOL_CHOICES = ("ospf", "is-is")


class MplsUnderlayTemplateInputs(
    InterfaceDescriptionsMixin,
    TtagMixin,
    LinkTemplateBase,
):
    """Template inputs for policy_type=mplsUnderlay (ISIS or OSPF with segment routing)."""

    policy_type_marker: Literal["mplsUnderlay"] = Field(default="mplsUnderlay", exclude=True)

    mpls_fabric_type: str | None = Field(default=None, alias="mplsFabricType", json_schema_extra=con(choices=MPLS_FABRIC_TYPE_CHOICES, required=True))
    dci_routing_protocol: str | None = Field(
        default=None, alias="dciRoutingProtocol", json_schema_extra=con(choices=DCI_ROUTING_PROTOCOL_CHOICES, required=True)
    )
    dci_routing_tag: str | None = Field(default=None, alias="dciRoutingTag", json_schema_extra=pd("MPLS_UNDERLAY", required=True))
    ospf_area_id: str | None = Field(default=None, alias="ospfAreaId")

    sr_global_block_range: str | None = Field(default=None, alias="srGlobalBlockRange", json_schema_extra=pd("16000-23999"))
    src_sr_index: int | None = Field(default=None, alias="srcSrIndex", json_schema_extra=con(minimum=0, maximum=471804))
    dst_sr_index: int | None = Field(default=None, alias="dstSrIndex", json_schema_extra=con(minimum=0, maximum=471804))

    src_ip_address_mask: str | None = Field(default=None, alias="srcIpAddressMask", json_schema_extra=con(required=True))
    dst_ip_address: str | None = Field(default=None, alias="dstIpAddress", json_schema_extra=con(required=True))

    link_mtu: int | None = Field(default=None, alias="linkMtu", json_schema_extra=pd(9216, minimum=576, maximum=9216))
