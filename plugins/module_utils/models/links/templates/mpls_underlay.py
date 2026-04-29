# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import (
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
    TtagMixin,
)


class MplsUnderlayTemplateInputs(
    InterfaceDescriptionsMixin,
    TtagMixin,
    LinkTemplateBase,
):
    """Template inputs for policy_type=mplsUnderlay (ISIS or OSPF with segment routing)."""

    policy_type_marker: Literal["mplsUnderlay"] = Field(default="mplsUnderlay", exclude=True)

    mpls_fabric_type: Optional[str] = Field(default=None, alias="mplsFabricType")
    dci_routing_protocol: Optional[str] = Field(default=None, alias="dciRoutingProtocol")
    dci_routing_tag: Optional[str] = Field(default=None, alias="dciRoutingTag")
    ospf_area_id: Optional[str] = Field(default=None, alias="ospfAreaId")

    sr_global_block_range: Optional[str] = Field(default=None, alias="srGlobalBlockRange")
    src_sr_index: Optional[int] = Field(default=None, alias="srcSrIndex")
    dst_sr_index: Optional[int] = Field(default=None, alias="dstSrIndex")

    src_ip_address_mask: Optional[str] = Field(default=None, alias="srcIpAddressMask")
    dst_ip_address: Optional[str] = Field(default=None, alias="dstIpAddress")

    link_mtu: Optional[int] = Field(default=None, alias="linkMtu")
