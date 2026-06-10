# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import LinkTemplateBase


class MplsOverlayTemplateInputs(LinkTemplateBase):
    """Template inputs for policy_type=mplsOverlay (MPLS SR loopback eBGP peering)."""

    policy_type_marker: Literal["mplsOverlay"] = Field(default="mplsOverlay", exclude=True)

    src_ebgp_asn: str | None = Field(default=None, alias="srcEbgpAsn")
    dst_ebgp_asn: str | None = Field(default=None, alias="dstEbgpAsn")
    dst_ip_address: str | None = Field(default=None, alias="dstIpAddress")
