# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import InterfaceDescriptionsMixin, LinkTemplateBase, con, pd


class CsrMultisiteUnderlayTemplateInputs(InterfaceDescriptionsMixin, LinkTemplateBase):
    """CSR multisite underlay inputs, identical in ND 4.2.1 and 4.3.1.

    The neighbor-password alias and disabled-by-default password control differ
    from the NX-OS eBGP mixin, so they are declared explicitly here.
    """

    policy_type_marker: Literal["csrMultisiteUnderlay"] = Field(default="csrMultisiteUnderlay", exclude=True)

    src_ip_address_mask: str | None = Field(default=None, alias="srcIpAddressMask", json_schema_extra=con(required=True))
    dst_ip: str | None = Field(default=None, alias="dstIp", json_schema_extra=con(required=True))
    enable_ebgp_password: bool | None = Field(default=None, alias="enableEbgpPassword", json_schema_extra=pd(False))
    ebgp_neighbor_password: str | None = Field(default=None, alias="ebgpNeighborPassword", json_schema_extra={"secret": True})
