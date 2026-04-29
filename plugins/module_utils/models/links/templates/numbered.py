# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import (
    BfdEchoMixin,
    DhcpRelayMixin,
    InterfaceBasicsMixin,
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
    MacsecCoreMixin,
)


class NumberedTemplateInputs(
    InterfaceBasicsMixin,
    InterfaceDescriptionsMixin,
    DhcpRelayMixin,
    BfdEchoMixin,
    MacsecCoreMixin,
    LinkTemplateBase,
):
    """Template inputs for policy_type=numbered (IPv4/IPv6 addressed P2P link)."""

    policy_type_marker: Literal["numbered"] = Field(default="numbered", exclude=True)

    src_ip: Optional[str] = Field(default=None, alias="srcIp")
    dst_ip: Optional[str] = Field(default=None, alias="dstIp")
    src_ipv6: Optional[str] = Field(default=None, alias="srcIpv6")
    dst_ipv6: Optional[str] = Field(default=None, alias="dstIpv6")
