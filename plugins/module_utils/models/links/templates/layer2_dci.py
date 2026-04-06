# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import (
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
    MacsecFullMixin,
    QkdMixin,
    TtagMixin,
)


class Layer2DciTemplateInputs(
    InterfaceDescriptionsMixin,
    MacsecFullMixin,
    QkdMixin,
    TtagMixin,
    LinkTemplateBase,
):
    """Template inputs for policy_type=layer2Dci (L2 trunk between data centers)."""

    policy_type_marker: Literal["layer2Dci"] = Field(default="layer2Dci", exclude=True)

    trunk_allowed_vlans: Optional[str] = Field(default=None, alias="trunkAllowedVlans")
    native_vlan: Optional[int] = Field(default=None, alias="nativeVlan")
    bpdu_guard: Optional[str] = Field(default=None, alias="bpduGuard")
    port_type_fast: Optional[bool] = Field(default=None, alias="portTypeFast")

    mtu_type: Optional[str] = Field(default=None, alias="mtuType")
    speed: Optional[str] = Field(default=None, alias="speed")
