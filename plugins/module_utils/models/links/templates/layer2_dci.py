# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import (
    SPEED_CHOICES,
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
    MacsecFullMixin,
    QkdMixin,
    con,
    pd,
)

BPDU_GUARD_CHOICES = ("enable", "disable", "default")
MTU_TYPE_CHOICES = ("default", "jumbo")


class Layer2DciTemplateInputs(
    InterfaceDescriptionsMixin,
    MacsecFullMixin,
    QkdMixin,
    LinkTemplateBase,
):
    """Template inputs for policy_type=layer2Dci (L2 trunk between data centers).

    ``inheritTtagFabricSetting`` (TtagMixin) is intentionally NOT composed here: the
    OpenAPI ``layer2DciConfig`` schema does not define it, so sending it is off
    contract.
    """

    policy_type_marker: Literal["layer2Dci"] = Field(default="layer2Dci", exclude=True)

    trunk_allowed_vlans: str | None = Field(default=None, alias="trunkAllowedVlans")
    native_vlan: int | None = Field(default=None, alias="nativeVlan", json_schema_extra=con(minimum=1, maximum=4094))
    bpdu_guard: str | None = Field(default=None, alias="bpduGuard", json_schema_extra=con(choices=BPDU_GUARD_CHOICES))
    port_type_fast: bool | None = Field(default=None, alias="portTypeFast", json_schema_extra=pd(True))

    mtu_type: str | None = Field(default=None, alias="mtuType", json_schema_extra=con(choices=MTU_TYPE_CHOICES))
    speed: str | None = Field(default=None, alias="speed", json_schema_extra=pd("auto", choices=SPEED_CHOICES))
