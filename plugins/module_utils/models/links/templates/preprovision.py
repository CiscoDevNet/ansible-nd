# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import (
    SPEED_CHOICES,
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
    pd,
)


class PreprovisionTemplateInputs(
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
):
    """Template inputs for policy_type=preprovision.

    Per the OpenAPI ``preprovisionConfig`` schema this policy carries the interface
    description/config fields plus ``mtu`` and ``speed`` (but not ``fec`` or
    ``interfaceAdminState``, unlike numbered/unnumbered). ``mtu``/``speed`` were
    previously omitted, which made a controller read of a preprovision link with
    those fields fall back to the opaque unsupported record (and hence immutable).
    """

    policy_type_marker: Literal["preprovision"] = Field(default="preprovision", exclude=True)

    mtu: int | None = Field(default=None, alias="mtu", json_schema_extra=pd(9216, minimum=576, maximum=9216))
    speed: str | None = Field(default=None, alias="speed", json_schema_extra=pd("auto", choices=SPEED_CHOICES))
