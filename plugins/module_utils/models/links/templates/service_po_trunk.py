# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import LinkTemplateBase, pd
from .service_trunk import ServiceTrunkFieldsMixin


class ServicePoTrunkTemplateInputs(ServiceTrunkFieldsMixin, LinkTemplateBase):
    """ND 4.3 service port-channel trunk with the complete LACP field set."""

    minimum_nd_version: ClassVar[tuple[int, int] | None] = (4, 3)
    policy_type_marker: Literal["servicePoTrunk"] = Field(default="servicePoTrunk", exclude=True)

    port_channel_mode: str | None = Field(
        default=None, alias="portChannelMode", json_schema_extra=pd("active", choices=("on", "active", "passive"), required=True)
    )
    copy_description: bool | None = Field(default=None, alias="copyDescription", json_schema_extra=pd(False))
    lacp_rate: str | None = Field(default=None, alias="lacpRate", json_schema_extra=pd("normal", choices=("normal", "fast")))
    lacp_suspend: bool | None = Field(default=None, alias="lacpSuspend", json_schema_extra=pd(False))
    lacp_port_priority: int | None = Field(default=None, alias="lacpPortPriority", json_schema_extra=pd(32768, minimum=1, maximum=65535))
