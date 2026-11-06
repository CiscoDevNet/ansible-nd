# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, Field

from .base import SPEED_CHOICES, LinkTemplateBase, con, pd

INTERFACE_DESCRIPTION_PATTERN = "^[A-Za-z0-9 ., :;!?'\"+*/=<>@#$%&^_~\\|()\\[\\]{}\\r\\n—-]*$"


class ServiceTrunkFieldsMixin(BaseModel):
    """ND 4.3 serviceLinkBaseConfig shared by physical and port-channel trunks."""

    admin_state: bool | None = Field(default=None, alias="adminState", json_schema_extra=pd(True, required=True))
    allowed_vlans: str | None = Field(default=None, alias="allowedVlans", json_schema_extra=pd("none", required=True))
    bpdu_guard: str | None = Field(default=None, alias="bpduGuard", json_schema_extra=pd("default", choices=("enable", "disable", "default"), required=True))
    cdp: bool | None = Field(default=None, alias="cdp", json_schema_extra=pd(True))
    mtu: str | None = Field(default=None, alias="mtu", json_schema_extra=pd("jumbo", choices=("default", "jumbo"), required=True))
    native_vlan: int | None = Field(default=None, alias="nativeVlan", json_schema_extra=con(minimum=1, maximum=4094, omit_if_unset=True))
    netflow: bool | None = Field(default=None, alias="netflow", json_schema_extra=pd(False))
    netflow_monitor: str | None = Field(default=None, alias="netflowMonitor")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler")
    orphan_port: bool | None = Field(default=None, alias="orphanPort", json_schema_extra=pd(False))
    pfc: bool | None = Field(default=None, alias="pfc", json_schema_extra=pd(False))
    duplex_mode: str | None = Field(default=None, alias="duplexMode", json_schema_extra=pd("auto", choices=("auto", "full", "half")))
    port_type_edge_trunk: bool | None = Field(default=None, alias="portTypeEdgeTrunk", json_schema_extra=pd(True, required=True))
    qos: bool | None = Field(default=None, alias="qos", json_schema_extra=pd(False))
    qos_policy: str | None = Field(default=None, alias="qosPolicy")
    queuing_policy: str | None = Field(default=None, alias="queuingPolicy")
    speed: str | None = Field(default=None, alias="speed", json_schema_extra=con(choices=SPEED_CHOICES, omit_if_unset=True))
    description: str | None = Field(
        default=None,
        alias="description",
        json_schema_extra=con(min_length=1, max_length=254, pattern=INTERFACE_DESCRIPTION_PATTERN, omit_if_unset=True),
    )
    extra_config: str | None = Field(default=None, alias="extraConfig")


class ServiceTrunkTemplateInputs(ServiceTrunkFieldsMixin, LinkTemplateBase):
    """ND 4.3 service trunk.

    The schema places ``required: [speed]`` beside a reference, which OpenAPI
    3.0 ignores. Keep speed optional without synthesizing an invalid enum value.
    """

    minimum_nd_version: ClassVar[tuple[int, int] | None] = (4, 3)
    policy_type_marker: Literal["serviceTrunk"] = Field(default="serviceTrunk", exclude=True)
