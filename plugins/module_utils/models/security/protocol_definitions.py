# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pydantic models for security protocol definitions."""

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field, field_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.security.base import (
    ManageSecurityBaseModel,
    common_module_argument_spec,
    validate_numeric_port_range,
)

ProtocolType = Literal["Default", "IP", "IPv4", "IPv6"]
MatchType = Literal["any"]
TcpFlag = Literal["est", "ack", "fin", "rst", "syn"]


class ProtocolDefinitionMatchCriteriaModel(NDNestedModel):
    """Match criteria item for a security protocol definition."""

    match_name: str = Field(alias="matchName", min_length=1)
    type: ProtocolType | None = Field(default=None, alias="type")
    protocol_options: str | None = Field(default=None, alias="protocolOptions", min_length=1)
    src_port_range: str | None = Field(default=None, alias="srcPortRange")
    dst_port_range: str | None = Field(default=None, alias="dstPortRange")
    tcp_flags: TcpFlag | None = Field(default=None, alias="tcpFlags")
    only_fragments: bool | None = Field(default=None, alias="onlyFragments")
    stateful: bool | None = Field(default=None, alias="stateful")
    dscp: int | None = Field(default=None, alias="dscp", ge=0, le=63)

    @field_validator("src_port_range", "dst_port_range")
    @classmethod
    def validate_port_range(cls, value: str | None) -> str | None:
        """Reject service names and malformed port ranges."""
        return validate_numeric_port_range(value)


class SecurityProtocolDefinitionModel(ManageSecurityBaseModel):
    """Top-level security protocol definition resource."""

    exclude_from_diff: ClassVar[set[str]] = {"match_summary", "security_contract_count"}
    payload_exclude_fields: ClassVar[set[str]] = {"match_summary", "security_contract_count"}

    match_type: MatchType | None = Field(default=None, alias="matchType")
    match_items: list[ProtocolDefinitionMatchCriteriaModel] | None = Field(default=None, alias="matchItems")

    match_summary: str | None = Field(default=None, alias="matchSummary")
    security_contract_count: int | None = Field(default=None, alias="securityContractCount")

    @classmethod
    def get_argument_spec(cls) -> dict:
        """Return Ansible argument spec for nd_manage_security_protocol_definitions."""
        config_options = dict(
            name=dict(type="str", required=True),
            tenant_name=dict(type="str"),
            display_name=dict(type="str"),
            description=dict(type="str"),
            match_type=dict(type="str", choices=["any"]),
            match_items=dict(
                type="list",
                elements="dict",
                options=dict(
                    match_name=dict(type="str", required=True),
                    type=dict(type="str", choices=["Default", "IP", "IPv4", "IPv6"]),
                    protocol_options=dict(type="str"),
                    src_port_range=dict(type="str"),
                    dst_port_range=dict(type="str"),
                    tcp_flags=dict(type="str", choices=["est", "ack", "fin", "rst", "syn"]),
                    only_fragments=dict(type="bool"),
                    stateful=dict(type="bool"),
                    dscp=dict(type="int"),
                ),
            ),
        )
        return common_module_argument_spec(config_options)

