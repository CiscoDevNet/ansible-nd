# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pydantic models for security protocol definitions."""

from __future__ import annotations

import json
import re
from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field, ValidationInfo, field_validator, model_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.security.base import (
    CaseInsensitiveIdentifier,
    ManageSecurityBaseModel,
    common_module_argument_spec,
    controller_version_at_least,
    controller_version_major_minor,
    validate_versioned_security_name,
    validate_numeric_port_range,
)

ProtocolType = Literal["Default", "IP", "IPv4", "IPv6"]
MatchType = Literal["any"]
TcpFlag = str

TCP_FLAG_CHOICES = ("est", "ack", "fin", "rst", "syn")
_MATCH_NAME_42_RE = re.compile(r"^[A-Za-z0-9.~_-]+$")
_MATCH_NAME_43_RE = re.compile(r"^[A-Za-z0-9.:_-]+$")


class ProtocolDefinitionMatchCriteriaModel(NDNestedModel):
    """Match criteria item for a security protocol definition."""

    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        "onlyFragments": False,
        "stateful": False,
    }

    match_name: str = Field(alias="matchName", min_length=1, max_length=64)
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

    @field_validator("match_name")
    @classmethod
    def validate_match_name(cls, value: str, info: ValidationInfo) -> str:
        """Validate the release-specific protocol match-name character set."""
        return validate_versioned_security_name(
            value,
            info,
            label="protocol match name",
            max_length_42=64,
            max_length_43=64,
            pattern_42=_MATCH_NAME_42_RE,
            pattern_43=_MATCH_NAME_43_RE,
        )

    @field_validator("tcp_flags")
    @classmethod
    def validate_tcp_flags(cls, value: str | None, info: ValidationInfo) -> str | None:
        """Validate single ND 4.2 flags and ND 4.3 semicolon combinations."""
        if value is None:
            return value
        flags = value.split(";")
        invalid = [flag for flag in flags if flag not in TCP_FLAG_CHOICES]
        if invalid:
            raise ValueError(f"tcp_flags contains unsupported flag(s): {', '.join(invalid)}")
        if len(flags) != len(set(flags)):
            raise ValueError("tcp_flags must not contain duplicate flags")
        if "est" in flags and len(flags) > 1:
            raise ValueError("tcp_flags value 'est' must be used by itself")
        is_response = (info.context or {}).get("mode") == "response"
        if len(flags) > 1 and not is_response and not controller_version_at_least(info, (4, 3)):
            raise ValueError("multiple tcp_flags require ND 4.3 or later")
        return value

    def to_diff_dict(self, **kwargs) -> dict[str, Any]:
        """Normalize false values that ND echoes for omitted boolean options."""
        data = super().to_diff_dict(**kwargs)
        for alias, default in self.reverse_diff_defaults.items():
            if data.get(alias) is default:
                data.pop(alias)
        return data


class SecurityProtocolDefinitionModel(ManageSecurityBaseModel):
    """Top-level security protocol definition resource."""

    exclude_from_diff: ClassVar[set[str]] = {"match_summary", "security_contract_count"}
    payload_exclude_fields: ClassVar[set[str]] = {"match_summary", "security_contract_count"}

    name_max_length_42: ClassVar[int] = 92
    name_max_length_43: ClassVar[int] = 102
    name_case_sensitive: ClassVar[bool] = False
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {"matchType": "any"}

    match_type: MatchType | None = Field(default=None, alias="matchType")
    match_items: list[ProtocolDefinitionMatchCriteriaModel] | None = Field(default=None, alias="matchItems")

    match_summary: str | None = Field(default=None, alias="matchSummary")
    security_contract_count: int | None = Field(default=None, alias="securityContractCount")

    def get_identifier_value(self) -> CaseInsensitiveIdentifier:
        """Return a case-insensitive identity while retaining original spelling."""
        return CaseInsensitiveIdentifier(self.api_name)

    @model_validator(mode="after")
    def validate_nd42_default_tenant_name_limit(self, info: ValidationInfo) -> "SecurityProtocolDefinitionModel":
        """Apply the live ND 4.2 default-tenant limit to write operations."""
        context = info.context or {}
        if context.get("mode") == "response" or context.get("state") in {"deleted", "gathered"}:
            return self
        if controller_version_major_minor(info) == (4, 2) and self.tenant_name is None and len(self.name) > 20:
            raise ValueError("security protocol definition name must be at most 20 characters on ND 4.2 when tenant_name is omitted")
        return self

    @field_validator("match_items")
    @classmethod
    def validate_unique_match_items(cls, value: list[ProtocolDefinitionMatchCriteriaModel] | None) -> list[ProtocolDefinitionMatchCriteriaModel] | None:
        """Enforce the OpenAPI uniqueItems contract for match criteria."""
        if value is None:
            return value
        seen: set[str] = set()
        for match_item in value:
            canonical = json.dumps(match_item.to_payload(), sort_keys=True)
            if canonical in seen:
                raise ValueError("match_items entries must be unique")
            seen.add(canonical)
        return value

    def to_diff_dict(self, **kwargs) -> dict[str, Any]:
        """Normalize the case-insensitive definition name for comparisons."""
        data = super().to_diff_dict(**kwargs)
        if "name" in data:
            data["name"] = data["name"].casefold()
        if "tenantName" in data:
            data["tenantName"] = data["tenantName"].casefold()
        if self.match_items is not None and "matchItems" in data:
            data["matchItems"] = [match_item.to_diff_dict() for match_item in self.match_items]
        return data

    def _scrub_reverse_diff_dict(self, data: dict[str, Any]) -> None:
        """Apply nested OpenAPI defaults inside the match-items list."""
        super()._scrub_reverse_diff_dict(data)
        serialized_items = data.get("matchItems")
        if not isinstance(serialized_items, list) or self.match_items is None:
            return
        for match_item, serialized_item in zip(self.match_items, serialized_items):
            if isinstance(serialized_item, dict):
                match_item._scrub_reverse_diff_dict(serialized_item)  # pylint: disable=protected-access

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
                    tcp_flags=dict(type="str"),
                    only_fragments=dict(type="bool"),
                    stateful=dict(type="bool"),
                    dscp=dict(type="int"),
                ),
            ),
        )
        return common_module_argument_spec(config_options)
