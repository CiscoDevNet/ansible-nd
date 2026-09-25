# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pydantic models for security contracts."""

from __future__ import annotations

import json
from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    ValidationInfo,
    field_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.security.base import (
    CaseInsensitiveIdentifier,
    ManageSecurityBaseModel,
    SecurityAciDataModel,
    common_module_argument_spec,
    validate_versioned_security_reference_name,
)

ContractDirection = Literal["bidirectional", "unidirectional", "custom"]
RuleDirection = Literal["bidirectional", "unidirectional"]
ContractAction = Literal["permit", "permitLog", "deny", "denyLog"]


class SecurityContractRuleModel(NDNestedModel):
    """Rule item for a security contract."""

    payload_exclude_fields: ClassVar[set[str]] = {"protocol_definition_match_summary"}
    exclude_from_diff: ClassVar[set[str]] = {"protocol_definition_match_summary"}

    rule_direction: RuleDirection = Field(alias="ruleDirection")
    action: ContractAction = Field(alias="action")
    protocol_definition_name: str = Field(alias="protocolDefinitionName", min_length=1)
    protocol_definition_match_summary: str | None = Field(default=None, alias="protocolDefinitionMatchSummary")

    @field_validator("protocol_definition_name")
    @classmethod
    def validate_protocol_definition_name(cls, value: str, info: ValidationInfo) -> str:
        """Validate a referenced protocol definition name for the target release."""
        return validate_versioned_security_reference_name(
            value,
            info,
            label="protocol_definition_name",
            max_length_42=92,
            max_length_43=102,
        )

    def to_diff_dict(self, **kwargs) -> dict[str, Any]:
        """Compare case-insensitive protocol references without changing payloads."""
        data = super().to_diff_dict(**kwargs)
        if "protocolDefinitionName" in data:
            data["protocolDefinitionName"] = data["protocolDefinitionName"].casefold()
        return data


class SecurityContractModel(ManageSecurityBaseModel):
    """Top-level security contract resource."""

    exclude_from_diff: ClassVar[set[str]] = {"security_association_count"}
    payload_exclude_fields: ClassVar[set[str]] = {"security_association_count"}

    name_max_length_42: ClassVar[int] = 92
    name_max_length_43: ClassVar[int] = 102
    name_case_sensitive: ClassVar[bool] = False
    direction: ContractDirection | None = Field(default=None, alias="direction")
    rules: list[SecurityContractRuleModel] | None = Field(default=None, alias="rules")
    aci_data: SecurityAciDataModel | None = Field(default=None, alias="aciData")
    security_association_count: int | None = Field(default=None, alias="securityAssociationCount")

    def get_identifier_value(self) -> CaseInsensitiveIdentifier:
        """Return a case-insensitive identity while retaining original spelling."""
        return CaseInsensitiveIdentifier(self.api_name)

    @field_validator("rules")
    @classmethod
    def validate_unique_rules(cls, value: list[SecurityContractRuleModel] | None) -> list[SecurityContractRuleModel] | None:
        """Enforce the OpenAPI uniqueItems contract for rules."""
        if value is None:
            return value
        seen: set[str] = set()
        for rule in value:
            canonical = json.dumps(rule.to_diff_dict(), sort_keys=True)
            if canonical in seen:
                raise ValueError("rules entries must be unique")
            seen.add(canonical)
        return value

    def to_diff_dict(self, **kwargs) -> dict[str, Any]:
        """Normalize case-insensitive names and protocol references for diffs."""
        data = super().to_diff_dict(**kwargs)
        if "name" in data:
            data["name"] = data["name"].casefold()
        if "tenantName" in data:
            data["tenantName"] = data["tenantName"].casefold()
        if self.rules is not None and "rules" in data:
            data["rules"] = [rule.to_diff_dict() for rule in self.rules]
        return data

    @classmethod
    def get_argument_spec(cls) -> dict:
        """Return Ansible argument spec for nd_manage_security_contracts."""
        config_options = dict(
            name=dict(type="str", required=True),
            tenant_name=dict(type="str"),
            display_name=dict(type="str"),
            description=dict(type="str"),
            direction=dict(type="str", choices=["bidirectional", "unidirectional", "custom"]),
            rules=dict(
                type="list",
                elements="dict",
                options=dict(
                    rule_direction=dict(
                        type="str",
                        required=True,
                        choices=["bidirectional", "unidirectional"],
                    ),
                    action=dict(
                        type="str",
                        required=True,
                        choices=["permit", "permitLog", "deny", "denyLog"],
                    ),
                    protocol_definition_name=dict(type="str", required=True),
                ),
            ),
            aci_data=dict(
                type="dict",
                options=dict(
                    subject_name=dict(type="str"),
                ),
            ),
        )
        return common_module_argument_spec(config_options)
