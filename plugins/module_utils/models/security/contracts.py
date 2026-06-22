# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pydantic models for security contracts."""

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.security.base import ManageSecurityBaseModel, SecurityAciDataModel, common_module_argument_spec

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


class SecurityContractModel(ManageSecurityBaseModel):
    """Top-level security contract resource."""

    exclude_from_diff: ClassVar[set[str]] = {"security_association_count"}
    payload_exclude_fields: ClassVar[set[str]] = {"security_association_count"}

    direction: ContractDirection | None = Field(default=None, alias="direction")
    rules: list[SecurityContractRuleModel] | None = Field(default=None, alias="rules")
    aci_data: SecurityAciDataModel | None = Field(default=None, alias="aciData")
    security_association_count: int | None = Field(default=None, alias="securityAssociationCount")

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
                    rule_direction=dict(type="str", required=True, choices=["bidirectional", "unidirectional"]),
                    action=dict(type="str", required=True, choices=["permit", "permitLog", "deny", "denyLog"]),
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

