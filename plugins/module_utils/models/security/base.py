# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Shared models and argument-spec helpers for security resources."""

from __future__ import annotations

import re
from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field, model_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription


SecurityState = Literal["merged", "replaced", "overridden", "deleted"]
ConfigActionType = Literal["switch", "global"]

STATE_CHOICES = ["merged", "replaced", "overridden", "deleted"]
CONFIG_ACTION_TYPE_CHOICES = ["switch", "global"]


class ConfigActionsModel(NDNestedModel):
    """Save and deploy controls used by security modules."""

    save: bool = Field(default=True, description="Save or recalculate the fabric configuration after updates")
    deploy: bool = Field(default=True, description="Deploy pending configuration after updates")
    type: ConfigActionType = Field(default="switch", description="Deploy operation scope")

    @model_validator(mode="after")
    def validate_save_deploy_dependency(self) -> "ConfigActionsModel":
        """Require save when deploy is enabled."""
        if self.deploy and not self.save:
            raise ValueError("config_actions.deploy=true requires config_actions.save=true")
        return self


class SecurityAciDataModel(NDNestedModel):
    """ACI integration data shared by security group and contract resources."""

    application_profile_name: str | None = Field(default=None, alias="applicationProfileName")
    subject_name: str | None = Field(default=None, alias="subjectName")


class ManageSecurityBaseModel(NDBaseModel):
    """Base model for fabric-scoped security resources identified by name."""

    identifiers: ClassVar[list[str] | None] = ["name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"

    exclude_from_diff: ClassVar[set[str]] = set()
    payload_exclude_fields: ClassVar[set[str]] = set()

    name: str = Field(min_length=1)
    tenant_name: str | None = Field(default=None, alias="tenantName", min_length=1)
    display_name: str | None = Field(default=None, alias="displayName", min_length=1)
    description: AsciiDescription = Field(default=None, min_length=1)

    @classmethod
    def required_payload_fields(cls) -> tuple[str, ...]:
        """Return model field names that are required when creating a resource."""
        return ()

    def validate_required_payload_fields(self) -> None:
        """Validate create/update fields that are optional for delete-friendly argspecs."""
        missing = [field_name for field_name in self.required_payload_fields() if getattr(self, field_name, None) in (None, [], {})]
        if missing:
            raise ValueError(f"{self.name}: missing required field(s) for create/update: {', '.join(missing)}")


def config_actions_argument_spec() -> dict[str, Any]:
    """Return the shared config_actions Ansible argument spec."""
    return dict(
        type="dict",
        options=dict(
            save=dict(type="bool", default=True),
            deploy=dict(type="bool", default=True),
            type=dict(type="str", default="switch", choices=CONFIG_ACTION_TYPE_CHOICES),
        ),
        default=dict(save=True, deploy=True, type="switch"),
    )


def common_module_argument_spec(config_options: dict[str, Any]) -> dict[str, Any]:
    """Return the shared module argument spec wrapper around a resource config spec."""
    return dict(
        fabric_name=dict(type="str", required=True),
        cluster_name=dict(type="str"),
        config=dict(
            type="list",
            elements="dict",
            required=True,
            options=config_options,
        ),
        config_actions=config_actions_argument_spec(),
        state=dict(
            type="str",
            default="merged",
            choices=STATE_CHOICES,
        ),
    )


def validate_config_actions_dict(config_actions: dict[str, Any] | None) -> ConfigActionsModel:
    """Validate and normalize a config_actions dict."""
    return ConfigActionsModel.model_validate(config_actions or {})


_PORT_RANGE_RE = re.compile(r"^(?P<first>\d{1,5})(?:-(?P<last>\d{1,5}))?$")


def validate_numeric_port_range(value: str | None) -> str | None:
    """Validate a numeric port or inclusive numeric port range."""
    if value is None:
        return value
    match = _PORT_RANGE_RE.match(str(value))
    if match is None:
        raise ValueError(f"port range must be a numeric port or range such as '80' or '80-90': {value!r}")
    first = int(match.group("first"))
    last = int(match.group("last") or first)
    if first > 65535 or last > 65535:
        raise ValueError("port range values must be between 0 and 65535")
    if first > last:
        raise ValueError("port range start must be less than or equal to the range end")
    return str(value)

