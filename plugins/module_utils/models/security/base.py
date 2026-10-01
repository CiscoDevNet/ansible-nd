# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Shared models and argument-spec helpers for security resources."""

from __future__ import annotations

import re
from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field, ValidationInfo, field_validator, model_validator
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.argument_spec import config_actions_spec
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import SECURITY_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel

SecurityState = Literal["merged", "replaced", "overridden", "deleted", "gathered"]

STATE_CHOICES = ["merged", "replaced", "overridden", "deleted", "gathered"]

_SECURITY_RESOURCE_NAME_RE = re.compile(r"^[A-Za-z0-9.:~_-]+$")
_DISPLAY_NAME_RE = re.compile(r"^[A-Za-z0-9.:_~-]+$")
_TENANT_NAME_42_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_TENANT_NAME_43_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_DEFAULT_TENANT_RESOURCE_NAME_MAX_LENGTH = 63


class CaseInsensitiveIdentifier(str):
    """Case-insensitive model key that retains its spelling for wire use.

    Equality is deliberately limited to this key type.  Comparing case-insensitively
    with an ordinary ``str`` would violate Python's hash contract whenever that
    string contains uppercase characters: equal objects must have equal hashes.
    The security orchestrator creates this key type on both sides of every identity
    comparison, while its existing ``str(identifier)`` calls retain the original
    spelling for endpoint and action payloads.
    """

    def __hash__(self) -> int:
        """Hash names using the same case-insensitive form used for equality."""
        return hash(self.casefold())

    def __eq__(self, other: object) -> bool:
        """Compare string identifiers without changing their wire spelling."""
        if not isinstance(other, CaseInsensitiveIdentifier):
            return False
        return self.casefold() == other.casefold()

    def __ne__(self, other: object) -> bool:
        """Keep inequality consistent with case-insensitive equality."""
        equal = self.__eq__(other)
        if equal is NotImplemented:
            return NotImplemented
        return not equal


def controller_version_major_minor(info: ValidationInfo | None) -> tuple[int, int] | None:
    """Return ``(major, minor)`` from validation context, or ``None`` when unknown."""
    context = (info.context or {}) if info is not None else {}
    raw_version = context.get("controller_version")
    if not raw_version:
        return None
    match = re.match(r"^\s*(\d+)\.(\d+)", str(raw_version))
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)))


def controller_version_at_least(info: ValidationInfo | None, target: tuple[int, int]) -> bool:
    """Return whether validation context identifies an ND release at or above ``target``.

    Security models deliberately do not discover controller versions.  The module
    runner supplies ``controller_version`` in Pydantic validation context; absent or
    malformed versions use the older, more conservative contract.
    """
    version = controller_version_major_minor(info)
    return version is not None and version >= target


def validate_versioned_security_name(
    value: str,
    info: ValidationInfo | None,
    *,
    label: str,
    max_length_42: int,
    max_length_43: int,
    pattern_42: re.Pattern[str] = _SECURITY_RESOURCE_NAME_RE,
    pattern_43: re.Pattern[str] = _SECURITY_RESOURCE_NAME_RE,
) -> str:
    """Validate an ND security name against the active 4.2 or 4.3 contract."""
    context = (info.context or {}) if info is not None else {}
    version = controller_version_major_minor(info)
    if version is None and context.get("mode") == "response":
        max_length = max(max_length_42, max_length_43)
        patterns = (pattern_42, pattern_43)
    else:
        is_43_or_later = version is not None and version >= (4, 3)
        max_length = max_length_43 if is_43_or_later else max_length_42
        patterns = (pattern_43,) if is_43_or_later else (pattern_42,)
    if len(value) > max_length:
        raise ValueError(f"{label} must be at most {max_length} characters")
    if not any(pattern.fullmatch(value) is not None for pattern in patterns):
        raise ValueError(f"{label} cannot contain characters outside the ND security-name character set")
    return value


def validate_versioned_security_reference_name(
    value: str,
    info: ValidationInfo | None,
    *,
    label: str,
    max_length_42: int,
    max_length_43: int,
) -> str:
    """Validate a bare or tenant-qualified security resource reference."""
    value = validate_versioned_security_name(
        value,
        info,
        label=label,
        max_length_42=max_length_42,
        max_length_43=max_length_43,
    )
    if "~" not in value:
        if len(value) > _DEFAULT_TENANT_RESOURCE_NAME_MAX_LENGTH:
            raise ValueError(f"{label} must be at most {_DEFAULT_TENANT_RESOURCE_NAME_MAX_LENGTH} characters when unqualified")
        return value

    if value.count("~") != 1:
        raise ValueError(f"{label} must use tenantName~resourceName format when tenant-qualified")
    tenant_name, resource_name = value.split("~", 1)
    if not tenant_name or not resource_name:
        raise ValueError(f"{label} must use tenantName~resourceName format when tenant-qualified")
    context = (info.context or {}) if info is not None else {}
    pattern = _TENANT_NAME_43_RE if controller_version_at_least(info, (4, 3)) or context.get("mode") == "response" else _TENANT_NAME_42_RE
    if pattern.fullmatch(tenant_name) is None:
        raise ValueError(f"{label} contains a tenant qualifier unsupported by the target ND release")
    return value


class SecurityAciDataModel(NDNestedModel):
    """ACI integration data shared by security group and contract resources."""

    application_profile_name: str | None = Field(default=None, alias="applicationProfileName")
    subject_name: str | None = Field(default=None, alias="subjectName")


class ManageSecurityBaseModel(NDBaseModel):
    """Base model for fabric-scoped security resources identified by name."""

    identifiers: ClassVar[list[str] | None] = ["api_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"

    exclude_from_diff: ClassVar[set[str]] = set()
    payload_exclude_fields: ClassVar[set[str]] = set()

    name_max_length_42: ClassVar[int] = 128
    name_max_length_43: ClassVar[int] = 128
    name_unqualified_max_length: ClassVar[int] = _DEFAULT_TENANT_RESOURCE_NAME_MAX_LENGTH
    name_case_sensitive: ClassVar[bool] = True

    name: str = Field(min_length=1)
    tenant_name: str | None = Field(default=None, alias="tenantName", min_length=1, max_length=63)
    display_name: str | None = Field(default=None, alias="displayName", min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=128)

    @property
    def api_name(self) -> str:
        """Return the tenant-qualified name used by ND paths and payloads."""
        if self.tenant_name:
            return f"{self.tenant_name}~{self.name}"
        return self.name

    @model_validator(mode="before")
    @classmethod
    def normalize_tenant_scoped_name(cls, data: Any) -> Any:
        """Store qualified wire names as a bare name plus tenant_name."""
        if not isinstance(data, dict):
            return data
        normalized = dict(data)
        tenant_name = normalized.get("tenantName", normalized.get("tenant_name"))
        if tenant_name == "":
            tenant_name = None
            normalized.pop("tenantName", None)
            normalized.pop("tenant_name", None)
        name = normalized.get("name")
        if not isinstance(name, str) or "~" not in name:
            return normalized
        if name.count("~") != 1:
            raise ValueError("name must use tenantName~resourceName format when tenant-qualified")
        qualifier, bare_name = name.split("~", 1)
        if not qualifier or not bare_name:
            raise ValueError("name must use tenantName~resourceName format when tenant-qualified")
        if tenant_name is not None:
            qualifiers_match = qualifier == tenant_name
            if not cls.name_case_sensitive:
                qualifiers_match = qualifier.casefold() == str(tenant_name).casefold()
            if not qualifiers_match:
                raise ValueError("name tenant qualifier must match tenant_name")
        normalized["name"] = bare_name
        normalized["tenantName"] = qualifier
        normalized.pop("tenant_name", None)
        return normalized

    @field_validator("name")
    @classmethod
    def validate_resource_name(cls, value: str, info: ValidationInfo) -> str:
        """Validate the resource name using release-specific maximum lengths."""
        return validate_versioned_security_name(
            value,
            info,
            label="security resource name",
            max_length_42=cls.name_max_length_42,
            max_length_43=cls.name_max_length_43,
        )

    @model_validator(mode="after")
    def validate_name_for_tenant_scope(self, info: ValidationInfo) -> "ManageSecurityBaseModel":
        """Enforce default-tenant and release-specific qualified-name limits."""
        if self.tenant_name is None:
            if len(self.name) > self.name_unqualified_max_length:
                raise ValueError(f"security resource name must be at most {self.name_unqualified_max_length} characters when tenant_name is omitted")
            return self
        validate_versioned_security_name(
            self.api_name,
            info,
            label="tenant-qualified security resource name",
            max_length_42=self.name_max_length_42,
            max_length_43=self.name_max_length_43,
        )
        return self

    @field_validator("tenant_name")
    @classmethod
    def validate_tenant_name(cls, value: str | None, info: ValidationInfo) -> str | None:
        """Validate the tenant name, including ND 4.3 support for dots."""
        if value is None:
            return value
        context = info.context or {}
        pattern = _TENANT_NAME_43_RE if controller_version_at_least(info, (4, 3)) or context.get("mode") == "response" else _TENANT_NAME_42_RE
        if pattern.fullmatch(value) is None:
            raise ValueError("tenant_name contains characters unsupported by the target ND release")
        return value

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str | None) -> str | None:
        """Validate the shared security resource display-name character set."""
        if value is not None and _DISPLAY_NAME_RE.fullmatch(value) is None:
            raise ValueError("display_name contains unsupported characters")
        return value

    @field_validator("description", mode="before")
    @classmethod
    def validate_description(cls, value: Any, info: ValidationInfo) -> Any:
        """Reject CR/LF for ND 4.3 while retaining the ND 4.2 wire contract."""
        if value is None or not isinstance(value, str):
            return value
        if (info.context or {}).get("mode") == "response":
            return value
        # Unknown versions take the stricter 4.3-compatible path.  A confirmed
        # 4.2 controller may use the older schema, which has no newline pattern.
        version = controller_version_major_minor(info)
        is_confirmed_42 = version is not None and version < (4, 3)
        if not is_confirmed_42 and ("\r" in value or "\n" in value):
            raise ValueError("description must not contain carriage-return or newline characters on ND 4.3 or later")
        return value

    def to_payload(self, **kwargs) -> dict[str, Any]:
        """Convert to API form, qualifying tenant-scoped resource names."""
        data = super().to_payload(**kwargs)
        data["name"] = self.api_name
        return data

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
    return config_actions_spec(SECURITY_CONFIG_ACTIONS)["config_actions"]


def common_module_argument_spec(config_options: dict[str, Any]) -> dict[str, Any]:
    """Return the shared module argument spec wrapper around a resource config spec."""
    return dict(
        fabric_name=dict(type="str", required=True),
        cluster_name=dict(type="str"),
        config=dict(
            type="list",
            elements="dict",
            required=False,
            options=config_options,
        ),
        config_actions=config_actions_argument_spec(),
        state=dict(
            type="str",
            default="merged",
            choices=STATE_CHOICES,
        ),
    )


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
