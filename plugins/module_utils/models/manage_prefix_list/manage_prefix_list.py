# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Pydantic models for Prefix List management (IPv4 and IPv6) via Nexus Dashboard.

This module provides a unified set of models for creating, updating, and
deleting both IPv4 and IPv6 prefix lists through the Nexus Dashboard Fabric
Controller (NDFC) Manage API.

## Models Overview

- ``PrefixListEntryModel``  - A single prefix list entry
  (sequenceNumber + action + prefix + optional length constraints)
- ``PrefixListModel``       - Complete prefix list
  (ip_version + name + entries)

## Design Notes

IPv4 and IPv6 prefix lists share the same JSON schema structure and are
distinguished solely by the ``ip_version`` field (values: ``"ipv4"`` /
``"ipv6"``). This Ansible-only field is:
  - Injected by the orchestrator during ``query_all`` (not present in API
    responses).
  - Excluded from API payloads via ``payload_exclude_fields``.
  - Used as part of the composite identifier ``(ip_version, tenant_name, name)`` so that
    IPv4, IPv6, and tenant-scoped prefix lists with the same bare name coexist in the same collection.

Entry-level validation normalizes ``prefix`` and ``mask`` spellings and checks that
they match the declared ``ip_version`` of the containing prefix list.

## Usage

```python
pl = PrefixListModel.from_config({
    "ip_version": "ipv4",
    "name": "PL-IPV4-1",
    "entries": [
        {"sequence_number": 10, "action": "permit", "prefix": "10.0.0.0/8"},
        {"sequence_number": 20, "action": "deny",   "prefix": "192.168.0.0/16",
         "min_prefix_length": 24, "max_prefix_length": 32},
    ],
})
payload = pl.to_payload()
# {"name": "PL-IPV4-1", "entries": [{"sequenceNumber": 10, "action": "permit",
#   "prefix": "10.0.0.0/8"}, ...]}
```
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_prefix_list.enums import (
    IpVersionEnum,
    PrefixListActionEnum,
)

# Allowed characters for prefix list / tenant names (from OpenAPI pattern)
_NAME_RE = re.compile(r"^[a-zA-Z0-9~_-]+$")
_TENANT_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_DEFAULT_TENANT_NAME_MAX_LENGTH = 63
_QUALIFIED_NAME_MAX_LENGTH = 115


class PrefixListEntryModel(NDNestedModel):
    """
    A single entry in a prefix list.

    Required fields: ``sequence_number``, ``action``, ``prefix``.
    Optional length constraints: ``exact_length``, ``min_prefix_length``,
    ``max_prefix_length``, ``mask``.

    Length-constraint ranges (validated at the PrefixListModel level):
    - IPv4: 1-32
    - IPv6: 1-128
    """

    sequence_number: int = Field(
        alias="sequenceNumber",
        ge=1,
        le=4294967294,
        description="Sequence number of the entry (1-4294967294).",
    )

    action: PrefixListActionEnum = Field(
        default=PrefixListActionEnum.PERMIT,
        alias="action",
        description="Action for matching prefixes: permit or deny.",
    )

    prefix: str = Field(
        alias="prefix",
        description="IP prefix in CIDR notation (e.g. '10.1.1.0/24' or '2001:db8::/32').",
    )

    exact_length: int | None = Field(
        default=None,
        alias="exactLength",
        description="Exact prefix length to match.",
    )

    # NOTE: Python field names avoid collision with Pydantic's built-in
    # ``min_length`` / ``max_length`` Field constraints.
    min_prefix_length: int | None = Field(
        default=None,
        alias="minLength",
        description="Minimum prefix length to match.",
    )

    max_prefix_length: int | None = Field(
        default=None,
        alias="maxLength",
        description="Maximum prefix length to match.",
    )

    mask: str | None = Field(
        default=None,
        alias="mask",
        description="Explicit match mask in dotted-decimal IPv4 or IPv6 address format.",
    )

    @field_validator("prefix")
    @classmethod
    def normalize_prefix(cls, value: str) -> str:
        """Normalize CIDR notation so equivalent IPv6 spellings do not cause false diffs."""
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise ValueError(f"prefix '{value}' is not a valid IP network in CIDR notation.")

    @field_validator("mask")
    @classmethod
    def normalize_mask(cls, value: str | None) -> str | None:
        """Normalize explicit match masks so equivalent IPv6 spellings do not cause false diffs."""
        if value is None:
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            raise ValueError(f"mask '{value}' is not a valid IP address.")


class PrefixListModel(NDBaseModel):
    """
    Prefix list configuration (IPv4 or IPv6) for a Nexus Dashboard fabric.

    ## Identifier

    ``composite`` strategy using ``(ip_version, tenant_name, name)``, which allows
    IPv4 and IPv6 prefix lists and tenant-scoped prefix lists with the same bare
    name to coexist in the same ``NDConfigCollection``.

    ## Serialization Notes

    - ``ip_version`` is an Ansible-only field; it is excluded from API payloads.
    - ``last_update_timestamp`` is read-only and excluded from payloads and diffs.
    - Validation ensures that ``entries[*].prefix`` and ``entries[*].mask``
      (when set) are syntactically valid CIDRs/addresses for the declared
      ``ip_version``.
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[list[str] | None] = ["ip_version", "tenant_name", "name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "composite"

    # --- Serialization Configuration ---

    exclude_from_diff: ClassVar[set[str]] = {"last_update_timestamp"}
    payload_exclude_fields: ClassVar[set[str]] = {"ip_version", "last_update_timestamp"}
    unwanted_keys: ClassVar[list] = []

    # --- Fields ---

    ip_version: IpVersionEnum = Field(
        alias="ipVersion",
        description="IP version of this prefix list: 'ipv4' or 'ipv6'. " "This is an Ansible-only field and is not sent to the API.",
    )

    name: str = Field(
        alias="name",
        min_length=1,
        max_length=115,
        description="Name of the prefix list (pattern: ^[a-zA-Z0-9~_-]+$).",
    )

    description: AsciiDescription = Field(
        default=None,
        alias="description",
        max_length=90,
        description="Description of the prefix list.",
    )

    last_update_timestamp: str | None = Field(
        default=None,
        alias="lastUpdateTimestamp",
        description="Timestamp of the last update (read-only, set by ND).",
    )

    tenant_name: str | None = Field(
        default=None,
        alias="tenantName",
        max_length=63,
        description="Name of the tenant (pattern: ^[A-Za-z0-9_-]+$).",
    )

    entries: list[PrefixListEntryModel] | None = Field(
        default=None,
        alias="entries",
        description="List of prefix list entries.",
    )

    @property
    def api_name(self) -> str:
        """Return the name format required by item and bulk-delete endpoints."""
        if self.tenant_name:
            return f"{self.tenant_name}~{self.name}"
        return self.name

    # --- Field Validators ---

    @model_validator(mode="before")
    @classmethod
    def normalize_tenant_scoped_name(cls, data: Any) -> Any:
        """
        Normalize API-returned tenant-scoped names from ``tenant~name`` to the
        Ansible-facing bare ``name`` plus ``tenant_name`` field.
        """
        if not isinstance(data, dict):
            return data
        tenant_name = data.get("tenantName", data.get("tenant_name"))
        name = data.get("name")
        if isinstance(tenant_name, str) and isinstance(name, str):
            prefix = f"{tenant_name}~"
            if name.startswith(prefix):
                data = dict(data)
                data["name"] = name[len(prefix) :]
        return data

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        """Enforce API name pattern: ^[a-zA-Z0-9~_-]+$."""
        if not _NAME_RE.match(value):
            raise ValueError(f"Prefix list name '{value}' is invalid. " "Only alphanumeric characters and '~', '_', '-' are allowed.")
        return value

    @field_validator("tenant_name")
    @classmethod
    def validate_tenant_name(cls, value: str | None) -> str | None:
        """Enforce tenant name pattern: ^[A-Za-z0-9_-]+$."""
        if value is not None and not _TENANT_RE.match(value):
            raise ValueError(f"Tenant name '{value}' is invalid. " "Only alphanumeric characters, '_', and '-' are allowed.")
        return value

    # --- Model Validators (cross-field) ---

    @model_validator(mode="after")
    def validate_name_length_for_tenant_scope(self) -> "PrefixListModel":
        """
        Enforce the API's default-tenant and tenant-qualified prefix-list name lengths.

        The OpenAPI schema caps the path/body ``prefixListName`` at 115 characters
        but documents a stricter 63-character limit for names in the default tenant.
        Tenant-scoped item paths use the qualified ``tenantName~name`` form, so the
        combined value must also fit the 115-character endpoint field.
        """
        if self.tenant_name is None and len(self.name) > _DEFAULT_TENANT_NAME_MAX_LENGTH:
            raise ValueError(f"name must be {_DEFAULT_TENANT_NAME_MAX_LENGTH} characters or fewer when tenant_name is omitted; got {len(self.name)}.")
        if self.tenant_name is not None and len(self.api_name) > _QUALIFIED_NAME_MAX_LENGTH:
            raise ValueError(
                f"combined tenant-qualified prefix list name '{self.api_name}' must be {_QUALIFIED_NAME_MAX_LENGTH} characters or fewer; "
                f"got {len(self.api_name)} from tenant_name length {len(self.tenant_name)} and name length {len(self.name)}."
            )
        return self

    @model_validator(mode="after")
    def validate_entries_for_ip_version(self) -> "PrefixListModel":
        """
        Validate that every entry's ``prefix`` and ``mask`` (when set) are
        syntactically correct for the declared ``ip_version``, and that
        length constraints are within the valid range.
        """
        version = str(self.ip_version)
        max_len = 32 if version == "ipv4" else 128
        entries = self.entries or []
        seen_sequence_numbers = set()

        for idx, entry in enumerate(entries):
            if entry.sequence_number in seen_sequence_numbers:
                raise ValueError(
                    f"entries[{idx}].sequenceNumber '{entry.sequence_number}' is duplicated. Sequence numbers must be unique within a prefix list."
                )
            seen_sequence_numbers.add(entry.sequence_number)

            # Validate prefix CIDR
            try:
                network = ipaddress.ip_network(entry.prefix, strict=False)
            except ValueError:
                raise ValueError(f"entries[{idx}].prefix '{entry.prefix}' is not a valid IP network in CIDR notation.")
            if version == "ipv4" and not isinstance(network, ipaddress.IPv4Network):
                raise ValueError(f"entries[{idx}].prefix '{entry.prefix}' must be an IPv4 CIDR (ip_version='ipv4').")
            if version == "ipv6" and not isinstance(network, ipaddress.IPv6Network):
                raise ValueError(f"entries[{idx}].prefix '{entry.prefix}' must be an IPv6 CIDR (ip_version='ipv6').")

            # Validate mask (when present)
            if entry.mask is not None:
                try:
                    addr = ipaddress.ip_address(entry.mask)
                except ValueError:
                    raise ValueError(f"entries[{idx}].mask '{entry.mask}' is not a valid IP address.")
                if version == "ipv4" and not isinstance(addr, ipaddress.IPv4Address):
                    raise ValueError(f"entries[{idx}].mask '{entry.mask}' must be an IPv4 address (ip_version='ipv4').")
                if version == "ipv6" and not isinstance(addr, ipaddress.IPv6Address):
                    raise ValueError(f"entries[{idx}].mask '{entry.mask}' must be an IPv6 address (ip_version='ipv6').")

            # Validate length constraints
            for field_name, label in [
                ("exact_length", "exactLength"),
                ("min_prefix_length", "minLength"),
                ("max_prefix_length", "maxLength"),
            ]:
                val = getattr(entry, field_name, None)
                if val is not None and not (1 <= val <= max_len):
                    raise ValueError(f"entries[{idx}].{label}={val} is out of range " f"(1-{max_len} for ip_version='{version}').")

            if entry.exact_length is not None and (entry.min_prefix_length is not None or entry.max_prefix_length is not None):
                raise ValueError(
                    f"entries[{idx}] cannot define exactLength together with minLength/maxLength. "
                    "Use exactLength alone, or use minLength/maxLength without exactLength."
                )

            if entry.min_prefix_length is not None and entry.max_prefix_length is not None:
                if entry.min_prefix_length > entry.max_prefix_length:
                    raise ValueError(
                        f"entries[{idx}].minLength={entry.min_prefix_length} cannot be greater than entries[{idx}].maxLength={entry.max_prefix_length}."
                    )

        return self

    # --- Argument Spec ---

    def get_identifier_value(self) -> tuple[str, str | None, str]:
        """Return the tenant-aware composite identifier."""
        return (str(self.ip_version), self.tenant_name, self.name)

    def get_diff(self, other: NDBaseModel, exclude_unset: bool = False) -> bool:
        """
        Compare prefix-list config, treating omitted description as empty in replace-style states.

        ``NDStateMachine`` calls this with ``exclude_unset=True`` for ``merged``,
        where omitted fields must be left untouched. For ``replaced`` and
        ``overridden`` it passes ``exclude_unset=False``; in that path an omitted
        description means the desired value is empty/absent, so a stale controller
        description must trigger an update.
        """
        if not exclude_unset and isinstance(other, PrefixListModel):
            if other.description is None and self.description not in (None, ""):
                return False
        return super().get_diff(other, exclude_unset=exclude_unset)

    @classmethod
    def validate_config_for_state(cls, config: list[dict[str, Any]], state: str) -> None:
        """Validate state-dependent requirements that cannot be expressed in a static Ansible argspec."""
        if state not in {"merged", "replaced", "overridden"}:
            return
        for index, item in enumerate(config or []):
            entries = item.get("entries") if isinstance(item, dict) else None
            if not entries:
                raise ValueError(f"config[{index}].entries is required and must contain at least one entry when state is '{state}'.")

    @classmethod
    def get_argument_spec(cls) -> dict[str, Any]:
        return dict(
            fabric_name=dict(
                type="str",
                required=True,
            ),
            cluster_name=dict(
                type="str",
                required=False,
            ),
            config=dict(
                type="list",
                elements="dict",
                required=True,
                options=dict(
                    ip_version=dict(
                        type="str",
                        required=True,
                        choices=["ipv4", "ipv6"],
                        aliases=["ipVersion"],
                    ),
                    name=dict(
                        type="str",
                        required=True,
                    ),
                    description=dict(
                        type="str",
                    ),
                    tenant_name=dict(
                        type="str",
                        aliases=["tenantName"],
                    ),
                    entries=dict(
                        type="list",
                        elements="dict",
                        required=False,
                        options=dict(
                            sequence_number=dict(
                                type="int",
                                required=True,
                                aliases=["sequenceNumber"],
                            ),
                            action=dict(
                                type="str",
                                required=False,
                                choices=["permit", "deny"],
                            ),
                            prefix=dict(
                                type="str",
                                required=True,
                            ),
                            exact_length=dict(
                                type="int",
                                aliases=["exactLength"],
                            ),
                            min_prefix_length=dict(
                                type="int",
                                aliases=["minLength"],
                            ),
                            max_prefix_length=dict(
                                type="int",
                                aliases=["maxLength"],
                            ),
                            mask=dict(
                                type="str",
                            ),
                        ),
                    ),
                ),
            ),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "replaced", "overridden", "deleted"],
            ),
        )
