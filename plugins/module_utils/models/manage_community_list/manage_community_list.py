# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Pydantic models for the nd_manage_community_list module.

Community lists come in two flavours that share the same top-level schema but
differ in their entry structure:

- **standard** - entries may reference well-known communities (noAdvertise,
  blackhole, noExport, internet, gracefulShutdown, localAsn) and/or explicit
  community numbers in ASN:NN format (communityNumbers).
- **expanded** - entries match communities via a regular expression
  (communityNumberRegex, required).

A single flat ``CommunityListEntryModel`` covers both flavours.  A
``model_validator`` on ``CommunityListModel`` enforces the type-specific
entry constraints.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_community_list.enums import (
    CommunityListTypeEnum,
    CommunityListActionEnum,
)

# Regex: ASN:NN where each part is 0-65535
_COMMUNITY_NUMBER_RE = re.compile(
    r"^(0|[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])"
    r":"
    r"(0|[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$"
)

# Regex for expanded community-list entries: must not start with [a-zA-Z~!#%@`;]
_COMMUNITY_REGEX_RE = re.compile(r"^[^a-zA-Z~!#%@`;].*$")
DEFAULT_TENANT_COMMUNITY_LIST_NAME_MAX_LENGTH = 63
TENANT_COMMUNITY_LIST_API_NAME_MAX_LENGTH = 115
_STANDARD_FALSE_DEFAULT_ALIASES = (
    "noAdvertise",
    "blackhole",
    "noExport",
    "internet",
    "gracefulShutdown",
    "localAsn",
)


class CommunityListEntryModel(NDNestedModel):
    """
    A single entry inside a community list.

    For **standard** community lists the entry may set any combination of:
    - ``no_advertise``, ``blackhole``, ``no_export``, ``internet``,
      ``graceful_shutdown``, ``local_asn`` (well-known community flags)
    - ``community_numbers`` (list of ASN:NN strings)

    For **expanded** community lists the entry must set:
    - ``community_number_regex`` (regular-expression string, required)
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="ignore",
    )

    # --- Required fields (both standard and expanded) ---
    sequence_number: int = Field(
        alias="sequenceNumber",
        description="Sequence number of the entry (1-4294967294).",
        ge=1,
        le=4294967294,
    )
    action: CommunityListActionEnum = Field(
        alias="action",
        description="Permit or deny operation.",
    )

    # --- Standard-only: well-known community flags ---
    no_advertise: bool | None = Field(
        default=None,
        alias="noAdvertise",
        description=("Do not advertise the route to any iBGP or eBGP neighbors " "(well-known community 65535:65282)."),
    )
    blackhole: bool | None = Field(
        default=None,
        alias="blackhole",
        description=("Used to drop traffic to a specified destination " "(well-known community 65535:666)."),
    )
    no_export: bool | None = Field(
        default=None,
        alias="noExport",
        description="Do not export to next AS (well-known community).",
    )
    internet: bool | None = Field(
        default=None,
        alias="internet",
        description="Internet (well-known community).",
    )
    graceful_shutdown: bool | None = Field(
        default=None,
        alias="gracefulShutdown",
        description="Graceful shutdown (well-known community).",
    )
    local_asn: bool | None = Field(
        default=None,
        alias="localAsn",
        description=(
            "Do not advertise the route to an iBGP neighbor if the route " "is received from another iBGP neighbor " "(well-known community 65535:65284)."
        ),
    )
    community_numbers: list[str] | None = Field(
        default=None,
        alias="communityNumbers",
        description="List of community numbers in ASN:NN format (0-65535:0-65535).",
    )

    # --- Expanded-only ---
    community_number_regex: str | None = Field(
        default=None,
        alias="communityNumberRegex",
        description=("Regular expression in aa:nn format for matching community strings. " "Max length 63. Must not start with [a-zA-Z~!#%@`;]."),
        max_length=63,
    )

    @field_validator("community_numbers", mode="before")
    @classmethod
    def validate_community_numbers(cls, v):
        """Validate each community number matches ASN:NN format (0-65535:0-65535)."""
        if v is None:
            return v
        for num in v:
            if not _COMMUNITY_NUMBER_RE.match(str(num)):
                raise ValueError(f"community_numbers entry '{num}' must be in ASN:NN format " "(each part 0-65535).")
        return v

    @field_validator("community_number_regex", mode="before")
    @classmethod
    def validate_community_number_regex(cls, v):
        """Validate communityNumberRegex does not start with a disallowed character."""
        if v is None:
            return v
        if not _COMMUNITY_REGEX_RE.match(str(v)):
            raise ValueError(f"community_number_regex '{v}' must not start with " "[a-zA-Z~!#%@`;].")
        return v


class CommunityListModel(NDBaseModel):
    """
    Model for a Nexus Dashboard community list resource.

    Supports both **standard** and **expanded** types; the ``type`` field
    discriminates between them and a ``model_validator`` enforces the
    type-specific entry constraints.

    Identifier strategy: ``single`` on the fully qualified ``api_name``.
    """

    identifiers: ClassVar[list[str] | None] = ["api_name"]
    identifier_strategy: ClassVar[str] = "single"

    # Read-only timestamp excluded from payloads and diffs
    exclude_from_diff: ClassVar[set[str]] = {"last_update_timestamp"}
    payload_exclude_fields: ClassVar[set[str]] = {"last_update_timestamp"}

    # Strip any summary-only keys that appear in the list response but are
    # not part of the full item schema
    unwanted_keys: ClassVar[list[str]] = [
        "numberOfEntries",
        "numberOfAssociations",
        "associations",
    ]

    # --- Fields ---
    name: str = Field(
        alias="name",
        description=(
            "Name of the community list. Allowed characters: [a-zA-Z0-9~_-]. "
            "Max 63 characters for the default tenant, 115 when using a "
            "non-default tenant."
        ),
        min_length=1,
        max_length=115,
    )
    type: CommunityListTypeEnum | None = Field(
        default=None,
        alias="type",
        description="Type of community list: standard or expanded.",
    )
    last_update_timestamp: str | None = Field(
        default=None,
        alias="lastUpdateTimestamp",
        description="Timestamp of the last update (read-only, set by the API).",
    )
    tenant_name: str | None = Field(
        default=None,
        alias="tenantName",
        description=("Name of the tenant that owns this community list. " "Allowed characters: [A-Za-z0-9_-]. Max 63 characters."),
        max_length=63,
    )
    entries: list[CommunityListEntryModel] | None = Field(
        default=None,
        alias="entries",
        description="Collection of community list entries.",
        min_length=1,
    )

    @property
    def api_name(self) -> str:
        """Return the community-list name used in API paths and delete payloads."""
        if self.tenant_name and not self.name.startswith(f"{self.tenant_name}~"):
            return f"{self.tenant_name}~{self.name}"
        return self.name

    def to_payload(self, **kwargs) -> dict[str, Any]:
        """Export an API payload with a fully qualified tenant-scoped name."""
        data = super().to_payload(**kwargs)
        if self.tenant_name:
            data["name"] = self.api_name
        return data

    def to_diff_dict(self, **kwargs) -> dict[str, Any]:
        """Ignore false and empty defaults ND adds to standard entry responses."""
        data = super().to_diff_dict(**kwargs)
        for entry in data.get("entries") or []:
            for field_name in _STANDARD_FALSE_DEFAULT_ALIASES:
                if entry.get(field_name) is False:
                    entry.pop(field_name)
            if entry.get("communityNumbers") == []:
                entry.pop("communityNumbers")
        return data

    @field_validator("name", mode="before")
    @classmethod
    def validate_name(cls, v):
        """Validate community list name matches [a-zA-Z0-9~_-]+."""
        pattern = re.compile(r"^[a-zA-Z0-9~_-]+$")
        if not pattern.match(str(v)):
            raise ValueError(f"name '{v}' contains invalid characters. " "Allowed: [a-zA-Z0-9~_-].")
        return v

    @field_validator("tenant_name", mode="before")
    @classmethod
    def validate_tenant_name(cls, v):
        """Validate tenant name matches [A-Za-z0-9_-]+."""
        if v is None:
            return v
        pattern = re.compile(r"^[A-Za-z0-9_-]+$")
        if not pattern.match(str(v)):
            raise ValueError(f"tenant_name '{v}' contains invalid characters. " "Allowed: [A-Za-z0-9_-].")
        return v

    @model_validator(mode="after")
    def normalize_and_validate_name(self) -> "CommunityListModel":
        """Store tenant-scoped lists with a bare config name and validate API name limits."""
        if self.tenant_name:
            prefix = f"{self.tenant_name}~"
            if self.name.startswith(prefix):
                self.name = self.name[len(prefix) :]
            if len(self.api_name) > TENANT_COMMUNITY_LIST_API_NAME_MAX_LENGTH:
                raise ValueError(
                    f"tenant-scoped community list API name '{self.api_name}' must be "
                    f"{TENANT_COMMUNITY_LIST_API_NAME_MAX_LENGTH} characters or fewer."
                )
        elif len(self.name) > DEFAULT_TENANT_COMMUNITY_LIST_NAME_MAX_LENGTH:
            raise ValueError(
                f"default-tenant community list name '{self.name}' must be "
                f"{DEFAULT_TENANT_COMMUNITY_LIST_NAME_MAX_LENGTH} characters or fewer."
            )
        return self

    @model_validator(mode="after")
    def validate_required_for_write_states(self, info: ValidationInfo) -> "CommunityListModel":
        """Require the API body fields for write states while allowing name-only deletes."""
        state = (info.context or {}).get("state")
        if state in ("merged", "replaced", "overridden"):
            missing = [field_name for field_name in ("type", "entries") if getattr(self, field_name) is None]
            if missing:
                verb = "is" if len(missing) == 1 else "are"
                raise ValueError(f"community list '{self.api_name}': '{', '.join(missing)}' {verb} required for state '{state}'.")
        return self

    @model_validator(mode="after")
    def validate_entries_match_type(self, info: ValidationInfo):
        """
        Cross-validate entries against the declared community list type.

        - For *expanded* lists every entry MUST have community_number_regex set.
          Standard-only fields (community_numbers, well-known flags) MUST NOT be set.
        - For *standard* lists entries MUST NOT have community_number_regex set.
        """
        if (info.context or {}).get("mode") == "response":
            return self

        standard_only_fields = {
            "no_advertise",
            "blackhole",
            "no_export",
            "internet",
            "graceful_shutdown",
            "local_asn",
            "community_numbers",
        }

        if self.type is None or self.entries is None:
            return self

        for i, entry in enumerate(self.entries):
            if self.type == CommunityListTypeEnum.EXPANDED:
                if not entry.community_number_regex:
                    raise ValueError(f"entries[{i}].community_number_regex is required " "for type='expanded'.")
                for field in standard_only_fields:
                    if getattr(entry, field) is not None:
                        raise ValueError(f"entries[{i}].{field} must not be set for " "type='expanded'. Use community_number_regex instead.")
            else:
                # standard
                if entry.community_number_regex is not None:
                    raise ValueError(
                        f"entries[{i}].community_number_regex must not be set "
                        "for type='standard'. Use community_numbers or "
                        "well-known community flags instead."
                    )
        return self

    @classmethod
    def get_argument_spec(cls) -> dict:
        return dict(
            fabric_name=dict(type="str", required=True),
            cluster_name=dict(type="str"),
            config=dict(
                type="list",
                elements="dict",
                required=True,
                options=dict(
                    name=dict(type="str", required=True),
                    type=dict(
                        type="str",
                        choices=["standard", "expanded"],
                    ),
                    tenant_name=dict(
                        type="str",
                        aliases=["tenantName"],
                    ),
                    entries=dict(
                        type="list",
                        elements="dict",
                        options=dict(
                            sequence_number=dict(
                                type="int",
                                required=True,
                                aliases=["sequenceNumber"],
                            ),
                            action=dict(
                                type="str",
                                required=True,
                                choices=["permit", "deny"],
                            ),
                            no_advertise=dict(
                                type="bool",
                                aliases=["noAdvertise"],
                            ),
                            blackhole=dict(type="bool"),
                            no_export=dict(
                                type="bool",
                                aliases=["noExport"],
                            ),
                            internet=dict(type="bool"),
                            graceful_shutdown=dict(
                                type="bool",
                                aliases=["gracefulShutdown"],
                            ),
                            local_asn=dict(
                                type="bool",
                                aliases=["localAsn"],
                            ),
                            community_numbers=dict(
                                type="list",
                                elements="str",
                                aliases=["communityNumbers"],
                            ),
                            community_number_regex=dict(
                                type="str",
                                aliases=["communityNumberRegex"],
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
