# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Pydantic models for the nd_manage_extended_community_list module.

Extended community lists come in two flavours that share the same top-level
schema but differ in their entry structure:

- **standard** - entries may specify any combination of:
    - routerMacCollection: MAC addresses in eeee.eeee.eeee, ee:ee:ee:ee:ee:ee,
      or ee-ee-ee-ee-ee-ee format.
    - routeTargetCollection: route targets in ASN2:NN, ASN4:NN, or IPv4:NN format.
    - siteOfOriginCollection: site-of-origin values in ASN2:NN, ASN4:NN, or
      IPv4:NN format.
    - transitiveGenericExtendedCollection: transitive generic extended communities
      in ASN4:NN format.
    - nonTransitiveGenericExtendedCollection: non-transitive generic extended
      communities in ASN4:NN format.

- **expanded** - entries must specify:
    - communityNumberRegex (required): regular expression in aa:nn format.

A single flat ``ExtendedCommunityListEntryModel`` covers both flavours.
A ``model_validator`` on ``ExtendedCommunityListModel`` enforces the
type-specific entry constraints at validation time.
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
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_extended_community_list.enums import (
    ExtendedCommunityListTypeEnum,
    ExtendedCommunityListActionEnum,
)

# ---------------------------------------------------------------------------
# Compiled validation regexes (from OpenAPI spec patterns)
# ---------------------------------------------------------------------------

# MAC: eeee.eeee.eeee  OR  ee:ee:ee:ee:ee:ee  OR  ee-ee-ee-ee-ee-ee
_ROUTER_MAC_RE = re.compile(r"^(?:[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}" + r"|([a-fA-F0-9]{2}[:\-]){5}[a-fA-F0-9]{2})$")

# Canonical route-target token: ASN2:NN  |  ASN4:NN  |  IPv4:NN
_ROUTE_TARGET_RE = re.compile(
    r"^((\d{1,5}:\d{1,9})|(\d{1,10}:\d{1,9})"
    r"|((25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})"
    r"\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}):\d{1,9}))$"
)

# Site of origin: ASN2:NN  |  ASN4:NN  |  IPv4:NN
_SITE_OF_ORIGIN_RE = re.compile(r"^(\d{1,5}|\d{1,10}|(?:\d{1,3}\.){3}\d{1,3}):\d+$")

# Transitive/non-transitive generic extended: ASN4:NN (starts with 1-9)
_GENERIC_EXTENDED_RE = re.compile(r"^[1-9]\d{0,9}:\d+$")

# Expanded community-number regex: must not start with [a-zA-Z~!#%@`;]
_COMMUNITY_REGEX_RE = re.compile(r"^[^a-zA-Z~!#%@`;].*$")
DEFAULT_TENANT_EXTENDED_COMMUNITY_LIST_NAME_MAX_LENGTH = 63
TENANT_EXTENDED_COMMUNITY_LIST_API_NAME_MAX_LENGTH = 115
_STANDARD_EMPTY_COLLECTION_ALIASES = (
    "routerMacCollection",
    "routeTargetCollection",
    "siteOfOriginCollection",
    "transitiveGenericExtendedCollection",
    "nonTransitiveGenericExtendedCollection",
)


class ExtendedCommunityListEntryModel(NDNestedModel):
    """
    A single entry inside an extended community list.

    For **standard** extended community lists the entry may set any combination
    of:
    - ``router_mac_collection``
    - ``route_target_collection``
    - ``site_of_origin_collection``
    - ``transitive_generic_extended_collection``
    - ``non_transitive_generic_extended_collection``

    For **expanded** extended community lists the entry must set:
    - ``community_number_regex`` (required)
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
    action: ExtendedCommunityListActionEnum = Field(
        alias="action",
        description="Permit or deny operation.",
    )

    # --- Standard-only fields ---
    router_mac_collection: list[str] | None = Field(
        default=None,
        alias="routerMacCollection",
        description=("One or more router MAC addresses in eeee.eeee.eeee, " "ee:ee:ee:ee:ee:ee, or ee-ee-ee-ee-ee-ee format."),
    )
    route_target_collection: list[str] | None = Field(
        default=None,
        alias="routeTargetCollection",
        description=("One or more route targets in ASN2:NN, ASN4:NN, or IPv4:NN format."),
    )
    site_of_origin_collection: list[str] | None = Field(
        default=None,
        alias="siteOfOriginCollection",
        description=("One or more site-of-origin values in ASN2:NN, ASN4:NN, or " "IPv4:NN format."),
    )
    transitive_generic_extended_collection: list[str] | None = Field(
        default=None,
        alias="transitiveGenericExtendedCollection",
        description=("One or more transitive generic extended community values " "in ASN4:NN format (e.g. 65000:123)."),
    )
    non_transitive_generic_extended_collection: list[str] | None = Field(
        default=None,
        alias="nonTransitiveGenericExtendedCollection",
        description=("One or more non-transitive generic extended community values " "in ASN4:NN format (e.g. 64512:789)."),
    )

    # --- Expanded-only ---
    community_number_regex: str | None = Field(
        default=None,
        alias="communityNumberRegex",
        description=("Regular expression in aa:nn format for matching extended community " "strings. Max 63 characters. Must not start with [a-zA-Z~!#%@`;]."),
        max_length=63,
    )

    # ------------------------------------------------------------------
    # Field validators
    # ------------------------------------------------------------------

    @field_validator("router_mac_collection", mode="before")
    @classmethod
    def validate_router_mac_collection(cls, v):
        if v is None:
            return v
        for mac in v:
            if not _ROUTER_MAC_RE.match(str(mac)):
                raise ValueError(f"router_mac_collection entry '{mac}' must be in " "eeee.eeee.eeee, ee:ee:ee:ee:ee:ee, or ee-ee-ee-ee-ee-ee format.")
        return v

    @field_validator("route_target_collection", mode="before")
    @classmethod
    def validate_route_target_collection(cls, v: Any) -> Any:
        """Validate route targets and flatten OpenAPI-compatible comma-packed items."""
        if v is None:
            return v
        if not isinstance(v, list):
            return v

        normalized: list[str] = []
        for packed_route_targets in v:
            for route_target in str(packed_route_targets).split(","):
                if not _ROUTE_TARGET_RE.match(route_target):
                    raise ValueError(
                        f"route_target_collection entry '{packed_route_targets}' "
                        "must contain only ASN2:NN, ASN4:NN, or IPv4:NN values."
                    )
                normalized.append(route_target)
        return normalized

    @field_validator("site_of_origin_collection", mode="before")
    @classmethod
    def validate_site_of_origin_collection(cls, v):
        if v is None:
            return v
        for soo in v:
            if not _SITE_OF_ORIGIN_RE.match(str(soo)):
                raise ValueError(f"site_of_origin_collection entry '{soo}' must be in " "ASN2:NN, ASN4:NN, or IPv4:NN format.")
        return v

    @field_validator("transitive_generic_extended_collection", mode="before")
    @classmethod
    def validate_transitive_generic_extended_collection(cls, v):
        if v is None:
            return v
        for val in v:
            if not _GENERIC_EXTENDED_RE.match(str(val)):
                raise ValueError(f"transitive_generic_extended_collection entry '{val}' " "must be in ASN4:NN format (e.g. 65000:123).")
        return v

    @field_validator("non_transitive_generic_extended_collection", mode="before")
    @classmethod
    def validate_non_transitive_generic_extended_collection(cls, v):
        if v is None:
            return v
        for val in v:
            if not _GENERIC_EXTENDED_RE.match(str(val)):
                raise ValueError(f"non_transitive_generic_extended_collection entry '{val}' " "must be in ASN4:NN format (e.g. 64512:789).")
        return v

    @field_validator("community_number_regex", mode="before")
    @classmethod
    def validate_community_number_regex(cls, v):
        if v is None:
            return v
        if not _COMMUNITY_REGEX_RE.match(str(v)):
            raise ValueError(f"community_number_regex '{v}' must not start with " "[a-zA-Z~!#%@`;].")
        return v


class ExtendedCommunityListModel(NDBaseModel):
    """
    Model for a Nexus Dashboard extended community list resource.

    Supports both **standard** and **expanded** types; the ``type`` field
    discriminates between them and a ``model_validator`` enforces the
    type-specific entry constraints at validation time.

    Identifier strategy: ``single`` on the fully qualified ``api_name``.
    """

    identifiers: ClassVar[list[str] | None] = ["api_name"]
    identifier_strategy: ClassVar[str] = "single"

    # Read-only timestamp excluded from payloads and diffs
    exclude_from_diff: ClassVar[set[str]] = {"last_update_timestamp"}
    payload_exclude_fields: ClassVar[set[str]] = {"last_update_timestamp"}

    # Strip summary-only keys returned by the list/summary endpoints
    unwanted_keys: ClassVar[list[str]] = [
        "numberOfEntries",
        "numberOfAssociations",
        "associations",
    ]

    # --- Top-level fields ---
    name: str = Field(
        alias="name",
        description=(
            "Name of the extended community list. Allowed characters: "
            "[a-zA-Z0-9~_-]. Max 63 characters for the default tenant, "
            "115 when using a non-default tenant."
        ),
        min_length=1,
        max_length=115,
    )
    type: ExtendedCommunityListTypeEnum | None = Field(
        default=None,
        alias="type",
        description="Type of extended community list: standard or expanded.",
    )
    last_update_timestamp: str | None = Field(
        default=None,
        alias="lastUpdateTimestamp",
        description="Timestamp of the last update (read-only, set by the API).",
    )
    tenant_name: str | None = Field(
        default=None,
        alias="tenantName",
        description=("Name of the tenant that owns this extended community list. " "Allowed characters: [A-Za-z0-9_-]. Max 63 characters."),
        max_length=63,
    )
    entries: list[ExtendedCommunityListEntryModel] | None = Field(
        default=None,
        alias="entries",
        description="Collection of extended community list entries.",
        min_length=1,
    )

    @property
    def api_name(self) -> str:
        """Return the extended-community-list name used in API paths and delete payloads."""
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
        """Ignore empty collection defaults ND adds to standard entry responses."""
        data = super().to_diff_dict(**kwargs)
        for entry in data.get("entries") or []:
            for field_name in _STANDARD_EMPTY_COLLECTION_ALIASES:
                if entry.get(field_name) == []:
                    entry.pop(field_name)
        return data

    # ------------------------------------------------------------------
    # Field validators
    # ------------------------------------------------------------------

    @field_validator("name", mode="before")
    @classmethod
    def validate_name(cls, v):
        """Validate extended community list name matches [a-zA-Z0-9~_-]+."""
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
    def normalize_and_validate_name(self) -> "ExtendedCommunityListModel":
        """Store tenant-scoped lists with a bare config name and validate API name limits."""
        if self.tenant_name:
            prefix = f"{self.tenant_name}~"
            if self.name.startswith(prefix):
                self.name = self.name[len(prefix) :]
            if len(self.api_name) > TENANT_EXTENDED_COMMUNITY_LIST_API_NAME_MAX_LENGTH:
                raise ValueError(
                    f"tenant-scoped extended community list API name '{self.api_name}' must be "
                    f"{TENANT_EXTENDED_COMMUNITY_LIST_API_NAME_MAX_LENGTH} characters or fewer."
                )
        elif len(self.name) > DEFAULT_TENANT_EXTENDED_COMMUNITY_LIST_NAME_MAX_LENGTH:
            raise ValueError(
                f"default-tenant extended community list name '{self.name}' must be "
                f"{DEFAULT_TENANT_EXTENDED_COMMUNITY_LIST_NAME_MAX_LENGTH} characters or fewer."
            )
        return self

    @model_validator(mode="after")
    def validate_required_for_write_states(self, info: ValidationInfo) -> "ExtendedCommunityListModel":
        """Require the API body fields for write states while allowing name-only deletes."""
        state = (info.context or {}).get("state")
        if state in ("merged", "replaced", "overridden"):
            missing = [field_name for field_name in ("type", "entries") if getattr(self, field_name) is None]
            if missing:
                verb = "is" if len(missing) == 1 else "are"
                raise ValueError(f"extended community list '{self.api_name}': '{', '.join(missing)}' {verb} required for state '{state}'.")
        return self

    # ------------------------------------------------------------------
    # Cross-field model validator
    # ------------------------------------------------------------------

    @model_validator(mode="after")
    def validate_entries_match_type(self, info: ValidationInfo):
        """
        Cross-validate entries against the declared extended community list type.

        - For *expanded* lists every entry MUST have community_number_regex set.
          Standard-only fields MUST NOT be set.
        - For *standard* lists entries MUST NOT have community_number_regex set.
        """
        if (info.context or {}).get("mode") == "response":
            return self

        standard_only_fields = {
            "router_mac_collection",
            "route_target_collection",
            "site_of_origin_collection",
            "transitive_generic_extended_collection",
            "non_transitive_generic_extended_collection",
        }

        if self.type is None or self.entries is None:
            return self

        for i, entry in enumerate(self.entries):
            if self.type == ExtendedCommunityListTypeEnum.EXPANDED:
                if not entry.community_number_regex:
                    raise ValueError(f"entries[{i}].community_number_regex is required " "for type='expanded'.")
                for field in standard_only_fields:
                    if getattr(entry, field) is not None:
                        raise ValueError(f"entries[{i}].{field} must not be set for " "type='expanded'. Use community_number_regex instead.")
            else:
                # standard
                if entry.community_number_regex is not None:
                    raise ValueError(f"entries[{i}].community_number_regex must not be set " "for type='standard'. Use standard-only fields instead.")
        return self

    # ------------------------------------------------------------------
    # Argument spec
    # ------------------------------------------------------------------

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
                            router_mac_collection=dict(
                                type="list",
                                elements="str",
                                aliases=["routerMacCollection"],
                            ),
                            route_target_collection=dict(
                                type="list",
                                elements="str",
                                aliases=["routeTargetCollection"],
                            ),
                            site_of_origin_collection=dict(
                                type="list",
                                elements="str",
                                aliases=["siteOfOriginCollection"],
                            ),
                            transitive_generic_extended_collection=dict(
                                type="list",
                                elements="str",
                                aliases=["transitiveGenericExtendedCollection"],
                            ),
                            non_transitive_generic_extended_collection=dict(
                                type="list",
                                elements="str",
                                aliases=["nonTransitiveGenericExtendedCollection"],
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
