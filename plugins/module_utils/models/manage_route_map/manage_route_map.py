# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Pydantic models for Route Map management via Nexus Dashboard.

This module provides Pydantic models for creating, updating, and deleting
route maps through the Nexus Dashboard Fabric Controller (NDFC) Manage API.

## Models Overview

- ``RouteMapRuleEntryModel`` - Flat model for all rule entry types
  (match/set conditions discriminated by ``ruleType``)
- ``RouteMapEntryModel``     - A single route map entry (sequence + action + rules)
- ``RouteMapModel``          - Complete route map (name + entries list)

## Usage

```python
# Create a route map model from Ansible config
rm = RouteMapModel.from_config({
    "name": "MY-BGP-ROUTEMAP-1",
    "entries": [
        {
            "sequence_number": 10,
            "action": "permit",
            "rule_entries": [
                {"rule_type": "matchIpv4PrefixList", "prefix_list_names": ["PL-1"]},
            ],
        }
    ],
})
payload = rm.to_payload()
# {"name": "MY-BGP-ROUTEMAP-1", "entries": [{"sequenceNumber": 10, "action": "permit",
#   "ruleEntries": [{"ruleType": "matchIpv4PrefixList", "prefixListNames": ["PL-1"]}]}]}
```
"""

from __future__ import annotations

import ipaddress
from typing import Annotated, Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field, model_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_route_map.enums import ActionEnum, RuleTypeEnum

# Rule type choices list (used in argument_spec)
RULE_TYPE_CHOICES = [e.value for e in RuleTypeEnum]
Uint32 = Annotated[int, Field(ge=0, le=4294967295)]
DEFAULT_TENANT_ROUTE_MAP_NAME_MAX_LENGTH = 63
TENANT_ROUTE_MAP_API_NAME_MAX_LENGTH = 115

_REQUIRED_RULE_FIELDS: dict[str, set[str]] = {
    RuleTypeEnum.MATCH_IPV4_ACL.value: {"access_control_list_name"},
    RuleTypeEnum.MATCH_IPV6_ACL.value: {"access_control_list_name"},
    RuleTypeEnum.MATCH_IPV4_PREFIX_LIST.value: {"prefix_list_names"},
    RuleTypeEnum.MATCH_IPV6_PREFIX_LIST.value: {"prefix_list_names"},
    RuleTypeEnum.MATCH_COMMUNITY.value: {"community_list_names"},
    RuleTypeEnum.MATCH_EXTENDED_COMMUNITY.value: {"extended_community_list_names"},
    RuleTypeEnum.MATCH_TAG.value: {"tags"},
    RuleTypeEnum.SET_COMMUNITY.value: {"community_numbers"},
    RuleTypeEnum.SET_EXTENDED_COMMUNITY_LIST.value: {"extended_community_list_name"},
    RuleTypeEnum.SET_LOCAL_PREFERENCE.value: {"value"},
}

_ALLOWED_RULE_FIELDS: dict[str, set[str]] = {
    RuleTypeEnum.MATCH_IPV4_ACL.value: {"access_control_list_name"},
    RuleTypeEnum.MATCH_IPV6_ACL.value: {"access_control_list_name"},
    RuleTypeEnum.MATCH_IPV4_PREFIX_LIST.value: {"prefix_list_names"},
    RuleTypeEnum.MATCH_IPV6_PREFIX_LIST.value: {"prefix_list_names"},
    RuleTypeEnum.MATCH_COMMUNITY.value: {"community_list_names", "exact_match"},
    RuleTypeEnum.MATCH_EXTENDED_COMMUNITY.value: {"extended_community_list_names", "exact_match"},
    RuleTypeEnum.MATCH_TAG.value: {"tags"},
    RuleTypeEnum.SET_COMMUNITY.value: {
        "additive",
        "community_numbers",
        "graceful_restart_shutdown_community",
        "internet_community",
        "local_as_community",
        "no_advertise_community",
        "no_export_community",
    },
    RuleTypeEnum.SET_EXTENDED_COMMUNITY_LIST.value: {"extended_community_list_name"},
    RuleTypeEnum.SET_LOCAL_PREFERENCE.value: {"value"},
    RuleTypeEnum.SET_IPV4_NEXT_HOP.value: {
        "drop_on_fail",
        "enforce_order",
        "load_share",
        "next_hop_ip_collection",
        "redistribute_unchanged",
        "track_id",
        "unchanged",
        "use_peer_address",
        "verify_availability",
    },
    RuleTypeEnum.SET_IPV6_NEXT_HOP.value: {
        "drop_on_fail",
        "enforce_order",
        "load_share",
        "next_hop_ip_collection",
        "redistribute_unchanged",
        "track_id",
        "unchanged",
        "use_peer_address",
        "verify_availability",
    },
}

_NEXT_HOP_RULE_TYPES = {
    RuleTypeEnum.SET_IPV4_NEXT_HOP.value,
    RuleTypeEnum.SET_IPV6_NEXT_HOP.value,
}
_NEXT_HOP_BOOLEAN_OPTION_FIELDS = (
    "drop_on_fail",
    "enforce_order",
    "load_share",
    "redistribute_unchanged",
    "unchanged",
    "use_peer_address",
    "verify_availability",
)
_NEXT_HOP_RESTRICTED_MODE_FIELDS = ("use_peer_address", "redistribute_unchanged", "unchanged")
_NEXT_HOP_ORDERING_FLAG_FIELDS = ("drop_on_fail", "enforce_order", "load_share")
_USE_PEER_ADDRESS_COMPANION_DENY_FIELDS = (
    "drop_on_fail",
    "enforce_order",
    "load_share",
    "redistribute_unchanged",
    "unchanged",
)
# TODO(4.2.1) TBD: ND echoes these next-hop booleans as false on GET even when
# the module never sent them, so diff normalization treats false as absent.
_NEXT_HOP_FALSE_DEFAULT_FIELDS = (
    "dropOnFail",
    "enforceOrder",
    "loadShare",
    "redistributeUnchanged",
    "unchanged",
    "usePeerAddress",
    "verifyAvailability",
)


class RouteMapRuleEntryModel(NDNestedModel):
    """
    # Summary

    Flat Pydantic model for a single route map rule entry.

    A rule entry is a match or set condition identified by ``ruleType``.
    All variant-specific fields are Optional; only the fields relevant to the
    active ``ruleType`` are serialised into the API payload
    (``exclude_none=True`` in ``to_payload``).

    ## Supported ruleType values

    - ``matchIpv4Acl``           - ``accessControlListName`` (required)
    - ``matchIpv6Acl``           - ``accessControlListName`` (required)
    - ``matchIpv4PrefixList``    - ``prefixListNames`` (required)
    - ``matchIpv6PrefixList``    - ``prefixListNames`` (required)
    - ``matchCommunity``         - ``communityListNames`` (required), ``exactMatch``
    - ``matchExtendedCommunity`` - ``extendedCommunityListNames`` (required), ``exactMatch``
    - ``matchTag``               - ``tags`` (required)
    - ``setCommunity``           - ``communityNumbers`` (required), ``additive``,
                                   ``gracefulRestartShutdownCommunity``,
                                   ``noAdvertiseCommunity``, ``noExportCommunity``,
                                   ``localAsCommunity``, ``internetCommunity``
    - ``setExtendedCommunityList`` - ``extendedCommunityListName`` (required)
    - ``setLocalPreference``     - ``value`` (required)
    - ``setIpv4NextHop``         - ``nextHopIpCollection``, ``dropOnFail``,
                                   ``loadShare``, ``enforceOrder``,
                                   ``verifyAvailability``, ``usePeerAddress``,
                                   ``redistributeUnchanged``, ``unchanged``,
                                   ``trackId``. UI/controller next-hop option
                                   rules are enforced locally.
    - ``setIpv6NextHop``         - same optional fields as ``setIpv4NextHop``
    """

    # --- Discriminator (required for every rule entry) ---

    rule_type: str = Field(alias="ruleType", description="Rule type discriminator.")

    # --- matchIpv4Acl / matchIpv6Acl ---

    access_control_list_name: str | None = Field(
        default=None,
        alias="accessControlListName",
        description="Name of the access control list to match.",
    )

    # --- matchIpv4PrefixList / matchIpv6PrefixList ---

    prefix_list_names: list[str] | None = Field(
        default=None,
        alias="prefixListNames",
        description="Names of the prefix lists to match.",
    )

    # --- matchCommunity ---

    community_list_names: list[str] | None = Field(
        default=None,
        alias="communityListNames",
        description="Names of the community lists to match.",
    )

    # --- matchExtendedCommunity ---

    extended_community_list_names: list[str] | None = Field(
        default=None,
        alias="extendedCommunityListNames",
        description="Names of the extended community lists to match.",
    )

    # --- matchCommunity / matchExtendedCommunity ---

    exact_match: bool | None = Field(
        default=None,
        alias="exactMatch",
        description="Require an exact match for the (extended) community lists.",
    )

    # --- matchTag ---

    tags: list[Uint32] | None = Field(
        default=None,
        alias="tags",
        description="List of integer tags to match (0-4294967295).",
    )

    # --- setCommunity ---

    community_numbers: list[str] | None = Field(
        default=None,
        alias="communityNumbers",
        description="Community numbers in ASN2:NN format (e.g. '65000:100').",
    )

    additive: bool | None = Field(
        default=None,
        alias="additive",
        description="Add communities without replacing existing ones.",
    )

    graceful_restart_shutdown_community: bool | None = Field(
        default=None,
        alias="gracefulRestartShutdownCommunity",
        description="Set the graceful-restart shutdown community.",
    )

    no_advertise_community: bool | None = Field(
        default=None,
        alias="noAdvertiseCommunity",
        description="Set the no-advertise community.",
    )

    no_export_community: bool | None = Field(
        default=None,
        alias="noExportCommunity",
        description="Set the no-export community.",
    )

    local_as_community: bool | None = Field(
        default=None,
        alias="localAsCommunity",
        description="Set the local-AS community.",
    )

    internet_community: bool | None = Field(
        default=None,
        alias="internetCommunity",
        description="Set the internet community.",
    )

    # --- setExtendedCommunityList ---

    extended_community_list_name: str | None = Field(
        default=None,
        alias="extendedCommunityListName",
        description="Name of the extended community list to set.",
    )

    # --- setLocalPreference ---

    value: Uint32 | None = Field(
        default=None,
        alias="value",
        description="Local preference value (0-4294967295).",
    )

    # --- setIpv4NextHop / setIpv6NextHop ---

    next_hop_ip_collection: list[str] | None = Field(
        default=None,
        alias="nextHopIpCollection",
        description="List of next-hop IP addresses.",
    )

    drop_on_fail: bool | None = Field(
        default=None,
        alias="dropOnFail",
        description="Drop the packet if the next hop is unavailable.",
    )

    load_share: bool | None = Field(
        default=None,
        alias="loadShare",
        description="Enable load sharing across multiple next hops.",
    )

    enforce_order: bool | None = Field(
        default=None,
        alias="enforceOrder",
        description="Enforce the order of next-hop IPs.",
    )

    verify_availability: bool | None = Field(
        default=None,
        alias="verifyAvailability",
        description="Ensure the next hop is reachable before using it.",
    )

    use_peer_address: bool | None = Field(
        default=None,
        alias="usePeerAddress",
        description="Use the peer address as the next hop.",
    )

    redistribute_unchanged: bool | None = Field(
        default=None,
        alias="redistributeUnchanged",
        description="Redistribute routes without changing the next hop.",
    )

    unchanged: bool | None = Field(
        default=None,
        alias="unchanged",
        description="Keep the next hop unchanged.",
    )

    track_id: int | None = Field(
        default=None,
        alias="trackId",
        ge=1,
        le=512,
        description="Tracking subsystem object ID (1-512).",
    )

    # --- Validators ---

    @model_validator(mode="after")
    def validate_rule_type_fields(self) -> "RouteMapRuleEntryModel":
        """
        Validate discriminator-specific rule fields.

        The OpenAPI schema represents each rule type as a separate object, while
        this Ansible model intentionally keeps a flat field surface. This
        validator restores the per-rule required/allowed-field contract.
        """
        self._validate_rule_type()
        self._validate_required_fields()
        self._validate_allowed_fields()
        self._validate_next_hop()
        return self

    @staticmethod
    def _is_missing(value: Any) -> bool:
        """Return True when a value should be treated as absent for rule validation."""
        return value is None or value == "" or value == []

    def _validate_rule_type(self) -> None:
        """Validate the rule_type discriminator before applying its field matrix."""
        if self.rule_type not in _ALLOWED_RULE_FIELDS:
            raise ValueError(f"rule_type '{self.rule_type}' must be one of: {', '.join(RULE_TYPE_CHOICES)}")

    def _validate_required_fields(self) -> None:
        """Validate fields required by the active rule_type."""
        required_fields = _REQUIRED_RULE_FIELDS.get(self.rule_type, set())
        missing = [field for field in sorted(required_fields) if self._is_missing(getattr(self, field))]
        if missing:
            raise ValueError(f"rule_type '{self.rule_type}' requires: {', '.join(missing)}")

    def _validate_allowed_fields(self) -> None:
        """Validate that populated fields are allowed by the active rule_type."""
        allowed_fields = _ALLOWED_RULE_FIELDS.get(self.rule_type, set())
        provided_fields = {field for field in self.model_fields_set if field != "rule_type" and not self._is_missing(getattr(self, field))}
        unexpected = sorted(provided_fields - allowed_fields)
        if unexpected:
            raise ValueError(f"rule_type '{self.rule_type}' does not allow: {', '.join(unexpected)}")

    def _validate_next_hop(self) -> None:
        """Validate next-hop address family and UI/controller option combinations."""
        if self.rule_type not in _NEXT_HOP_RULE_TYPES:
            return

        self._validate_next_hop_address_family()
        self._validate_next_hop_dependencies()
        self._validate_next_hop_option_presence()
        self._validate_next_hop_option_compatibility()

    def _validate_next_hop_address_family(self) -> None:
        """Validate that next-hop addresses match the IPv4/IPv6 rule type."""
        if self.next_hop_ip_collection:
            expected_version = 4 if self.rule_type == RuleTypeEnum.SET_IPV4_NEXT_HOP.value else 6
            for address in self.next_hop_ip_collection:
                parsed_address = ipaddress.ip_address(address)
                if parsed_address.version != expected_version:
                    raise ValueError(f"rule_type '{self.rule_type}' expects IPv{expected_version} next-hop addresses.")

    def _validate_next_hop_dependencies(self) -> None:
        """Validate next-hop dependencies confirmed through ND UI/controller behavior."""
        if self.verify_availability is True and self._is_missing(self.next_hop_ip_collection):
            raise ValueError("verify_availability requires next_hop_ip_collection.")

        if self.track_id is not None and (self._is_missing(self.next_hop_ip_collection) or self.verify_availability is not True):
            raise ValueError("track_id requires next_hop_ip_collection and verify_availability.")

    def _validate_next_hop_option_presence(self) -> None:
        """Validate that each next-hop rule selects at least one IP next-hop option."""
        has_next_hop_addresses = not self._is_missing(self.next_hop_ip_collection)
        has_boolean_option = bool(self._enabled_next_hop_fields(_NEXT_HOP_BOOLEAN_OPTION_FIELDS))
        if not has_next_hop_addresses and not has_boolean_option:
            raise ValueError(f"rule_type '{self.rule_type}' requires at least one next-hop IP option.")

    def _validate_next_hop_option_compatibility(self) -> None:
        """
        Validate UI/controller-only next-hop option combinations.

        OpenAPI defines the available next-hop fields, but it does not fully
        encode the controller compatibility matrix for these flat Ansible
        fields. These checks mirror verified UI behavior for IPv4 and IPv6.
        """
        restricted_modes = self._enabled_next_hop_fields(_NEXT_HOP_RESTRICTED_MODE_FIELDS)
        ordering_flags = self._enabled_next_hop_fields(_NEXT_HOP_ORDERING_FLAG_FIELDS)
        if restricted_modes and ordering_flags:
            raise ValueError(
                "Cannot mix use_peer_address, redistribute_unchanged, or unchanged with " "drop_on_fail, load_share, or enforce_order next-hop configurations."
            )

        use_peer_conflicts = self._enabled_next_hop_fields(_USE_PEER_ADDRESS_COMPANION_DENY_FIELDS)
        if self.use_peer_address is True and use_peer_conflicts:
            raise ValueError(f"use_peer_address cannot be mixed with: {', '.join(use_peer_conflicts)}.")

    def _enabled_next_hop_fields(self, field_names: tuple[str, ...]) -> list[str]:
        """Return next-hop boolean field names explicitly enabled by the rule."""
        return [field_name for field_name in field_names if getattr(self, field_name) is True]


class RouteMapEntryModel(NDNestedModel):
    """
    # Summary

    A single route map entry (one sequence block).

    Each entry consists of a sequence number, a permit/deny action, and a list
    of rule entries (match/set conditions).
    """

    sequence_number: int = Field(
        alias="sequenceNumber",
        ge=0,
        le=65535,
        description="Route map sequence number (0-65535).",
    )

    action: ActionEnum = Field(
        default=ActionEnum.PERMIT,
        alias="action",
        description="Action for this entry: permit or deny.",
    )

    rule_entries: list[RouteMapRuleEntryModel] = Field(
        alias="ruleEntries",
        description="List of match or set rule conditions.",
    )


class RouteMapModel(NDBaseModel):
    """
    # Summary

    Route map configuration for a Nexus Dashboard fabric.

    ## Identifier

    ``api_name`` (single) - the API route map name within its fabric.
    For tenant-specific route maps this is ``tenant_name~name``.

    ## Serialization Notes

    - ``last_update_timestamp`` is a read-only field returned by the API.
      It is excluded from payload output and diff comparisons.
    - ``fabric_name`` is managed at the orchestrator level and is NOT part of
      this model; path construction is handled by the endpoint classes.
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[list[str] | None] = ["api_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"

    # --- Serialization Configuration ---

    exclude_from_diff: ClassVar[set[str]] = {"last_update_timestamp"}
    payload_exclude_fields: ClassVar[set[str]] = {"last_update_timestamp"}
    unwanted_keys: ClassVar[list] = []

    # --- Fields ---

    name: str = Field(
        alias="name",
        min_length=1,
        max_length=TENANT_ROUTE_MAP_API_NAME_MAX_LENGTH,
        pattern=r"^[a-zA-Z0-9~_-]+$",
        description="Name of the route map (pattern: ^[a-zA-Z0-9~_-]+$).",
    )

    last_update_timestamp: str | None = Field(
        default=None,
        alias="lastUpdateTimestamp",
        description="Timestamp of the last update (read-only, set by ND).",
    )

    tenant_name: str | None = Field(
        default=None,
        alias="tenantName",
        min_length=1,
        max_length=DEFAULT_TENANT_ROUTE_MAP_NAME_MAX_LENGTH,
        pattern=r"^[A-Za-z0-9_-]+$",
        description="Tenant name for tenant-specific route maps.",
    )

    entries: list[RouteMapEntryModel] | None = Field(
        default=None,
        alias="entries",
        description="List of route map entries (sequence + action + rule conditions).",
    )

    @property
    def api_name(self) -> str:
        """Return the route-map name used in API paths and delete payloads."""
        if self.tenant_name and not self.name.startswith(f"{self.tenant_name}~"):
            return f"{self.tenant_name}~{self.name}"
        return self.name

    def to_payload(self, **kwargs) -> dict[str, Any]:
        """Export API payload, using the fully qualified API name for tenant-scoped route maps."""
        data = super().to_payload(**kwargs)
        if self.tenant_name:
            data["name"] = self.api_name
        return data

    @model_validator(mode="after")
    def normalize_and_validate_route_map_name(self) -> "RouteMapModel":
        """Store tenant route maps with a bare config name and enforce API name limits."""
        if self.tenant_name:
            prefix = f"{self.tenant_name}~"
            if self.name.startswith(prefix):
                self.name = self.name[len(prefix) :]
            if len(self.api_name) > TENANT_ROUTE_MAP_API_NAME_MAX_LENGTH:
                raise ValueError(f"tenant-scoped route map API name '{self.api_name}' must be " f"{TENANT_ROUTE_MAP_API_NAME_MAX_LENGTH} characters or fewer.")
        elif len(self.name) > DEFAULT_TENANT_ROUTE_MAP_NAME_MAX_LENGTH:
            raise ValueError(f"default-tenant route map name '{self.name}' must be {DEFAULT_TENANT_ROUTE_MAP_NAME_MAX_LENGTH} characters or fewer.")
        return self

    def to_diff_dict(self, **kwargs) -> dict[str, Any]:
        """Export for diff comparison, normalizing ND next-hop false defaults."""
        data = super().to_diff_dict(**kwargs)
        for entry in data.get("entries") or []:
            for rule_entry in entry.get("ruleEntries") or []:
                if rule_entry.get("ruleType") not in _NEXT_HOP_RULE_TYPES:
                    continue
                # TODO(4.2.1) TBD: Strip false values that ND adds on read for
                # unsent next-hop booleans so create/read diffs stay idempotent.
                for field_name in _NEXT_HOP_FALSE_DEFAULT_FIELDS:
                    if rule_entry.get(field_name) is False:
                        rule_entry.pop(field_name)
        return data

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict[str, Any]:
        return dict(
            fabric_name=dict(
                type="str",
                required=True,
            ),
            cluster_name=dict(
                type="str",
            ),
            config=dict(
                type="list",
                elements="dict",
                required=True,
                options=dict(
                    name=dict(
                        type="str",
                        required=True,
                    ),
                    entries=dict(
                        type="list",
                        elements="dict",
                        options=dict(
                            sequence_number=dict(
                                type="int",
                                default=10,
                            ),
                            action=dict(
                                type="str",
                                default="permit",
                                choices=["permit", "deny"],
                            ),
                            rule_entries=dict(
                                type="list",
                                elements="dict",
                                required=True,
                                options=dict(
                                    rule_type=dict(
                                        type="str",
                                        required=True,
                                        choices=RULE_TYPE_CHOICES,
                                        aliases=["ruleType"],
                                    ),
                                    # matchIpv4Acl / matchIpv6Acl
                                    access_control_list_name=dict(
                                        type="str",
                                        aliases=["accessControlListName"],
                                    ),
                                    # matchIpv4PrefixList / matchIpv6PrefixList
                                    prefix_list_names=dict(
                                        type="list",
                                        elements="str",
                                        aliases=["prefixListNames"],
                                    ),
                                    # matchCommunity
                                    community_list_names=dict(
                                        type="list",
                                        elements="str",
                                        aliases=["communityListNames"],
                                    ),
                                    # matchExtendedCommunity
                                    extended_community_list_names=dict(
                                        type="list",
                                        elements="str",
                                        aliases=["extendedCommunityListNames"],
                                    ),
                                    # matchCommunity / matchExtendedCommunity
                                    exact_match=dict(
                                        type="bool",
                                        aliases=["exactMatch"],
                                    ),
                                    # matchTag
                                    tags=dict(
                                        type="list",
                                        elements="int",
                                    ),
                                    # setCommunity
                                    community_numbers=dict(
                                        type="list",
                                        elements="str",
                                        aliases=["communityNumbers"],
                                    ),
                                    additive=dict(type="bool"),
                                    graceful_restart_shutdown_community=dict(
                                        type="bool",
                                        aliases=["gracefulRestartShutdownCommunity"],
                                    ),
                                    no_advertise_community=dict(
                                        type="bool",
                                        aliases=["noAdvertiseCommunity"],
                                    ),
                                    no_export_community=dict(
                                        type="bool",
                                        aliases=["noExportCommunity"],
                                    ),
                                    local_as_community=dict(
                                        type="bool",
                                        aliases=["localAsCommunity"],
                                    ),
                                    internet_community=dict(
                                        type="bool",
                                        aliases=["internetCommunity"],
                                    ),
                                    # setExtendedCommunityList
                                    extended_community_list_name=dict(
                                        type="str",
                                        aliases=["extendedCommunityListName"],
                                    ),
                                    # setLocalPreference
                                    value=dict(type="int"),
                                    # setIpv4NextHop / setIpv6NextHop
                                    next_hop_ip_collection=dict(
                                        type="list",
                                        elements="str",
                                        aliases=["nextHopIpCollection"],
                                    ),
                                    drop_on_fail=dict(
                                        type="bool",
                                        aliases=["dropOnFail"],
                                    ),
                                    load_share=dict(
                                        type="bool",
                                        aliases=["loadShare"],
                                    ),
                                    enforce_order=dict(
                                        type="bool",
                                        aliases=["enforceOrder"],
                                    ),
                                    verify_availability=dict(
                                        type="bool",
                                        aliases=["verifyAvailability"],
                                    ),
                                    use_peer_address=dict(
                                        type="bool",
                                        aliases=["usePeerAddress"],
                                    ),
                                    redistribute_unchanged=dict(
                                        type="bool",
                                        aliases=["redistributeUnchanged"],
                                    ),
                                    unchanged=dict(type="bool"),
                                    track_id=dict(
                                        type="int",
                                        aliases=["trackId"],
                                    ),
                                ),
                            ),
                        ),
                    ),
                    tenant_name=dict(
                        type="str",
                        aliases=["tenantName"],
                    ),
                ),
            ),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "replaced", "overridden", "deleted"],
            ),
        )
