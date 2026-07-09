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

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import ipaddress
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field, model_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_route_map.enums import ActionEnum, RuleTypeEnum

# Rule type choices list (used in argument_spec)
RULE_TYPE_CHOICES = [e.value for e in RuleTypeEnum]
Uint32 = Annotated[int, Field(ge=0, le=4294967295)]

_REQUIRED_RULE_FIELDS: Dict[str, Set[str]] = {
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

_ALLOWED_RULE_FIELDS: Dict[str, Set[str]] = {
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
                                   ``trackId``. Exactly one next-hop mode is
                                   required.
    - ``setIpv6NextHop``         - same optional fields as ``setIpv4NextHop``
    """

    # --- Discriminator (required for every rule entry) ---

    rule_type: str = Field(alias="ruleType", description="Rule type discriminator.")

    # --- matchIpv4Acl / matchIpv6Acl ---

    access_control_list_name: Optional[str] = Field(
        default=None,
        alias="accessControlListName",
        description="Name of the access control list to match.",
    )

    # --- matchIpv4PrefixList / matchIpv6PrefixList ---

    prefix_list_names: Optional[List[str]] = Field(
        default=None,
        alias="prefixListNames",
        description="Names of the prefix lists to match.",
    )

    # --- matchCommunity ---

    community_list_names: Optional[List[str]] = Field(
        default=None,
        alias="communityListNames",
        description="Names of the community lists to match.",
    )

    # --- matchExtendedCommunity ---

    extended_community_list_names: Optional[List[str]] = Field(
        default=None,
        alias="extendedCommunityListNames",
        description="Names of the extended community lists to match.",
    )

    # --- matchCommunity / matchExtendedCommunity ---

    exact_match: Optional[bool] = Field(
        default=None,
        alias="exactMatch",
        description="Require an exact match for the (extended) community lists.",
    )

    # --- matchTag ---

    tags: Optional[List[Uint32]] = Field(
        default=None,
        alias="tags",
        description="List of integer tags to match (0-4294967295).",
    )

    # --- setCommunity ---

    community_numbers: Optional[List[str]] = Field(
        default=None,
        alias="communityNumbers",
        description="Community numbers in ASN2:NN format (e.g. '65000:100').",
    )

    additive: Optional[bool] = Field(
        default=None,
        alias="additive",
        description="Add communities without replacing existing ones.",
    )

    graceful_restart_shutdown_community: Optional[bool] = Field(
        default=None,
        alias="gracefulRestartShutdownCommunity",
        description="Set the graceful-restart shutdown community.",
    )

    no_advertise_community: Optional[bool] = Field(
        default=None,
        alias="noAdvertiseCommunity",
        description="Set the no-advertise community.",
    )

    no_export_community: Optional[bool] = Field(
        default=None,
        alias="noExportCommunity",
        description="Set the no-export community.",
    )

    local_as_community: Optional[bool] = Field(
        default=None,
        alias="localAsCommunity",
        description="Set the local-AS community.",
    )

    internet_community: Optional[bool] = Field(
        default=None,
        alias="internetCommunity",
        description="Set the internet community.",
    )

    # --- setExtendedCommunityList ---

    extended_community_list_name: Optional[str] = Field(
        default=None,
        alias="extendedCommunityListName",
        description="Name of the extended community list to set.",
    )

    # --- setLocalPreference ---

    value: Optional[Uint32] = Field(
        default=None,
        alias="value",
        description="Local preference value (0-4294967295).",
    )

    # --- setIpv4NextHop / setIpv6NextHop ---

    next_hop_ip_collection: Optional[List[str]] = Field(
        default=None,
        alias="nextHopIpCollection",
        description="List of next-hop IP addresses.",
    )

    drop_on_fail: Optional[bool] = Field(
        default=None,
        alias="dropOnFail",
        description="Drop the packet if the next hop is unavailable.",
    )

    load_share: Optional[bool] = Field(
        default=None,
        alias="loadShare",
        description="Enable load sharing across multiple next hops.",
    )

    enforce_order: Optional[bool] = Field(
        default=None,
        alias="enforceOrder",
        description="Enforce the order of next-hop IPs.",
    )

    verify_availability: Optional[bool] = Field(
        default=None,
        alias="verifyAvailability",
        description="Ensure the next hop is reachable before using it.",
    )

    use_peer_address: Optional[bool] = Field(
        default=None,
        alias="usePeerAddress",
        description="Use the peer address as the next hop.",
    )

    redistribute_unchanged: Optional[bool] = Field(
        default=None,
        alias="redistributeUnchanged",
        description="Redistribute routes without changing the next hop.",
    )

    unchanged: Optional[bool] = Field(
        default=None,
        alias="unchanged",
        description="Keep the next hop unchanged.",
    )

    track_id: Optional[int] = Field(
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
        """Validate next-hop rule mode and address-family combinations."""
        if self.rule_type not in _NEXT_HOP_RULE_TYPES:
            return

        selected_modes = [
            bool(self.next_hop_ip_collection),
            self.use_peer_address is True,
            self.unchanged is True,
            self.redistribute_unchanged is True,
        ]
        if sum(selected_modes) != 1:
            raise ValueError(
                f"rule_type '{self.rule_type}' requires exactly one next-hop mode: "
                "next_hop_ip_collection, use_peer_address, unchanged, or redistribute_unchanged."
            )

        if self.next_hop_ip_collection:
            expected_version = 4 if self.rule_type == RuleTypeEnum.SET_IPV4_NEXT_HOP.value else 6
            for address in self.next_hop_ip_collection:
                parsed_address = ipaddress.ip_address(address)
                if parsed_address.version != expected_version:
                    raise ValueError(f"rule_type '{self.rule_type}' expects IPv{expected_version} next-hop addresses.")

        if self.track_id is not None and self._is_missing(self.next_hop_ip_collection):
            raise ValueError("track_id requires next_hop_ip_collection.")


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

    rule_entries: List[RouteMapRuleEntryModel] = Field(
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

    identifiers: ClassVar[Optional[List[str]]] = ["api_name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"

    # --- Serialization Configuration ---

    exclude_from_diff: ClassVar[Set[str]] = {"last_update_timestamp"}
    payload_exclude_fields: ClassVar[Set[str]] = {"last_update_timestamp"}
    unwanted_keys: ClassVar[List] = []

    # --- Fields ---

    name: str = Field(
        alias="name",
        min_length=1,
        max_length=115,
        description="Name of the route map (pattern: ^[a-zA-Z0-9~_-]+$).",
    )

    last_update_timestamp: Optional[str] = Field(
        default=None,
        alias="lastUpdateTimestamp",
        description="Timestamp of the last update (read-only, set by ND).",
    )

    tenant_name: Optional[str] = Field(
        default=None,
        alias="tenantName",
        description="Tenant name for tenant-specific route maps.",
    )

    entries: Optional[List[RouteMapEntryModel]] = Field(
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

    @model_validator(mode="after")
    def normalize_tenant_scoped_name(self) -> "RouteMapModel":
        """Store tenant-scoped route maps with a bare name and tenant context."""
        if self.tenant_name:
            prefix = f"{self.tenant_name}~"
            if self.name.startswith(prefix):
                self.name = self.name[len(prefix) :]
        return self

    def to_diff_dict(self, **kwargs) -> Dict[str, Any]:
        """Export for diff comparison, normalizing ND next-hop false defaults."""
        data = super().to_diff_dict(**kwargs)
        for entry in data.get("entries") or []:
            for rule_entry in entry.get("ruleEntries") or []:
                if rule_entry.get("ruleType") not in _NEXT_HOP_RULE_TYPES:
                    continue
                for field_name in _NEXT_HOP_FALSE_DEFAULT_FIELDS:
                    if rule_entry.get(field_name) is False:
                        rule_entry.pop(field_name)
        return data

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> Dict[str, Any]:
        return dict(
            fabric_name=dict(
                type="str",
                required=True,
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
