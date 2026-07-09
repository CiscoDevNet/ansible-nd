# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_route_map.py models.

Tests route-map model identifiers, alias conversion, payload serialization, read-only field
exclusion, tenantName round-trip, delete-by-name construction, and argspec shape.
"""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_route_map.manage_route_map import (
    RULE_TYPE_CHOICES,
    RouteMapEntryModel,
    RouteMapModel,
    RouteMapRuleEntryModel,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise

SAMPLE_ANSIBLE_CONFIG = {
    "name": "RM_EXPORT",
    "tenant_name": "tenantSales",
    "entries": [
        {
            "sequence_number": 10,
            "action": "permit",
            "rule_entries": [
                {
                    "rule_type": "matchIpv4PrefixList",
                    "prefix_list_names": ["tenantSales~PL_EXPORT"],
                },
                {
                    "rule_type": "setLocalPreference",
                    "value": 200,
                },
            ],
        }
    ],
}

SAMPLE_WIRE_RESPONSE = {
    "name": "tenantSales~RM_EXPORT",
    "tenantName": "tenantSales",
    "lastUpdateTimestamp": "2026-01-01T00:00:00Z",
    "entries": [
        {
            "sequenceNumber": 10,
            "action": "permit",
            "ruleEntries": [
                {
                    "ruleType": "matchIpv4PrefixList",
                    "prefixListNames": ["tenantSales~PL_EXPORT"],
                }
            ],
        }
    ],
}


def test_manage_route_map_model_00010() -> None:
    """
    # Summary

    Verify RouteMapRuleEntryModel parses wire aliases.

    ## Classes and Methods

    - RouteMapRuleEntryModel.model_validate()
    """
    with does_not_raise():
        instance = RouteMapRuleEntryModel.model_validate({"ruleType": "setLocalPreference", "value": 150}, by_alias=True)

    assert instance.rule_type == "setLocalPreference"
    assert instance.value == 150


def test_manage_route_map_model_00020() -> None:
    """
    # Summary

    Verify RouteMapEntryModel defaults action to permit.

    ## Classes and Methods

    - RouteMapEntryModel.model_validate()
    """
    with does_not_raise():
        instance = RouteMapEntryModel.model_validate(
            {
                "sequence_number": 20,
                "rule_entries": [{"rule_type": "matchTag", "tags": [100]}],
            },
            by_name=True,
        )

    assert instance.action == "permit"
    assert instance.sequence_number == 20


@pytest.mark.parametrize(
    "rule_config",
    [
        {"rule_type": "matchIpv4Acl", "access_control_list_name": "ACL_IPV4"},
        {"rule_type": "matchIpv6Acl", "access_control_list_name": "ACL_IPV6"},
        {"rule_type": "matchIpv4PrefixList", "prefix_list_names": ["PL_IPV4"]},
        {"rule_type": "matchIpv6PrefixList", "prefix_list_names": ["PL_IPV6"]},
        {"rule_type": "matchCommunity", "community_list_names": ["COMMUNITY_LIST"], "exact_match": True},
        {"rule_type": "matchExtendedCommunity", "extended_community_list_names": ["EXT_COMMUNITY_LIST"], "exact_match": False},
        {"rule_type": "matchTag", "tags": [0, 4294967295]},
        {"rule_type": "setCommunity", "community_numbers": ["65000:100"], "additive": True},
        {"rule_type": "setExtendedCommunityList", "extended_community_list_name": "EXT_COMMUNITY_LIST"},
        {"rule_type": "setLocalPreference", "value": 0},
    ],
    ids=[
        "match-ipv4-acl",
        "match-ipv6-acl",
        "match-ipv4-prefix-list",
        "match-ipv6-prefix-list",
        "match-community",
        "match-extended-community",
        "match-tag",
        "set-community",
        "set-extended-community-list",
        "set-local-preference",
    ],
)
def test_manage_route_map_model_00030(rule_config: dict) -> None:
    """
    # Summary

    Verify rule-type companion fields accept the valid minimal permutations.

    ## Classes and Methods

    - RouteMapRuleEntryModel.model_validate()
    """
    with does_not_raise():
        instance = RouteMapRuleEntryModel.model_validate(rule_config, by_name=True)

    assert instance.rule_type == rule_config["rule_type"]


@pytest.mark.parametrize(
    "rule_config, error",
    [
        ({"rule_type": "matchIpv4Acl"}, "access_control_list_name"),
        ({"rule_type": "matchIpv6Acl"}, "access_control_list_name"),
        ({"rule_type": "matchIpv4PrefixList"}, "prefix_list_names"),
        ({"rule_type": "matchIpv6PrefixList"}, "prefix_list_names"),
        ({"rule_type": "matchCommunity"}, "community_list_names"),
        ({"rule_type": "matchExtendedCommunity"}, "extended_community_list_names"),
        ({"rule_type": "matchTag"}, "tags"),
        ({"rule_type": "setCommunity"}, "community_numbers"),
        ({"rule_type": "setExtendedCommunityList"}, "extended_community_list_name"),
        ({"rule_type": "setLocalPreference"}, "value"),
        ({"rule_type": "notSupported"}, "rule_type"),
    ],
    ids=[
        "match-ipv4-acl",
        "match-ipv6-acl",
        "match-ipv4-prefix-list",
        "match-ipv6-prefix-list",
        "match-community",
        "match-extended-community",
        "match-tag",
        "set-community",
        "set-extended-community-list",
        "set-local-preference",
        "unsupported-rule-type",
    ],
)
def test_manage_route_map_model_00040(rule_config: dict, error: str) -> None:
    """
    # Summary

    Verify missing required companion fields and unsupported rule types fail validation.

    ## Classes and Methods

    - RouteMapRuleEntryModel.model_validate()
    """
    with pytest.raises(ValueError, match=error):
        RouteMapRuleEntryModel.model_validate(rule_config, by_name=True)


def test_manage_route_map_model_00050() -> None:
    """
    # Summary

    Verify populated fields from another rule type fail validation.

    ## Classes and Methods

    - RouteMapRuleEntryModel.model_validate()
    """
    with pytest.raises(ValueError, match="does not allow"):
        RouteMapRuleEntryModel.model_validate({"rule_type": "matchTag", "tags": [100], "value": 200}, by_name=True)


@pytest.mark.parametrize(
    "rule_config",
    [
        {"rule_type": "setIpv4NextHop", "next_hop_ip_collection": ["192.0.2.10"], "drop_on_fail": False, "verify_availability": True, "track_id": 10},
        {"rule_type": "setIpv4NextHop", "use_peer_address": True},
        {"rule_type": "setIpv4NextHop", "use_peer_address": True, "verify_availability": True},
        {"rule_type": "setIpv4NextHop", "unchanged": True},
        {"rule_type": "setIpv4NextHop", "redistribute_unchanged": True},
        {"rule_type": "setIpv6NextHop", "next_hop_ip_collection": ["2001:db8::10"]},
    ],
    ids=[
        "ipv4-addresses",
        "use-peer-address",
        "use-peer-address-with-verify",
        "unchanged",
        "redistribute-unchanged",
        "ipv6-addresses",
    ],
)
def test_manage_route_map_model_00060(rule_config: dict) -> None:
    """
    # Summary

    Verify next-hop rules accept one explicit next-hop mode.

    ## Classes and Methods

    - RouteMapRuleEntryModel.model_validate()
    """
    with does_not_raise():
        instance = RouteMapRuleEntryModel.model_validate(rule_config, by_name=True)

    assert instance.rule_type == rule_config["rule_type"]


@pytest.mark.parametrize(
    "rule_config, error",
    [
        ({"rule_type": "setIpv4NextHop"}, "exactly one next-hop mode"),
        ({"rule_type": "setIpv4NextHop", "next_hop_ip_collection": ["192.0.2.10"], "use_peer_address": True}, "exactly one next-hop mode"),
        ({"rule_type": "setIpv4NextHop", "next_hop_ip_collection": ["2001:db8::10"]}, "expects IPv4"),
        ({"rule_type": "setIpv6NextHop", "next_hop_ip_collection": ["192.0.2.10"]}, "expects IPv6"),
        ({"rule_type": "setIpv4NextHop", "use_peer_address": True, "track_id": 10}, "track_id requires next_hop_ip_collection"),
        ({"rule_type": "setIpv4NextHop", "next_hop_ip_collection": ["192.0.2.10"], "track_id": 0}, "track_id"),
        ({"rule_type": "matchTag", "tags": [-1]}, "tags"),
        ({"rule_type": "setLocalPreference", "value": 4294967296}, "value"),
    ],
    ids=[
        "missing-mode",
        "multiple-modes",
        "ipv4-rule-ipv6-address",
        "ipv6-rule-ipv4-address",
        "track-id-with-peer-mode",
        "track-id-out-of-range",
        "tag-out-of-range",
        "local-preference-out-of-range",
    ],
)
def test_manage_route_map_model_00070(rule_config: dict, error: str) -> None:
    """
    # Summary

    Verify invalid next-hop and numeric boundary permutations fail validation.

    ## Classes and Methods

    - RouteMapRuleEntryModel.model_validate()
    """
    with pytest.raises(ValueError, match=error):
        RouteMapRuleEntryModel.model_validate(rule_config, by_name=True)


def test_manage_route_map_model_00100() -> None:
    """
    # Summary

    Verify RouteMapModel converts Ansible config to the expected API payload.

    ## Classes and Methods

    - RouteMapModel.from_config()
    - RouteMapModel.to_payload()
    """
    with does_not_raise():
        instance = RouteMapModel.from_config(SAMPLE_ANSIBLE_CONFIG)

    assert instance.get_identifier_value() == "tenantSales~RM_EXPORT"
    assert instance.api_name == "tenantSales~RM_EXPORT"
    assert instance.name == "RM_EXPORT"
    assert instance.tenant_name == "tenantSales"
    assert instance.to_payload() == {
        "name": "RM_EXPORT",
        "tenantName": "tenantSales",
        "entries": [
            {
                "sequenceNumber": 10,
                "action": "permit",
                "ruleEntries": [
                    {
                        "ruleType": "matchIpv4PrefixList",
                        "prefixListNames": ["tenantSales~PL_EXPORT"],
                    },
                    {
                        "ruleType": "setLocalPreference",
                        "value": 200,
                    },
                ],
            }
        ],
    }


def test_manage_route_map_model_00110() -> None:
    """
    # Summary

    Verify RouteMapModel parses wire aliases and excludes read-only timestamp from payload.

    ## Classes and Methods

    - RouteMapModel.from_response()
    - RouteMapModel.to_payload()
    """
    with does_not_raise():
        instance = RouteMapModel.from_response(SAMPLE_WIRE_RESPONSE)

    assert instance.name == "RM_EXPORT"
    assert instance.get_identifier_value() == "tenantSales~RM_EXPORT"
    assert instance.tenant_name == "tenantSales"
    assert instance.last_update_timestamp == "2026-01-01T00:00:00Z"
    payload = instance.to_payload()
    assert "lastUpdateTimestamp" not in payload
    assert payload["name"] == "RM_EXPORT"
    assert payload["tenantName"] == "tenantSales"


def test_manage_route_map_model_00115() -> None:
    """
    # Summary

    Verify tenant-scoped route maps normalize full API names to bare config names.

    ## Classes and Methods

    - RouteMapModel.from_config()
    - RouteMapModel.get_identifier_value()
    - RouteMapModel.to_payload()
    """
    with does_not_raise():
        instance = RouteMapModel.from_config({"name": "tenantSales~RM_EXPORT", "tenant_name": "tenantSales"})

    assert instance.name == "RM_EXPORT"
    assert instance.api_name == "tenantSales~RM_EXPORT"
    assert instance.get_identifier_value() == "tenantSales~RM_EXPORT"
    assert instance.to_payload() == {"name": "RM_EXPORT", "tenantName": "tenantSales"}


def test_manage_route_map_model_00116() -> None:
    """
    # Summary

    Verify ND-returned false next-hop defaults do not trigger a route-map diff.

    ## Classes and Methods

    - RouteMapModel.from_response()
    - RouteMapModel.from_config()
    - RouteMapModel.get_diff()
    """
    existing = RouteMapModel.from_response(
        {
            "name": "RM_NH",
            "entries": [
                {
                    "sequenceNumber": 10,
                    "action": "permit",
                    "ruleEntries": [
                        {
                            "ruleType": "setIpv4NextHop",
                            "nextHopIpCollection": ["192.0.2.10"],
                            "dropOnFail": False,
                            "enforceOrder": False,
                            "loadShare": False,
                            "redistributeUnchanged": False,
                            "unchanged": False,
                            "usePeerAddress": False,
                            "verifyAvailability": False,
                        }
                    ],
                }
            ],
        }
    )
    proposed = RouteMapModel.from_config(
        {
            "name": "RM_NH",
            "entries": [
                {
                    "sequence_number": 10,
                    "action": "permit",
                    "rule_entries": [{"rule_type": "setIpv4NextHop", "next_hop_ip_collection": ["192.0.2.10"]}],
                }
            ],
        }
    )

    assert existing.get_diff(proposed, exclude_unset=True) is True


def test_manage_route_map_model_00117() -> None:
    """
    # Summary

    Verify true next-hop flags still trigger a diff when the proposed rule disables them.

    ## Classes and Methods

    - RouteMapModel.from_response()
    - RouteMapModel.from_config()
    - RouteMapModel.get_diff()
    """
    existing = RouteMapModel.from_response(
        {
            "name": "RM_NH",
            "entries": [
                {
                    "sequenceNumber": 10,
                    "action": "permit",
                    "ruleEntries": [
                        {
                            "ruleType": "setIpv4NextHop",
                            "nextHopIpCollection": ["192.0.2.10"],
                            "verifyAvailability": True,
                        }
                    ],
                }
            ],
        }
    )
    proposed = RouteMapModel.from_config(
        {
            "name": "RM_NH",
            "entries": [
                {
                    "sequence_number": 10,
                    "action": "permit",
                    "rule_entries": [
                        {
                            "rule_type": "setIpv4NextHop",
                            "next_hop_ip_collection": ["192.0.2.10"],
                            "verify_availability": False,
                        }
                    ],
                }
            ],
        }
    )

    assert existing.get_diff(proposed, exclude_unset=True) is False


def test_manage_route_map_model_00120() -> None:
    """
    # Summary

    Verify delete-state route map config can be represented by name only.

    ## Classes and Methods

    - RouteMapModel.from_config()
    - RouteMapModel.get_identifier_value()
    """
    with does_not_raise():
        instance = RouteMapModel.from_config({"name": "RM_DELETE_ME"})

    assert instance.get_identifier_value() == "RM_DELETE_ME"
    assert instance.entries is None


def test_manage_route_map_model_00200() -> None:
    """
    # Summary

    Verify the argspec exposes route-map rule choices and does not require entries at argspec level.

    ## Classes and Methods

    - RouteMapModel.get_argument_spec()
    """
    spec = RouteMapModel.get_argument_spec()
    config_options = spec["config"]["options"]
    rule_options = config_options["entries"]["options"]["rule_entries"]["options"]

    assert config_options["name"]["required"] is True
    assert config_options["entries"].get("required") is not True
    assert config_options["tenant_name"]["aliases"] == ["tenantName"]
    assert set(rule_options["rule_type"]["choices"]) == set(RULE_TYPE_CHOICES)
