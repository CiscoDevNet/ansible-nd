# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_route_map.py models.

Tests route-map model identifiers, alias conversion, payload serialization, read-only field
exclusion, tenantName round-trip, delete-by-name construction, and argspec shape.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_route_map.manage_route_map import (
    RULE_TYPE_CHOICES,
    RouteMapEntryModel,
    RouteMapModel,
    RouteMapRuleEntryModel,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise

SAMPLE_ANSIBLE_CONFIG = {
    "name": "tenantSales~RM_EXPORT",
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
    assert instance.tenant_name == "tenantSales"
    assert instance.to_payload() == {
        "name": "tenantSales~RM_EXPORT",
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

    assert instance.name == "tenantSales~RM_EXPORT"
    assert instance.tenant_name == "tenantSales"
    assert instance.last_update_timestamp == "2026-01-01T00:00:00Z"
    payload = instance.to_payload()
    assert "lastUpdateTimestamp" not in payload
    assert payload["tenantName"] == "tenantSales"


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
