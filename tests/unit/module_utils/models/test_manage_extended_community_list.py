# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for models/manage_extended_community_list/manage_extended_community_list.py."""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_extended_community_list.manage_extended_community_list import (
    ExtendedCommunityListModel,
)

STANDARD_API_RESPONSE = {
    "name": "ECL-STANDARD",
    "type": "standard",
    "tenantName": "tenantA",
    "lastUpdateTimestamp": "2026-01-01T00:00:00Z",
    "entries": [
        {
            "sequenceNumber": 10,
            "action": "permit",
            "routeTargetCollection": ["65000:100"],
            "routerMacCollection": ["d478.1111.57b8"],
        }
    ],
}


def test_manage_extended_community_list_00010() -> None:
    """
    # Summary

    Verify identifier configuration and name-only delete model construction.

    ## Classes and Methods

    - ExtendedCommunityListModel.from_config()
    - ExtendedCommunityListModel.get_identifier_value()
    """
    instance = ExtendedCommunityListModel.from_config({"name": "ECL-DELETE"})

    assert ExtendedCommunityListModel.identifiers == ["api_name"]
    assert ExtendedCommunityListModel.identifier_strategy == "single"
    assert instance.get_identifier_value() == "ECL-DELETE"
    assert instance.type is None
    assert instance.entries is None


def test_manage_extended_community_list_00020() -> None:
    """
    # Summary

    Verify API alias loading and payload serialization.

    ## Classes and Methods

    - ExtendedCommunityListModel.from_response()
    - ExtendedCommunityListModel.to_payload()
    """
    instance = ExtendedCommunityListModel.from_response(STANDARD_API_RESPONSE)
    payload = instance.to_payload()

    assert instance.name == "ECL-STANDARD"
    assert instance.tenant_name == "tenantA"
    assert "lastUpdateTimestamp" not in payload
    assert payload["tenantName"] == "tenantA"
    assert payload["entries"][0]["sequenceNumber"] == 10
    assert payload["entries"][0]["routeTargetCollection"] == ["65000:100"]


def test_manage_extended_community_list_00030() -> None:
    """
    # Summary

    Verify type-specific validation for expanded extended community lists.

    ## Classes and Methods

    - ExtendedCommunityListModel.from_config()
    """
    with pytest.raises(ValueError, match="community_number_regex is required"):
        ExtendedCommunityListModel.from_config(
            {
                "name": "ECL-EXPANDED",
                "type": "expanded",
                "entries": [{"sequence_number": 10, "action": "permit"}],
            }
        )


def test_manage_extended_community_list_00040() -> None:
    """
    # Summary

    Verify the argument spec allows name-only config for state=deleted.

    ## Classes and Methods

    - ExtendedCommunityListModel.get_argument_spec()
    """
    spec = ExtendedCommunityListModel.get_argument_spec()
    config_options = spec["config"]["options"]

    assert config_options["name"]["required"] is True
    assert "required" not in config_options["type"]
    assert "required" not in config_options["entries"]


def test_manage_extended_community_list_00050() -> None:
    """Verify tenant-scoped names are normalized while API identity stays qualified."""
    instance = ExtendedCommunityListModel.from_config(
        {
            "name": "tenantA~ECL-TENANT",
            "tenant_name": "tenantA",
            "type": "standard",
            "entries": [{"sequence_number": 10, "action": "permit"}],
        }
    )

    assert instance.name == "ECL-TENANT"
    assert instance.api_name == "tenantA~ECL-TENANT"
    assert instance.get_identifier_value() == "tenantA~ECL-TENANT"
    assert instance.to_config()["name"] == "ECL-TENANT"
    assert instance.to_payload()["name"] == "tenantA~ECL-TENANT"


def test_manage_extended_community_list_00060() -> None:
    """Verify same-name lists in different tenants have distinct identifiers."""
    first = ExtendedCommunityListModel.from_config({"name": "ECL-SHARED", "tenant_name": "tenantA"})
    second = ExtendedCommunityListModel.from_config({"name": "ECL-SHARED", "tenant_name": "tenantB"})

    assert first.get_identifier_value() == "tenantA~ECL-SHARED"
    assert second.get_identifier_value() == "tenantB~ECL-SHARED"
    assert first.get_identifier_value() != second.get_identifier_value()


def test_manage_extended_community_list_00070() -> None:
    """Verify default and tenant-qualified API name length limits."""
    ExtendedCommunityListModel.from_config({"name": "E" * 63})
    with pytest.raises(ValueError, match="default-tenant extended community list name"):
        ExtendedCommunityListModel.from_config({"name": "E" * 64})

    tenant_name = "T" * 63
    ExtendedCommunityListModel.from_config({"name": "E" * 51, "tenant_name": tenant_name})
    with pytest.raises(ValueError, match="tenant-scoped extended community list API name"):
        ExtendedCommunityListModel.from_config({"name": "E" * 52, "tenant_name": tenant_name})


def test_manage_extended_community_list_00080() -> None:
    """Verify type-specific validation is config-only and does not reject ND responses."""
    response = {
        "name": "ECL-EXPANDED",
        "type": "expanded",
        "entries": [
            {
                "sequenceNumber": 10,
                "action": "permit",
                "communityNumberRegex": "65000:.*",
                "routeTargetCollection": [],
            }
        ],
    }

    instance = ExtendedCommunityListModel.from_response(response)
    assert instance.entries[0].route_target_collection == []

    with pytest.raises(ValueError, match="route_target_collection must not be set"):
        ExtendedCommunityListModel.from_config(response)
