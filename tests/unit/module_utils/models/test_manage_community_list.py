# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for models/manage_community_list/manage_community_list.py."""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_community_list.manage_community_list import CommunityListModel

STANDARD_API_RESPONSE = {
    "name": "CL-STANDARD",
    "type": "standard",
    "tenantName": "tenantA",
    "lastUpdateTimestamp": "2026-01-01T00:00:00Z",
    "entries": [
        {
            "sequenceNumber": 10,
            "action": "permit",
            "communityNumbers": ["100:200"],
            "noAdvertise": False,
        }
    ],
}


def test_manage_community_list_00010() -> None:
    """
    # Summary

    Verify identifier configuration and name-only delete model construction.

    ## Classes and Methods

    - CommunityListModel.from_config()
    - CommunityListModel.get_identifier_value()
    """
    instance = CommunityListModel.from_config({"name": "CL-DELETE"})

    assert CommunityListModel.identifiers == ["api_name"]
    assert CommunityListModel.identifier_strategy == "single"
    assert instance.get_identifier_value() == "CL-DELETE"
    assert instance.type is None
    assert instance.entries is None


def test_manage_community_list_00020() -> None:
    """
    # Summary

    Verify API alias loading and payload serialization.

    ## Classes and Methods

    - CommunityListModel.from_response()
    - CommunityListModel.to_payload()
    """
    instance = CommunityListModel.from_response(STANDARD_API_RESPONSE)
    payload = instance.to_payload()

    assert instance.name == "CL-STANDARD"
    assert instance.tenant_name == "tenantA"
    assert "lastUpdateTimestamp" not in payload
    assert payload["tenantName"] == "tenantA"
    assert payload["entries"][0]["sequenceNumber"] == 10
    assert payload["entries"][0]["communityNumbers"] == ["100:200"]


def test_manage_community_list_00030() -> None:
    """
    # Summary

    Verify type-specific validation for expanded community lists.

    ## Classes and Methods

    - CommunityListModel.from_config()
    """
    with pytest.raises(ValueError, match="community_number_regex is required"):
        CommunityListModel.from_config(
            {
                "name": "CL-EXPANDED",
                "type": "expanded",
                "entries": [{"sequence_number": 10, "action": "permit"}],
            }
        )


def test_manage_community_list_00040() -> None:
    """
    # Summary

    Verify the argument spec allows name-only config for state=deleted.

    ## Classes and Methods

    - CommunityListModel.get_argument_spec()
    """
    spec = CommunityListModel.get_argument_spec()
    config_options = spec["config"]["options"]

    assert config_options["name"]["required"] is True
    assert "required" not in config_options["type"]
    assert "required" not in config_options["entries"]


def test_manage_community_list_00050() -> None:
    """Verify tenant-scoped names are normalized while API identity stays qualified."""
    instance = CommunityListModel.from_config(
        {
            "name": "tenantA~CL-TENANT",
            "tenant_name": "tenantA",
            "type": "standard",
            "entries": [{"sequence_number": 10, "action": "permit"}],
        }
    )

    assert instance.name == "CL-TENANT"
    assert instance.api_name == "tenantA~CL-TENANT"
    assert instance.get_identifier_value() == "tenantA~CL-TENANT"
    assert instance.to_config()["name"] == "CL-TENANT"
    assert instance.to_payload()["name"] == "tenantA~CL-TENANT"


def test_manage_community_list_00060() -> None:
    """Verify same-name lists in different tenants have distinct identifiers."""
    first = CommunityListModel.from_config({"name": "CL-SHARED", "tenant_name": "tenantA"})
    second = CommunityListModel.from_config({"name": "CL-SHARED", "tenant_name": "tenantB"})

    assert first.get_identifier_value() == "tenantA~CL-SHARED"
    assert second.get_identifier_value() == "tenantB~CL-SHARED"
    assert first.get_identifier_value() != second.get_identifier_value()


def test_manage_community_list_00070() -> None:
    """Verify default and tenant-qualified API name length limits."""
    CommunityListModel.from_config({"name": "C" * 63})
    with pytest.raises(ValueError, match="default-tenant community list name"):
        CommunityListModel.from_config({"name": "C" * 64})

    tenant_name = "T" * 63
    CommunityListModel.from_config({"name": "C" * 51, "tenant_name": tenant_name})
    with pytest.raises(ValueError, match="tenant-scoped community list API name"):
        CommunityListModel.from_config({"name": "C" * 52, "tenant_name": tenant_name})


def test_manage_community_list_00080() -> None:
    """Verify type-specific validation is config-only and does not reject ND responses."""
    response = {
        "name": "CL-EXPANDED",
        "type": "expanded",
        "entries": [
            {
                "sequenceNumber": 10,
                "action": "permit",
                "communityNumberRegex": "100:.*",
                "noAdvertise": False,
            }
        ],
    }

    instance = CommunityListModel.from_response(response)
    assert instance.entries[0].no_advertise is False

    with pytest.raises(ValueError, match="no_advertise must not be set"):
        CommunityListModel.from_config(response)


def test_manage_community_list_00090() -> None:
    """Verify type and entries are required only for write-state config."""
    for state in ("merged", "replaced", "overridden"):
        with pytest.raises(ValueError, match=f"required for state '{state}'"):
            CommunityListModel.from_config({"name": "CL1"}, context={"state": state})

    deleted = CommunityListModel.from_config({"name": "CL1"}, context={"state": "deleted"})
    without_state = CommunityListModel.from_config({"name": "CL1"})
    complete = CommunityListModel.from_config(
        {
            "name": "CL1",
            "type": "standard",
            "entries": [{"sequence_number": 10, "action": "permit"}],
        },
        context={"state": "merged"},
    )

    assert deleted.type is None
    assert without_state.entries is None
    assert complete.type == "standard"
