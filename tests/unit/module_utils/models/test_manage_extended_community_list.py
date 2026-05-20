# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for models/manage_extended_community_list/manage_extended_community_list.py."""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

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

    assert ExtendedCommunityListModel.identifiers == ["name"]
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
