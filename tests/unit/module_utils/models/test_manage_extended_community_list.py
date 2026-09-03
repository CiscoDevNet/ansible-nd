# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for models/manage_extended_community_list/manage_extended_community_list.py."""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_extended_community_list.manage_extended_community_list import ExtendedCommunityListModel

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

    assert config_options["name"].get("required", False) is False
    assert spec["cluster_name"]["type"] == "str"
    assert "required" not in config_options["type"]
    assert "required" not in config_options["entries"]


def test_manage_extended_community_list_00050() -> None:
    """Verify tenant-scoped names are normalized while API identity stays qualified."""
    instance = ExtendedCommunityListModel.from_config(
        {
            "name": "tenantA~ECL-TENANT",
            "tenant_name": "tenantA",
            "type": "standard",
            "entries": [{"sequence_number": 10, "action": "permit", "route_target_collection": ["65000:100"]}],
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


def test_manage_extended_community_list_00090() -> None:
    """Verify type and entries are required only for write-state config."""
    for state in ("merged", "replaced", "overridden"):
        with pytest.raises(ValueError, match=f"required for state '{state}'"):
            ExtendedCommunityListModel.from_config({"name": "ECL1"}, context={"state": state})

    deleted = ExtendedCommunityListModel.from_config({"name": "ECL1"}, context={"state": "deleted"})
    without_state = ExtendedCommunityListModel.from_config({"name": "ECL1"})
    complete = ExtendedCommunityListModel.from_config(
        {
            "name": "ECL1",
            "type": "standard",
            "entries": [{"sequence_number": 10, "action": "permit", "route_target_collection": ["65000:100"]}],
        },
        context={"state": "merged"},
    )

    assert deleted.type is None
    assert without_state.entries is None
    assert complete.type == "standard"


def test_manage_extended_community_list_00100() -> None:
    """Verify ND-added empty collection defaults do not break merged-state idempotency."""
    current = ExtendedCommunityListModel.from_response(
        {
            "name": "ECL1",
            "type": "standard",
            "entries": [
                {
                    "sequenceNumber": 10,
                    "action": "permit",
                    "routeTargetCollection": ["65000:100"],
                    "routerMacCollection": [],
                    "siteOfOriginCollection": [],
                    "transitiveGenericExtendedCollection": [],
                    "nonTransitiveGenericExtendedCollection": [],
                }
            ],
        }
    )
    proposed = ExtendedCommunityListModel.from_config(
        {
            "name": "ECL1",
            "type": "standard",
            "entries": [{"sequence_number": 10, "action": "permit", "route_target_collection": ["65000:100"]}],
        }
    )

    assert current.get_diff(proposed, exclude_unset=True) is True


def test_manage_extended_community_list_00110() -> None:
    """Verify packed route-target config is normalized and serialized canonically."""
    instance = ExtendedCommunityListModel.from_config(
        {
            "name": "ECL-PACKED",
            "type": "standard",
            "entries": [
                {
                    "sequence_number": 10,
                    "action": "permit",
                    "route_target_collection": ["65000:100,65000:200", "192.0.2.1:300"],
                }
            ],
        }
    )

    expected = ["65000:100", "65000:200", "192.0.2.1:300"]
    assert instance.entries[0].route_target_collection == expected
    assert instance.to_payload()["entries"][0]["routeTargetCollection"] == expected


def test_manage_extended_community_list_00120() -> None:
    """Verify packed route targets returned by ND are normalized before reconciliation."""
    instance = ExtendedCommunityListModel.from_response(
        {
            "name": "ECL-PACKED",
            "type": "standard",
            "entries": [
                {
                    "sequenceNumber": 10,
                    "action": "permit",
                    "routeTargetCollection": ["65000:100,65000:200"],
                }
            ],
        }
    )

    assert instance.entries[0].route_target_collection == ["65000:100", "65000:200"]


def test_manage_extended_community_list_00130() -> None:
    """Verify packed response data is idempotent with equivalent unpacked config."""
    current = ExtendedCommunityListModel.from_response(
        {
            "name": "ECL-PACKED",
            "type": "standard",
            "entries": [
                {
                    "sequenceNumber": 10,
                    "action": "permit",
                    "routeTargetCollection": ["65000:100,65000:200"],
                }
            ],
        }
    )
    proposed = ExtendedCommunityListModel.from_config(
        {
            "name": "ECL-PACKED",
            "type": "standard",
            "entries": [
                {
                    "sequence_number": 10,
                    "action": "permit",
                    "route_target_collection": ["65000:100", "65000:200"],
                }
            ],
        }
    )

    assert current.get_diff(proposed, exclude_unset=True) is True


@pytest.mark.parametrize(
    "route_targets",
    (
        ["65000:100,"],
        [",65000:100"],
        ["65000:100,invalid"],
        ["65000:100, 65000:200"],
    ),
)
def test_manage_extended_community_list_00140(route_targets: list[str]) -> None:
    """Verify malformed packed route-target items remain invalid."""
    with pytest.raises(ValueError, match="route_target_collection entry"):
        ExtendedCommunityListModel.from_config(
            {
                "name": "ECL-INVALID",
                "type": "standard",
                "entries": [
                    {
                        "sequence_number": 10,
                        "action": "permit",
                        "route_target_collection": route_targets,
                    }
                ],
            }
        )


@pytest.mark.parametrize(
    "entry",
    (
        {"sequence_number": 10, "action": "permit"},
        {
            "sequence_number": 10,
            "action": "permit",
            "router_mac_collection": [],
            "route_target_collection": [],
            "site_of_origin_collection": [],
            "transitive_generic_extended_collection": [],
            "non_transitive_generic_extended_collection": [],
        },
    ),
)
def test_manage_extended_community_list_00150(entry: dict) -> None:
    """Verify standard entries require at least one non-empty selector collection."""
    with pytest.raises(ValueError, match="at least one standard selector collection"):
        ExtendedCommunityListModel.from_config(
            {
                "name": "ECL-FLAGLESS",
                "type": "standard",
                "entries": [entry],
            }
        )


def test_manage_extended_community_list_00160() -> None:
    """Verify sparse standard entries returned by ND remain readable."""
    instance = ExtendedCommunityListModel.from_response(
        {
            "name": "ECL-RESPONSE",
            "type": "standard",
            "entries": [{"sequenceNumber": 10, "action": "permit"}],
        }
    )

    assert instance.entries[0].route_target_collection is None


@pytest.mark.parametrize(
    ("selector", "value"),
    (
        ("router_mac_collection", "d478.1111.57b8"),
        ("route_target_collection", "65000:100"),
        ("site_of_origin_collection", "64512:300"),
        ("transitive_generic_extended_collection", "65000:123"),
        ("non_transitive_generic_extended_collection", "64512:789"),
    ),
)
def test_manage_extended_community_list_00170(selector: str, value: str) -> None:
    """Verify each standard selector collection independently satisfies the requirement."""
    instance = ExtendedCommunityListModel.from_config(
        {
            "name": "ECL-SELECTOR",
            "type": "standard",
            "entries": [{"sequence_number": 10, "action": "permit", selector: [value]}],
        }
    )

    assert getattr(instance.entries[0], selector) == [value]


# =============================================================================
# Gathered state and filtering tests
# =============================================================================


def test_manage_extended_community_list_00200_gathered_state_in_choices() -> None:
    """
    # Summary

    Verify state choices include ``gathered`` and default is ``merged``.

    ## Classes and Methods

    - ExtendedCommunityListModel.get_argument_spec()
    """
    spec = ExtendedCommunityListModel.get_argument_spec()
    state_spec = spec["state"]
    assert state_spec["choices"] == ["merged", "replaced", "overridden", "deleted", "gathered"]
    assert state_spec["default"] == "merged"


def test_manage_extended_community_list_00210_config_optional_for_gathered() -> None:
    """
    # Summary

    Verify ``config`` is optional so ``state=gathered`` can run without input.

    ## Classes and Methods

    - ExtendedCommunityListModel.get_argument_spec()
    """
    spec = ExtendedCommunityListModel.get_argument_spec()
    assert spec["config"].get("required", False) is False
    assert spec["config"]["options"]["name"].get("required", False) is False


def test_manage_extended_community_list_00220_supports_gathered_filtering() -> None:
    """
    # Summary

    Verify ``supports_gathered_filtering`` is ``True`` on ``ExtendedCommunityListModel``.

    ## Classes and Methods

    - ExtendedCommunityListModel.supports_gathered_filtering
    """
    from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

    assert NDBaseModel.supports_gathered_filtering is False
    assert ExtendedCommunityListModel.supports_gathered_filtering is True


def test_manage_extended_community_list_00230_gathered_filter_properties() -> None:
    """
    # Summary

    Verify ``gathered_filter_properties`` contains ``name`` and ``type``.

    ## Classes and Methods

    - ExtendedCommunityListModel.gathered_filter_properties
    """
    assert ExtendedCommunityListModel.gathered_filter_properties == ("name", "type")


def test_manage_extended_community_list_00240_normalize_gathered_filter_passthrough() -> None:
    """
    # Summary

    Verify ``normalize_gathered_filter`` returns filters unchanged.

    ## Classes and Methods

    - ExtendedCommunityListModel.normalize_gathered_filter()
    """
    assert ExtendedCommunityListModel.normalize_gathered_filter({"name": "ECL1"}) == {"name": "ECL1"}
    assert ExtendedCommunityListModel.normalize_gathered_filter({"type": "standard"}) == {"type": "standard"}
    assert ExtendedCommunityListModel.normalize_gathered_filter({}) == {}
