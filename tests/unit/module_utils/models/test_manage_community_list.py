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

    assert config_options["name"].get("required", False) is False
    assert spec["cluster_name"]["type"] == "str"
    assert "required" not in config_options["type"]
    assert "required" not in config_options["entries"]


def test_manage_community_list_00050() -> None:
    """Verify tenant-scoped names are normalized while API identity stays qualified."""
    instance = CommunityListModel.from_config(
        {
            "name": "tenantA~CL-TENANT",
            "tenant_name": "tenantA",
            "type": "standard",
            "entries": [{"sequence_number": 10, "action": "permit", "internet": True}],
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
            "entries": [{"sequence_number": 10, "action": "permit", "internet": True}],
        },
        context={"state": "merged"},
    )

    assert deleted.type is None
    assert without_state.entries is None
    assert complete.type == "standard"


def test_manage_community_list_00100() -> None:
    """Verify ND-added false defaults do not break merged-state idempotency."""
    current = CommunityListModel.from_response(
        {
            "name": "CL1",
            "type": "standard",
            "entries": [
                {
                    "sequenceNumber": 10,
                    "action": "permit",
                    "communityNumbers": ["100:200"],
                    "noAdvertise": False,
                    "blackhole": False,
                    "noExport": False,
                    "internet": False,
                    "gracefulShutdown": False,
                    "localAsn": False,
                },
                {
                    "sequenceNumber": 20,
                    "action": "deny",
                    "communityNumbers": [],
                    "noAdvertise": False,
                    "blackhole": False,
                    "noExport": True,
                    "internet": False,
                    "gracefulShutdown": False,
                    "localAsn": False,
                },
            ],
        }
    )
    proposed = CommunityListModel.from_config(
        {
            "name": "CL1",
            "type": "standard",
            "entries": [
                {"sequence_number": 10, "action": "permit", "community_numbers": ["100:200"]},
                {"sequence_number": 20, "action": "deny", "no_export": True},
            ],
        }
    )

    assert current.get_diff(proposed, exclude_unset=True) is True


def test_manage_community_list_00110() -> None:
    """Verify explicitly clearing a true well-known flag still produces a diff."""
    current = CommunityListModel.from_response(
        {
            "name": "CL1",
            "type": "standard",
            "entries": [
                {
                    "sequenceNumber": 10,
                    "action": "permit",
                    "communityNumbers": ["100:200"],
                    "noExport": True,
                }
            ],
        }
    )
    proposed = CommunityListModel.from_config(
        {
            "name": "CL1",
            "type": "standard",
            "entries": [
                {
                    "sequence_number": 10,
                    "action": "permit",
                    "community_numbers": ["100:200"],
                    "no_export": False,
                }
            ],
        }
    )

    assert current.get_diff(proposed, exclude_unset=True) is False


@pytest.mark.parametrize(
    "entry",
    (
        {"sequence_number": 10, "action": "permit"},
        {"sequence_number": 10, "action": "permit", "community_numbers": []},
        {
            "sequence_number": 10,
            "action": "permit",
            "no_advertise": False,
            "blackhole": False,
            "no_export": False,
            "internet": False,
            "graceful_shutdown": False,
            "local_asn": False,
        },
    ),
)
def test_manage_community_list_00120(entry: dict[str, object]) -> None:
    """Verify standard config entries require a community number or an enabled flag."""
    with pytest.raises(ValueError, match="must set at least one community number or enable at least one well-known community flag"):
        CommunityListModel.from_config(
            {
                "name": "CL-STANDARD",
                "type": "standard",
                "entries": [entry],
            },
            context={"state": "merged"},
        )


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    (
        ("community_numbers", ["100:200"]),
        ("no_advertise", True),
        ("blackhole", True),
        ("no_export", True),
        ("internet", True),
        ("graceful_shutdown", True),
        ("local_asn", True),
    ),
)
def test_manage_community_list_00130(field_name: str, field_value: object) -> None:
    """Verify every supported standard-entry match selector satisfies validation."""
    entry = {
        "sequence_number": 10,
        "action": "permit",
        field_name: field_value,
    }

    instance = CommunityListModel.from_config(
        {
            "name": "CL-STANDARD",
            "type": "standard",
            "entries": [entry],
        },
        context={"state": "merged"},
    )

    assert getattr(instance.entries[0], field_name) == field_value


def test_manage_community_list_00140() -> None:
    """Verify flagless standard entries remain parseable as controller responses."""
    instance = CommunityListModel.from_response(
        {
            "name": "CL-STANDARD",
            "type": "standard",
            "entries": [{"sequenceNumber": 10, "action": "permit"}],
        }
    )

    assert instance.entries[0].sequence_number == 10


# =============================================================================
# Gathered state and filtering tests
# =============================================================================


def test_manage_community_list_00200_gathered_state_in_choices() -> None:
    """
    # Summary

    Verify state choices include ``gathered`` and default is ``merged``.

    ## Test

    - state choices: ["merged", "replaced", "overridden", "deleted", "gathered"]
    - state default: "merged"

    ## Classes and Methods

    - CommunityListModel.get_argument_spec()
    """
    spec = CommunityListModel.get_argument_spec()
    state_spec = spec["state"]
    assert state_spec["choices"] == [
        "merged",
        "replaced",
        "overridden",
        "deleted",
        "gathered",
    ]
    assert state_spec["default"] == "merged"


def test_manage_community_list_00210_config_optional_for_gathered() -> None:
    """
    # Summary

    Verify ``config`` is optional so ``state=gathered`` can run without input.

    ## Test

    - config required is False
    - name within config is not required

    ## Classes and Methods

    - CommunityListModel.get_argument_spec()
    """
    spec = CommunityListModel.get_argument_spec()
    assert spec["config"].get("required", False) is False
    config_options = spec["config"]["options"]
    assert config_options["name"].get("required", False) is False


def test_manage_community_list_00220_supports_gathered_filtering() -> None:
    """
    # Summary

    Verify ``supports_gathered_filtering`` is ``True`` on ``CommunityListModel``
    and ``False`` on the base ``NDBaseModel``.

    ## Test

    - NDBaseModel.supports_gathered_filtering is False
    - CommunityListModel.supports_gathered_filtering is True

    ## Classes and Methods

    - NDBaseModel.supports_gathered_filtering
    - CommunityListModel.supports_gathered_filtering
    """
    from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

    assert NDBaseModel.supports_gathered_filtering is False
    assert CommunityListModel.supports_gathered_filtering is True


def test_manage_community_list_00230_gathered_filter_properties() -> None:
    """
    # Summary

    Verify ``gathered_filter_properties`` contains the expected 2 properties.

    ## Test

    - gathered_filter_properties tuple has exactly 2 entries
    - Entries are "name" and "type"

    ## Classes and Methods

    - CommunityListModel.gathered_filter_properties
    """
    assert CommunityListModel.gathered_filter_properties == (
        "name",
        "type",
    )


def test_manage_community_list_00240_normalize_gathered_filter_passthrough() -> None:
    """
    # Summary

    Verify ``normalize_gathered_filter`` returns filters unchanged
    (no custom normalization needed for community lists).

    ## Test

    - A filter with name is returned unchanged
    - A filter with type is returned unchanged
    - An empty filter is returned unchanged

    ## Classes and Methods

    - CommunityListModel.normalize_gathered_filter()
    """
    assert CommunityListModel.normalize_gathered_filter({"name": "CL1"}) == {"name": "CL1"}
    assert CommunityListModel.normalize_gathered_filter({"type": "standard"}) == {"type": "standard"}
    assert CommunityListModel.normalize_gathered_filter({}) == {}
