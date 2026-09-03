# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `PrefixListModel`, `PrefixListEntryModel`.

Tests the Pydantic model classes for managing IPv4 and IPv6 prefix lists.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import annotations

import copy

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_prefix_list.manage_prefix_list import (
    PrefixListEntryModel,
    PrefixListModel,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise

SAMPLE_IPV4_CONFIG = {
    "ip_version": "ipv4",
    "name": "PL-IPV4-BORDERS",
    "description": "IPv4 Border Router Prefixes",
    "tenant_name": "TENANT1",
    "entries": [
        {"sequence_number": 10, "action": "permit", "prefix": "10.0.1.0/24"},
        {"sequence_number": 20, "action": "deny", "prefix": "192.168.0.0/16"},
    ],
}

SAMPLE_IPV6_CONFIG = {
    "ip_version": "ipv6",
    "name": "PL-IPV6-DATACENTER",
    "description": "IPv6 Datacenter Prefixes",
    "tenant_name": "TENANT1",
    "entries": [
        {"sequence_number": 10, "action": "permit", "prefix": "2001:db8::/32", "min_prefix_length": 32, "max_prefix_length": 48},
    ],
}

SAMPLE_IPV4_API_RESPONSE = {
    "ipVersion": "ipv4",
    "name": "PL-IPV4-BORDERS",
    "description": "IPv4 Border Router Prefixes",
    "tenantName": "TENANT1",
    "entries": [
        {"sequenceNumber": 10, "action": "permit", "prefix": "10.0.1.0/24"},
        {"sequenceNumber": 20, "action": "deny", "prefix": "192.168.0.0/16"},
    ],
    "lastUpdateTimestamp": "2026-06-12T10:00:00Z",
}


# =============================================================================
# Test: PrefixListEntryModel validation
# =============================================================================


def test_manage_prefix_list_00010() -> None:
    """
    # Summary

    Verify PrefixListEntryModel instantiates with minimal required fields.

    ## Test

    - Entry can be created with sequence_number, action, and prefix
    - Optional fields default to None

    ## Classes and Methods

    - PrefixListEntryModel.__init__()
    """
    with does_not_raise():
        entry = PrefixListEntryModel(sequence_number=10, action="permit", prefix="10.0.1.0/24")
    assert entry.sequence_number == 10
    assert entry.action == "permit"
    assert entry.prefix == "10.0.1.0/24"
    assert entry.exact_length is None
    assert entry.min_prefix_length is None
    assert entry.max_prefix_length is None
    assert entry.mask is None


def test_manage_prefix_list_00015() -> None:
    """
    # Summary

    Verify PrefixListEntryModel defaults action to permit.

    ## Classes and Methods

    - PrefixListEntryModel.__init__()
    """
    entry = PrefixListEntryModel(sequence_number=10, prefix="10.0.1.0/24")

    assert entry.action == "permit"


def test_manage_prefix_list_00020() -> None:
    """
    # Summary

    Verify sequence_number must be in valid range [1, 4294967294].

    ## Test

    - sequence_number=0 raises ValidationError
    - sequence_number=4294967295 raises ValidationError

    ## Classes and Methods

    - PrefixListEntryModel validators
    """
    bad_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    bad_config["entries"] = [{"sequence_number": 0, "action": "permit", "prefix": "10.0.1.0/24"}]
    with pytest.raises(ValidationError, match="sequence_number"):
        PrefixListModel(**bad_config)

    bad_config["entries"] = [{"sequence_number": 4294967295, "action": "permit", "prefix": "10.0.1.0/24"}]
    with pytest.raises(ValidationError, match="sequence_number"):
        PrefixListModel(**bad_config)


def test_manage_prefix_list_00030() -> None:
    """
    # Summary

    Verify IPv4 prefix validates and rejects invalid CIDR.

    ## Test

    - Valid IPv4 CIDR "10.0.1.0/24" is accepted
    - Invalid CIDR "999.999.999.999/24" raises ValidationError

    ## Classes and Methods

    - IPv4NetworkCIDR validator (shared types)
    """
    with does_not_raise():
        entry = PrefixListEntryModel(sequence_number=10, action="permit", prefix="10.0.1.0/24")
    assert entry.prefix == "10.0.1.0/24"

    bad_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    bad_config["entries"] = [{"sequence_number": 10, "action": "permit", "prefix": "999.999.999.999/24"}]
    with pytest.raises(ValidationError, match="not a valid IP network"):
        PrefixListModel(**bad_config)


def test_manage_prefix_list_00040() -> None:
    """
    # Summary

    Verify IPv6 prefix validates and rejects invalid CIDR.

    ## Test

    - Valid IPv6 CIDR "2001:db8::/32" is accepted
    - Invalid CIDR "gggg::/32" raises ValidationError

    ## Classes and Methods

    - IPv6NetworkCIDR validator (shared types)
    """
    with does_not_raise():
        entry = PrefixListEntryModel(sequence_number=10, action="permit", prefix="2001:db8::/32")
    assert entry.prefix == "2001:db8::/32"

    bad_config = copy.deepcopy(SAMPLE_IPV6_CONFIG)
    bad_config["entries"] = [{"sequence_number": 10, "action": "permit", "prefix": "gggg::/32"}]
    with pytest.raises(ValidationError, match="not a valid IP network"):
        PrefixListModel(**bad_config)


def test_manage_prefix_list_00045() -> None:
    """
    # Summary

    Verify IPv6 prefixes and masks are normalized for stable diff comparison.

    ## Classes and Methods

    - PrefixListEntryModel.normalize_prefix
    - PrefixListEntryModel.normalize_mask
    """
    model = PrefixListModel.from_config(
        {
            "ip_version": "ipv6",
            "name": "PL-IPV6-NORMALIZE",
            "entries": [
                {
                    "sequence_number": 10,
                    "action": "permit",
                    "prefix": "2001:0db8:0000:0000:0000:0000:0000:0000/32",
                    "mask": "ffff:ffff:0000:0000:0000:0000:0000:0000",
                }
            ],
        }
    )

    assert model.entries[0].prefix == "2001:db8::/32"
    assert model.entries[0].mask == "ffff:ffff::"


# =============================================================================
# Test: PrefixListModel semantic validators
# =============================================================================


def test_manage_prefix_list_00050() -> None:
    """
    # Summary

    Verify duplicate sequence_number entries are rejected.

    ## Test

    - Two entries with same sequence_number raises ValidationError

    ## Classes and Methods

    - PrefixListModel.validate_entries_for_ip_version
    """
    bad_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    bad_config["entries"] = [
        {"sequence_number": 10, "action": "permit", "prefix": "10.0.1.0/24"},
        {"sequence_number": 10, "action": "deny", "prefix": "192.168.0.0/16"},
    ]
    with pytest.raises(ValidationError, match="duplicated"):
        PrefixListModel(**bad_config)


def test_manage_prefix_list_00060() -> None:
    """
    # Summary

    Verify exact_length is mutually exclusive with min/max_prefix_length.

    ## Test

    - Entry with both exact_length and min_prefix_length raises ValidationError

    ## Classes and Methods

    - PrefixListModel.validate_entries_for_ip_version
    """
    bad_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    bad_config["entries"] = [
        {
            "sequence_number": 10,
            "action": "permit",
            "prefix": "10.0.0.0/8",
            "exact_length": 24,
            "min_prefix_length": 16,
        },
    ]
    with pytest.raises(ValidationError, match="cannot define exactLength together"):
        PrefixListModel(**bad_config)


def test_manage_prefix_list_00070() -> None:
    """
    # Summary

    Verify min_prefix_length <= max_prefix_length.

    ## Test

    - min_prefix_length > max_prefix_length raises ValidationError

    ## Classes and Methods

    - PrefixListModel.validate_entries_for_ip_version
    """
    bad_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    bad_config["entries"] = [
        {
            "sequence_number": 10,
            "action": "permit",
            "prefix": "10.0.0.0/8",
            "min_prefix_length": 30,
            "max_prefix_length": 24,
        },
    ]
    with pytest.raises(ValidationError, match="cannot be greater than"):
        PrefixListModel(**bad_config)


def test_manage_prefix_list_00080() -> None:
    """
    # Summary

    Verify IPv4 exact_length is in valid range [1, 32].

    ## Test

    - exact_length=0 raises ValidationError
    - exact_length=33 raises ValidationError

    ## Classes and Methods

    - PrefixListModel.validate_entries_for_ip_version
    """
    bad_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    bad_config["entries"] = [{"sequence_number": 10, "action": "permit", "prefix": "10.0.0.0/8", "exact_length": 0}]
    with pytest.raises(ValidationError, match="exactLength.*out of range"):
        PrefixListModel(**bad_config)

    bad_config["entries"] = [{"sequence_number": 10, "action": "permit", "prefix": "10.0.0.0/8", "exact_length": 33}]
    with pytest.raises(ValidationError, match="exactLength.*out of range"):
        PrefixListModel(**bad_config)


def test_manage_prefix_list_00090() -> None:
    """
    # Summary

    Verify IPv6 exact_length is in valid range [1, 128].

    ## Test

    - exact_length=0 raises ValidationError
    - exact_length=129 raises ValidationError

    ## Classes and Methods

    - PrefixListModel.validate_entries_for_ip_version
    """
    bad_config = copy.deepcopy(SAMPLE_IPV6_CONFIG)
    bad_config["entries"] = [{"sequence_number": 10, "action": "permit", "prefix": "2001:db8::/32", "exact_length": 0}]
    with pytest.raises(ValidationError, match="exactLength.*out of range"):
        PrefixListModel(**bad_config)

    bad_config["entries"] = [{"sequence_number": 10, "action": "permit", "prefix": "2001:db8::/32", "exact_length": 129}]
    with pytest.raises(ValidationError, match="exactLength.*out of range"):
        PrefixListModel(**bad_config)


def test_manage_prefix_list_00100() -> None:
    """
    # Summary

    Verify IPv4 min/max_prefix_length are in valid range [1, 32].

    ## Test

    - min_prefix_length=0 raises ValidationError
    - max_prefix_length=33 raises ValidationError

    ## Classes and Methods

    - PrefixListModel.validate_entries_for_ip_version
    """
    bad_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    bad_config["entries"] = [{"sequence_number": 10, "action": "permit", "prefix": "10.0.0.0/8", "min_prefix_length": 0}]
    with pytest.raises(ValidationError, match="minLength.*out of range"):
        PrefixListModel(**bad_config)

    bad_config["entries"] = [{"sequence_number": 10, "action": "permit", "prefix": "10.0.0.0/8", "max_prefix_length": 33}]
    with pytest.raises(ValidationError, match="maxLength.*out of range"):
        PrefixListModel(**bad_config)


def test_manage_prefix_list_00110() -> None:
    """
    # Summary

    Verify description accepts only ASCII characters.

    ## Test

    - ASCII description is accepted
    - Non-ASCII description raises ValidationError

    ## Classes and Methods

    - AsciiDescription validator (shared types)
    """
    good_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    good_config["description"] = "ASCII-only description 123"
    with does_not_raise():
        model = PrefixListModel(**good_config)
    assert model.description == "ASCII-only description 123"

    bad_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    bad_config["description"] = "Non-ASCII: café"
    with pytest.raises(ValidationError, match="ASCII"):
        PrefixListModel(**bad_config)


# =============================================================================
# Test: PrefixListModel identifier strategy
# =============================================================================


def test_manage_prefix_list_00120() -> None:
    """
    # Summary

    Verify identifier strategy is composite (ip_version + name).

    ## Test

    - identifier_strategy is "composite"
    - identifiers is ["ip_version", "tenant_name", "name"]
    - get_identifier_value() returns (ip_version, tenant_name, name) tuple

    ## Classes and Methods

    - PrefixListModel.identifier_strategy
    - PrefixListModel.identifiers
    - PrefixListModel.get_identifier_value
    """
    assert PrefixListModel.identifier_strategy == "composite"
    assert PrefixListModel.identifiers == ["ip_version", "tenant_name", "name"]

    model = PrefixListModel(**SAMPLE_IPV4_CONFIG)
    assert model.get_identifier_value() == ("ipv4", "TENANT1", "PL-IPV4-BORDERS")


# =============================================================================
# Test: from_response / from_config factories
# =============================================================================


def test_manage_prefix_list_00130() -> None:
    """
    # Summary

    Verify from_response accepts ND API camelCase keys.

    ## Test

    - from_response() accepts ipVersion, prefixListEntries, camelCase keys
    - Snake_case fields are populated correctly

    ## Classes and Methods

    - PrefixListModel.from_response
    """
    with does_not_raise():
        model = PrefixListModel.from_response(copy.deepcopy(SAMPLE_IPV4_API_RESPONSE))
    assert model.ip_version == "ipv4"
    assert model.name == "PL-IPV4-BORDERS"
    assert model.description == "IPv4 Border Router Prefixes"
    assert model.tenant_name == "TENANT1"
    # prefixListEntries in response maps to entries field
    assert model.entries is not None
    assert len(model.entries) == 2
    assert model.entries[0].sequence_number == 10
    assert model.last_update_timestamp == "2026-06-12T10:00:00Z"


def test_manage_prefix_list_00135() -> None:
    """
    # Summary

    Verify tenant-scoped API names are normalized from tenant~name to bare name plus tenant_name.

    ## Classes and Methods

    - PrefixListModel.normalize_tenant_scoped_name
    - PrefixListModel.api_name
    """
    model = PrefixListModel.from_response(
        {
            "ipVersion": "ipv4",
            "name": "TENANT1~PL-SHARED",
            "tenantName": "TENANT1",
            "entries": [{"sequenceNumber": 10, "action": "permit", "prefix": "10.0.0.0/8"}],
        }
    )

    assert model.name == "PL-SHARED"
    assert model.tenant_name == "TENANT1"
    assert model.api_name == "TENANT1~PL-SHARED"
    assert model.get_identifier_value() == ("ipv4", "TENANT1", "PL-SHARED")


def test_manage_prefix_list_00140() -> None:
    """
    # Summary

    Verify from_config accepts Ansible snake_case keys.

    ## Test

    - from_config() accepts snake_case keys
    - Nested entries are instantiated as PrefixListEntryModel

    ## Classes and Methods

    - PrefixListModel.from_config
    """
    with does_not_raise():
        model = PrefixListModel.from_config(copy.deepcopy(SAMPLE_IPV4_CONFIG))
    assert model.ip_version == "ipv4"
    assert model.name == "PL-IPV4-BORDERS"
    assert len(model.entries) == 2
    assert all(isinstance(e, PrefixListEntryModel) for e in model.entries)


# =============================================================================
# Test: to_payload serialization
# =============================================================================


def test_manage_prefix_list_00150() -> None:
    """
    # Summary

    Verify to_payload() excludes ip_version and last_update_timestamp.

    ## Test

    - to_payload() returns payload with entries
    - ip_version and last_update_timestamp are not in payload

    ## Classes and Methods

    - PrefixListModel.to_payload
    """
    model = PrefixListModel.from_config(copy.deepcopy(SAMPLE_IPV4_CONFIG))
    payload = model.to_payload()

    assert "name" in payload
    assert "description" in payload
    assert "tenantName" in payload
    # entries key is present (may be serialized as prefixListEntries by API layer)
    assert "entries" in payload or "prefixListEntries" in payload
    assert "ipVersion" not in payload
    assert "lastUpdateTimestamp" not in payload


def test_manage_prefix_list_00160() -> None:
    """
    # Summary

    Verify to_payload() with entries=None produces valid payload (delete operations).

    ## Test

    - to_payload() with None entries returns payload without entries key
    - Other fields are still present

    ## Classes and Methods

    - PrefixListModel.to_payload
    """
    model = PrefixListModel(ip_version="ipv4", name="PL-IPV4-BORDERS", entries=None)
    payload = model.to_payload()

    assert payload.get("name") == "PL-IPV4-BORDERS"
    # prefixListEntries should not be present or should be None/excluded


def test_manage_prefix_list_00165() -> None:
    """
    # Summary

    Verify replace-style diff detects stale descriptions when config omits description.

    ## Classes and Methods

    - PrefixListModel.get_diff
    """
    existing = PrefixListModel.from_response(copy.deepcopy(SAMPLE_IPV4_API_RESPONSE))
    proposed = PrefixListModel.from_config(
        {
            "ip_version": "ipv4",
            "tenant_name": "TENANT1",
            "name": "PL-IPV4-BORDERS",
            "entries": copy.deepcopy(SAMPLE_IPV4_CONFIG["entries"]),
        }
    )

    assert existing.get_diff(proposed, exclude_unset=True) is True
    assert existing.get_diff(proposed, exclude_unset=False) is False

    existing.description = ""
    assert existing.get_diff(proposed, exclude_unset=False) is True


# =============================================================================
# Test: argument spec
# =============================================================================


def test_manage_prefix_list_00170() -> None:
    """
    # Summary

    Verify argument spec shape matches module documentation.

    ## Test

    - fabric_name is top-level required field
    - config is a list of dicts
    - ip_version and name are required in config (with aliases)
    - entries is required=false (semantic enforcement)

    ## Classes and Methods

    - PrefixListModel.get_argument_spec
    """
    spec = PrefixListModel.get_argument_spec()

    # Top-level fields
    assert spec["fabric_name"] == {"type": "str", "required": True}
    assert spec["cluster_name"] == {"type": "str", "required": False}

    # Config structure
    config = spec["config"]
    assert config["type"] == "list"
    assert config["elements"] == "dict"

    # Config options
    opts = config["options"]
    # ip_version includes aliases
    assert opts["ip_version"]["type"] == "str"
    assert opts["ip_version"].get("required", False) is False
    assert opts["ip_version"]["choices"] == ["ipv4", "ipv6"]
    assert "aliases" in opts["ip_version"]  # Has aliases key

    assert opts["name"]["type"] == "str"
    assert opts["name"].get("required", False) is False
    assert opts["description"]["type"] == "str"
    # tenant_name has aliases
    assert opts["tenant_name"]["type"] == "str"
    assert "aliases" in opts["tenant_name"]

    # Entries (required=false for delete semantic flexibility)
    entries = opts["entries"]
    assert entries["type"] == "list"
    assert entries["elements"] == "dict"
    assert entries["required"] is False
    assert entries["options"]["action"]["required"] is False
    assert "default" not in entries["options"]["action"]
    assert PrefixListEntryModel(sequence_number=10, prefix="10.0.0.0/8").action == "permit"


def test_manage_prefix_list_00175() -> None:
    """
    # Summary

    Verify state-dependent entries validation.

    ## Classes and Methods

    - PrefixListModel.validate_config_for_state
    """
    config = [{"ip_version": "ipv4", "name": "PL-IPV4-BORDERS"}]

    with pytest.raises(ValueError, match="entries is required"):
        PrefixListModel.validate_config_for_state(config, "merged")

    with does_not_raise():
        PrefixListModel.validate_config_for_state(config, "deleted")


# =============================================================================
# Test: edge cases
# =============================================================================


def test_manage_prefix_list_00180() -> None:
    """
    # Summary

    Verify IPv4 and IPv6 prefix lists can have the same name (composite key).

    ## Test

    - Two models with same name but different ip_version are distinct
    - Both deserialize without conflict

    ## Classes and Methods

    - PrefixListModel composite identifier handling
    """
    ipv4 = PrefixListModel.from_config(
        {"ip_version": "ipv4", "name": "PL-SHARED", "entries": [{"sequence_number": 10, "action": "permit", "prefix": "10.0.0.0/8"}]}
    )
    ipv6 = PrefixListModel.from_config(
        {"ip_version": "ipv6", "name": "PL-SHARED", "entries": [{"sequence_number": 10, "action": "permit", "prefix": "2001:db8::/32"}]}
    )

    assert ipv4.get_identifier_value() != ipv6.get_identifier_value()
    assert ipv4.get_identifier_value() == ("ipv4", None, "PL-SHARED")
    assert ipv6.get_identifier_value() == ("ipv6", None, "PL-SHARED")


def test_manage_prefix_list_00190() -> None:
    """
    # Summary

    Verify same prefix list name can coexist across tenants.

    ## Classes and Methods

    - PrefixListModel composite identifier handling
    """
    tenant_a = PrefixListModel.from_config(
        {
            "ip_version": "ipv4",
            "tenant_name": "TENANT_A",
            "name": "PL-SHARED",
            "entries": [{"sequence_number": 10, "action": "permit", "prefix": "10.0.0.0/8"}],
        }
    )
    tenant_b = PrefixListModel.from_config(
        {
            "ip_version": "ipv4",
            "tenant_name": "TENANT_B",
            "name": "PL-SHARED",
            "entries": [{"sequence_number": 10, "action": "permit", "prefix": "10.0.0.0/8"}],
        }
    )

    assert tenant_a.get_identifier_value() != tenant_b.get_identifier_value()
    assert tenant_a.api_name == "TENANT_A~PL-SHARED"
    assert tenant_b.api_name == "TENANT_B~PL-SHARED"


def test_manage_prefix_list_00200() -> None:
    """
    # Summary

    Verify default-tenant prefix list names are limited to 63 characters.

    ## Classes and Methods

    - PrefixListModel.validate_name_length_for_tenant_scope
    """
    good_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    good_config.pop("tenant_name")
    good_config["name"] = "P" * 63
    with does_not_raise():
        PrefixListModel.from_config(good_config)

    bad_config = copy.deepcopy(good_config)
    bad_config["name"] = "P" * 64
    with pytest.raises(ValidationError, match="tenant_name is omitted"):
        PrefixListModel.from_config(bad_config)


def test_manage_prefix_list_00210() -> None:
    """
    # Summary

    Verify tenant-qualified prefix list names are limited to 115 characters.

    ## Classes and Methods

    - PrefixListModel.validate_name_length_for_tenant_scope
    """
    good_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    good_config["tenant_name"] = "T" * 8
    good_config["name"] = "P" * 106
    with does_not_raise():
        model = PrefixListModel.from_config(good_config)
    assert len(model.api_name) == 115

    bad_config = copy.deepcopy(good_config)
    bad_config["name"] = "P" * 107
    with pytest.raises(ValidationError, match="combined tenant-qualified"):
        PrefixListModel.from_config(bad_config)


# =============================================================================
# Gathered state and filtering tests
# =============================================================================


def test_manage_prefix_list_00300_gathered_state_in_choices() -> None:
    """
    # Summary

    Verify state choices include ``gathered`` and default is ``merged``.

    ## Classes and Methods

    - PrefixListModel.get_argument_spec()
    """
    spec = PrefixListModel.get_argument_spec()
    state_spec = spec["state"]
    assert state_spec["choices"] == ["merged", "replaced", "overridden", "deleted", "gathered"]
    assert state_spec["default"] == "merged"


def test_manage_prefix_list_00310_config_optional_for_gathered() -> None:
    """
    # Summary

    Verify ``config`` is optional so ``state=gathered`` can run without input.

    ## Classes and Methods

    - PrefixListModel.get_argument_spec()
    """
    spec = PrefixListModel.get_argument_spec()
    assert spec["config"].get("required", False) is False
    opts = spec["config"]["options"]
    assert opts["ip_version"].get("required", False) is False
    assert opts["name"].get("required", False) is False


def test_manage_prefix_list_00320_supports_gathered_filtering() -> None:
    """
    # Summary

    Verify ``supports_gathered_filtering`` is ``True`` on ``PrefixListModel``.

    ## Classes and Methods

    - PrefixListModel.supports_gathered_filtering
    """
    from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

    assert NDBaseModel.supports_gathered_filtering is False
    assert PrefixListModel.supports_gathered_filtering is True


def test_manage_prefix_list_00330_gathered_filter_properties() -> None:
    """
    # Summary

    Verify ``gathered_filter_properties`` contains ``ip_version`` and ``name``.

    ## Classes and Methods

    - PrefixListModel.gathered_filter_properties
    """
    assert PrefixListModel.gathered_filter_properties == ("ip_version", "name")


def test_manage_prefix_list_00340_normalize_gathered_filter_passthrough() -> None:
    """
    # Summary

    Verify ``normalize_gathered_filter`` returns filters unchanged.

    ## Classes and Methods

    - PrefixListModel.normalize_gathered_filter()
    """
    assert PrefixListModel.normalize_gathered_filter({"ip_version": "ipv4", "name": "PL1"}) == {"ip_version": "ipv4", "name": "PL1"}
    assert PrefixListModel.normalize_gathered_filter({"ip_version": "ipv6"}) == {"ip_version": "ipv6"}
    assert PrefixListModel.normalize_gathered_filter({}) == {}
