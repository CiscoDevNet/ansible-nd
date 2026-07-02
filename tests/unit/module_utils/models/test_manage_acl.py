# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Slawomir Kaszlikowski (@skaszlik)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `AclModel`, `AclEntryModel`.

Tests the Pydantic model classes for managing IPv4 and IPv6 access control lists.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import copy

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.models.acl.acl import (
    AclEntryModel,
    AclModel,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise

SAMPLE_IPV4_CONFIG = {
    "type": "ipv4",
    "name": "ACL-IPV4-WEB",
    "description": "IPv4 web ACL",
    "entries": [
        {"sequence_number": 10, "action": "permit", "protocol": "tcp", "src": "any", "dst": "10.0.0.0/24", "dst_port_action": "equal_to", "dst_port": 80},
        {"sequence_number": 20, "action": "deny", "protocol": "ip", "src": "any", "dst": "any"},
    ],
}

SAMPLE_IPV4_API_RESPONSE = {
    "type": "ipv4",
    "name": "ACL-IPV4-WEB",
    "description": "IPv4 web ACL",
    "entries": [
        {"sequenceNumber": 10, "action": "permit", "protocol": "tcp", "src": "any", "dst": "10.0.0.0/24", "dstPortAction": "equalTo", "dstPort": 80},
        {"sequenceNumber": 20, "action": "deny", "protocol": "ip", "src": "any", "dst": "any"},
    ],
    "lastUpdateTimestamp": "2026-06-12T10:00:00Z",
}


# =============================================================================
# Test: AclEntryModel validation
# =============================================================================


def test_manage_acl_00010() -> None:
    """
    # Summary

    Verify AclEntryModel instantiates with minimal required fields.

    ## Test

    - Entry can be created with sequence_number and action only
    - Optional match/port fields default to None

    ## Classes and Methods

    - AclEntryModel.__init__()
    """
    with does_not_raise():
        entry = AclEntryModel(sequence_number=10, action="permit")
    assert entry.sequence_number == 10
    assert str(entry.action) == "permit"
    assert entry.protocol is None
    assert entry.src is None
    assert entry.dst is None
    assert entry.src_port_action is None
    assert entry.dst_port_action is None


def test_manage_acl_00020() -> None:
    """
    # Summary

    Verify sequence_number must be in valid range [1, 4294967294].

    ## Test

    - sequence_number=0 raises ValidationError
    - sequence_number=4294967295 raises ValidationError

    ## Classes and Methods

    - AclEntryModel field constraints
    """
    with pytest.raises(ValidationError, match="sequence_number"):
        AclEntryModel(sequence_number=0, action="permit")

    with pytest.raises(ValidationError, match="sequence_number"):
        AclEntryModel(sequence_number=4294967295, action="permit")


def test_manage_acl_00030() -> None:
    """
    # Summary

    Verify snake_case port-action input is normalised to the API wire value.

    ## Test

    - src_port_action="equal_to" is stored as the wire value "equalTo"
    - dst_port_action="port_range" is stored as "portRange"

    ## Classes and Methods

    - AclEntryModel.normalize_port_action
    """
    with does_not_raise():
        entry = AclEntryModel(sequence_number=10, action="permit", src_port_action="equal_to", src_port=80)
    assert str(entry.src_port_action) == "equalTo"

    with does_not_raise():
        entry = AclEntryModel(
            sequence_number=20,
            action="permit",
            dst_port_action="port_range",
            dst_port_range_start=100,
            dst_port_range_end=200,
        )
    assert str(entry.dst_port_action) == "portRange"


def test_manage_acl_00040() -> None:
    """
    # Summary

    Verify a port-action value of "none" collapses to None (excluded from payload/diff).

    ## Test

    - src_port_action="none" results in src_port_action is None

    ## Classes and Methods

    - AclEntryModel.normalize_port_action
    """
    with does_not_raise():
        entry = AclEntryModel(sequence_number=10, action="permit", src_port_action="none")
    assert entry.src_port_action is None


def test_manage_acl_00050() -> None:
    """
    # Summary

    Verify port-action input already in wire form is accepted (API responses).

    ## Test

    - src_port_action="equalTo" (camelCase) validates and is preserved

    ## Classes and Methods

    - AclEntryModel.normalize_port_action
    """
    with does_not_raise():
        entry = AclEntryModel(sequence_number=10, action="permit", src_port_action="equalTo", src_port=443)
    assert str(entry.src_port_action) == "equalTo"


# =============================================================================
# Test: AclModel semantic validators
# =============================================================================


def test_manage_acl_00060() -> None:
    """
    # Summary

    Verify duplicate sequence_number entries are rejected.

    ## Test

    - Two entries with the same sequence_number raise ValidationError

    ## Classes and Methods

    - AclModel.validate_entries
    """
    bad_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    bad_config["entries"] = [
        {"sequence_number": 10, "action": "permit", "protocol": "ip", "src": "any", "dst": "any"},
        {"sequence_number": 10, "action": "deny", "protocol": "ip", "src": "any", "dst": "any"},
    ]
    with pytest.raises(ValidationError, match="duplicated"):
        AclModel(**bad_config)


def test_manage_acl_00070() -> None:
    """
    # Summary

    Verify a 'remark' entry requires remark_comment.

    ## Test

    - action='remark' without remark_comment raises ValidationError

    ## Classes and Methods

    - AclModel._validate_entry
    """
    bad_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    bad_config["entries"] = [{"sequence_number": 10, "action": "remark"}]
    with pytest.raises(ValidationError, match="remark_comment"):
        AclModel(**bad_config)


def test_manage_acl_00080() -> None:
    """
    # Summary

    Verify permit/deny entries require protocol, src, and dst.

    ## Test

    - action='permit' missing protocol/src/dst raises ValidationError

    ## Classes and Methods

    - AclModel._validate_entry
    """
    bad_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    bad_config["entries"] = [{"sequence_number": 10, "action": "permit"}]
    with pytest.raises(ValidationError, match="required for permit/deny"):
        AclModel(**bad_config)


def test_manage_acl_00090() -> None:
    """
    # Summary

    Verify protocol='custom' requires custom_protocol.

    ## Test

    - protocol='custom' without custom_protocol raises ValidationError

    ## Classes and Methods

    - AclModel._validate_entry
    """
    bad_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    bad_config["entries"] = [{"sequence_number": 10, "action": "permit", "protocol": "custom", "src": "any", "dst": "any"}]
    with pytest.raises(ValidationError, match="custom_protocol"):
        AclModel(**bad_config)


def test_manage_acl_00100() -> None:
    """
    # Summary

    Verify port_range operator requires range start/end and start <= end.

    ## Test

    - port_range without start/end raises ValidationError
    - port_range with start > end raises ValidationError

    ## Classes and Methods

    - AclModel._validate_port_options
    """
    bad_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    bad_config["entries"] = [{"sequence_number": 10, "action": "permit", "protocol": "tcp", "src": "any", "dst": "any", "dst_port_action": "port_range"}]
    with pytest.raises(ValidationError, match="port_range_start.*port_range_end.*required"):
        AclModel(**bad_config)

    bad_config["entries"] = [
        {
            "sequence_number": 10,
            "action": "permit",
            "protocol": "tcp",
            "src": "any",
            "dst": "any",
            "dst_port_action": "port_range",
            "dst_port_range_start": 200,
            "dst_port_range_end": 100,
        }
    ]
    with pytest.raises(ValidationError, match="must be less than or equal to"):
        AclModel(**bad_config)


def test_manage_acl_00110() -> None:
    """
    # Summary

    Verify a non-range port operator requires the scalar port value.

    ## Test

    - dst_port_action='equal_to' without dst_port raises ValidationError

    ## Classes and Methods

    - AclModel._validate_port_options
    """
    bad_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    bad_config["entries"] = [{"sequence_number": 10, "action": "permit", "protocol": "tcp", "src": "any", "dst": "any", "dst_port_action": "equal_to"}]
    with pytest.raises(ValidationError, match="dst_port.*required"):
        AclModel(**bad_config)


def test_manage_acl_00120() -> None:
    """
    # Summary

    Verify icmp_option/tcp_option are only valid with their matching protocol.

    ## Test

    - icmp_option with protocol='tcp' raises ValidationError
    - tcp_option with protocol='udp' raises ValidationError

    ## Classes and Methods

    - AclModel._validate_entry
    """
    bad_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    bad_config["entries"] = [
        {
            "sequence_number": 10,
            "action": "permit",
            "protocol": "tcp",
            "src": "any",
            "dst": "any",
            "dst_port_action": "equal_to",
            "dst_port": 80,
            "icmp_option": "echo",
        }
    ]
    with pytest.raises(ValidationError, match="icmp_option"):
        AclModel(**bad_config)

    bad_config["entries"] = [{"sequence_number": 10, "action": "permit", "protocol": "udp", "src": "any", "dst": "any", "tcp_option": "established"}]
    with pytest.raises(ValidationError, match="tcp_option"):
        AclModel(**bad_config)


def test_manage_acl_00130() -> None:
    """
    # Summary

    Verify ACL name must match the pattern ^[a-zA-Z0-9_-]+$.

    ## Test

    - A name with an invalid character raises ValidationError

    ## Classes and Methods

    - AclModel.validate_name
    """
    bad_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    bad_config["name"] = "bad name!"
    with pytest.raises(ValidationError, match="is invalid"):
        AclModel(**bad_config)


def test_manage_acl_00131() -> None:
    """
    # Summary

    Verify tenant-qualified ACL names and long names are accepted.

    ## Test

    - A tenant-qualified name using '~' (e.g. 'tenant1~acl3') is accepted
    - A 115-character name is accepted (OpenAPI maximum)
    - A 116-character name is rejected

    ## Classes and Methods

    - AclModel.validate_name
    """
    tenant_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    tenant_config["name"] = "tenant1~acl3"
    assert AclModel(**tenant_config).name == "tenant1~acl3"

    max_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    max_config["name"] = "a" * 115
    assert AclModel(**max_config).name == "a" * 115

    too_long_config = copy.deepcopy(SAMPLE_IPV4_CONFIG)
    too_long_config["name"] = "a" * 116
    with pytest.raises(ValidationError):
        AclModel(**too_long_config)


# =============================================================================
# Test: AclModel identifier strategy
# =============================================================================


def test_manage_acl_00140() -> None:
    """
    # Summary

    Verify identifier strategy is single (keyed on name).

    ## Test

    - identifier_strategy is "single"
    - identifiers is ["name"]
    - get_identifier_value() returns the bare name (not a tuple)

    ## Classes and Methods

    - AclModel.identifier_strategy
    - AclModel.identifiers
    - AclModel.get_identifier_value
    """
    assert AclModel.identifier_strategy == "single"
    assert AclModel.identifiers == ["name"]

    model = AclModel(**SAMPLE_IPV4_CONFIG)
    assert model.get_identifier_value() == "ACL-IPV4-WEB"


def test_manage_acl_00150() -> None:
    """
    # Summary

    Verify a name-only model (state=deleted) is valid without type/entries.

    ## Test

    - AclModel(name=...) instantiates with type=None and entries=None
    - get_identifier_value() returns the name

    ## Classes and Methods

    - AclModel.__init__()
    - AclModel.get_identifier_value
    """
    with does_not_raise():
        model = AclModel(name="ACL-IPV4-WEB")
    assert model.type is None
    assert model.entries is None
    assert model.get_identifier_value() == "ACL-IPV4-WEB"


# =============================================================================
# Test: from_response / from_config factories
# =============================================================================


def test_manage_acl_00160() -> None:
    """
    # Summary

    Verify from_response accepts ND API camelCase keys.

    ## Test

    - from_response() accepts sequenceNumber, dstPortAction, lastUpdateTimestamp
    - Snake_case fields and nested entries are populated correctly

    ## Classes and Methods

    - AclModel.from_response
    """
    with does_not_raise():
        model = AclModel.from_response(copy.deepcopy(SAMPLE_IPV4_API_RESPONSE))
    assert str(model.type) == "ipv4"
    assert model.name == "ACL-IPV4-WEB"
    assert model.description == "IPv4 web ACL"
    assert model.entries is not None
    assert len(model.entries) == 2
    assert model.entries[0].sequence_number == 10
    assert str(model.entries[0].dst_port_action) == "equalTo"
    assert model.last_update_timestamp == "2026-06-12T10:00:00Z"


def test_manage_acl_00170() -> None:
    """
    # Summary

    Verify from_config accepts Ansible snake_case keys.

    ## Test

    - from_config() accepts snake_case keys
    - Nested entries are instantiated as AclEntryModel
    - snake_case port action is normalised to the wire value

    ## Classes and Methods

    - AclModel.from_config
    """
    with does_not_raise():
        model = AclModel.from_config(copy.deepcopy(SAMPLE_IPV4_CONFIG))
    assert str(model.type) == "ipv4"
    assert model.name == "ACL-IPV4-WEB"
    assert len(model.entries) == 2
    assert all(isinstance(e, AclEntryModel) for e in model.entries)
    assert str(model.entries[0].dst_port_action) == "equalTo"


# =============================================================================
# Test: to_payload serialization
# =============================================================================


def test_manage_acl_00180() -> None:
    """
    # Summary

    Verify to_payload() emits camelCase keys, includes type, and excludes
    last_update_timestamp.

    ## Test

    - Payload uses camelCase aliases (sequenceNumber, dstPortAction)
    - 'type' is present (real API body field)
    - lastUpdateTimestamp is excluded

    ## Classes and Methods

    - AclModel.to_payload
    """
    model = AclModel.from_config(copy.deepcopy(SAMPLE_IPV4_CONFIG))
    payload = model.to_payload()

    assert payload["name"] == "ACL-IPV4-WEB"
    assert payload["type"] == "ipv4"
    assert "lastUpdateTimestamp" not in payload
    assert payload["entries"][0]["sequenceNumber"] == 10
    assert payload["entries"][0]["dstPortAction"] == "equalTo"


def test_manage_acl_00190() -> None:
    """
    # Summary

    Verify a port-action of "none" is excluded from the payload.

    ## Test

    - An entry built with src_port_action="none" produces a payload entry
      without the srcPortAction key

    ## Classes and Methods

    - AclModel.to_payload
    - AclEntryModel.normalize_port_action
    """
    config = {
        "type": "ipv4",
        "name": "ACL-NONE",
        "entries": [{"sequence_number": 10, "action": "permit", "protocol": "ip", "src": "any", "dst": "any", "src_port_action": "none"}],
    }
    payload = AclModel.from_config(config).to_payload()
    assert "srcPortAction" not in payload["entries"][0]


def test_manage_acl_00200() -> None:
    """
    # Summary

    Verify to_payload() with entries=None (delete semantics) omits the entries key.

    ## Test

    - A name-only model produces a payload with name but no entries

    ## Classes and Methods

    - AclModel.to_payload
    """
    model = AclModel(name="ACL-IPV4-WEB")
    payload = model.to_payload()
    assert payload.get("name") == "ACL-IPV4-WEB"
    assert "entries" not in payload


# =============================================================================
# Test: idempotency diff
# =============================================================================


def test_manage_acl_00210() -> None:
    """
    # Summary

    Verify a model is idempotent against its own round-tripped response.

    ## Test

    - get_diff() of a desired model vs the equivalent response model is True
      (proposed is a subset of existing => no change required)

    ## Classes and Methods

    - AclModel.get_diff
    """
    desired = AclModel.from_config(copy.deepcopy(SAMPLE_IPV4_CONFIG))
    existing = AclModel.from_response(copy.deepcopy(SAMPLE_IPV4_API_RESPONSE))
    assert desired.get_diff(existing) is True


# =============================================================================
# Test: argument spec
# =============================================================================


def test_manage_acl_00220() -> None:
    """
    # Summary

    Verify argument spec shape matches module documentation.

    ## Test

    - fabric_name is a top-level required str
    - config is a required list of dicts
    - name is required; type is optional with ipv4/ipv6 choices
    - entries is required=false (semantic enforcement)
    - state choices match the supported states

    ## Classes and Methods

    - AclModel.get_argument_spec
    """
    spec = AclModel.get_argument_spec()

    assert spec["fabric_name"] == {"type": "str", "required": True}

    config = spec["config"]
    assert config["type"] == "list"
    assert config["elements"] == "dict"
    assert config["required"] is True

    opts = config["options"]
    assert opts["name"]["type"] == "str"
    assert opts["name"]["required"] is True
    assert opts["type"]["choices"] == ["ipv4", "ipv6"]
    assert opts["type"].get("required") in (None, False)

    entries = opts["entries"]
    assert entries["type"] == "list"
    assert entries["elements"] == "dict"
    assert entries["required"] is False

    assert spec["state"]["choices"] == ["merged", "replaced", "overridden", "deleted"]
