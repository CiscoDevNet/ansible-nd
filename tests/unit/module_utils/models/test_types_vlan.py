# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for the shared trunk VLAN types in models/types.py and the shared `VlanMappingEntryModel` in models/nested.py.

These types were consolidated from per-model copies in the ethernet, port-channel, and vPC trunk-host models (issue #347). The validators are
exercised here once, through real Pydantic models, so every trunk module that imports them inherits identical VLAN syntax acceptance.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name

from __future__ import annotations

from contextlib import contextmanager

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, Field
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import VlanMappingEntryModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import (
    AllowedVlans,
    CustomerVlanIdList,
    VlanId,
    validate_allowed_vlans,
    validate_customer_vlan_id_list,
    validate_vlan_id_or_range,
)
from pydantic import ValidationError


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


class _AllowedVlansHost(BaseModel):
    """Minimal host model exercising the `AllowedVlans` Annotated type through real Pydantic validation."""

    allowed_vlans: AllowedVlans = Field(default=None)


class _CustomerVlanIdListHost(BaseModel):
    """Minimal host model exercising the `CustomerVlanIdList` Annotated type through real Pydantic validation."""

    customer_vlan_id: CustomerVlanIdList = Field(default=None)


class _VlanIdHost(BaseModel):
    """Minimal host model exercising the `VlanId` Annotated type, both required and optional, layered with an outer `Field`."""

    vlan: VlanId
    optional_vlan: VlanId | None = Field(default=None, alias="optionalVlan")


# =============================================================================
# Test: validate_vlan_id_or_range()
# =============================================================================


@pytest.mark.parametrize("token", ["1", "4094", "100", "1-4094", "100-200", "7-7"])
def test_types_vlan_00000(token):
    """
    # Summary

    Verify `validate_vlan_id_or_range` accepts single ids and ranges whose bounds are in 1..4094 and ordered.

    ## Test

    - At-min, at-max, mid-range ids accepted
    - Full-span, ordered, and degenerate (`7-7`) ranges accepted

    ## Classes and Methods

    - types.validate_vlan_id_or_range()
    """
    with does_not_raise():
        validate_vlan_id_or_range(token, "field")


@pytest.mark.parametrize(
    "token,match",
    [
        ("abc", r"field entry 'abc' must be a VLAN id or range"),
        ("", r"field entry '' must be a VLAN id or range"),
        ("100-", r"field entry '100-' must be a VLAN id or range"),
        ("-100", r"field entry '-100' must be a VLAN id or range"),
        ("100-200-300", r"field entry '100-200-300' must be a VLAN id or range"),
        ("0", r"field id 0 is out of bounds; VLAN ids must be in 1\.\.4094"),
        ("4095", r"field id 4095 is out of bounds; VLAN ids must be in 1\.\.4094"),
        ("0-100", r"field range '0-100' is out of bounds; VLAN ids must be in 1\.\.4094"),
        ("100-4095", r"field range '100-4095' is out of bounds; VLAN ids must be in 1\.\.4094"),
        ("200-100", r"field range '200-100' has start greater than end"),
    ],
)
def test_types_vlan_00010(token, match):
    """
    # Summary

    Verify `validate_vlan_id_or_range` rejects malformed tokens, out-of-bounds ids/ranges, and reversed ranges, naming the caller's field.

    ## Test

    - Shape failures name the field and the offending token
    - Bound failures cite 1..4094
    - Reversed range cites start greater than end

    ## Classes and Methods

    - types.validate_vlan_id_or_range()
    """
    with pytest.raises(ValueError, match=match):
        validate_vlan_id_or_range(token, "field")


# =============================================================================
# Test: validate_allowed_vlans() / AllowedVlans
# =============================================================================


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, None),
        ("", ""),
        ("none", "none"),
        ("all", "all"),
        ("100", "100"),
        ("1-200,500-2000,3000", "1-200,500-2000,3000"),
        ("1", "1"),
        ("4094", "4094"),
        (250, "250"),
        (4094, "4094"),
    ],
)
def test_types_vlan_00100(value, expected):
    """
    # Summary

    Verify `AllowedVlans` accepts `none`, `all`, ids, comma-separated ids/ranges, and passes `None` / empty string through unchanged.

    ## Test

    - Keywords and well-formed lists accepted verbatim
    - JSON int (ND GET echo of a single id) coerced to its string form so round-trips compare equal to user input
    - `None` and `""` returned unchanged

    ## Classes and Methods

    - types.validate_allowed_vlans()
    - types.AllowedVlans
    """
    assert validate_allowed_vlans(value) == expected
    with does_not_raise():
        instance = _AllowedVlansHost(allowed_vlans=value)
    assert instance.allowed_vlans == expected


@pytest.mark.parametrize(
    "value,match",
    [
        ("abc", r"allowed_vlans must be 'none', 'all', or a comma-separated list"),
        ("100,", r"allowed_vlans must be 'none', 'all', or a comma-separated list"),
        ("100 200", r"allowed_vlans must be 'none', 'all', or a comma-separated list"),
        ("NONE", r"allowed_vlans must be 'none', 'all', or a comma-separated list"),
        ("0", r"allowed_vlans id 0 is out of bounds"),
        ("4095", r"allowed_vlans id 4095 is out of bounds"),
        ("100,5000", r"allowed_vlans id 5000 is out of bounds"),
        ("0-100", r"allowed_vlans range '0-100' is out of bounds"),
        ("200-100", r"allowed_vlans range '200-100' has start greater than end"),
        (0, r"allowed_vlans id 0 is out of bounds"),
        (4095, r"allowed_vlans id 4095 is out of bounds"),
    ],
)
def test_types_vlan_00110(value, match):
    """
    # Summary

    Verify `AllowedVlans` rejects malformed shapes, out-of-bounds ids and ranges, and reversed ranges, both as a bare validator and via Pydantic.

    ## Test

    - Bare validator raises `ValueError` with the expected message
    - Host model raises `ValidationError` carrying the same message

    ## Classes and Methods

    - types.validate_allowed_vlans()
    - types.AllowedVlans
    """
    with pytest.raises(ValueError, match=match):
        validate_allowed_vlans(value)
    with pytest.raises(ValidationError, match=match):
        _AllowedVlansHost(allowed_vlans=value)


def test_types_vlan_00120():
    """
    # Summary

    Verify `AllowedVlans` does not coerce `bool` (a `bool` is an `int` subclass) and leaves non-str/non-int values for Pydantic's type check to reject.

    ## Test

    - Bare validator returns `True` unchanged rather than coercing it to `"True"`
    - Host model rejects `True` and a list with a type error, not a VLAN-shape error

    ## Classes and Methods

    - types.validate_allowed_vlans()
    - types.AllowedVlans
    """
    assert validate_allowed_vlans(True) is True
    with pytest.raises(ValidationError, match=r"Input should be a valid string"):
        _AllowedVlansHost(allowed_vlans=True)
    with pytest.raises(ValidationError, match=r"Input should be a valid string"):
        _AllowedVlansHost(allowed_vlans=["100"])


# =============================================================================
# Test: validate_customer_vlan_id_list() / CustomerVlanIdList
# =============================================================================


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, None),
        ([], []),
        (["1"], ["1"]),
        (["4094"], ["4094"]),
        (["100", "200-300"], ["100", "200-300"]),
        ([100], ["100"]),
        ([100, "200-300", 4094], ["100", "200-300", "4094"]),
    ],
)
def test_types_vlan_00200(value, expected):
    """
    # Summary

    Verify `CustomerVlanIdList` accepts lists of VLAN id / range strings and coerces JSON int entries (ND GET echo) to their string form.

    ## Test

    - `None` and the empty list pass through
    - Well-formed string entries accepted verbatim
    - Int entries coerced to str so GET responses round-trip against user-supplied strings

    ## Classes and Methods

    - types.validate_customer_vlan_id_list()
    - types.CustomerVlanIdList
    """
    assert validate_customer_vlan_id_list(value) == expected
    with does_not_raise():
        instance = _CustomerVlanIdListHost(customer_vlan_id=value)
    assert instance.customer_vlan_id == expected


@pytest.mark.parametrize(
    "value,match",
    [
        ([""], r"customer_vlan_id entries must be non-empty strings"),
        ([None], r"customer_vlan_id entries must be non-empty strings"),
        ([True], r"customer_vlan_id entries must be non-empty strings"),
        ([1.5], r"customer_vlan_id entries must be non-empty strings"),
        (["abc"], r"customer_vlan_id entry 'abc' must be a VLAN id or range"),
        (["100,200"], r"customer_vlan_id entry '100,200' must be a VLAN id or range"),
        (["0"], r"customer_vlan_id id 0 is out of bounds"),
        (["4095"], r"customer_vlan_id id 4095 is out of bounds"),
        ([0], r"customer_vlan_id id 0 is out of bounds"),
        (["0-100"], r"customer_vlan_id range '0-100' is out of bounds"),
        (["200-100"], r"customer_vlan_id range '200-100' has start greater than end"),
        (["100", "4095"], r"customer_vlan_id id 4095 is out of bounds"),
    ],
)
def test_types_vlan_00210(value, match):
    """
    # Summary

    Verify `CustomerVlanIdList` rejects empty / non-string entries, comma-joined tokens, out-of-bounds ids and ranges, and reversed ranges.

    ## Test

    - Bare validator raises `ValueError` with the expected message
    - Host model raises `ValidationError` carrying the same message
    - A bad entry anywhere in the list fails the whole list

    ## Classes and Methods

    - types.validate_customer_vlan_id_list()
    - types.CustomerVlanIdList
    """
    with pytest.raises(ValueError, match=match):
        validate_customer_vlan_id_list(value)
    with pytest.raises(ValidationError, match=match):
        _CustomerVlanIdListHost(customer_vlan_id=value)


def test_types_vlan_00220():
    """
    # Summary

    Verify `CustomerVlanIdList` leaves a non-list value for Pydantic's type check to reject rather than iterating it.

    ## Test

    - Bare validator returns a bare string unchanged
    - Host model rejects a bare string with a list type error

    ## Classes and Methods

    - types.validate_customer_vlan_id_list()
    - types.CustomerVlanIdList
    """
    assert validate_customer_vlan_id_list("100") == "100"
    with pytest.raises(ValidationError, match=r"Input should be a valid list"):
        _CustomerVlanIdListHost(customer_vlan_id="100")


# =============================================================================
# Test: VlanId
# =============================================================================


@pytest.mark.parametrize("value", [1, 4094, 100])
def test_types_vlan_00300(value):
    """
    # Summary

    Verify `VlanId` accepts ints in 1..4094, as a required field and when layered under an outer `Field` with an alias.

    ## Test

    - At-min, at-max, and mid-range values accepted on both fields
    - Alias on the outer `Field` still populates the field

    ## Classes and Methods

    - types.VlanId
    """
    with does_not_raise():
        instance = _VlanIdHost(vlan=value, optionalVlan=value)
    assert instance.vlan == value
    assert instance.optional_vlan == value


@pytest.mark.parametrize(
    "value,match",
    [
        (0, r"greater than or equal to 1"),
        (-1, r"greater than or equal to 1"),
        (4095, r"less than or equal to 4094"),
    ],
)
def test_types_vlan_00310(value, match):
    """
    # Summary

    Verify `VlanId` rejects ints outside 1..4094 on both the required and the optional field.

    ## Test

    - Below-min rejected with the `ge` message
    - Above-max rejected with the `le` message

    ## Classes and Methods

    - types.VlanId
    """
    with pytest.raises(ValidationError, match=match):
        _VlanIdHost(vlan=value)
    with pytest.raises(ValidationError, match=match):
        _VlanIdHost(vlan=1, optionalVlan=value)


def test_types_vlan_00320():
    """
    # Summary

    Verify `VlanId | None` accepts `None` and defaults to `None` when omitted.

    ## Test

    - Omitted optional field is `None`
    - Explicit `None` accepted

    ## Classes and Methods

    - types.VlanId
    """
    with does_not_raise():
        omitted = _VlanIdHost(vlan=1)
        explicit = _VlanIdHost(vlan=1, optionalVlan=None)
    assert omitted.optional_vlan is None
    assert explicit.optional_vlan is None


# =============================================================================
# Test: VlanMappingEntryModel
# =============================================================================


def test_types_vlan_00400():
    """
    # Summary

    Verify `VlanMappingEntryModel` defaults every field to `None`.

    ## Test

    - No-arg construction succeeds
    - All four fields are `None`

    ## Classes and Methods

    - nested.VlanMappingEntryModel.__init__()
    """
    with does_not_raise():
        instance = VlanMappingEntryModel()
    assert instance.customer_inner_vlan_id is None
    assert instance.customer_vlan_id is None
    assert instance.dot1q_tunnel is None
    assert instance.provider_vlan_id is None


def test_types_vlan_00410():
    """
    # Summary

    Verify `VlanMappingEntryModel` populates from snake_case names and from the ND camelCase aliases, and dumps back to the aliases.

    ## Test

    - snake_case construction sets every field
    - camelCase (alias) construction sets the same fields
    - `model_dump(by_alias=True)` emits the four ND wire keys

    ## Classes and Methods

    - nested.VlanMappingEntryModel.__init__()
    - nested.VlanMappingEntryModel.model_dump()
    """
    with does_not_raise():
        snake = VlanMappingEntryModel(customer_inner_vlan_id=10, customer_vlan_id=["100", "200-300"], dot1q_tunnel=True, provider_vlan_id=1000)
        camel = VlanMappingEntryModel(customerInnerVlanId=10, customerVlanId=["100", "200-300"], dot1qTunnel=True, providerVlanId=1000)
    for instance in (snake, camel):
        assert instance.customer_inner_vlan_id == 10
        assert instance.customer_vlan_id == ["100", "200-300"]
        assert instance.dot1q_tunnel is True
        assert instance.provider_vlan_id == 1000
    assert snake.model_dump(by_alias=True) == {
        "customerInnerVlanId": 10,
        "customerVlanId": ["100", "200-300"],
        "dot1qTunnel": True,
        "providerVlanId": 1000,
    }


@pytest.mark.parametrize(
    "field,value,should_raise",
    [
        ("customer_inner_vlan_id", 1, False),
        ("customer_inner_vlan_id", 4094, False),
        ("customer_inner_vlan_id", 0, True),
        ("customer_inner_vlan_id", 4095, True),
        ("provider_vlan_id", 1, False),
        ("provider_vlan_id", 4094, False),
        ("provider_vlan_id", 0, True),
        ("provider_vlan_id", 4095, True),
    ],
    ids=lambda v: str(v) if not isinstance(v, bool) else ("raise" if v else "ok"),
)
def test_types_vlan_00420(field, value, should_raise):
    """
    # Summary

    Verify the two scalar VLAN-id fields of `VlanMappingEntryModel` enforce 1..4094 via the shared `VlanId` type.

    ## Test

    - At-min and at-max values accepted
    - Below-min and above-max values rejected

    ## Classes and Methods

    - nested.VlanMappingEntryModel.__init__()
    - types.VlanId
    """
    if should_raise:
        with pytest.raises(ValidationError):
            VlanMappingEntryModel(**{field: value})
    else:
        with does_not_raise():
            instance = VlanMappingEntryModel(**{field: value})
        assert getattr(instance, field) == value


def test_types_vlan_00430():
    """
    # Summary

    Verify `VlanMappingEntryModel.customer_vlan_id` goes through `CustomerVlanIdList`: int entries are coerced and bad entries rejected.

    ## Test

    - `[100, "200-300"]` is stored as `["100", "200-300"]`
    - A reversed range is rejected with the customer_vlan_id message

    ## Classes and Methods

    - nested.VlanMappingEntryModel.__init__()
    - types.CustomerVlanIdList
    """
    with does_not_raise():
        instance = VlanMappingEntryModel(customer_vlan_id=[100, "200-300"])
    assert instance.customer_vlan_id == ["100", "200-300"]
    with pytest.raises(ValidationError, match=r"customer_vlan_id range '200-100' has start greater than end"):
        VlanMappingEntryModel(customer_vlan_id=["200-100"])
