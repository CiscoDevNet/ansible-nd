# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for utils.py

Tests the ``issubset`` helper (both the default bidirectional list matching and
the one-directional ``allow_superset=True`` matching) and ``NDBaseModel.get_diff``
with list-valued fields under ``exclude_unset=True``.
"""

# pylint: disable=protected-access

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from typing import Any, ClassVar, Dict, List, Literal, Optional

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.utils import issubset

# =============================================================================
# issubset - scalars
# =============================================================================


@pytest.mark.parametrize(
    "subset, superset, expected",
    [
        (1, 1, True),
        (1, 2, False),
        ("a", "a", True),
        ("a", "b", False),
        (True, True, True),
        (1, "1", False),  # different types
        (1.0, 1, False),  # different types (float vs int)
    ],
)
def test_issubset_scalars(subset, superset, expected):
    """Scalar comparison is strict equality and type-sensitive."""
    assert issubset(subset, superset) is expected


# =============================================================================
# issubset - dicts
# =============================================================================


@pytest.mark.parametrize(
    "subset, superset, expected",
    [
        # Subset of keys present with matching values -> True
        ({"a": 1}, {"a": 1, "b": 2}, True),
        # Exact match -> True
        ({"a": 1, "b": 2}, {"a": 1, "b": 2}, True),
        # Missing key in superset -> False
        ({"a": 1, "c": 3}, {"a": 1, "b": 2}, False),
        # Value mismatch -> False
        ({"a": 1}, {"a": 2}, False),
        # None values in subset are ignored
        ({"a": 1, "b": None}, {"a": 1}, True),
        # Nested dict subset
        ({"a": {"x": 1}}, {"a": {"x": 1, "y": 2}}, True),
        # Nested dict mismatch
        ({"a": {"x": 1}}, {"a": {"x": 2}}, False),
    ],
)
def test_issubset_dicts(subset, superset, expected):
    """Dict comparison checks each non-None key/value of subset."""
    assert issubset(subset, superset) is expected


def test_issubset_dicts_none_keys_not_strict_equality():
    """
    Bidirectional dict matching is NOT strict ``==`` equality: ``None``-valued
    keys are skipped, so unequal dicts can still match in both directions.
    This documents the behavior described in the ``issubset`` docstring.
    """
    a = {"a": 1, "b": None}
    b = {"a": 1}

    # Not equal as plain dicts ...
    assert a != b
    # ... yet issubset matches in both directions (b: None is ignored).
    assert issubset(a, b) is True
    assert issubset(b, a) is True


# =============================================================================
# issubset - lists with allow_superset=False (default, bidirectional)
#
# This is the behavior deliberately added in PR #209: for lists of dicts the
# match is bidirectional, which is equivalent to equality. An element whose
# candidate carries extra keys does NOT match.
# =============================================================================


@pytest.mark.parametrize(
    "subset, superset, expected",
    [
        # Equal lists -> True
        ([1, 2, 3], [1, 2, 3], True),
        # Order-independent matching -> True
        ([3, 1, 2], [1, 2, 3], True),
        # Different length -> False
        ([1, 2], [1, 2, 3], False),
        # Element missing -> False
        ([1, 2, 4], [1, 2, 3], False),
        # Lists of dicts, exact element match -> True
        ([{"a": 1}], [{"a": 1}], True),
        # Lists of dicts, candidate has EXTRA key -> False (bidirectional)
        ([{"a": 1}], [{"a": 1, "b": 2}], False),
        # Lists of dicts, subset element has extra key -> False
        ([{"a": 1, "b": 2}], [{"a": 1}], False),
    ],
)
def test_issubset_lists_bidirectional(subset, superset, expected):
    """Default list matching is bidirectional (equivalent to equality)."""
    assert issubset(subset, superset) is expected


# =============================================================================
# issubset - lists with allow_superset=True (one-directional)
#
# New behavior introduced in this PR: an element in ``subset`` matches a
# candidate in ``superset`` when it is a subset of that candidate, even if the
# candidate has additional keys. The ``subset`` list may also be shorter than
# ``superset`` (extra existing elements are tolerated) as long as every
# proposed element matches a distinct candidate.
# =============================================================================


@pytest.mark.parametrize(
    "subset, superset, expected",
    [
        # Candidate has EXTRA key -> now matches (one-directional)
        ([{"a": 1}], [{"a": 1, "b": 2}], True),
        # Multiple elements, each a subset of a distinct candidate -> True
        (
            [{"a": 1}, {"c": 3}],
            [{"a": 1, "b": 2}, {"c": 3, "d": 4}],
            True,
        ),
        # Subset element with extra key not in candidate -> still False
        ([{"a": 1, "z": 9}], [{"a": 1, "b": 2}], False),
        # Proposed list shorter than existing: the proposed item matches a
        # candidate and the extra existing element is tolerated -> True
        ([{"a": 1}], [{"a": 1, "b": 2}, {"c": 3}], True),
        # More proposed items than candidates -> no one-to-one match -> False
        ([{"a": 1}, {"c": 3}], [{"a": 1, "b": 2}], False),
        # Value mismatch -> False
        ([{"a": 2}], [{"a": 1, "b": 2}], False),
    ],
)
def test_issubset_lists_one_directional(subset, superset, expected):
    """``allow_superset=True`` relaxes list matching to one-directional."""
    assert issubset(subset, superset, allow_superset=True) is expected


def test_issubset_one_directional_does_not_reuse_candidate():
    """Each candidate is consumed at most once during list matching."""
    # Two identical subset elements require two matching candidates.
    subset = [{"a": 1}, {"a": 1}]
    superset = [{"a": 1, "b": 2}, {"a": 1, "c": 3}]
    assert issubset(subset, superset, allow_superset=True) is True

    # Only one candidate matches -> the second subset element fails.
    subset = [{"a": 1}, {"a": 1}]
    superset = [{"a": 1, "b": 2}, {"x": 9}]
    assert issubset(subset, superset, allow_superset=True) is False


def test_issubset_one_directional_allows_shorter_subset():
    """Under allow_superset the proposed list may be shorter than the existing.

    This is the merged-state contract: a user who names only some children must
    not flag the parent as changed when the controller already holds additional
    children. Every proposed child must still match a distinct existing child.
    """
    # One proposed child, two existing children -> matches the first; the extra
    # existing child is tolerated.
    subset = [{"vrf_name": "TENANT_A"}]
    superset = [
        {"vrf_name": "TENANT_A", "vlan_id": 500},
        {"vrf_name": "TENANT_B", "vlan_id": 600},
    ]
    assert issubset(subset, superset, allow_superset=True) is True

    # Two proposed children, each matching a distinct existing child that
    # carries extra keys, with a third existing child left untouched -> True.
    subset = [{"vrf_name": "TENANT_A"}, {"vrf_name": "TENANT_B"}]
    superset = [
        {"vrf_name": "TENANT_A", "vlan_id": 500},
        {"vrf_name": "TENANT_B", "vlan_id": 600},
        {"vrf_name": "TENANT_C", "vlan_id": 700},
    ]
    assert issubset(subset, superset, allow_superset=True) is True

    # A proposed child that matches none of the existing children -> False.
    subset = [{"vrf_name": "TENANT_Z"}]
    superset = [
        {"vrf_name": "TENANT_A", "vlan_id": 500},
        {"vrf_name": "TENANT_B", "vlan_id": 600},
    ]
    assert issubset(subset, superset, allow_superset=True) is False

    # More proposed children than existing -> one-to-one match impossible.
    subset = [{"vrf_name": "TENANT_A"}, {"vrf_name": "TENANT_B"}]
    superset = [{"vrf_name": "TENANT_A", "vlan_id": 500}]
    assert issubset(subset, superset, allow_superset=True) is False


def test_issubset_type_mismatch_returns_false():
    """Mismatched top-level types short-circuit to False."""
    assert issubset({"a": 1}, [1, 2]) is False
    assert issubset([1], {"a": 1}) is False


# =============================================================================
# issubset - greedy-matching regression (bipartite matching)
#
# A less-specific subset item must not greedily consume a candidate that a
# more-specific item needs. These cases fail with first-match/greedy logic but
# pass with a proper maximum-matching solution.
# =============================================================================


def test_issubset_one_directional_no_greedy_false_diff():
    """
    The less-specific ``{"a": 1}`` must yield the ``{"a": 1, "b": 2}`` candidate
    to the more-specific ``{"a": 1, "b": 2}`` proposed item, matching instead
    against ``{"a": 1, "b": 3}``. A valid pairing exists, so no diff.
    """
    subset = [{"a": 1}, {"a": 1, "b": 2}]
    superset = [{"a": 1, "b": 2}, {"a": 1, "b": 3}]
    assert issubset(subset, superset, allow_superset=True) is True


def test_issubset_one_directional_no_greedy_reordered():
    """Order-independence: same data, subset elements swapped."""
    subset = [{"a": 1, "b": 2}, {"a": 1}]
    superset = [{"a": 1, "b": 3}, {"a": 1, "b": 2}]
    assert issubset(subset, superset, allow_superset=True) is True


def test_issubset_one_directional_no_valid_pairing_is_false():
    """When no perfect pairing exists, a diff is still correctly reported."""
    # Both proposed items demand b==2, but only one candidate has b==2.
    subset = [{"a": 1, "b": 2}, {"a": 1, "b": 2}]
    superset = [{"a": 1, "b": 2}, {"a": 1, "b": 3}]
    assert issubset(subset, superset, allow_superset=True) is False


def test_issubset_bidirectional_no_greedy_false_diff():
    """
    Greedy matching can also misfire in the default bidirectional mode when
    duplicate values are present. A perfect matching still exists here.
    """
    subset = [{"a": 1}, {"a": 1}]
    superset = [{"a": 1}, {"a": 1}]
    assert issubset(subset, superset) is True


# =============================================================================
# NDBaseModel.get_diff with list-valued fields under exclude_unset=True
# =============================================================================


class _ListFieldModel(NDBaseModel):
    """Minimal model with a list-valued field for diff testing."""

    identifiers: ClassVar[Optional[List[str]]] = ["name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"]] = "single"

    name: str = Field(alias="name")
    members: Optional[List[Dict[str, Any]]] = Field(default=None, alias="members")


def test_get_diff_list_field_subset_with_extra_keys_no_diff():
    """
    With allow_superset=True, an existing element carrying extra keys (e.g. a
    controller-populated ``deploy`` flag) does not trigger a spurious diff when
    the proposed element omits those keys.
    """
    existing = _ListFieldModel(name="vrf1", members=[{"id": 1, "deploy": True}])
    proposed = _ListFieldModel(name="vrf1", members=[{"id": 1}])

    # allow_superset=True -> one-directional list match -> proposed is a subset.
    assert existing.get_diff(proposed, exclude_unset=True, allow_superset=True) is True


def test_get_diff_exclude_unset_without_allow_superset_flags_extra_keys():
    """
    exclude_unset and allow_superset are independent: comparing only the
    proposed model's set fields (exclude_unset=True) while keeping strict
    bidirectional list matching (allow_superset=False) still flags an existing
    element that carries extra keys.
    """
    existing = _ListFieldModel(name="vrf1", members=[{"id": 1, "deploy": True}])
    proposed = _ListFieldModel(name="vrf1", members=[{"id": 1}])

    assert existing.get_diff(proposed, exclude_unset=True, allow_superset=False) is False


def test_get_diff_allow_superset_without_exclude_unset():
    """
    allow_superset can be requested on its own: with exclude_unset=False the
    proposed model's defaults are compared, but list elements are still matched
    one-directionally so the extra ``deploy`` key is tolerated.
    """
    existing = _ListFieldModel(name="vrf1", members=[{"id": 1, "deploy": True}])
    proposed = _ListFieldModel(name="vrf1", members=[{"id": 1}])

    assert existing.get_diff(proposed, allow_superset=True) is True


def test_get_diff_list_field_extra_keys_triggers_diff_without_exclude_unset():
    """
    Without exclude_unset (default), list matching is bidirectional, so the
    extra ``deploy`` key on the existing element produces a diff.
    """
    existing = _ListFieldModel(name="vrf1", members=[{"id": 1, "deploy": True}])
    proposed = _ListFieldModel(name="vrf1", members=[{"id": 1}])

    assert existing.get_diff(proposed) is False


def test_get_diff_list_field_value_change_triggers_diff():
    """A genuine value change in a list element is always a diff."""
    existing = _ListFieldModel(name="vrf1", members=[{"id": 1}])
    proposed = _ListFieldModel(name="vrf1", members=[{"id": 2}])

    assert existing.get_diff(proposed, exclude_unset=True) is False


def test_get_diff_unset_list_field_ignored():
    """A list field not set on the proposed model is ignored under exclude_unset."""
    existing = _ListFieldModel(name="vrf1", members=[{"id": 1, "deploy": True}])
    proposed = _ListFieldModel(name="vrf1")  # members not set

    assert existing.get_diff(proposed, exclude_unset=True) is True
