# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ``models/manage_policies/policy_actions.py``.

Covers the two bulk-action request bodies:

- ``SwitchIds`` - body for ``POST /fabrics/{fabricName}/switchActions/deploy``.
  Wraps ``list[str]`` of switch serial numbers. ``min_length=1`` is enforced and
  every entry must be a non-empty string. Emits ``{"switchIds": [...]}``.
- ``PolicyIds`` - body for ``markDelete`` / ``pushConfig`` policy actions.
  Wraps ``list[str]`` of policy IDs. Same validation rules. Emits
  ``{"policyIds": [...]}``.
"""

# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.policy_actions import (
    PolicyIds,
    SwitchIds,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: SwitchIds basic construction
# =============================================================================


def test_manage_policies_policy_actions_00010() -> None:
    """
    # Summary

    Verify ``SwitchIds`` constructs from a single switch ID and exposes it on
    ``switch_ids``.

    ## Test

    - ``switch_ids`` is the supplied list.
    - ``identifiers`` ClassVar is the empty list (no model-level identifier).

    ## Classes and Methods

    - ``SwitchIds.__init__``
    """
    with does_not_raise():
        body = SwitchIds(switch_ids=["FOC21373AFA"])

    assert body.switch_ids == ["FOC21373AFA"]
    assert SwitchIds.identifiers == []


def test_manage_policies_policy_actions_00020() -> None:
    """
    # Summary

    Verify ``SwitchIds`` constructs from multiple switch IDs and preserves
    their order.

    ## Test

    - All entries kept in the supplied order.

    ## Classes and Methods

    - ``SwitchIds.__init__``
    """
    with does_not_raise():
        body = SwitchIds(switch_ids=["FOC21373AFA", "FVT93126SKE", "FDO25031SY4"])

    assert body.switch_ids == ["FOC21373AFA", "FVT93126SKE", "FDO25031SY4"]


def test_manage_policies_policy_actions_00030() -> None:
    """
    # Summary

    Verify ``SwitchIds`` accepts the camelCase alias ``switchIds`` (the same
    name used on the wire) at construction time.

    ## Test

    - ``SwitchIds(switchIds=[...])`` produces the same model as
      ``SwitchIds(switch_ids=[...])``.

    ## Classes and Methods

    - ``SwitchIds.__init__`` (Field alias)
    """
    with does_not_raise():
        body = SwitchIds(switchIds=["FOC21373AFA"])

    assert body.switch_ids == ["FOC21373AFA"]


# =============================================================================
# Test: SwitchIds validation failures
# =============================================================================


def test_manage_policies_policy_actions_00100() -> None:
    """
    # Summary

    Verify ``SwitchIds`` rejects an empty list (``min_length=1`` enforced by
    Pydantic).

    ## Test

    - Empty list raises ``ValidationError``.

    ## Classes and Methods

    - ``SwitchIds.__init__``
    """
    with pytest.raises(ValidationError):
        SwitchIds(switch_ids=[])


@pytest.mark.parametrize("bad", ["", "   ", "\t"])
def test_manage_policies_policy_actions_00110(bad) -> None:
    """
    # Summary

    Verify ``SwitchIds.validate_switch_ids`` rejects empty/whitespace-only
    strings inside the list.

    ## Test

    - Empty or whitespace-only IDs raise ``ValidationError``.

    ## Classes and Methods

    - ``SwitchIds.validate_switch_ids``
    """
    with pytest.raises(ValidationError):
        SwitchIds(switch_ids=["FOC21373AFA", bad])


def test_manage_policies_policy_actions_00120() -> None:
    """
    # Summary

    Verify ``SwitchIds.validate_switch_ids`` rejects non-string entries
    (e.g. integers) in the list.

    ## Test

    - Non-string entry raises ``ValidationError``.

    ## Classes and Methods

    - ``SwitchIds.validate_switch_ids``
    """
    with pytest.raises(ValidationError):
        SwitchIds(switch_ids=["FOC21373AFA", 12345])


def test_manage_policies_policy_actions_00130() -> None:
    """
    # Summary

    Document the default-value behavior of ``SwitchIds``: the field uses
    ``default_factory=list``, and Pydantic v2 does NOT validate defaults
    (no ``validate_default=True``), so constructing with no arguments
    yields a model whose ``switch_ids`` is the empty list. The
    ``min_length=1`` constraint is enforced only against explicitly
    supplied values (see ``_00100``).

    ## Test

    - ``SwitchIds()`` constructs successfully.
    - ``switch_ids`` is the empty list.

    ## Classes and Methods

    - ``SwitchIds.__init__``
    """
    with does_not_raise():
        body = SwitchIds()

    assert body.switch_ids == []


# =============================================================================
# Test: SwitchIds.to_request_dict() payload shape
# =============================================================================


def test_manage_policies_policy_actions_00200() -> None:
    """
    # Summary

    Verify ``SwitchIds.to_request_dict()`` emits the documented
    ``{"switchIds": [...]}`` shape (camelCase key, list preserved).

    ## Test

    - Output dict has exactly one top-level key, ``"switchIds"``.
    - Value equals the input list in order.

    ## Classes and Methods

    - ``SwitchIds.to_request_dict``
    """
    body = SwitchIds(switch_ids=["FOC21373AFA", "FVT93126SKE"])

    payload = body.to_request_dict()

    assert payload == {"switchIds": ["FOC21373AFA", "FVT93126SKE"]}


def test_manage_policies_policy_actions_00210() -> None:
    """
    # Summary

    Verify ``SwitchIds.to_request_dict()`` is equivalent to the inherited
    ``NDBaseModel.to_payload()`` (no payload-shape drift).

    ## Test

    - ``to_request_dict()`` == ``to_payload()``.

    ## Classes and Methods

    - ``SwitchIds.to_request_dict``
    - ``NDBaseModel.to_payload``
    """
    body = SwitchIds(switch_ids=["FOC21373AFA"])

    assert body.to_request_dict() == body.to_payload()


# =============================================================================
# Test: PolicyIds basic construction
# =============================================================================


def test_manage_policies_policy_actions_00300() -> None:
    """
    # Summary

    Verify ``PolicyIds`` constructs from a single policy ID and exposes it on
    ``policy_ids``.

    ## Test

    - ``policy_ids`` is the supplied list.
    - ``identifiers`` ClassVar is the empty list (no model-level identifier).

    ## Classes and Methods

    - ``PolicyIds.__init__``
    """
    with does_not_raise():
        body = PolicyIds(policy_ids=["POLICY-121110"])

    assert body.policy_ids == ["POLICY-121110"]
    assert PolicyIds.identifiers == []


def test_manage_policies_policy_actions_00310() -> None:
    """
    # Summary

    Verify ``PolicyIds`` constructs from multiple policy IDs and preserves
    their order.

    ## Test

    - All entries kept in the supplied order.

    ## Classes and Methods

    - ``PolicyIds.__init__``
    """
    with does_not_raise():
        body = PolicyIds(policy_ids=["POLICY-121110", "POLICY-121120", "POLICY-121130"])

    assert body.policy_ids == ["POLICY-121110", "POLICY-121120", "POLICY-121130"]


def test_manage_policies_policy_actions_00320() -> None:
    """
    # Summary

    Verify ``PolicyIds`` accepts the camelCase alias ``policyIds`` (same name
    used on the wire) at construction time.

    ## Test

    - ``PolicyIds(policyIds=[...])`` produces the same model as
      ``PolicyIds(policy_ids=[...])``.

    ## Classes and Methods

    - ``PolicyIds.__init__`` (Field alias)
    """
    with does_not_raise():
        body = PolicyIds(policyIds=["POLICY-121110"])

    assert body.policy_ids == ["POLICY-121110"]


# =============================================================================
# Test: PolicyIds validation failures
# =============================================================================


def test_manage_policies_policy_actions_00400() -> None:
    """
    # Summary

    Verify ``PolicyIds`` rejects an empty list (``min_length=1`` enforced by
    Pydantic).

    ## Test

    - Empty list raises ``ValidationError``.

    ## Classes and Methods

    - ``PolicyIds.__init__``
    """
    with pytest.raises(ValidationError):
        PolicyIds(policy_ids=[])


@pytest.mark.parametrize("bad", ["", "   ", "\n"])
def test_manage_policies_policy_actions_00410(bad) -> None:
    """
    # Summary

    Verify ``PolicyIds.validate_policy_ids`` rejects empty/whitespace-only
    strings inside the list.

    ## Test

    - Empty or whitespace-only IDs raise ``ValidationError``.

    ## Classes and Methods

    - ``PolicyIds.validate_policy_ids``
    """
    with pytest.raises(ValidationError):
        PolicyIds(policy_ids=["POLICY-121110", bad])


def test_manage_policies_policy_actions_00420() -> None:
    """
    # Summary

    Verify ``PolicyIds.validate_policy_ids`` rejects non-string entries
    (e.g. ``None``, integers) in the list.

    ## Test

    - Non-string entry raises ``ValidationError``.

    ## Classes and Methods

    - ``PolicyIds.validate_policy_ids``
    """
    with pytest.raises(ValidationError):
        PolicyIds(policy_ids=["POLICY-121110", None])


def test_manage_policies_policy_actions_00430() -> None:
    """
    # Summary

    Document the default-value behavior of ``PolicyIds``: the field uses
    ``default_factory=list``, and Pydantic v2 does NOT validate defaults
    (no ``validate_default=True``), so constructing with no arguments
    yields a model whose ``policy_ids`` is the empty list. The
    ``min_length=1`` constraint is enforced only against explicitly
    supplied values (see ``_00400``).

    ## Test

    - ``PolicyIds()`` constructs successfully.
    - ``policy_ids`` is the empty list.

    ## Classes and Methods

    - ``PolicyIds.__init__``
    """
    with does_not_raise():
        body = PolicyIds()

    assert body.policy_ids == []


# =============================================================================
# Test: PolicyIds.to_request_dict() payload shape
# =============================================================================


def test_manage_policies_policy_actions_00500() -> None:
    """
    # Summary

    Verify ``PolicyIds.to_request_dict()`` emits the documented
    ``{"policyIds": [...]}`` shape (camelCase key, list preserved).

    ## Test

    - Output dict has exactly one top-level key, ``"policyIds"``.
    - Value equals the input list in order.

    ## Classes and Methods

    - ``PolicyIds.to_request_dict``
    """
    body = PolicyIds(policy_ids=["POLICY-121110", "POLICY-121120"])

    payload = body.to_request_dict()

    assert payload == {"policyIds": ["POLICY-121110", "POLICY-121120"]}


def test_manage_policies_policy_actions_00510() -> None:
    """
    # Summary

    Verify ``PolicyIds.to_request_dict()`` is equivalent to the inherited
    ``NDBaseModel.to_payload()`` (no payload-shape drift).

    ## Test

    - ``to_request_dict()`` == ``to_payload()``.

    ## Classes and Methods

    - ``PolicyIds.to_request_dict``
    - ``NDBaseModel.to_payload``
    """
    body = PolicyIds(policy_ids=["POLICY-121110"])

    assert body.to_request_dict() == body.to_payload()


def test_manage_policies_policy_actions_00520() -> None:
    """
    # Summary

    Verify the two action body models are independent (the same payload shape
    family but namespaced under different top-level keys, so they cannot be
    confused on the wire).

    ## Test

    - The two payloads use different top-level keys ("switchIds" vs
      "policyIds") even when the underlying list values are identical.

    ## Classes and Methods

    - ``SwitchIds.to_request_dict``
    - ``PolicyIds.to_request_dict``
    """
    same_list = ["AAA111", "BBB222"]
    switch_payload = SwitchIds(switch_ids=same_list).to_request_dict()
    policy_payload = PolicyIds(policy_ids=same_list).to_request_dict()

    assert switch_payload == {"switchIds": same_list}
    assert policy_payload == {"policyIds": same_list}
    assert "policyIds" not in switch_payload
    assert "switchIds" not in policy_payload
