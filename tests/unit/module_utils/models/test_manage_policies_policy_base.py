# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ``models/manage_policies/policy_base.py``.

Tests ``PolicyCreate``, the request body model for
``POST /api/v1/manage/fabrics/{fabricName}/policies``:

- Required vs optional fields and documented defaults
- Field aliases (camelCase) preserved by ``to_request_dict()`` / ``to_payload()``
- Field constraints (priority 1-2000, maxLength=255 on description/template_name/
  entity_name)
- ``entity_type`` accepts both ``PolicyEntityType`` enum and equivalent string
- ``identifiers`` / ``identifier_strategy`` / ``exclude_from_diff`` class-vars
- ``get_identifier_value()`` returns the documented composite tuple
- ``to_diff_dict()`` honors ``exclude_from_diff = {"source"}``
"""

# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.enums import (
    PolicyEntityType,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.policy_base import (
    PolicyCreate,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)


def _minimal_kwargs(**overrides) -> dict:
    """Return the minimum required field set for constructing ``PolicyCreate``."""
    data = {
        "switch_id": "FDO25031SY4",
        "template_name": "feature_enable",
        "entity_type": PolicyEntityType.SWITCH,
        "entity_name": "SWITCH",
    }
    data.update(overrides)
    return data


# =============================================================================
# Test: ClassVars (identifiers / identifier_strategy / exclude_from_diff)
# =============================================================================


def test_manage_policies_policy_base_00010() -> None:
    """
    # Summary

    Verify ``PolicyCreate`` exposes the documented identifier strategy and the
    ``source`` exclusion used by diff comparison.

    ## Test

    - ``identifiers`` is ``["switch_id", "template_name", "description"]``
    - ``identifier_strategy`` is ``"composite"``
    - ``exclude_from_diff`` contains ``"source"``

    ## Classes and Methods

    - ``PolicyCreate.identifiers``
    - ``PolicyCreate.identifier_strategy``
    - ``PolicyCreate.exclude_from_diff``
    """
    assert PolicyCreate.identifiers == ["switch_id", "template_name", "description"]
    assert PolicyCreate.identifier_strategy == "composite"
    assert "source" in PolicyCreate.exclude_from_diff


# =============================================================================
# Test: required field enforcement
# =============================================================================


@pytest.mark.parametrize("missing", ["switch_id", "template_name", "entity_type", "entity_name"])
def test_manage_policies_policy_base_00020(missing) -> None:
    """
    # Summary

    Verify each required ``PolicyCreate`` field raises on omission.

    ## Test

    - Omitting any of ``switch_id``, ``template_name``, ``entity_type``,
      ``entity_name`` raises ``ValidationError``.

    ## Classes and Methods

    - ``PolicyCreate.__init__``
    """
    data = _minimal_kwargs()
    data.pop(missing)
    with pytest.raises(ValidationError):
        PolicyCreate(**data)


def test_manage_policies_policy_base_00030() -> None:
    """
    # Summary

    Verify ``PolicyCreate`` constructs from the minimum required field set and
    applies documented defaults for the optional fields.

    ## Test

    - ``description`` defaults to ``None``
    - ``priority`` defaults to ``500``
    - ``source`` defaults to ``""``
    - ``template_inputs`` defaults to ``None``
    - ``secondary_entity_name`` / ``secondary_entity_type`` default to ``None``

    ## Classes and Methods

    - ``PolicyCreate.__init__``
    """
    with does_not_raise():
        instance = PolicyCreate(**_minimal_kwargs())

    assert instance.switch_id == "FDO25031SY4"
    assert instance.template_name == "feature_enable"
    assert instance.entity_type == PolicyEntityType.SWITCH
    assert instance.entity_name == "SWITCH"
    assert instance.description is None
    assert instance.priority == 500
    assert instance.source == ""
    assert instance.template_inputs is None
    assert instance.secondary_entity_name is None
    assert instance.secondary_entity_type is None


# =============================================================================
# Test: optional fields & aliases (camelCase) on input
# =============================================================================


def test_manage_policies_policy_base_00040() -> None:
    """
    # Summary

    Verify ``PolicyCreate.model_validate()`` accepts camelCase aliases from an
    API-shaped dict (``switchId``, ``templateName``, ``entityType``,
    ``entityName``, ``templateInputs``, ``secondaryEntityName``,
    ``secondaryEntityType``).

    ## Test

    - Each canonical Python field is populated from the aliased input key.

    ## Classes and Methods

    - ``PolicyCreate.from_response``
    """
    with does_not_raise():
        instance = PolicyCreate.from_response(
            {
                "switchId": "FDO123",
                "templateName": "feature_enable",
                "entityType": "switch",
                "entityName": "SWITCH",
                "templateInputs": {"featureName": "lacp"},
                "secondaryEntityName": "overlay-a",
                "secondaryEntityType": "configProfile",
                "priority": 100,
                "description": "feature_enable lacp",
                "source": "UNDERLAY",
            }
        )

    assert instance.switch_id == "FDO123"
    assert instance.template_name == "feature_enable"
    assert instance.entity_type == PolicyEntityType.SWITCH
    assert instance.entity_name == "SWITCH"
    assert instance.template_inputs == {"featureName": "lacp"}
    assert instance.secondary_entity_name == "overlay-a"
    assert instance.secondary_entity_type == PolicyEntityType.CONFIG_PROFILE
    assert instance.priority == 100
    assert instance.description == "feature_enable lacp"
    assert instance.source == "UNDERLAY"


def test_manage_policies_policy_base_00050() -> None:
    """
    # Summary

    Verify ``entity_type`` accepts an equivalent string value (``"switch"``)
    and is coerced into the ``PolicyEntityType`` enum.

    ## Test

    - String input ``"switch"`` produces ``PolicyEntityType.SWITCH``.
    - String input ``"configProfile"`` produces ``PolicyEntityType.CONFIG_PROFILE``.

    ## Classes and Methods

    - ``PolicyCreate.__init__``
    """
    with does_not_raise():
        instance = PolicyCreate(**_minimal_kwargs(entity_type="switch"))
    assert instance.entity_type == PolicyEntityType.SWITCH

    with does_not_raise():
        instance = PolicyCreate(
            **_minimal_kwargs(
                entity_type="configProfile",
                secondary_entity_type="interface",
            )
        )
    assert instance.entity_type == PolicyEntityType.CONFIG_PROFILE
    assert instance.secondary_entity_type == PolicyEntityType.INTERFACE


def test_manage_policies_policy_base_00060() -> None:
    """
    # Summary

    Verify an invalid ``entity_type`` raises ``ValidationError``.

    ## Test

    - Unknown value (e.g. ``"bogus"``) is rejected.

    ## Classes and Methods

    - ``PolicyCreate.__init__``
    """
    with pytest.raises(ValidationError):
        PolicyCreate(**_minimal_kwargs(entity_type="bogus"))


# =============================================================================
# Test: field constraints (priority bounds, maxLength)
# =============================================================================


@pytest.mark.parametrize("priority", [0, -1, 2001])
def test_manage_policies_policy_base_00100(priority) -> None:
    """
    # Summary

    Verify ``PolicyCreate`` rejects out-of-range priorities.

    ## Test

    - Priorities outside [1, 2000] raise ``ValidationError``.

    ## Classes and Methods

    - ``PolicyCreate.__init__``
    """
    with pytest.raises(ValidationError):
        PolicyCreate(**_minimal_kwargs(priority=priority))


@pytest.mark.parametrize("priority", [1, 500, 2000])
def test_manage_policies_policy_base_00110(priority) -> None:
    """
    # Summary

    Verify ``PolicyCreate`` accepts boundary priorities.

    ## Test

    - 1, 500, and 2000 are all accepted.

    ## Classes and Methods

    - ``PolicyCreate.__init__``
    """
    with does_not_raise():
        instance = PolicyCreate(**_minimal_kwargs(priority=priority))
    assert instance.priority == priority


def test_manage_policies_policy_base_00120() -> None:
    """
    # Summary

    Verify ``template_name`` enforces the 255-char cap.

    ## Test

    - 255-char template_name passes; 256-char raises ``ValidationError``.

    ## Classes and Methods

    - ``PolicyCreate.__init__``
    """
    with does_not_raise():
        PolicyCreate(**_minimal_kwargs(template_name="x" * 255))

    with pytest.raises(ValidationError):
        PolicyCreate(**_minimal_kwargs(template_name="x" * 256))


def test_manage_policies_policy_base_00130() -> None:
    """
    # Summary

    Verify ``entity_name`` enforces the 255-char cap.

    ## Test

    - 255-char entity_name passes; 256-char raises ``ValidationError``.

    ## Classes and Methods

    - ``PolicyCreate.__init__``
    """
    with does_not_raise():
        PolicyCreate(**_minimal_kwargs(entity_name="x" * 255))

    with pytest.raises(ValidationError):
        PolicyCreate(**_minimal_kwargs(entity_name="x" * 256))


def test_manage_policies_policy_base_00140() -> None:
    """
    # Summary

    Verify ``description`` enforces the 255-char cap.

    ## Test

    - 256-char description raises ``ValidationError``.

    ## Classes and Methods

    - ``PolicyCreate.__init__``
    """
    with pytest.raises(ValidationError):
        PolicyCreate(**_minimal_kwargs(description="d" * 256))


def test_manage_policies_policy_base_00150() -> None:
    """
    # Summary

    Verify ``source`` enforces the 255-char cap.

    ## Test

    - 256-char source raises ``ValidationError``.

    ## Classes and Methods

    - ``PolicyCreate.__init__``
    """
    with pytest.raises(ValidationError):
        PolicyCreate(**_minimal_kwargs(source="s" * 256))


# =============================================================================
# Test: to_request_dict() / to_payload() emit camelCase, drop None
# =============================================================================


def test_manage_policies_policy_base_00200() -> None:
    """
    # Summary

    Verify ``to_request_dict()`` emits camelCase keys and drops fields set to
    ``None`` (None-only optional fields like ``description`` and
    ``template_inputs`` should not appear in the payload).

    ## Test

    - All required camelCase keys are present.
    - ``description`` and ``templateInputs`` are NOT present when unset
      (Pydantic ``exclude_none=True`` in ``to_payload``).

    ## Classes and Methods

    - ``PolicyCreate.to_request_dict``
    """
    instance = PolicyCreate(**_minimal_kwargs())

    payload = instance.to_request_dict()

    assert payload["switchId"] == "FDO25031SY4"
    assert payload["templateName"] == "feature_enable"
    assert payload["entityType"] == "switch"
    assert payload["entityName"] == "SWITCH"
    assert payload["priority"] == 500
    # ``source`` defaults to "" (not None) so it's emitted; ``description``
    # and ``templateInputs`` default to None and are excluded.
    assert payload["source"] == ""
    assert "description" not in payload
    assert "templateInputs" not in payload
    assert "secondaryEntityName" not in payload
    assert "secondaryEntityType" not in payload


def test_manage_policies_policy_base_00210() -> None:
    """
    # Summary

    Verify ``to_request_dict()`` emits all populated optional fields with the
    expected camelCase keys and JSON-friendly enum values.

    ## Test

    - ``templateInputs`` round-trips a nested dict verbatim.
    - ``secondaryEntityType`` is serialised as its enum value
      (``"configProfile"``).

    ## Classes and Methods

    - ``PolicyCreate.to_request_dict``
    """
    instance = PolicyCreate(
        **_minimal_kwargs(
            description="feature_enable lacp",
            priority=100,
            source="UNDERLAY",
            template_inputs={"featureName": "lacp"},
            secondary_entity_name="overlay-a",
            secondary_entity_type=PolicyEntityType.CONFIG_PROFILE,
        )
    )

    payload = instance.to_request_dict()

    assert payload["description"] == "feature_enable lacp"
    assert payload["priority"] == 100
    assert payload["source"] == "UNDERLAY"
    assert payload["templateInputs"] == {"featureName": "lacp"}
    assert payload["secondaryEntityName"] == "overlay-a"
    assert payload["secondaryEntityType"] == "configProfile"


def test_manage_policies_policy_base_00220() -> None:
    """
    # Summary

    Verify ``to_request_dict()`` is a thin wrapper around ``to_payload()``.

    ## Test

    - Output of both methods is byte-equivalent for the same instance.

    ## Classes and Methods

    - ``PolicyCreate.to_request_dict``
    - ``NDBaseModel.to_payload``
    """
    instance = PolicyCreate(
        **_minimal_kwargs(
            description="feature_enable lacp",
            template_inputs={"featureName": "lacp"},
        )
    )

    assert instance.to_request_dict() == instance.to_payload()


# =============================================================================
# Test: get_identifier_value() composite behavior
# =============================================================================


def test_manage_policies_policy_base_00300() -> None:
    """
    # Summary

    Verify ``get_identifier_value()`` returns the composite identifier tuple
    in the documented order (``switch_id``, ``template_name``, ``description``).

    ## Test

    - When all three identifier fields are populated, a 3-tuple is returned.

    ## Classes and Methods

    - ``PolicyCreate.get_identifier_value``
    """
    instance = PolicyCreate(**_minimal_kwargs(description="feature_enable lacp"))

    assert instance.get_identifier_value() == ("FDO25031SY4", "feature_enable", "feature_enable lacp")


def test_manage_policies_policy_base_00310() -> None:
    """
    # Summary

    Verify ``get_identifier_value()`` raises when any composite field is
    ``None`` (``description`` is part of the composite identifier and defaults
    to ``None``).

    ## Test

    - Missing description in the composite identifier raises ``ValueError``.

    ## Classes and Methods

    - ``PolicyCreate.get_identifier_value``
    """
    instance = PolicyCreate(**_minimal_kwargs())

    with pytest.raises(ValueError, match="Composite identifier"):
        instance.get_identifier_value()


# =============================================================================
# Test: exclude_from_diff respected by to_diff_dict()
# =============================================================================


def test_manage_policies_policy_base_00400() -> None:
    """
    # Summary

    Verify ``to_diff_dict()`` drops ``source`` (per ``exclude_from_diff``) so
    diff comparison ignores the field documented as cosmetic.

    ## Test

    - ``source`` is NOT present in the diff dict output even when set.
    - Other camelCase keys (``switchId``, ``templateName``, ...) are present.

    ## Classes and Methods

    - ``PolicyCreate.to_diff_dict``
    """
    instance = PolicyCreate(**_minimal_kwargs(source="UNDERLAY"))

    diff = instance.to_diff_dict()

    assert "source" not in diff
    assert diff["switchId"] == "FDO25031SY4"
    assert diff["templateName"] == "feature_enable"
    assert diff["entityName"] == "SWITCH"
