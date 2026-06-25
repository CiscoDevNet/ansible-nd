# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ``models/manage_policy_groups/policy_group_base.py``.

Tests ``PolicyGroupCreate`` -- the Pydantic request-body model used for
creating, updating, and identifying policy groups in ``nd_manage_policy_group``:

- Field defaults, aliases, validators.
- ``validate_switch_ids`` field validator.
- ``_normalize_priority_from_template_inputs`` model validator for older
  controller responses that carry priority in ``templateInputs.PRIORITY``.
- ``from_config()`` classmethod (Ansible-dict -> model translation).
- ``get_argument_spec()`` classmethod.
- ``to_request_dict()`` (alias + nested payload shape).
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
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policy_groups.policy_group_base import (
    PolicyGroupCreate,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: Field defaults and required fields
# =============================================================================


def test_manage_policy_groups_policy_group_base_00010() -> None:
    """
    # Summary

    Verify ``PolicyGroupCreate`` accepts the minimum required input and
    applies documented defaults.

    ## Test

    - ``template_name`` is the only required field for a minimal instance.
    - ``switch_ids`` defaults to an empty list.
    - ``entity_type`` defaults to ``PolicyEntityType.SWITCH``.
    - ``entity_name`` defaults to ``"SWITCH"``.
    - ``description`` defaults to ``None``.
    - ``priority`` defaults to ``None`` so omitted updates preserve the
      existing controller value. Create defaulting to ``500`` happens at the
      orchestrator API boundary.
    - ``source`` defaults to ``""``.
    - ``template_inputs`` defaults to ``None``.
    - ``policy_id`` defaults to ``None``.
    - ``create_additional_policy`` defaults to ``False``.

    ## Classes and Methods

    - ``PolicyGroupCreate.__init__``
    """
    with does_not_raise():
        instance = PolicyGroupCreate(template_name="feature_enable")

    assert instance.template_name == "feature_enable"
    assert instance.switch_ids == []
    assert instance.entity_type == PolicyEntityType.SWITCH
    assert instance.entity_name == "SWITCH"
    assert instance.description is None
    assert instance.priority is None
    assert instance.source == ""
    assert instance.template_inputs is None
    assert instance.policy_id is None
    assert instance.create_additional_policy is False
    assert instance.secondary_entity_name is None
    assert instance.secondary_entity_type is None


def test_manage_policy_groups_policy_group_base_00020() -> None:
    """
    # Summary

    Verify ``PolicyGroupCreate`` accepts a fully populated instance with
    all optional fields supplied.

    ## Test

    - Every documented field can be set explicitly and is preserved.

    ## Classes and Methods

    - ``PolicyGroupCreate.__init__``
    """
    with does_not_raise():
        instance = PolicyGroupCreate(
            policy_id="POLICY-GROUP-143310",
            switch_ids=["FDO25031SY4", "FDO245206N5"],
            template_name="feature_enable",
            entity_type=PolicyEntityType.SWITCH,
            entity_name="SWITCH",
            description="Enable LACP",
            priority=100,
            source="UNDERLAY",
            template_inputs={"featureName": "lacp"},
            secondary_entity_name="overlay-1",
            secondary_entity_type=PolicyEntityType.CONFIG_PROFILE,
            create_additional_policy=True,
        )

    assert instance.policy_id == "POLICY-GROUP-143310"
    assert instance.switch_ids == ["FDO25031SY4", "FDO245206N5"]
    assert instance.template_name == "feature_enable"
    assert instance.entity_type == PolicyEntityType.SWITCH
    assert instance.entity_name == "SWITCH"
    assert instance.description == "Enable LACP"
    assert instance.priority == 100
    assert instance.source == "UNDERLAY"
    assert instance.template_inputs == {"featureName": "lacp"}
    assert instance.secondary_entity_name == "overlay-1"
    assert instance.secondary_entity_type == PolicyEntityType.CONFIG_PROFILE
    assert instance.create_additional_policy is True


def test_manage_policy_groups_policy_group_base_00030() -> None:
    """
    # Summary

    Verify ``PolicyGroupCreate`` rejects instantiation when ``template_name``
    is omitted.

    ## Test

    - Pydantic raises ``ValidationError`` mentioning the missing field.

    ## Classes and Methods

    - ``PolicyGroupCreate.__init__``
    """
    # Pydantic v2 reports the alias (``templateName``) in the missing-field
    # message even when ``populate_by_name`` is set.
    with pytest.raises(ValidationError, match="templateName"):
        PolicyGroupCreate()


def test_manage_policy_groups_policy_group_base_00040() -> None:
    """
    # Summary

    Verify ``PolicyGroupCreate`` enforces the documented ``max_length`` for
    string fields.

    ## Test

    - ``template_name`` longer than 255 chars is rejected.
    - ``entity_name`` longer than 255 chars is rejected.
    - ``description`` longer than 255 chars is rejected.

    ## Classes and Methods

    - ``PolicyGroupCreate.__init__``
    """
    long_value = "x" * 256
    with pytest.raises(ValidationError, match="template_name"):
        PolicyGroupCreate(template_name=long_value)
    with pytest.raises(ValidationError, match="entity_name"):
        PolicyGroupCreate(template_name="feature_enable", entity_name=long_value)
    with pytest.raises(ValidationError, match="description"):
        PolicyGroupCreate(template_name="feature_enable", description=long_value)


def test_manage_policy_groups_policy_group_base_00050() -> None:
    """
    # Summary

    Verify ``PolicyGroupCreate`` enforces the documented ``priority`` range
    (1-2000).

    ## Test

    - ``priority=0`` is rejected.
    - ``priority=1`` is accepted (lower bound).
    - ``priority=2000`` is accepted (upper bound).
    - ``priority=-1`` is rejected.
    - ``priority=2001`` is rejected.

    ## Classes and Methods

    - ``PolicyGroupCreate.__init__``
    """
    with pytest.raises(ValidationError, match="priority"):
        PolicyGroupCreate(template_name="feature_enable", priority=0)
    with does_not_raise():
        PolicyGroupCreate(template_name="feature_enable", priority=1)
    with does_not_raise():
        PolicyGroupCreate(template_name="feature_enable", priority=2000)
    with pytest.raises(ValidationError, match="priority"):
        PolicyGroupCreate(template_name="feature_enable", priority=-1)
    with pytest.raises(ValidationError, match="priority"):
        PolicyGroupCreate(template_name="feature_enable", priority=2001)


# =============================================================================
# Test: Alias handling (camelCase / snake_case)
# =============================================================================


def test_manage_policy_groups_policy_group_base_00100() -> None:
    """
    # Summary

    Verify ``PolicyGroupCreate`` accepts camelCase aliases via
    ``model_validate`` with ``by_name=True`` (mirroring API response shape).

    ## Test

    - ``switchIds``, ``templateName``, ``entityType``, ``entityName``,
      ``templateInputs``, ``policyId`` all map to their snake_case fields.

    ## Classes and Methods

    - ``PolicyGroupCreate.model_validate``
    """
    payload = {
        "switchIds": ["FDO111", "FDO222"],
        "templateName": "feature_enable",
        "entityType": "switch",
        "entityName": "SWITCH",
        "templateInputs": {"featureName": "lacp"},
        "policyId": "POLICY-GROUP-999",
    }
    with does_not_raise():
        instance = PolicyGroupCreate.model_validate(payload)

    assert instance.switch_ids == ["FDO111", "FDO222"]
    assert instance.template_name == "feature_enable"
    assert instance.entity_type == PolicyEntityType.SWITCH
    assert instance.entity_name == "SWITCH"
    assert instance.template_inputs == {"featureName": "lacp"}
    assert instance.policy_id == "POLICY-GROUP-999"


# =============================================================================
# Test: validate_switch_ids field validator
# =============================================================================


def test_manage_policy_groups_policy_group_base_00200() -> None:
    """
    # Summary

    Verify ``validate_switch_ids`` accepts an empty list (default state) and
    passes through valid serial numbers unchanged.

    ## Test

    - Empty list does not raise.
    - A single valid serial is preserved.
    - Multiple valid serials are preserved in order.

    ## Classes and Methods

    - ``PolicyGroupCreate.validate_switch_ids``
    """
    with does_not_raise():
        instance = PolicyGroupCreate(template_name="feature_enable", switch_ids=[])
    assert instance.switch_ids == []

    with does_not_raise():
        instance = PolicyGroupCreate(
            template_name="feature_enable", switch_ids=["FDO111"]
        )
    assert instance.switch_ids == ["FDO111"]

    with does_not_raise():
        instance = PolicyGroupCreate(
            template_name="feature_enable",
            switch_ids=["FDO111", "FDO222", "FDO333"],
        )
    assert instance.switch_ids == ["FDO111", "FDO222", "FDO333"]


def test_manage_policy_groups_policy_group_base_00210() -> None:
    """
    # Summary

    Verify ``validate_switch_ids`` rejects an entry containing an empty
    string or whitespace-only serial number.

    ## Test

    - Empty string in switch_ids list raises ``ValidationError``.
    - Whitespace-only string in switch_ids list raises ``ValidationError``.

    ## Classes and Methods

    - ``PolicyGroupCreate.validate_switch_ids``
    """
    with pytest.raises(ValidationError, match="Invalid switch ID"):
        PolicyGroupCreate(template_name="feature_enable", switch_ids=["FDO111", ""])
    with pytest.raises(ValidationError, match="Invalid switch ID"):
        PolicyGroupCreate(template_name="feature_enable", switch_ids=["   "])


def test_manage_policy_groups_policy_group_base_00220() -> None:
    """
    # Summary

    Verify ``validate_switch_ids`` rejects non-string entries.

    ## Test

    - Integer entry in switch_ids list raises ``ValidationError``.
    - None entry in switch_ids list raises ``ValidationError``.

    ## Classes and Methods

    - ``PolicyGroupCreate.validate_switch_ids``
    """
    with pytest.raises(ValidationError):
        PolicyGroupCreate(template_name="feature_enable", switch_ids=[123])
    with pytest.raises(ValidationError):
        PolicyGroupCreate(template_name="feature_enable", switch_ids=[None])


# =============================================================================
# Test: _normalize_priority_from_template_inputs model validator
# =============================================================================


def test_manage_policy_groups_policy_group_base_00300() -> None:
    """
    # Summary

    Verify the priority normalisation is a no-op when ``template_inputs``
    does not carry a ``PRIORITY`` echo.

    ## Test

    - Top-level priority is preserved.
    - ``template_inputs`` is preserved unchanged.

    ## Classes and Methods

    - ``PolicyGroupCreate._normalize_priority_from_template_inputs``
    """
    with does_not_raise():
        instance = PolicyGroupCreate(
            template_name="switch_freeform",
            priority=750,
            template_inputs={"CONF": "banner motd #X#"},
        )
    assert instance.priority == 750
    assert instance.template_inputs == {"CONF": "banner motd #X#"}


def test_manage_policy_groups_policy_group_base_00310() -> None:
    """
    # Summary

    Verify the priority normalisation lifts ``templateInputs.PRIORITY`` to
    the top level only when top-level ``priority`` is absent or ``None``,
    and strips ``PRIORITY`` from ``template_inputs``.

    ## Test

    - When ``priority=None`` is in input, ``PRIORITY`` from template_inputs
      is lifted to top level.
    - When top-level ``priority`` is omitted, ``PRIORITY`` from
      template_inputs is lifted to top level.
    - ``PRIORITY`` is removed from ``template_inputs`` in both cases.

    ## Classes and Methods

    - ``PolicyGroupCreate._normalize_priority_from_template_inputs``
    """
    with does_not_raise():
        instance = PolicyGroupCreate.model_validate(
            {
                "template_name": "switch_freeform",
                "priority": None,
                "template_inputs": {"PRIORITY": "750", "CONF": "banner"},
            }
        )
    assert instance.priority == 750
    assert instance.template_inputs == {"CONF": "banner"}

    with does_not_raise():
        instance = PolicyGroupCreate.model_validate(
            {
                "template_name": "switch_freeform",
                "template_inputs": {"PRIORITY": "200", "CONF": "banner"},
            }
        )
    assert instance.priority == 200
    assert instance.template_inputs == {"CONF": "banner"}

    with pytest.raises(ValidationError, match="priority"):
        PolicyGroupCreate.model_validate(
            {
                "template_name": "switch_freeform",
                "priority": 0,
                "template_inputs": {"PRIORITY": "200", "CONF": "banner"},
            }
        )


def test_manage_policy_groups_policy_group_base_00320() -> None:
    """
    # Summary

    Verify the priority normalisation respects an explicit non-zero
    top-level ``priority`` (controller's stale echo loses).

    ## Test

    - When top-level ``priority=400`` is set AND
      ``templateInputs.PRIORITY=750`` is also present, top-level wins.
    - ``PRIORITY`` is still stripped from ``template_inputs`` for
      symmetric diff.

    ## Classes and Methods

    - ``PolicyGroupCreate._normalize_priority_from_template_inputs``
    """
    with does_not_raise():
        instance = PolicyGroupCreate.model_validate(
            {
                "template_name": "switch_freeform",
                "priority": 400,
                "template_inputs": {"PRIORITY": "750", "CONF": "banner"},
            }
        )
    assert instance.priority == 400
    assert instance.template_inputs == {"CONF": "banner"}


def test_manage_policy_groups_policy_group_base_00330() -> None:
    """
    # Summary

    Verify the priority normalisation handles the camelCase
    ``templateInputs`` alias path (API response shape).

    ## Test

    - ``templateInputs.PRIORITY`` is lifted when the camelCase key is used and
      top-level priority is absent.
    - ``PRIORITY`` is stripped from the camelCase ``templateInputs`` dict.

    ## Classes and Methods

    - ``PolicyGroupCreate._normalize_priority_from_template_inputs``
    """
    with does_not_raise():
        instance = PolicyGroupCreate.model_validate(
            {
                "templateName": "switch_freeform",
                "templateInputs": {"PRIORITY": "300", "CONF": "banner"},
            }
        )
    assert instance.priority == 300
    assert instance.template_inputs == {"CONF": "banner"}


def test_manage_policy_groups_policy_group_base_00340() -> None:
    """
    # Summary

    Verify the priority normalisation tolerates a non-integer
    ``templateInputs.PRIORITY`` echo by leaving top-level priority
    unchanged while still stripping ``PRIORITY``.

    ## Test

    - Non-numeric ``PRIORITY`` value does not raise.
    - Top-level priority stays as the explicit user-supplied value (``None``
      here) when the lift fails -- Pydantic only substitutes the field
      default when the key is absent, not when it was passed as ``None``.
    - ``PRIORITY`` is removed from ``template_inputs`` regardless.

    ## Classes and Methods

    - ``PolicyGroupCreate._normalize_priority_from_template_inputs``
    """
    with does_not_raise():
        instance = PolicyGroupCreate.model_validate(
            {
                "template_name": "switch_freeform",
                "priority": None,
                "template_inputs": {"PRIORITY": "not-an-int", "CONF": "x"},
            }
        )
    # Lift failed; explicit None is preserved (default only fires on absent key).
    assert instance.priority is None
    assert instance.template_inputs == {"CONF": "x"}


def test_manage_policy_groups_policy_group_base_00350() -> None:
    """
    # Summary

    Verify the priority normalisation collapses ``template_inputs`` to
    ``None`` when ``PRIORITY`` is the only key.

    ## Test

    - After stripping ``PRIORITY``, an empty ``template_inputs`` dict is
      coerced to ``None``.

    ## Classes and Methods

    - ``PolicyGroupCreate._normalize_priority_from_template_inputs``
    """
    with does_not_raise():
        instance = PolicyGroupCreate.model_validate(
            {
                "template_name": "switch_freeform",
                "template_inputs": {"PRIORITY": "150"},
            }
        )
    assert instance.priority == 150
    assert instance.template_inputs is None


# =============================================================================
# Test: from_config classmethod
# =============================================================================


def test_manage_policy_groups_policy_group_base_00400() -> None:
    """
    # Summary

    Verify ``from_config()`` translates the user-facing ``name`` field to
    the model's ``template_name`` field.

    ## Test

    - Ansible-style ``name`` is mapped to ``template_name``.
    - Original ``name`` key is removed.

    ## Classes and Methods

    - ``PolicyGroupCreate.from_config``
    """
    with does_not_raise():
        instance = PolicyGroupCreate.from_config(
            {"name": "feature_enable", "switch_ids": ["FDO111"]}
        )
    assert instance.template_name == "feature_enable"
    assert instance.switch_ids == ["FDO111"]


def test_manage_policy_groups_policy_group_base_00410() -> None:
    """
    # Summary

    Verify ``from_config()`` prefers an explicit ``template_name`` over
    ``name`` when both are present (no overwrite).

    ## Test

    - If both ``name`` and ``template_name`` are passed, ``template_name``
      wins.

    ## Classes and Methods

    - ``PolicyGroupCreate.from_config``
    """
    with does_not_raise():
        instance = PolicyGroupCreate.from_config(
            {"name": "user_facing", "template_name": "model_value"}
        )
    assert instance.template_name == "model_value"


def test_manage_policy_groups_policy_group_base_00420() -> None:
    """
    # Summary

    Verify ``from_config()`` strips Ansible-injected default placeholders
    (``None``, ``[]``, ``{}``) so Pydantic defaults are honoured
    and ``model_fields_set`` accurately reflects user input.

    ## Test

    - ``description=None`` is stripped -> field remains the model default.
    - omitted ``priority`` remains ``None``.
    - ``switch_ids=[]`` is stripped -> switch_ids remains the default [].
    - ``template_inputs={}`` is stripped -> template_inputs remains None.

    ## Classes and Methods

    - ``PolicyGroupCreate.from_config``
    """
    with does_not_raise():
        instance = PolicyGroupCreate.from_config(
            {
                "name": "feature_enable",
                "description": None,
                "switch_ids": [],
                "template_inputs": {},
            }
        )
    assert instance.description is None
    assert instance.priority is None
    assert instance.switch_ids == []
    assert instance.template_inputs is None

    with pytest.raises(ValidationError, match="priority"):
        PolicyGroupCreate.from_config({"name": "feature_enable", "priority": 0})


def test_manage_policy_groups_policy_group_base_00430() -> None:
    """
    # Summary

    Verify ``from_config()`` stringifies all ``template_inputs`` values so
    diff comparison matches the controller's after-deploy shape (controller
    coerces all template input values to strings).

    ## Test

    - Integer template input value is converted to its string form.
    - Boolean template input value is converted to its string form.
    - Existing string values are preserved.

    ## Classes and Methods

    - ``PolicyGroupCreate.from_config``
    """
    with does_not_raise():
        instance = PolicyGroupCreate.from_config(
            {
                "name": "feature_enable",
                "template_inputs": {
                    "intValue": 5,
                    "boolValue": True,
                    "strValue": "lacp",
                },
            }
        )
    assert instance.template_inputs == {
        "intValue": "5",
        "boolValue": "True",
        "strValue": "lacp",
    }


# =============================================================================
# Test: get_argument_spec classmethod
# =============================================================================


def test_manage_policy_groups_policy_group_base_00500() -> None:
    """
    # Summary

    Verify ``get_argument_spec()`` returns the documented module-level
    argument spec shape consumed by ``AnsibleModule``.

    ## Test

    - Top-level keys ``fabric_name``, ``deploy``, ``config``,
      ``ticket_id``, ``cluster_name``, ``state`` are present.
    - ``fabric_name`` is required and aliased to ``fabric``.
    - ``deploy`` defaults to ``True``.
    - ``ticket_id`` and ``cluster_name`` are plain optional strings
      (no default, no required flag) so they are omitted from the
      emitted request path when callers do not set them.
    - ``state`` choices are ``["merged", "deleted", "gathered"]``.

    ## Classes and Methods

    - ``PolicyGroupCreate.get_argument_spec``
    """
    spec = PolicyGroupCreate.get_argument_spec()

    assert set(spec.keys()) == {
        "fabric_name",
        "deploy",
        "config",
        "ticket_id",
        "cluster_name",
        "state",
    }
    assert spec["fabric_name"]["required"] is True
    assert spec["fabric_name"]["aliases"] == ["fabric"]
    assert spec["deploy"]["default"] is True
    assert spec["ticket_id"] == {"type": "str"}
    assert spec["cluster_name"] == {"type": "str"}
    assert spec["state"]["default"] == "merged"
    assert spec["state"]["choices"] == ["merged", "deleted", "gathered"]


def test_manage_policy_groups_policy_group_base_00510() -> None:
    """
    # Summary

    Verify the ``config`` suboptions in ``get_argument_spec()`` expose every
    user-facing playbook field.

    ## Test

    - ``config.options`` includes ``name``, ``policy_id``, ``description``,
      ``switch_ids``, ``priority``, ``template_inputs``,
      ``create_additional_policy``.
    - ``create_additional_policy`` defaults to ``False``.
    - ``config`` is typed as ``list`` of ``dict`` elements.

    ## Classes and Methods

    - ``PolicyGroupCreate.get_argument_spec``
    """
    spec = PolicyGroupCreate.get_argument_spec()
    config_spec = spec["config"]
    assert config_spec["type"] == "list"
    assert config_spec["elements"] == "dict"

    options = config_spec["options"]
    assert set(options.keys()) == {
        "name",
        "policy_id",
        "description",
        "switch_ids",
        "priority",
        "template_inputs",
        "create_additional_policy",
    }
    assert options["create_additional_policy"]["default"] is False


# =============================================================================
# Test: to_request_dict (payload shape with alias keys)
# =============================================================================


def test_manage_policy_groups_policy_group_base_00600() -> None:
    """
    # Summary

    Verify ``to_request_dict()`` emits camelCase alias keys and excludes
    ``None`` values from the payload.

    ## Test

    - ``switchIds``, ``templateName``, ``entityType``, ``entityName`` are
      present with camelCase keys.
    - ``description=None`` is omitted from the payload.
    - ``templateInputs`` is present when set.

    ## Classes and Methods

    - ``PolicyGroupCreate.to_request_dict``
    """
    instance = PolicyGroupCreate(
        switch_ids=["FDO111"],
        template_name="feature_enable",
        template_inputs={"featureName": "lacp"},
    )
    payload = instance.to_request_dict()

    assert payload["switchIds"] == ["FDO111"]
    assert payload["templateName"] == "feature_enable"
    assert payload["entityType"] == "switch"
    assert payload["entityName"] == "SWITCH"
    assert payload["templateInputs"] == {"featureName": "lacp"}
    assert "description" not in payload
    assert "priority" not in payload


def test_manage_policy_groups_policy_group_base_00610() -> None:
    """
    # Summary

    Verify ``to_request_dict()`` excludes the ``payload_exclude_fields``
    declared on the model (``policy_id`` and ``create_additional_policy``).

    ## Test

    - ``policyId`` is excluded even when set (server-generated, never sent).
    - ``create_additional_policy`` is excluded (module-only flag).

    ## Classes and Methods

    - ``PolicyGroupCreate.to_request_dict``
    - ``PolicyGroupCreate.payload_exclude_fields``
    """
    instance = PolicyGroupCreate(
        policy_id="POLICY-GROUP-999",
        switch_ids=["FDO111"],
        template_name="feature_enable",
        create_additional_policy=True,
    )
    payload = instance.to_request_dict()

    assert "policyId" not in payload
    assert "policy_id" not in payload
    assert "create_additional_policy" not in payload
    assert "createAdditionalPolicy" not in payload


def test_manage_policy_groups_policy_group_base_00620() -> None:
    """
    # Summary

    Verify ``to_request_dict()`` preserves switch_ids ordering and includes
    the explicit ``description`` and ``priority`` when supplied.

    ## Test

    - ``switchIds`` order matches input.
    - ``description`` is included as snake-cased field has no alias.
    - ``priority`` is included.
    - ``source`` is included (even when empty string).

    ## Classes and Methods

    - ``PolicyGroupCreate.to_request_dict``
    """
    instance = PolicyGroupCreate(
        switch_ids=["FDO333", "FDO111", "FDO222"],
        template_name="feature_enable",
        description="Enable LACP",
        priority=100,
        source="UNDERLAY",
    )
    payload = instance.to_request_dict()

    assert payload["switchIds"] == ["FDO333", "FDO111", "FDO222"]
    assert payload["description"] == "Enable LACP"
    assert payload["priority"] == 100
    assert payload["source"] == "UNDERLAY"


# =============================================================================
# Test: Composite identifier ClassVars
# =============================================================================


def test_manage_policy_groups_policy_group_base_00700() -> None:
    """
    # Summary

    Verify ``PolicyGroupCreate`` declares the composite identifier used by
    ``NDConfigCollection`` to key the have/want diff.

    ## Test

    - ``identifiers`` is exactly ``["description", "template_name"]``.
    - ``identifier_strategy`` is ``"composite"``.
    - ``exclude_from_diff`` covers the server-only / module-only fields
      that should not trigger an update.

    ## Classes and Methods

    - ``PolicyGroupCreate.identifiers``
    - ``PolicyGroupCreate.identifier_strategy``
    - ``PolicyGroupCreate.exclude_from_diff``
    """
    assert PolicyGroupCreate.identifiers == ["description", "template_name"]
    assert PolicyGroupCreate.identifier_strategy == "composite"
    assert PolicyGroupCreate.exclude_from_diff == {
        "source",
        "policy_id",
        "create_additional_policy",
    }
    assert PolicyGroupCreate.payload_exclude_fields == {
        "policy_id",
        "create_additional_policy",
    }
