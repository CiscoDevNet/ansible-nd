# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ``models/manage_policy_groups/gathered_models.py``.

Tests ``GatheredPolicyGroup`` -- the read-model used by the
``state: gathered`` path of ``nd_policy_group``:

- Field defaults and aliases (mirrors the controller's policy-group GET shape).
- ``from_api_policy_group()`` parsing, including JSON-encoded
  ``templateInputs`` and the ``nvPairs`` fallback name.
- ``to_gathered_config()`` round-trip shape:
  * key renames (``template_name`` -> ``name``)
  * priority lift from ``templateInputs.PRIORITY`` (the wire-shape
    workaround for ``switch_freeform``-style templates)
  * stripping of ``SYSTEM_INJECTED_TEMPLATE_KEYS``
  * ``priority=0`` is preserved (server-reset sentinel) and not
    replaced by the model default of 500.
"""

# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.constants import (
    SYSTEM_INJECTED_TEMPLATE_KEYS,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policy_groups.gathered_models import (
    GatheredPolicyGroup,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: Field defaults and required fields
# =============================================================================


def test_manage_policy_groups_gathered_models_00010() -> None:
    """
    # Summary

    Verify ``GatheredPolicyGroup`` accepts the minimum required input and
    applies documented defaults.

    ## Test

    - ``policy_id`` is the only required field.
    - All other fields fall back to their documented defaults.

    ## Classes and Methods

    - ``GatheredPolicyGroup.__init__``
    """
    with does_not_raise():
        instance = GatheredPolicyGroup(policy_id="POLICY-GROUP-1")

    assert instance.policy_id == "POLICY-GROUP-1"
    assert instance.switch_ids == []
    assert instance.template_name == ""
    assert instance.description == ""
    assert instance.priority == 500
    assert instance.entity_type is None
    assert instance.entity_name is None
    assert instance.source is None
    assert instance.template_inputs is None


def test_manage_policy_groups_gathered_models_00020() -> None:
    """
    # Summary

    Verify ``GatheredPolicyGroup`` raises ``ValidationError`` when the
    required ``policy_id`` field is omitted.

    ## Classes and Methods

    - ``GatheredPolicyGroup.__init__``
    """
    # Pydantic v2 reports the alias (``policyId``) in the missing-field message.
    with pytest.raises(ValidationError, match="policyId"):
        GatheredPolicyGroup()


def test_manage_policy_groups_gathered_models_00030() -> None:
    """
    # Summary

    Verify ``GatheredPolicyGroup`` accepts a fully populated instance and
    preserves every field.

    ## Classes and Methods

    - ``GatheredPolicyGroup.__init__``
    """
    with does_not_raise():
        instance = GatheredPolicyGroup(
            policy_id="POLICY-GROUP-9",
            switch_ids=["FDO1", "FDO2"],
            template_name="feature_enable",
            description="LACP",
            priority=750,
            entity_type="switch",
            entity_name="SWITCH",
            source="UNDERLAY",
            template_inputs={"featureName": "lacp"},
        )

    assert instance.switch_ids == ["FDO1", "FDO2"]
    assert instance.template_name == "feature_enable"
    assert instance.description == "LACP"
    assert instance.priority == 750
    assert instance.entity_type == "switch"
    assert instance.entity_name == "SWITCH"
    assert instance.source == "UNDERLAY"
    assert instance.template_inputs == {"featureName": "lacp"}


def test_manage_policy_groups_gathered_models_00040() -> None:
    """
    # Summary

    Verify ``GatheredPolicyGroup`` accepts the camelCase aliases used in
    the API response shape.

    ## Test

    - ``policyId``, ``switchIds``, ``templateName``, ``entityType``,
      ``entityName``, ``templateInputs`` map to their snake_case fields.

    ## Classes and Methods

    - ``GatheredPolicyGroup.model_validate``
    """
    payload = {
        "policyId": "POLICY-GROUP-7",
        "switchIds": ["FDO1"],
        "templateName": "feature_enable",
        "entityType": "switch",
        "entityName": "SWITCH",
        "templateInputs": {"featureName": "lacp"},
    }
    with does_not_raise():
        instance = GatheredPolicyGroup.model_validate(payload)

    assert instance.policy_id == "POLICY-GROUP-7"
    assert instance.switch_ids == ["FDO1"]
    assert instance.template_name == "feature_enable"
    assert instance.entity_type == "switch"
    assert instance.entity_name == "SWITCH"
    assert instance.template_inputs == {"featureName": "lacp"}


# =============================================================================
# Test: from_api_policy_group classmethod
# =============================================================================


def test_manage_policy_groups_gathered_models_00100() -> None:
    """
    # Summary

    Verify ``from_api_policy_group()`` parses a minimal API response dict
    containing only the required ``policyId``.

    ## Classes and Methods

    - ``GatheredPolicyGroup.from_api_policy_group``
    """
    with does_not_raise():
        instance = GatheredPolicyGroup.from_api_policy_group({"policyId": "POLICY-GROUP-1"})

    assert instance.policy_id == "POLICY-GROUP-1"
    assert instance.template_inputs == {}


def test_manage_policy_groups_gathered_models_00110() -> None:
    """
    # Summary

    Verify ``from_api_policy_group()`` parses a fully populated controller
    response into the corresponding model fields.

    ## Classes and Methods

    - ``GatheredPolicyGroup.from_api_policy_group``
    """
    api_doc = {
        "policyId": "POLICY-GROUP-143310",
        "switchIds": ["FDO25031SY4", "FDO245206N5"],
        "templateName": "feature_enable",
        "description": "LACP",
        "priority": 100,
        "entityType": "switch",
        "entityName": "SWITCH",
        "source": "UNDERLAY",
        "templateInputs": {"featureName": "lacp"},
    }
    with does_not_raise():
        instance = GatheredPolicyGroup.from_api_policy_group(api_doc)

    assert instance.policy_id == "POLICY-GROUP-143310"
    assert instance.switch_ids == ["FDO25031SY4", "FDO245206N5"]
    assert instance.template_name == "feature_enable"
    assert instance.description == "LACP"
    assert instance.priority == 100
    assert instance.entity_type == "switch"
    assert instance.entity_name == "SWITCH"
    assert instance.source == "UNDERLAY"
    assert instance.template_inputs == {"featureName": "lacp"}


def test_manage_policy_groups_gathered_models_00120() -> None:
    """
    # Summary

    Verify ``from_api_policy_group()`` decodes a JSON-encoded
    ``templateInputs`` string back into a dict.

    ## Test

    - JSON-encoded ``templateInputs`` is parsed to a dict.

    ## Classes and Methods

    - ``GatheredPolicyGroup.from_api_policy_group``
    """
    api_doc = {
        "policyId": "POLICY-GROUP-1",
        "templateInputs": '{"featureName": "lacp", "PRIORITY": "750"}',
    }
    with does_not_raise():
        instance = GatheredPolicyGroup.from_api_policy_group(api_doc)

    assert instance.template_inputs == {"featureName": "lacp", "PRIORITY": "750"}


def test_manage_policy_groups_gathered_models_00130() -> None:
    """
    # Summary

    Verify ``from_api_policy_group()`` tolerates a malformed JSON string in
    ``templateInputs`` by silently falling back to an empty dict (a warning
    is logged but no exception is raised).

    ## Classes and Methods

    - ``GatheredPolicyGroup.from_api_policy_group``
    """
    api_doc = {
        "policyId": "POLICY-GROUP-1",
        "templateInputs": "{not-valid-json",
    }
    with does_not_raise():
        instance = GatheredPolicyGroup.from_api_policy_group(api_doc)

    assert instance.template_inputs == {}


def test_manage_policy_groups_gathered_models_00140() -> None:
    """
    # Summary

    Verify ``from_api_policy_group()`` falls back to the ``nvPairs`` key
    when ``templateInputs`` is absent (older controller response shape).

    ## Classes and Methods

    - ``GatheredPolicyGroup.from_api_policy_group``
    """
    api_doc = {
        "policyId": "POLICY-GROUP-1",
        "nvPairs": {"featureName": "lacp"},
    }
    with does_not_raise():
        instance = GatheredPolicyGroup.from_api_policy_group(api_doc)

    assert instance.template_inputs == {"featureName": "lacp"}


def test_manage_policy_groups_gathered_models_00150() -> None:
    """
    # Summary

    Verify ``from_api_policy_group()`` does not mutate the input dict.

    ## Test

    - The caller's dict still has its original ``templateInputs`` string
      after parsing.

    ## Classes and Methods

    - ``GatheredPolicyGroup.from_api_policy_group``
    """
    original = {
        "policyId": "POLICY-GROUP-1",
        "templateInputs": '{"k": "v"}',
    }
    snapshot = dict(original)
    GatheredPolicyGroup.from_api_policy_group(original)
    assert original == snapshot


# =============================================================================
# Test: to_gathered_config method
# =============================================================================


def test_manage_policy_groups_gathered_models_00200() -> None:
    """
    # Summary

    Verify ``to_gathered_config()`` emits the documented playbook-config
    shape with ``template_name`` renamed to ``name``.

    ## Test

    - Output dict keys are ``{name, policy_id, description, switch_ids,
      priority}`` when no ``template_inputs`` are present.
    - ``template_inputs`` is omitted when empty.

    ## Classes and Methods

    - ``GatheredPolicyGroup.to_gathered_config``
    """
    instance = GatheredPolicyGroup(
        policy_id="POLICY-GROUP-1",
        switch_ids=["FDO1"],
        template_name="feature_enable",
        description="LACP",
        priority=100,
    )
    config = instance.to_gathered_config()

    assert config == {
        "name": "feature_enable",
        "policy_id": "POLICY-GROUP-1",
        "description": "LACP",
        "switch_ids": ["FDO1"],
        "priority": 100,
    }


def test_manage_policy_groups_gathered_models_00210() -> None:
    """
    # Summary

    Verify ``to_gathered_config()`` strips every key in
    ``SYSTEM_INJECTED_TEMPLATE_KEYS`` from ``template_inputs`` so the
    round-tripped config does not leak controller-injected metadata.

    ## Test

    - Every key in ``SYSTEM_INJECTED_TEMPLATE_KEYS`` is removed.
    - Genuine user keys are preserved.

    ## Classes and Methods

    - ``GatheredPolicyGroup.to_gathered_config``
    """
    raw_inputs = {key: "stripped" for key in SYSTEM_INJECTED_TEMPLATE_KEYS}
    raw_inputs.update({"featureName": "lacp", "CONF": "x"})

    instance = GatheredPolicyGroup(
        policy_id="POLICY-GROUP-1",
        template_name="feature_enable",
        priority=750,
        template_inputs=raw_inputs,
    )
    config = instance.to_gathered_config()

    assert config["template_inputs"] == {"featureName": "lacp", "CONF": "x"}
    for key in SYSTEM_INJECTED_TEMPLATE_KEYS:
        assert key not in config["template_inputs"]


def test_manage_policy_groups_gathered_models_00220() -> None:
    """
    # Summary

    Verify ``to_gathered_config()`` omits ``template_inputs`` entirely when
    the only entries are system-injected keys (cleaning results in empty).

    ## Classes and Methods

    - ``GatheredPolicyGroup.to_gathered_config``
    """
    instance = GatheredPolicyGroup(
        policy_id="POLICY-GROUP-1",
        template_name="switch_freeform",
        priority=750,
        template_inputs={"PRIORITY": "750", "POLICY_ID": "POLICY-GROUP-1"},
    )
    config = instance.to_gathered_config()

    assert "template_inputs" not in config


def test_manage_policy_groups_gathered_models_00230() -> None:
    """
    # Summary

    Verify ``to_gathered_config()`` lifts ``templateInputs.PRIORITY`` into
    the top-level ``priority`` (wire-shape workaround for
    ``switch_freeform``-style templates whose top-level ``priority`` field
    is server-reset to 0).

    ## Test

    - With ``priority=0`` and ``templateInputs.PRIORITY="750"``, the
      gathered output reports ``priority=750``.
    - ``PRIORITY`` is removed from the emitted ``template_inputs`` because
      it is in ``SYSTEM_INJECTED_TEMPLATE_KEYS``.

    ## Classes and Methods

    - ``GatheredPolicyGroup.to_gathered_config``
    """
    instance = GatheredPolicyGroup(
        policy_id="POLICY-GROUP-1",
        template_name="switch_freeform",
        priority=0,
        template_inputs={"PRIORITY": "750", "CONF": "banner"},
    )
    config = instance.to_gathered_config()

    assert config["priority"] == 750
    assert config["template_inputs"] == {"CONF": "banner"}


def test_manage_policy_groups_gathered_models_00240() -> None:
    """
    # Summary

    Verify ``to_gathered_config()`` preserves ``priority=0`` (server-reset
    sentinel) when ``templateInputs.PRIORITY`` is absent. The model
    default of 500 must NOT be substituted here -- doing so would break
    idempotency on the next round-trip (the next have would still be 0).

    ## Classes and Methods

    - ``GatheredPolicyGroup.to_gathered_config``
    """
    instance = GatheredPolicyGroup(
        policy_id="POLICY-GROUP-1",
        template_name="feature_enable",
        priority=0,
        template_inputs={"featureName": "lacp"},
    )
    config = instance.to_gathered_config()

    assert config["priority"] == 0


def test_manage_policy_groups_gathered_models_00250() -> None:
    """
    # Summary

    Verify ``to_gathered_config()`` ignores a non-integer
    ``templateInputs.PRIORITY`` and falls back to the top-level priority.

    ## Test

    - Non-numeric ``PRIORITY`` does not raise.
    - Top-level priority is preserved unchanged.

    ## Classes and Methods

    - ``GatheredPolicyGroup.to_gathered_config``
    """
    instance = GatheredPolicyGroup(
        policy_id="POLICY-GROUP-1",
        template_name="switch_freeform",
        priority=200,
        template_inputs={"PRIORITY": "not-an-int", "CONF": "x"},
    )
    config = instance.to_gathered_config()

    assert config["priority"] == 200
    # PRIORITY is in SYSTEM_INJECTED_TEMPLATE_KEYS so it is stripped anyway.
    assert config["template_inputs"] == {"CONF": "x"}


def test_manage_policy_groups_gathered_models_00260() -> None:
    """
    # Summary

    Verify ``to_gathered_config()`` substitutes empty defaults for
    ``description`` and ``switch_ids`` when they are missing on the model.

    ## Test

    - ``description=None`` is emitted as the empty string in the
      gathered output (so playbook round-trip never carries ``null``).
    - ``switch_ids`` default of ``[]`` is emitted verbatim.

    ## Classes and Methods

    - ``GatheredPolicyGroup.to_gathered_config``
    """
    instance = GatheredPolicyGroup(
        policy_id="POLICY-GROUP-1",
        template_name="feature_enable",
        description=None,
        priority=500,
    )
    config = instance.to_gathered_config()

    assert config["description"] == ""
    assert config["switch_ids"] == []


# =============================================================================
# Test: NDConfigCollection ClassVars
# =============================================================================


def test_manage_policy_groups_gathered_models_00300() -> None:
    """
    # Summary

    Verify ``GatheredPolicyGroup`` declares the single-identifier strategy
    used by ``NDConfigCollection`` to de-duplicate gathered output by
    ``policy_id``.

    ## Test

    - ``identifiers`` is exactly ``["policy_id"]``.
    - ``identifier_strategy`` is ``"single"``.
    - ``exclude_from_diff`` is an empty set (read-model has no diff
      semantics).

    ## Classes and Methods

    - ``GatheredPolicyGroup.identifiers``
    - ``GatheredPolicyGroup.identifier_strategy``
    - ``GatheredPolicyGroup.exclude_from_diff``
    """
    assert GatheredPolicyGroup.identifiers == ["policy_id"]
    assert GatheredPolicyGroup.identifier_strategy == "single"
    assert GatheredPolicyGroup.exclude_from_diff == set()
