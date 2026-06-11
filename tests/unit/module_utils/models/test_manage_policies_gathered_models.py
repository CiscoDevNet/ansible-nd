# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ``models/manage_policies/gathered_models.py``.

Covers the ``GatheredPolicy`` read-model used by ``state=gathered``:

- Construction (snake_case and camelCase aliases, defaults, required fields).
- ClassVar contract (``identifiers``, ``identifier_strategy="single"``,
  ``exclude_from_diff``, ``config_exclude_fields``).
- ``from_api_policy()`` classmethod:
    * ``templateInputs`` JSON-string parsing, malformed-JSON fallback to ``{}``,
      missing-key fallback, ``nvPairs`` alias fallback.
    * ``switchId`` <-- ``serialNumber`` fallback.
    * Pass-through to ``from_response()`` (alias resolution by Pydantic).
- ``to_gathered_config()`` shape (matches the playbook ``config[]`` schema
  so users can copy-paste gathered output into a playbook).
- ``get_identifier_value()`` single-strategy lookup.
"""

# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.gathered_models import (
    GatheredPolicy,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)


def _api_policy(**overrides) -> dict:
    """Return a representative raw API policy dict (camelCase keys, JSON
    ``templateInputs``)."""
    data = {
        "policyId": "POLICY-28440",
        "switchId": "FDO25031SY4",
        "templateName": "feature_enable",
        "description": "Enable LACP",
        "priority": 100,
        "entityType": "switch",
        "entityName": "SWITCH",
        "source": "",
        "templateInputs": '{"featureName": "lacp"}',
        # Junk fields the API returns but the model ignores
        "generatedConfig": "feature lacp\n",
        "markDeleted": False,
        "createTimestamp": "2026-01-01T00:00:00Z",
    }
    data.update(overrides)
    return data


# =============================================================================
# Test: ClassVars
# =============================================================================


def test_manage_policies_gathered_models_00010() -> None:
    """
    # Summary

    Verify the ``GatheredPolicy`` ClassVar contract (identifier metadata and
    config-exclude set) matches the design.

    ## Test

    - ``identifiers == ["policy_id"]`` (single primary key).
    - ``identifier_strategy == "single"`` (NDConfigCollection dedup key).
    - ``exclude_from_diff`` is the empty set (gathered model is not diffed).
    - ``config_exclude_fields`` covers exactly the 5 internal/non-user-facing
      fields (entity_type, entity_name, source, secondary_entity_name,
      secondary_entity_type).

    ## Classes and Methods

    - ``GatheredPolicy`` ClassVars
    """
    assert GatheredPolicy.identifiers == ["policy_id"]
    assert GatheredPolicy.identifier_strategy == "single"
    assert GatheredPolicy.exclude_from_diff == set()
    assert GatheredPolicy.config_exclude_fields == {
        "entity_type",
        "entity_name",
        "source",
        "secondary_entity_name",
        "secondary_entity_type",
    }


# =============================================================================
# Test: Construction
# =============================================================================


def test_manage_policies_gathered_models_00020() -> None:
    """
    # Summary

    Verify minimal-arg construction (only required fields: ``policy_id`` and
    ``switch_id``) succeeds, and that defaults are applied.

    ## Test

    - Required fields are accepted via snake_case names.
    - Defaults: ``template_name=""``, ``description=""``, ``priority=500``.
    - All other optional fields default to ``None``.

    ## Classes and Methods

    - ``GatheredPolicy.__init__``
    """
    with does_not_raise():
        m = GatheredPolicy(policy_id="POLICY-1", switch_id="FDO111")

    assert m.policy_id == "POLICY-1"
    assert m.switch_id == "FDO111"
    assert m.template_name == ""
    assert m.description == ""
    assert m.priority == 500
    assert m.entity_type is None
    assert m.entity_name is None
    assert m.source is None
    assert m.template_inputs is None
    assert m.secondary_entity_name is None
    assert m.secondary_entity_type is None


def test_manage_policies_gathered_models_00030() -> None:
    """
    # Summary

    Verify construction accepts the camelCase aliases used on the wire
    (``policyId``, ``switchId``, ``templateName``, ``entityType``,
    ``entityName``, ``templateInputs``, etc.).

    ## Test

    - Each aliased input is mapped to its Python attribute.

    ## Classes and Methods

    - ``GatheredPolicy.__init__`` (Field aliases)
    """
    with does_not_raise():
        m = GatheredPolicy(
            policyId="POLICY-99",
            switchId="FDO999",
            templateName="feature_enable",
            entityType="switch",
            entityName="SWITCH",
            templateInputs={"featureName": "lacp"},
            secondaryEntityName="other",
            secondaryEntityType="interface",
        )

    assert m.policy_id == "POLICY-99"
    assert m.switch_id == "FDO999"
    assert m.template_name == "feature_enable"
    assert m.entity_type == "switch"
    assert m.entity_name == "SWITCH"
    assert m.template_inputs == {"featureName": "lacp"}
    assert m.secondary_entity_name == "other"
    assert m.secondary_entity_type == "interface"


@pytest.mark.parametrize("missing", ["policy_id", "switch_id"])
def test_manage_policies_gathered_models_00040(missing) -> None:
    """
    # Summary

    Verify the two required fields are enforced (``policy_id`` and
    ``switch_id`` have no default).

    ## Test

    - Omitting either ``policy_id`` or ``switch_id`` raises ``ValidationError``.

    ## Classes and Methods

    - ``GatheredPolicy.__init__``
    """
    kwargs = {"policy_id": "POLICY-1", "switch_id": "FDO111"}
    del kwargs[missing]

    with pytest.raises(ValidationError):
        GatheredPolicy(**kwargs)


# =============================================================================
# Test: get_identifier_value() uses single strategy
# =============================================================================


def test_manage_policies_gathered_models_00050() -> None:
    """
    # Summary

    Verify ``get_identifier_value()`` returns the ``policy_id`` string
    directly (single-strategy lookup, NOT a tuple).

    ## Test

    - Return value is the bare ``policy_id`` string.

    ## Classes and Methods

    - ``GatheredPolicy.get_identifier_value`` (inherited from NDBaseModel)
    """
    m = GatheredPolicy(policy_id="POLICY-42", switch_id="FDO000")

    assert m.get_identifier_value() == "POLICY-42"


# =============================================================================
# Test: from_api_policy() basic path
# =============================================================================


def test_manage_policies_gathered_models_00100() -> None:
    """
    # Summary

    Verify ``from_api_policy()`` consumes a realistic API response (with
    JSON-string ``templateInputs`` and several "ignored" extra keys) and
    returns a valid ``GatheredPolicy``.

    ## Test

    - All documented fields are populated correctly.
    - ``templateInputs`` JSON string is parsed into a dict.
    - Unknown response keys (``generatedConfig``, ``markDeleted``,
      ``createTimestamp``) are silently dropped (``extra="ignore"``).

    ## Classes and Methods

    - ``GatheredPolicy.from_api_policy``
    """
    with does_not_raise():
        m = GatheredPolicy.from_api_policy(_api_policy())

    assert m.policy_id == "POLICY-28440"
    assert m.switch_id == "FDO25031SY4"
    assert m.template_name == "feature_enable"
    assert m.description == "Enable LACP"
    assert m.priority == 100
    assert m.entity_type == "switch"
    assert m.entity_name == "SWITCH"
    assert m.source == ""
    assert m.template_inputs == {"featureName": "lacp"}


def test_manage_policies_gathered_models_00110() -> None:
    """
    # Summary

    Verify ``from_api_policy()`` does not mutate the caller's dict (the
    method must operate on a copy so retries/log statements still see the
    original raw payload).

    ## Test

    - The original input dict is unchanged after the call.
    - In particular, the ``templateInputs`` string is not replaced with a
      parsed dict on the caller's side.

    ## Classes and Methods

    - ``GatheredPolicy.from_api_policy``
    """
    raw = _api_policy()
    snapshot = dict(raw)
    snapshot_inputs = raw["templateInputs"]

    GatheredPolicy.from_api_policy(raw)

    assert raw == snapshot
    assert raw["templateInputs"] == snapshot_inputs
    assert isinstance(raw["templateInputs"], str)


# =============================================================================
# Test: from_api_policy() templateInputs handling
# =============================================================================


def test_manage_policies_gathered_models_00120() -> None:
    """
    # Summary

    Verify ``from_api_policy()`` accepts ``templateInputs`` already as a
    dict (no JSON parsing performed) and stores it verbatim.

    ## Test

    - Dict-valued ``templateInputs`` is kept as-is.

    ## Classes and Methods

    - ``GatheredPolicy.from_api_policy``
    """
    raw = _api_policy(templateInputs={"featureName": "vpc", "extra": [1, 2]})

    m = GatheredPolicy.from_api_policy(raw)

    assert m.template_inputs == {"featureName": "vpc", "extra": [1, 2]}


def test_manage_policies_gathered_models_00130() -> None:
    """
    # Summary

    Verify ``from_api_policy()`` parses a JSON-encoded ``templateInputs``
    string and exposes the resulting dict on ``template_inputs``.

    ## Test

    - JSON-string input is decoded into the expected Python dict.

    ## Classes and Methods

    - ``GatheredPolicy.from_api_policy``
    """
    raw = _api_policy(templateInputs='{"featureName": "vpc", "n": 3}')

    m = GatheredPolicy.from_api_policy(raw)

    assert m.template_inputs == {"featureName": "vpc", "n": 3}


def test_manage_policies_gathered_models_00140() -> None:
    """
    # Summary

    Verify ``from_api_policy()`` swallows malformed JSON in
    ``templateInputs`` and falls back to an empty dict (must not crash on
    bad API output).

    ## Test

    - Malformed JSON does not raise; ``template_inputs == {}``.

    ## Classes and Methods

    - ``GatheredPolicy.from_api_policy``
    """
    raw = _api_policy(templateInputs="{not-json")

    with does_not_raise():
        m = GatheredPolicy.from_api_policy(raw)

    assert m.template_inputs == {}


def test_manage_policies_gathered_models_00150() -> None:
    """
    # Summary

    Verify ``from_api_policy()`` falls back to the legacy ``nvPairs`` key
    when ``templateInputs`` is not present.

    ## Test

    - ``nvPairs`` content (string or dict) is used in place of
      ``templateInputs``.

    ## Classes and Methods

    - ``GatheredPolicy.from_api_policy``
    """
    raw = _api_policy()
    raw.pop("templateInputs")
    raw["nvPairs"] = {"featureName": "ospf"}

    m = GatheredPolicy.from_api_policy(raw)

    assert m.template_inputs == {"featureName": "ospf"}


def test_manage_policies_gathered_models_00160() -> None:
    """
    # Summary

    Verify ``from_api_policy()`` falls back to an empty dict when both
    ``templateInputs`` and ``nvPairs`` are absent.

    ## Test

    - With neither key in the input, ``template_inputs == {}``.

    ## Classes and Methods

    - ``GatheredPolicy.from_api_policy``
    """
    raw = _api_policy()
    raw.pop("templateInputs")

    m = GatheredPolicy.from_api_policy(raw)

    assert m.template_inputs == {}


# =============================================================================
# Test: from_api_policy() switchId fallback to serialNumber
# =============================================================================


def test_manage_policies_gathered_models_00170() -> None:
    """
    # Summary

    Verify ``from_api_policy()`` substitutes ``serialNumber`` for
    ``switchId`` when only the legacy key is present in the API response.

    ## Test

    - ``serialNumber`` becomes the ``switch_id``.

    ## Classes and Methods

    - ``GatheredPolicy.from_api_policy``
    """
    raw = _api_policy()
    raw.pop("switchId")
    raw["serialNumber"] = "FDO_LEGACY"

    m = GatheredPolicy.from_api_policy(raw)

    assert m.switch_id == "FDO_LEGACY"


def test_manage_policies_gathered_models_00180() -> None:
    """
    # Summary

    Verify ``from_api_policy()`` prefers ``switchId`` when both keys are
    present (no overwrite by the legacy ``serialNumber`` fallback).

    ## Test

    - The model's ``switch_id`` matches the value from ``switchId``, not
      ``serialNumber``.

    ## Classes and Methods

    - ``GatheredPolicy.from_api_policy``
    """
    raw = _api_policy(switchId="FDO_NEW", serialNumber="FDO_OLD")

    m = GatheredPolicy.from_api_policy(raw)

    assert m.switch_id == "FDO_NEW"


# =============================================================================
# Test: to_gathered_config() shape
# =============================================================================


def test_manage_policies_gathered_models_00200() -> None:
    """
    # Summary

    Verify ``to_gathered_config()`` produces a dict that matches the
    playbook ``config[]`` schema (so users can copy-paste gathered output
    straight into a ``state=merged`` playbook).

    ## Test

    - Top-level keys: exactly ``name``, ``policy_id``, ``switch``,
      ``description``, ``priority``, ``template_inputs``,
      ``create_additional_policy``.
    - ``switch`` is a list of one dict with ``serial_number``.
    - ``create_additional_policy`` is always ``False`` for gathered.

    ## Classes and Methods

    - ``GatheredPolicy.to_gathered_config``
    """
    m = GatheredPolicy.from_api_policy(_api_policy())

    cfg = m.to_gathered_config()

    assert set(cfg.keys()) == {
        "name",
        "policy_id",
        "switch",
        "description",
        "priority",
        "template_inputs",
        "create_additional_policy",
    }
    assert cfg["name"] == "feature_enable"
    assert cfg["policy_id"] == "POLICY-28440"
    assert cfg["switch"] == [{"serial_number": "FDO25031SY4"}]
    assert cfg["description"] == "Enable LACP"
    assert cfg["priority"] == 100
    assert cfg["template_inputs"] == {"featureName": "lacp"}
    assert cfg["create_additional_policy"] is False


def test_manage_policies_gathered_models_00210() -> None:
    """
    # Summary

    Verify ``to_gathered_config()`` substitutes friendly defaults for
    ``None``-valued fields:

    - ``description`` -> ``""``
    - ``priority`` -> ``500``
    - ``template_inputs`` -> ``{}``

    ## Test

    - The three ``or``-fallbacks produce the documented values, not ``None``.

    ## Classes and Methods

    - ``GatheredPolicy.to_gathered_config``
    """
    m = GatheredPolicy(
        policy_id="POLICY-NULL",
        switch_id="FDO000",
        description=None,
        priority=None,
        template_inputs=None,
    )

    cfg = m.to_gathered_config()

    assert cfg["description"] == ""
    assert cfg["priority"] == 500
    assert cfg["template_inputs"] == {}
    assert cfg["create_additional_policy"] is False


def test_manage_policies_gathered_models_00220() -> None:
    """
    # Summary

    Verify ``to_gathered_config()`` omits the internal/non-user-facing
    fields tracked by ``config_exclude_fields`` (entity_type, entity_name,
    source, secondary_entity_name, secondary_entity_type are never present
    in the gathered output).

    ## Test

    - None of the 5 internal field names appear in the gathered dict
      (neither snake_case nor camelCase).

    ## Classes and Methods

    - ``GatheredPolicy.to_gathered_config``
    """
    m = GatheredPolicy.from_api_policy(
        _api_policy(
            entityType="switch",
            entityName="SWITCH",
            source="config-source",
            secondaryEntityName="other",
            secondaryEntityType="interface",
        )
    )

    cfg = m.to_gathered_config()

    forbidden = {
        "entity_type",
        "entityType",
        "entity_name",
        "entityName",
        "source",
        "secondary_entity_name",
        "secondaryEntityName",
        "secondary_entity_type",
        "secondaryEntityType",
    }
    assert forbidden.isdisjoint(cfg.keys())


def test_manage_policies_gathered_models_00230() -> None:
    """
    # Summary

    Round-trip sanity: ``from_api_policy()`` followed by
    ``to_gathered_config()`` produces a dict whose ``policy_id`` and
    ``switch.serial_number`` come from the original raw response (most
    important for stable dedup keys downstream).

    ## Test

    - ``policy_id`` round-trips verbatim.
    - ``switch[0].serial_number`` round-trips verbatim.

    ## Classes and Methods

    - ``GatheredPolicy.from_api_policy``
    - ``GatheredPolicy.to_gathered_config``
    """
    raw = _api_policy(policyId="POLICY-RT", switchId="FDO_RT")

    cfg = GatheredPolicy.from_api_policy(raw).to_gathered_config()

    assert cfg["policy_id"] == "POLICY-RT"
    assert cfg["switch"][0]["serial_number"] == "FDO_RT"
