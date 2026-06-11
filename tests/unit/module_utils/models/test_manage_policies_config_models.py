# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ``models/manage_policies/config_models.py``.

Tests the user-facing Pydantic models that validate ``nd_policy`` playbook
input before any API or translation logic runs:

- ``PlaybookSwitchPolicyConfig``  - per-switch policy override entry.
- ``PlaybookSwitchEntry``         - switch list entry with ``ip`` alias.
- ``PlaybookPolicyConfig``        - top-level config entry with state-aware
                                    validation (``state``, ``use_desc_as_key``).
"""

# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.config_models import (
    PlaybookPolicyConfig,
    PlaybookSwitchEntry,
    PlaybookSwitchPolicyConfig,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: PlaybookSwitchPolicyConfig
# =============================================================================


def test_manage_policies_config_models_00010() -> None:
    """
    # Summary

    Verify ``PlaybookSwitchPolicyConfig`` accepts the minimum required input
    and applies documented defaults.

    ## Test

    - ``name`` is the only required field.
    - ``description`` defaults to ``""``.
    - ``priority`` defaults to ``500``.
    - ``create_additional_policy`` defaults to ``True``.
    - ``template_inputs`` defaults to an empty dict.

    ## Classes and Methods

    - ``PlaybookSwitchPolicyConfig.__init__``
    """
    with does_not_raise():
        instance = PlaybookSwitchPolicyConfig(name="switch_freeform")

    assert instance.name == "switch_freeform"
    assert instance.description == ""
    assert instance.priority == 500
    assert instance.create_additional_policy is True
    assert instance.template_inputs == {}


def test_manage_policies_config_models_00020() -> None:
    """
    # Summary

    Verify ``PlaybookSwitchPolicyConfig`` accepts a fully populated entry.

    ## Test

    - All optional fields can be supplied and are preserved verbatim.

    ## Classes and Methods

    - ``PlaybookSwitchPolicyConfig.__init__``
    """
    with does_not_raise():
        instance = PlaybookSwitchPolicyConfig(
            name="switch_freeform",
            description="MOTD banner override",
            priority=100,
            create_additional_policy=False,
            template_inputs={"CONF": "motd banner X"},
        )

    assert instance.name == "switch_freeform"
    assert instance.description == "MOTD banner override"
    assert instance.priority == 100
    assert instance.create_additional_policy is False
    assert instance.template_inputs == {"CONF": "motd banner X"}


def test_manage_policies_config_models_00030() -> None:
    """
    # Summary

    Verify ``PlaybookSwitchPolicyConfig`` rejects an empty ``name``.

    ## Test

    - Empty string for ``name`` raises ``ValidationError`` (``min_length=1``).

    ## Classes and Methods

    - ``PlaybookSwitchPolicyConfig.__init__``
    """
    with pytest.raises(ValidationError):
        PlaybookSwitchPolicyConfig(name="")


def test_manage_policies_config_models_00040() -> None:
    """
    # Summary

    Verify ``PlaybookSwitchPolicyConfig`` enforces the 255-char ``name`` cap.

    ## Test

    - Exactly 255 chars is accepted.
    - 256 chars raises ``ValidationError``.

    ## Classes and Methods

    - ``PlaybookSwitchPolicyConfig.__init__``
    """
    with does_not_raise():
        PlaybookSwitchPolicyConfig(name="x" * 255)

    with pytest.raises(ValidationError):
        PlaybookSwitchPolicyConfig(name="x" * 256)


def test_manage_policies_config_models_00050() -> None:
    """
    # Summary

    Verify ``PlaybookSwitchPolicyConfig`` enforces the 255-char description cap.

    ## Test

    - 256-char description raises ``ValidationError``.

    ## Classes and Methods

    - ``PlaybookSwitchPolicyConfig.__init__``
    """
    with pytest.raises(ValidationError):
        PlaybookSwitchPolicyConfig(name="switch_freeform", description="d" * 256)


@pytest.mark.parametrize("priority", [0, -1, 2001])
def test_manage_policies_config_models_00060(priority) -> None:
    """
    # Summary

    Verify ``PlaybookSwitchPolicyConfig`` rejects out-of-range priorities.

    ## Test

    - Priorities outside [1, 2000] raise ``ValidationError``.

    ## Classes and Methods

    - ``PlaybookSwitchPolicyConfig.__init__``
    """
    with pytest.raises(ValidationError):
        PlaybookSwitchPolicyConfig(name="switch_freeform", priority=priority)


@pytest.mark.parametrize("priority", [1, 500, 2000])
def test_manage_policies_config_models_00070(priority) -> None:
    """
    # Summary

    Verify ``PlaybookSwitchPolicyConfig`` accepts boundary priorities.

    ## Test

    - 1, 500, and 2000 are all accepted as priority values.

    ## Classes and Methods

    - ``PlaybookSwitchPolicyConfig.__init__``
    """
    with does_not_raise():
        instance = PlaybookSwitchPolicyConfig(name="switch_freeform", priority=priority)
    assert instance.priority == priority


# =============================================================================
# Test: PlaybookSwitchEntry
# =============================================================================


def test_manage_policies_config_models_00100() -> None:
    """
    # Summary

    Verify ``PlaybookSwitchEntry`` accepts a canonical ``serial_number`` and
    defaults ``policies`` to an empty list.

    ## Test

    - ``serial_number`` is preserved.
    - ``policies`` defaults to an empty list.

    ## Classes and Methods

    - ``PlaybookSwitchEntry.__init__``
    """
    with does_not_raise():
        instance = PlaybookSwitchEntry(serial_number="FDO25031SY4")

    assert instance.serial_number == "FDO25031SY4"
    assert instance.policies == []


def test_manage_policies_config_models_00110() -> None:
    """
    # Summary

    Verify the ``ip`` backward-compatible alias is copied into ``serial_number``.

    ## Test

    - Input dict with only ``ip`` produces a model with ``serial_number == ip``.

    ## Classes and Methods

    - ``PlaybookSwitchEntry.accept_ip_alias``
    """
    with does_not_raise():
        instance = PlaybookSwitchEntry.model_validate({"ip": "192.0.2.10"})

    assert instance.serial_number == "192.0.2.10"


def test_manage_policies_config_models_00120() -> None:
    """
    # Summary

    Verify ``serial_number`` wins when both ``serial_number`` and ``ip`` are
    supplied (alias does not overwrite an explicit canonical value).

    ## Test

    - ``serial_number`` is preserved as supplied; the ``ip`` value is ignored.

    ## Classes and Methods

    - ``PlaybookSwitchEntry.accept_ip_alias``
    """
    with does_not_raise():
        instance = PlaybookSwitchEntry.model_validate({"serial_number": "FDO123", "ip": "192.0.2.10"})

    assert instance.serial_number == "FDO123"


def test_manage_policies_config_models_00130() -> None:
    """
    # Summary

    Verify ``PlaybookSwitchEntry`` validates nested ``policies`` items as
    ``PlaybookSwitchPolicyConfig`` instances.

    ## Test

    - Valid nested entries are parsed and exposed as model instances.
    - A nested entry with an empty ``name`` raises ``ValidationError``.

    ## Classes and Methods

    - ``PlaybookSwitchEntry.__init__``
    """
    with does_not_raise():
        instance = PlaybookSwitchEntry.model_validate(
            {
                "serial_number": "FDO123",
                "policies": [{"name": "switch_freeform", "priority": 200}],
            }
        )

    assert len(instance.policies) == 1
    assert isinstance(instance.policies[0], PlaybookSwitchPolicyConfig)
    assert instance.policies[0].priority == 200

    with pytest.raises(ValidationError):
        PlaybookSwitchEntry.model_validate({"serial_number": "FDO123", "policies": [{"name": ""}]})


def test_manage_policies_config_models_00140() -> None:
    """
    # Summary

    Verify ``PlaybookSwitchEntry`` rejects an empty ``serial_number``.

    ## Test

    - Empty ``serial_number`` raises ``ValidationError`` (``min_length=1``).

    ## Classes and Methods

    - ``PlaybookSwitchEntry.__init__``
    """
    with pytest.raises(ValidationError):
        PlaybookSwitchEntry(serial_number="")


# =============================================================================
# Test: PlaybookPolicyConfig (defaults)
# =============================================================================


def test_manage_policies_config_models_00200() -> None:
    """
    # Summary

    Verify ``PlaybookPolicyConfig`` accepts the minimum input without
    context (no state) and applies documented defaults.

    ## Test

    - ``name`` defaults to ``None``.
    - ``description`` defaults to ``""``.
    - ``priority`` defaults to ``500``.
    - ``create_additional_policy`` defaults to ``True``.
    - ``template_inputs`` defaults to an empty dict.
    - ``switch`` defaults to ``None``.

    ## Classes and Methods

    - ``PlaybookPolicyConfig.__init__``
    - ``PlaybookPolicyConfig.validate_state_requirements``
    """
    with does_not_raise():
        instance = PlaybookPolicyConfig()

    assert instance.name is None
    assert instance.description == ""
    assert instance.priority == 500
    assert instance.create_additional_policy is True
    assert instance.template_inputs == {}
    assert instance.switch is None


def test_manage_policies_config_models_00210() -> None:
    """
    # Summary

    Verify ``PlaybookPolicyConfig`` accepts a fully populated policy entry
    (no state context required).

    ## Test

    - All policy-level fields are preserved.
    - Nested switch entries become ``PlaybookSwitchEntry`` instances.

    ## Classes and Methods

    - ``PlaybookPolicyConfig.__init__``
    """
    with does_not_raise():
        instance = PlaybookPolicyConfig.model_validate(
            {
                "name": "switch_freeform",
                "description": "MOTD banner",
                "priority": 100,
                "create_additional_policy": False,
                "template_inputs": {"CONF": "motd banner X"},
                "switch": [{"serial_number": "FDO123"}],
            }
        )

    assert instance.name == "switch_freeform"
    assert instance.priority == 100
    assert instance.create_additional_policy is False
    assert instance.template_inputs == {"CONF": "motd banner X"}
    assert len(instance.switch) == 1
    assert isinstance(instance.switch[0], PlaybookSwitchEntry)
    assert instance.switch[0].serial_number == "FDO123"


# =============================================================================
# Test: PlaybookPolicyConfig field constraint enforcement
# =============================================================================


def test_manage_policies_config_models_00220() -> None:
    """
    # Summary

    Verify ``PlaybookPolicyConfig`` enforces the 255-char ``name`` cap.

    ## Test

    - 255-char name passes; 256-char name raises ``ValidationError``.

    ## Classes and Methods

    - ``PlaybookPolicyConfig.__init__``
    """
    with does_not_raise():
        PlaybookPolicyConfig(name="x" * 255)

    with pytest.raises(ValidationError):
        PlaybookPolicyConfig(name="x" * 256)


def test_manage_policies_config_models_00230() -> None:
    """
    # Summary

    Verify ``PlaybookPolicyConfig`` enforces the 255-char ``description`` cap.

    ## Test

    - 256-char description raises ``ValidationError``.

    ## Classes and Methods

    - ``PlaybookPolicyConfig.__init__``
    """
    with pytest.raises(ValidationError):
        PlaybookPolicyConfig(description="d" * 256)


@pytest.mark.parametrize("priority", [0, -1, 2001])
def test_manage_policies_config_models_00240(priority) -> None:
    """
    # Summary

    Verify ``PlaybookPolicyConfig`` rejects out-of-range priorities.

    ## Test

    - Priorities outside [1, 2000] raise ``ValidationError``.

    ## Classes and Methods

    - ``PlaybookPolicyConfig.__init__``
    """
    with pytest.raises(ValidationError):
        PlaybookPolicyConfig(priority=priority)


# =============================================================================
# Test: PlaybookPolicyConfig state-aware validation (state=merged)
# =============================================================================


def test_manage_policies_config_models_00300() -> None:
    """
    # Summary

    Verify ``state=merged`` requires a ``name`` on policy entries.

    ## Test

    - Entry without ``name`` and without ``switch`` raises ``ValidationError``
      whose message points to the missing ``name``.

    ## Classes and Methods

    - ``PlaybookPolicyConfig.validate_state_requirements``
    """
    with pytest.raises(ValidationError, match="'name'"):
        PlaybookPolicyConfig.model_validate(
            {"description": "no name"},
            context={"state": "merged"},
        )


def test_manage_policies_config_models_00310() -> None:
    """
    # Summary

    Verify ``state=merged`` accepts a switch-only entry (``name`` is None,
    ``switch`` is present).

    ## Test

    - Switch-only entry validates successfully under ``state=merged``.

    ## Classes and Methods

    - ``PlaybookPolicyConfig.validate_state_requirements``
    """
    with does_not_raise():
        instance = PlaybookPolicyConfig.model_validate(
            {"switch": [{"serial_number": "FDO123"}]},
            context={"state": "merged"},
        )
    assert instance.name is None
    assert instance.switch is not None
    assert instance.switch[0].serial_number == "FDO123"


def test_manage_policies_config_models_00320() -> None:
    """
    # Summary

    Verify ``state=merged`` with a populated ``name`` passes.

    ## Test

    - A policy entry with a template name validates successfully.

    ## Classes and Methods

    - ``PlaybookPolicyConfig.validate_state_requirements``
    """
    with does_not_raise():
        instance = PlaybookPolicyConfig.model_validate(
            {"name": "switch_freeform"},
            context={"state": "merged"},
        )
    assert instance.name == "switch_freeform"


# =============================================================================
# Test: PlaybookPolicyConfig use_desc_as_key handling
# =============================================================================


@pytest.mark.parametrize("state", ["merged", "deleted"])
def test_manage_policies_config_models_00400(state) -> None:
    """
    # Summary

    Verify ``use_desc_as_key=True`` requires a non-empty ``description`` for
    template-name entries in ``merged`` and ``deleted`` states.

    ## Test

    - Missing/empty description raises ``ValidationError`` whose message points
      to ``description``.

    ## Classes and Methods

    - ``PlaybookPolicyConfig.validate_state_requirements``
    """
    with pytest.raises(ValidationError, match="'description'"):
        PlaybookPolicyConfig.model_validate(
            {"name": "switch_freeform"},
            context={"state": state, "use_desc_as_key": True},
        )


def test_manage_policies_config_models_00410() -> None:
    """
    # Summary

    Verify ``use_desc_as_key=True`` is satisfied when description is supplied.

    ## Test

    - Template-name entry with a non-empty description validates successfully.

    ## Classes and Methods

    - ``PlaybookPolicyConfig.validate_state_requirements``
    """
    with does_not_raise():
        instance = PlaybookPolicyConfig.model_validate(
            {"name": "switch_freeform", "description": "MOTD"},
            context={"state": "merged", "use_desc_as_key": True},
        )
    assert instance.description == "MOTD"


def test_manage_policies_config_models_00420() -> None:
    """
    # Summary

    Verify ``use_desc_as_key=True`` does NOT require a description when the
    name is a policy ID (``POLICY-<digits>`` style).

    ## Test

    - Policy ID entry without description passes under ``state=merged`` even
      when ``use_desc_as_key`` is True.

    ## Classes and Methods

    - ``PlaybookPolicyConfig.validate_state_requirements``
    """
    with does_not_raise():
        instance = PlaybookPolicyConfig.model_validate(
            {"name": "POLICY-12345"},
            context={"state": "merged", "use_desc_as_key": True},
        )
    assert instance.name == "POLICY-12345"
    assert instance.description == ""


def test_manage_policies_config_models_00430() -> None:
    """
    # Summary

    Verify ``use_desc_as_key=True`` is ignored for state=gathered.

    ## Test

    - Template-name entry without description under ``state=gathered`` passes
      even when ``use_desc_as_key`` is True.

    ## Classes and Methods

    - ``PlaybookPolicyConfig.validate_state_requirements``
    """
    with does_not_raise():
        instance = PlaybookPolicyConfig.model_validate(
            {"name": "switch_freeform"},
            context={"state": "gathered", "use_desc_as_key": True},
        )
    assert instance.description == ""


def test_manage_policies_config_models_00440() -> None:
    """
    # Summary

    Verify ``use_desc_as_key=False`` (the default) does not require a
    description for template-name entries.

    ## Test

    - Template-name entry without description under ``state=merged`` passes
      when ``use_desc_as_key`` is False.

    ## Classes and Methods

    - ``PlaybookPolicyConfig.validate_state_requirements``
    """
    with does_not_raise():
        instance = PlaybookPolicyConfig.model_validate(
            {"name": "switch_freeform"},
            context={"state": "merged", "use_desc_as_key": False},
        )
    assert instance.description == ""


# =============================================================================
# Test: PlaybookPolicyConfig state=deleted handling
# =============================================================================


def test_manage_policies_config_models_00500() -> None:
    """
    # Summary

    Verify ``state=deleted`` does not require a ``name`` on its own (deleted
    state may target a fabric-wide cleanup with switch-only entries).

    ## Test

    - Empty-name entry passes under ``state=deleted`` so long as
      ``use_desc_as_key`` is not set.

    ## Classes and Methods

    - ``PlaybookPolicyConfig.validate_state_requirements``
    """
    with does_not_raise():
        instance = PlaybookPolicyConfig.model_validate(
            {"switch": [{"serial_number": "FDO123"}]},
            context={"state": "deleted"},
        )
    assert instance.switch is not None


# =============================================================================
# Test: PlaybookPolicyConfig get_argument_spec()
# =============================================================================


def test_manage_policies_config_models_00600() -> None:
    """
    # Summary

    Verify ``get_argument_spec()`` returns the documented argument spec.

    ## Test

    - All expected keys are present.
    - ``fabric_name`` is required and aliased to ``fabric``.
    - ``state`` defaults to ``merged`` with the documented choices.
    - ``deploy`` defaults to ``True`` and ``use_desc_as_key`` defaults to
      ``False``.

    ## Classes and Methods

    - ``PlaybookPolicyConfig.get_argument_spec``
    """
    spec = PlaybookPolicyConfig.get_argument_spec()

    assert set(spec) == {
        "fabric_name",
        "config",
        "use_desc_as_key",
        "deploy",
        "ticket_id",
        "cluster_name",
        "state",
    }
    assert spec["fabric_name"]["required"] is True
    assert spec["fabric_name"]["aliases"] == ["fabric"]
    assert spec["state"]["default"] == "merged"
    assert spec["state"]["choices"] == ["merged", "deleted", "gathered"]
    assert spec["deploy"]["default"] is True
    assert spec["use_desc_as_key"]["default"] is False
    assert spec["config"]["type"] == "list"
    assert spec["config"]["elements"] == "dict"
