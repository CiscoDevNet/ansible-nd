# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Regression tests for typed custom-template reconciliation."""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.config_models import (
    InterfaceGroupConfigModel,
    InterfaceGroupModuleConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.validators import (
    InterfaceGroupValidators,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection


def _comparison_models(state: str, current: dict, requested: dict) -> tuple[InterfaceGroupConfigModel, InterfaceGroupConfigModel]:
    existing = InterfaceGroupConfigModel.from_response(
        {
            "interfaceGroupName": "typed-template-group",
            "type": "ethernet",
            "policyDetails": {
                "policyType": "userDefinedSharedTrunk",
                "templateName": "custom-template",
                "templateConfig": current,
            },
        }
    )
    proposed = InterfaceGroupModuleConfigModel.model_validate(
        {
            "fabric_name": "test-fabric",
            "state": state,
            "config": [
                {
                    "interface_group_name": "typed-template-group",
                    "type": "ethernetCustom" if state != "merged" else None,
                    "template_name": "custom-template" if state != "merged" else None,
                    "template_config": requested,
                }
            ],
        }
    ).config[0]
    return existing, proposed


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize(
    ("current", "requested"),
    [
        ({"DESC": "1"}, {"DESC": "001"}),
        ({"DESC": "TRUE"}, {"DESC": "true"}),
    ],
)
def test_string_parameters_preserve_exact_text(state: str, current: dict, requested: dict) -> None:
    """A string template input must trigger an update when its text changes."""
    existing, proposed = _comparison_models(state, current, requested)
    proposed.set_template_parameter_types([{"name": "DESC", "parameterType": "string"}])
    assert existing.get_diff(proposed, exclude_unset=state == "merged") is False


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
def test_declared_numeric_boolean_parameters_keep_echo_normalization(state: str) -> None:
    """Quoted numeric/boolean inputs match typed controller echoes."""
    existing, proposed = _comparison_models(state, {"VLAN": "1", "ENABLED": "TRUE"}, {"VLAN": "001", "ENABLED": "true"})
    proposed.set_template_parameter_types(
        [
            {"name": "VLAN", "parameterType": "Integer"},
            {"name": "ENABLED", "parameterType": "Boolean"},
        ]
    )
    assert existing.get_diff(proposed, exclude_unset=state == "merged") is True


def test_unknown_parameter_type_does_not_coerce_string_text() -> None:
    """Absent schema metadata must not silently equate distinct strings."""
    existing, proposed = _comparison_models("merged", {"DESC": "1"}, {"DESC": "001"})
    assert existing.get_diff(proposed, exclude_unset=True) is False


def test_legacy_schema_free_filter_keeps_prior_echo_comparison() -> None:
    """Gathered/validator callers without a schema keep their old matching behavior."""
    expected = {"VLAN": "001", "FLAG": "true", "NESTED": {"VALUES": ["001", "true"]}}
    actual = {"VLAN": "1", "FLAG": "TRUE", "NESTED": {"VALUES": ["1", "TRUE"]}}

    assert InterfaceGroupValidators.template_config_is_subset(expected, actual) is True
    assert InterfaceGroupValidators.template_config_is_subset(expected, actual, {}) is False


def test_template_parameter_types_are_comparison_only() -> None:
    """The schema map must neither leak to payloads nor replace input values."""
    existing, proposed = _comparison_models("replaced", {"DESC": "1"}, {"DESC": "001"})
    proposed.set_template_parameter_types([{"name": "DESC", "parameterType": "string"}])
    assert existing.get_diff(proposed, exclude_unset=False) is False
    payload = InterfaceGroupValidators.to_wire_group(proposed.to_payload())
    assert payload["policyDetails"]["templateConfig"] == {"DESC": "001"}
    assert "template_parameter_types" not in str(payload)


@pytest.mark.parametrize("supplied_field", ["template_name", "template_config"])
@pytest.mark.parametrize("parameter_type", ["String", None])
def test_merge_replaces_template_schema_including_empty_metadata(supplied_field: str, parameter_type: str | None) -> None:
    """A freshly validated template must not inherit a previous parameter type."""
    existing = _comparison_models("merged", {"DESC": "true"}, {})[0]
    existing.set_template_parameter_types([{"name": "DESC", "parameterType": "Boolean"}, {"name": "OLD", "parameterType": "Integer"}])
    proposed = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": existing.interface_group_name,
            supplied_field: "new-template" if supplied_field == "template_name" else {"DESC": "true"},
        }
    )
    proposed.set_template_parameter_types([{"name": "DESC", "parameterType": parameter_type}] if parameter_type else [])

    merged = NDConfigCollection(InterfaceGroupConfigModel, [existing]).merge(proposed)

    assert merged._template_parameter_types == ({"DESC": "string"} if parameter_type else {})
    assert InterfaceGroupValidators.template_config_is_subset({"DESC": "true"}, {"DESC": "TRUE"}, merged._template_parameter_types) is False


@pytest.mark.parametrize(
    "update",
    [
        {"networks": ["NETWORK-A"]},
        {"switch_interfaces": [{"switch_id": "SN1", "interface_names": ["Ethernet1/10"]}]},
    ],
)
def test_membership_only_merge_preserves_known_template_types(update: dict) -> None:
    """A proposal with no template fields must not erase existing schema knowledge."""
    existing = _comparison_models("merged", {"ENABLED": "true"}, {})[0]
    existing.set_template_parameter_types([{"name": "ENABLED", "parameterType": "Boolean"}])
    proposed = InterfaceGroupConfigModel.from_config({"interface_group_name": existing.interface_group_name, **update})

    merged = NDConfigCollection(InterfaceGroupConfigModel, [existing]).merge(proposed)

    assert merged._template_parameter_types == {"ENABLED": "boolean"}
    assert merged.template_config == {"ENABLED": "true"}
    assert InterfaceGroupValidators.template_config_is_subset({"ENABLED": "true"}, {"ENABLED": "TRUE"}, merged._template_parameter_types) is True


def test_merged_schema_has_independent_ownership_and_stays_out_of_payload() -> None:
    """Retain input values on the wire while keeping copied schema metadata private."""
    existing, proposed = _comparison_models("merged", {"ENABLED": "TRUE"}, {"ENABLED": "true"})
    proposed.set_template_parameter_types([{"name": "ENABLED", "parameterType": "Boolean"}])

    merged = NDConfigCollection(InterfaceGroupConfigModel, [existing]).merge(proposed)
    proposed._template_parameter_types["ENABLED"] = "string"

    assert merged._template_parameter_types == {"ENABLED": "boolean"}
    assert merged.template_config == {"ENABLED": "true"}
    payload = InterfaceGroupValidators.to_wire_group(merged.to_payload())
    assert payload["policyDetails"]["templateConfig"] == {"ENABLED": "true"}
    assert "template_parameter_types" not in str(payload)
