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
