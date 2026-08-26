# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for Routed and AI/ML Routed fabric models."""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

import pytest
from pydantic import ValidationError

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import FabricTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_routed import (
    FabricRoutedModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_routed import (
    FabricAiRoutedModel,
)


def test_manage_fabric_routed_00010() -> None:
    """
    # Summary

    Verify the Routed fabric model applies the routed type discriminator and
    propagates the fabric name and site_id defaults.
    """
    model = FabricRoutedModel(
        fabric_name="routed_fabric",
        management={"type": "routed", "bgp_asn": "65001"},
    )

    assert model._fabric_type == FabricTypeEnum.ROUTED
    assert model.management is not None
    assert model.management.type == FabricTypeEnum.ROUTED
    assert model.management.name == "routed_fabric"
    assert model.management.site_id == "65001"
    assert model.telemetry_collection is False


def test_manage_fabric_routed_00020() -> None:
    """
    # Summary

    Verify the AI Routed fabric model inherits the routed base behavior and
    forces aiml_qos to True.
    """
    model = FabricAiRoutedModel(
        fabric_name="ai_routed_fabric",
        management={"type": "aimlRouted", "bgp_asn": "65002"},
    )

    assert model._fabric_type == FabricTypeEnum.AIML_ROUTED
    assert model.management is not None
    assert model.management.type == "aimlRouted"
    assert model.management.name == "ai_routed_fabric"
    assert model.management.site_id == "65002"
    assert model.management.aiml_qos is True
    assert model.telemetry_collection is False


def test_manage_fabric_routed_00030() -> None:
    """
    # Summary

    Verify aiml_qos is not exposed in the AI Routed model argument spec.
    """
    spec = FabricAiRoutedModel.get_argument_spec()

    def contains_option(node: dict, key: str) -> bool:
        if not isinstance(node, dict):
            return False
        options = node.get("options")
        if isinstance(options, dict):
            if key in options:
                return True
            for child in options.values():
                if isinstance(child, dict) and contains_option(child, key):
                    return True
        elements = node.get("elements")
        if isinstance(elements, dict) and contains_option(elements, key):
            return True
        return False

    assert contains_option(spec, "aiml_qos") is False


def test_manage_fabric_routed_00040() -> None:
    """
    # Summary

    Verify aiml_qos is locked to True on the AI Routed model and cannot be
    overridden to a non-True value, including via a wire payload.
    """
    with pytest.raises(ValidationError):
        FabricAiRoutedModel(
            fabric_name="ai_routed_fabric",
            management={"type": "aimlRouted", "bgp_asn": "65002", "aiml_qos": False},
        )

    with pytest.raises(ValidationError):
        FabricAiRoutedModel(
            fabric_name="ai_routed_fabric",
            management={"type": "aimlRouted", "bgp_asn": "65002", "aimlQos": False},
        )
