# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for AI/ML fabric models."""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import FabricTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import (
    FabricAiEbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import (
    FabricAiIbgpVxlanModel,
)


def test_manage_fabric_ai_vxlan_00010() -> None:
    """
    # Summary

    Verify the AI eBGP fabric model inherits the standard fabric base behavior.
    """
    model = FabricAiEbgpVxlanModel(
        fabric_name="ai_ebgp_fabric",
        management={"type": "aimlVxlanEbgp", "bgp_asn": "65001"},
    )

    assert model._fabric_type == FabricTypeEnum.AIML_VXLAN_EBGP
    assert model.management is not None
    assert model.management.type == "aimlVxlanEbgp"
    assert model.management.name == "ai_ebgp_fabric"
    assert model.management.site_id == "65001"
    assert model.management.aiml_qos is True
    assert model.telemetry_collection is False


def test_manage_fabric_ai_vxlan_00020() -> None:
    """
    # Summary

    Verify the AI iBGP fabric model inherits the standard iBGP fields and validation.
    """
    model = FabricAiIbgpVxlanModel(
        fabric_name="ai_ibgp_fabric",
        management={"type": "aimlVxlanIbgp", "bgp_asn": "65002", "enable_dpu_pinning": True},
    )

    assert model._fabric_type == FabricTypeEnum.AIML_VXLAN_IBGP
    assert model.management is not None
    assert model.management.type == "aimlVxlanIbgp"
    assert model.management.name == "ai_ibgp_fabric"
    assert model.management.site_id == "65002"
    assert model.management.enable_dpu_pinning is True
    assert model.management.aiml_qos is True
    assert model.telemetry_collection is False


def test_manage_fabric_ai_vxlan_00030() -> None:
    """
    # Summary

    Verify aiml_qos is not exposed in AI model argument specs.
    """

    ebgp_spec = FabricAiEbgpVxlanModel.get_argument_spec()
    ibgp_spec = FabricAiIbgpVxlanModel.get_argument_spec()

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

    assert contains_option(ebgp_spec, "aiml_qos") is False
    assert contains_option(ibgp_spec, "aiml_qos") is False
