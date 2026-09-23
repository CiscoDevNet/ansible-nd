# -*- coding: utf-8 -*-

# Copyright: (c) 2026,  Deeksha Pandey (@deekpand)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for shared manage-fabric model behavior."""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import validate_gathered_filters
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import FabricAiEbgpVxlanModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import FabricAiIbgpVxlanModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import FabricEbgpModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import FabricExternalConnectivityModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import FabricIbgpModel


@pytest.mark.parametrize(
    "model_class",
    [
        FabricExternalConnectivityModel,
        FabricEbgpModel,
        FabricIbgpModel,
        FabricAiEbgpVxlanModel,
        FabricAiIbgpVxlanModel,
    ],
    ids=[
        "external",
        "ebgp",
        "ibgp",
        "ai_ebgp",
        "ai_ibgp",
    ],
)
def test_mutating_fabric_states_require_config(model_class) -> None:
    """Verify every fabric model requires config only for mutating states."""
    assert model_class.get_required_if() == [
        ("state", "merged", ["config"]),
        ("state", "replaced", ["config"]),
        ("state", "overridden", ["config"]),
        ("state", "deleted", ["config"]),
    ]


@pytest.mark.parametrize(
    "model_class",
    [
        FabricExternalConnectivityModel,
        FabricEbgpModel,
        FabricIbgpModel,
        FabricAiEbgpVxlanModel,
        FabricAiIbgpVxlanModel,
    ],
    ids=["external", "ebgp", "ibgp", "ai_ebgp", "ai_ibgp"],
)
@pytest.mark.parametrize(
    "filter_item",
    [
        {"fabric_name": "invalid/name"},
        {"license_tier": "invalid"},
        {"alert_suspend": "invalid"},
    ],
    ids=["fabric_name", "license_tier", "alert_suspend"],
)
def test_invalid_supported_gathered_filter_values_are_rejected(model_class, filter_item) -> None:
    """Verify supported properties still receive Pydantic validation before queries."""
    with pytest.raises(ValueError):
        validate_gathered_filters(
            filters=[filter_item],
            normalize_filter=model_class.normalize_gathered_filter,
            supported_properties=model_class.gathered_filter_properties,
        )


@pytest.mark.parametrize(
    "model_class",
    [
        FabricExternalConnectivityModel,
        FabricEbgpModel,
        FabricIbgpModel,
        FabricAiEbgpVxlanModel,
        FabricAiIbgpVxlanModel,
    ],
    ids=["external", "ebgp", "ibgp", "ai_ebgp", "ai_ibgp"],
)
def test_gathered_filter_values_are_normalized(model_class) -> None:
    """Verify canonical values, including boolean false, survive partial validation."""
    assert model_class.normalize_gathered_filter(
        {
            "fabric_name": " valid-fabric ",
            "license_tier": "premier",
            "security_domain": " production ",
            "alert_suspend": "disabled",
            "telemetry_collection": False,
        }
    ) == {
        "fabric_name": "valid-fabric",
        "license_tier": "premier",
        "security_domain": "production",
        "alert_suspend": "disabled",
        "telemetry_collection": False,
    }
