# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `MultiClusterFabricGroupVxlanModel`.

Tests the OneManage multi-cluster VXLAN fabric group model: the
``multiClusterFabricGroup`` category discriminator, reuse of the shared VXLAN
management settings, fabric-name propagation into the management model, payload
generation, and the argument spec.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_multi_cluster_fabric_group_vxlan import (
    MultiClusterFabricGroupVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_vxlan import (
    VxlanFabricGroupManagementModel,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise


def test_mcfg_vxlan_defaults() -> None:
    """The model defaults to the multiClusterFabricGroup category and vxlan management type."""
    with does_not_raise():
        model = MultiClusterFabricGroupVxlanModel(fabric_name="my_mcfg")
    assert model.category == "multiClusterFabricGroup"
    assert model.management.type == "vxlan"
    assert isinstance(model.management, VxlanFabricGroupManagementModel)


def test_mcfg_vxlan_identifier() -> None:
    """The fabric group is identified by its fabric_name (single identifier)."""
    model = MultiClusterFabricGroupVxlanModel(fabric_name="my_mcfg")
    assert MultiClusterFabricGroupVxlanModel.identifiers == ["fabric_name"]
    assert MultiClusterFabricGroupVxlanModel.identifier_strategy == "single"
    assert model.get_identifier_value() == "my_mcfg"


def test_mcfg_vxlan_name_propagation() -> None:
    """fabric_name is propagated into the management model so payloads carry it."""
    model = MultiClusterFabricGroupVxlanModel(fabric_name="my_mcfg")
    assert model.management.name == "my_mcfg"


def test_mcfg_vxlan_reuses_management_settings() -> None:
    """Management settings are the shared fabricGroupTypeVxlan model (identical defaults)."""
    model = MultiClusterFabricGroupVxlanModel(
        fabric_name="my_mcfg",
        management={"l2_vni_range": "40000-49000", "anycast_gateway_mac": "2020.0000.00bb"},
    )
    assert model.management.l2_vni_range == "40000-49000"
    assert model.management.anycast_gateway_mac == "2020.0000.00bb"
    # Untouched settings retain their shared defaults.
    assert model.management.l3_vni_range == "50000-59000"


def test_mcfg_vxlan_to_payload_category() -> None:
    """to_payload carries the multiClusterFabricGroup category and nested management."""
    model = MultiClusterFabricGroupVxlanModel(fabric_name="my_mcfg")
    payload = model.to_payload()
    assert payload["category"] == "multiClusterFabricGroup"
    assert isinstance(payload["management"], dict)
    assert payload["management"]["type"] == "vxlan"


def test_mcfg_vxlan_invalid_mac_rejected() -> None:
    """An invalid anycast gateway MAC is rejected by the shared validator."""
    with pytest.raises(Exception, match="MAC address"):
        MultiClusterFabricGroupVxlanModel(fabric_name="my_mcfg", management={"anycast_gateway_mac": "not-a-mac"})


def test_mcfg_vxlan_argument_spec() -> None:
    """get_argument_spec contributes config, state, and config_actions with management options."""
    spec = MultiClusterFabricGroupVxlanModel.get_argument_spec()
    assert spec["state"]["choices"] == ["merged", "replaced", "deleted", "overridden"]
    assert spec["config"]["type"] == "list"
    # Nested management options are auto-generated from the shared settings model.
    mgmt = spec["config"]["options"]["management"]["options"]
    assert "l2_vni_range" in mgmt
    assert "anycast_gateway_mac" in mgmt
    # Single-value Literal fields are excluded from the argspec.
    assert "category" not in spec["config"]["options"]
    assert "type" not in mgmt
    # Shared config_actions controls.
    assert spec["config_actions"]["options"]["save"]["type"] == "bool"
    assert spec["config_actions"]["options"]["deploy"]["type"] == "bool"
    assert spec["config_actions"]["options"]["type"]["choices"] == ["switch", "global"]
