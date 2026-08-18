# -*- coding: utf-8 -*-

# Copyright: (c) 2026,  Deeksha Pandey (@deekpand)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for shared manage-fabric model behavior."""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import (
    FabricAiEbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import (
    FabricAiIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import (
    FabricEbgpModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import (
    FabricExternalConnectivityModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import (
    FabricIbgpModel,
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
