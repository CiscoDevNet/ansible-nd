"""Fabric models must build ``config_actions`` from the shared policy fragment.

Mirrors ``tests/unit/modules/test_nd_interface_deploy_default.py`` for the fabric family.
The policy is the single source of truth for validation, so an inline copy in the argument
spec can silently drift from what ``parse_config_actions`` actually enforces.
"""

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.argument_spec import config_actions_spec
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import FABRIC_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import FabricAiEbgpVxlanModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import FabricAiIbgpVxlanModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import FabricEbgpModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import FabricExternalConnectivityModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import FabricIbgpModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_vxlan import FabricGroupVxlanModel

FABRIC_MODELS = [
    FabricIbgpModel,
    FabricEbgpModel,
    FabricAiIbgpVxlanModel,
    FabricAiEbgpVxlanModel,
    FabricExternalConnectivityModel,
    FabricGroupVxlanModel,
]


@pytest.mark.parametrize("model_cls", FABRIC_MODELS, ids=lambda c: c.__name__)
def test_config_actions_uses_shared_fragment(model_cls):
    expected = config_actions_spec(FABRIC_CONFIG_ACTIONS)["config_actions"]
    assert model_cls.get_argument_spec()["config_actions"] == expected


@pytest.mark.parametrize("model_cls", FABRIC_MODELS, ids=lambda c: c.__name__)
def test_config_actions_matches_policy_defaults(model_cls):
    """The argspec defaults must agree with the policy that validation enforces."""
    options = model_cls.get_argument_spec()["config_actions"]["options"]
    assert options["save"]["default"] == FABRIC_CONFIG_ACTIONS.defaults.save
    assert options["deploy"]["default"] == FABRIC_CONFIG_ACTIONS.defaults.deploy
    assert options["type"]["default"] == FABRIC_CONFIG_ACTIONS.defaults.type
    assert set(options["type"]["choices"]) == set(FABRIC_CONFIG_ACTIONS.allowed_types)
