# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Unit tests for config_actions.validation.
"""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import FABRIC_CONFIG_ACTIONS, RESOURCE_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActions
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.validation import reject_empty_config_actions, validate_config_actions


def test_config_actions_validation_00000() -> None:
    """
    # Summary

    Verify explicit empty config_actions is rejected.

    ## Raises

    None
    """
    with pytest.raises(ValueError, match="config_actions cannot be empty"):
        reject_empty_config_actions({})


def test_config_actions_validation_00010() -> None:
    """
    # Summary

    Verify unsupported fields are rejected.

    ## Raises

    None
    """
    actions = ConfigActions(save=True, deploy=True, type="switch", provided=True, explicit_options=frozenset({"save"}))
    with pytest.raises(ValueError, match="Unsupported config_actions option"):
        validate_config_actions(actions, RESOURCE_CONFIG_ACTIONS)


def test_config_actions_validation_00020() -> None:
    """
    # Summary

    Verify unsupported deploy type is rejected.

    ## Raises

    None
    """
    actions = ConfigActions(save=False, deploy=True, type="global", provided=True, explicit_options=frozenset({"type"}))
    with pytest.raises(ValueError, match="config_actions.type must be one of"):
        validate_config_actions(actions, RESOURCE_CONFIG_ACTIONS)


def test_config_actions_validation_00030() -> None:
    """
    # Summary

    Verify deploy requiring save is policy-specific and enforced for fabric actions.

    ## Raises

    None
    """
    actions = ConfigActions(save=False, deploy=True, type="switch", provided=True, explicit_options=frozenset({"save", "deploy"}))
    with pytest.raises(ValueError, match="deploy=true requires config_actions.save=true"):
        validate_config_actions(actions, FABRIC_CONFIG_ACTIONS)


def test_config_actions_validation_00040() -> None:
    """
    # Summary

    Verify gathered state rejects explicitly enabled write actions.

    ## Raises

    None
    """
    actions = ConfigActions(save=False, deploy=True, type="switch", provided=True, explicit_options=frozenset({"deploy"}))
    with pytest.raises(ValueError, match="not allowed for state='gathered'"):
        validate_config_actions(actions, RESOURCE_CONFIG_ACTIONS, state="gathered")


def test_config_actions_validation_00050() -> None:
    """
    # Summary

    Verify resource item deploy is rejected outside resource mode.

    ## Raises

    None
    """
    actions = ConfigActions(
        save=False,
        deploy=True,
        type="switch",
        provided=True,
        explicit_options=frozenset({"type"}),
        resource_deploy_provided=True,
        resource_deploy_indexes=(0,),
        resource_deploy_overrides=(True,),
    )
    with pytest.raises(ValueError, match="allowed only when config_actions.type='resource'"):
        validate_config_actions(actions, RESOURCE_CONFIG_ACTIONS)


def test_config_actions_validation_00060() -> None:
    """
    # Summary

    Verify resource item deploy is accepted in resource mode.

    ## Raises

    None
    """
    actions = ConfigActions(
        save=False,
        deploy=True,
        type="resource",
        provided=True,
        explicit_options=frozenset({"type"}),
        resource_deploy_provided=True,
        resource_deploy_indexes=(0,),
        resource_deploy_overrides=(True,),
    )
    validate_config_actions(actions, RESOURCE_CONFIG_ACTIONS)
