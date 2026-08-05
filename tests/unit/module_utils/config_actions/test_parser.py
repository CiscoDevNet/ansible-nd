# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Unit tests for config_actions.parser.
"""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.parser import parse_config_actions
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import FABRIC_CONFIG_ACTIONS, RESOURCE_CONFIG_ACTIONS


def test_config_actions_parser_00000() -> None:
    """
    # Summary

    Verify omitted config_actions applies policy defaults.

    ## Raises

    None
    """
    actions = parse_config_actions(params={}, raw_args={}, policy=RESOURCE_CONFIG_ACTIONS)
    assert actions.provided is False
    assert actions.deploy is True
    assert actions.type == "switch"
    assert actions.save is False


def test_config_actions_parser_00010() -> None:
    """
    # Summary

    Verify explicit empty config_actions is rejected before defaults are applied.

    ## Raises

    None
    """
    with pytest.raises(ValueError, match="config_actions cannot be empty"):
        parse_config_actions(params={"config_actions": {"deploy": True, "type": "switch"}}, raw_args={"config_actions": {}}, policy=RESOURCE_CONFIG_ACTIONS)


def test_config_actions_parser_00020() -> None:
    """
    # Summary

    Verify explicit false values are preserved.

    ## Raises

    None
    """
    actions = parse_config_actions(
        params={"config_actions": {"deploy": False, "type": "resource"}},
        raw_args={"config_actions": {"deploy": False, "type": "resource"}},
        policy=RESOURCE_CONFIG_ACTIONS,
    )
    assert actions.provided is True
    assert actions.deploy is False
    assert actions.type == "resource"
    assert actions.explicit_options == frozenset({"deploy", "type"})


def test_config_actions_parser_00030() -> None:
    """
    # Summary

    Verify resource deploy is accepted only in resource mode.

    ## Raises

    None
    """
    params = {
        "config_actions": {"deploy": True, "type": "resource"},
        "config": [{"name": "BLUE"}, {"name": "GREEN", "deploy": False}],
    }
    raw_args = {
        "config_actions": {"deploy": True, "type": "resource"},
        "config": [{"name": "BLUE"}, {"name": "GREEN", "deploy": False}],
    }
    actions = parse_config_actions(params=params, raw_args=raw_args, policy=RESOURCE_CONFIG_ACTIONS)
    assert actions.resource_deploy_provided is True
    assert actions.resource_deploy_indexes == (1,)
    assert actions.resource_deploy_enabled(0) is True
    assert actions.resource_deploy_enabled(1) is False


def test_config_actions_parser_00040() -> None:
    """
    # Summary

    Verify item deploy is rejected when config_actions.type is switch.

    ## Raises

    None
    """
    params = {
        "config_actions": {"deploy": True, "type": "switch"},
        "config": [{"name": "BLUE", "deploy": False}],
    }
    raw_args = {
        "config_actions": {"deploy": True, "type": "switch"},
        "config": [{"name": "BLUE", "deploy": False}],
    }
    with pytest.raises(ValueError, match="allowed only when config_actions.type='resource'"):
        parse_config_actions(params=params, raw_args=raw_args, policy=RESOURCE_CONFIG_ACTIONS)


def test_config_actions_parser_00050() -> None:
    """
    # Summary

    Verify deploy requiring save is enforced by policy.

    ## Raises

    None
    """
    with pytest.raises(ValueError, match="deploy=true requires config_actions.save=true"):
        parse_config_actions(
            params={"config_actions": {"save": False, "deploy": True, "type": "switch"}},
            raw_args={"config_actions": {"save": False, "deploy": True, "type": "switch"}},
            policy=FABRIC_CONFIG_ACTIONS,
        )


def test_config_actions_parser_00060() -> None:
    """
    # Summary

    Verify omitted write actions are disabled in gathered state.

    ## Raises

    None
    """
    actions = parse_config_actions(params={}, raw_args={}, policy=RESOURCE_CONFIG_ACTIONS, state="gathered")
    assert actions.save is False
    assert actions.deploy is False
    assert actions.type == "switch"


def test_config_actions_parser_00070() -> None:
    """
    # Summary

    Verify explicitly enabled write actions are rejected in gathered state.

    ## Raises

    None
    """
    with pytest.raises(ValueError, match="not allowed for state='gathered'"):
        parse_config_actions(
            params={"config_actions": {"deploy": True, "type": "switch"}},
            raw_args={"config_actions": {"deploy": True}},
            policy=RESOURCE_CONFIG_ACTIONS,
            state="gathered",
        )
