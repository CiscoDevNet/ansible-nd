# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Unit tests for config_actions.argument_spec.
"""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.argument_spec import config_actions_spec
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import (
    FABRIC_CONFIG_ACTIONS,
    INTERFACE_CONFIG_ACTIONS,
    RESOURCE_CONFIG_ACTIONS,
    SWITCH_CONFIG_ACTIONS,
)


def test_config_actions_argument_spec_00000() -> None:
    """
    # Summary

    Verify interface policy exposes only deploy with its compatibility default.

    ## Raises

    None
    """
    assert config_actions_spec(INTERFACE_CONFIG_ACTIONS) == {
        "config_actions": {
            "type": "dict",
            "options": {
                "deploy": {"type": "bool", "default": True},
            },
        },
    }


def test_config_actions_argument_spec_00010() -> None:
    """
    # Summary

    Verify fabric policy preserves fabric defaults and switch/global choices.

    ## Raises

    None
    """
    options = config_actions_spec(FABRIC_CONFIG_ACTIONS)["config_actions"]["options"]
    assert options["save"] == {"type": "bool", "default": False}
    assert options["deploy"] == {"type": "bool", "default": False}
    assert options["type"] == {"type": "str", "default": "switch", "choices": ["switch", "global"]}


def test_config_actions_argument_spec_00020() -> None:
    """
    # Summary

    Verify switch policy preserves switch manager defaults.

    ## Raises

    None
    """
    options = config_actions_spec(SWITCH_CONFIG_ACTIONS)["config_actions"]["options"]
    assert options["save"]["default"] is True
    assert options["deploy"]["default"] is True
    assert options["type"]["default"] == "switch"
    assert options["type"]["choices"] == ["switch", "global"]


def test_config_actions_argument_spec_00030() -> None:
    """
    # Summary

    Verify resource policy exposes deploy and type only.

    ## Raises

    None
    """
    options = config_actions_spec(RESOURCE_CONFIG_ACTIONS)["config_actions"]["options"]
    assert set(options) == {"deploy", "type"}
    assert options["deploy"] == {"type": "bool", "default": True}
    assert options["type"] == {"type": "str", "default": "switch", "choices": ["resource", "switch"]}


def test_config_actions_argument_spec_00040() -> None:
    """
    # Summary

    Verify include filters policy options and rejects unknown names.

    ## Raises

    None
    """
    assert config_actions_spec(SWITCH_CONFIG_ACTIONS, include=("deploy",)) == {
        "config_actions": {
            "type": "dict",
            "options": {
                "deploy": {"type": "bool", "default": True},
            },
        },
    }
    with pytest.raises(ValueError, match="Unknown option name"):
        config_actions_spec(SWITCH_CONFIG_ACTIONS, include=("bogus",))
