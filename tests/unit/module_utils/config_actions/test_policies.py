# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Unit tests for config action policy declarations.
"""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import (
    FABRIC_CONFIG_ACTIONS,
    INTERFACE_CONFIG_ACTIONS,
    RESOURCE_CONFIG_ACTIONS,
    SWITCH_CONFIG_ACTIONS,
    VPC_PAIR_CONFIG_ACTIONS,
)


def test_config_actions_policies_00000() -> None:
    """
    # Summary

    Verify policy defaults preserve current module-family behavior.

    ## Raises

    None
    """
    assert INTERFACE_CONFIG_ACTIONS.defaults.deploy is True
    assert INTERFACE_CONFIG_ACTIONS.supported == frozenset({"deploy"})

    assert FABRIC_CONFIG_ACTIONS.defaults.save is False
    assert FABRIC_CONFIG_ACTIONS.defaults.deploy is False
    assert FABRIC_CONFIG_ACTIONS.allowed_types == frozenset({"switch", "global"})

    assert SWITCH_CONFIG_ACTIONS.defaults.save is True
    assert SWITCH_CONFIG_ACTIONS.defaults.deploy is True
    assert SWITCH_CONFIG_ACTIONS.allowed_types == frozenset({"switch", "global"})

    assert VPC_PAIR_CONFIG_ACTIONS.defaults.save is True
    assert VPC_PAIR_CONFIG_ACTIONS.defaults.deploy is True

    assert RESOURCE_CONFIG_ACTIONS.supported == frozenset({"deploy", "type"})
    assert RESOURCE_CONFIG_ACTIONS.allowed_types == frozenset({"switch", "resource"})
    assert RESOURCE_CONFIG_ACTIONS.resource_interaction == "type_resource_gated"
