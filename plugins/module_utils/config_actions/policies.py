# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Central config action policies for module families.
"""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import (
    ConfigActionsDefaults,
    ConfigActionsPolicy,
)

INTERFACE_CONFIG_ACTIONS = ConfigActionsPolicy(
    name="interface",
    supported=frozenset({"deploy"}),
    defaults=ConfigActionsDefaults(deploy=True),
    allowed_types=frozenset(),
    deploy_requires_save=False,
    resource_interaction="none",
)

FABRIC_CONFIG_ACTIONS = ConfigActionsPolicy(
    name="fabric",
    supported=frozenset({"save", "deploy", "type"}),
    defaults=ConfigActionsDefaults(save=False, deploy=False, type="switch"),
    allowed_types=frozenset({"switch", "global"}),
    deploy_requires_save=True,
    resource_interaction="none",
)

SWITCH_CONFIG_ACTIONS = ConfigActionsPolicy(
    name="switch",
    supported=frozenset({"save", "deploy", "type"}),
    defaults=ConfigActionsDefaults(save=True, deploy=True, type="switch"),
    allowed_types=frozenset({"switch", "global"}),
    deploy_requires_save=True,
    resource_interaction="none",
)

VPC_PAIR_CONFIG_ACTIONS = ConfigActionsPolicy(
    name="vpc_pair",
    supported=frozenset({"save", "deploy", "type"}),
    defaults=ConfigActionsDefaults(save=True, deploy=True, type="switch"),
    allowed_types=frozenset({"switch", "global"}),
    deploy_requires_save=True,
    resource_interaction="none",
)

RESOURCE_CONFIG_ACTIONS = ConfigActionsPolicy(
    name="resource",
    supported=frozenset({"deploy", "type"}),
    defaults=ConfigActionsDefaults(deploy=True, type="switch"),
    allowed_types=frozenset({"switch", "resource"}),
    deploy_requires_save=False,
    resource_interaction="type_resource_gated",
)

LEGACY_CONFIG_ACTIONS = ConfigActionsPolicy(
    name="legacy",
    supported=frozenset({"save", "deploy", "type"}),
    defaults=ConfigActionsDefaults(save=True, deploy=True, type="switch"),
    allowed_types=frozenset({"resource", "switch", "global"}),
    deploy_requires_save=False,
    resource_interaction="none",
)
