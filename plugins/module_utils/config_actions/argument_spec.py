# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Argument-spec builder for repository-wide config action policies.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import LEGACY_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActionsPolicy

_TYPE_CHOICE_ORDER = ("resource", "switch", "global")


def _select_options(options: dict[str, Any], include: Iterable[str] | None) -> dict[str, Any]:
    """
    # Summary

    Return a copy of `options` filtered to `include`.

    ## Raises

    ### ValueError

    - If `include` contains an unknown option.
    """
    if include is None:
        return dict(options)
    include_set = set(include)
    unknown = include_set - options.keys()
    if unknown:
        raise ValueError(f"Unknown option name(s) in include: {', '.join(sorted(unknown))}. Valid options: {', '.join(sorted(options))}.")
    return {key: value for key, value in options.items() if key in include_set}


def _option_with_default(option_type: str, default: Any) -> dict[str, Any]:
    """
    # Summary

    Build an Ansible option spec and include `default` only when the policy defines one.

    ## Raises

    None
    """
    spec: dict[str, Any] = {"type": option_type}
    if default is not None:
        spec["default"] = default
    return spec


def config_actions_spec(policy: ConfigActionsPolicy = LEGACY_CONFIG_ACTIONS, include: Iterable[str] | None = None) -> dict[str, Any]:
    """
    # Summary

    Return an Ansible `config_actions` argument spec for `policy`.

    ## Raises

    ### ValueError

    - If `include` or the policy references an unsupported option.
    """
    options: dict[str, Any] = {}
    if "save" in policy.supported:
        options["save"] = _option_with_default("bool", policy.defaults.save)
    if "deploy" in policy.supported:
        options["deploy"] = _option_with_default("bool", policy.defaults.deploy)
    if "type" in policy.supported:
        option = _option_with_default("str", policy.defaults.type)
        option["choices"] = [choice for choice in _TYPE_CHOICE_ORDER if choice in policy.allowed_types]
        options["type"] = option

    known = {"save", "deploy", "type"}
    unknown_supported = policy.supported - known
    if unknown_supported:
        raise ValueError(f"Unknown config_actions policy option(s): {', '.join(sorted(unknown_supported))}.")

    return {"config_actions": {"type": "dict", "options": _select_options(options, include)}}
