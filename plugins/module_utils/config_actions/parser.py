# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Parser for converting module parameters into normalized config action intent.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActions, ConfigActionsPolicy
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.validation import reject_empty_config_actions, validate_config_actions


def _as_mapping(value: object) -> Mapping[str, Any]:
    """
    # Summary

    Return `value` as a mapping when possible, otherwise an empty mapping.

    ## Raises

    None
    """
    return value if isinstance(value, Mapping) else {}


def _bool_value(name: str, value: object) -> bool:
    """
    # Summary

    Return a normalized bool value.

    ## Raises

    ### ValueError

    - If `value` is not a bool.
    """
    if isinstance(value, bool):
        return value
    raise ValueError(f"{name} must be a boolean.")


def _raw_resource_deploy_indexes(raw_args: Mapping[str, Any], policy: ConfigActionsPolicy) -> set[int]:
    """
    # Summary

    Return indexes where the raw user config explicitly supplied resource-level deploy.

    ## Raises

    None
    """
    indexes: set[int] = set()
    raw_config = raw_args.get(policy.config_key)
    if not isinstance(raw_config, list):
        return indexes
    for index, item in enumerate(raw_config):
        if isinstance(item, Mapping) and policy.resource_deploy_key in item:
            indexes.add(index)
    return indexes


def _resource_deploy_overrides(params: Mapping[str, Any], raw_args: Mapping[str, Any], policy: ConfigActionsPolicy) -> tuple[bool | None, ...]:
    """
    # Summary

    Return explicit per-resource deploy overrides aligned to `params[policy.config_key]`.

    ## Raises

    ### ValueError

    - If an explicit resource deploy value is not a bool.
    """
    config = params.get(policy.config_key) or []
    if not isinstance(config, list):
        return ()

    raw_indexes = _raw_resource_deploy_indexes(raw_args, policy)
    fallback_to_params = policy.config_key not in raw_args
    overrides: list[bool | None] = []

    for index, item in enumerate(config):
        explicit = index in raw_indexes
        if fallback_to_params and isinstance(item, Mapping) and policy.resource_deploy_key in item:
            explicit = True

        if not explicit:
            overrides.append(None)
            continue

        if not isinstance(item, Mapping):
            overrides.append(None)
            continue

        value = item.get(policy.resource_deploy_key)
        overrides.append(_bool_value(f"{policy.config_key}[{index}].{policy.resource_deploy_key}", value))

    return tuple(overrides)


def parse_config_actions(
    *,
    params: Mapping[str, Any],
    raw_args: Mapping[str, Any],
    policy: ConfigActionsPolicy,
    state: str | None = None,
) -> ConfigActions:
    """
    # Summary

    Parse, default and validate config action intent.

    ## Raises

    ### ValueError

    - If explicit config action input violates the selected policy.
    """
    raw_config_actions = raw_args.get("config_actions")
    reject_empty_config_actions(raw_config_actions)

    params_config_actions = params.get("config_actions")
    if raw_config_actions is None and params_config_actions == {}:
        reject_empty_config_actions(params_config_actions)

    raw_actions = _as_mapping(raw_config_actions)
    params_actions = _as_mapping(params_config_actions)
    provided = raw_config_actions is not None or params_config_actions == {}
    explicit_options = frozenset(raw_actions.keys())

    save_value = params_actions.get("save", policy.defaults.save)
    deploy_value = params_actions.get("deploy", policy.defaults.deploy)
    type_value = params_actions.get("type", policy.defaults.type)

    save = _bool_value("config_actions.save", save_value) if save_value is not None else False
    deploy = _bool_value("config_actions.deploy", deploy_value) if deploy_value is not None else False
    action_type = str(type_value) if type_value is not None else None

    resource_overrides = _resource_deploy_overrides(params, raw_args, policy)
    resource_indexes = tuple(index for index, value in enumerate(resource_overrides) if value is not None)

    actions = ConfigActions(
        save=save,
        deploy=deploy,
        type=action_type,
        provided=provided,
        explicit_options=explicit_options,
        resource_deploy_provided=bool(resource_indexes),
        resource_deploy_indexes=resource_indexes,
        resource_deploy_overrides=resource_overrides,
    )

    if state in policy.read_only_states and not provided:
        actions = ConfigActions(
            save=False,
            deploy=False,
            type=actions.type,
            provided=actions.provided,
            explicit_options=actions.explicit_options,
            resource_deploy_provided=actions.resource_deploy_provided,
            resource_deploy_indexes=actions.resource_deploy_indexes,
            resource_deploy_overrides=actions.resource_deploy_overrides,
        )

    validate_config_actions(actions, policy, state=state)
    return actions
