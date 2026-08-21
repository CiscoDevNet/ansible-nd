# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Validation for normalized config action intent.
"""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActions, ConfigActionsPolicy


def validate_config_actions(actions: ConfigActions, policy: ConfigActionsPolicy, state: str | None = None) -> None:
    """
    # Summary

    Validate normalized config actions against a module-family policy.

    ## Raises

    ### ValueError

    - If the normalized actions violate the selected policy.
    """
    unsupported = actions.explicit_options - policy.supported
    if unsupported:
        raise ValueError(f"Unsupported config_actions option(s) for {policy.name}: {', '.join(sorted(unsupported))}.")

    if "save" not in policy.supported and "save" in actions.explicit_options:
        raise ValueError(f"config_actions.save is not supported for {policy.name}.")
    if "deploy" not in policy.supported and "deploy" in actions.explicit_options:
        raise ValueError(f"config_actions.deploy is not supported for {policy.name}.")

    if actions.type is not None and actions.type not in policy.allowed_types:
        raise ValueError(f"config_actions.type must be one of: {', '.join(sorted(policy.allowed_types))}.")

    if policy.deploy_requires_save and actions.deploy and not actions.save:
        raise ValueError("config_actions.deploy=true requires config_actions.save=true.")

    if state in policy.read_only_states:
        explicit_write = actions.explicit_options & {"save", "deploy"}
        if explicit_write and (actions.save or actions.deploy):
            raise ValueError(f"config_actions.save/config_actions.deploy are not allowed for state='{state}'.")

    if actions.resource_deploy_provided:
        if policy.resource_interaction != "type_resource_gated":
            raise ValueError(f"{policy.config_key}[].{policy.resource_deploy_key} is not supported for {policy.name}.")
        if actions.type != policy.resource_deploy_type:
            raise ValueError(f"{policy.config_key}[].{policy.resource_deploy_key} is allowed only when config_actions.type='resource'.")


def reject_empty_config_actions(raw_config_actions: object) -> None:
    """
    # Summary

    Reject explicit empty `config_actions`.

    ## Raises

    ### ValueError

    - If `raw_config_actions` is an empty dictionary.
    """
    if raw_config_actions == {}:
        raise ValueError("config_actions cannot be empty; omit it to use defaults or specify at least one supported suboption.")
