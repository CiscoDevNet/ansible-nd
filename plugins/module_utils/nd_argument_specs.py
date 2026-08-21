# Copyright: (c) 2023, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
# nd_argument_specs.py

Shared argument-spec building blocks for ND modules: the common connection/authentication spec (`nd_argument_spec`) and reusable
fragments (`config_actions_spec`, `ntp_server_spec`, ...) that modules compose into their `argument_spec`.
"""

from __future__ import annotations

from typing import Any

from ansible.module_utils.basic import env_fallback
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.argument_spec import (
    _select_options as _config_actions_select_options,
    config_actions_spec as _config_actions_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import LEGACY_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActionsPolicy


def nd_argument_spec() -> dict[str, Any]:
    """
    # Summary

    Return the common connection/authentication argument spec accepted by all ND modules.

    ## Raises

    None
    """
    return {
        "host": {"type": "str", "required": False, "aliases": ["hostname"], "fallback": (env_fallback, ["ND_HOST"])},
        "port": {"type": "int", "required": False, "fallback": (env_fallback, ["ND_PORT"])},
        "username": {"type": "str", "fallback": (env_fallback, ["ND_USERNAME", "ANSIBLE_NET_USERNAME"])},
        "password": {"type": "str", "required": False, "no_log": True, "fallback": (env_fallback, ["ND_PASSWORD", "ANSIBLE_NET_PASSWORD"])},
        "output_level": {"type": "str", "default": "normal", "choices": ["debug", "info", "normal"], "fallback": (env_fallback, ["ND_OUTPUT_LEVEL"])},
        "use_proxy": {"type": "bool", "fallback": (env_fallback, ["ND_USE_PROXY"])},
        "use_ssl": {"type": "bool", "fallback": (env_fallback, ["ND_USE_SSL"])},
        "validate_certs": {"type": "bool", "fallback": (env_fallback, ["ND_VALIDATE_CERTS"])},
        "login_domain": {"type": "str", "fallback": (env_fallback, ["ND_LOGIN_DOMAIN"])},
    }


def _select_options(options: dict[str, Any], include: object | None) -> dict[str, Any]:
    """
    # Summary

    Compatibility wrapper for filtering config action option specs.

    ## Raises

    ### ValueError

    - If `include` contains an unknown option.
    """
    return _config_actions_select_options(options, include)


def config_actions_spec(
    policy: ConfigActionsPolicy | None = None,
    include: object | None = None,
) -> dict[str, Any]:
    """
    # Summary

    Return the shared `config_actions` argument spec fragment.

    This compatibility wrapper delegates to the policy-based implementation in `config_actions.argument_spec`.

    ## Raises

    ### ValueError

    - If the policy or include list references unsupported options.
    """
    selected_policy = policy or LEGACY_CONFIG_ACTIONS
    selected_include = include

    if policy is not None and not isinstance(policy, ConfigActionsPolicy):
        selected_policy = LEGACY_CONFIG_ACTIONS
        selected_include = policy

    return _config_actions_spec(selected_policy, include=selected_include)


def ntp_server_spec():
    return dict(
        ntp_host=dict(type="str", required=True),
        ntp_key_id=dict(type="int", no_log=False),
        preferred=dict(type="bool", default=False),
    )


def ntp_keys_spec():
    return dict(
        ntp_key_id=dict(type="int", required=True, no_log=False),
        ntp_key=dict(type="str", required=True, no_log=True),
        authentication_type=dict(type="str", required=True, choices=["AES128CMAC", "SHA1", "MD5"]),
        trusted=dict(type="bool", default=False),
    )


def network_spec(vlan=False):
    spec = dict(
        ipv4_address=dict(type="str", aliases=["ip"]),
        ipv4_gateway=dict(type="str", aliases=["gateway"]),
        ipv6_address=dict(type="str"),
        ipv6_gateway=dict(type="str"),
    )
    if vlan:
        spec["vlan"] = dict(type="int")
    return spec


def bgp_spec():
    return dict(
        asn=dict(type="int", required=True),
        peers=dict(
            type="list",
            elements="dict",
            options=dict(
                ip=dict(type="str", required=True),
                asn=dict(type="int", required=True),
            ),
        ),
    )
