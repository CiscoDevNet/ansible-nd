# Copyright: (c) 2023, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
# nd_argument_specs.py

Shared argument-spec building blocks for ND modules: the common connection/authentication spec (`nd_argument_spec`) and reusable
fragments (`config_actions_spec`, `ntp_server_spec`, ...) that modules compose into their `argument_spec`.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ansible.module_utils.basic import env_fallback


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
        "timeout": {"type": "int", "default": 30, "fallback": (env_fallback, ["ND_TIMEOUT"])},
        "use_proxy": {"type": "bool", "fallback": (env_fallback, ["ND_USE_PROXY"])},
        "use_ssl": {"type": "bool", "fallback": (env_fallback, ["ND_USE_SSL"])},
        "validate_certs": {"type": "bool", "fallback": (env_fallback, ["ND_VALIDATE_CERTS"])},
        "login_domain": {"type": "str", "fallback": (env_fallback, ["ND_LOGIN_DOMAIN"])},
    }


def _select_options(options: dict[str, Any], include: Iterable[str] | None) -> dict[str, Any]:
    """
    # Summary

    Return a copy of `options` filtered to the allowlist `include`. `include=None` selects every option.

    An allowlist (rather than an exclude list) is deliberate: options added to a shared fragment in the future must never silently appear in
    modules that composed the fragment before the addition.

    ## Raises

    ### ValueError

    - If `include` names an option that does not exist in `options`
    """
    if include is None:
        return dict(options)
    include_set = set(include)
    unknown = include_set - options.keys()
    if unknown:
        raise ValueError(f"Unknown option name(s) in include: {', '.join(sorted(unknown))}. Valid options: {', '.join(sorted(options))}.")
    return {key: value for key, value in options.items() if key in include_set}


def config_actions_spec(include: Iterable[str] | None = None) -> dict[str, Any]:
    """
    # Summary

    Return the shared `config_actions` argument spec fragment, filtered to the allowlist `include`.

    The full option set is `save`, `deploy`, and `type`. Modules that expose only a subset pass the option names they support, e.g.
    `config_actions_spec(include=("deploy",))` for the `nd_interface_*` modules.

    `type` accepts `switch` and `global`, per the contract in issue #368. The companion per-resource `deploy` key described in that
    issue is not part of this fragment yet: it lives in each module's `config` suboptions and its interaction with `config_actions` (mutually
    exclusive, or gated on deploy scope) is still under discussion on #368. It will be added as a separate fragment once settled.

    ## Raises

    ### ValueError

    - If `include` names an option that is not part of the fragment
    """
    options: dict[str, Any] = {
        "save": {"type": "bool", "default": True},
        "deploy": {"type": "bool", "default": True},
        "type": {"type": "str", "default": "switch", "choices": ["switch", "global"]},
    }
    return {"config_actions": {"type": "dict", "options": _select_options(options, include)}}


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
