# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `nd_interface_loopback` module-level behavior.

Live ND interaction is exercised by the integration target.
"""

# pylint: disable=invalid-name
# pylint: disable=line-too-long

from __future__ import annotations

from typing import Any

import pytest
import yaml
from ansible_collections.cisco.nd.plugins.modules import nd_interface_loopback
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import LoopbackInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import validate_gathered_filters
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator


class _ArgumentSpecCaptured(Exception):
    """
    # Summary

    Raised by the `AnsibleModule` stand-in to abort `main()` immediately after the `argument_spec` has been built, carrying the spec.

    ## Raises

    None
    """


def _capture_argument_spec(**kwargs: Any) -> None:
    """
    # Summary

    Stand in for `AnsibleModule` inside `main()`: raise `_ArgumentSpecCaptured` with the `argument_spec` keyword argument.

    ## Raises

    ### _ArgumentSpecCaptured

    - Always, carrying `kwargs["argument_spec"]`
    """
    raise _ArgumentSpecCaptured(kwargs["argument_spec"])


def test_nd_interface_loopback_00000_deploy_default_matches_documentation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    # Summary

    Verify `config_actions.deploy` defaults to `False` in both the DOCUMENTATION and the runtime `argument_spec`.

    ## Test

    - DOCUMENTATION declares `options.config_actions.suboptions.deploy.default` as `false`
    - `main()` builds an `argument_spec` whose `config_actions.options.deploy.default` is `False`

    ## Classes and Methods

    - nd_interface_loopback.main()
    """
    documentation = yaml.safe_load(nd_interface_loopback.DOCUMENTATION)
    assert documentation["options"]["config_actions"]["suboptions"]["deploy"]["default"] is False

    monkeypatch.setattr(nd_interface_loopback, "AnsibleModule", _capture_argument_spec)
    with pytest.raises(_ArgumentSpecCaptured) as exc_info:
        nd_interface_loopback.main()
    argument_spec = exc_info.value.args[0]
    assert argument_spec["config_actions"]["options"]["deploy"]["default"] is False


@pytest.mark.parametrize(
    "policy_filter",
    [
        {"ip": "10.100.102.1"},
        {"ipv6": "2001:db8::1"},
        {"vrf": "management"},
        {"admin_state": False},
    ],
)
def test_nd_interface_loopback_00010(policy_filter):
    """
    Verify supported partial nested gathered filters pass both the Ansible
    argument specification and gathered-property validation.
    """
    validator = ArgumentSpecValidator(
        LoopbackInterfaceModel.get_argument_spec(),
        required_if=[
            ("state", "merged", ["config"]),
            ("state", "replaced", ["config"]),
            ("state", "overridden", ["config"]),
            ("state", "deleted", ["config"]),
        ],
    )

    result = validator.validate(
        {
            "fabric_name": "fabric-1",
            "state": "gathered",
            "config": [
                {
                    "config_data": {
                        "network_os": {
                            "policy": policy_filter,
                        },
                    },
                },
            ],
        },
    )

    assert result.error_messages == []

    validate_gathered_filters(
        filters=result.validated_parameters["config"],
        normalize_filter=LoopbackInterfaceModel.normalize_gathered_filter,
        supported_properties=LoopbackInterfaceModel.gathered_filter_properties,
    )


@pytest.mark.parametrize(
    "policy_filter",
    [
        {"ip": "not-an-ip"},
        {"ip": "10.0.0.1/33"},
        {"ipv6": "not-an-ipv6"},
        {"ipv6": "2001:db8::1/129"},
        {"vrf": ""},
        {"vrf": "v" * 33},
    ],
)
def test_nd_interface_loopback_00020(policy_filter):
    validator = ArgumentSpecValidator(
        LoopbackInterfaceModel.get_argument_spec(),
        required_if=[
            ("state", "merged", ["config"]),
            ("state", "replaced", ["config"]),
            ("state", "overridden", ["config"]),
            ("state", "deleted", ["config"]),
        ],
    )

    result = validator.validate(
        {
            "fabric_name": "fabric-1",
            "state": "gathered",
            "config": [
                {
                    "config_data": {
                        "network_os": {
                            "policy": policy_filter,
                        },
                    },
                }
            ],
        }
    )

    assert result.error_messages == []

    with pytest.raises(ValueError):
        validate_gathered_filters(
            result.validated_parameters["config"],
            LoopbackInterfaceModel.normalize_gathered_filter,
            LoopbackInterfaceModel.gathered_filter_properties,
        )
