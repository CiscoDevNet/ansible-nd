# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests verifying the `config_actions` contract is uniform across the `nd_interface_*` modules.

Deployment is opt-in: each module must document `default: false` and build an `argument_spec` whose `config_actions.deploy` default is
`False`, so that changes are staged on the controller and only pushed to switches when the user sets `config_actions.deploy: true`.

Every module must also build its `config_actions` option from the shared `config_actions_spec()` fragment rather than an inline copy, so
the interface family cannot drift from the collection-wide contract.
"""

# pylint: disable=invalid-name
# pylint: disable=line-too-long

from __future__ import annotations

import importlib
from typing import Any

import pytest
import yaml
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import config_actions_spec

INTERFACE_MODULES = (
    "nd_interface_ethernet_access",
    "nd_interface_ethernet_trunk_host",
    "nd_interface_loopback",
    "nd_interface_port_channel_access",
    "nd_interface_port_channel_trunk_host",
    "nd_interface_subinterface_managed",
    "nd_interface_subinterface_unmanaged",
    "nd_interface_svi",
    "nd_interface_vpc_access",
    "nd_interface_vpc_trunk_host",
)


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

    Stand in for `AnsibleModule` inside a module's `main()`: raise `_ArgumentSpecCaptured` with the `argument_spec` keyword argument.

    ## Raises

    ### _ArgumentSpecCaptured

    - Always, carrying `kwargs["argument_spec"]`
    """
    raise _ArgumentSpecCaptured(kwargs["argument_spec"])


@pytest.mark.parametrize("module_name", INTERFACE_MODULES)
def test_nd_interface_deploy_default_00000(monkeypatch: pytest.MonkeyPatch, module_name: str) -> None:
    """
    # Summary

    Verify `config_actions.deploy` defaults to `False` in both the DOCUMENTATION and the runtime `argument_spec` of each interface module.

    ## Test

    - DOCUMENTATION declares `options.config_actions.suboptions.deploy.default` as `false`
    - `main()` builds an `argument_spec` whose `config_actions.options.deploy.default` is `False`

    ## Classes and Methods

    - nd_interface_*.main()
    """
    module = importlib.import_module(f"ansible_collections.cisco.nd.plugins.modules.{module_name}")

    documentation = yaml.safe_load(module.DOCUMENTATION)
    assert documentation["options"]["config_actions"]["suboptions"]["deploy"]["default"] is False

    monkeypatch.setattr(module, "AnsibleModule", _capture_argument_spec)
    with pytest.raises(_ArgumentSpecCaptured) as exc_info:
        module.main()
    argument_spec = exc_info.value.args[0]
    assert argument_spec["config_actions"]["options"]["deploy"]["default"] is False


@pytest.mark.parametrize("module_name", INTERFACE_MODULES)
def test_nd_interface_deploy_default_00010(monkeypatch: pytest.MonkeyPatch, module_name: str) -> None:
    """
    # Summary

    Verify each interface module builds its `config_actions` option from the shared `config_actions_spec()` fragment (deploy-only subset).

    ## Test

    - `main()` builds an `argument_spec` whose `config_actions` entry equals `config_actions_spec(include=("deploy",))["config_actions"]`

    ## Classes and Methods

    - nd_interface_*.main()
    - config_actions_spec()
    """
    module = importlib.import_module(f"ansible_collections.cisco.nd.plugins.modules.{module_name}")

    monkeypatch.setattr(module, "AnsibleModule", _capture_argument_spec)
    with pytest.raises(_ArgumentSpecCaptured) as exc_info:
        module.main()
    argument_spec = exc_info.value.args[0]
    assert argument_spec["config_actions"] == config_actions_spec(include=("deploy",))["config_actions"]
