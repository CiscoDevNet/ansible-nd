# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Production-wrapper tests for ``nd_manage_vrf_lite`` config safety."""

from __future__ import absolute_import, annotations, division, print_function

import json
from unittest.mock import patch

import pytest
from ansible.module_utils import basic as ansible_basic

from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine as RealNDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_vrf_lite import ManageVrfLiteOrchestrator
from ansible_collections.cisco.nd.plugins.modules import nd_manage_vrf_lite

_MISSING_CONFIG = object()


class _ModuleFailure(Exception):
    """Capture ``AnsibleModule.fail_json`` without terminating pytest."""

    def __init__(self, module, result):
        super().__init__(result.get("msg", "module failed"))
        self.module = module
        self.result = result


class _FakeOutput:
    """Return the smallest valid state-machine output for wrapper tests."""

    @staticmethod
    def format():
        return {
            "changed": False,
            "before": [],
            "after": [],
            "current": [],
            "diff": [],
        }


class _FakeRuntimeOrchestrator:
    """No-op runtime collaborator used after wrapper validation succeeds."""

    @staticmethod
    def preflight_validate_check_mode(proposed):
        assert proposed == []

    @staticmethod
    def format_public_output(result):
        return result

    @staticmethod
    def deploy_pending(result):
        del result
        return {}

    @staticmethod
    def refresh_verified_state(result):
        return result

    @staticmethod
    def inject_runtime_metadata(result):
        return result


class _FakeStateMachine:
    """Exercise the real guard while avoiding controller I/O."""

    validate_config_presence = staticmethod(RealNDStateMachine.validate_config_presence)
    constructed_modules = []

    def __init__(self, module, model_orchestrator):
        assert model_orchestrator is ManageVrfLiteOrchestrator
        self.constructed_modules.append(module)
        self.model_orchestrator = _FakeRuntimeOrchestrator()
        self.proposed = []
        self.sent = []
        self.output = _FakeOutput()

    @staticmethod
    def manage_state():
        return None


def _module_args(state, config, check_mode):
    args = {
        "fabric_name": "fab1",
        "state": state,
        "config_actions": {
            "save": False,
            "deploy": False,
            "type": "switch",
        },
        "_ansible_check_mode": check_mode,
        "_ansible_verbosity": 0,
    }
    if config is not _MISSING_CONFIG:
        args["config"] = config
    return args


def _run_vrf_lite_module(module_args, state_machine_class=RealNDStateMachine):
    """Run real Ansible parsing and the production wrapper."""
    raw_args = json.dumps({"ANSIBLE_MODULE_ARGS": module_args}).encode()
    captured = {}

    def exit_json(module, **kwargs):
        captured["module"] = module
        captured["result"] = kwargs

    def fail_json(module, **kwargs):
        raise _ModuleFailure(module, kwargs)

    with (
        patch.object(ansible_basic, "_ANSIBLE_ARGS", raw_args),
        patch.object(nd_manage_vrf_lite.AnsibleModule, "exit_json", exit_json),
        patch.object(nd_manage_vrf_lite.AnsibleModule, "fail_json", fail_json),
        patch.object(nd_manage_vrf_lite, "setup_logging"),
        patch.object(nd_manage_vrf_lite, "NDStateMachine", state_machine_class),
    ):
        nd_manage_vrf_lite.main()

    return captured


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize(
    "config",
    [
        pytest.param(_MISSING_CONFIG, id="omitted"),
        pytest.param(None, id="null"),
    ],
)
def test_vrf_lite_wrapper_rejects_missing_write_config_before_normalization(state, check_mode, config):
    """Omitted/null config must fail before the wrapper turns it into ``[]``."""
    with patch.object(ManageVrfLiteOrchestrator, "prepare_module_params") as prepare:
        with pytest.raises(_ModuleFailure) as exc_info:
            _run_vrf_lite_module(_module_args(state, config, check_mode))

    assert exc_info.value.module.params["config"] is None
    assert "config must be provided and cannot be null" in exc_info.value.result["msg"]
    prepare.assert_not_called()


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_vrf_lite_wrapper_preserves_explicit_empty_write_config(state, check_mode):
    """Explicit ``config: []`` remains a valid intentional empty desired set."""
    _FakeStateMachine.constructed_modules = []

    run = _run_vrf_lite_module(
        _module_args(state, [], check_mode),
        state_machine_class=_FakeStateMachine,
    )

    assert len(_FakeStateMachine.constructed_modules) == 1
    assert run["module"].params["_vrf_lite_nested_config"] == []
    assert run["module"].params["config"] == []
    assert run["result"]["changed"] is False
