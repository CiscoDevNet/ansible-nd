# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Production-wrapper tests for ``nd_manage_vrf_lite``."""

from __future__ import absolute_import, annotations, division, print_function

import json
from unittest.mock import patch

import pytest
import yaml
from ansible.module_utils import basic as ansible_basic

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_vrf_lite import ManageVrfLiteOrchestrator
from ansible_collections.cisco.nd.plugins.modules import nd_manage_vrf_lite

_MISSING_CONFIG = object()
_EXISTING_ENTRY = {"vrf_name": "VRF1", "switch_ip": "SERIAL1", "vlan_id": 500}
_DESIRED_CONFIG = [
    {
        "vrf_name": "VRF1",
        "vlan_id": 500,
        "attach": [{"ip_address": "SERIAL1"}],
    }
]
_WRITE_BASE_FIELDS = {"output_level", "changed", "before", "after", "current", "diff"}
_ALL_RETURN_FIELDS = {
    "changed",
    "output_level",
    "before",
    "after",
    "current",
    "diff",
    "proposed",
    "logs",
    "gathered",
    "warnings",
    "deployment",
    "deployment_needed",
    "ip_to_sn_mapping",
    "response",
    "result",
}


class _ModuleFailure(Exception):
    """Capture ``AnsibleModule.fail_json`` without terminating pytest."""

    def __init__(self, module, result):
        super().__init__(result.get("msg", "module failed"))
        self.module = module
        self.result = result


class _ModuleExit(BaseException):
    """Stop the production wrapper after ``exit_json`` is captured."""


def _module_args(state, config, check_mode, output_level="normal", config_actions=None):
    args = {
        "fabric_name": "fab1",
        "state": state,
        "config_actions": (
            config_actions
            if config_actions is not None
            else {
                "save": False,
                "deploy": False,
                "type": "switch",
            }
        ),
        "output_level": output_level,
        "_ansible_check_mode": check_mode,
        "_ansible_verbosity": 0,
    }
    if config is not _MISSING_CONFIG:
        args["config"] = config
    return args


def _run_vrf_lite_module(module_args, current_state=None, runtime_metadata=None):
    """Run the production wrapper, state machine, and orchestrator without controller I/O."""
    raw_args = json.dumps({"ANSIBLE_MODULE_ARGS": module_args}).encode()
    captured = {}
    current_state = list(current_state or [])
    runtime_metadata = dict(runtime_metadata or {})

    def query_current_state(orchestrator, flat=True):
        assert flat is True
        module = orchestrator._module()
        if "warnings" in runtime_metadata:
            module.params["_warnings"] = list(runtime_metadata["warnings"])
        if "ip_to_sn_mapping" in runtime_metadata:
            ip_to_sn_mapping = dict(runtime_metadata["ip_to_sn_mapping"])
            module.params["_ip_to_sn_mapping"] = ip_to_sn_mapping
            module.params["_sn_to_ip_mapping"] = {serial: ip_address for ip_address, serial in ip_to_sn_mapping.items()}
        return [dict(item) for item in current_state]

    def exit_json(module, **kwargs):
        captured["module"] = module
        captured["result"] = kwargs
        raise _ModuleExit()

    def fail_json(module, **kwargs):
        raise _ModuleFailure(module, kwargs)

    with (
        patch.object(ansible_basic, "_ANSIBLE_ARGS", raw_args),
        patch.object(nd_manage_vrf_lite.AnsibleModule, "exit_json", exit_json),
        patch.object(nd_manage_vrf_lite.AnsibleModule, "fail_json", fail_json),
        patch.object(nd_manage_vrf_lite, "setup_logging"),
        patch.object(ManageVrfLiteOrchestrator, "_query_current_state", query_current_state),
    ):
        try:
            nd_manage_vrf_lite.main()
        except _ModuleExit:
            pass

    return captured


def _assert_result_matches_return_docs(result, expected_fields):
    """Require the exact wrapper shape and matching documented Python types."""
    return_docs = yaml.safe_load(nd_manage_vrf_lite.RETURN)
    python_types = {
        "bool": bool,
        "dict": dict,
        "list": list,
        "str": str,
    }

    def assert_documented_value(value, field_docs):
        documented_type = field_docs["type"]
        assert documented_type in python_types
        assert isinstance(value, python_types[documented_type])
        if documented_type == "list" and value and field_docs.get("elements"):
            assert all(isinstance(item, python_types[field_docs["elements"]]) for item in value)
        if documented_type == "dict" and field_docs.get("contains"):
            assert set(value).issubset(field_docs["contains"])
            for nested_field, nested_value in value.items():
                assert_documented_value(nested_value, field_docs["contains"][nested_field])

    assert set(result) == expected_fields
    assert set(result).issubset(return_docs)
    for field, value in result.items():
        assert_documented_value(value, return_docs[field])

    if "deployment" in result:
        deployment_docs = return_docs["deployment"]["contains"]
        expected_deployment_fields = {"msg", "changed", "deployment_needed", "config_actions", "response"}
        if result["deployment"]["deployment_needed"]:
            expected_deployment_fields.update({"target_vrfs", "planned_actions"})
        assert set(result["deployment"]) == expected_deployment_fields
        assert set(result["deployment"]["config_actions"]) == set(deployment_docs["config_actions"]["contains"])


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
    run = _run_vrf_lite_module(_module_args(state, [], check_mode))

    assert run["module"].params["_vrf_lite_nested_config"] == []
    assert run["module"].params["config"] == []
    assert run["result"]["changed"] is False


@pytest.mark.parametrize(
    ("output_level", "has_proposed", "has_logs"),
    [
        ("normal", False, False),
        ("info", True, False),
        ("debug", True, True),
    ],
)
def test_vrf_lite_wrapper_output_level_fields_match_return_contract(output_level, has_proposed, has_logs):
    """The wrapper must emit verbosity-controlled fields exactly as documented."""
    run = _run_vrf_lite_module(
        _module_args("merged", _DESIRED_CONFIG, False, output_level=output_level),
        current_state=[_EXISTING_ENTRY],
    )

    result = run["result"]
    assert result["output_level"] == output_level
    assert result["before"] and result["after"] and result["current"]
    assert result["diff"] == []
    assert ("proposed" in result) is has_proposed
    assert ("logs" in result) is has_logs
    if has_proposed:
        assert result["proposed"]
    if has_logs:
        assert result["logs"] == []
    expected_fields = set(_WRITE_BASE_FIELDS)
    if has_proposed:
        expected_fields.add("proposed")
    if has_logs:
        expected_fields.add("logs")
    _assert_result_matches_return_docs(result, expected_fields)


@pytest.mark.parametrize(
    "config_actions",
    [
        pytest.param({"save": True, "deploy": False, "type": "switch"}, id="save-only"),
        pytest.param({"save": True, "deploy": True, "type": "switch"}, id="save-and-deploy"),
    ],
)
def test_vrf_lite_wrapper_documents_idempotent_deployment_fields(config_actions):
    """Enabled config actions expose a documented no-deployment-needed result."""
    run = _run_vrf_lite_module(
        _module_args(
            "merged",
            _DESIRED_CONFIG,
            False,
            config_actions=config_actions,
        ),
        current_state=[_EXISTING_ENTRY],
    )

    result = run["result"]
    assert result["changed"] is False
    assert result["deployment_needed"] is False
    assert result["deployment"]["deployment_needed"] is False
    _assert_result_matches_return_docs(result, _WRITE_BASE_FIELDS | {"deployment", "deployment_needed"})


def test_vrf_lite_wrapper_documents_projected_deployment_fields_in_check_mode():
    """A changed check-mode plan exposes deployment-needed without controller writes."""
    run = _run_vrf_lite_module(
        _module_args(
            "overridden",
            [],
            True,
            config_actions={"save": True, "deploy": True, "type": "switch"},
        ),
        current_state=[_EXISTING_ENTRY],
    )

    result = run["result"]
    assert result["changed"] is True
    assert result["deployment_needed"] is True
    assert result["deployment"]["deployment_needed"] is True
    assert result["deployment"]["changed"] is True
    # Check mode does not mark projected state-machine operations as sent, so
    # production plans the fabric config-save without inventing deploy targets.
    assert result["deployment"]["target_vrfs"] == []
    assert len(result["deployment"]["planned_actions"]) == 1
    assert result["deployment"]["planned_actions"][0].startswith("POST ")
    _assert_result_matches_return_docs(result, _WRITE_BASE_FIELDS | {"deployment", "deployment_needed"})


def test_vrf_lite_wrapper_documents_conditional_runtime_metadata_fields():
    """Warnings and switch-resolution mappings are documented when emitted."""
    run = _run_vrf_lite_module(
        _module_args("merged", _DESIRED_CONFIG, False),
        current_state=[_EXISTING_ENTRY],
        runtime_metadata={
            "warnings": ["wrapper contract warning"],
            "ip_to_sn_mapping": {"10.0.0.1": "SERIAL1"},
        },
    )

    result = run["result"]
    assert result["ip_to_sn_mapping"] == {"10.0.0.1": "SERIAL1"}
    assert result["warnings"] == ["wrapper contract warning"]
    _assert_result_matches_return_docs(result, _WRITE_BASE_FIELDS | {"warnings", "ip_to_sn_mapping"})


@pytest.mark.parametrize("output_level", ["normal", "info", "debug"])
def test_vrf_lite_wrapper_documents_gathered_response_and_result_fields(output_level):
    """The gathered wrapper contract includes its controller result collections."""
    run = _run_vrf_lite_module(
        _module_args("gathered", _MISSING_CONFIG, False, output_level=output_level),
        current_state=[_EXISTING_ENTRY],
    )

    result = run["result"]
    assert result["output_level"] == output_level
    assert result["gathered"] == result["before"] == result["after"] == result["current"]
    assert result["gathered"][0]["vrf_name"] == "VRF1"
    assert result["response"] == []
    assert result["result"] == []
    assert "proposed" not in result
    assert "logs" not in result
    assert "deployment" not in result
    assert "deployment_needed" not in result
    _assert_result_matches_return_docs(
        result,
        _WRITE_BASE_FIELDS | {"response", "result", "gathered"},
    )


def test_vrf_lite_return_docs_list_every_public_wrapper_field():
    """Keep ansible-doc synchronized with every top-level public result field."""
    return_docs = yaml.safe_load(nd_manage_vrf_lite.RETURN)
    assert set(return_docs) == _ALL_RETURN_FIELDS
