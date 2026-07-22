# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase
from ansible_collections.cisco.nd.plugins.action.nd4x_module_test import (
    ActionModule,
)


def base_args():
    return {
        "module": "cisco.nd.nd_interface_ethernet_access",
        "state": "merged",
        "common_args": {
            "fabric_name": "unit_test_fabric",
        },
        "config": [
            {
                "switch_ip": "192.0.2.10",
                "interface_names": ["Ethernet1/41"],
            }
        ],
        "expected": {
            "check_mode": {
                "changed": True,
                "failed": False,
            },
            "apply": {
                "changed": True,
                "failed": False,
            },
            "idempotency": {
                "changed": False,
                "failed": False,
            },
        },
    }


@pytest.fixture
def action_plugin():
    plugin = ActionModule.__new__(ActionModule)

    plugin._task = SimpleNamespace(
        args=base_args(),
        check_mode=False,
    )
    plugin._play_context = SimpleNamespace(
        check_mode=False,
    )
    plugin._templar = SimpleNamespace(
        template=lambda value: value,
    )
    plugin._execute_module = Mock()

    return plugin


def run_plugin(plugin):
    with patch.object(ActionBase, "run", return_value={}):
        return plugin.run(task_vars={})


@pytest.mark.parametrize(
    "value",
    [True, "true", "TRUE", "yes", "on", "1", 1],
)
def test_parse_bool_true(action_plugin, value):
    assert action_plugin._parse_bool(value, "test") is True


@pytest.mark.parametrize(
    "value",
    [False, "false", "FALSE", "no", "off", "0", 0],
)
def test_parse_bool_false(action_plugin, value):
    assert action_plugin._parse_bool(value, "test") is False


@pytest.mark.parametrize(
    "value",
    ["invalid", 2, None, [], {}],
)
def test_parse_bool_invalid(action_plugin, value):
    with pytest.raises(
        AnsibleActionFail,
        match="must be a boolean",
    ):
        action_plugin._parse_bool(value, "test")


@pytest.mark.parametrize(
    "value",
    ["invalid", None, [], {}],
)
def test_parse_int_invalid(action_plugin, value):
    with pytest.raises(
        AnsibleActionFail,
        match="must be an integer",
    ):
        action_plugin._parse_int(value, "test")


def test_unknown_top_level_argument_rejected(action_plugin):
    arguments = base_args()
    arguments["idempotency_retrise"] = 1

    with pytest.raises(
        AnsibleActionFail,
        match="Unsupported keys",
    ):
        action_plugin._validate_arguments(arguments)


def test_unknown_expected_phase_rejected(action_plugin):
    expected = {
        "wrong_phase": {
            "changed": False,
        }
    }

    with pytest.raises(
        AnsibleActionFail,
        match="Unsupported keys in expected",
    ):
        action_plugin._normalize_expected(expected)


def test_unknown_phase_expectation_rejected(action_plugin):
    expected = {
        "apply": {
            "change": True,
        }
    }

    with pytest.raises(
        AnsibleActionFail,
        match="Unsupported keys in expected.apply",
    ):
        action_plugin._normalize_expected(expected)


def test_unknown_nd_query_argument_rejected(action_plugin):
    queries = [
        {
            "path": "/api/v1/test",
            "expected_stats": 200,
        }
    ]

    with pytest.raises(
        AnsibleActionFail,
        match="Unsupported keys",
    ):
        action_plugin._validate_nd_queries(queries)


@pytest.mark.parametrize(
    ("argument_name", "argument_value", "message"),
    [
        (
            "idempotency_retries",
            "invalid",
            "must be an integer",
        ),
        (
            "idempotency_delay",
            "invalid",
            "must be an integer",
        ),
        (
            "idempotency_retries",
            2,
            "must be 1",
        ),
        (
            "idempotency_delay",
            10,
            "must be 0",
        ),
    ],
)
def test_invalid_idempotency_controls_rejected(
    action_plugin,
    argument_name,
    argument_value,
    message,
):
    action_plugin._task.args[argument_name] = argument_value

    with pytest.raises(AnsibleActionFail, match=message):
        run_plugin(action_plugin)

    action_plugin._execute_module.assert_not_called()


def test_normal_execution_runs_each_phase_once(action_plugin):
    responses = iter(
        [
            {"changed": True, "failed": False},
            {"changed": True, "failed": False},
            {"changed": False, "failed": False},
        ]
    )
    observed_check_modes = []

    def execute_module(**kwargs):
        del kwargs
        observed_check_modes.append(
            action_plugin._task.check_mode
        )
        return next(responses)

    action_plugin._execute_module = Mock(
        side_effect=execute_module
    )

    result = run_plugin(action_plugin)

    assert action_plugin._execute_module.call_count == 3
    assert observed_check_modes == [True, False, False]
    assert result["changed"] is True
    assert result["idempotency_attempts"] == 1
    assert result["second_run_result"]["changed"] is False
    assert action_plugin._task.check_mode is False


def test_global_check_mode_runs_only_check_phase(action_plugin):
    action_plugin._play_context.check_mode = True
    action_plugin._task.args["nd_queries"] = [
        {
            "path": "/api/v1/test",
            "method": "get",
            "expected_status": 200,
        }
    ]

    action_plugin._execute_module.return_value = {
        "changed": True,
        "failed": False,
    }

    result = run_plugin(action_plugin)

    assert action_plugin._execute_module.call_count == 1
    assert result["changed"] is True
    assert result["check_mode_result"] is not None
    assert result["first_run_result"] is None
    assert result["second_run_result"] is None
    assert result["idempotency_attempts"] == 0
    assert result["nd_query_results"] == []
    assert action_plugin._task.check_mode is False


def test_changed_idempotency_result_fails_once(action_plugin):
    action_plugin._execute_module.side_effect = [
        {"changed": True, "failed": False},
        {"changed": True, "failed": False},
        {"changed": True, "failed": False},
    ]

    with pytest.raises(
        AnsibleActionFail,
        match="idempotency changed=False",
    ):
        run_plugin(action_plugin)

    # Check, apply, and exactly one idempotency run.
    assert action_plugin._execute_module.call_count == 3
    assert action_plugin._task.check_mode is False


def test_idempotency_is_required_automatically(action_plugin):
    del action_plugin._task.args["expected"]["idempotency"]

    action_plugin._execute_module.side_effect = [
        {"changed": True, "failed": False},
        {"changed": True, "failed": False},
        {"changed": True, "failed": False},
    ]

    with pytest.raises(
        AnsibleActionFail,
        match="idempotency changed=False",
    ):
        run_plugin(action_plugin)

    assert action_plugin._execute_module.call_count == 3


def test_check_mode_restored_after_execution_error(
    action_plugin,
):
    action_plugin._task.check_mode = False
    action_plugin._execute_module.side_effect = RuntimeError(
        "simulated execution error"
    )

    with pytest.raises(
        RuntimeError,
        match="simulated execution error",
    ):
        run_plugin(action_plugin)

    assert action_plugin._task.check_mode is False