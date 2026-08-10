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


def check_mode_query(unordered=True, ignore_keys=None):
    query = {
        "name": "Snapshot managed interfaces",
        "path": ("/api/v1/manage/fabrics/unit_test_fabric/" "switches/SWITCH123/interfaces"),
        "expected_status": 200,
        "unordered": unordered,
    }

    if ignore_keys is not None:
        query["ignore_keys"] = ignore_keys

    return query


def snapshot_response(current, status=200, failed=False, msg=None):
    result = {
        "changed": False,
        "failed": failed,
        "status": status,
        "current": current,
    }

    if msg is not None:
        result["msg"] = msg

    return result


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


def test_check_mode_queries_must_be_list(action_plugin):
    arguments = base_args()
    arguments["check_mode_queries"] = {
        "path": "/api/v1/test",
    }

    with pytest.raises(
        AnsibleActionFail,
        match="check_mode_queries must be a list",
    ):
        action_plugin._validate_arguments(arguments)


def test_check_mode_query_must_be_dictionary(action_plugin):
    with pytest.raises(
        AnsibleActionFail,
        match=r"check_mode_queries\[0\] must be a dictionary",
    ):
        action_plugin._validate_check_mode_queries(["not-a-dictionary"])


def test_unknown_check_mode_query_argument_rejected(
    action_plugin,
):
    queries = [
        {
            "path": "/api/v1/test",
            "method": "post",
        }
    ]

    with pytest.raises(
        AnsibleActionFail,
        match="Unsupported keys",
    ):
        action_plugin._validate_check_mode_queries(queries)


@pytest.mark.parametrize("path", [None, "", "   ", [], {}])
def test_invalid_check_mode_query_path_rejected(
    action_plugin,
    path,
):
    with pytest.raises(
        AnsibleActionFail,
        match="path must be a non-empty string",
    ):
        action_plugin._validate_check_mode_queries([{"path": path}])


def test_invalid_check_mode_query_status_rejected(
    action_plugin,
):
    with pytest.raises(
        AnsibleActionFail,
        match="must be an integer",
    ):
        action_plugin._validate_check_mode_queries(
            [
                {
                    "path": "/api/v1/test",
                    "expected_status": "invalid",
                }
            ]
        )


def test_invalid_check_mode_query_unordered_rejected(
    action_plugin,
):
    with pytest.raises(
        AnsibleActionFail,
        match="must be a boolean",
    ):
        action_plugin._validate_check_mode_queries(
            [
                {
                    "path": "/api/v1/test",
                    "unordered": "invalid",
                }
            ]
        )


@pytest.mark.parametrize(
    "ignore_keys",
    [None, "operData", {}, 1],
)
def test_check_mode_query_ignore_keys_must_be_list(
    action_plugin,
    ignore_keys,
):
    with pytest.raises(
        AnsibleActionFail,
        match="ignore_keys must be a list",
    ):
        action_plugin._validate_check_mode_queries(
            [
                {
                    "path": "/api/v1/test",
                    "ignore_keys": ignore_keys,
                }
            ]
        )


@pytest.mark.parametrize("ignore_key", [None, "", "   ", [], {}])
def test_check_mode_query_ignore_keys_must_be_strings(
    action_plugin,
    ignore_key,
):
    with pytest.raises(
        AnsibleActionFail,
        match="ignore_keys\\[0\\] must be a non-empty string",
    ):
        action_plugin._validate_check_mode_queries(
            [
                {
                    "path": "/api/v1/test",
                    "ignore_keys": [ignore_key],
                }
            ]
        )


def test_prepare_check_mode_queries_applies_defaults(
    action_plugin,
):
    prepared = action_plugin._prepare_check_mode_queries(
        [
            {
                "name": "Snapshot",
                "path": "/api/v1/test",
            }
        ]
    )

    assert prepared == [
        {
            "name": "Snapshot",
            "path": "/api/v1/test",
            "expected_status": 200,
            "unordered": False,
            "ignore_keys": [],
        }
    ]


def test_prepare_check_mode_queries_renders_path(action_plugin):
    action_plugin._templar.template = Mock(return_value="/api/v1/rendered")

    prepared = action_plugin._prepare_check_mode_queries([{"path": "/api/v1/{{ value }}"}])

    assert prepared[0]["path"] == "/api/v1/rendered"
    action_plugin._templar.template.assert_called_once_with("/api/v1/{{ value }}")


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
        observed_check_modes.append(action_plugin._task.check_mode)
        return next(responses)

    action_plugin._execute_module = Mock(side_effect=execute_module)

    result = run_plugin(action_plugin)

    assert action_plugin._execute_module.call_count == 3
    assert observed_check_modes == [True, False, False]
    assert result["changed"] is True
    assert result["check_mode_query_results"] == []
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
    assert result["check_mode_query_results"] == []
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
    action_plugin._execute_module.side_effect = RuntimeError("simulated execution error")

    with pytest.raises(
        RuntimeError,
        match="simulated execution error",
    ):
        run_plugin(action_plugin)

    assert action_plugin._task.check_mode is False


def test_check_mode_query_wraps_predictive_execution(
    action_plugin,
):
    query = check_mode_query(unordered=True)
    action_plugin._task.args["check_mode_queries"] = [query]

    before_state = [
        {
            "interfaceName": "Ethernet1/41",
            "configData": {
                "networkOS": {
                    "policy": {
                        "accessVlan": 100,
                    }
                }
            },
        },
        {
            "interfaceName": "Ethernet1/42",
            "configData": {
                "networkOS": {
                    "policy": {
                        "accessVlan": 200,
                    }
                }
            },
        },
    ]
    after_state = list(reversed(before_state))

    responses = iter(
        [
            snapshot_response(before_state),
            {"changed": True, "failed": False},
            snapshot_response(after_state),
            {"changed": True, "failed": False},
            {"changed": False, "failed": False},
        ]
    )
    observed_calls = []

    def execute_module(**kwargs):
        observed_calls.append(
            {
                "module_name": kwargs["module_name"],
                "module_args": kwargs["module_args"],
                "check_mode": action_plugin._task.check_mode,
            }
        )
        return next(responses)

    action_plugin._execute_module = Mock(side_effect=execute_module)

    result = run_plugin(action_plugin)

    assert action_plugin._execute_module.call_count == 5
    assert [call["module_name"] for call in observed_calls] == [
        "cisco.nd.nd_rest",
        "cisco.nd.nd_interface_ethernet_access",
        "cisco.nd.nd_rest",
        "cisco.nd.nd_interface_ethernet_access",
        "cisco.nd.nd_interface_ethernet_access",
    ]
    assert [call["check_mode"] for call in observed_calls] == [
        False,
        True,
        False,
        False,
        False,
    ]
    assert observed_calls[0]["module_args"] == {
        "path": query["path"],
        "method": "get",
    }
    assert observed_calls[2]["module_args"] == {
        "path": query["path"],
        "method": "get",
    }
    assert result["check_mode_query_results"] == [
        {
            "name": "Snapshot managed interfaces",
            "path": query["path"],
            "before_status": 200,
            "after_status": 200,
            "unchanged": True,
        }
    ]
    assert result["changed"] is True
    assert result["idempotency_attempts"] == 1
    assert action_plugin._task.check_mode is False


def test_check_mode_mutation_fails_before_apply(action_plugin):
    action_plugin._task.args["check_mode_queries"] = [check_mode_query()]

    before_state = [
        {
            "interfaceName": "Ethernet1/41",
            "configData": {
                "networkOS": {
                    "policy": {
                        "accessVlan": 100,
                    }
                }
            },
        }
    ]
    after_state = [
        {
            "interfaceName": "Ethernet1/41",
            "configData": {
                "networkOS": {
                    "policy": {
                        "accessVlan": 999,
                    }
                }
            },
        }
    ]

    action_plugin._execute_module.side_effect = [
        snapshot_response(before_state),
        {"changed": True, "failed": False},
        snapshot_response(after_state),
    ]

    with pytest.raises(
        AnsibleActionFail,
        match=("Controller state changed during predictive.*" "accessVlan.*before=100, after=999"),
    ):
        run_plugin(action_plugin)

    assert action_plugin._execute_module.call_count == 3
    assert action_plugin._task.check_mode is False


def test_unordered_snapshot_lists_compare_equal(action_plugin):
    before = action_plugin._normalize_snapshot(
        [
            {"interfaceName": "Ethernet1/41"},
            {"interfaceName": "Ethernet1/42"},
        ],
        unordered=True,
    )
    after = action_plugin._normalize_snapshot(
        [
            {"interfaceName": "Ethernet1/42"},
            {"interfaceName": "Ethernet1/41"},
        ],
        unordered=True,
    )

    assert before == after


def test_ordered_snapshot_lists_preserve_order(action_plugin):
    before = action_plugin._normalize_snapshot(
        ["one", "two"],
        unordered=False,
    )
    after = action_plugin._normalize_snapshot(
        ["two", "one"],
        unordered=False,
    )

    assert before != after


def test_snapshot_ignores_configured_volatile_keys(
    action_plugin,
):
    before = action_plugin._normalize_snapshot(
        {
            "interfaces": [
                {
                    "interfaceName": "Ethernet1/41",
                    "configData": {"accessVlan": 100},
                    "operData": {"lastUpdated": 1},
                }
            ]
        },
        unordered=True,
        ignore_keys=["operData"],
    )
    after = action_plugin._normalize_snapshot(
        {
            "interfaces": [
                {
                    "interfaceName": "Ethernet1/41",
                    "configData": {"accessVlan": 100},
                    "operData": {"lastUpdated": 2},
                }
            ]
        },
        unordered=True,
        ignore_keys=["operData"],
    )

    assert before == after


def test_snapshot_still_compares_managed_config_when_ignoring_keys(
    action_plugin,
):
    before = action_plugin._normalize_snapshot(
        {
            "interfaces": [
                {
                    "interfaceName": "Ethernet1/41",
                    "configData": {"accessVlan": 100},
                    "operData": {"lastUpdated": 1},
                }
            ]
        },
        unordered=True,
        ignore_keys=["operData"],
    )
    after = action_plugin._normalize_snapshot(
        {
            "interfaces": [
                {
                    "interfaceName": "Ethernet1/41",
                    "configData": {"accessVlan": 999},
                    "operData": {"lastUpdated": 2},
                }
            ]
        },
        unordered=True,
        ignore_keys=["operData"],
    )

    assert before != after


def test_volatile_snapshot_change_does_not_block_apply(
    action_plugin,
):
    action_plugin._task.args["check_mode_queries"] = [check_mode_query(ignore_keys=["operData"])]
    before_state = {
        "interfaces": [
            {
                "interfaceName": "Ethernet1/41",
                "configData": {"accessVlan": 100},
                "operData": {"lastUpdated": 1},
            }
        ]
    }
    after_state = {
        "interfaces": [
            {
                "interfaceName": "Ethernet1/41",
                "configData": {"accessVlan": 100},
                "operData": {"lastUpdated": 2},
            }
        ]
    }
    action_plugin._execute_module.side_effect = [
        snapshot_response(before_state),
        {"changed": True, "failed": False},
        snapshot_response(after_state),
        {"changed": True, "failed": False},
        {"changed": False, "failed": False},
    ]

    result = run_plugin(action_plugin)

    assert action_plugin._execute_module.call_count == 5
    assert result["check_mode_query_results"][0]["unchanged"] is True
    assert result["first_run_result"]["changed"] is True


def test_global_check_mode_runs_snapshot_queries_only(
    action_plugin,
):
    action_plugin._play_context.check_mode = True
    action_plugin._task.args["check_mode_queries"] = [check_mode_query()]

    state = [{"interfaceName": "Ethernet1/41"}]
    responses = iter(
        [
            snapshot_response(state),
            {"changed": True, "failed": False},
            snapshot_response(state),
        ]
    )
    observed_check_modes = []

    def execute_module(**kwargs):
        del kwargs
        observed_check_modes.append(action_plugin._task.check_mode)
        return next(responses)

    action_plugin._execute_module = Mock(side_effect=execute_module)

    result = run_plugin(action_plugin)

    assert action_plugin._execute_module.call_count == 3
    assert observed_check_modes == [False, True, False]
    assert result["first_run_result"] is None
    assert result["second_run_result"] is None
    assert result["idempotency_attempts"] == 0
    assert result["nd_query_results"] == []
    assert result["check_mode_query_results"][0]["unchanged"] is True
    assert action_plugin._task.check_mode is False


def test_snapshot_queries_require_check_mode(action_plugin):
    action_plugin._task.args["check_mode"] = False
    action_plugin._task.args["check_mode_queries"] = [check_mode_query()]

    with pytest.raises(
        AnsibleActionFail,
        match="requires check_mode=true",
    ):
        run_plugin(action_plugin)

    action_plugin._execute_module.assert_not_called()


def test_after_snapshot_runs_before_check_expectation_failure(
    action_plugin,
):
    action_plugin._task.args["check_mode_queries"] = [check_mode_query()]
    state = [{"interfaceName": "Ethernet1/41"}]

    action_plugin._execute_module.side_effect = [
        snapshot_response(state),
        {"changed": False, "failed": False},
        snapshot_response(state),
    ]

    with pytest.raises(
        AnsibleActionFail,
        match="Expected check_mode changed=True",
    ):
        run_plugin(action_plugin)

    assert action_plugin._execute_module.call_count == 3
    assert action_plugin._task.check_mode is False


def test_snapshot_runs_after_check_mode_execution_error(
    action_plugin,
):
    action_plugin._task.args["check_mode_queries"] = [check_mode_query()]
    state = [{"interfaceName": "Ethernet1/41"}]

    action_plugin._execute_module.side_effect = [
        snapshot_response(state),
        RuntimeError("simulated predictive error"),
        snapshot_response(state),
    ]

    with pytest.raises(
        RuntimeError,
        match="simulated predictive error",
    ):
        run_plugin(action_plugin)

    assert action_plugin._execute_module.call_count == 3
    assert action_plugin._task.check_mode is False


def test_snapshot_query_failure_stops_before_target(
    action_plugin,
):
    action_plugin._task.args["check_mode_queries"] = [check_mode_query()]
    action_plugin._execute_module.return_value = snapshot_response(
        {},
        status=500,
        failed=True,
        msg="simulated query failure",
    )

    with pytest.raises(
        AnsibleActionFail,
        match="simulated query failure",
    ):
        run_plugin(action_plugin)

    assert action_plugin._execute_module.call_count == 1
    assert action_plugin._task.check_mode is False

def test_jsonpath_values_support_extended_filters(action_plugin):
    controller_state = {
        "current": {
            "interfaces": [
                {
                    "interfaceName": "loopback100",
                    "configData": {
                        "networkOS": {
                            "policy": {
                                "policyType": "loopback",
                            }
                        }
                    },
                },
                {
                    "interfaceName": "loopback101",
                    "configData": {
                        "networkOS": {
                            "policy": {},
                        }
                    },
                },
            ]
        }
    }

    managed_loopback100 = (
        "$.current.interfaces[?("
        "@.interfaceName == 'loopback100' & "
        "@.configData.networkOS.policy.policyType == 'loopback'"
        ")]"
    )
    managed_loopback101 = (
        "$.current.interfaces[?("
        "@.interfaceName == 'loopback101' & "
        "@.configData.networkOS.policy.policyType == 'loopback'"
        ")]"
    )

    assert len(
        action_plugin._jsonpath_values(
            controller_state,
            managed_loopback100,
        )
    ) == 1
    assert (
        action_plugin._jsonpath_values(
            controller_state,
            managed_loopback101,
        )
        == []
    )