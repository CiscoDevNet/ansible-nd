# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Public argument, pre-connection validation and result-preservation tests."""

from __future__ import annotations

from copy import deepcopy

import pytest
import yaml
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.modules import nd_manage_breakout_interfaces as module_under_test


def _params(state="merged", **changes):
    group = {"switch_id": "FDO222425SE", "interface_names": ["Ethernet1/50"]}
    if state == "merged":
        group["breakout_map"] = "25g-4x"
    params = {"fabric_name": "fab1", "state": state, "config": [group], "config_actions": None, "verify": None, "output_level": "normal"}
    params.update(changes)
    return params


@pytest.mark.parametrize("fabric", [None, "", "   ", 1])
def test_fabric_is_required_and_nonempty(fabric):
    with pytest.raises(ValueError, match="fabric_name"):
        module_under_test.validate_module_params(_params(fabric_name=fabric))


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("actions", [{}, {"save": False}, {"deploy": False}, {"type": "switch"}, {"deploy": True}, True])
def test_config_actions_are_rejected_for_all_supported_states(state, actions):
    with pytest.raises(ValueError, match="config_actions is not supported"):
        module_under_test.validate_module_params(_params(state, config_actions=actions))


def test_raw_config_actions_are_rejected_even_when_params_omit_them():
    with pytest.raises(ValueError, match="config_actions is not supported"):
        module_under_test.validate_module_params(_params("deleted"), {"config_actions": {}})


@pytest.mark.parametrize("verify", [True, False, "true", {"enabled": "false"}, {"attempts": 1}, {"enabled": True, "timeout": 5}])
def test_verify_has_only_the_focused_enabled_contract(verify):
    with pytest.raises(ValueError, match="verify"):
        module_under_test.validate_module_params(_params(verify=verify))


@pytest.mark.parametrize("verify", [None, {}, {"enabled": False}, {"enabled": True}])
def test_valid_focused_verification_settings(verify):
    params = _params(verify=verify)
    original = deepcopy(params)
    module_under_test.validate_module_params(params)
    assert params == original


class _Exit(Exception):
    def __init__(self, result):
        super().__init__(result)
        self.result = result


class _Fail(_Exit):
    pass


class _Module:
    def __init__(self, params, check_mode=False, verbosity=0):
        self.params = deepcopy(params)
        self.check_mode = check_mode
        self._verbosity = verbosity
        self._socket_path = "unused-no-connection"

    def exit_json(self, **result):
        raise _Exit(result)

    def fail_json(self, **result):
        raise _Fail(result)


def _harness(monkeypatch, params=None, output=None, check_mode=False, error=None, verbosity=0):
    module = _Module(params or _params(), check_mode=check_mode, verbosity=verbosity)
    captured = {}
    real_sender = module_under_test.Sender

    def sender_factory():
        captured["sender_initialized"] = True
        return real_sender()

    class Orchestrator:
        def __init__(self, *, rest_send, results):
            captured["rest_send"] = rest_send
            captured["results"] = results

        def run(self):
            captured["run_called"] = True
            if error is not None:
                raise error
            return deepcopy(output or {"changed": False, "failed": False, "after_status": "unchanged", "api_outcomes": []})

    monkeypatch.setattr(module_under_test, "AnsibleModule", lambda **kwargs: module)
    monkeypatch.setattr(module_under_test, "require_pydantic", lambda unused: None)
    monkeypatch.setattr(module_under_test, "setup_logging", lambda unused: None)
    monkeypatch.setattr(module_under_test, "Sender", sender_factory)
    monkeypatch.setattr(module_under_test, "ManageBreakoutInterfacesOrchestrator", Orchestrator)
    return module, captured


def test_validation_happens_before_initializing_sender(monkeypatch):
    _, captured = _harness(monkeypatch, _params(fabric_name=" "))
    with pytest.raises(_Fail) as exc:
        module_under_test.main()
    assert exc.value.result["changed"] is False
    assert "sender_initialized" not in captured
    assert "run_called" not in captured
    assert exc.value.result["failed"] is True
    assert exc.value.result["output_level"] == "normal"
    assert exc.value.result["before"] == exc.value.result["after"] == exc.value.result["diff"] == []
    assert exc.value.result["after_status"] == "unknown"


@pytest.mark.parametrize("state", ["merged", "deleted"])
def test_unsupported_config_actions_fail_before_initializing_sender(monkeypatch, state):
    _, captured = _harness(monkeypatch, _params(state, config_actions={"deploy": True}))
    with pytest.raises(_Fail) as exc:
        module_under_test.main()
    assert exc.value.result["changed"] is False
    assert "config_actions is not supported" in exc.value.result["msg"]
    assert "sender_initialized" not in captured


def test_merged_child_input_is_rejected_before_initializing_sender(monkeypatch):
    params = _params(config=[{"switch_id": "FDO222425SE", "interface_names": ["Ethernet1/50/2"], "breakout_map": "25g-4x"}])
    _, captured = _harness(monkeypatch, params)
    with pytest.raises(_Fail) as exc:
        module_under_test.main()
    assert exc.value.result["changed"] is False
    assert "sender_initialized" not in captured


@pytest.mark.parametrize("selector,expected_child", [("Ethernet1/50", None), (" ethernet01/0050/0002 ", "Ethernet1/50/2")])
def test_deleted_parent_and_child_inputs_pass_pre_connection_contract(selector, expected_child):
    models = module_under_test.validate_module_params(_params("deleted", config=[{"switch_id": "FDO222425SE", "interface_names": [selector]}]))
    assert models[0].interface_name == "Ethernet1/50"
    assert models[0].requested_child == expected_child


@pytest.mark.parametrize("output_level", ["normal", "info", "debug"])
def test_deleted_child_selector_preserves_parent_identity_wire_child_and_requested_intent(monkeypatch, output_level):
    params = _params("deleted", output_level=output_level, config=[{"switch_id": "FDO222425SE", "interface_names": ["ethernet01/0050/0002"]}])
    report = {
        "changed": True,
        "failed": False,
        "before": [{"switch_id": "FDO222425SE", "interface_name": "Ethernet1/50", "broken_out": True}],
        "after": [{"switch_id": "FDO222425SE", "interface_name": "Ethernet1/50", "broken_out": False}],
        "after_status": "response_confirmed",
        "api_outcomes": [
            {
                "switch_id": "FDO222425SE",
                "interface_name": "Ethernet1/50",
                "requested_interface_name": "Ethernet1/50/2",
                "api_interface_name": "Ethernet1/50/1",
                "action": "unbreakout",
                "outcome": "success",
            }
        ],
        "proposed": [{"switch_id": "FDO222425SE", "interface_names": ["Ethernet1/50/2"]}],
        "diff": [{"switch_id": "FDO222425SE", "interface_names": ["Ethernet1/50/2"]}],
    }
    _harness(monkeypatch, params, output=report)
    with pytest.raises(_Exit) as exc:
        module_under_test.main()
    output = exc.value.result
    assert output["before"] == report["before"]
    assert output["after"] == report["after"]
    assert output["api_outcomes"] == report["api_outcomes"]
    assert output["diff"] == report["diff"]
    assert ("proposed" in output) == (output_level in {"info", "debug"})
    if "proposed" in output:
        assert output["proposed"] == report["proposed"]


def test_check_mode_keeps_real_discovery_transport_and_passes_prediction_flag(monkeypatch):
    _, captured = _harness(monkeypatch, check_mode=True)
    with pytest.raises(_Exit):
        module_under_test.main()
    assert captured["rest_send"].params["check_mode"] is True
    assert captured["rest_send"].check_mode is False
    assert captured["results"].check_mode is True


@pytest.mark.parametrize("state", ["merged", "deleted"])
def test_supported_state_passes_through_shared_results_and_rest_send(monkeypatch, state):
    _, captured = _harness(monkeypatch, _params(state))
    with pytest.raises(_Exit):
        module_under_test.main()
    assert captured["rest_send"].params["state"] == state
    assert captured["results"].state == state


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("output_level", ["normal", "info", "debug"])
@pytest.mark.parametrize("verbosity", [0, 2, 3])
def test_replaced_is_rejected_before_sender_and_workflow_with_standard_output(monkeypatch, check_mode, output_level, verbosity):
    params = _params(output_level=output_level)
    params["state"] = "replaced"
    _, captured = _harness(monkeypatch, params, check_mode=check_mode, verbosity=verbosity)
    with pytest.raises(_Fail) as exc:
        module_under_test.main()
    output = exc.value.result
    assert output["changed"] is False and output["failed"] is True
    assert "state must be merged or deleted" in output["msg"]
    assert "sender_initialized" not in captured
    assert "rest_send" not in captured and "run_called" not in captured
    assert output["before"] == output["after"] == output["diff"] == output["api_outcomes"] == []
    assert output["after_status"] == "unknown" and output["may_have_changed"] is False
    assert output["output_level"] == output_level
    assert ("proposed" in output) == (output_level in {"info", "debug"})
    assert ("logs" in output) == (output_level == "debug")
    assert "api_calls" not in output and "api_paths" not in output


def test_success_preserves_response_provenance_not_fabricated_after(monkeypatch):
    result = {
        "changed": True,
        "failed": False,
        "after_status": "response_confirmed",
        "api_outcomes": [{"switch_id": "FDO222425SE", "interface_name": "Ethernet1/50", "outcome": "success"}],
    }
    _harness(monkeypatch, output=result)
    with pytest.raises(_Exit) as exc:
        module_under_test.main()
    assert all(exc.value.result[key] == value for key, value in result.items())
    assert exc.value.result["after"] == []


def test_partial_failure_preserves_changed_unknown_and_per_parent_results(monkeypatch):
    result = {
        "changed": True,
        "failed": True,
        "after_status": "unknown",
        "may_have_changed": True,
        "before": [{"interface_name": "Ethernet1/50"}],
        "api_outcomes": [{"interface_name": "Ethernet1/50", "outcome": "unknown"}, {"interface_name": "Ethernet1/51", "outcome": "failed"}],
        "msg": "Mixed breakout result",
    }
    _harness(monkeypatch, output=result)
    with pytest.raises(_Fail) as exc:
        module_under_test.main()
    assert all(exc.value.result[key] == value for key, value in result.items())
    assert exc.value.result["after"] == []


@pytest.mark.parametrize("failed", [False, True])
def test_diagnostic_formatting_error_does_not_erase_operation_results(monkeypatch, failed):
    result = {
        "changed": True,
        "failed": failed,
        "after_status": "unknown" if failed else "response_confirmed",
        "api_outcomes": [{"interface_name": "Ethernet1/50", "outcome": "success"}],
    }
    _harness(monkeypatch, output=result)

    def diagnostic_error(*unused, **unused_kwargs):
        raise ValueError("diagnostic formatting failure")

    monkeypatch.setattr(module_under_test.NDOutput, "format_with_verbosity", diagnostic_error)
    with pytest.raises(_Fail if failed else _Exit) as exc:
        module_under_test.main()
    assert exc.value.result["changed"] is True
    assert exc.value.result["after_status"] == result["after_status"]
    assert exc.value.result["api_outcomes"] == result["api_outcomes"]
    assert "diagnostic formatting failure" in exc.value.result["warnings"][0]


def test_unexpected_workflow_exception_does_not_claim_native_or_confirmed_state(monkeypatch):
    _harness(monkeypatch, error=RuntimeError("unexpected workflow failure"))
    with pytest.raises(_Fail) as exc:
        module_under_test.main()
    assert exc.value.result["after_status"] == "unknown"
    assert exc.value.result["may_have_changed"] is True
    assert exc.value.result["after"] == []
    assert exc.value.result["failed"] is True
    assert exc.value.result["before"] == exc.value.result["diff"] == []
    assert exc.value.result["output_level"] == "normal"


def test_initialization_failure_uses_standard_shape_without_claiming_a_write(monkeypatch):
    _, captured = _harness(monkeypatch)

    def sender_error():
        raise RuntimeError("sender initialization failure")

    monkeypatch.setattr(module_under_test, "Sender", sender_error)
    with pytest.raises(_Fail) as exc:
        module_under_test.main()
    assert exc.value.result["output_level"] == "normal"
    assert exc.value.result["before"] == exc.value.result["after"] == exc.value.result["diff"] == []
    assert exc.value.result["changed"] is False
    assert exc.value.result["failed"] is True
    assert exc.value.result["after_status"] == "unknown"
    assert exc.value.result["may_have_changed"] is False
    assert "run_called" not in captured


@pytest.mark.parametrize("failure_path", ["validation", "initialization", "unexpected_workflow"])
@pytest.mark.parametrize("output_level", ["normal", "info", "debug"])
@pytest.mark.parametrize("verbosity", [0, 2, 3])
def test_business_failure_paths_follow_standard_output_and_visibility(monkeypatch, failure_path, output_level, verbosity):
    params = _params(output_level=output_level, fabric_name=" " if failure_path == "validation" else "fab1")
    _harness(monkeypatch, params, verbosity=verbosity, error=RuntimeError("unexpected workflow") if failure_path == "unexpected_workflow" else None)
    if failure_path == "initialization":

        def initialize_error():
            raise RuntimeError("initialization failed")

        monkeypatch.setattr(module_under_test, "Sender", initialize_error)
    with pytest.raises(_Fail) as exc:
        module_under_test.main()
    output = exc.value.result
    assert output["output_level"] == output_level
    assert output["changed"] is False and output["failed"] is True
    assert output["before"] == output["after"] == output["diff"] == []
    assert output["after_status"] == "unknown"
    assert output["api_outcomes"] == []
    assert output["may_have_changed"] is (failure_path == "unexpected_workflow")
    assert ("proposed" in output) == (output_level in {"info", "debug"})
    assert ("logs" in output) == (output_level == "debug")
    if "proposed" in output:
        assert output["proposed"] == []
    if "logs" in output:
        assert output["logs"] == []
    assert "api_calls" not in output and "api_paths" not in output


def test_public_spec_matches_documented_defaults(monkeypatch):
    class Capture(Exception):
        pass

    def capture(**kwargs):
        raise Capture(kwargs["argument_spec"])

    monkeypatch.setattr(module_under_test, "AnsibleModule", capture)
    with pytest.raises(Capture) as exc:
        module_under_test.main()
    spec = exc.value.args[0]
    doc = yaml.safe_load(module_under_test.DOCUMENTATION)["options"]
    assert spec["state"]["choices"] == doc["state"]["choices"] == ["merged", "deleted"]
    assert "config_actions" not in spec
    assert "config_actions" not in doc
    assert spec["verify"]["options"]["enabled"]["default"] is False
    assert "ticket_id" not in spec
    assert "cluster_name" not in spec
    assert "requested_child" not in spec["config"]["options"]
    assert "requested_child" not in doc["config"]["suboptions"]


def test_all_documented_examples_pass_local_contract_validation():
    for task in yaml.safe_load(module_under_test.EXAMPLES):
        module_under_test.validate_module_params(task["cisco.nd.nd_manage_breakout_interfaces"])


def _diagnostic_results():
    """Real query/write records deliberately disagree with workflow authority."""
    results = Results()
    for path, verb, operation, verbosity in [
        ("/interfacesSummary", HttpVerbEnum.GET, OperationType.QUERY, 3),
        ("/interfaceActions/breakout", HttpVerbEnum.POST, OperationType.CREATE, 2),
    ]:
        results.path_current = path
        results.verb_current = verb
        results.operation_type = operation
        results.verbosity_level_current = verbosity
        results.payload_current = None if verb == HttpVerbEnum.GET else {"interfaces": []}
        results.response_current = {"RETURN_CODE": 200, "DATA": {"path": path}}
        results.result_current = {"success": verb == HttpVerbEnum.GET, "changed": True}
        results.diff_current = {}
        results.register_api_call()
    results.build_final_result()
    assert results.final_result["changed"] is True
    assert results.final_result["failed"] is True
    return results


def _workflow_report(case):
    report = {
        "changed": case in {"success", "check"},
        "failed": case == "failure",
        "before": [{"switch_id": "SERIAL", "interface_name": "Ethernet1/50", "broken_out": case == "noop"}],
        "after_status": {"success": "response_confirmed", "noop": "unchanged", "check": "predicted", "failure": "unknown"}[case],
        "api_outcomes": [
            {
                "switch_id": "SERIAL",
                "interface_name": "Ethernet1/50",
                "outcome": {"success": "success", "noop": "noop", "check": "planned", "failure": "unknown"}[case],
            }
        ],
        "may_have_changed": case == "failure",
        "proposed": [{"switch_id": "SERIAL", "interface_names": ["Ethernet1/50"], "breakout_map": "25g-4x"}],
        "diff": [] if case == "noop" else [{"switch_id": "SERIAL", "interface_names": ["Ethernet1/50"], "breakout_map": "25g-4x"}],
        "logs": ["workflow diagnostic log"],
        "api_calls": [{"method": "GET", "path": "/interfacesSummary", "http_status": 200, "elapsed_seconds": 0.01}],
        "verification": {"enabled": True, "complete": False},
    }
    if case != "failure":
        report["after"] = [{"switch_id": "SERIAL", "interface_name": "Ethernet1/50", "broken_out": True}]
    if case == "failure":
        report["msg"] = "Primary uncertain operation result"
    return report


@pytest.mark.parametrize("case", ["success", "noop", "check", "failure"])
@pytest.mark.parametrize("output_level", ["normal", "info", "debug"])
@pytest.mark.parametrize("verbosity", [0, 2, 3])
def test_output_level_and_cli_verbosity_matrix_uses_shared_formatting(monkeypatch, case, output_level, verbosity):
    report = _workflow_report(case)
    original = deepcopy(report)
    module = _Module(_params(output_level=output_level), check_mode=case == "check", verbosity=verbosity)
    results = _diagnostic_results()
    shared_format = module_under_test.NDOutput.format_with_verbosity
    calls = []

    def format_spy(self, level, accumulator=None, **kwargs):
        calls.append((self, level, accumulator, deepcopy(kwargs)))
        return shared_format(self, level, accumulator, **kwargs)

    def assign_error(*unused, **unused_kwargs):
        raise AssertionError("Plain list snapshots must not be passed through NDOutput.assign")

    monkeypatch.setattr(module_under_test.NDOutput, "format_with_verbosity", format_spy)
    monkeypatch.setattr(module_under_test.NDOutput, "assign", assign_error)
    output = module_under_test._format_output(module, report, results)
    assert len(calls) == 1 and calls[0][1:3] == (verbosity, results)
    assert report == original
    assert output["output_level"] == output_level
    assert output["changed"] is report["changed"]
    assert output["failed"] is report["failed"]
    assert output["before"] == report["before"]
    assert output["after"] == report.get("after", [])
    assert output["diff"] == report["diff"]
    assert output["after_status"] == report["after_status"]
    assert output["api_outcomes"] == report["api_outcomes"]
    assert output["verification"] == report["verification"]
    assert ("proposed" in output) == (output_level in {"info", "debug"})
    assert ("logs" in output) == (output_level == "debug")
    if "proposed" in output:
        assert output["proposed"] == report["proposed"]
    if "logs" in output:
        assert output["logs"] == report["logs"]
    assert ("api_calls" in output) == (verbosity >= 3)
    if verbosity == 0:
        assert "api_paths" not in output and "api_verbs" not in output
    elif verbosity == 2:
        assert output["api_paths"] == ["/interfaceActions/breakout"]
        assert output["api_verbs"] == ["POST"]
    else:
        assert output["api_paths"] == ["/interfacesSummary", "/interfaceActions/breakout"]
        assert output["api_verbs"] == ["GET", "POST"]
        assert output["api_calls"] == report["api_calls"]
    for key in ("response", "result", "diff", "metadata", "payload"):
        assert (f"api_{key}" in output) == (verbosity >= 3)
        if verbosity >= 3:
            assert output[f"api_{key}"] == results.final_result[key]


@pytest.mark.parametrize("case", ["success", "failure"])
@pytest.mark.parametrize("output_level", ["normal", "info", "debug"])
@pytest.mark.parametrize("verbosity", [0, 2, 3])
def test_formatter_failure_falls_back_to_shared_config_format_and_keeps_primary_fields(monkeypatch, case, output_level, verbosity):
    report = _workflow_report(case)
    module = _Module(_params(output_level=output_level), verbosity=verbosity)
    config_format = module_under_test.NDOutput.format
    calls = []

    def broken_formatter(*unused, **unused_kwargs):
        raise ValueError("aggregate diagnostics unavailable")

    def format_spy(self, **kwargs):
        calls.append(deepcopy(kwargs))
        return config_format(self, **kwargs)

    monkeypatch.setattr(module_under_test.NDOutput, "format_with_verbosity", broken_formatter)
    monkeypatch.setattr(module_under_test.NDOutput, "format", format_spy)
    output = module_under_test._format_output(module, report, _diagnostic_results())
    assert len(calls) == 1
    assert output["changed"] is report["changed"]
    assert output["failed"] is report["failed"]
    assert output["after_status"] == report["after_status"]
    assert output["api_outcomes"] == report["api_outcomes"]
    assert output["after"] == report.get("after", [])
    assert output.get("msg") == report.get("msg")
    assert "aggregate diagnostics unavailable" in output["warnings"][0]
    assert "api_paths" not in output
    assert ("api_calls" in output) == (verbosity >= 3)
    assert ("proposed" in output) == (output_level in {"info", "debug"})
    assert ("logs" in output) == (output_level == "debug")
