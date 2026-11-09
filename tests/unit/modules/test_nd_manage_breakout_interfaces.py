# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Public argument, pre-connection validation and result-preservation tests."""

from __future__ import annotations

import json
from copy import deepcopy

import pytest
import yaml
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.modules import nd_manage_breakout_interfaces as module_under_test
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_guarded_workflows import topology
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_interfaces import (
    BREAKOUT,
    SERIAL,
    RecordingSender,
    action,
    group,
    inventory,
    item,
)


def _params(state="merged", **changes):
    group = {"switch_id": "FDO222425SE", "interface_names": ["Ethernet1/50"]}
    if state in {"merged", "overridden"}:
        group["breakout_map"] = "25g-4x"
    params = {"fabric_name": "fab1", "state": state, "config": [group], "config_actions": None, "verify": None, "output_level": "normal"}
    params.update(changes)
    return params


@pytest.mark.parametrize("fabric", [None, "", "   ", 1])
def test_fabric_is_required_and_nonempty(fabric):
    with pytest.raises(ValueError, match="fabric_name"):
        module_under_test.validate_module_params(_params(fabric_name=fabric))


@pytest.mark.parametrize("state", ["merged", "deleted", "overridden"])
@pytest.mark.parametrize("actions", [{}, {"save": False}, {"deploy": False}, {"type": "switch"}, {"deploy": True}, True])
def test_config_actions_are_rejected_for_all_supported_states(state, actions):
    with pytest.raises(ValueError, match="config_actions is not supported"):
        module_under_test.validate_module_params(_params(state, config_actions=actions))


def test_raw_config_actions_are_rejected_even_when_params_omit_them():
    with pytest.raises(ValueError, match="config_actions is not supported"):
        module_under_test.validate_module_params(_params("deleted"), {"config_actions": {}})


@pytest.mark.parametrize("verify", [True, False, "true", {"enabled": "false"}, {"attempts": 1}, {"enabled": True, "timeout": 5}])
def test_verify_has_only_the_enabled_contract(verify):
    with pytest.raises(ValueError, match="verify"):
        module_under_test.validate_module_params(_params(verify=verify))


@pytest.mark.parametrize("verify", [None, {}, {"enabled": False}, {"enabled": True}])
def test_valid_optional_verification_settings(verify):
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


@pytest.mark.parametrize("state", ["merged", "deleted", "overridden"])
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


@pytest.mark.parametrize("config", [None, [], [{"switch_id": "FDO222425SE", "interface_names": []}]])
def test_overridden_empty_desired_scopes_pass_pre_connection_validation(monkeypatch, config):
    params = _params("overridden", config=config)
    _, captured = _harness(monkeypatch, params)
    with pytest.raises(_Exit):
        module_under_test.main()
    assert captured["run_called"] is True
    assert captured["rest_send"].params["config"] == config
    assert captured["rest_send"].params["state"] == "overridden"


@pytest.mark.parametrize("switch_id", [None, "", " ", 1, False])
def test_overridden_clear_only_invalid_switch_fails_before_sender(monkeypatch, switch_id):
    params = _params("overridden", config=[{"switch_id": switch_id, "interface_names": []}])
    _, captured = _harness(monkeypatch, params)
    with pytest.raises(_Fail) as exc:
        module_under_test.main()
    assert "switch_id" in exc.value.result["msg"]
    assert "sender_initialized" not in captured
    assert exc.value.result["recovery"] == []


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("config", [None, []])
def test_empty_or_omitted_config_is_rejected_for_non_override_states_before_sender(monkeypatch, state, config):
    _, captured = _harness(monkeypatch, _params(state, config=config))
    with pytest.raises(_Fail) as exc:
        module_under_test.main()
    assert "config must be a non-empty list" in exc.value.result["msg"]
    assert "sender_initialized" not in captured


def test_overridden_child_selector_is_rejected_before_sender(monkeypatch):
    params = _params("overridden", config=[{"switch_id": "FDO222425SE", "interface_names": ["Ethernet1/50/1"], "breakout_map": "25g-4x"}])
    _, captured = _harness(monkeypatch, params)
    with pytest.raises(_Fail):
        module_under_test.main()
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


@pytest.mark.parametrize("state", ["merged", "deleted", "overridden"])
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
    assert "state must be merged, deleted, or overridden" in output["msg"]
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


@pytest.mark.parametrize("output_level", ["normal", "info", "debug"])
@pytest.mark.parametrize("verbosity", [0, 3])
def test_incomplete_forward_request_preserves_unattempted_unverified_recovery(monkeypatch, output_level, verbosity):
    recovery = [
        {
            "switch_id": "FDO222425SE",
            "phase": "breakout",
            "action": "unbreakout",
            "status": "not_attempted",
            "topology_verified": False,
            "api_outcomes": [],
            "msg": "The forward request did not report synchronous completion.",
        }
    ]
    report = {"changed": True, "failed": True, "may_have_changed": True, "after_status": "unknown", "recovery": recovery}
    _harness(monkeypatch, _params(output_level=output_level), output=report, verbosity=verbosity)
    with pytest.raises(_Fail) as exc:
        module_under_test.main()
    assert exc.value.result["recovery"] == recovery
    assert exc.value.result["after_status"] == "unknown"
    assert exc.value.result["after"] == []
    assert exc.value.result["changed"] is True
    assert exc.value.result["may_have_changed"] is True


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
    assert spec["state"]["choices"] == doc["state"]["choices"] == ["merged", "deleted", "overridden"]
    assert spec["config"]["default"] == doc["config"]["default"] == []
    assert spec["config"].get("required", False) is False
    assert doc["config"].get("required", False) is False
    assert "config_actions" not in spec
    assert "config_actions" not in doc
    assert spec["verify"]["options"]["enabled"]["default"] is doc["verify"]["suboptions"]["enabled"]["default"] is True
    assert spec["verify"]["apply_defaults"] is True
    assert "ticket_id" not in spec
    assert "cluster_name" not in spec
    assert "requested_child" not in spec["config"]["options"]
    assert "requested_child" not in doc["config"]["suboptions"]


@pytest.mark.parametrize("verify", [None, {}, {"enabled": False}, {"enabled": True}])
def test_argument_defaults_enable_verification_when_dict_is_omitted_or_empty(verify):
    params = {"fabric_name": "fab1", "state": "overridden"}
    if verify is not None:
        params["verify"] = verify
    result = ArgumentSpecValidator(module_under_test.BreakoutInterfaceModel.get_argument_spec()).validate(params)
    assert result.error_messages == []
    assert result.validated_parameters["config"] == []
    assert result.validated_parameters["verify"] == {"enabled": verify.get("enabled", True) if verify is not None else True}


def test_documentation_describes_verification_boundary_coupled_parent_scope_and_response_only_recovery():
    docs = yaml.safe_load(module_under_test.DOCUMENTATION)
    verify_notes = " ".join(docs["options"]["verify"]["description"])
    assert "reads current state, validates inputs and platforms, skips operations already satisfied and checks API results" in verify_notes
    assert "skips post-change interface checks, discovery waiting and automatic recovery" in verify_notes
    notes = " ".join(docs["notes"])
    assert "Individual child lanes and disappearing native siblings" in notes
    assert "unchanged unlisted breakout families are allowed" in notes
    assert "Earlier successful operations and safe changes on other switches remain" in notes
    assert "Recovery is not independently verified" in notes
    assert "If the original breakout map cannot be determined, the task fails before unbreakout" in notes
    assert "times out or returns HTTP 500, no recovery request" in notes
    assert "overridden only selects existing breakout families found before the task for removal" in notes
    assert "Additional families created through hardware coupling during the task are not automatically selected for removal" in notes
    returned = yaml.safe_load(module_under_test.RETURN)
    assert "initial-discovery evidence for switches not acted on" in " ".join(returned["after_status"]["description"])
    assert "historical observation evidence, not the current topology after compensation" in " ".join(returned["observed_before_recovery"]["description"])


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


def _scripted_main(monkeypatch, responses, params, *, verbosity=0, check_mode=False):
    """Exercise module.main and its real workflow using only scripted REST replies."""
    module = _Module(params, check_mode=check_mode, verbosity=verbosity)
    sender = RecordingSender(responses)
    real_rest_send = module_under_test.RestSend

    def rest_send_factory(settings):
        transport = real_rest_send(settings)
        transport.unit_test = True
        transport.timeout = 600
        transport.send_interval = 1
        return transport

    monkeypatch.setattr(module_under_test, "AnsibleModule", lambda **unused: module)
    monkeypatch.setattr(module_under_test, "require_pydantic", lambda unused: None)
    monkeypatch.setattr(module_under_test, "setup_logging", lambda unused: None)
    monkeypatch.setattr(module_under_test, "Sender", lambda: sender)
    monkeypatch.setattr(module_under_test, "RestSend", rest_send_factory)
    return module, sender


@pytest.mark.parametrize("verify", [False, True])
@pytest.mark.parametrize("verbosity", [0, 3])
@pytest.mark.parametrize(
    "failure_message",
    [
        pytest.param({"error": "Unsupported map"}, id="object"),
        pytest.param(["Unsupported", "map"], id="array"),
        pytest.param(42, id="integer"),
        pytest.param(True, id="boolean"),
        pytest.param(None, id="null"),
        pytest.param({}, id="empty-object"),
        pytest.param([], id="empty-array"),
    ],
)
def test_real_main_keeps_partial_success_when_controller_error_message_is_not_text(monkeypatch, verify, verbosity, failure_message):
    """Error presentation cannot erase accepted writes or fresh topology evidence."""
    accepted, rejected = "Ethernet1/21", "Ethernet1/23"
    replies = [
        inventory(),
        topology(native=(accepted, rejected)),
        action(item(accepted), item(rejected, status="Failed", message=failure_message)),
    ]
    if verify:
        replies.append(topology(accepted, native=(rejected,)))
    params = _params(config=[group(accepted, rejected)], verify={"enabled": verify})
    _, sender = _scripted_main(monkeypatch, replies, params, verbosity=verbosity)

    with pytest.raises(_Fail) as caught:
        module_under_test.main()
    output = caught.value.result
    assert output["failed"] is True
    assert output["changed"] is True
    assert output["recovery"] == []
    assert len(output["before"]) == 2
    assert all(not row["broken_out"] and row["children"] == [] for row in output["before"])
    assert output["diff"] == [group(accepted, rejected)]
    reported = {(row["switch_id"], row["interface_name"]): row for row in output["api_outcomes"]}
    assert reported[(SERIAL, accepted)]["outcome"] == "success"
    assert reported[(SERIAL, rejected)]["outcome"] == "failed"
    assert isinstance(reported[(SERIAL, rejected)]["message"], str)
    assert reported[(SERIAL, rejected)]["message"]
    assert isinstance(output["msg"], str) and output["msg"]
    assert "unhashable type" not in output["msg"]
    assert "sequence item" not in output["msg"]
    if verify:
        assert output["after_status"] == "observed"
        after = {row["interface_name"]: row for row in output["after"]}
        assert after[accepted]["broken_out"] is True
        assert after[accepted]["children"] == [accepted + "/" + str(lane) for lane in (1, 2, 3, 4)]
        assert after[rejected]["broken_out"] is False
        assert all(row["evidence"] == "post_action_discovery" for row in output["after"])
    else:
        assert output["after_status"] == "unknown"
        assert output["after"] == []
    writes = [call for call in sender.calls if call["verb"] == HttpVerbEnum.POST]
    assert len(writes) == 1 and writes[0]["path"] == BREAKOUT
    assert writes[0]["payload"] == {
        "interfaces": [
            {"switchId": SERIAL, "interfaceName": accepted, "breakoutMap": "25g-4x"},
            {"switchId": SERIAL, "interfaceName": rejected, "breakoutMap": "25g-4x"},
        ]
    }
    assert len(sender.calls) == (4 if verify else 3)
    if verbosity >= 3:
        raw_rejections = [
            row for response in output["api_response"] for row in response.get("DATA", {}).get("results", []) if row.get("interfaceName") == rejected
        ]
        assert len(raw_rejections) == 1
        assert raw_rejections[0]["message"] == failure_message
    json.dumps(output)


@pytest.mark.parametrize("observed_after", [False, True])
@pytest.mark.parametrize("verbosity", [0, 3])
def test_real_main_preserves_accumulated_report_when_unexpected_run_exception_escapes(monkeypatch, observed_after, verbosity):
    """Unexpected report-boundary failures retain known changes without inventing after."""
    parent = "Ethernet1/21"
    replies = [inventory(), topology(native=(parent,)), action(item(parent))]
    if observed_after:
        replies.append(topology(parent))
    _, sender = _scripted_main(monkeypatch, replies, _params(config=[group(parent)], verify={"enabled": True}), verbosity=verbosity)
    real_orchestrator = module_under_test.ManageBreakoutInterfacesOrchestrator
    captured = {}

    class InterruptedWorkflow(real_orchestrator):
        def _topology_snapshot(self, switch_ids=None, evidence="post_action_discovery"):
            if evidence == "post_action_discovery" and not observed_after:
                raise RuntimeError("Guard observation unavailable after the accepted action")
            return super()._topology_snapshot(switch_ids, evidence)

        def run(self):
            report = super().run()
            captured["workflow_report"] = deepcopy(report)
            captured["orchestrator"] = self
            raise RuntimeError("Unexpected report-boundary failure after workflow evidence accumulated")

    monkeypatch.setattr(module_under_test, "ManageBreakoutInterfacesOrchestrator", InterruptedWorkflow)
    with pytest.raises(_Fail) as caught:
        module_under_test.main()
    output = caught.value.result
    progress = captured["workflow_report"]
    assert output["failed"] is True
    assert output["changed"] is True
    assert output["may_have_changed"] is True
    assert output["before"] == progress["before"]
    assert output["diff"] == progress["diff"]
    assert output["api_outcomes"] == progress["api_outcomes"]
    assert output["api_outcomes"][0]["outcome"] == "success"
    assert output["after_status"] == ("observed" if observed_after else "unknown")
    assert output["after"] == progress.get("after", [])
    if observed_after:
        assert output["after"][0]["broken_out"] is True
        assert output["after"][0]["evidence"] == "post_action_discovery"
    else:
        assert output["after"] == []
    assert "Unexpected report-boundary failure" in output["msg"]
    assert len([call for call in sender.calls if call["verb"] == HttpVerbEnum.POST]) == 1
    assert len(sender.calls) == (4 if observed_after else 3)
    snapshot = captured["orchestrator"].report_snapshot
    snapshot["before"].clear()
    snapshot["api_outcomes"].clear()
    assert captured["orchestrator"].report_snapshot["before"] == progress["before"]
    assert captured["orchestrator"].report_snapshot["api_outcomes"] == progress["api_outcomes"]
    json.dumps(output)


@pytest.mark.parametrize("verify", [False, True])
@pytest.mark.parametrize("scenario", ["noop", "check_mode"])
@pytest.mark.parametrize("verbosity", [0, 3])
def test_unexpected_report_exception_after_read_only_workflow_does_not_imply_write_uncertainty(monkeypatch, verify, scenario, verbosity):
    parent = "Ethernet1/21"
    check_mode = scenario == "check_mode"
    baseline = topology(native=(parent,)) if check_mode else topology(parent)
    _, sender = _scripted_main(
        monkeypatch,
        [inventory(), baseline],
        _params(config=[group(parent)], verify={"enabled": verify}),
        verbosity=verbosity,
        check_mode=check_mode,
    )
    real_orchestrator = module_under_test.ManageBreakoutInterfacesOrchestrator
    captured = {}

    class InterruptedReadOnlyWorkflow(real_orchestrator):
        def run(self):
            captured["report"] = deepcopy(super().run())
            raise RuntimeError("Unexpected read-only report-boundary failure")

    monkeypatch.setattr(module_under_test, "ManageBreakoutInterfacesOrchestrator", InterruptedReadOnlyWorkflow)
    with pytest.raises(_Fail) as caught:
        module_under_test.main()
    output = caught.value.result
    assert output["failed"] is True
    assert output["changed"] is check_mode
    assert output["may_have_changed"] is False
    assert output["before"] == captured["report"]["before"]
    assert output["after"] == captured["report"]["after"]
    assert output["after_status"] == ("predicted" if check_mode else "unchanged")
    assert output["api_outcomes"][0]["outcome"] == ("planned" if check_mode else "noop")
    assert len(sender.calls) == 2
    assert all(call["verb"] == HttpVerbEnum.GET for call in sender.calls)


@pytest.mark.parametrize("verbosity", [0, 3])
def test_orchestrator_constructor_failure_has_no_mutation_uncertainty(monkeypatch, verbosity):
    _, sender = _scripted_main(monkeypatch, [], _params(), verbosity=verbosity)

    def constructor_failure(**unused):
        raise RuntimeError("Orchestrator construction failed before discovery")

    monkeypatch.setattr(module_under_test, "ManageBreakoutInterfacesOrchestrator", constructor_failure)
    with pytest.raises(_Fail) as caught:
        module_under_test.main()
    output = caught.value.result
    assert output["failed"] is True
    assert output["changed"] is False
    assert output["may_have_changed"] is False
    assert output["after_status"] == "unknown"
    assert output["before"] == output["after"] == output["diff"] == output["api_outcomes"] == []
    assert "construction failed before discovery" in output["msg"]
    assert sender.calls == []


@pytest.mark.parametrize("verify", [False, True])
@pytest.mark.parametrize("verbosity", [0, 3])
def test_parser_exception_after_post_preserves_baseline_without_fabricating_success(monkeypatch, verify, verbosity):
    existing, requested = "Ethernet1/21", "Ethernet1/23"
    _, sender = _scripted_main(
        monkeypatch,
        [inventory(), topology(existing, native=(requested,)), action(item(requested))],
        _params(config=[group(existing, requested)], verify={"enabled": verify}),
        verbosity=verbosity,
    )
    real_orchestrator = module_under_test.ManageBreakoutInterfacesOrchestrator

    class ParserFailureWorkflow(real_orchestrator):
        @staticmethod
        def match_action_results(response, submitted, action_name):
            raise RuntimeError("Unexpected parser failure before identified outcomes were established")

    monkeypatch.setattr(module_under_test, "ManageBreakoutInterfacesOrchestrator", ParserFailureWorkflow)
    with pytest.raises(_Fail) as caught:
        module_under_test.main()
    output = caught.value.result
    assert output["failed"] is True
    assert output["changed"] is False
    assert output["may_have_changed"] is True
    assert output["after_status"] == "unknown"
    assert output["after"] == []
    assert len(output["before"]) == 2
    assert output["diff"] == [group(requested)]
    assert all(row["outcome"] not in {"success", "planned"} for row in output["api_outcomes"])
    assert "Unexpected parser failure" in output["msg"]
    assert output["recovery"] == []
    writes = [call for call in sender.calls if call["verb"] == HttpVerbEnum.POST]
    assert len(writes) == 1
    assert writes[0]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": requested, "breakoutMap": "25g-4x"}]}
    assert len(sender.calls) == 3
    json.dumps(output)
