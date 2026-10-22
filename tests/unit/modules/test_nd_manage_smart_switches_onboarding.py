# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Module wiring and full state/output contracts without live ND requests."""

import logging
from copy import deepcopy
from types import SimpleNamespace

import pytest
import yaml

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.module_failure import fail_from_exception
from ansible_collections.cisco.nd.plugins.module_utils.models.smart_switches_onboarding.association import SmartSwitchOnboardingModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.modules import nd_manage_smart_switches_onboarding as smart_module
from ansible_collections.cisco.nd.tests.unit.module_utils.smart_switches_onboarding_helpers import orchestrator, page, response, row


def run_state(state, rows, config, writes=(), check=False, output_level="normal"):
    instance = orchestrator([page(rows, len(rows), 0), *writes], state=state, check=check)
    prepared = instance.prepare_config_data(config)
    module = SimpleNamespace(params={"state": state, "config": config, "output_level": output_level}, check_mode=check)
    return NDStateMachine(module, instance, config=prepared)


def test_supported_state_argspec_and_docs_match():
    spec = SmartSwitchOnboardingModel.get_argument_spec()
    docs = yaml.safe_load(smart_module.DOCUMENTATION)
    assert docs["version_added"] == "2.0.0"
    assert spec["state"]["choices"] == ["replaced", "overridden", "deleted"]
    assert docs["options"]["state"]["choices"] == spec["state"]["choices"]
    assert set(docs["options"]["config"]["suboptions"]) == set(spec["config"]["options"])
    assert spec["config"]["required"] is True
    for task in yaml.safe_load(smart_module.EXAMPLES):
        args = task["cisco.nd.nd_manage_smart_switches_onboarding"]
        assert args["state"] in spec["state"]["choices"]


def test_bulk_only_module_does_not_offer_undocumented_ticket_parameter(monkeypatch):
    class StopArguments(Exception):
        pass

    def construct_module(**kwargs):
        assert "ticket_id" not in kwargs["argument_spec"]
        assert "ticket_id" not in yaml.safe_load(smart_module.DOCUMENTATION)["options"]
        raise StopArguments

    monkeypatch.setattr(smart_module, "AnsibleModule", construct_module)
    with pytest.raises(StopArguments):
        smart_module.main()


def test_docs_describe_confirmed_effects_partial_failure_and_uncertainty():
    notes = " ".join(yaml.safe_load(smart_module.DOCUMENTATION)["notes"])
    assert "controller-confirmed" in notes
    assert "Partial success" in notes
    assert "Unknown" in notes
    assert "HTTP" not in notes
    assert "HTTP" not in yaml.safe_load(smart_module.RETURN)["failed"]["description"]


def test_return_documents_initialized_output_level_and_empty_debug_logs():
    returns = yaml.safe_load(smart_module.RETURN)
    assert returns["output_level"]["type"] == "str"
    assert returns["output_level"]["returned"] == "after state-machine initialization"
    assert returns["logs"]["type"] == "list"
    assert returns["logs"]["elements"] == "str"
    assert returns["logs"]["sample"] == []
    assert "debug" in returns["logs"]["returned"]
    assert "initialization" in returns["logs"]["returned"]
    assert "initialization" in returns["before"]["returned"]
    assert "initialization" in returns["proposed"]["returned"]


@pytest.mark.parametrize("level", ["normal", "info", "debug"])
@pytest.mark.parametrize("scenario", ["success", "mixed", "all_failed", "check", "noop", "unknown"])
def test_documented_return_types_and_output_levels(level, scenario):
    body = {
        "success": {"successResults": [{"name": "a"}, {"name": "b"}]},
        "mixed": {"successResults": [{"name": "a"}], "failureResults": [{"name": "b"}]},
        "all_failed": {"failureResults": [{"name": "a"}, {"name": "b"}]},
        "unknown": {"successResults": [{"name": "a"}]},
    }
    sm = run_state(
        "replaced",
        [row(key, "h" if scenario == "noop" else "") for key in ("a", "b")],
        [{"switch_id": key, "integration_name": "h"} for key in ("a", "b")],
        [response(body[scenario], 202)] if scenario in body else [],
        check=scenario == "check",
        output_level=level,
    )
    if scenario in {"mixed", "all_failed", "unknown"}:
        with pytest.raises(NDStateMachineError):
            sm.manage_state()
    else:
        sm.manage_state()
    output = sm.output.format()
    returns = yaml.safe_load(smart_module.RETURN)
    types = {"str": str, "bool": bool, "list": list, "dict": dict, "raw": (dict, list)}
    for key, value in output.items():
        assert key in returns
        assert isinstance(value, types[returns[key]["type"]])
        if returns[key].get("elements"):
            assert all(isinstance(item, types[returns[key]["elements"]]) for item in value)
    assert output["output_level"] == level
    assert ("proposed" in output) is (level in {"info", "debug"})
    assert ("logs" in output) is (level == "debug")
    if level == "debug":
        assert output["logs"] == []
    assert ("after" in output) is (scenario != "unknown")
    assert ("diff" in output) is (scenario != "unknown")
    assert output["after_status"] == ("unknown" if scenario == "unknown" else "planned" if scenario == "check" else "confirmed")
    if scenario in {"check", "noop"}:
        assert sm.model_orchestrator.rest_send.mutation_attempt_count == 0


@pytest.mark.parametrize("state", ["replaced", "overridden"])
def test_onboard_only_absent_associations_and_repeat_noop(state):
    config = [{"switch_id": "a", "integration_name": "h"}, {"switch_id": "b", "integration_name": "h"}]
    sm = run_state(state, [row("a"), row("b", "h")], config, [response({"successResults": [{"name": "a"}]}, 202)])
    sm.manage_state()
    output = sm.output.format()
    assert output["changed"] and not output["failed"]
    assert [item["identifier"] for item in output["action_results"]] == ["a"]
    assert len(sm.model_orchestrator.rest_send.responses) == 2
    repeat = run_state(state, [row("a", "h"), row("b", "h")], config)
    repeat.manage_state()
    assert not repeat.output.format()["changed"]
    assert repeat.output.format()["action_results"] == []
    assert len(repeat.model_orchestrator.rest_send.responses) == 1


@pytest.mark.parametrize("state,expected", [("replaced", ["a"]), ("deleted", ["a"]), ("overridden", [])])
def test_empty_collection_semantics(state, expected):
    writes = [response(None, 202)] if state == "overridden" else []
    sm = run_state(state, [row("a", "h")], [], writes)
    sm.manage_state()
    assert [item["switch_id"] for item in sm.output.format()["after"]] == expected
    assert sm.output.format()["changed"] is (state == "overridden")


def test_override_onboards_before_deboarding_omitted_associations():
    sm = run_state(
        "overridden",
        [row("a"), row("old", "h")],
        [{"switch_id": "a", "integration_name": "h"}],
        [response({"successResults": [{"name": "a"}]}, 202), response(None, 202)],
    )
    sm.manage_state()
    assert [item["switch_id"] for item in sm.output.format()["after"]] == ["a"]
    assert [(item["identifier"], item["operation"]) for item in sm.output.format()["action_results"]] == [("a", "create"), ("old", "delete")]


def test_changed_integration_fails_before_any_write():
    sm = run_state("overridden", [row("a"), row("b", "old")], [{"switch_id": "a", "integration_name": "h"}, {"switch_id": "b", "integration_name": "new"}])
    with pytest.raises(NDStateMachineError, match="update"):
        sm.manage_state()
    assert len(sm.model_orchestrator.rest_send.responses) == 1
    assert not sm.output.format()["changed"]
    assert [item["switch_id"] for item in sm.output.format()["after"]] == ["b"]


@pytest.mark.parametrize("successes,failures,changed,after", [(["a", "b"], [], True, ["a", "b"]), (["a"], ["b"], True, ["a"]), ([], ["a", "b"], False, [])])
def test_bulk_output_semantics(successes, failures, changed, after):
    body = {"successResults": [{"name": key} for key in successes], "failureResults": [{"name": key, "message": "refused"} for key in failures]}
    sm = run_state("replaced", [row("a"), row("b")], [{"switch_id": key, "integration_name": "h"} for key in ("a", "b")], [response(body, 202)])
    if failures:
        with pytest.raises(NDStateMachineError):
            sm.manage_state()
    else:
        sm.manage_state()
    for verbosity in (0, 2, 3):
        output = sm.output.format_with_verbosity(verbosity, sm.results)
        assert output["changed"] is changed
        assert output["failed"] is bool(failures)
        assert [item["switch_id"] for item in output["after"]] == after


def test_missing_result_and_transport_failure_do_not_publish_planned_state():
    for write in (response({"successResults": [{"name": "a"}]}, 202), response({"message": "controller unavailable"}, 500)):
        sm = run_state("replaced", [row("a"), row("b")], [{"switch_id": key, "integration_name": "h"} for key in ("a", "b")], [write])
        with pytest.raises(NDStateMachineError):
            sm.manage_state()
        output = sm.output.format()
        assert "after" not in output and "diff" not in output
        assert output["may_have_changed"]
        assert len(sm.model_orchestrator.rest_send.responses) == 2


def test_check_mode_no_mutation_and_planned_state_labeled():
    sm = run_state("overridden", [row("a"), row("old", "h")], [{"switch_id": "a", "integration_name": "h"}], check=True)
    sm.manage_state()
    output = sm.output.format()
    assert output["changed"] and output["after_status"] == "planned"
    assert [item["switch_id"] for item in output["after"]] == ["a"]
    assert output["action_results"] == []
    assert len(sm.model_orchestrator.rest_send.responses) == 1


def test_deleted_absent_and_omitted_are_noops():
    sm = run_state("deleted", [row("a", "h")], [{"switch_id": "missing"}])
    sm.manage_state()
    assert not sm.output.format()["changed"]
    assert [item["switch_id"] for item in sm.output.format()["after"]] == ["a"]


@pytest.mark.parametrize("state", ["deleted", "overridden"])
def test_multiple_deboards_use_one_bulk_request_and_repeat_as_noop(state):
    config = [{"switch_id": "a"}, {"switch_id": "b"}] if state == "deleted" else [{"switch_id": "retain", "integration_name": "h"}]
    sm = run_state(state, [row(key, "h") for key in ("a", "b", "retain")], config, [response({}, 202)])
    sm.manage_state()
    for verbosity in (0, 2, 3):
        output = sm.output.format_with_verbosity(verbosity, sm.results)
        assert output["changed"] and not output["failed"]
        assert output["after_status"] == "confirmed"
        assert [item["switch_id"] for item in output["after"]] == ["retain"]
        assert sorted((item["identifier"], item["operation"], item["effect_confirmed"]) for item in output["action_results"]) == [
            ("a", "delete", True),
            ("b", "delete", True),
        ]
    assert sorted(sm.removed.keys()) == ["a", "b"]
    assert sm.model_orchestrator.rest_send.path.endswith("/smartSwitch/actions/remove")
    payload = sm.model_orchestrator.rest_send.committed_payload
    assert set(payload) == {"smartSwitchIntegrations"}
    assert sorted(payload["smartSwitchIntegrations"], key=lambda item: item["switchId"]) == [{"switchId": "a"}, {"switchId": "b"}]
    assert len(sm.model_orchestrator.rest_send.responses) == 2
    repeat = run_state(state, [row("retain", "h")], config)
    repeat.manage_state()
    assert not repeat.output.format()["changed"]
    assert not repeat.output.format()["action_results"]
    assert len(repeat.model_orchestrator.rest_send.responses) == 1


def test_empty_override_deboards_every_association_in_one_request():
    sm = run_state("overridden", [row("a", "h"), row("b", "h")], [], [response(None, 202)])
    sm.manage_state()
    assert sm.output.format()["after"] == []
    payload = sm.model_orchestrator.rest_send.committed_payload
    assert set(payload) == {"smartSwitchIntegrations"}
    assert sorted(payload["smartSwitchIntegrations"], key=lambda item: item["switchId"]) == [{"switchId": "a"}, {"switchId": "b"}]
    assert len(sm.model_orchestrator.rest_send.responses) == 2


@pytest.mark.parametrize("write", [response({"message": "unavailable"}, 500), response({"successResults": [{"name": "a"}]}, 202)])
def test_unverified_deboard_omits_snapshot_and_does_not_fallback_or_replay(write):
    sm = run_state("deleted", [row("a", "h"), row("b", "h")], [{"switch_id": "a"}, {"switch_id": "b"}], [write])
    with pytest.raises(NDStateMachineError):
        sm.manage_state()
    output = sm.output.format_with_verbosity(3, sm.results)
    assert output["failed"] and not output["changed"] and output["may_have_changed"]
    assert "after" not in output and "diff" not in output
    assert output["unknown_identifiers"] == ["a", "b"]
    assert all(not item["effect_confirmed"] for item in output["action_results"])
    assert len(sm.model_orchestrator.rest_send.responses) == 2
    assert sm.removed.keys() == []


def test_bulk_deboard_failure_retains_earlier_onboarding_success_through_fail_json():
    sm = run_state(
        "overridden",
        [row("a"), row("b", "h"), row("c", "h")],
        [{"switch_id": "a", "integration_name": "h"}],
        [response({"successResults": [{"name": "a"}]}, 202), response({"message": "unavailable"}, 500)],
    )
    captured = {}

    class StopFailure(Exception):
        pass

    def fail_json(**kwargs):
        captured.update(kwargs)
        raise StopFailure

    sm.module.fail_json = fail_json
    try:
        sm.manage_state()
    except NDStateMachineError as error:
        with pytest.raises(StopFailure):
            fail_from_exception(sm.module, logging.getLogger("test"), sm, error)
    assert captured["changed"] and captured["failed"]
    assert [item["switch_id"] for item in captured["before"]] == ["b", "c"]
    assert "after" not in captured and "diff" not in captured
    assert captured["action_results"][0]["effect_confirmed"]
    assert [item["outcome"] for item in captured["action_results"]] == ["succeeded", "unknown", "unknown"]
    assert sm.confirmed.keys() == ["b", "c", "a"]
    assert sm.sent.keys() == ["a"] and sm.removed.keys() == []
    assert len(sm.model_orchestrator.rest_send.responses) == 3


def test_partial_onboarding_stops_before_bulk_deboarding():
    sm = run_state(
        "overridden",
        [row("a"), row("b"), row("old", "h")],
        [{"switch_id": key, "integration_name": "h"} for key in ("a", "b")],
        [response({"successResults": [{"name": "a"}], "failureResults": [{"name": "b"}]}, 202)],
    )
    with pytest.raises(NDStateMachineError):
        sm.manage_state()
    output = sm.output.format()
    assert output["changed"] and output["failed"]
    assert [item["switch_id"] for item in output["after"]] == ["old", "a"]
    assert output["planned_operations"][-1] == {"identifier": "old", "operation": "delete", "outcome": "not_attempted"}
    assert len(sm.model_orchestrator.rest_send.responses) == 2


def test_partial_fail_json_preserves_both_outcomes():
    sm = run_state(
        "replaced",
        [row("a"), row("b")],
        [{"switch_id": key, "integration_name": "h"} for key in ("a", "b")],
        [response({"successResults": [{"name": "a"}], "failureResults": [{"name": "b", "message": "refused"}]}, 202)],
    )
    captured = {}

    class StopFailure(Exception):
        pass

    def fail_json(**kwargs):
        captured.update(kwargs)
        raise StopFailure

    sm.module.fail_json = fail_json
    try:
        sm.manage_state()
    except NDStateMachineError as error:
        with pytest.raises(StopFailure):
            fail_from_exception(sm.module, logging.getLogger("test"), sm, error)
    assert captured["changed"] and captured["failed"]
    assert len(captured["action_results"]) == 2
    assert [item["switch_id"] for item in captured["after"]] == ["a"]


def test_main_orchestrator_construction_failure_uses_shared_failure_handler(monkeypatch):
    events = []
    module = SimpleNamespace(params={"state": "replaced", "config": [], "fabric_name": "fabric_1"}, check_mode=False)

    class StopMain(Exception):
        pass

    def fail_handler(actual_module, module_log, state_machine, error):
        assert actual_module is module and state_machine is None
        assert isinstance(error, ValueError)
        events.append("failure")
        raise StopMain

    def construct_orchestrator(**kwargs):
        events.append("orchestrator")
        raise ValueError("orchestrator unavailable")

    monkeypatch.setattr(smart_module, "AnsibleModule", lambda **kwargs: module)
    monkeypatch.setattr(smart_module, "require_pydantic", lambda actual_module: None)
    monkeypatch.setattr(smart_module, "SmartSwitchOnboardingOrchestrator", construct_orchestrator)
    monkeypatch.setattr(smart_module, "fail_from_exception", fail_handler)
    with pytest.raises(StopMain):
        smart_module.main()
    assert events == ["orchestrator", "failure"]


class MainExit(BaseException):
    """Model Ansible's process exit without entering main's exception handler."""

    def __init__(self, kind, output):
        super().__init__(kind)
        self.kind = kind
        self.output = output


def install_main_session(monkeypatch, instance, config, *, check=False, output_level="normal"):
    """Observe the real entrypoint/state machine with a recorded Smart transport."""
    module = SimpleNamespace(
        params={"state": "replaced", "config": config, "fabric_name": "fabric_1", "cluster_name": "cluster-a", "output_level": output_level},
        check_mode=check,
    )
    observed = SimpleNamespace(events=[], prepared=[], machines=[], failures=[])
    prepare = type(instance).prepare_config_data
    manage = NDStateMachine.manage_state

    def construct_orchestrator(**kwargs):
        observed.events.append("orchestrator")
        assert kwargs["fabric_name"] == "fabric_1"
        assert kwargs["cluster_name"] == "cluster-a"
        assert kwargs["rest_send"].check_mode is check
        return instance

    def prepare_once(self, raw):
        observed.events.append("prepare")
        assert self is instance and raw is config
        prepared = prepare(self, raw)
        observed.prepared.append(prepared)
        return prepared

    def construct_state_machine(actual_module, actual_orchestrator, *, config):
        observed.events.append("state_machine")
        assert actual_module is module and actual_orchestrator is instance
        assert config is observed.prepared[0]
        machine = NDStateMachine(actual_module, actual_orchestrator, config=config)
        observed.machines.append(machine)
        return machine

    def manage_state(self):
        observed.events.append("manage")
        return manage(self)

    def exit_json(**output):
        observed.events.append("exit")
        raise MainExit("exit", output)

    def fail_json(**output):
        observed.events.append("fail_json")
        # Real Ansible fail_json supplies these defaults for initialization errors.
        output.setdefault("changed", False)
        output["failed"] = True
        raise MainExit("fail", output)

    def fail_handler(actual_module, module_log, machine, error):
        observed.events.append("failure")
        observed.failures.append((machine, error))
        fail_from_exception(actual_module, module_log, machine, error)

    def construct_module(**kwargs):
        assert kwargs["supports_check_mode"] is True
        return module

    module.exit_json = exit_json
    module.fail_json = fail_json
    monkeypatch.setattr(smart_module, "AnsibleModule", construct_module)
    monkeypatch.setattr(smart_module, "require_pydantic", lambda actual_module: None)
    monkeypatch.setattr(smart_module, "setup_logging", lambda actual_module: None)
    monkeypatch.setattr(smart_module, "SmartSwitchOnboardingOrchestrator", construct_orchestrator)
    monkeypatch.setattr(type(instance), "prepare_config_data", prepare_once)
    monkeypatch.setattr(smart_module, "NDStateMachine", construct_state_machine)
    monkeypatch.setattr(NDStateMachine, "manage_state", manage_state)
    monkeypatch.setattr(smart_module, "fail_from_exception", fail_handler)
    return module, observed


@pytest.mark.parametrize("check", [False, True])
def test_real_main_prepares_once_passes_exact_copy_and_preserves_check_mode(monkeypatch, check):
    config = [{"switch_id": "a", "integration_name": "h"}]
    original = deepcopy(config)
    writes = [] if check else [response({"successResults": [{"name": "a"}]}, 202)]
    instance = orchestrator([page([row("a")], 1, 0), *writes], check=check)
    module, observed = install_main_session(monkeypatch, instance, config, check=check)
    with pytest.raises(MainExit) as stopped:
        smart_module.main()
    assert stopped.value.kind == "exit"
    assert observed.events == ["orchestrator", "prepare", "state_machine", "manage", "exit"]
    assert len(observed.prepared) == len(observed.machines) == 1
    assert observed.prepared[0] is not config
    assert observed.prepared[0][0]["switch_name"] == "leaf-a"
    assert module.params["config"] is config and config == original
    machine = observed.machines[0]
    assert machine.model_orchestrator is instance
    assert machine.check_mode is machine.results.check_mode is check
    assert instance.rest_send.check_mode is check
    assert instance.rest_send.mutation_attempt_count == (0 if check else 1)
    assert stopped.value.output["after_status"] == ("planned" if check else "confirmed")
    assert stopped.value.output["changed"] and not stopped.value.output["failed"]
    assert observed.failures == []


@pytest.mark.parametrize("phase", ["preparation", "initialization"])
def test_real_main_early_failures_pass_no_state_machine_to_real_handler(monkeypatch, phase):
    config = [{"switch_id": "missing", "integration_name": "h"}] if phase == "preparation" else [{"switch_id": "a"}]
    original = deepcopy(config)
    instance = orchestrator([page([row("a")], 1, 0)])
    module, observed = install_main_session(monkeypatch, instance, config)
    with pytest.raises(MainExit) as stopped:
        smart_module.main()
    assert stopped.value.kind == "fail"
    expected = ["orchestrator", "prepare"] + (["state_machine"] if phase == "initialization" else []) + ["failure", "fail_json"]
    assert observed.events == expected
    assert observed.machines == []
    assert observed.failures[0][0] is None
    assert isinstance(observed.failures[0][1], NDStateMachineError if phase == "initialization" else ValueError)
    assert module.params["config"] == original
    assert instance.rest_send.mutation_attempt_count == 0
    assert stopped.value.output["failed"] and not stopped.value.output["changed"]
    assert isinstance(stopped.value.output["msg"], str)
    assert not ({"before", "after", "diff", "output_level", "logs"} & stopped.value.output.keys())


@pytest.mark.parametrize("unknown", [False, True])
def test_real_main_failure_handler_retains_partial_success_and_uncertainty(monkeypatch, unknown):
    config = [{"switch_id": key, "integration_name": "h"} for key in ("a", "b")]
    original = deepcopy(config)
    body = {"successResults": [{"name": "a"}]}
    if not unknown:
        body["failureResults"] = [{"name": "b", "message": "refused"}]
    instance = orchestrator([page([row("a"), row("b")], 2, 0), response(body, 202)])
    module, observed = install_main_session(monkeypatch, instance, config, output_level="debug")
    with pytest.raises(MainExit) as stopped:
        smart_module.main()
    assert stopped.value.kind == "fail"
    assert observed.events == ["orchestrator", "prepare", "state_machine", "manage", "failure", "fail_json"]
    assert len(observed.prepared) == len(observed.machines) == 1
    assert observed.failures[0][0] is observed.machines[0]
    assert isinstance(observed.failures[0][1], NDStateMachineError)
    assert module.params["config"] == original
    assert instance.rest_send.mutation_attempt_count == 1
    output = stopped.value.output
    assert output["changed"] and output["failed"]
    assert isinstance(output["msg"], str)
    assert output["output_level"] == "debug" and output["logs"] == []
    assert [item["outcome"] for item in output["action_results"]] == ["succeeded", "unknown" if unknown else "failed"]
    assert [item["effect_confirmed"] for item in output["action_results"]] == [True, False]
    if unknown:
        assert "after" not in output and "diff" not in output
        assert output["unknown_identifiers"] == ["b"]
        assert output["may_have_changed"] and not output["reconciliation_complete"]
    else:
        assert [item["switch_id"] for item in output["after"]] == ["a"]
        assert [item["switch_id"] for item in output["diff"]["after"]] == ["a"]
        assert output["action_results"][1]["messages"] == ["refused"]
        assert not output["may_have_changed"] and output["reconciliation_complete"]
