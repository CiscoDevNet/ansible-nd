# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Module wiring and full state/output contracts without live ND requests."""

import logging
from types import SimpleNamespace

import pytest
import yaml

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.module_failure import fail_from_exception
from ansible_collections.cisco.nd.plugins.module_utils.models.smart_switches_onboarding import SmartSwitchOnboardingModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.modules import nd_manage_smart_switches_onboarding as smart_module
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_smart_switches_onboarding import orchestrator, page, response, row


def run_state(state, rows, config, writes=(), check=False):
    instance = orchestrator([page(rows, len(rows), 0), *writes], state=state, check=check)
    prepared = instance.prepare_config_data(config)
    module = SimpleNamespace(params={"state": state, "config": config, "output_level": "normal"}, check_mode=check)
    return NDStateMachine(module, instance, config=prepared)


def test_supported_state_argspec_and_docs_match():
    spec = SmartSwitchOnboardingModel.get_argument_spec()
    docs = yaml.safe_load(smart_module.DOCUMENTATION)
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


def test_docs_distinguish_onboarding_results_from_bodyless_deboarding_completion():
    notes = " ".join(yaml.safe_load(smart_module.DOCUMENTATION)["notes"])
    assert "bodyless HTTP 202" in notes


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
        assert [(item["identifier"], item["operation"], item["effect_confirmed"]) for item in output["action_results"]] == [
            ("a", "delete", True),
            ("b", "delete", True),
        ]
    assert sm.removed.keys() == ["a", "b"]
    assert sm.model_orchestrator.rest_send.path.endswith("/smartSwitch/actions/remove")
    assert sm.model_orchestrator.rest_send.committed_payload == {"smartSwitchIntegrations": [{"switchId": "a"}, {"switchId": "b"}]}
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
    assert sm.model_orchestrator.rest_send.committed_payload == {"smartSwitchIntegrations": [{"switchId": "a"}, {"switchId": "b"}]}
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


def test_main_wires_prepared_config_once_and_uses_shared_failure_handler(monkeypatch):
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
        raise ValueError("preparation unavailable")

    monkeypatch.setattr(smart_module, "AnsibleModule", lambda **kwargs: module)
    monkeypatch.setattr(smart_module, "require_pydantic", lambda actual_module: None)
    monkeypatch.setattr(smart_module, "SmartSwitchOnboardingOrchestrator", construct_orchestrator)
    monkeypatch.setattr(smart_module, "fail_from_exception", fail_handler)
    with pytest.raises(StopMain):
        smart_module.main()
    assert events == ["orchestrator", "failure"]
