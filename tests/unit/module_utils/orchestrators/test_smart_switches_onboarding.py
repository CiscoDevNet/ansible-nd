# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Smart API evidence is correlated by exact switchId, never order or message."""

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.smart_switches_onboarding import SmartSwitchOnboardingModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_reconciliation import MutationOutcome
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.smart_switches_onboarding import (
    SmartSwitchOnboardingOrchestrator,
    SmartSwitchOnboardingResponseAdapter,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture


def test_schema_shaped_fixture_read_and_confirmed_wrapper_evidence():
    fixture = load_fixture("test_smart_switches_onboarding")
    instance = orchestrator([fixture["inventory"], fixture["mixed_onboarding"]])
    assert [item["switchId"] for item in instance.query_all()] == ["b"]
    models = [SmartSwitchOnboardingModel(switch_id=key, switch_name=f"leaf-{key}", integration_name="hypershield") for key in ("a", "b")]
    outcome = instance.create_bulk(models)
    assert [item.outcome for item in outcome.outcomes] == [MutationOutcome.SUCCEEDED, MutationOutcome.FAILED]


def response(data, code=200):
    return {"RETURN_CODE": code, "MESSAGE": "OK", "DATA": data}


def row(key, integration="", name=None, smart=True, alias="additionalData"):
    return {
        "switchId": key,
        "hostname": name or f"leaf-{key}",
        "fabricName": "fabric_1",
        alias: {"smartSwitch": smart, "hypershieldIntegrationName": integration},
    }


def page(rows, total=None, remaining=None):
    data = {"switches": rows}
    if total is not None:
        data["meta"] = {"counts": {"total": total, "remaining": remaining}}
    return response(data)


def orchestrator(responses, state="replaced", check=False):
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(iter(responses))
    rest = RestSend({"check_mode": check, "state": state})
    rest.sender = sender
    rest.response_handler = ResponseHandler()
    rest.unit_test = True
    rest.timeout = 1
    results = Results()
    results.state = state
    results.check_mode = check
    return SmartSwitchOnboardingOrchestrator(rest_send=rest, results=results, fabric_name="fabric_1")


@pytest.mark.parametrize(
    "body,expected,errors",
    [
        ({"successResults": [{"name": "b"}, {"name": "a"}]}, ["succeeded", "succeeded"], False),
        ({"failureResults": [{"name": "a"}, {"name": "b"}]}, ["failed", "failed"], False),
        ({"successResults": [{"name": "a"}], "failureResults": [{"name": "b", "message": "controller failure"}]}, ["succeeded", "failed"], False),
        ({}, ["unknown", "unknown"], False),
        ({"successResults": [{"name": "a"}]}, ["succeeded", "unknown"], False),
        ({"successResults": [{"name": "a"}, {"name": "unexpected"}]}, ["succeeded", "unknown"], True),
        ({"successResults": [{"name": "A"}]}, ["unknown", "unknown"], True),
        ({"successResults": None}, ["unknown", "unknown"], True),
        ({"successResults": [{"name": "a"}, None]}, ["succeeded", "unknown"], True),
        ({"successResults": [{"name": "a"}, {"name": "a"}], "failureResults": [{"name": "b"}]}, ["succeeded", "failed"], False),
        ({"successResults": [{"name": "a"}], "failureResults": [{"name": "a"}, {"name": "b"}]}, ["unknown", "failed"], True),
    ],
)
def test_response_contract(body, expected, errors):
    result = SmartSwitchOnboardingResponseAdapter.normalize(body, ("a", "b"))
    assert [item.outcome.value for item in result.outcomes] == expected
    assert bool(result.protocol_errors) is errors


def test_duplicate_evidence_preserved_and_message_never_matches_identity():
    result = SmartSwitchOnboardingResponseAdapter.normalize(
        {"failureResults": [{"name": "a", "message": "first"}, {"name": "a", "message": "second"}], "successResults": [{"message": "b succeeded"}]}, ("a", "b")
    )
    assert result.outcomes[0].messages == ("first", "second")
    assert result.outcomes[1].outcome is MutationOutcome.UNKNOWN
    assert len(result.outcomes[0].evidence) == 2


def test_wrapper_validation_preserves_success_beside_malformed_entry():
    body = {"successResults": [{"name": "a"}], "failureResults": [{"name": "b", "status": 12}]}
    result = SmartSwitchOnboardingResponseAdapter.normalize(body, ("a", "b"))
    assert [item.outcome for item in result.outcomes] == [MutationOutcome.SUCCEEDED, MutationOutcome.UNKNOWN]
    assert result.protocol_errors


def test_wrapper_validation_preserves_failure_beside_malformed_success_list():
    result = SmartSwitchOnboardingResponseAdapter.normalize({"successResults": None, "failureResults": [{"name": "b", "message": "refused"}]}, ("a", "b"))
    assert [item.outcome for item in result.outcomes] == [MutationOutcome.UNKNOWN, MutationOutcome.FAILED]
    assert result.outcomes[1].messages == ("refused",)
    assert result.protocol_errors


def test_partial_http_body_is_preserved_and_payload_is_wrapped():
    body = {"successResults": [{"name": "a"}], "failureResults": [{"name": "b", "status": "futureStatus", "message": "refused"}]}
    instance = orchestrator([response(body, 202)])
    models = [SmartSwitchOnboardingModel(switch_id=key, switch_name=f"leaf-{key}", integration_name="hypershield") for key in ("a", "b")]
    result = instance.create_bulk(models)
    assert result.outcomes[0].outcome is MutationOutcome.SUCCEEDED
    assert result.outcomes[1].outcome is MutationOutcome.FAILED
    assert instance.rest_send.response_current["DATA"] == body
    assert instance.rest_send.committed_payload == {"smartSwitchIntegrations": [model.to_payload() for model in models]}
    assert instance.results.responses[-1]["DATA"] == body


def test_paginated_inventory_is_cached_and_preparation_does_not_mutate_input():
    instance = orchestrator([page([row("a")], 2, 1), page([row("b", "existing", alias="additionalSwitchData")], 2, 0)])
    raw = [{"switch_id": "a", "integration_name": "hypershield"}]
    original = deepcopy(raw)
    prepared = instance.prepare_config_data(raw)
    assert prepared[0]["switch_name"] == "leaf-a"
    assert raw == original
    assert instance.query_all() == [{"switchId": "b", "switchName": "leaf-b", "integrationName": "existing"}]
    assert len(instance.rest_send.responses) == 2
    assert "offset=1" in instance.rest_send.path


def test_short_page_without_metadata_requires_empty_page():
    instance = orchestrator([page([row("a")]), page([])])
    assert instance.query_all() == []
    assert len(instance.rest_send.responses) == 2


@pytest.mark.parametrize(
    "bad",
    [
        {"switchId": "a", "fabricName": "other", "additionalData": {"smartSwitch": True, "hypershieldIntegrationName": ""}},
        {"switchId": "a", "additionalData": {"smartSwitch": True}},
        {"switchId": "a", "additionalData": {"smartSwitch": True, "hypershieldIntegrationName": None}},
        {
            "switchId": "a",
            "additionalData": {"smartSwitch": True, "hypershieldIntegrationName": ""},
            "additionalSwitchData": {"smartSwitch": True, "hypershieldIntegrationName": "other"},
        },
    ],
)
def test_ambiguous_inventory_rejected_before_writes(bad):
    instance = orchestrator([page([bad], 1, 0)])
    with pytest.raises(ValueError):
        instance.query_all()


@pytest.mark.parametrize(
    "pages", [[page([row("a")], 2, 1), page([row("a")], 2, 0)], [page([row("a")], 2, 1), page([], 2, 1)], [page([row("a")], 2, 1), page([row("b")], 3, 0)]]
)
def test_incomplete_or_unstable_inventory_rejected(pages):
    with pytest.raises(ValueError):
        orchestrator(pages).query_all()


@pytest.mark.parametrize(
    "raw",
    [
        [{"switch_id": "missing", "integration_name": "h"}],
        [{"switch_id": "a", "switch_name": "wrong", "integration_name": "h"}],
        [{"switch_id": "a", "integration_name": "h"}, {"switch_id": "a", "integration_name": "h"}],
    ],
)
def test_input_identity_guards(raw):
    with pytest.raises(ValueError):
        orchestrator([page([row("a")], 1, 0)]).prepare_config_data(raw)


def test_not_smart_and_different_integration_rejected():
    instance = orchestrator([page([row("a", smart=False)], 1, 0)])
    with pytest.raises(ValueError, match="Smart"):
        instance.prepare_config_data([{"switch_id": "a", "integration_name": "h"}])
    instance = orchestrator([page([row("a", "old")], 1, 0)])
    instance.query_all()
    with pytest.raises(ValueError, match="update"):
        instance.preflight([SmartSwitchOnboardingModel(switch_id="a", integration_name="new", switch_name="leaf-a")])
    with pytest.raises(NotImplementedError):
        instance.update(SmartSwitchOnboardingModel(switch_id="a"))


def test_deleted_absent_switch_and_single_deboard_uses_bulk_action():
    instance = orchestrator([page([], 0, 0)], state="deleted")
    assert instance.prepare_config_data([{"switch_id": "missing"}]) == [{"switch_id": "missing"}]
    instance = orchestrator([response(None, 202)], state="deleted")
    result = instance.delete(SmartSwitchOnboardingModel(switch_id="a"))
    assert result.outcomes[0].outcome is MutationOutcome.SUCCEEDED
    assert instance.rest_send.path.endswith("/smartSwitch/actions/remove")
    assert instance.rest_send.committed_payload == {"smartSwitchIntegrations": [{"switchId": "a"}]}


@pytest.mark.parametrize("body", [None, {}])
def test_bodyless_bulk_deboard_confirms_each_requested_effect(body):
    instance = orchestrator([response(body, 202)], state="deleted")
    instance.cluster_name = "cluster+a"
    assert instance.supports_bulk_delete
    models = [SmartSwitchOnboardingModel(switch_id=key, switch_name=f"leaf-{key}", integration_name="h") for key in ("a", "b")]
    result = instance.delete_bulk(models)
    assert [(item.identifier, item.outcome) for item in result.outcomes] == [("a", MutationOutcome.SUCCEEDED), ("b", MutationOutcome.SUCCEEDED)]
    assert instance.rest_send.path.endswith("/smartSwitch/actions/remove?clusterName=cluster%2Ba")
    assert instance.rest_send.committed_payload == {"smartSwitchIntegrations": [{"switchId": "a"}, {"switchId": "b"}]}
    assert len(instance.rest_send.responses) == 1
    assert instance.results.responses[-1]["DATA"] == body
    assert all(item.evidence[0]["match"] == "bulk_request_completion" for item in result.outcomes)


@pytest.mark.parametrize("body,code", [({"message": "accepted"}, 202), ([], 202), ("unrecognized", 202), (None, 200), (None, 204)])
def test_unverified_bulk_deboard_response_is_not_confirmation(body, code):
    instance = orchestrator([response(body, code)], state="deleted")
    result = instance.delete_bulk([SmartSwitchOnboardingModel(switch_id="a")])
    assert not result.outcomes
    assert result.protocol_errors
    assert instance.results.responses[-1]["DATA"] == body


def test_bulk_deboard_empty_or_duplicate_requests_never_write():
    instance = orchestrator([], state="deleted")
    assert not instance.delete_bulk([]).outcomes
    with pytest.raises(ValueError, match="Duplicate"):
        instance.delete_bulk([SmartSwitchOnboardingModel(switch_id="a"), SmartSwitchOnboardingModel(switch_id="a")])
    assert not instance.rest_send.responses
