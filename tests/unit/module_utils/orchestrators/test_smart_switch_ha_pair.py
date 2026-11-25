# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Pairing workflow against realistic Manage transport responses."""

from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.smart_switches_ha_pair.pairing import SmartSwitchHaPairModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_reconciliation import MutationOutcome
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.smart_switches_ha_pair import (
    SmartSwitchHaPairOrchestrator,
    normalize_ha_pair_action_response,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.smart_switch_ha_pair_helpers import (
    RecordingHaSender,
    action_response,
    controller_response,
    ha_switch_row,
    inventory_responses,
    pair_config,
    posted_action_payloads,
    recommendations_response,
)


# State machine and transport setup


def build_ha_state_machine(state, config, responses, *, check=False, cluster=None, version=None):
    """Exercise the real state machine and REST response handling with a scripted sender."""
    sender = RecordingHaSender(responses)
    params = {"state": state, "config": config, "check_mode": check}
    module = SimpleNamespace(params=params, check_mode=check)
    rest = RestSend(params)
    rest.sender = sender
    rest.response_handler = ResponseHandler()
    rest.unit_test = True
    rest.timeout = 1
    rest.controller_version = version
    orchestrator = SmartSwitchHaPairOrchestrator(rest_send=rest, fabric_name="test/fabric", cluster_name=cluster)
    return NDStateMachine(module, orchestrator), sender


# Inventory discovery and validation


def test_gathered_reads_to_empty_page_and_deduplicates_reciprocal_rows():
    pages = [
        controller_response(
            {"rows": [ha_switch_row("B", "A", "paired", topology="vpc", role="secondary"), ha_switch_row("E", "F", "unpaired", topology="vpc")]}
        ),
        controller_response(
            {"rows": [ha_switch_row("C", "D", "pairPending"), ha_switch_row("A", "B", "paired", topology="vpc"), ha_switch_row("G", status="unpairPending")]}
        ),
        controller_response({"rows": []}),
    ]
    machine, sender = build_ha_state_machine("gathered", None, pages, check=True, cluster="west & east")
    machine.manage_state()
    output = machine.output.format()
    assert output["gathered"] == [pair_config("A", "B"), pair_config("C", "D")]
    assert output["changed"] is False
    paths = [path for _verb, path, _payload in sender.calls]
    assert [parse_qs(urlsplit(path).query)["offset"][0] for path in paths] == ["0", "2", "5"]
    assert all("fabrics/test%2Ffabric/" in path and "clusterName=west%20%26%20east" in path for path in paths)
    assert not posted_action_payloads(sender.calls)


@pytest.mark.parametrize("state", ["replaced", "overridden", "deleted"])
def test_empty_fabric_is_idempotent(state):
    machine, sender = build_ha_state_machine(state, [], inventory_responses())
    machine.manage_state()
    assert machine.output.format()["changed"] is False
    assert len(sender.calls) == 1


def test_older_local_controller_rejected_and_routed_version_uses_target_read():
    with pytest.raises(NDStateMachineError, match="requires Nexus Dashboard 4.3.1"):
        build_ha_state_machine("gathered", None, [], version="4.2.1.87")
    machine, sender = build_ha_state_machine("gathered", None, inventory_responses(), cluster="target", version="4.2.1.87")
    machine.manage_state()
    assert machine.output.format()["gathered"] == []
    assert len(sender.calls) == 1


def test_page_limit_rejects_incomplete_inventory(monkeypatch):
    monkeypatch.setattr(SmartSwitchHaPairOrchestrator, "_PAGE_LIMIT", 2)
    with pytest.raises(NDStateMachineError, match="pagination exceeded"):
        build_ha_state_machine("overridden", [], [controller_response({"rows": [ha_switch_row("A")]}), controller_response({"rows": [ha_switch_row("B")]})])


@pytest.mark.parametrize(
    "responses, message",
    [
        ([controller_response({}, 404)], "Request failed"),
        ([controller_response({}, 204)], "Request failed"),
        ([controller_response({})], "rows"),
        ([controller_response({"rows": []}, 202)], "HTTP 200"),
        ([controller_response({"rows": [ha_switch_row("A")]}), controller_response({"rows": [ha_switch_row("A")]})], "repeat"),
        (inventory_responses(ha_switch_row("A", "B", "paired"), ha_switch_row("B", "C", "paired")), "Conflicting HA inventory"),
        (inventory_responses(ha_switch_row("A", "B", "paired"), ha_switch_row("C", "B", "paired")), "Conflicting HA inventory"),
        (inventory_responses(ha_switch_row("A", status="paired")), "requires a peer"),
        pytest.param(inventory_responses(ha_switch_row("A", "A", "paired")), "requires a peer with a different switch ID", id="self-peer"),
        (inventory_responses(ha_switch_row("A", status=None)), "missing haPaired"),
    ],
)
def test_read_failures_never_look_like_an_empty_fabric(responses, message):
    with pytest.raises(NDStateMachineError, match=message):
        build_ha_state_machine("overridden", [], responses)


@pytest.mark.parametrize("other", [ha_switch_row("B", "A", "pairPending", topology="vpc"), ha_switch_row("B", "A", "paired", topology="vpc", vpcDomain=2)])
def test_reciprocal_rows_with_contradictory_status_or_domain_fail(other):
    with pytest.raises(NDStateMachineError, match="Conflicting HA inventory"):
        build_ha_state_machine("gathered", None, inventory_responses(ha_switch_row("A", "B", "paired", topology="vpc"), other))


# Pair validation and check mode


@pytest.mark.parametrize("status", ["paired", "pairPending"])
def test_present_pair_in_reverse_order_skips_recommendations_and_mutations(status):
    machine, sender = build_ha_state_machine("replaced", [pair_config("B", "A")], inventory_responses(ha_switch_row("A", "B", status)))
    machine.manage_state()
    assert machine.output.format()["changed"] is False
    assert len(sender.calls) == 2


@pytest.mark.parametrize("check", [False, True])
def test_existing_pair_blocks_reassignment_before_eligibility_or_writes(check):
    machine, sender = build_ha_state_machine(
        "overridden", [pair_config("A", "C")], inventory_responses(ha_switch_row("A", "B", "paired"), ha_switch_row("C")), check=check
    )
    with pytest.raises(NDStateMachineError, match="already paired.*unpair"):
        machine.manage_state()
    assert len(sender.calls) == 2


def test_check_mode_reads_preflight_and_predicts_new_pair():
    machine, sender = build_ha_state_machine(
        "replaced",
        [pair_config("A", "B")],
        [*inventory_responses(ha_switch_row("A"), ha_switch_row("B")), recommendations_response(ha_switch_row("B"))],
        check=True,
    )
    machine.manage_state()
    assert not posted_action_payloads(sender.calls)
    output = machine.output.format()
    assert output["changed"] is True
    assert output["after_status"] == "planned"
    assert output["after"] == [pair_config("A", "B")]


@pytest.mark.parametrize(
    "inventory_rows, recommendation_responses, message",
    [
        pytest.param([ha_switch_row("A")], [], "not in the HA inventory", id="missing-switch"),
        pytest.param([ha_switch_row("A", "C", topology="vpc"), ha_switch_row("B")], [], "vPC peer", id="wrong-vpc-peer"),
        pytest.param(
            [ha_switch_row("A", status="unpairPending"), ha_switch_row("B", status="unpairPending")], [], "unpairPending", id="pending-standalone-unpair"
        ),
        pytest.param(
            [ha_switch_row("A"), ha_switch_row("B")], [recommendations_response(ha_switch_row("C"))], "not an eligible HA peer", id="unrecommended-peer"
        ),
        pytest.param(
            [ha_switch_row("A"), ha_switch_row("B")],
            [recommendations_response(ha_switch_row("B", topology="vpc"))],
            "not an eligible HA peer",
            id="recommended-peer-with-wrong-topology",
        ),
    ],
)
def test_ineligible_creates_fail_before_mutation(inventory_rows, recommendation_responses, message):
    responses = [*inventory_responses(*inventory_rows), *recommendation_responses]
    machine, sender = build_ha_state_machine("replaced", [pair_config("A", "B")], responses)
    with pytest.raises(NDStateMachineError, match=message):
        machine.manage_state()
    assert not posted_action_payloads(sender.calls)


def test_non_vpc_pairing_rejects_unpaired_row_that_still_has_peer_information():
    machine, sender = build_ha_state_machine("replaced", [pair_config("A", "B")], inventory_responses(ha_switch_row("A", "B")))
    with pytest.raises(NDStateMachineError, match="must be standalone"):
        machine.manage_state()
    assert not posted_action_payloads(sender.calls)


# Pair and unpair requests


def test_vpc_create_uses_controller_orientation_and_one_row():
    inventory_row = ha_switch_row("B", "A", topology="vpc", configStatus="outOfSync")
    expected_request_row = ha_switch_row("B", "A", topology="vpc")
    scripted = [*inventory_responses(inventory_row), recommendations_response(ha_switch_row("A", topology="vpc", role="secondary")), action_response(["B-A"])]
    machine, sender = build_ha_state_machine("replaced", [pair_config("A", "B")], scripted)
    machine.manage_state()
    assert posted_action_payloads(sender.calls) == [("haPair", {"rows": [expected_request_row]})]
    assert sender.calls[2][1].endswith("/B/haPairRecommendations")
    assert machine.output.format()["after"] == [pair_config("A", "B")]


@pytest.mark.parametrize("primary_first", [False, True])
def test_vpc_create_prefers_primary_from_reciprocal_inventory_rows(primary_first):
    primary = ha_switch_row("B", "A", topology="vpc", role="primary")
    secondary = ha_switch_row("A", "B", topology="vpc", role="secondary")
    inventory_rows = [primary, secondary] if primary_first else [secondary, primary]
    scripted = [
        *inventory_responses(*inventory_rows),
        recommendations_response(ha_switch_row("A", topology="vpc", role="secondary")),
        action_response(["B-A"]),
    ]
    machine, sender = build_ha_state_machine("replaced", [pair_config("A", "B")], scripted)
    machine.manage_state()
    assert posted_action_payloads(sender.calls) == [("haPair", {"rows": [primary]})]
    assert sender.calls[2][1].endswith("/B/haPairRecommendations")


def test_creates_use_one_request_per_pair_and_preflight_all_pairs_first():
    standalone = [ha_switch_row("A"), ha_switch_row("B"), ha_switch_row("C"), ha_switch_row("D")]
    scripted = [
        *inventory_responses(*standalone),
        recommendations_response(standalone[1]),
        recommendations_response(standalone[3]),
        action_response(["A", "B"]),
        action_response(["C-D"]),
    ]
    machine, sender = build_ha_state_machine("overridden", [pair_config("B", "A"), pair_config("D", "C")], scripted, cluster="one")
    machine.manage_state()
    assert posted_action_payloads(sender.calls) == [("haPair", {"rows": standalone[:2]}), ("haPair", {"rows": standalone[2:]})]
    assert [verb for verb, _path, _payload in sender.calls] == [HttpVerbEnum.GET] * 4 + [HttpVerbEnum.POST] * 2
    assert all("clusterName=one" in path for _verb, path, _payload in sender.calls)


def test_reversal_of_pending_vpc_unpair_uses_the_existing_orientation():
    current = ha_switch_row("A", "B", "unpairPending", topology="vpc")
    machine, sender = build_ha_state_machine("replaced", [pair_config("B", "A")], [*inventory_responses(current), action_response(["A-B"])])
    machine.manage_state()
    assert len(sender.calls) == 3
    assert posted_action_payloads(sender.calls) == [("haPair", {"rows": [current]})]


def test_unpair_can_cancel_pending_pair_without_deboarding():
    existing = ha_switch_row("B", "A", "pairPending")
    machine, sender = build_ha_state_machine(
        "deleted",
        [pair_config("A", "B")],
        [
            *inventory_responses(existing),
            action_response(["B-A"], rows=[ha_switch_row("A", status="unpairPending"), ha_switch_row("B", status="unpairPending")]),
        ],
    )
    machine.manage_state()
    assert posted_action_payloads(sender.calls) == [("haUnpair", {"rows": [existing]})]
    assert machine.output.format()["after"] == []
    repeat, sender = build_ha_state_machine(
        "deleted", [pair_config("A", "B")], inventory_responses(ha_switch_row("A", status="unpairPending"), ha_switch_row("B", status="unpairPending"))
    )
    repeat.manage_state()
    assert repeat.output.format()["changed"] is False
    assert not posted_action_payloads(sender.calls)


def test_direct_pair_commands_share_the_inventory_and_use_idempotent_queries():
    existing = ha_switch_row("A", "B", "paired")
    standalone = [ha_switch_row("C"), ha_switch_row("D")]
    scripted = [*inventory_responses(existing, *standalone), recommendations_response(standalone[1]), action_response(["C-D"]), action_response(["B-A"])]
    machine, sender = build_ha_state_machine("gathered", None, scripted)
    orchestrator = machine.model_orchestrator
    present = SmartSwitchHaPairModel(**pair_config("B", "A"))
    absent = SmartSwitchHaPairModel(**pair_config("D", "C"))
    assert orchestrator.query_one(present) == pair_config("A", "B")
    assert orchestrator.query_one(absent) == {}
    assert orchestrator.delete(absent).outcomes == ()
    assert orchestrator.create(absent).outcomes[0].outcome is MutationOutcome.SUCCEEDED
    assert orchestrator.delete(present).outcomes[0].outcome is MutationOutcome.SUCCEEDED
    with pytest.raises(NotImplementedError, match="in-place update"):
        orchestrator.update(present)
    assert len(sender.calls) == 5


# Mutation failure and outcome tracking


def test_bulk_override_retains_success_only_on_partial_unpair():
    existing = [ha_switch_row("B", "A", "paired"), ha_switch_row("C", "D", "paired", topology="vpc")]
    machine, sender = build_ha_state_machine("overridden", [], [*inventory_responses(*existing), action_response(["A-B"], ["D-C"])])
    with pytest.raises(NDStateMachineError):
        machine.manage_state()
    assert posted_action_payloads(sender.calls) == [("haUnpair", {"rows": existing})]
    output = machine.output.format()
    assert output["changed"] is True
    assert output["after"] == [pair_config("C", "D")]
    assert {result["identifier"]: result["outcome"] for result in output["action_results"]} == {("A", "B"): "succeeded", ("C", "D"): "failed"}


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(action_response(["A"]), id="incomplete-peer-evidence"),
        pytest.param(controller_response({"rows": []}, 202), id="missing-results"),
        pytest.param(action_response(["A-B"], ["B-A"]), id="conflicting-results"),
        pytest.param(controller_response({"error": "error"}, 500), id="server-error"),
        pytest.param(ConnectionError("response lost"), id="lost-response"),
    ],
)
def test_inconclusive_unpair_hides_after_and_never_replays(failure):
    machine, sender = build_ha_state_machine("deleted", [pair_config("A", "B")], [*inventory_responses(ha_switch_row("A", "B", "paired")), failure])
    with pytest.raises(NDStateMachineError):
        machine.manage_state()
    assert len(posted_action_payloads(sender.calls)) == 1
    output = machine.output.format()
    assert not output["changed"]
    assert output["may_have_changed"] is True
    assert output["reconciliation_complete"] is False
    assert output["after_status"] == "unknown"
    assert "after" not in output and "diff" not in output
    assert output["unknown_identifiers"] == [("A", "B")]


@pytest.mark.parametrize(
    "code, expected_outcome",
    [(200, "unknown"), (204, "unknown"), (400, "unknown"), (401, "failed"), (403, "failed"), (404, "failed")],
)
def test_action_protocol_error_and_definite_refusals_remain_distinct(code, expected_outcome):
    machine, sender = build_ha_state_machine(
        "deleted", [pair_config("A", "B")], [*inventory_responses(ha_switch_row("A", "B", "paired")), controller_response({}, code)]
    )
    with pytest.raises(NDStateMachineError):
        machine.manage_state()
    output = machine.output.format()
    assert len(posted_action_payloads(sender.calls)) == 1
    assert output["changed"] is False
    assert output["action_results"][0]["outcome"] == expected_outcome
    if expected_outcome == "failed":
        assert output["after"] == [pair_config("A", "B")]
    else:
        assert "after" not in output


# Switch-scoped deployment


def test_empty_switch_deployment_skips_controller_request():
    machine, sender = build_ha_state_machine("gathered", None, inventory_responses())
    orchestrator = machine.model_orchestrator
    previous_calls = sender.calls.copy()
    assert orchestrator.deploy_switch_ids(orchestrator.fabric_name, []) is None
    assert sender.calls == previous_calls


# Pair and unpair response evidence


@pytest.mark.parametrize(
    "bad_report, message",
    [
        ({"rows": [], "results": {"successResults": "invalid", "failureResults": [{"name": "C-D"}]}}, "must be an array"),
        ({"results": {"successResults": [{"name": "A-B"}]}}, "rows array"),
        ({"rows": [], "results": {"successResults": [{}, "C-D", {"name": "A-B", "status": "other"}]}}, "Malformed HA result"),
        ({"rows": [], "results": {"successResults": [{"name": "A-B", "status": "failed"}]}}, "contradicts"),
        ([], "results object"),
    ],
)
def test_action_result_protocol_errors_have_diagnostics(bad_report, message):
    result = normalize_ha_pair_action_response(bad_report, [("A", "B"), ("C", "D")])
    assert any(message in error for error in result.protocol_errors)


def test_malformed_and_ambiguous_keys_never_override_independent_evidence():
    body = action_response(["A-B-C", "D-E"])["DATA"]
    body["results"]["failureResults"].append({"name": "F-G", "message": 12})
    result = normalize_ha_pair_action_response(body, [("A", "B-C"), ("A-B", "C"), ("D", "E"), ("F", "G")])
    outcomes_by_pair = {item.identifier: item for item in result.outcomes}
    assert {pair: item.outcome for pair, item in outcomes_by_pair.items()} == {
        ("A", "B-C"): MutationOutcome.UNKNOWN,
        ("A-B", "C"): MutationOutcome.UNKNOWN,
        ("D", "E"): MutationOutcome.SUCCEEDED,
        ("F", "G"): MutationOutcome.UNKNOWN,
    }
    assert any("ambiguous" in error for error in result.protocol_errors)
    assert any("Malformed HA result" in error for error in result.protocol_errors)
    confirmed_pair = outcomes_by_pair[("D", "E")]
    assert confirmed_pair.statuses == ("success",)
    assert confirmed_pair.messages == ("accepted",)
    assert confirmed_pair.evidence == ({"source": "successResults", "returned_name": "D-E"},)


def test_both_peer_failures_are_conclusive_even_without_optional_status():
    body = {"rows": [], "results": {"failureResults": [{"name": "A"}, {"name": "B"}]}}
    result = normalize_ha_pair_action_response(body, [("A", "B")])
    assert not result.protocol_errors
    assert result.outcomes[0].outcome is MutationOutcome.FAILED
    assert not result.outcomes[0].statuses
