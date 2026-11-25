# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Module entry point, state contract and config action integration."""

import json
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml
from ansible.module_utils import basic

from ansible_collections.cisco.nd.plugins.module_utils.models.smart_switches_ha_pair.pairing import SmartSwitchHaPairModel
from ansible_collections.cisco.nd.plugins.modules import nd_manage_smart_switches_ha_pair as ha_module
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

# Module invocation


def invoke_ha_module(monkeypatch, capsys, responses=(), **module_args):
    """Run the Ansible entry point and record every scripted controller call."""
    params = {"fabric_name": "HA/Fabric", "cluster_name": "remote & west", **module_args}
    monkeypatch.setattr(basic, "_ANSIBLE_ARGS", json.dumps({"ANSIBLE_MODULE_ARGS": params}).encode())
    monkeypatch.setattr(basic, "_ANSIBLE_PROFILE", "legacy", raising=False)
    sender = RecordingHaSender(responses)
    monkeypatch.setattr(ha_module, "Sender", lambda: sender)
    with pytest.raises(SystemExit) as module_exit:
        ha_module.main()
    result = json.loads(capsys.readouterr().out)
    assert module_exit.value.code == int(result.get("failed", False))
    assert len(sender.calls) == len(responses), f"Expected {len(responses)} controller requests, observed {sender.calls!r}"
    return result, sender.calls


# Module arguments and documentation


def test_documentation_matches_public_argspec_and_covers_each_state():
    doc = yaml.safe_load(ha_module.DOCUMENTATION)
    spec = SmartSwitchHaPairModel.get_argument_spec()
    assert doc["options"]["state"]["choices"] == spec["state"]["choices"]
    assert set(doc["options"]["config"]["suboptions"]) == set(spec["config"]["options"])
    examples = yaml.safe_load(ha_module.EXAMPLES)
    assert set(spec["state"]["choices"]) <= {task["cisco.nd.nd_manage_smart_switches_ha_pair"]["state"] for task in examples}
    returns = yaml.safe_load(ha_module.RETURN)
    assert {"gathered", "config_actions_result", "action_results", "after_status", "unknown_identifiers"} <= returns.keys()


@pytest.mark.parametrize(
    "args, message",
    [
        ({"state": "overridden"}, "config"),
        ({"state": "deleted"}, "config"),
        ({"state": "replaced"}, "config"),
        ({"state": "overridden", "config": None}, "config"),
        ({"state": "gathered", "config": [pair_config("A", "B")]}, "gather-all"),
        ({"state": "gathered", "config_actions": {"save": True}}, "not allowed"),
        ({"state": "gathered", "config_actions": {"save": True, "deploy": True}}, "not allowed"),
        ({"state": "gathered", "config_actions": {}}, "cannot be empty"),
        ({"state": "replaced", "config": [], "config_actions": {"deploy": True}}, "requires"),
        ({"state": "replaced", "config": [], "config_actions": {"type": "resource"}}, "must be one of"),
        ({"state": "deleted", "config": [dict(pair_config("A", "B"), deploy=True)]}, "deploy"),
        ({"state": "replaced", "config": [pair_config("A", "A")]}, "distinct"),
        ({"state": "replaced", "config": [pair_config("A", "B"), pair_config("B", "A")]}, "multiple"),
        ({"state": "deleted", "config": [pair_config("A", "B"), pair_config("C", "A")]}, "multiple"),
        pytest.param({"state": "gathered", "cluster_name": ""}, "cluster_name", id="empty-cluster-name"),
    ],
)
def test_invalid_arguments_fail_before_controller_access(monkeypatch, capsys, args, message):
    result, calls = invoke_ha_module(monkeypatch, capsys, **args)
    assert result["failed"] is True
    assert message in result["msg"]
    assert not calls


# Gathered state and staged changes


@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check-mode"])
@pytest.mark.parametrize(
    "gather_args",
    [pytest.param({}, id="omitted-config"), pytest.param({"config": [], "config_actions": {"save": False, "deploy": False}}, id="empty-config")],
)
def test_gathered_round_trip_preserves_intent_and_sends_no_writes(monkeypatch, capsys, check_mode, gather_args):
    pending = ha_switch_row("B", "A", "pairPending")
    result, calls = invoke_ha_module(
        monkeypatch,
        capsys,
        inventory_responses(pending),
        state="gathered",
        _ansible_check_mode=check_mode,
        **gather_args,
    )
    assert result["gathered"] == [pair_config("A", "B")]
    assert result["changed"] is False
    assert "config_actions_result" not in result
    assert not posted_action_payloads(calls)
    replay, calls = invoke_ha_module(monkeypatch, capsys, inventory_responses(pending), state="replaced", config=result["gathered"])
    assert replay["changed"] is False
    assert not posted_action_payloads(calls)


@pytest.mark.parametrize("state", ["replaced", "deleted"])
def test_default_staging_performs_only_the_pair_action(monkeypatch, capsys, state):
    creating = state == "replaced"
    rows = [ha_switch_row("A"), ha_switch_row("B")] if creating else [ha_switch_row("A", "B", "paired")]
    responses = [*inventory_responses(*rows), *([recommendations_response(ha_switch_row("B"))] if creating else []), action_response(["A-B"])]
    result, calls = invoke_ha_module(monkeypatch, capsys, responses, state=state, config=[pair_config("A", "B")])
    assert result["changed"] is True
    assert result["after"] == ([pair_config("A", "B")] if creating else [])
    assert [step for step, _payload in posted_action_payloads(calls)] == ["haPair" if creating else "haUnpair"]


# Configuration save and deployment


@pytest.mark.parametrize(
    "last_peer_result",
    [
        pytest.param({"switchId": "D", "status": "success"}, id="all-peers-deployed"),
        pytest.param({"switchId": "D", "status": "notExecuted", "message": "No Commands to execute"}, id="one-peer-already-in-sync"),
    ],
)
def test_override_and_routed_switch_deploy_covers_both_peers_of_changed_pairs(monkeypatch, capsys, last_peer_result):
    kept = ha_switch_row("E", "F", "paired")
    removed = ha_switch_row("A", "B", "paired", topology="vpc")
    switch_deploy_results = [{"switchId": serial, "status": "success"} for serial in "ABC"]
    switch_deploy_results.append(last_peer_result)
    responses = [
        *inventory_responses(kept, removed, ha_switch_row("C"), ha_switch_row("D")),
        recommendations_response(ha_switch_row("D")),
        action_response(["C-D"]),
        action_response(["A-B"]),
        controller_response({"status": "saved"}),
        controller_response({"switchIds": switch_deploy_results}, 207),
    ]
    result, calls = invoke_ha_module(
        monkeypatch,
        capsys,
        responses,
        state="overridden",
        config=[pair_config("C", "D"), pair_config("E", "F")],
        config_actions={"save": True, "deploy": True},
    )
    assert result["changed"] is True
    config_actions_result = result["config_actions_result"]
    assert config_actions_result["status"] == "completed"
    assert config_actions_result["targets"]["switches"] == list("ABCD")
    assert config_actions_result["actions"][-1]["response"]["switchIds"] == switch_deploy_results
    assert result["after"] == [pair_config("E", "F"), pair_config("C", "D")]
    posted_actions = posted_action_payloads(calls)
    assert [step for step, _payload in posted_actions] == ["haPair", "haUnpair", "configSave", "deploy"]
    assert posted_actions[-1] == ("deploy", {"switchIds": list("ABCD")})
    request_urls = [urlsplit(path) for _verb, path, _payload in calls]
    assert request_urls[-1].path.endswith("/switchActions/deploy")
    assert all(parse_qs(url.query)["clusterName"] == ["remote & west"] and not url.path.endswith("/switches") for url in request_urls)


@pytest.mark.parametrize("deploy", [False, True])
def test_save_only_and_explicit_global_scope(monkeypatch, capsys, deploy):
    current = [ha_switch_row("A", "B", "paired")]
    responses = [*inventory_responses(*current), action_response(["A-B"]), controller_response({"status": "saved"})]
    if deploy:
        responses.append(controller_response({"status": "deployed"}))
    result, calls = invoke_ha_module(
        monkeypatch, capsys, responses, state="deleted", config=[pair_config("A", "B")], config_actions={"save": True, "deploy": deploy, "type": "global"}
    )
    assert result["config_actions_result"]["status"] == "completed"
    assert [step for step, _payload in posted_action_payloads(calls)] == (["haUnpair", "configSave", "deploy"] if deploy else ["haUnpair", "configSave"])
    if deploy:
        assert "/actions/deploy?" in calls[-1][1]
        assert not calls[-1][2]


def test_check_mode_includes_config_action_preview(monkeypatch, capsys):
    result, calls = invoke_ha_module(
        monkeypatch,
        capsys,
        inventory_responses(ha_switch_row("A", "B", "paired")),
        state="deleted",
        config=[pair_config("B", "A")],
        config_actions={"save": True, "deploy": True},
        _ansible_check_mode=True,
    )
    assert result["after_status"] == "planned"
    config_actions_result = result["config_actions_result"]
    assert config_actions_result["status"] == "planned"
    assert config_actions_result["targets"]["switches"] == ["A", "B"]
    assert [step["action"] for step in config_actions_result["actions"]] == ["save", "deploy"]
    assert not posted_action_payloads(calls)


def test_noop_skips_even_explicit_config_actions(monkeypatch, capsys):
    result, calls = invoke_ha_module(
        monkeypatch,
        capsys,
        inventory_responses(ha_switch_row("A", "B", "paired")),
        config=[pair_config("B", "A")],
        config_actions={"save": True, "deploy": True},
    )
    assert result["changed"] is False
    assert "config_actions_result" not in result
    assert not posted_action_payloads(calls)


# Failure handling


@pytest.mark.parametrize(
    "failed_response, failure_step, error_fragment",
    [
        pytest.param(controller_response({"error": "save failed"}, 500), "save", "save failed", id="save-http-error"),
        pytest.param(
            controller_response({"switchIds": [{"switchId": "A", "status": "success"}, {"switchId": "B", "status": "failed"}]}, 207),
            "deploy",
            "failed",
            id="failed-peer",
        ),
        pytest.param(
            controller_response({"switchIds": [{"switchId": "A", "status": "success"}]}, 207),
            "deploy",
            "does not cover every requested HA peer",
            id="missing-peer",
        ),
        pytest.param(
            controller_response({"switchIds": [{"switchId": "A", "status": "success"}, {"switchId": "C", "status": "success"}]}, 207),
            "deploy",
            "does not cover every requested HA peer",
            id="unexpected-peer",
        ),
        pytest.param(controller_response({}, 207), "deploy", "Expected HTTP 207 with per-switch deployment results", id="missing-results"),
        pytest.param(
            controller_response({"switchIds": [{"switchId": "A", "status": "success"}, {"switchId": "B", "status": "success"}]}, 200),
            "deploy",
            "Expected HTTP 207 with per-switch deployment results",
            id="wrong-status-code",
        ),
    ],
)
def test_config_action_failure_keeps_accepted_intent_and_is_not_retried(monkeypatch, capsys, failed_response, failure_step, error_fragment):
    responses = [*inventory_responses(ha_switch_row("A", "B", "paired")), action_response(["A-B"])]
    expected_post_actions = ["haUnpair", "configSave"]
    if failure_step == "deploy":
        responses.append(controller_response({"status": "saved"}))
        expected_post_actions.append("deploy")
    responses.append(failed_response)
    result, calls = invoke_ha_module(
        monkeypatch, capsys, responses, state="deleted", config=[pair_config("A", "B")], config_actions={"save": True, "deploy": True}
    )
    assert result["failed"] is True
    assert result["changed"] is True
    assert result["after"] == []
    assert result["action_results"][0]["outcome"] == "succeeded"
    failed_action = result["config_actions_result"]["actions"][-1]
    assert failed_action["action"] == failure_step
    assert failed_action["status"] == "failed"
    assert error_fragment in failed_action["error"]
    assert [name for name, _payload in posted_action_payloads(calls)] == expected_post_actions


def test_failed_create_stops_override_and_config_actions(monkeypatch, capsys):
    requested_config = [pair_config("D", "C")]
    responses = [
        *inventory_responses(ha_switch_row("A", "B", "paired"), ha_switch_row("C"), ha_switch_row("D")),
        recommendations_response(ha_switch_row("D")),
        action_response(failure=["C-D"]),
    ]
    result, calls = invoke_ha_module(
        monkeypatch, capsys, responses, state="overridden", config=requested_config, config_actions={"save": True, "deploy": True}
    )
    assert result["failed"] is True
    assert result["changed"] is False
    assert result["after"] == [pair_config("A", "B")]
    assert [op["outcome"] for op in result["planned_operations"]] == ["failed", "not_attempted"]
    assert [name for name, _payload in posted_action_payloads(calls)] == ["haPair"]
    assert result["invocation"]["module_args"]["config"] == requested_config
