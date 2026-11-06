"""Render actual pipeline payloads offline; never contact ND or switches."""

from pathlib import Path

from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment
import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "playbooks/nd_ensure_switches.yaml"
FABRIC_TYPES = ("externalConnectivity", "vxlanIbgp", "vxlanEbgp", None)


def environment():
    renderer = NativeEnvironment(undefined=StrictUndefined)
    renderer.filters["combine"] = lambda value, other: {**value, **other}
    renderer.filters["bool"] = bool
    return renderer


def find_task(tasks, name):
    for task in tasks:
        if task.get("name") == name:
            return task
        found = find_task(task.get("block", []), name)
        if found:
            return found
    return None


def render(value, context):
    if isinstance(value, str):
        return environment().from_string(value).render(**context)
    if isinstance(value, dict):
        return {key: render(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [render(item, context) for item in value]
    return value


@pytest.mark.parametrize("fabric_type", FABRIC_TYPES)
@pytest.mark.parametrize("expected_serial_supported", (False, True))
def test_guard_add_request_is_explicit_false_even_without_fabric_probe(fabric_type, expected_serial_supported):
    play = yaml.safe_load(GUARD.read_text())[0]
    onboard = next(task for task in play["tasks"] if task.get("name", "").startswith("Onboard the missing switches"))
    builder = find_task(onboard["block"], "Build one add request per fabric")
    request = render(builder["ansible.builtin.set_fact"]["nd_add_requests"], {
        "_sw": {"fabric": "fixture-fabric", "seed_ip": "192.0.2.10", "role": "edge_router", "serial": "FIXTURE0001"},
        "nd_add_requests": {}, "nd_switch_username": "fixture-user", "nd_switch_password": "fixture-password",
        "nd_switch_expected_serial_supported": expected_serial_supported,
        "nd_switch_rediscover_enabled": True, "nd_rediscovery_protocol_by_seed": {"192.0.2.10": "md5"},
        # Neither stale overrides nor unavailable/unknown probe data can select
        # preservation or omit the field. They are deliberately ignored now.
        "nd_preserve_override": {"fixture-fabric": {"preserve_config": True}},
        "nd_fabric_type_probe": {"failed": fabric_type is None, "current": {"management": {"type": fabric_type}}},
    })
    payload = request["fixture-fabric"][0]
    assert payload["preserve_config"] is False
    assert payload["seed_ip"] == "192.0.2.10"
    assert payload["role"] == "edge_router"
    assert payload["username"] == "fixture-user"
    assert ("expected_serial_number" in payload) is expected_serial_supported
    assert not any(task.get("register") == "nd_fabric_type_probe" for task in onboard["block"])


@pytest.mark.parametrize("fabric_type", FABRIC_TYPES)
@pytest.mark.parametrize("filename", (
    "apply_ensure_switch_membership.yaml", "apply_membership_move.yaml", "apply_repair_switch.yaml",
))
def test_prerequisite_add_and_repair_payloads_are_explicit_false(fabric_type, filename):
    tasks = yaml.safe_load((ROOT / "playbooks/nd_prerequisite" / filename).read_text())
    module = next(task["cisco.nd.nd_manage_switches"] for task in tasks
                  if task.get("cisco.nd.nd_manage_switches", {}).get("state") == "merged")
    context = {
        "_ndp_operation": {"switch_ref": "fixture-switch", "fabric_ref": "fixture", "destination_fabric_ref": "fixture",
                           "desired_role": "edge_router"},
        "_ndp_repair_operation": {"switch_ip": "192.0.2.10", "fabric_name": "fixture-fabric",
                                  "fabric_type": fabric_type, "desired_role": "edge_router"},
        "_ndp_fabric_name_by_ref": {"fixture": "fixture-fabric"},
        "_ndp_fabric_type_by_ref": {} if fabric_type is None else {"fixture": fabric_type},
        "_ndp_switch_seed_ip": {"fixture-switch": "192.0.2.10"},
        "nd_switch_username": "fixture-user", "nd_switch_password": "fixture-password",
    }
    payload = render(module, context)
    assert payload["fabric"] == "fixture-fabric"
    assert payload["config"][0]["preserve_config"] is False
    assert payload["config"][0]["seed_ip"] == "192.0.2.10"
    assert payload["config_actions"]["save"] is payload["config_actions"]["deploy"] is True


@pytest.mark.parametrize("value,accepted", (
    (False, True), ("false", True), ("FALSE", True), (True, False), ("true", False),
    ("auto", False), (None, False), ("", False),
))
def test_guard_rejects_attempts_to_select_automatic_or_preserving_mode(value, accepted):
    play = yaml.safe_load(GUARD.read_text())[0]
    assert play["vars"]["nd_switch_preserve_config"] is False
    policy = find_task(play["tasks"], "Require the fixed preservation policy before any switch operation")["ansible.builtin.assert"]
    assert render("{{ " + policy["that"][0] + " }}", {"nd_switch_preserve_config": value}) is accepted


def test_existing_direct_rest_role_change_does_not_receive_an_unrelated_api_field():
    play = yaml.safe_load(GUARD.read_text())[0]
    confirm = next(task for task in play["tasks"] if task.get("name", "").startswith("Confirm the full canonical roster"))
    role = next(task["cisco.nd.nd_rest"] for task in confirm["block"]
                if task.get("name", "").startswith("Correct role drift"))
    assert role["path"].endswith("/switchActions/changeRoles")
    assert set(role["content"]["switchRoles"][0]) == {"switchId", "role"}
