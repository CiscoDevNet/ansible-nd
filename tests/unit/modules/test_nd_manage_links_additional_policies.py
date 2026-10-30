# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Offline lifecycle coverage for the twelve native link-policy additions."""

from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.links.links import NDLinkModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.links import NDLinkOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.manage_link import ManageLinkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.models.test_links_additional_policies import ADDITIONAL_POLICIES, ONLY_431, config, link


def state_machine(monkeypatch, policy_type, *, state="merged", check=False, existing=False, version="4.3.1", inputs=None):
    """Use current state/runtime code while replacing only controller I/O."""
    calls = []
    strategy = ManageLinkStrategy(fabric_name="fabric-a")
    monkeypatch.setattr(NDLinkModel, "identifiers", strategy.identifier_fields)
    desired = config(policy_type, inputs)
    inventory = []
    if existing:
        inventory = [{**link(policy_type).to_payload(controller_version="4.3.1"), "linkId": "LINK-TEST"}]
    if state == "deleted":
        desired.pop("config_data")
    module = SimpleNamespace(
        params={"state": state, "config": [desired], "output_level": "normal"},
        check_mode=check,
        no_log_values=set(),
        warn=lambda message: None,
    )
    rest = RestSend({"state": state, "check_mode": check})
    rest.controller_version = version
    orchestrator = NDLinkOrchestrator(rest_send=rest, strategy=strategy)

    def request(self, path, verb, data=None, **kwargs):
        calls.append({"path": path, "verb": verb.value, "payload": copy.deepcopy(data)})
        if verb.value == "GET":
            return {"links": copy.deepcopy(inventory)}
        return {"links": [{"linkId": "LINK-TEST", "status": "success"}]}

    monkeypatch.setattr(NDLinkOrchestrator, "_request", request)
    machine = NDStateMachine(module, orchestrator, config=[desired])
    return machine, calls


@pytest.mark.parametrize("policy_type", ADDITIONAL_POLICIES)
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("check", [False, True])
def test_native_policy_create_uses_existing_state_and_check_mode_paths(monkeypatch, policy_type, state, check):
    machine, calls = state_machine(monkeypatch, policy_type, state=state, check=check)
    machine.manage_state()
    writes = [call for call in calls if call["verb"] != "GET"]
    assert len([call for call in calls if call["verb"] == "GET"]) == 1
    assert len(writes) == (0 if check else 1)
    output = machine.output.format()
    assert output["changed"] is True
    assert output["after"][0]["config_data"]["policy_type"] == policy_type
    assert "TEST-IPSEC-KEY" not in json.dumps(output)
    if writes:
        assert writes[0]["verb"] == "POST"
        assert writes[0]["path"].startswith("/api/v1/manage/links")
        config_data = writes[0]["payload"]["links"][0]["configData"]
        assert config_data["policyType"] == policy_type
        if policy_type == "serviceVpcTrunk":
            assert config_data == {"policyType": "serviceVpcTrunk"}


@pytest.mark.parametrize("policy_type", ADDITIONAL_POLICIES)
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
def test_native_policy_repeat_after_controller_echo_is_idempotent_except_explicit_required_secret(monkeypatch, policy_type, state):
    machine, calls = state_machine(monkeypatch, policy_type, state=state, existing=True)
    machine.manage_state()
    writes = [call for call in calls if call["verb"] != "GET"]
    if policy_type == "csrBgpOverIpsec":
        # The contract requires resupplying this write-only key, so each explicit
        # application is rotation intent even though diff output hides its value.
        assert len(writes) == 1
        assert writes[0]["verb"] == "PUT"
        assert machine.output.format()["changed"] is True
    else:
        assert writes == []
        assert machine.output.format()["changed"] is False


@pytest.mark.parametrize("policy_type", ADDITIONAL_POLICIES)
@pytest.mark.parametrize("check", [False, True])
def test_native_policy_identifier_only_delete_is_available_and_safe_in_check_mode(monkeypatch, policy_type, check):
    machine, calls = state_machine(monkeypatch, policy_type, state="deleted", check=check, existing=True)
    machine.manage_state()
    writes = [call for call in calls if call["verb"] != "GET"]
    assert len(writes) == (0 if check else 1)
    assert machine.output.format()["after"] == []
    if writes:
        assert writes[0]["path"].startswith("/api/v1/manage/linkActions/remove")
        assert writes[0]["payload"] == {"links": ["LINK-TEST"]}


@pytest.mark.parametrize("policy_type", sorted(ONLY_431))
@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("version", ["4.2.1", None])
def test_release_guard_runs_before_mutation_in_both_modes(monkeypatch, policy_type, check, version):
    machine, calls = state_machine(monkeypatch, policy_type, check=check, version=version)
    with pytest.raises(Exception, match="version|4.3|release"):
        machine.manage_state()
    assert [call for call in calls if call["verb"] != "GET"] == []


@pytest.mark.parametrize(
    "policy_type,field,value,unsupported_version",
    [
        ("vxlanAciMultisiteUnderlay", "src_interface_config", "logging event port link-status", "4.3.1"),
        ("vxlanAciMultisiteUnderlay", "speed", "100Gb", "4.2.1"),
        ("vxlanAciEvpnOverlay", "macsec", True, "4.3.1"),
        ("vxlanAciEvpnOverlay", "ebgp_multihop", 10, "4.2.1"),
    ],
)
@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("unknown_version", [False, True])
def test_explicit_aci_field_release_guards_precede_normal_and_check_mode_mutation(
    monkeypatch, policy_type, field, value, unsupported_version, check, unknown_version
):
    inputs = config(policy_type)["config_data"]["template_inputs"]
    inputs[field] = value
    machine, calls = state_machine(monkeypatch, policy_type, inputs=inputs, check=check, version=None if unknown_version else unsupported_version)
    with pytest.raises(Exception, match="version|4.3|4.2|release"):
        machine.manage_state()
    assert [call for call in calls if call["verb"] != "GET"] == []


@pytest.mark.parametrize("policy_type", ADDITIONAL_POLICIES)
def test_gathered_native_policy_is_visible_and_does_not_mutate(monkeypatch, policy_type):
    machine, calls = state_machine(monkeypatch, policy_type, state="gathered", existing=True)
    machine.manage_state()
    output = machine.output.format()
    assert len(calls) == 1
    assert calls[0]["verb"] == "GET"
    assert output["changed"] is False
    assert output["gathered"][0]["config_data"]["policy_type"] == policy_type
    assert "TEST-IPSEC-KEY" not in json.dumps(output)


def test_version_discovery_is_cached_across_native_policy_batch(monkeypatch):
    """New capability validation must not add a version query per link."""
    discoveries = []

    def get_version():
        discoveries.append("get_version")
        return "4.3.1.175"

    rest = RestSend({"state": "merged", "check_mode": False})
    rest.sender = SimpleNamespace(path="", verb=None, payload=None, response={}, commit=lambda: None, get_version=get_version)
    strategy = ManageLinkStrategy(fabric_name="fabric-a")
    monkeypatch.setattr(NDLinkModel, "identifiers", strategy.identifier_fields)
    orchestrator = NDLinkOrchestrator(rest_send=rest, strategy=strategy)
    old_config = config("ospfVrfLite")
    old_config["config_data"]["policy_type"] = "numbered"
    old_model = NDLinkModel.from_config(old_config, context={"state": "merged"})
    orchestrator.preflight([old_model])
    assert discoveries == []

    models = [link(policy_type) for policy_type in ADDITIONAL_POLICIES]
    orchestrator.preflight(models)
    for model in models:
        orchestrator._policy_payload(model)
    assert discoveries == ["get_version"]
