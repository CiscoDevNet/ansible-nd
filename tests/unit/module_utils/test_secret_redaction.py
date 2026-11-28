# Copyright: (c) 2026, astawast <astawast@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Secrets stay out of debug logs, error text and public result copies while requests keep the real values."""

from __future__ import annotations

import json
import logging
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from ansible.module_utils.common.parameters import remove_values

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.vrf_data_models import VrfDataModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import StandaloneVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator import VrfWorkflowCoordinator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrfs import NDVrfOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.redaction import NO_LOG_PLACEHOLDER, SecretRedactor, get_redactor
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender

# BGP passwords must be hex; these are dummies that never reach a controller.
USER_SECRET = "d0d0cafe0001"
ND_SECRET = "d0d0cafe0002"
OTHER_VRF_SECRET = "d0d0cafe0003"
ALL_SECRETS = (USER_SECRET, ND_SECRET, OTHER_VRF_SECRET)
CONNECTION = "ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd.Connection"


class _Connection:
    """HttpApi stand-in: GET returns the observed VRFs, writes return ``write_response``."""

    def __init__(self, observed, write_response=None, get_response=None):
        self.observed = observed
        self.write_response = write_response or {"RETURN_CODE": 200, "MESSAGE": "OK", "DATA": {}}
        self.get_response = get_response
        self.requests = []

    def set_params(self, params):
        pass

    def send_request(self, verb, path, data=None):
        self.requests.append({"verb": verb, "path": path, "data": data})
        if verb == "GET" and self.get_response is not None:
            return deepcopy(self.get_response)
        if verb == "GET":
            vrfs = deepcopy(self.observed)
            return {"RETURN_CODE": 200, "MESSAGE": "OK", "DATA": {"vrfs": vrfs, "meta": {"counts": {"remaining": 0, "total": len(vrfs)}}}}
        return deepcopy(self.write_response)


def _module(state, config, check=False):
    def fail_json(**kwargs):
        raise AssertionError(kwargs)

    module = SimpleNamespace(
        params={"fabric_name": "FAB", "state": state, "config": config, "output_level": "debug"},
        check_mode=check,
        _verbosity=3,
        _socket_path="/tmp/nd-test-socket",
        no_log_values=set(),
        fail_json=fail_json,
    )
    # AnsibleModule registers no_log argument values before the module runs.
    module.no_log_values |= {item["bgp_password"] for item in config if item.get("bgp_password")}
    return module


def _observed(blue_password=ND_SECRET, **blue_overrides):
    strategy = StandaloneVrfStrategy(fabric_name="FAB", fabric_data={"managementType": "vxlanIbgp", "members": []})
    orchestrator = NDVrfOrchestrator(rest_send=RestSend({"state": "replaced"}), strategy=strategy)
    blue = VrfDataModel.from_config(orchestrator.prepare_config_data([{"vrf_name": "BLUE", "vrf_id": 50001}])[0]).to_payload()
    blue["vrfId"] = 50001
    blue.setdefault("fabricData", {}).update(bgpPassword=blue_password, bgpPasswordKeyType=7)
    blue.update(blue_overrides)
    red = deepcopy(blue)
    red.update(vrfName="RED", vrfId=50002)
    red["fabricData"]["bgpPassword"] = OTHER_VRF_SECRET
    return [blue, red]


def _run(monkeypatch, connection, module):
    strategy = StandaloneVrfStrategy(fabric_name="FAB", fabric_data={"managementType": "vxlanIbgp", "members": []})
    coordinator = VrfWorkflowCoordinator(module, strategy)
    new_rest_send = coordinator._new_rest_send

    def rest_send(*args, **kwargs):
        runtime = new_rest_send(*args, **kwargs)
        runtime.controller_version = "4.2.1.10"
        return runtime

    monkeypatch.setattr(coordinator, "_new_rest_send", rest_send)
    with patch(CONNECTION, return_value=connection):
        return coordinator._attach_workflow_trace(coordinator._handle_standalone_workflow(dict(module.params), strategy.fabric_type))


def _assert_clean(text):
    for secret in ALL_SECRETS:
        assert secret not in text


# ── End to end: complete result and captured logs ───────────


@pytest.mark.parametrize("check", [False, True])
def test_password_change_keeps_every_secret_out_of_logs_and_result(monkeypatch, caplog, check):
    caplog.set_level(logging.DEBUG)
    connection = _Connection(_observed())
    config = [{"vrf_name": "BLUE", "vrf_id": 50001, "bgp_password": USER_SECRET, "bgp_passwd_encrypt": "type7"}]
    module = _module("merged", config, check=check)

    result = _run(monkeypatch, connection, module)

    writes = [request for request in connection.requests if request["verb"] != "GET" and "/query" not in request["path"]]
    if check:
        assert not writes
    else:
        # The private request still carries the real value.
        assert any(USER_SECRET in (request["data"] or "") for request in writes)
    assert result["changed"] is True
    assert result["api_response"] and result["workflow_trace"]
    _assert_clean(json.dumps(result, default=str))
    _assert_clean(caplog.text)
    assert NO_LOG_PLACEHOLDER in caplog.text
    # Every secret, including the one ND returned for a VRF outside the playbook, is registered for Ansible's final scrub.
    assert set(ALL_SECRETS) <= module.no_log_values


def test_gathered_registers_controller_passwords_without_playbook_secret(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    module = _module("gathered", [])

    result = _run(monkeypatch, _Connection(_observed()), module)

    assert {entry["vrf_name"] for entry in result["gathered"]} == {"BLUE", "RED"}
    _assert_clean(json.dumps(result, default=str))
    _assert_clean(caplog.text)
    assert {ND_SECRET, OTHER_VRF_SECRET} <= module.no_log_values


def test_controller_password_is_registered_before_model_validation(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    module = _module("merged", [{"vrf_name": "BLUE", "vrf_id": 50001}])

    with pytest.raises(Exception) as error:
        _run(monkeypatch, _Connection(_observed(vrfType="not-a-vrf-type")), module)

    assert {ND_SECRET, OTHER_VRF_SECRET} <= module.no_log_values
    _assert_clean(remove_values(str(error.value), module.no_log_values))
    _assert_clean(caplog.text)


def test_query_failure_that_echoes_passwords_is_redacted(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    failure = {
        "RETURN_CODE": 500,
        "MESSAGE": "Internal Server Error",
        "DATA": {"message": f"bgpPassword {USER_SECRET} rejected", "vrfs": [{"vrfName": "RED", "fabricData": {"bgpPassword": OTHER_VRF_SECRET}}]},
    }
    config = [{"vrf_name": "BLUE", "vrf_id": 50001, "bgp_password": USER_SECRET, "bgp_passwd_encrypt": "type7"}]
    module = _module("merged", config)
    connection = _Connection(_observed(), get_response=failure)
    monkeypatch.setattr("ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send.sleep", lambda _seconds: None)

    with pytest.raises(Exception) as error:
        _run(monkeypatch, connection, module)

    assert not [request for request in connection.requests if request["verb"] != "GET"]
    assert OTHER_VRF_SECRET in module.no_log_values
    _assert_clean(remove_values(str(error.value), module.no_log_values))
    _assert_clean(caplog.text)


def test_controller_error_that_echoes_the_password_is_redacted(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    echo = {"RETURN_CODE": 400, "MESSAGE": "Bad Request", "DATA": {"message": f"invalid bgpPassword {USER_SECRET}"}}
    config = [{"vrf_name": "BLUE", "vrf_id": 50001, "bgp_password": USER_SECRET, "bgp_passwd_encrypt": "type7"}]
    module = _module("merged", config)

    with pytest.raises(Exception) as error:
        _run(monkeypatch, _Connection(_observed(), write_response=echo), module)

    _assert_clean(remove_values(str(error.value), module.no_log_values))
    _assert_clean(caplog.text)


# ── Redaction points ────────────────────────────────────────


def test_redactor_masks_by_key_and_by_registered_value_without_mutating():
    module = SimpleNamespace(no_log_values={"short", "short-and-longer"})
    redactor = SecretRedactor(module)
    redactor.add_keys({"bgpPassword", "", None})
    data = {"fabricData": {"bgpPassword": "k1", "empty": ""}, "items": ({"bgpPassword": None}, "has short-and-longer")}

    assert redactor.redact_keys(data) == {
        "fabricData": {"bgpPassword": NO_LOG_PLACEHOLDER, "empty": ""},
        "items": [{"bgpPassword": None}, "has short-and-longer"],
    }
    assert redactor.redact(data)["items"][1] == f"has {NO_LOG_PLACEHOLDER}"
    assert data["fabricData"]["bgpPassword"] == "k1"
    module.no_log_values.add("k9")
    assert redactor.redact_text("failed with k9") == f"failed with {NO_LOG_PLACEHOLDER}"
    assert redactor.keys == frozenset({"bgpPassword"})


def test_only_secret_field_values_are_registered_from_responses():
    module = SimpleNamespace(no_log_values=set())
    redactor = SecretRedactor(module)
    redactor.add_keys(VrfDataModel.redaction_keys())
    redactor.add_secret_value_keys(VrfDataModel.secret_value_keys())

    redactor.register_secret_values({"vrfs": [{"fabricData": {"bgpPassword": ND_SECRET}, "vrfTemplateConfig": {"vrfVlanName": "true"}}, {"bgpPassword": ""}]})

    assert module.no_log_values == {ND_SECRET}
    assert "vrfTemplateConfig" in redactor.keys


def test_get_redactor_is_shared_per_module():
    module = SimpleNamespace()
    assert get_redactor(module) is get_redactor(module)
    assert get_redactor(None) is not get_redactor(None)
    assert isinstance(get_redactor(MagicMock()), SecretRedactor)


def test_results_api_copies_are_redacted_and_live_response_is_not():
    results = Results()
    results.redactor = SecretRedactor()
    results.redactor.add_keys({"bgpPassword"})
    response = {"RETURN_CODE": 200, "DATA": {"fabricData": {"bgpPassword": ND_SECRET}}}
    results.response_current = response
    results.result_current = {"success": True, "changed": False}
    results.action = "query"
    results.operation_type = OperationType.QUERY
    results.path_current = "/vrfs"
    results.verb_current = HttpVerbEnum.GET
    results.payload_current = {"fabricData": {"bgpPassword": USER_SECRET}}

    results.register_api_call()
    results.build_final_result()

    assert results.final_result["response"][0]["DATA"]["fabricData"]["bgpPassword"] == NO_LOG_PLACEHOLDER
    assert results.final_result["payload"][0]["fabricData"]["bgpPassword"] == NO_LOG_PLACEHOLDER
    assert response["DATA"]["fabricData"]["bgpPassword"] == ND_SECRET


def test_rest_send_logs_parameter_names_only(caplog):
    caplog.set_level(logging.DEBUG)
    RestSend({"state": "merged", "config": [{"bgp_password": USER_SECRET}]})
    assert "config" in caplog.text
    _assert_clean(caplog.text)


def test_sender_logs_redacted_payload_and_sends_the_real_one(caplog):
    caplog.set_level(logging.DEBUG)
    module = SimpleNamespace(_socket_path="/tmp/nd-test-socket", params={}, no_log_values=set())
    get_redactor(module).add_keys({"bgpPassword"})
    connection = MagicMock()
    connection.send_request.return_value = {"RETURN_CODE": 200, "MESSAGE": "OK", "DATA": {}}
    sender = Sender()
    sender.ansible_module = module
    sender.path = "/vrfs"
    sender.verb = HttpVerbEnum.POST
    sender.payload = {"fabricData": {"bgpPassword": USER_SECRET}}

    with patch(CONNECTION, return_value=connection):
        sender.commit()

    connection.send_request.assert_called_once_with("POST", "/vrfs", json.dumps({"fabricData": {"bgpPassword": USER_SECRET}}))
    _assert_clean(caplog.text)


def test_workflow_trace_payloads_are_redacted():
    module = _module("merged", [])
    coordinator = VrfWorkflowCoordinator(module, StandaloneVrfStrategy(fabric_name="FAB", fabric_data={"managementType": "vxlanIbgp", "members": []}))
    coordinator._trace("api_request_start", payload={"vrfs": [{"fabricData": {"bgpPassword": USER_SECRET}, "vrfTemplateConfig": "x"}]})
    payload = coordinator.workflow_trace[-1]["payload"]["vrfs"][0]
    assert payload == {"fabricData": {"bgpPassword": NO_LOG_PLACEHOLDER}, "vrfTemplateConfig": NO_LOG_PLACEHOLDER}
