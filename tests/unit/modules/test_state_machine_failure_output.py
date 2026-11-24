# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Regression coverage for confirmed and uncertain writes through module entry points."""

import json
from copy import deepcopy
from types import SimpleNamespace

import pytest
from ansible.module_utils.connection import ConnectionError as AnsibleConnectionError
from ansible_collections.cisco.nd.plugins.module_utils.rest import rest_send, sender_nd
from ansible_collections.cisco.nd.plugins.modules import nd_fabric_update_group, nd_local_user
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule


class _ModuleExit(SystemExit):
    def __init__(self, failed, output):
        super().__init__(1 if failed else 0)
        self.failed = failed
        self.output = output


class _CapturingModule(MockAnsibleModule):
    _socket_path = "/unused/fake-ansible-socket"

    def __init__(self, config, ignore_errors):
        super().__init__()
        self.params = {
            "state": "merged",
            "config": config,
            "output_level": "normal",
            "ignore_errors": ignore_errors,
            "fabric_name": "fabric_1",
        }

    def exit_json(self, **output):
        raise _ModuleExit(False, output)

    def fail_json(self, msg, **output):
        raise _ModuleExit(True, {"msg": msg, **output})


def _run_module(monkeypatch, module, config, ignore_errors, send):
    """Run the real module, sender, response handler and state machine without a controller."""

    class _SimulatedConnection:
        def __init__(self, _socket_path):
            pass

        def set_params(self, _params):
            pass

        def send_request(self, verb, path, payload=None):
            return send(verb, path, json.loads(payload) if payload is not None else None)

    monkeypatch.setattr(module, "AnsibleModule", lambda **_kwargs: _CapturingModule(config, ignore_errors))
    monkeypatch.setattr(sender_nd, "Connection", _SimulatedConnection)
    with pytest.raises(_ModuleExit) as result:
        module.main()
    return result.value


def _response(code, message, data):
    return {"RETURN_CODE": code, "MESSAGE": message, "DATA": data}


@pytest.fixture
def fabric_context(monkeypatch):
    ip_to_id = {"192.0.2.1": "FDO1", "192.0.2.2": "FDO2"}
    context = SimpleNamespace(get_switch_id=ip_to_id.__getitem__, switch_map_by_id={serial: ip for ip, serial in ip_to_id.items()})
    monkeypatch.setattr(nd_fabric_update_group.FabricUpdateGroupOrchestrator, "fabric_context", property(lambda _self: context))
    monkeypatch.setattr(nd_fabric_update_group, "setup_logging", lambda _module: None)


@pytest.mark.parametrize(
    "ignore_errors,settings_requested,existing_membership",
    [
        (False, False, False),
        (True, False, False),
        (False, True, False),
        (True, True, False),
        pytest.param(False, False, True, id="accepted-attach-moves-an-existing-member"),
    ],
)
def test_fabric_update_group_reconciles_mixed_attach_outcomes(fabric_context, monkeypatch, ignore_errors, settings_requested, existing_membership):
    groups = {"group-before": {"updateGroupName": "group-before", "updateGroupSwitches": ["FDO1"]}} if existing_membership else {}
    requests = []

    def send(verb, path, payload):
        operation = path.rsplit("/", 1)[-1]
        requests.append((verb, operation))
        if verb == "GET" and operation == "updateGroups":
            return _response(200, "OK", {"updateGroups": list(deepcopy(groups).values())})

        assert (verb, operation) == ("POST", "attachGroup")
        attached, rejected = payload["attachUpdateGroups"]
        assert attached["updateGroupName"] == "group-a"
        assert rejected["updateGroupName"] == "group-b"
        if existing_membership:
            assert groups.pop("group-before")["updateGroupSwitches"] == attached["switchIds"]
        groups["group-a"] = {
            "updateGroupName": "group-a",
            "updateGroupSwitches": attached["switchIds"],
            "execution": "parallel",
        }
        return _response(
            207,
            "Multi-Status",
            {
                "attachUpdateGroups": [
                    {"updateGroupName": "group-a", "status": "success"},
                    {"updateGroupName": "group-b", "status": "failed", "warningMessage": "simulated rejection"},
                ]
            },
        )

    config = [
        {"update_group_name": "group-a", "update_group_switches": ["192.0.2.1"]},
        {"update_group_name": "group-b", "update_group_switches": ["192.0.2.2"]},
    ]
    if settings_requested:
        config[0]["execution"] = "serial"
    result = _run_module(monkeypatch, nd_fabric_update_group, config, ignore_errors, send)
    output = result.output

    assert requests == [("GET", "updateGroups"), ("POST", "attachGroup")], output.get("msg")
    assert list(groups) == ["group-a"]
    assert groups["group-a"]["execution"] == "parallel"
    assert result.failed is (not ignore_errors)
    assert output["changed"] is True
    outcomes = {record["identifier"]: record for record in output["action_results"]}
    assert outcomes["group-a"]["outcome"] == "succeeded"
    assert outcomes["group-a"]["effect_confirmed"] is True
    assert outcomes["group-a"]["statuses"] == ["success"]
    assert outcomes["group-b"]["outcome"] == "failed"
    assert outcomes["group-b"]["effect_confirmed"] is False
    if not ignore_errors:
        assert "group-b: failed - simulated rejection" in output["msg"]
    if existing_membership:
        assert [(group["update_group_name"], group["update_group_switches"]) for group in output["before"]] == [("group-before", ["192.0.2.1"])]
    if settings_requested or existing_membership:
        assert outcomes["group-a"]["after_known"] is False
        assert output["after_status"] == "unknown"
        assert output["unknown_identifiers"] == ["group-a"]
        assert "after" not in output
        assert "diff" not in output
    else:
        assert output["after_status"] == "confirmed"
        assert output["unknown_identifiers"] == []
        assert [(group["update_group_name"], group["update_group_switches"]) for group in output["after"]] == [("group-a", ["192.0.2.1"])]


def test_fabric_update_group_reports_attach_when_following_settings_write_fails(fabric_context, monkeypatch):
    groups = {}
    requests = []

    def send(verb, path, payload):
        operation = path.rsplit("/", 1)[-1]
        requests.append((verb, operation))
        if (verb, operation) == ("GET", "updateGroups"):
            return _response(200, "OK", {"updateGroups": list(deepcopy(groups).values())})
        if (verb, operation) == ("POST", "attachGroup"):
            (attached,) = payload["attachUpdateGroups"]
            groups["group-a"] = {
                "updateGroupName": "group-a",
                "updateGroupSwitches": attached["switchIds"],
                "execution": "parallel",
                "contingency": "continue",
                "analysis": "noAnalysis",
                "isMaintenance": False,
                "isDisruptiveUpdate": False,
            }
            return _response(207, "Multi-Status", {"attachUpdateGroups": [{"updateGroupName": "group-a", "status": "success"}]})
        if (verb, operation) == ("GET", "group-a"):
            return _response(200, "OK", deepcopy(groups["group-a"]))
        assert (verb, operation) == ("PUT", "group-a")
        assert payload["execution"] == "serial"
        return _response(400, "Bad Request", {"message": "simulated settings rejection"})

    config = [{"update_group_name": "group-a", "update_group_switches": ["192.0.2.1"], "execution": "serial"}]
    result = _run_module(monkeypatch, nd_fabric_update_group, config, False, send)
    output = result.output

    assert requests == [("GET", "updateGroups"), ("POST", "attachGroup"), ("GET", "group-a"), ("PUT", "group-a")], output.get("msg")
    assert groups["group-a"]["execution"] == "parallel"
    assert result.failed
    assert output["changed"] is True
    assert output["after_status"] == "unknown"
    assert output["unknown_identifiers"] == ["group-a"]
    assert "after" not in output
    assert "diff" not in output
    (attachment,) = output["action_results"]
    assert attachment["outcome"] == "succeeded"
    assert attachment["effect_confirmed"] is True
    assert attachment["after_known"] is False


@pytest.mark.parametrize("ignore_errors", [False, True])
@pytest.mark.parametrize("confirmed_before_loss", [False, True])
def test_local_user_lost_update_response_keeps_final_state_unknown(monkeypatch, ignore_errors, confirmed_before_loss):
    users = {"uncertain": {"loginID": "uncertain", "firstName": "Before"}}
    config = [{"login_id": "uncertain", "first_name": "After"}]
    if confirmed_before_loss:
        users["confirmed"] = {"loginID": "confirmed", "firstName": "Before"}
        users["later"] = {"loginID": "later", "firstName": "Before"}
        config.insert(0, {"login_id": "confirmed", "first_name": "After"})
        config.append({"login_id": "later", "first_name": "After"})
    requests = []

    def send(verb, path, payload):
        identifier = path.rsplit("/", 1)[-1]
        requests.append((verb, identifier))
        if verb == "GET":
            return _response(200, "OK", {"localusers": list(deepcopy(users).values())})

        assert verb == "PUT"
        users[identifier].update(payload)
        if identifier == "uncertain":
            raise AnsibleConnectionError("server response lost after update")
        return _response(200, "OK", {})

    result = _run_module(monkeypatch, nd_local_user, config, ignore_errors, send)
    output = result.output

    expected_requests = [("GET", "localUsers"), ("PUT", "uncertain")]
    if confirmed_before_loss:
        expected_requests.insert(1, ("PUT", "confirmed"))
        if ignore_errors:
            expected_requests.append(("PUT", "later"))
    assert requests == expected_requests, output.get("msg")
    assert users["uncertain"]["firstName"] == "After"
    assert result.failed is (not ignore_errors)
    assert output["changed"] is confirmed_before_loss
    assert output["may_have_changed"] is True
    assert output["after_status"] == "unknown"
    assert output["unknown_identifiers"] == ["uncertain"]
    assert "after" not in output
    assert "diff" not in output


def test_local_user_definite_rejection_preserves_known_snapshot(monkeypatch):
    previous = {"loginID": "definite", "firstName": "Before"}
    requests = []

    def send(verb, path, _payload):
        requests.append((verb, path.rsplit("/", 1)[-1]))
        if verb == "GET":
            return _response(200, "OK", {"localusers": [previous]})
        assert verb == "PUT"
        return _response(400, "Bad Request", {"message": "simulated rejection"})

    config = [{"login_id": "definite", "first_name": "After"}]
    result = _run_module(monkeypatch, nd_local_user, config, False, send)
    output = result.output

    assert requests == [("GET", "localUsers"), ("PUT", "definite")], output.get("msg")
    assert result.failed
    assert output["changed"] is False
    assert not output.get("may_have_changed")
    assert output["after"] == output["before"]
    assert output["after"][0]["first_name"] == "Before"


def test_local_user_terminal_rejection_after_retry_keeps_final_state_unknown(monkeypatch):
    monkeypatch.setattr(rest_send, "sleep", lambda _interval: None)
    user = {"loginID": "uncertain", "firstName": "Before"}
    requests = []

    def send(verb, path, payload):
        requests.append((verb, path.rsplit("/", 1)[-1]))
        if verb == "GET":
            return _response(200, "OK", {"localusers": [deepcopy(user)]})
        assert verb == "PUT"
        if user["firstName"] == "Before":
            user.update(payload)
            return _response(503, "Service Unavailable", {})
        return _response(400, "Bad Request", {"message": "simulated terminal rejection"})

    config = [{"login_id": "uncertain", "first_name": "After"}]
    result = _run_module(monkeypatch, nd_local_user, config, False, send)
    output = result.output

    assert requests == [("GET", "localUsers"), ("PUT", "uncertain"), ("PUT", "uncertain")], output.get("msg")
    assert user["firstName"] == "After"
    assert result.failed
    assert output["changed"] is False
    assert output["may_have_changed"] is True
    assert output["after_status"] == "unknown"
    assert output["unknown_identifiers"] == ["uncertain"]
    assert "after" not in output
    assert "diff" not in output
