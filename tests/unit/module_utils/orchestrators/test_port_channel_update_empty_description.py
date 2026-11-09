# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NX-OS Po PUT wire adaptation preserves canonical desired intent."""

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import EpManageInterfacesPut
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_trunk_host_interface import PortChannelTrunkHostInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_base import PortChannelBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_coordinator import InterfaceWorkflowCoordinator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.test_interface_workflow_planner import _planner


def _model(description):
    policy = {
        "policy_type": "trunkPoHost",
        "admin_state": True,
        "port_type_edge_trunk": True,
        "orphan_port": False,
        "qos": False,
        "monitor": False,
        "description": description,
        "bpdu_guard": "enable",
        "lacp_suspend": False,
        "native_vlan": 1,
        "lacp_port_priority": 32768,
        "duplex_mode": "auto",
        "port_channel_mode": "active",
        "lacp_rate": "normal",
        "speed": "auto",
        "mtu": "jumbo",
        "allowed_vlans": "none",
        "ports": [],
    }
    return PortChannelTrunkHostInterfaceModel.from_config(
        {
            "switch_ip": "10.122.84.181",
            "interface_name": "port-channel501",
            "config_data": {"network_os": {"network_os_type": "nx-os", "policy": policy}},
        },
        context={"state": "replaced"},
    )


def _put(model):
    requests = []

    def configure(endpoint, switch_sn):
        endpoint.fabric_name = "nac-msd-fabric1"
        endpoint.switch_sn = switch_sn
        return endpoint

    orchestrator = SimpleNamespace(
        _resolve_switch_id=lambda _ip: "99TRB2TMZYJ",
        _removed_xe_members=lambda *_args: [],
        _configure_endpoint=configure,
        update_endpoint=EpManageInterfacesPut,
        _request=lambda **kwargs: requests.append(deepcopy(kwargs)) or {},
        _prepare_deploy_context=lambda *_args: None,
        _queue_deploy=lambda *_args: None,
        deploy=False,
        workflow_deploy_requested=False,
    )
    PortChannelBaseOrchestrator.update(orchestrator, model)
    assert len(requests) == 1
    return requests[0]["data"]


def test_exact_po501_invalid_blank_is_omitted_only_on_wire():
    """The 513-byte live rejection violates interfaceDescription minLength=1."""
    model = _model("")
    before = model.to_payload()
    before["switchId"] = "99TRB2TMZYJ"
    assert len(json.dumps(before, separators=(",", ":")).encode()) == 513
    assert before["configData"]["networkOS"]["policy"]["description"] == ""
    assert len(before["configData"]["networkOS"]["policy"]["description"]) < 1

    sent = _put(model)
    expected = deepcopy(before)
    expected["configData"]["networkOS"]["policy"].pop("description")
    assert sent == expected
    assert sent["configData"]["networkOS"]["policy"]["ports"] == []
    assert sent["configData"]["networkOS"]["policy"]["lacpSuspend"] is False
    assert model.to_payload()["configData"]["networkOS"]["policy"]["description"] == ""


@pytest.mark.parametrize("description", [None, "Preserved description"])
def test_none_omitted_and_nonempty_description_unchanged(description):
    model = _model(description)
    expected = model.to_payload()
    expected["switchId"] = "99TRB2TMZYJ"
    assert _put(model) == expected
    policy = expected["configData"]["networkOS"]["policy"]
    if description is None:
        assert "description" not in policy
    else:
        assert policy["description"] == description


def test_non_nx_payload_is_not_adapted():
    """The wire adaptation cannot change another OS's payload semantics."""
    payload = _model("").to_payload()
    payload["configData"]["networkOS"]["networkOSType"] = "ios-xe"
    payload["configData"]["networkOS"]["policy"]["policyType"] = "iosXeTrunkPoHost"
    model = SimpleNamespace(
        switch_ip="10.122.84.181",
        interface_name="port-channel501",
        to_payload=lambda: deepcopy(payload),
    )
    assert _put(model)["configData"]["networkOS"]["policy"]["description"] == ""


def _observed_po501():
    path = Path(__file__).parents[1] / "fixtures/fixture_data/po501_after_empty_description_put.json"
    return json.loads(path.read_text())["row"]


def test_actual_absent_description_echo_matches_explicit_clear():
    raw = _observed_po501()
    assert "description" not in raw["configData"]["networkOS"]["policy"]
    observed = PortChannelTrunkHostInterfaceModel.from_response(dict(raw, switchIp="10.122.84.181"))
    desired = _model("")
    assert observed.get_diff(desired) is True
    assert desired.to_config()["config_data"]["network_os"]["policy"]["description"] == ""
    assert "description" not in desired.to_diff_dict()["configData"]["networkOS"]["policy"]

    # A nonempty current description must still trigger a clearing update.
    changed = deepcopy(raw)
    changed["configData"]["networkOS"]["policy"]["description"] = "Must be removed"
    assert PortChannelTrunkHostInterfaceModel.from_response(dict(changed, switchIp="10.122.84.181")).get_diff(desired) is False


def _actual_noop_result(monkeypatch):
    raw = _observed_po501()
    resources = [{"type": "port_channel_trunk_host", "state": "replaced", "config": [_model("").to_config()]}]
    planner, recorder = _planner(switches={"10.122.84.181": "99TRB2TMZYJ"}, responses=[{"interfaces": [raw]}])
    params = {
        "fabric_name": "fabric_1",
        "resources": resources,
        "config_actions": {"deploy": False},
        "verify": {"enabled": True},
        "execution_options": {"contract_version": 1, "desired_equality": True, "member_batching": "disabled"},
    }
    coordinator = InterfaceWorkflowCoordinator(SimpleNamespace(params=params, check_mode=False))
    coordinator._snapshot = planner.snapshot
    monkeypatch.setattr(coordinator, "_build_plan", lambda: planner.plan(resources))
    monkeypatch.setattr(coordinator, "_new_rest_send", lambda params=None, **_kwargs: RestSend(params or {}))
    coordinator.executor_factory = lambda **_kwargs: pytest.fail("Actual cleared Po must not construct a write executor")
    result = coordinator.run()
    assert len(recorder.calls) == 1
    return result, resources


def test_actual_controller_capture_plans_noop_and_emits_bound_equality(monkeypatch):
    result, _resources = _actual_noop_result(monkeypatch)
    assert result["changed"] is False
    assert result["mutation_count"] == 0
    assert result["write_receipt"]["no_mutation_attempted"] is True
    proof = result["desired_equality"]
    assert proof["observed"] and proof["complete"] and proof["all_satisfied"]
    assert proof["request_sha256"] == result["workflow_contract"]["request_sha256"]
