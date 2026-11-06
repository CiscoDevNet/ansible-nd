# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Keep Interface Group preflight and ordered moves intact with shared planning."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.config_models import InterfaceGroupConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_interface_group import ManageInterfaceGroupOrchestrator


def _group(name, members, *, group_type="portChannel", switch_id="SN1", **kwargs):
    """Build playbook input with an explicitly authoritative member list."""
    return {
        "interface_group_name": name,
        "type": group_type,
        "switch_interfaces": [{"switch_id": switch_id, "interface_names": members}] if members else [],
        **kwargs,
    }


def _members(payload):
    return {(entry["switchId"], name) for entry in payload.get("switchInterfaces", []) for name in entry["interfaceNames"]}


@pytest.fixture
def workflow(monkeypatch):
    """Stub controller I/O only; exercise the real planner, preflight and CRUD."""

    def build(state, check_mode, before, config, *, template=None):
        controller = {item["interface_group_name"]: InterfaceGroupConfigModel.from_config(item) for item in before}
        initial = deepcopy(controller)
        reads = []
        writes = []

        def query_all(orchestrator, **_kwargs):
            orchestrator._existing_groups = deepcopy(controller)
            return [item.model_dump(by_alias=True, exclude_none=True, mode="json") for item in controller.values()]

        def request(_orchestrator, *, path, verb, data=None, **_kwargs):
            if verb == HttpVerbEnum.GET:
                reads.append(path)
                if path.endswith("/switches/SN1/vpcPair"):
                    return {"switchId": "SN1", "peerSwitchId": "SN2"}
                if path.endswith("/configTemplates/custom-template") and template is not None:
                    return deepcopy(template)
                raise AssertionError(f"Unexpected controller read: {path}")
            writes.append((verb, path, deepcopy(data)))
            if verb == HttpVerbEnum.PUT:
                name = data["interfaceGroupName"]
                # Model the controller's one-group-per-interface requirement:
                # adding the target before detaching its source must fail.
                for other_name, other in controller.items():
                    if other_name != name:
                        assert not (_members(data) & _members(other.to_payload()))
                controller[name] = InterfaceGroupConfigModel.from_response(data)
                return {}
            if verb == HttpVerbEnum.POST and path.endswith("/interfaceGroups/actions/remove"):
                for name in data["interfaceGroupNames"]:
                    assert not controller[name].switch_interfaces
                    controller.pop(name)
                return {"interfaceGroups": [{"interfaceGroupName": name, "status": "success"} for name in data["interfaceGroupNames"]]}
            raise AssertionError(f"Unexpected controller mutation: {verb} {path}")

        monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "query_all", query_all)
        monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", request)
        module = SimpleNamespace(
            check_mode=check_mode,
            params={
                "fabric_name": "fab1",
                "state": state,
                "config": deepcopy(config),
                "config_actions": {"deploy": False, "type": "resource"},
                "output_level": "normal",
            },
        )
        machine = NDStateMachine(module=module, model_orchestrator=ManageInterfaceGroupOrchestrator)
        return SimpleNamespace(machine=machine, controller=controller, initial=initial, reads=reads, writes=writes)

    return build


@pytest.mark.parametrize("state", ["replaced", "overridden"])
@pytest.mark.parametrize("check_mode", [False, True], ids=["apply", "check"])
def test_explicit_move_detaches_source_before_target_add(workflow, state, check_mode):
    """An authoritative move works even when input lists its target first."""
    run = workflow(
        state,
        check_mode,
        [_group("source", ["Port-channel10", "Port-channel11"]), _group("target", ["Port-channel20"])],
        [_group("target", ["Port-channel10", "Port-channel20"]), _group("source", ["Port-channel11"])],
    )

    run.machine.manage_state()

    after = {item["interface_group_name"]: item for item in run.machine.output.format()["after"]}
    assert after["source"]["switch_interfaces"] == [{"switch_id": "SN1", "interface_names": ["Port-channel11"]}]
    assert after["target"]["switch_interfaces"] == [{"switch_id": "SN1", "interface_names": ["Port-channel10", "Port-channel20"]}]
    assert run.machine.output.format()["changed"] is True
    if check_mode:
        assert run.writes == []
        assert run.controller == run.initial
    else:
        assert [(data["interfaceGroupName"], _members(data)) for _verb, _path, data in run.writes] == [
            ("source", {("SN1", "Port-channel11")}),
            ("target", {("SN1", "Port-channel10"), ("SN1", "Port-channel20")}),
        ]


@pytest.mark.parametrize("check_mode", [False, True], ids=["apply", "check"])
def test_overridden_omitted_source_is_deleted_without_restoring_moved_member(workflow, check_mode):
    """Deleting the pre-planned source uses its current, already-detached state."""
    run = workflow(
        "overridden",
        check_mode,
        [_group("source", ["Port-channel10", "Port-channel11"]), _group("target", ["Port-channel20"])],
        [_group("target", ["Port-channel10", "Port-channel20"])],
    )

    run.machine.manage_state()

    assert [item["interface_group_name"] for item in run.machine.output.format()["after"]] == ["target"]
    if check_mode:
        assert run.writes == []
        assert run.controller == run.initial
    else:
        assert set(run.controller) == {"target"}
        assert [(data["interfaceGroupName"], _members(data)) for verb, _path, data in run.writes if verb == HttpVerbEnum.PUT] == [
            ("source", {("SN1", "Port-channel11")}),
            ("target", {("SN1", "Port-channel10"), ("SN1", "Port-channel20")}),
            ("source", set()),
        ]
        assert run.writes[-1][2] == {"interfaceGroupNames": ["source"]}


@pytest.mark.parametrize("state", ["replaced", "overridden"])
@pytest.mark.parametrize("check_mode", [False, True], ids=["apply", "check"])
def test_invalid_move_fails_preflight_without_mutation_or_predicted_change(workflow, state, check_mode):
    """Keeping the same member in its source cannot produce a partial move."""
    run = workflow(
        state,
        check_mode,
        [_group("source", ["Port-channel10"]), _group("target", ["Port-channel20"])],
        [_group("target", ["Port-channel10", "Port-channel20"]), _group("source", ["Port-channel10"])],
    )

    with pytest.raises(NDStateMachineError, match="is present in both 'target' and 'source'"):
        run.machine.manage_state()

    assert run.writes == []
    assert run.controller == run.initial
    output = run.machine.output.format()
    assert output["after"] == output["before"]
    assert output["changed"] is False


@pytest.mark.parametrize("state", ["replaced", "overridden"])
@pytest.mark.parametrize("check_mode", [False, True], ids=["apply", "check"])
def test_opposite_peer_vpc_noop_uses_preflight_normalized_membership(workflow, state, check_mode):
    """A plan built before pair resolution must not force an unnecessary PUT."""
    run = workflow(
        state,
        check_mode,
        [_group("vpc-group", ["vPC200"], group_type="vpc", switch_id="SN2")],
        [_group("vpc-group", ["vPC200"], group_type="vpc", switch_id="SN1")],
    )

    run.machine.manage_state()

    assert run.reads == ["/api/v1/manage/fabrics/fab1/switches/SN1/vpcPair"]
    assert run.writes == []
    assert run.controller == run.initial
    output = run.machine.output.format()
    assert output["after"] == output["before"]
    assert output["changed"] is False


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("check_mode", [False, True], ids=["apply", "check"])
def test_template_noop_uses_types_learned_after_initial_plan(workflow, state, check_mode):
    """Equivalent Boolean echoes stay idempotent after schema preflight."""
    template = {
        "name": "custom-template",
        "templateType": "policy",
        "templateSubType": "interfaceEthernet",
        "contentType": "pythonCli",
        "tags": ["interface_edit_policy", "interface_edit_shared_policy", "int_trunk"],
        "content": "##template properties\nuserDefined = true;\n##\n",
        "supportedPlatforms": ["all"],
        "parameters": [{"name": "ENABLED", "parameterType": "Boolean", "optional": True}],
    }
    existing = _group("custom-group", ["Ethernet1/10"], group_type="ethernetCustom", template_name="custom-template", template_config={"ENABLED": "TRUE"})
    requested = deepcopy(existing)
    requested["template_config"] = {"ENABLED": "true"}
    run = workflow(state, check_mode, [existing], [requested], template=template)

    run.machine.manage_state()

    assert run.reads == ["/api/v1/manage/configTemplates/custom-template"]
    assert run.writes == []
    assert run.controller == run.initial
    output = run.machine.output.format()
    assert output["after"] == output["before"]
    assert output["changed"] is False
