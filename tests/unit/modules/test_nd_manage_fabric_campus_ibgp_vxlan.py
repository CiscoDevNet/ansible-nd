# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Module-surface tests for ``nd_manage_fabric_campus_ibgp_vxlan``."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import yaml

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_campus_ibgp_vxlan import (
    FabricCampusIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.modules import (
    nd_manage_fabric_campus_ibgp_vxlan as campus_module,
)


class _ExitJson(SystemExit):
    """Capture a successful fake AnsibleModule exit."""

    def __init__(self, result: dict):
        super().__init__("exit_json")
        self.result = result


class _FakeModule:
    def __init__(self, state: str, config_actions: dict):
        self.params = {
            "state": state,
            "config": [{"fabric_name": "campus1", "management": {"bgp_asn": "65001"}}],
            "config_actions": config_actions,
        }
        self.check_mode = False
        self.no_log_values = set()
        self._verbosity = 0

    def exit_json(self, **kwargs) -> None:
        raise _ExitJson(kwargs)

    def fail_json(self, msg: str, **kwargs) -> None:
        raise AssertionError(f"unexpected fail_json: {msg}; {kwargs}")


class _FakeOutput:
    @staticmethod
    def format_with_verbosity(verbosity, results) -> dict:
        return {"changed": False}


class _ActionRecorder:
    def __init__(self):
        self.calls: list[dict] = []

    def run_config_actions(self, **kwargs) -> None:
        self.calls.append(kwargs)


def test_nd_manage_fabric_campus_ibgp_vxlan_00010() -> None:
    """DOCUMENTATION exposes exactly the generated model argument surface."""
    documentation = yaml.safe_load(campus_module.DOCUMENTATION)
    documented = documentation["options"]
    spec = FabricCampusIbgpVxlanModel.get_argument_spec()

    assert documentation["version_added"] == "2.0.0"
    assert set(documented) == set(spec)
    assert set(documented["config"]["suboptions"]) == set(spec["config"]["options"])
    assert set(documented["config"]["suboptions"]["management"]["suboptions"]) == set(spec["config"]["options"]["management"]["options"])
    assert set(documented["config_actions"]["suboptions"]) == set(spec["config_actions"]["options"])
    assert documented["state"]["choices"] == spec["state"]["choices"]


def test_nd_manage_fabric_campus_ibgp_vxlan_00020(monkeypatch) -> None:
    """A changed fabric hands parsed config actions to the orchestrator."""
    requested = {"save": True, "deploy": False, "type": "switch"}
    module = _FakeModule("merged", requested)
    recorder = _ActionRecorder()
    sent = [SimpleNamespace(get_identifier_value=lambda: "campus1")]
    state_machine = SimpleNamespace(
        sent=sent,
        model_orchestrator=recorder,
        output=_FakeOutput(),
        results=SimpleNamespace(),
        manage_state=lambda: None,
    )

    monkeypatch.setattr(campus_module, "AnsibleModule", lambda **kwargs: module)
    monkeypatch.setattr(campus_module, "require_pydantic", lambda value: None)
    monkeypatch.setattr(campus_module, "get_raw_module_args", lambda: {"config_actions": requested})
    monkeypatch.setattr(campus_module, "NDStateMachine", lambda **kwargs: state_machine)

    with pytest.raises(_ExitJson):
        campus_module.main()

    assert len(recorder.calls) == 1
    call = recorder.calls[0]
    assert call["fabric_names"] == ["campus1"]
    assert call["state"] == "merged"
    assert call["check_mode"] is False
    assert call["actions"].save is True
    assert call["actions"].deploy is False
    assert call["actions"].type == "switch"


@pytest.mark.parametrize(
    "state,sent",
    (
        ("merged", []),
        ("deleted", [SimpleNamespace(get_identifier_value=lambda: "campus1")]),
    ),
)
def test_nd_manage_fabric_campus_ibgp_vxlan_00030(monkeypatch, state: str, sent: list) -> None:
    """No-drift and deleted runs never invoke fabric save/deploy actions."""
    requested = {"save": True, "deploy": False, "type": "switch"}
    module = _FakeModule(state, requested)
    recorder = _ActionRecorder()
    state_machine = SimpleNamespace(
        sent=sent,
        model_orchestrator=recorder,
        output=_FakeOutput(),
        results=SimpleNamespace(),
        manage_state=lambda: None,
    )

    monkeypatch.setattr(campus_module, "AnsibleModule", lambda **kwargs: module)
    monkeypatch.setattr(campus_module, "require_pydantic", lambda value: None)
    monkeypatch.setattr(campus_module, "get_raw_module_args", lambda: {"config_actions": requested})
    monkeypatch.setattr(campus_module, "NDStateMachine", lambda **kwargs: state_machine)

    with pytest.raises(_ExitJson):
        campus_module.main()

    assert recorder.calls == []
