# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Module-surface tests for ``nd_manage_fabric_campus_ibgp_vxlan``."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import yaml

from ansible.module_utils.common.arg_spec import ModuleArgumentSpecValidator
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


@pytest.mark.parametrize("config", (None, []), ids=("omitted", "empty"))
@pytest.mark.parametrize("check_mode", (False, True))
def test_nd_manage_fabric_campus_ibgp_vxlan_00040(
    monkeypatch,
    config,
    check_mode,
) -> None:
    """Gathered accepts omitted/empty config and skips fabric actions."""
    module = _FakeModule("gathered", None)
    module.params["config"] = config
    module.check_mode = check_mode

    recorder = _ActionRecorder()
    events = []

    state_machine = SimpleNamespace(
        sent=[],
        model_orchestrator=recorder,
        output=_FakeOutput(),
        results=SimpleNamespace(),
        manage_state=lambda: events.append("manage_state"),
    )

    def initialize_state_machine(**kwargs):
        assert kwargs["module"] is module
        events.append("initialize")
        return state_machine

    def initialize_ansible_module(**kwargs):
        assert kwargs["required_if"] == FabricCampusIbgpVxlanModel.get_required_if()

        supplied_args = {"state": "gathered"}
        if config is not None:
            supplied_args["config"] = config

        validation = ModuleArgumentSpecValidator(
            kwargs["argument_spec"],
            required_if=kwargs["required_if"],
        ).validate(supplied_args)

        assert validation.error_messages == []
        return module

    monkeypatch.setattr(campus_module, "AnsibleModule", initialize_ansible_module)
    monkeypatch.setattr(campus_module, "require_pydantic", lambda value: None)
    monkeypatch.setattr(campus_module, "get_raw_module_args", lambda: {})
    monkeypatch.setattr(campus_module, "NDStateMachine", initialize_state_machine)

    with pytest.raises(_ExitJson):
        campus_module.main()

    assert events == ["initialize", "manage_state"]
    assert recorder.calls == []


def test_nd_manage_fabric_campus_ibgp_vxlan_00050(
    monkeypatch,
) -> None:
    """Nonempty gathered config fails before state-machine initialization."""
    module = _FakeModule("gathered", None)
    # The existing fake supplies nonempty Campus configuration.

    def must_not_initialize(**kwargs):
        pytest.fail("NDStateMachine must not initialize for invalid gathered config")

    monkeypatch.setattr(campus_module, "AnsibleModule", lambda **kwargs: module)
    monkeypatch.setattr(campus_module, "require_pydantic", lambda value: None)
    monkeypatch.setattr(campus_module, "NDStateMachine", must_not_initialize)

    with pytest.raises(AssertionError, match="gather-all only"):
        campus_module.main()


@pytest.mark.parametrize(
    "requested",
    (
        {"save": True},
        {"save": True, "deploy": True},
    ),
    ids=("save", "save_and_deploy"),
)
def test_nd_manage_fabric_campus_ibgp_vxlan_00060(
    monkeypatch,
    requested,
) -> None:
    """Enabled fabric actions fail before gathered controller queries."""
    module = _FakeModule("gathered", requested)
    module.params["config"] = []

    def must_not_initialize(**kwargs):
        pytest.fail("NDStateMachine must not initialize for invalid gathered actions")

    monkeypatch.setattr(campus_module, "AnsibleModule", lambda **kwargs: module)
    monkeypatch.setattr(campus_module, "require_pydantic", lambda value: None)
    monkeypatch.setattr(
        campus_module,
        "get_raw_module_args",
        lambda: {"config_actions": requested},
    )
    monkeypatch.setattr(campus_module, "NDStateMachine", must_not_initialize)

    with pytest.raises(
        AssertionError,
        match="not allowed for state='gathered'",
    ):
        campus_module.main()


@pytest.mark.parametrize(
    "state",
    ("merged", "replaced", "overridden", "deleted"),
)
def test_nd_manage_fabric_campus_ibgp_vxlan_00070(
    monkeypatch,
    state,
) -> None:
    """Write states reject omitted config before state-machine initialization."""
    module = _FakeModule(state, None)
    module.params["config"] = None

    def initialize_ansible_module(**kwargs):
        validation = ModuleArgumentSpecValidator(
            kwargs["argument_spec"],
            required_if=kwargs.get("required_if", []),
        ).validate({"state": state})

        assert validation.error_messages
        module.fail_json(msg="; ".join(validation.error_messages))

    def must_not_initialize(**kwargs):
        pytest.fail("Missing write-state config must not initialize NDStateMachine")

    monkeypatch.setattr(campus_module, "AnsibleModule", initialize_ansible_module)
    monkeypatch.setattr(campus_module, "NDStateMachine", must_not_initialize)

    with pytest.raises(AssertionError, match="missing.*config"):
        campus_module.main()
