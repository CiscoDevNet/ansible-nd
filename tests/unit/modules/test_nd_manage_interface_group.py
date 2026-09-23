# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the nd_manage_interface_group module boundary."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
    NDStateMachineError,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import (
    HttpVerbEnum,
    OperationType,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.config_models import (
    InterfaceGroupConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.validators import (
    InterfaceGroupValidators,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
    NDConfigCollection,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.modules import (
    nd_manage_interface_group,
)


def test_nd_manage_interface_group_00005() -> None:
    """
    # Summary

    Verify Pydantic normalization runs before state-machine construction.

    ## Test

    - Build the Ansible module and require Pydantic.
    - Normalize argspec input before constructing or running the state machine.

    ## Classes and Methods

    - nd_manage_interface_group.main()
    """
    events = []

    class FakeAnsibleModule:
        def __init__(self, **kwargs):
            self.params = {"output_level": "normal"}
            self.check_mode = False
            events.append(("AnsibleModule", kwargs))

        def exit_json(self, **kwargs):
            events.append(("exit_json", kwargs))

        def fail_json(self, **kwargs):
            raise AssertionError(f"fail_json called unexpectedly: {kwargs}")

    class FakeOutput:
        @staticmethod
        def format_with_verbosity(verbosity, results, **kwargs):
            assert verbosity == 0
            assert isinstance(results, Results)
            assert kwargs == {}
            return {"changed": True}

    class FakeOrchestrator:
        warnings = []

        @staticmethod
        def deploy_pending():
            events.append(("deploy_pending",))

    class FakeStateMachine:
        def __init__(self, **kwargs):
            events.append(("NDStateMachine", kwargs))
            self.output = FakeOutput()
            self.results = Results()
            self.model_orchestrator = FakeOrchestrator()

        @staticmethod
        def manage_state():
            events.append(("manage_state",))

    def fake_require_pydantic(module):
        events.append(("require_pydantic", module))

    def fake_normalize(module):
        events.append(("normalize", module))

    with patch.object(nd_manage_interface_group, "AnsibleModule", FakeAnsibleModule), patch.object(
        nd_manage_interface_group, "require_pydantic", fake_require_pydantic
    ), patch.object(nd_manage_interface_group, "setup_logging"), patch.object(
        nd_manage_interface_group, "_normalize_module_params", fake_normalize
    ), patch.object(
        nd_manage_interface_group, "NDStateMachine", FakeStateMachine
    ):
        nd_manage_interface_group.main()

    assert [event[0] for event in events] == [
        "AnsibleModule",
        "require_pydantic",
        "normalize",
        "NDStateMachine",
        "manage_state",
        "deploy_pending",
        "exit_json",
    ]
    assert events[0][1]["argument_spec"]["timeout"]["default"] == 300
    assert events[0][1]["argument_spec"]["config_actions"]["options"]["deploy"]["default"] is False


def test_nd_manage_interface_group_00007() -> None:
    """Verify warnings and CLI verbosity use the standard NDOutput path."""

    results = Results()
    results.action = OperationType.UPDATE.value
    results.operation_type = OperationType.UPDATE
    results.path_current = "/api/v1/manage/fabrics/fabric-1/interfaceGroups/group-a"
    results.verb_current = HttpVerbEnum.PUT
    results.payload_current = {"interfaceGroupName": "group-a"}
    results.response_current = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    results.result_current = {"success": True, "changed": True}
    results.diff_current = {}
    results.verbosity_level_current = 2
    results.register_api_call()

    state_machine = SimpleNamespace(
        output=NDOutput("normal"),
        results=results,
        model_orchestrator=SimpleNamespace(warnings=["Resource-level deployment does not deploy network-a."]),
    )
    module = SimpleNamespace(params={"output_level": "normal"}, _verbosity=2)

    assert nd_manage_interface_group._format_output(module, state_machine) == {
        "output_level": "normal",
        "changed": True,
        "after": [],
        "before": [],
        "diff": [],
        "api_paths": ["/api/v1/manage/fabrics/fabric-1/interfaceGroups/group-a"],
        "api_verbs": [HttpVerbEnum.PUT],
        "warnings_nd": ["Resource-level deployment does not deploy network-a."],
    }


@pytest.mark.parametrize(
    ("output_level", "expected_keys", "excluded_keys"),
    [
        ("normal", set(), {"proposed", "logs"}),
        ("info", {"proposed"}, {"logs"}),
        ("debug", {"proposed", "logs"}, set()),
    ],
)
def test_nd_manage_interface_group_00008(output_level, expected_keys, excluded_keys) -> None:
    """Return the standard NDOutput shape even before state-machine creation."""
    module = SimpleNamespace(params={"output_level": output_level}, _verbosity=0)

    output = nd_manage_interface_group._format_output(
        module,
        None,
        changed=False,
    )

    assert {
        "output_level",
        "changed",
        "after",
        "before",
        "diff",
    }.issubset(output)
    assert output["output_level"] == output_level
    assert expected_keys.issubset(output)
    assert excluded_keys.isdisjoint(output)


def test_nd_manage_interface_group_00009() -> None:
    """Expose read-operation details only at Ansible verbosity C(-vvv)."""
    results = Results()
    results.action = OperationType.QUERY.value
    results.operation_type = OperationType.QUERY
    results.path_current = "/api/v1/manage/fabrics/fabric-1/interfaceGroups"
    results.verb_current = HttpVerbEnum.GET
    results.payload_current = None
    results.response_current = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    results.result_current = {"success": True, "changed": False}
    results.diff_current = {}
    results.verbosity_level_current = 3
    results.register_api_call()
    state_machine = SimpleNamespace(
        output=NDOutput("normal"),
        results=results,
        model_orchestrator=SimpleNamespace(warnings=[]),
    )

    quiet_query = nd_manage_interface_group._format_output(
        SimpleNamespace(params={"output_level": "normal"}, _verbosity=2),
        state_machine,
    )
    verbose_query = nd_manage_interface_group._format_output(
        SimpleNamespace(params={"output_level": "normal"}, _verbosity=3),
        state_machine,
    )

    assert "api_paths" not in quiet_query
    assert verbose_query["api_paths"] == ["/api/v1/manage/fabrics/fabric-1/interfaceGroups"]
    assert verbose_query["api_verbs"] == [HttpVerbEnum.GET]
    assert {
        "api_response",
        "api_result",
        "api_diff",
        "api_metadata",
        "api_payload",
    }.issubset(verbose_query)


def test_nd_manage_interface_group_00010() -> None:
    """
    # Summary

    Verify argspec input is normalized through Pydantic before orchestration.

    ## Test

    - Normalize names, networks, switches, and interfaces.
    - Preserve resource-level deployment controls.

    ## Classes and Methods

    - nd_manage_interface_group._normalize_module_params()
    """
    module = SimpleNamespace(
        params={
            "fabric_name": " fabric-1 ",
            "state": "merged",
            "config_actions": {"type": "resource", "deploy": True},
            "config": [
                {
                    "interface_group_name": " port-channel-group ",
                    "type": "portChannel",
                    "networks": ["network-b", "network-a", "network-a"],
                    "switch_interfaces": [
                        {
                            "switch_id": " FDO1 ",
                            "interface_names": [
                                "po20",
                                "Port-channel10",
                                "po20",
                            ],
                        }
                    ],
                    "deploy": True,
                }
            ],
        }
    )

    nd_manage_interface_group._normalize_module_params(module)

    assert module.params["fabric_name"] == "fabric-1"
    assert module.params["config_actions"] == {
        "deploy": True,
        "type": "resource",
    }
    assert module.params["config"] == [
        {
            "interface_group_name": "port-channel-group",
            "type": "portChannel",
            "networks": ["network-a", "network-b"],
            "switch_interfaces": [
                {
                    "switch_id": "FDO1",
                    "interface_names": ["Port-channel10", "Port-channel20"],
                }
            ],
            "deploy": True,
        }
    ]


@pytest.mark.parametrize(
    ("config_update", "expected_update"),
    [
        ({}, {}),
        (
            {"ethernet_attributes": {"cdp": False}},
            {"ethernet_attributes": {"cdp": False}},
        ),
        (
            {"ethernet_attributes": {}},
            {"ethernet_attributes": {}},
        ),
    ],
)
def test_nd_manage_interface_group_00011(
    config_update: dict[str, Any],
    expected_update: dict[str, Any],
) -> None:
    """Preserve sparse Ethernet policy input across merged normalization."""
    module = SimpleNamespace(
        params={
            "fabric_name": "fabric-1",
            "state": "merged",
            "config_actions": {"type": "resource", "deploy": False},
            "config": [
                {
                    "interface_group_name": "ethernet-policy-group",
                    "type": "ethernetWithPolicy",
                    "networks": ["network-b"],
                    **config_update,
                }
            ],
        }
    )

    nd_manage_interface_group._normalize_module_params(module)

    assert module.params["config"] == [
        {
            "interface_group_name": "ethernet-policy-group",
            "type": "ethernetWithPolicy",
            "networks": ["network-b"],
            **expected_update,
        }
    ]


def test_nd_manage_interface_group_00012() -> None:
    """Materialize controller-required Ethernet defaults after a sparse create handoff."""
    module = SimpleNamespace(
        params={
            "fabric_name": "fabric-1",
            "state": "merged",
            "config_actions": {"type": "resource", "deploy": False},
            "config": [
                {
                    "interface_group_name": "new-ethernet-policy-group",
                    "type": "ethernetWithPolicy",
                }
            ],
        }
    )

    nd_manage_interface_group._normalize_module_params(module)

    assert "ethernet_attributes" not in module.params["config"][0]
    reparsed = InterfaceGroupConfigModel.from_config(module.params["config"][0])
    assert reparsed.to_payload()["ethernetAttributes"] == InterfaceGroupValidators.ethernet_with_policy_defaults()


@pytest.mark.parametrize("deploy_enabled", [False, True])
def test_nd_manage_interface_group_00013(
    monkeypatch: pytest.MonkeyPatch,
    deploy_enabled: bool,
) -> None:
    """Keep existing policy and associations through sparse check, apply, and replay."""
    existing_attributes = {
        "admin_state": False,
        "allowed_vlans": "10-20",
        "cdp": False,
        "mtu": "default",
        "speed": "1Gb",
    }
    controller_state = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "ethernet-policy-group",
            "type": "ethernetWithPolicy",
            "networks": ["network-a"],
            "switch_interfaces": [
                {
                    "switch_id": "SN1",
                    "interface_names": ["Ethernet1/10"],
                }
            ],
            "ethernet_attributes": existing_attributes,
        }
    )
    put_models: list[InterfaceGroupConfigModel] = []
    deploy_calls: list[set[tuple[str, str]]] = []

    def fake_query_all(self, model_instance=None, **kwargs):
        del model_instance, kwargs
        response = InterfaceGroupValidators.to_wire_group(
            controller_state.to_payload(),
            include_empty_associations=True,
        )
        observed = InterfaceGroupConfigModel.from_response(response)
        self._existing_groups = {
            observed.interface_group_name: deepcopy(observed),
        }
        return [response]

    def fake_network_names(self):
        del self
        return {"network-a", "network-b"}

    def fake_put_group(self, model_instance):
        nonlocal controller_state
        del self
        put_models.append(deepcopy(model_instance))
        controller_state = deepcopy(model_instance)
        return {}

    def fake_deploy_interfaces(self, interfaces):
        del self
        deploy_calls.append(set(interfaces))
        return {}

    orchestrator_class = nd_manage_interface_group.ManageInterfaceGroupOrchestrator
    monkeypatch.setattr(orchestrator_class, "query_all", fake_query_all)
    monkeypatch.setattr(
        orchestrator_class,
        "_fetch_fabric_network_names",
        fake_network_names,
    )
    monkeypatch.setattr(orchestrator_class, "_put_group", fake_put_group)
    monkeypatch.setattr(
        orchestrator_class,
        "_deploy_interfaces",
        fake_deploy_interfaces,
    )

    def run_state_machine(check_mode: bool):
        module = SimpleNamespace(
            params={
                "fabric_name": "fabric-1",
                "state": "merged",
                "config_actions": {
                    "type": "resource",
                    "deploy": deploy_enabled,
                },
                "config": [
                    {
                        "interface_group_name": "ethernet-policy-group",
                        "type": "ethernetWithPolicy",
                        "networks": ["network-b"],
                    }
                ],
                "output_level": "normal",
            },
            check_mode=check_mode,
            no_log_values=set(),
            warn=lambda message: None,
        )
        nd_manage_interface_group._normalize_module_params(module)
        assert "ethernet_attributes" not in module.params["config"][0]
        state_machine = nd_manage_interface_group.NDStateMachine(
            module=module,
            model_orchestrator=orchestrator_class,
        )
        state_machine.manage_state()
        state_machine.model_orchestrator.deploy_pending()
        return state_machine

    def assert_nondefault_attributes_preserved(group):
        actual = group.ethernet_attributes.to_config()
        assert {key: actual[key] for key in existing_attributes} == existing_attributes

    check_mode_state = run_state_machine(check_mode=True)
    predicted = check_mode_state.existing.get("ethernet-policy-group")
    assert predicted.networks == ["network-a", "network-b"]
    assert predicted.switch_interfaces[0].interface_names == ["Ethernet1/10"]
    assert_nondefault_attributes_preserved(predicted)
    assert controller_state.networks == ["network-a"]
    assert put_models == []
    assert deploy_calls == []

    applied_state = run_state_machine(check_mode=False)
    applied = applied_state.existing.get("ethernet-policy-group")
    assert applied.networks == ["network-a", "network-b"]
    assert applied.switch_interfaces[0].interface_names == ["Ethernet1/10"]
    assert_nondefault_attributes_preserved(applied)
    assert len(put_models) == 1
    assert_nondefault_attributes_preserved(put_models[0])
    assert deploy_calls == ([{("SN1", "Ethernet1/10")}] if deploy_enabled else [])

    replay_state = run_state_machine(check_mode=False)
    replayed = replay_state.existing.get("ethernet-policy-group")
    assert replayed.to_config() == controller_state.to_config()
    assert len(put_models) == 1
    assert deploy_calls == ([{("SN1", "Ethernet1/10")}] if deploy_enabled else [])


@pytest.mark.parametrize(
    ("config_update", "error"),
    [
        ({"unsupported": True}, r"unsupported option\(s\) in config\[0\]"),
        (
            {
                "switch_interfaces": [
                    {
                        "switch_id": "FDO1",
                        "interface_names": ["po10"],
                        "unsupported": True,
                    }
                ]
            },
            r"unsupported option\(s\) in config\[0\]\.switch_interfaces\[0\]",
        ),
        (
            {"ethernet_attributes": {"native_vlan": 4095}},
            "native_vlan",
        ),
        (
            {"ethernet_attributes": {"description": "server link"}},
            "description",
        ),
    ],
)
def test_nd_manage_interface_group_00020(config_update, error) -> None:
    """
    # Summary

    Verify unsupported and invalid nested argspec values fail in Pydantic.

    ## Test

    - Reject unknown config and switch-interface keys.
    - Reject an invalid Ethernet policy VLAN.

    ## Classes and Methods

    - nd_manage_interface_group._normalize_module_params()
    """
    config = {
        "interface_group_name": "group-1",
        "type": "ethernetWithPolicy",
        **config_update,
    }
    module = SimpleNamespace(
        params={
            "fabric_name": "fabric-1",
            "state": "merged",
            "config_actions": {"type": "resource", "deploy": True},
            "config": [config],
        }
    )

    with pytest.raises((ValidationError, ValueError), match=error):
        nd_manage_interface_group._normalize_module_params(module)


def test_nd_manage_interface_group_00025() -> None:
    """Normalize gathered filters while clearing desired write configuration."""
    module = SimpleNamespace(
        params={
            "fabric_name": " fabric-1 ",
            "state": "gathered",
            "config_actions": {"type": "switch", "deploy": True},
            "config": [
                {
                    "networks": ["network-b", "network-a"],
                    "switch_interfaces": [{"switch_id": " SN1 "}],
                }
            ],
        }
    )

    filters = nd_manage_interface_group._normalize_module_params(module)

    assert module.params["fabric_name"] == "fabric-1"
    assert module.params["state"] == "gathered"
    assert module.params["config"] == []
    assert len(filters) == 1
    assert filters[0].to_filter_config() == {
        "networks": ["network-a", "network-b"],
        "switch_interfaces": [{"switch_id": "SN1"}],
    }


def test_nd_manage_interface_group_00027() -> None:
    """Gathered exits read-only without reconciliation or deployment."""
    events = []

    class ModuleExited(BaseException):
        """Stop the fake Ansible module after exit_json."""

    class FakeAnsibleModule:
        def __init__(self, **kwargs):
            del kwargs
            self.params = {
                "fabric_name": "fabric-1",
                "state": "gathered",
                "config": [],
                "config_actions": None,
                "output_level": "normal",
            }
            self.check_mode = False

        def exit_json(self, **kwargs):
            events.append(("exit_json", kwargs))
            raise ModuleExited

        def fail_json(self, **kwargs):
            raise AssertionError(f"fail_json called unexpectedly: {kwargs}")

    class FakeOrchestrator:
        warnings = []

        @staticmethod
        def gather(filters):
            events.append(("gather", filters))
            return [{"interface_group_name": "group-a", "type": "any"}]

        @staticmethod
        def deploy_pending():
            raise AssertionError("deploy_pending must not run for gathered")

    class FakeStateMachine:
        def __init__(self, **kwargs):
            del kwargs
            self.model_orchestrator = FakeOrchestrator()
            self.output = NDOutput("normal")
            self.results = Results()

        @staticmethod
        def manage_state():
            raise AssertionError("manage_state must not run for gathered")

    with patch.object(nd_manage_interface_group, "AnsibleModule", FakeAnsibleModule), patch.object(
        nd_manage_interface_group, "require_pydantic"
    ), patch.object(nd_manage_interface_group, "setup_logging"), patch.object(nd_manage_interface_group, "NDStateMachine", FakeStateMachine), pytest.raises(
        ModuleExited
    ):
        nd_manage_interface_group.main()

    assert events == [
        ("gather", []),
        (
            "exit_json",
            {
                "output_level": "normal",
                "changed": False,
                "after": [],
                "before": [],
                "diff": [],
                "gathered": [{"interface_group_name": "group-a", "type": "any"}],
            },
        ),
    ]


def test_nd_manage_interface_group_00030() -> None:
    """Verify Pydantic input failure returns changed=false before orchestration."""
    events = []

    class ModuleFailed(BaseException):
        """Stop the fake Ansible module after fail_json."""

    class FakeAnsibleModule:
        def __init__(self, **kwargs):
            del kwargs
            self.params = {"output_level": "normal"}
            self.check_mode = False

        def exit_json(self, **kwargs):
            raise AssertionError(f"exit_json called unexpectedly: {kwargs}")

        def fail_json(self, **kwargs):
            events.append(kwargs)
            raise ModuleFailed

    def reject_input(module):
        del module
        raise ValueError("invalid Interface Group input")

    def unexpected_state_machine(**kwargs):
        raise AssertionError(f"state machine constructed unexpectedly: {kwargs}")

    with patch.object(nd_manage_interface_group, "AnsibleModule", FakeAnsibleModule), patch.object(
        nd_manage_interface_group, "require_pydantic"
    ), patch.object(nd_manage_interface_group, "setup_logging"), patch.object(
        nd_manage_interface_group, "_normalize_module_params", reject_input
    ), patch.object(
        nd_manage_interface_group, "NDStateMachine", unexpected_state_machine
    ), pytest.raises(
        ModuleFailed
    ):
        nd_manage_interface_group.main()

    assert events == [
        {
            "msg": "Module validation failed: invalid Interface Group input",
            "output_level": "normal",
            "changed": False,
            "after": [],
            "before": [],
            "diff": [],
        }
    ]


class _BoundaryModuleFailed(BaseException):
    """Stop a module-boundary test after ``fail_json`` captures its output."""


def _boundary_group(
    name: str,
    *,
    networks: list[str] | None = None,
    members: list[str] | None = None,
) -> InterfaceGroupConfigModel:
    """Build one small port-channel Interface Group for boundary tests."""
    return InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": name,
            "type": "portChannel",
            "networks": networks or [],
            "switch_interfaces": (
                [
                    {
                        "switch_id": "SN1",
                        "interface_names": members,
                    }
                ]
                if members
                else []
            ),
        }
    )


def _boundary_collection(*groups: InterfaceGroupConfigModel) -> NDConfigCollection:
    """Return an Interface Group collection for before/after assertions."""
    return NDConfigCollection(
        model_class=InterfaceGroupConfigModel,
        items=list(groups),
    )


class _FailingBoundaryOutput(NDOutput):
    """Raise from formatting while recording each attempted invocation."""

    def __init__(
        self,
        output_level: str,
        *,
        state: str,
        error: Exception,
        call_log: list[str],
    ) -> None:
        super().__init__(output_level, state=state)
        self._error = error
        self._call_log = call_log

    def format_with_verbosity(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        del args, kwargs
        self._call_log.append("format_with_verbosity")
        raise self._error


class _BoundaryOrchestrator:
    """Record normal and failure-path deployment calls made by ``main``."""

    warnings: list[str] = []

    def __init__(
        self,
        *,
        confirmed: NDConfigCollection,
        deploy_enabled: bool,
        deploy_result: dict[str, list[Any]] | None = None,
        finalizer_error: Exception | None = None,
        normal_deploy_error: Exception | None = None,
        has_unresolved_accepted_changes: bool = False,
    ) -> None:
        self._confirmed = list(confirmed)
        self._deploy_enabled = deploy_enabled
        self._deploy_result = deploy_result or {"interfaces": [], "switches": []}
        self._finalizer_error = finalizer_error
        self._normal_deploy_error = normal_deploy_error
        self._has_unresolved_accepted_changes = has_unresolved_accepted_changes
        self.deploy_attempted = False
        self.finalizer_calls = 0
        self.deployment_requests = 0

    @property
    def has_unresolved_accepted_changes(self) -> bool:
        """Return whether accepted NDFC changes cannot be attributed safely."""
        return self._has_unresolved_accepted_changes

    def confirmed_groups(self) -> list[InterfaceGroupConfigModel]:
        """Return the NDFC-confirmed state used for failure output."""
        return list(self._confirmed)

    def deploy_pending(self) -> None:
        """Simulate the normal deployment stage."""
        if self._normal_deploy_error is None:
            return
        self.deploy_attempted = True
        self.deployment_requests += 1
        raise self._normal_deploy_error

    def deploy_accepted_mutations(self) -> dict[str, list[Any]]:
        """Simulate the Interface Group failure-path finalizer."""
        self.finalizer_calls += 1
        if not self._deploy_enabled or self.deploy_attempted:
            return {"interfaces": [], "switches": []}
        if self._finalizer_error is not None:
            self.deployment_requests += 1
            raise self._finalizer_error
        if self._deploy_result.get("interfaces") or self._deploy_result.get("switches"):
            self.deployment_requests += 1
        return self._deploy_result


class _BoundaryStateMachine:
    """State-machine stand-in with distinct predicted and confirmed states."""

    def __init__(
        self,
        *,
        module: Any,
        before: NDConfigCollection,
        predicted: NDConfigCollection,
        confirmed: NDConfigCollection,
        failure: Exception | None,
        deploy_enabled: bool,
        deploy_result: dict[str, list[Any]] | None = None,
        finalizer_error: Exception | None = None,
        normal_deploy_error: Exception | None = None,
        has_unresolved_accepted_changes: bool = False,
        formatter_error: Exception | None = None,
        formatter_call_log: list[str] | None = None,
    ) -> None:
        self.model_class = InterfaceGroupConfigModel
        self.before = before
        if formatter_error is None:
            self.output = NDOutput(module.params["output_level"], state=module.params["state"])
        else:
            self.output = _FailingBoundaryOutput(
                module.params["output_level"],
                state=module.params["state"],
                error=formatter_error,
                call_log=formatter_call_log if formatter_call_log is not None else [],
            )
        self.output.assign(before=before, after=predicted)
        self.results = Results()
        self.results.action = OperationType.UPDATE.value
        self.results.operation_type = OperationType.UPDATE
        self.results.path_current = "/api/v1/manage/fabrics/fabric-1/interfaceGroups/target"
        self.results.verb_current = HttpVerbEnum.PUT
        self.results.payload_current = {"interfaceGroupName": "target"}
        self.results.response_current = {"RETURN_CODE": 500, "MESSAGE": "rejected"}
        # Deliberately report an API-level change. Failure formatting must still
        # derive the final changed value from before versus confirmed state.
        self.results.result_current = {"success": False, "changed": True}
        self.results.diff_current = {"predicted": True}
        self.results.verbosity_level_current = 2
        self.results.register_api_call()
        self.model_orchestrator = _BoundaryOrchestrator(
            confirmed=confirmed,
            deploy_enabled=deploy_enabled,
            deploy_result=deploy_result,
            finalizer_error=finalizer_error,
            normal_deploy_error=normal_deploy_error,
            has_unresolved_accepted_changes=has_unresolved_accepted_changes,
        )
        self._failure = failure

    def manage_state(self) -> None:
        """Raise the configured reconciliation failure, if any."""
        if self._failure is not None:
            raise self._failure


def _run_failure_boundary(  # pylint: disable=too-many-arguments
    monkeypatch: pytest.MonkeyPatch,
    *,
    failure: Exception | None,
    before: NDConfigCollection,
    predicted: NDConfigCollection,
    confirmed: NDConfigCollection,
    deploy_enabled: bool = True,
    check_mode: bool = False,
    deploy_result: dict[str, list[Any]] | None = None,
    finalizer_error: Exception | None = None,
    normal_deploy_error: Exception | None = None,
    has_unresolved_accepted_changes: bool = False,
    formatter_error: Exception | None = None,
    formatter_call_log: list[str] | None = None,
) -> tuple[dict[str, Any], _BoundaryOrchestrator]:
    """Drive ``main`` and return captured failure output and orchestrator calls."""

    class FakeAnsibleModule:
        def __init__(self, **kwargs: Any) -> None:
            del kwargs
            self.params = {
                "fabric_name": "fabric-1",
                "state": "merged",
                "config": [],
                "config_actions": {"deploy": deploy_enabled, "type": "resource"},
                "output_level": "normal",
            }
            self.check_mode = check_mode
            self._verbosity = 2

        @staticmethod
        def exit_json(**kwargs: Any) -> None:
            raise AssertionError(f"exit_json called unexpectedly: {kwargs}")

        @staticmethod
        def fail_json(**kwargs: Any) -> None:
            raise _BoundaryModuleFailed(kwargs)

    module = FakeAnsibleModule()
    state_machine = _BoundaryStateMachine(
        module=module,
        before=before,
        predicted=predicted,
        confirmed=confirmed,
        failure=failure,
        deploy_enabled=deploy_enabled,
        deploy_result=deploy_result,
        finalizer_error=finalizer_error,
        normal_deploy_error=normal_deploy_error,
        has_unresolved_accepted_changes=has_unresolved_accepted_changes,
        formatter_error=formatter_error,
        formatter_call_log=formatter_call_log,
    )

    monkeypatch.setattr(nd_manage_interface_group, "AnsibleModule", lambda **kwargs: module)
    monkeypatch.setattr(nd_manage_interface_group, "require_pydantic", lambda module: None)
    monkeypatch.setattr(nd_manage_interface_group, "setup_logging", lambda module: None)
    monkeypatch.setattr(nd_manage_interface_group, "_normalize_module_params", lambda module: [])
    monkeypatch.setattr(nd_manage_interface_group, "NDStateMachine", lambda **kwargs: state_machine)

    with pytest.raises(_BoundaryModuleFailed) as exc_info:
        nd_manage_interface_group.main()
    return exc_info.value.args[0], state_machine.model_orchestrator


@pytest.mark.parametrize(
    ("failure", "deploy_result", "message_prefix", "target_text"),
    [
        (
            NDStateMachineError("target update rejected"),
            {"interfaces": [("SN1", "Port-channel10")], "switches": []},
            "Module execution failed: target update rejected",
            "interface(s) [Port-channel10 (switchId SN1)]",
        ),
        (
            RuntimeError("unexpected target failure"),
            {"interfaces": [], "switches": ["SN1"]},
            "Module failed: unexpected target failure",
            "switch(es) [SN1]",
        ),
        (
            ValueError("late validation failure"),
            {"interfaces": [("SN1", "Port-channel10")], "switches": []},
            "Module validation failed: late validation failure",
            "interface(s) [Port-channel10 (switchId SN1)]",
        ),
    ],
)
def test_nd_manage_interface_group_00040(
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
    deploy_result: dict[str, list[Any]],
    message_prefix: str,
    target_text: str,
) -> None:
    """Finalize accepted mutations and report only NDFC-confirmed state."""
    source_before = _boundary_group("source", networks=["network-a"], members=["Port-channel10"])
    source_detached = _boundary_group("source")
    target_before = _boundary_group("target")
    target_predicted = _boundary_group("target", networks=["network-b"], members=["Port-channel10"])
    before = _boundary_collection(source_before, target_before)
    confirmed = _boundary_collection(source_detached, target_before)

    output, orchestrator = _run_failure_boundary(
        monkeypatch,
        failure=failure,
        before=before,
        predicted=_boundary_collection(source_detached, target_predicted),
        confirmed=confirmed,
        deploy_result=deploy_result,
    )

    assert output["msg"].startswith(message_prefix)
    assert target_text in output["msg"]
    assert output["msg"].endswith("those changes were deployed.")
    assert output["before"] == before.to_ansible_config()
    assert output["after"] == confirmed.to_ansible_config()
    assert output["changed"] is True
    assert output["diff"] == []
    assert output["api_paths"] == ["/api/v1/manage/fabrics/fabric-1/interfaceGroups/target"]
    assert orchestrator.finalizer_calls == 1
    assert orchestrator.deployment_requests == 1


@pytest.mark.parametrize(
    ("deploy_enabled", "check_mode", "confirmed_changed", "expected_finalizer_calls"),
    [
        (False, False, True, 1),
        (True, True, False, 0),
    ],
)
def test_nd_manage_interface_group_00050(
    monkeypatch: pytest.MonkeyPatch,
    deploy_enabled: bool,
    check_mode: bool,
    confirmed_changed: bool,
    expected_finalizer_calls: int,
) -> None:
    """Honor deploy false and check mode without losing truthful failure output."""
    before_group = _boundary_group("source", networks=["network-a"], members=["Port-channel10"])
    accepted_group = _boundary_group("source")
    before = _boundary_collection(before_group)
    confirmed = _boundary_collection(accepted_group) if confirmed_changed else before.copy()

    output, orchestrator = _run_failure_boundary(
        monkeypatch,
        failure=NDStateMachineError("later failure"),
        before=before,
        predicted=_boundary_collection(),
        confirmed=confirmed,
        deploy_enabled=deploy_enabled,
        check_mode=check_mode,
        deploy_result={"interfaces": [("SN1", "Port-channel10")], "switches": []},
    )

    assert output["msg"] == "Module execution failed: later failure"
    assert output["after"] == confirmed.to_ansible_config()
    assert output["changed"] is confirmed_changed
    assert output["diff"] == []
    assert orchestrator.finalizer_calls == expected_finalizer_calls
    assert orchestrator.deployment_requests == 0


def test_nd_manage_interface_group_00060(monkeypatch: pytest.MonkeyPatch) -> None:
    """Preserve the primary error when failure-path deployment also fails."""
    before_group = _boundary_group("source", networks=["network-a"], members=["Port-channel10"])
    accepted_group = _boundary_group("source")
    before = _boundary_collection(before_group)
    confirmed = _boundary_collection(accepted_group)

    output, orchestrator = _run_failure_boundary(
        monkeypatch,
        failure=NDStateMachineError("target update rejected"),
        before=before,
        predicted=_boundary_collection(),
        confirmed=confirmed,
        finalizer_error=RuntimeError("failure-path deploy rejected"),
    )

    assert output["msg"].startswith("Module execution failed: target update rejected")
    assert "deploying those changes also failed" in output["msg"]
    assert "failure-path deploy rejected" in output["msg"]
    assert output["after"] == confirmed.to_ansible_config()
    assert output["changed"] is True
    assert orchestrator.finalizer_calls == 1
    assert orchestrator.deployment_requests == 1


def test_nd_manage_interface_group_00070(monkeypatch: pytest.MonkeyPatch) -> None:
    """Do not resubmit a normal deployment request that already failed."""
    before_group = _boundary_group("source", networks=["network-a"], members=["Port-channel10"])
    accepted_group = _boundary_group("source")
    before = _boundary_collection(before_group)
    confirmed = _boundary_collection(accepted_group)

    output, orchestrator = _run_failure_boundary(
        monkeypatch,
        failure=None,
        before=before,
        predicted=confirmed,
        confirmed=confirmed,
        deploy_result={"interfaces": [("SN1", "Port-channel10")], "switches": []},
        normal_deploy_error=RuntimeError("normal deploy rejected"),
    )

    assert output["msg"] == "Module failed: normal deploy rejected"
    assert output["after"] == confirmed.to_ansible_config()
    assert output["changed"] is True
    assert orchestrator.deploy_attempted is True
    assert orchestrator.finalizer_calls == 1
    assert orchestrator.deployment_requests == 1


def test_nd_manage_interface_group_00080(monkeypatch: pytest.MonkeyPatch) -> None:
    """At verbosity two, confirmed state overrides predicted API-level change."""
    before_group = _boundary_group("source", networks=["network-a"], members=["Port-channel10"])
    before = _boundary_collection(before_group)

    output, orchestrator = _run_failure_boundary(
        monkeypatch,
        failure=NDStateMachineError("request rejected before acceptance"),
        before=before,
        predicted=_boundary_collection(),
        confirmed=before.copy(),
        deploy_enabled=False,
    )

    assert output["after"] == before.to_ansible_config()
    assert output["changed"] is False
    assert output["diff"] == []
    assert output["api_paths"] == ["/api/v1/manage/fabrics/fabric-1/interfaceGroups/target"]
    assert orchestrator.deployment_requests == 0


def test_nd_manage_interface_group_00090(monkeypatch: pytest.MonkeyPatch) -> None:
    """Report unresolved accepted changes conservatively after module failure."""
    before_group = _boundary_group(
        "source",
        networks=["network-a"],
        members=["Port-channel10"],
    )
    before = _boundary_collection(before_group)

    output, orchestrator = _run_failure_boundary(
        monkeypatch,
        failure=NDStateMachineError("mixed create response"),
        before=before,
        predicted=_boundary_collection(),
        confirmed=before.copy(),
        deploy_enabled=False,
        has_unresolved_accepted_changes=True,
    )

    assert output["msg"].startswith("Module execution failed: mixed create response")
    assert "NOTE:" in output["msg"]
    assert "NDFC accepted" in output["msg"]
    assert "could not" in output["msg"]
    assert output["before"] == before.to_ansible_config()
    assert output["after"] == before.to_ansible_config()
    assert output["changed"] is True
    assert output["diff"] == []
    assert orchestrator.has_unresolved_accepted_changes is True


def test_nd_manage_interface_group_00100(monkeypatch: pytest.MonkeyPatch) -> None:
    """Preserve the primary failure when verbosity formatting also fails."""
    before_group = _boundary_group(
        "source",
        networks=["network-a"],
        members=["Port-channel10"],
    )
    accepted_group = _boundary_group("source")
    before = _boundary_collection(before_group)
    confirmed = _boundary_collection(accepted_group)
    formatter_calls: list[str] = []

    output, _orchestrator = _run_failure_boundary(
        monkeypatch,
        failure=NDStateMachineError("primary mutation failure"),
        before=before,
        predicted=_boundary_collection(),
        confirmed=confirmed,
        deploy_enabled=False,
        formatter_error=RuntimeError("verbosity formatting failed"),
        formatter_call_log=formatter_calls,
    )

    assert formatter_calls == ["format_with_verbosity"]
    assert output["msg"].startswith("Module execution failed: primary mutation failure")
    assert "format" in output["msg"].lower()
    assert "verbosity formatting failed" in output["msg"]
    assert output["output_level"] == "normal"
    assert output["before"] == before.to_ansible_config()
    assert output["after"] == confirmed.to_ansible_config()
    assert output["changed"] is True
    assert output["diff"] == []
    assert "api_paths" not in output


def test_nd_manage_interface_group_00110() -> None:
    """Use confirmed success state unless check mode is predicting a change."""
    before_group = _boundary_group(
        "source",
        networks=["network-a"],
        members=["Port-channel10"],
    )
    predicted_group = _boundary_group(
        "source",
        networks=["network-b"],
        members=["Port-channel10"],
    )
    before = _boundary_collection(before_group)
    predicted = _boundary_collection(predicted_group)
    confirmed = before.copy()

    output = NDOutput("normal", state="merged")
    output.assign(before=before, after=predicted)
    results = Results()
    results.action = OperationType.UPDATE.value
    results.operation_type = OperationType.UPDATE
    results.path_current = "/api/v1/manage/fabrics/fabric-1/interfaceGroups/source"
    results.verb_current = HttpVerbEnum.PUT
    results.payload_current = {"interfaceGroupName": "source"}
    results.response_current = {"RETURN_CODE": 200, "MESSAGE": "OK", "modified": "false"}
    results.result_current = {"success": True, "changed": True}
    results.diff_current = {"predicted": True}
    results.verbosity_level_current = 2
    results.register_api_call()

    orchestrator = SimpleNamespace(
        warnings=[],
        has_accepted_changes=False,
        confirmed_groups=lambda: list(confirmed),
    )
    state_machine = SimpleNamespace(
        before=before,
        model_class=InterfaceGroupConfigModel,
        model_orchestrator=orchestrator,
        output=output,
        results=results,
    )
    module = SimpleNamespace(
        params={"output_level": "normal", "state": "merged"},
        check_mode=False,
        _verbosity=2,
    )

    confirmed_output = nd_manage_interface_group._format_success_output(module, state_machine)

    assert confirmed_output["before"] == before.to_ansible_config()
    assert confirmed_output["after"] == confirmed.to_ansible_config()
    assert confirmed_output["changed"] is False
    assert confirmed_output["diff"] == []

    module.check_mode = True
    predictive_output = nd_manage_interface_group._format_success_output(module, state_machine)

    assert predictive_output["before"] == before.to_ansible_config()
    assert predictive_output["after"] == predicted.to_ansible_config()
    assert predictive_output["changed"] is True
