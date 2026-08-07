# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the nd_manage_interface_group module boundary."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import (
    HttpVerbEnum,
    OperationType,
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
