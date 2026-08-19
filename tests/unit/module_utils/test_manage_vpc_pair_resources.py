# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for the vPC pair resource management."""

from types import SimpleNamespace
from unittest.mock import patch

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair import resources


def test_resource_service_verifies_after_deployment_and_rebuilds_output():
    """The vPC controller readback must happen after its save/deploy actions."""
    events: list[str] = []

    class FakeStateMachine:
        WRITE_STATES = frozenset({"merged", "replaced", "overridden", "deleted"})

        def __init__(self, module):
            self.module = module
            self.state = module.params["state"]
            self.result = {}

        def finalize_result(self, *, changed=False):
            assert changed is True
            events.append("finalize_result")

        def add_logs_and_outputs(self):
            events.append("format")
            self.result = {"changed": True, "after": ["verified"]}

    module = SimpleNamespace(
        params={
            "state": "merged",
            "config_actions": {"save": True, "deploy": True, "type": "switch"},
            "_ip_to_sn_mapping": {"192.0.2.1": "FDO1"},
        }
    )

    def run_state_handler(_state_machine):
        events.append("state")
        return {"changed": True, "after": ["predicted"]}

    def deploy_handler(_state_machine, _fabric_name, result):
        assert result["after"] == ["predicted"]
        events.append("deploy")
        return {"deployment_needed": True}

    service = resources.VpcPairResourceService(
        module=module,
        run_state_handler=run_state_handler,
        deploy_handler=deploy_handler,
        needs_deployment_handler=lambda _result, _state_machine: False,
    )

    with patch.object(resources, "VpcPairStateMachine", FakeStateMachine):
        result = service.execute(fabric_name="fab1")

    assert events == ["state", "deploy", "finalize_result", "format"]
    assert result["after"] == ["verified"]
    assert result["deployment"] == {"deployment_needed": True}
    assert result["deployment_needed"] is True
    assert result["ip_to_sn_mapping"] == {"192.0.2.1": "FDO1"}


def test_resource_service_verifies_a_deployment_only_write():
    """A save/deploy write is sufficient to require final readback."""

    class FakeStateMachine:
        WRITE_STATES = frozenset({"merged", "replaced", "overridden", "deleted"})

        def __init__(self, module):
            self.module = module
            self.state = module.params["state"]
            self.result = {}

        def finalize_result(self, *, changed=False):
            assert changed is True

        def add_logs_and_outputs(self):
            self.result = {"changed": True, "after": ["verified"]}

    module = SimpleNamespace(
        params={
            "state": "merged",
            "config_actions": {"save": True, "deploy": True, "type": "switch"},
        }
    )
    service = resources.VpcPairResourceService(
        module=module,
        run_state_handler=lambda _state_machine: {"changed": False, "after": ["unchanged"]},
        deploy_handler=lambda _state_machine, _fabric_name, _result: {
            "deployment_needed": True,
            "changed": True,
        },
        needs_deployment_handler=lambda _result, _state_machine: True,
    )

    with patch.object(resources, "VpcPairStateMachine", FakeStateMachine):
        result = service.execute(fabric_name="fab1")

    assert result["changed"] is True
    assert result["after"] == ["verified"]
