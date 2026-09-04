# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for the public nd_interfaces_workflow module wrapper."""

from __future__ import annotations

from unittest.mock import patch

from ansible_collections.cisco.nd.plugins.modules import nd_interfaces_workflow


def test_argument_spec_uses_exact_registry_and_excludes_flow_rules():
    spec = nd_interfaces_workflow.interface_workflow_argument_spec()
    resource_options = spec["resources"]["options"]
    choices = resource_options["type"]["choices"]

    assert len(choices) == 10
    assert set(choices) == {
        "ethernet_access",
        "ethernet_trunk_host",
        "loopback",
        "port_channel_access",
        "port_channel_trunk_host",
        "subinterface_managed",
        "subinterface_unmanaged",
        "svi",
        "vpc_access",
        "vpc_trunk_host",
    }
    assert "flow_rules" not in choices
    assert resource_options["state"]["choices"] == [
        "deleted",
        "merged",
        "overridden",
        "replaced",
    ]
    assert "allow_policy_transition" not in resource_options
    assert resource_options["config"] == {
        "type": "list",
        "elements": "dict",
        "required": True,
    }
    assert spec["config_actions"]["options"] == {"deploy": {"type": "bool", "default": False}}
    assert spec["verify"] == {
        "type": "dict",
        "options": {"enabled": {"type": "bool", "default": False}},
    }


def test_documentation_links_every_standalone_module_and_not_flow_rules():
    for module_name in (
        "nd_interface_ethernet_access",
        "nd_interface_ethernet_trunk_host",
        "nd_interface_loopback",
        "nd_interface_port_channel_access",
        "nd_interface_port_channel_trunk_host",
        "nd_interface_subinterface_managed",
        "nd_interface_subinterface_unmanaged",
        "nd_interface_svi",
        "nd_interface_vpc_access",
        "nd_interface_vpc_trunk_host",
    ):
        assert f"M(cisco.nd.{module_name})" in nd_interfaces_workflow.DOCUMENTATION
    assert "M(cisco.nd.nd_interface_flow_rules)" not in nd_interfaces_workflow.DOCUMENTATION
    assert "default: false" in nd_interfaces_workflow.DOCUMENTATION
    assert "Outstanding interface" not in nd_interfaces_workflow.DOCUMENTATION
    assert "allow_policy_transition" not in nd_interfaces_workflow.DOCUMENTATION
    assert "allow_policy_transition" not in nd_interfaces_workflow.EXAMPLES
    assert "policy transition" in nd_interfaces_workflow.DOCUMENTATION
    assert "unconfigured default" in nd_interfaces_workflow.DOCUMENTATION
    assert "regardless of its current policy family" in nd_interfaces_workflow.DOCUMENTATION
    assert "\n  verify:" in nd_interfaces_workflow.DOCUMENTATION
    assert "after_verified" in nd_interfaces_workflow.DOCUMENTATION
    assert "from_policy_type" in nd_interfaces_workflow.RETURN


def test_loopback_union_contract_is_explicit_in_documentation_and_examples():
    managed_policy_types = {
        "loopback",
        "ipfmLoopback",
        "mplsLoopback",
        "iosXeLoopback",
        "iosXeLoopbackShutNoshut",
        "iosXeUnderlayLoopback",
        "iosXeInternalLoopback",
        "csrLoopback",
        "csr1kvLoopback",
    }

    for policy_type in managed_policy_types:
        assert f"C({policy_type})" in nd_interfaces_workflow.DOCUMENTATION
    assert "network_os_type: nx-os" in nd_interfaces_workflow.EXAMPLES
    assert "policy_type: loopback" in nd_interfaces_workflow.EXAMPLES
    assert "Identifier-only V(deleted) loopback items remain valid" in nd_interfaces_workflow.DOCUMENTATION
    assert "Changing C(network_os_type) is rejected" in nd_interfaces_workflow.DOCUMENTATION


def test_main_requires_pydantic_then_runs_coordinator_and_exits():
    events = []

    class FakeAnsibleModule:
        def __init__(self, **kwargs):
            self.params = {
                "fabric_name": "FABRIC1",
                "resources": [],
                "config_actions": {"deploy": True},
            }
            self.check_mode = True
            self.kwargs = kwargs
            events.append(("AnsibleModule", self))

        def exit_json(self, **kwargs):
            events.append(("exit_json", kwargs))

        def fail_json(self, **kwargs):
            raise AssertionError(f"fail_json called unexpectedly: {kwargs}")

    class FakeCoordinator:
        def __init__(self, module):
            events.append(("InterfaceWorkflowCoordinator", module))

        def run(self):
            events.append(("run",))
            return {"changed": True, "check_mode": True}

    def fake_require_pydantic(module):
        events.append(("require_pydantic", module))

    with (
        patch.object(nd_interfaces_workflow, "AnsibleModule", FakeAnsibleModule),
        patch.object(nd_interfaces_workflow, "require_pydantic", fake_require_pydantic),
        patch.object(nd_interfaces_workflow, "InterfaceWorkflowCoordinator", FakeCoordinator),
    ):
        nd_interfaces_workflow.main()

    assert [event[0] for event in events] == [
        "AnsibleModule",
        "require_pydantic",
        "InterfaceWorkflowCoordinator",
        "run",
        "exit_json",
    ]
    assert events[0][1].kwargs["supports_check_mode"] is True
    assert events[-1][1] == {"changed": True, "check_mode": True}


def test_main_preserves_structured_execution_failure():
    events = []

    class FakeAnsibleModule:
        def __init__(self, **_kwargs):
            self.params = {
                "fabric_name": "FABRIC1",
                "resources": [],
                "config_actions": {"deploy": True},
            }
            self.check_mode = False

        def exit_json(self, **kwargs):
            raise AssertionError(f"exit_json called unexpectedly: {kwargs}")

        def fail_json(self, **kwargs):
            events.append(kwargs)

    class FakeCoordinator:
        def __init__(self, module):
            self.module = module

        def run(self):
            raise nd_interfaces_workflow.InterfaceWorkflowExecutionFailed(
                {
                    "changed": True,
                    "failed": True,
                    "execution": {"status": "partial_failure"},
                },
                "bulk create failed",
            )

    with (
        patch.object(nd_interfaces_workflow, "AnsibleModule", FakeAnsibleModule),
        patch.object(nd_interfaces_workflow, "require_pydantic", lambda _module: None),
        patch.object(nd_interfaces_workflow, "InterfaceWorkflowCoordinator", FakeCoordinator),
    ):
        nd_interfaces_workflow.main()

    assert events == [
        {
            "msg": "bulk create failed",
            "changed": True,
            "failed": True,
            "execution": {"status": "partial_failure"},
        }
    ]
