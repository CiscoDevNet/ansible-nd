# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Standalone dot1q-tunnel module grouping and ownership-contract tests."""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_dot1q_tunnel_host_interface import (
    EthernetDot1qTunnelHostInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_dot1q_tunnel_host_interface import (
    EthernetDot1qTunnelHostInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.modules import nd_interface_ethernet_dot1q_tunnel_host as dot1q_module
from ansible_collections.cisco.nd.plugins.modules.nd_interface_ethernet_dot1q_tunnel_host import expand_config


def test_orchestrator_has_narrow_host_policy_scope() -> None:
    assert EthernetDot1qTunnelHostInterfaceOrchestrator.model_class is EthernetDot1qTunnelHostInterfaceModel
    assert EthernetDot1qTunnelHostInterfaceOrchestrator._managed_policy_types(None) == {"dot1qTunnelHost"}
    assert EthernetDot1qTunnelHostInterfaceOrchestrator.MEMBER_FAMILY == ""
    assert EthernetDot1qTunnelHostInterfaceOrchestrator.supports_bulk_create is True
    assert EthernetDot1qTunnelHostInterfaceOrchestrator.supports_bulk_delete is True
    assert EthernetDot1qTunnelHostInterfaceOrchestrator.supports_bulk_full_modify is False


def test_grouped_config_expands_once_per_switch_interface() -> None:
    grouped = [
        {"switch_ip": "192.0.2.11", "interface_names": ["Ethernet1/40", "Ethernet1/41"], "config_data": {"network_os": {"policy": {"access_vlan": 150}}}},
        {"switch_ip": "192.0.2.12", "interface_names": ["Ethernet1/40"], "config_data": {"network_os": {"policy": {"access_vlan": 151}}}},
    ]
    expanded = expand_config(grouped)
    assert [(item["switch_ip"], item["interface_name"]) for item in expanded] == [
        ("192.0.2.11", "Ethernet1/40"),
        ("192.0.2.11", "Ethernet1/41"),
        ("192.0.2.12", "Ethernet1/40"),
    ]
    assert all("interface_names" not in item for item in expanded)


def test_grouped_config_rejects_duplicate_exact_target() -> None:
    grouped = [
        {"switch_ip": "192.0.2.11", "interface_names": ["Ethernet1/40"]},
        {"switch_ip": "192.0.2.11", "interface_names": ["ethernet1/40"]},
    ]
    with pytest.raises(ValueError, match="multiple config items"):
        expand_config(grouped)


def test_empty_named_group_cannot_become_an_accidental_reset_all() -> None:
    with pytest.raises(ValueError, match=r"Use top-level config: \[\]"):
        expand_config([{"switch_ip": "192.0.2.11", "interface_names": []}])
    assert expand_config([]) == []


@pytest.mark.parametrize("check_mode", [False, True])
def test_public_module_rejects_empty_named_group_before_nd_query(monkeypatch, check_mode: bool) -> None:
    class StubModule:
        params = {
            "fabric_name": "fabric2",
            "config": [{"switch_ip": "192.0.2.82", "interface_names": []}],
            "state": "overridden",
            "config_actions": {"deploy": True},
        }

        def __init__(self) -> None:
            self.check_mode = check_mode

        def fail_json(self, **kwargs) -> None:
            raise ValueError(kwargs["msg"])

    monkeypatch.setattr(dot1q_module, "AnsibleModule", lambda **_kwargs: StubModule())
    monkeypatch.setattr(dot1q_module, "require_pydantic", lambda _module: None)
    monkeypatch.setattr(dot1q_module, "setup_logging", lambda _module: None)
    monkeypatch.setattr(dot1q_module, "NDStateMachine", lambda **_kwargs: pytest.fail("NDStateMachine must not be initialized"))
    with pytest.raises(ValueError, match="must name at least one interface"):
        dot1q_module.main()


def test_public_module_main_expands_names_and_runs_deployment_hooks(monkeypatch) -> None:
    calls = []

    class StubModule:
        check_mode = False
        params = {
            "fabric_name": "fabric2",
            "config": [{"switch_ip": "192.0.2.82", "interface_names": ["Ethernet1/40"]}],
            "state": "deleted",
            "config_actions": {"deploy": True},
        }

        def exit_json(self, **kwargs) -> None:
            calls.append(("exit", kwargs))

    class StubOrchestrator:
        def apply_config_actions(self, params) -> None:
            calls.append(("actions", params["config_actions"]))

        def remove_pending(self) -> None:
            calls.append(("remove", None))

        def deploy_pending(self) -> None:
            calls.append(("deploy", None))

    class StubOutput:
        def format(self) -> dict:
            return {"changed": True, "output_level": "normal"}

    class StubStateMachine:
        def __init__(self, module, model_orchestrator) -> None:
            calls.append(("config", module.params["config"]))
            self.model_orchestrator = StubOrchestrator()
            self.output = StubOutput()

        def manage_state(self) -> None:
            calls.append(("manage", None))

    monkeypatch.setattr(dot1q_module, "AnsibleModule", lambda **_kwargs: StubModule())
    monkeypatch.setattr(dot1q_module, "require_pydantic", lambda _module: None)
    monkeypatch.setattr(dot1q_module, "setup_logging", lambda _module: None)
    monkeypatch.setattr(dot1q_module, "NDBaseInterfaceOrchestrator", StubOrchestrator)
    monkeypatch.setattr(dot1q_module, "NDStateMachine", StubStateMachine)
    dot1q_module.main()
    assert calls == [
        ("config", [{"switch_ip": "192.0.2.82", "interface_name": "Ethernet1/40"}]),
        ("actions", {"deploy": True}),
        ("manage", None),
        ("remove", None),
        ("deploy", None),
        ("exit", {"changed": True, "output_level": "normal"}),
    ]
