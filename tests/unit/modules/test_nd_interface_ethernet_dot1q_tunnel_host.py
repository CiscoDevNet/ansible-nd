# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Standalone dot1q-tunnel module grouping and ownership-contract tests."""

from __future__ import annotations

from copy import deepcopy
import json

import pytest
from ansible.module_utils import basic as ansible_basic

from ansible_collections.cisco.nd.plugins.module_utils.interface_config_normalizer import expand_ethernet_dot1q_tunnel_host_config
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
    assert EthernetDot1qTunnelHostInterfaceOrchestrator.supports_bulk_full_modify is True


@pytest.mark.parametrize("normalize", [expand_config, expand_ethernet_dot1q_tunnel_host_config])
def test_grouped_config_expands_once_per_switch_interface(normalize) -> None:
    grouped = [
        {"switch_ip": "192.0.2.11", "interface_names": ["Ethernet1/40", "Ethernet1/41"], "config_data": {"network_os": {"policy": {"access_vlan": 150}}}},
        {"switch_ip": "192.0.2.12", "interface_names": ["Ethernet1/40"], "config_data": {"network_os": {"policy": {"access_vlan": 151}}}},
    ]
    expanded = normalize(grouped)
    assert [(item["switch_ip"], item["interface_name"]) for item in expanded] == [
        ("192.0.2.11", "Ethernet1/40"),
        ("192.0.2.11", "Ethernet1/41"),
        ("192.0.2.12", "Ethernet1/40"),
    ]
    assert all("interface_names" not in item for item in expanded)
    expanded[0]["config_data"]["network_os"]["policy"]["access_vlan"] = 152
    assert grouped[0]["config_data"]["network_os"]["policy"]["access_vlan"] == 150
    assert expanded[1]["config_data"]["network_os"]["policy"]["access_vlan"] == 150


@pytest.mark.parametrize("normalize", [expand_config, expand_ethernet_dot1q_tunnel_host_config])
def test_grouped_config_rejects_duplicate_exact_target(normalize) -> None:
    grouped = [
        {"switch_ip": "192.0.2.11", "interface_names": ["Ethernet1/40"]},
        {"switch_ip": "192.0.2.11", "interface_names": ["ethernet1/40"]},
    ]
    with pytest.raises(ValueError, match="multiple config items"):
        normalize(grouped)


@pytest.mark.parametrize("normalize", [expand_config, expand_ethernet_dot1q_tunnel_host_config])
def test_empty_named_group_cannot_become_an_accidental_reset_all(normalize) -> None:
    with pytest.raises(ValueError, match=r"Use top-level config: \[\]"):
        normalize([{"switch_ip": "192.0.2.11", "interface_names": []}])
    assert normalize([]) == []


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


class _GatheredResult(BaseException):
    """Capture real parser and state-machine results without printing JSON."""


def _configure_real_module(monkeypatch, args):
    monkeypatch.setattr(ansible_basic, "_ANSIBLE_ARGS", json.dumps({"ANSIBLE_MODULE_ARGS": args}).encode())
    if hasattr(ansible_basic, "_ANSIBLE_PROFILE"):
        monkeypatch.setattr(ansible_basic, "_ANSIBLE_PROFILE", "legacy")
    monkeypatch.setattr(dot1q_module, "require_pydantic", lambda _module: None)
    monkeypatch.setattr(dot1q_module, "setup_logging", lambda _module: None)

    def finish(_module, **kwargs):
        raise _GatheredResult(kwargs)

    def fail(_module, **kwargs):
        raise ValueError(kwargs["msg"])

    monkeypatch.setattr(ansible_basic.AnsibleModule, "exit_json", finish)
    monkeypatch.setattr(ansible_basic.AnsibleModule, "fail_json", fail)


def _gathered_wire():
    return {
        "switchIp": "192.0.2.11",
        "switchId": "SERIAL11",
        "interfaceName": "Ethernet1/40",
        "interfaceType": "ethernet",
        "configData": {
            "mode": "dot1qTunnel",
            "networkOS": {"networkOSType": "nx-os", "policy": {"policyType": "dot1qTunnelHost", "accessVlan": 150, "adminState": False}},
        },
    }


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("config", [None, [], [{"switch_ip": "192.0.2.11"}], [{"config_data": {"network_os": {"policy": {"admin_state": False}}}}]])
def test_real_gathered_entrypoint_is_read_only_and_returns_reusable_output(monkeypatch, check_mode, config) -> None:
    args = {"fabric_name": "fabric2", "state": "gathered", "config_actions": {"deploy": True}, "_ansible_check_mode": check_mode}
    if config is not None:
        args["config"] = config
    _configure_real_module(monkeypatch, args)
    calls = []

    def query(self, **kwargs):
        calls.append(kwargs["gathered_filters"])
        return [deepcopy(_gathered_wire())]

    monkeypatch.setattr(EthernetDot1qTunnelHostInterfaceOrchestrator, "query_all", query)
    for name in ("create", "update", "delete", "remove_pending", "deploy_pending"):
        monkeypatch.setattr(EthernetDot1qTunnelHostInterfaceOrchestrator, name, lambda *args, **kwargs: pytest.fail("Gathered must never write or deploy"))
    with pytest.raises(_GatheredResult) as result:
        dot1q_module.main()
    output = result.value.args[0]
    assert output["changed"] is False
    assert output["before"] == output["after"] == []
    assert "diff" not in output and "proposed" not in output
    assert len(output["gathered"]) == 1
    config_result = output["gathered"][0]
    assert config_result["interface_names"] == ["Ethernet1/40"]
    assert "interface_name" not in config_result
    expanded = expand_config(output["gathered"])
    replay = EthernetDot1qTunnelHostInterfaceModel.from_config(expanded[0])
    existing = EthernetDot1qTunnelHostInterfaceModel.from_response(_gathered_wire())
    assert existing.get_diff(replay, exclude_unset=True) is True
    assert len(calls) == 1


@pytest.mark.parametrize(
    "config, message",
    [
        ([{}], "at least one"),
        ([{"interface_names": None}], "must be a list"),
        ([{"interface_names": []}], "at least one"),
        ([{"config_data": {"network_os": {"network_os_type": "nx-os"}}}], "network_os_type"),
        ([{"config_data": {"network_os": {"policy": {"description": "unsupported filter"}}}}], "description"),
        ([{"config_data": {"network_os": {"policy": {"access_vlan": 4095}}}}], "4094"),
    ],
)
def test_real_gathered_rejects_invalid_filters_before_query(monkeypatch, config, message) -> None:
    _configure_real_module(monkeypatch, {"fabric_name": "fabric2", "state": "gathered", "config": config})
    monkeypatch.setattr(
        EthernetDot1qTunnelHostInterfaceOrchestrator, "query_all", lambda *args, **kwargs: pytest.fail("Invalid filters must fail before queries")
    )
    with pytest.raises(ValueError, match=message):
        dot1q_module.main()


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "deleted"])
def test_write_states_still_require_config(monkeypatch, state) -> None:
    _configure_real_module(monkeypatch, {"fabric_name": "fabric2", "state": state})
    monkeypatch.setattr(dot1q_module, "NDStateMachine", lambda **kwargs: pytest.fail("Missing config must fail before queries"))
    with pytest.raises(ValueError, match="config"):
        dot1q_module.main()


@pytest.mark.parametrize(
    "config, expected_switches",
    [
        ([{"switch_ip": "192.0.2.11", "config_data": {"network_os": {"policy": {"access_vlan": 151}}}}], []),
        ([{"switch_ip": "192.0.2.11"}, {"switch_ip": "192.0.2.12"}], ["192.0.2.11", "192.0.2.12"]),
        ([{"switch_ip": "192.0.2.11", "interface_names": ["e1/40"]}, {"switch_ip": "192.0.2.11"}], ["192.0.2.11"]),
    ],
)
def test_gathered_combines_and_or_filters_and_deduplicates(monkeypatch, config, expected_switches) -> None:
    _configure_real_module(monkeypatch, {"fabric_name": "fabric2", "state": "gathered", "config": config})
    other = _gathered_wire()
    other.update(switchIp="192.0.2.12", switchId="SERIAL12", interfaceName="Ethernet1/41")
    monkeypatch.setattr(EthernetDot1qTunnelHostInterfaceOrchestrator, "query_all", lambda self, **kwargs: [_gathered_wire(), other])
    with pytest.raises(_GatheredResult) as result:
        dot1q_module.main()
    assert [item["switch_ip"] for item in result.value.args[0]["gathered"]] == expected_switches
