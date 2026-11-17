# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Exercise dot1q-host states through the real ND state machine without REST writes."""

from __future__ import annotations

from copy import deepcopy
from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_dot1q_tunnel_host_interface import (
    EthernetDot1qTunnelHostInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule


class _SpyDot1qHostOrchestrator(EthernetDot1qTunnelHostInterfaceOrchestrator):
    """Keep real planning while recording all orchestrator mutation calls."""

    inventory: ClassVar[list[dict]] = []

    def model_post_init(self, context) -> None:
        super().model_post_init(context)
        self._calls: list[tuple[str, list[str]]] = []

    def query_all(self, model_instance=None, **kwargs) -> list[dict]:
        return deepcopy(type(self).inventory)

    def preflight_create(self, model_instances) -> None:
        return

    def preflight(self, model_instances) -> None:
        return

    def preflight_delete(self, model_instances) -> None:
        return

    def reconcile_no_diff(self, model_instances) -> bool:
        return False

    def reconcile_absent_deletes(self, model_instances) -> bool:
        return False

    def create_bulk(self, model_instances, **kwargs) -> dict:
        self._calls.append(("create_bulk", [item.interface_name for item in model_instances]))
        return {}

    def update(self, model_instance, **kwargs) -> dict:
        self._calls.append(("update", [model_instance.interface_name]))
        return {}

    def delete(self, model_instance, **kwargs) -> None:
        self._calls.append(("delete", [model_instance.interface_name]))

    def delete_bulk(self, model_instances, **kwargs) -> None:
        self._calls.append(("delete_bulk", [item.interface_name for item in model_instances]))


def _wire(name: str, *, description: str = "original", vlan: int = 150) -> dict:
    return {
        "switchIp": "192.0.2.82",
        "switchId": "SERIAL82",
        "interfaceName": name,
        "interfaceType": "ethernet",
        "configData": {
            "mode": "dot1qTunnel",
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {"policyType": "dot1qTunnelHost", "accessVlan": vlan, "description": description},
            },
        },
    }


def _config(name: str, *, description: str = "original", vlan: int = 150) -> dict:
    return {
        "switch_ip": "192.0.2.82",
        "interface_name": name,
        "config_data": {"network_os": {"policy": {"access_vlan": vlan, "description": description}}},
    }


def _machine(state: str, config: list[dict], existing: list[dict], *, check_mode: bool = False) -> NDStateMachine:
    _SpyDot1qHostOrchestrator.inventory = existing
    module = MockAnsibleModule()
    module.check_mode = check_mode
    module.params = {
        "state": state,
        "config": config,
        "output_level": "normal",
        "ignore_errors": False,
        "fabric_name": "fabric2",
    }
    return NDStateMachine(module=module, model_orchestrator=_SpyDot1qHostOrchestrator)


def test_dot1q_merged_create_and_check_mode_planning() -> None:
    proposed = [_config("Ethernet1/40")]
    preview = _machine("merged", proposed, [], check_mode=True)
    preview.manage_state()
    assert preview.output.format()["changed"] is True
    assert preview.model_orchestrator._calls == []

    execution = _machine("merged", proposed, [])
    execution.manage_state()
    assert execution.model_orchestrator._calls == [("create_bulk", ["Ethernet1/40"])]


def test_dot1q_replaced_updates_only_named_host() -> None:
    machine = _machine("replaced", [_config("Ethernet1/40", description="new")], [_wire("Ethernet1/40"), _wire("Ethernet1/41")])
    machine.manage_state()
    assert machine.model_orchestrator._calls == [("update", ["Ethernet1/40"])]


def test_dot1q_overridden_updates_named_host_and_resets_omitted_host() -> None:
    machine = _machine("overridden", [_config("Ethernet1/40", description="new")], [_wire("Ethernet1/40"), _wire("Ethernet1/41")])
    machine.manage_state()
    assert ("update", ["Ethernet1/40"]) in machine.model_orchestrator._calls
    assert ("delete_bulk", ["Ethernet1/41"]) in machine.model_orchestrator._calls


def test_dot1q_deleted_resets_only_named_host() -> None:
    machine = _machine("deleted", [{"switch_ip": "192.0.2.82", "interface_name": "Ethernet1/40"}], [_wire("Ethernet1/40"), _wire("Ethernet1/41")])
    machine.manage_state()
    assert machine.model_orchestrator._calls == [("delete_bulk", ["Ethernet1/40"])]


def test_dot1q_no_diff_replay_is_idempotent() -> None:
    machine = _machine("merged", [_config("Ethernet1/40")], [_wire("Ethernet1/40")])
    machine.manage_state()
    assert machine.output.format()["changed"] is False
    assert machine.model_orchestrator._calls == []
