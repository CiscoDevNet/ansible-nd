# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest
from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

from ansible_collections.cisco.nd.tests.integration.targets.nd_manage_smart_switches_ha_pair.action_plugins import (
    nd_smart_switch_ha_pair_observe as observer_plugin,
)

INVENTORY = "/api/v1/manage/fabrics/ha%2Ftest/smartSwitches/haPairs?clusterName=remote%20west"


@pytest.fixture
def observer(monkeypatch):
    monkeypatch.setattr(ActionBase, "run", lambda *args: {})
    plugin = object.__new__(observer_plugin.ActionModule)
    plugin._task = SimpleNamespace(args={"path": INVENTORY}, check_mode=True)
    plugin._execute_module = Mock()
    return plugin


def ha_row(switch_id: str, *, peer: str | None = None, state: str = "unpaired", topology: str = "nonVpc") -> dict:
    return {"pairingType": topology, "switchInfo": {"id": switch_id, "peerId": peer, "haPaired": state}}


def inventory_page(*rows: dict) -> dict:
    return {"status": 200, "current": {"rows": list(rows)}}


# Complete read and exact associations


def test_observer_follows_short_pages_and_reads_with_check_mode_disabled(observer):
    first_page = inventory_page(ha_row("B", peer="A", state="pairPending", topology="vpc"))
    second_page = inventory_page(ha_row("D", state="unpairPending"), ha_row("C"))
    pages = iter([first_page, second_page, inventory_page()])

    def fetch_page(**_kwargs):
        assert observer._task.check_mode is False
        return next(pages)

    observer._execute_module.side_effect = fetch_page
    task_vars = {"ansible_connection": "httpapi"}
    result = observer.run(task_vars=task_vars)

    assert result == {
        "changed": False,
        "present_pairs": [{"switch_id": "A", "peer_switch_id": "B"}],
        "switches": {
            "A": {"peer_id": "B", "state": "pairPending", "topology": "vpc"},
            "B": {"peer_id": "A", "state": "pairPending", "topology": "vpc"},
            "C": {"peer_id": None, "state": "unpaired", "topology": "nonVpc"},
            "D": {"peer_id": None, "state": "unpairPending", "topology": "nonVpc"},
        },
    }
    assert observer._execute_module.call_args_list == [
        call(module_name="cisco.nd.nd_rest", module_args={"path": f"{INVENTORY}&max=100&offset={offset}", "method": "get"}, task_vars=task_vars)
        for offset in (0, 1, 3)
    ]
    assert observer._task.check_mode is True


def test_observer_keeps_standalone_peer_evidence_independent(observer):
    observer._execute_module.side_effect = [
        inventory_page(ha_row("a", peer="B", state="paired"), ha_row("C", peer="D", state="unpairPending"), ha_row("D", state="unpairPending")),
        inventory_page(),
    ]

    result = observer.run()

    assert result["present_pairs"] == [{"switch_id": "B", "peer_switch_id": "a"}]
    assert set(result["switches"]) == {"a", "C", "D"}


def test_observer_deduplicates_reciprocal_rows(observer):
    observer._execute_module.side_effect = [
        inventory_page(ha_row("A", peer="B", state="paired"), ha_row("B", peer="A", state="paired")),
        inventory_page(),
    ]

    assert observer.run()["present_pairs"] == [{"switch_id": "A", "peer_switch_id": "B"}]


# Fail closed on invalid or incomplete inventory


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        ([ha_row("A"), ha_row("A")], "repeated serial"),
        ([ha_row("A", peer="A", state="paired")], "invalid peer serial"),
        ([ha_row("A", state="pairPending")], "missing a peer serial"),
        ([ha_row("A", topology="unknown")], "invalid pairing type"),
        ([ha_row("A", state="unknown")], "invalid HA state"),
        ([ha_row("A", peer="B", topology="vpc"), ha_row("B")], "conflicting vPC observations"),
        ([ha_row("A", peer="B", state="paired"), ha_row("B", peer="C", state="paired")], "conflicting active HA pairs"),
    ],
)
def test_observer_rejects_ambiguous_rows(observer, rows, message):
    observer._execute_module.side_effect = [inventory_page(*rows), inventory_page()]

    with pytest.raises(AnsibleActionFail, match=message):
        observer.run()
    assert observer._task.check_mode is True


@pytest.mark.parametrize(
    ("response", "message"),
    [
        ({"status": 404, "failed": True}, "HTTP 404"),
        ({"status": 200, "current": {}}, "requires current.rows"),
        ({"status": 200, "current": {"rows": None}}, "requires current.rows"),
        ({"status": 200, "current": {"rows": [None]}}, "requires switchInfo"),
    ],
)
def test_observer_never_treats_an_invalid_page_as_complete(observer, response, message):
    observer._execute_module.side_effect = [inventory_page(ha_row("A")), response]

    with pytest.raises(AnsibleActionFail, match=message):
        observer.run()
    assert observer._task.check_mode is True


def test_observer_does_not_accept_a_non_inventory_path(observer):
    observer._task.args["path"] = INVENTORY.replace("haPairs", "actions/haUnpair")

    with pytest.raises(AnsibleActionFail, match="HA inventory path"):
        observer.run()
    observer._execute_module.assert_not_called()


def test_observer_rejects_a_filtered_inventory(observer):
    observer._task.args["path"] = f"{INVENTORY}&filter=pairingType%20eq%20vpc"

    with pytest.raises(AnsibleActionFail, match="requires an unfiltered path"):
        observer.run()
    observer._execute_module.assert_not_called()


def test_observer_requires_an_empty_terminal_page_at_the_page_limit(observer, monkeypatch):
    monkeypatch.setattr(observer_plugin, "PAGE_LIMIT", 1)
    observer._execute_module.return_value = inventory_page(ha_row("A"))

    with pytest.raises(AnsibleActionFail, match="without an empty terminal page"):
        observer.run()
    observer._execute_module.assert_called_once()
    assert observer._task.check_mode is True


# Fabric inventory for management-IP discovery


def test_observer_reads_every_fabric_switch_page_with_cluster_routing(observer):
    path = INVENTORY.replace("/smartSwitches/haPairs", "/switches")
    observer._task.args["path"] = path
    observer._execute_module.side_effect = [
        {"status": 200, "current": {"switches": [{"switchId": "A", "fabricManagementIp": "192.0.2.1"}]}},
        {"status": 200, "current": {"switches": [{"switchId": "B", "fabricManagementIp": "192.0.2.2"}]}},
        {"status": 200, "current": {"switches": []}},
    ]

    assert observer.run() == {"changed": False, "fabric_switches": {"A": "192.0.2.1", "B": "192.0.2.2"}}
    assert [request.kwargs["module_args"] for request in observer._execute_module.call_args_list] == [
        {"path": f"{path}&max=100&offset={offset}", "method": "get"} for offset in range(3)
    ]


def test_observer_rejects_duplicate_switch_ids_in_the_fabric_inventory(observer):
    observer._task.args["path"] = INVENTORY.replace("/smartSwitches/haPairs", "/switches")
    observer._execute_module.side_effect = [
        {"status": 200, "current": {"switches": [{"switchId": "A", "fabricManagementIp": "192.0.2.1"}]}},
        {"status": 200, "current": {"switches": [{"switchId": "A", "fabricManagementIp": "192.0.2.2"}]}},
    ]

    with pytest.raises(AnsibleActionFail, match="repeated serial 'A'"):
        observer.run()
