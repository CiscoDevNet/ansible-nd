# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for the execution-scoped interface state snapshot provider."""

# pylint: disable=protected-access

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import InterfaceStateSnapshot
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_access_interface import (
    EthernetAccessInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_trunk_host_interface import (
    EthernetTrunkHostInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.loopback_interface import LoopbackInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_access_interface import (
    PortChannelAccessInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_trunk_host_interface import (
    PortChannelTrunkHostInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.subinterface_managed_interface import (
    SubinterfaceManagedInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.subinterface_unmanaged_interface import (
    SubinterfaceUnmanagedInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.svi_interface import SviInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vpc_access_interface import AccessVpcHostInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vpc_trunk_host_interface import TrunkVpcHostInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


class _RequestRecorder:
    """Return queued DATA bodies while recording request arguments."""

    def __init__(self, responses: list[Any]) -> None:
        self._responses: Iterator[Any] = iter(responses)
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs) -> Any:
        self.calls.append(kwargs)
        return next(self._responses)


def _snapshot(recorder: _RequestRecorder, *, fabric_name: str = "fabric_1", page_size: int | None = 500) -> InterfaceStateSnapshot:
    context = FabricContext(rest_send=RestSend({"fabric_name": fabric_name, "check_mode": False}), fabric_name=fabric_name)
    context._switch_map = {"192.0.2.1": "SERIAL1", "192.0.2.2": "SERIAL2"}
    context._switch_map_by_id = {"SERIAL1": "192.0.2.1", "SERIAL2": "192.0.2.2"}
    return InterfaceStateSnapshot(
        fabric_name=fabric_name,
        fabric_context=context,
        request=recorder,
        page_size=page_size,
    )


def _interface(name: str, interface_type: str, policy_type: str) -> dict:
    return {
        "interfaceName": name,
        "interfaceType": interface_type,
        "configData": {"networkOS": {"policy": {"policyType": policy_type}}},
    }


def _summary(name: str, switch_id: str, interface_type: str, policy_type: str) -> dict:
    return {
        "interfaceName": name,
        "switchId": switch_id,
        "interfaceType": interface_type,
        "policyType": policy_type,
        "editAllowed": True,
        "policyChangeSupported": True,
    }


def test_load_switch_caches_indexes_and_isolates_callers() -> None:
    """A second family sees one cached GET and an unmodified shared record."""
    recorder = _RequestRecorder(
        [
            {
                "interfaces": [
                    _interface("Ethernet1/1", "ethernet", "accessHost"),
                    _interface("loopback10", "loopback", "loopback"),
                    {"interfaceType": "ethernet"},
                ]
            }
        ]
    )
    snapshot = _snapshot(recorder)

    first = snapshot.load_switch("SERIAL1")
    first["ethernet1/1"]["switchIp"] = "192.0.2.10"
    second = snapshot.load_switch("SERIAL1")

    assert len(recorder.calls) == 1
    assert "switchIp" not in second["ethernet1/1"]
    assert set(second) == {"ethernet1/1", "loopback10"}
    assert ("SERIAL1", "ethernet1/1") in snapshot.interfaces_by_identity
    assert "ethernet1/1" in snapshot.interfaces_by_switch_ip["192.0.2.1"]
    assert ("SERIAL1", "loopback10") in snapshot.interfaces_by_type["loopback"]
    assert ("SERIAL1", "ethernet1/1") in snapshot.interfaces_by_policy_type["accessHost"]
    assert snapshot.request_stats == {
        "switches": 1,
        "interface_inventory_gets": 1,
        "interface_inventory_pages": 1,
        "interface_inventory_cache_hits": 1,
        "interface_summary_switches": 0,
        "interface_summary_gets": 0,
        "interface_summary_pages": 0,
        "interface_summary_cache_hits": 0,
        "interface_inventory_refreshes": 0,
        "interface_inventory_dirty_refetches": 0,
        "snapshot_overlays": 0,
    }


def test_interface_summaries_are_lazy_batched_cached_and_isolated() -> None:
    """Requested identities share one full summary fetch per switch and isolated cached rows."""
    recorder = _RequestRecorder(
        [
            {
                "interfaces": [
                    _summary("Ethernet1/1", "SERIAL1", "ethernet", "accessHost"),
                    _summary("Ethernet1/2", "SERIAL1", "ethernet", "trunkHost"),
                ]
            },
            {"interfaces": [_summary("loopback10", "SERIAL2", "loopback", "loopback")]},
        ]
    )
    snapshot = _snapshot(recorder)

    assert snapshot.interface_summaries_by_identity == {}
    assert recorder.calls == []

    result = snapshot.load_interface_summaries(
        [
            ("SERIAL1", "Ethernet1/1"),
            ("SERIAL1", "ETHERNET1/1"),
            ("SERIAL1", "Ethernet1/99"),
            ("SERIAL2", "loopback10"),
        ]
    )

    assert set(result) == {("SERIAL1", "ethernet1/1"), ("SERIAL2", "loopback10")}
    assert len(recorder.calls) == 2
    assert "switchId=SERIAL1" in recorder.calls[0]["path"]
    assert "switchId=SERIAL2" in recorder.calls[1]["path"]
    assert "max=500" in recorder.calls[0]["path"]
    assert "offset=0" in recorder.calls[0]["path"]

    result[("SERIAL1", "ethernet1/1")]["policyType"] = "mutated"
    assert snapshot.interface_summaries_by_identity[("SERIAL1", "ethernet1/1")]["policyType"] == "accessHost"

    cached = snapshot.load_interface_summaries([("SERIAL1", "Ethernet1/2")])
    assert cached[("SERIAL1", "ethernet1/2")]["policyType"] == "trunkHost"
    assert len(recorder.calls) == 2
    assert snapshot.request_stats["interface_summary_switches"] == 2
    assert snapshot.request_stats["interface_summary_gets"] == 2
    assert snapshot.request_stats["interface_summary_pages"] == 2
    assert snapshot.request_stats["interface_summary_cache_hits"] == 1


def test_interface_summary_pagination_fetches_full_switch_then_exactly_filters() -> None:
    """Summary pagination caches the switch while returning only requested identities."""
    recorder = _RequestRecorder(
        [
            {
                "interfaces": [
                    _summary("Ethernet1/1", "SERIAL1", "ethernet", "accessHost"),
                    _summary("Ethernet1/2", "SERIAL1", "ethernet", "trunkHost"),
                ]
            },
            {"interfaces": [_summary("loopback10", "SERIAL1", "loopback", "loopback")]},
        ]
    )
    snapshot = _snapshot(recorder, page_size=2)

    result = snapshot.load_interface_summaries([("SERIAL1", "LOOPBACK10")])

    assert set(result) == {("SERIAL1", "loopback10")}
    assert set(snapshot.interface_summaries_by_identity) == {
        ("SERIAL1", "ethernet1/1"),
        ("SERIAL1", "ethernet1/2"),
        ("SERIAL1", "loopback10"),
    }
    assert "offset=0" in recorder.calls[0]["path"]
    assert "offset=2" in recorder.calls[1]["path"]
    assert snapshot.request_stats["interface_summary_pages"] == 2


def test_interface_summary_rejects_case_insensitive_duplicate_within_page() -> None:
    recorder = _RequestRecorder(
        [
            {
                "interfaces": [
                    _summary("Ethernet1/1", "SERIAL1", "ethernet", "accessHost"),
                    _summary("ethernet1/1", "SERIAL1", "ethernet", "trunkHost"),
                ]
            }
        ]
    )
    snapshot = _snapshot(recorder)

    with pytest.raises(RuntimeError, match=r"duplicate.*case-insensitive.*ethernet1/1.*SERIAL1"):
        snapshot.load_interface_summaries([("SERIAL1", "Ethernet1/1")])


def test_interface_summary_rejects_case_insensitive_duplicate_across_pages() -> None:
    recorder = _RequestRecorder(
        [
            {
                "interfaces": [
                    _summary("Ethernet1/1", "SERIAL1", "ethernet", "accessHost"),
                    _summary("Ethernet1/2", "SERIAL1", "ethernet", "trunkHost"),
                ]
            },
            {"interfaces": [_summary("ETHERNET1/1", "SERIAL1", "ethernet", "accessHost")]},
        ]
    )
    snapshot = _snapshot(recorder, page_size=2)

    with pytest.raises(RuntimeError, match=r"duplicate.*case-insensitive.*ethernet1/1.*SERIAL1"):
        snapshot.load_interface_summaries([("SERIAL1", "Ethernet1/1")])


@pytest.mark.parametrize("returned_switch_id", [None, "", 123])
def test_interface_summary_rejects_malformed_switch_id(returned_switch_id: Any) -> None:
    summary = _summary("Ethernet1/1", "SERIAL1", "ethernet", "accessHost")
    if returned_switch_id is None:
        summary.pop("switchId")
    else:
        summary["switchId"] = returned_switch_id
    recorder = _RequestRecorder([{"interfaces": [summary]}])
    snapshot = _snapshot(recorder)

    with pytest.raises(RuntimeError, match=r"summary.*switchId.*SERIAL1"):
        snapshot.load_interface_summaries([("SERIAL1", "Ethernet1/1")])


def test_interface_summary_ignores_rows_for_other_switches() -> None:
    """ND may return fabric-wide rows even when switchId is supplied."""
    recorder = _RequestRecorder(
        [
            {
                "interfaces": [
                    _summary("Ethernet1/40", "SERIAL2", "ethernet", "accessHost"),
                    _summary("Ethernet1/40", "SERIAL1", "ethernet", "trunkHost"),
                    _summary("Ethernet1/41", "SERIAL2", "ethernet", "routedHost"),
                ]
            }
        ]
    )
    snapshot = _snapshot(recorder)

    result = snapshot.load_interface_summaries([("SERIAL1", "Ethernet1/40")])

    assert result == {
        ("SERIAL1", "ethernet1/40"): _summary("Ethernet1/40", "SERIAL1", "ethernet", "trunkHost")
    }
    assert snapshot.interface_summaries_by_identity == result
    assert len(recorder.calls) == 1
    assert "switchId=SERIAL1" in recorder.calls[0]["path"]
    assert "filter=switchId%3ASERIAL1" in recorder.calls[0]["path"]


def test_interface_summary_foreign_only_page_returns_no_requested_identity() -> None:
    """Unrelated fabric rows do not poison a requested switch's summary cache."""
    recorder = _RequestRecorder(
        [{"interfaces": [_summary("Ethernet1/40", "SERIAL2", "ethernet", "accessHost")]}]
    )
    snapshot = _snapshot(recorder)

    assert snapshot.load_interface_summaries([("SERIAL1", "Ethernet1/40")]) == {}
    assert snapshot.interface_summaries_by_identity == {}
    assert snapshot.load_interface_summaries([("SERIAL1", "Ethernet1/40")]) == {}
    assert len(recorder.calls) == 1
    assert snapshot.request_stats["interface_summary_cache_hits"] == 1


def test_interface_summary_mixed_pagination_advances_by_raw_page_length() -> None:
    """Foreign rows count toward pagination and a target on the final page is retained."""
    recorder = _RequestRecorder(
        [
            {
                "interfaces": [
                    _summary("Ethernet1/1", "SERIAL2", "ethernet", "accessHost"),
                    _summary("Ethernet1/2", "SERIAL2", "ethernet", "trunkHost"),
                ]
            },
            {"interfaces": [_summary("Ethernet1/40", "SERIAL1", "ethernet", "trunkHost")]},
        ]
    )
    snapshot = _snapshot(recorder, page_size=2)

    result = snapshot.load_interface_summaries([("SERIAL1", "Ethernet1/40")])

    assert result == {
        ("SERIAL1", "ethernet1/40"): _summary("Ethernet1/40", "SERIAL1", "ethernet", "trunkHost")
    }
    assert len(recorder.calls) == 2
    assert "offset=0" in recorder.calls[0]["path"]
    assert "offset=2" in recorder.calls[1]["path"]
    assert "filter=switchId%3ASERIAL1" in recorder.calls[0]["path"]
    assert "filter=switchId%3ASERIAL1" in recorder.calls[1]["path"]
    assert snapshot.request_stats["interface_summary_pages"] == 2


def test_interface_summary_rejects_repeated_full_mixed_switch_page() -> None:
    """Fabric-wide rows still detect a controller that ignores the summary offset."""
    page = {
        "interfaces": [
            _summary("Ethernet1/1", "SERIAL2", "ethernet", "accessHost"),
            _summary("Ethernet1/2", "SERIAL3", "ethernet", "trunkHost"),
        ]
    }
    recorder = _RequestRecorder([page, page])
    snapshot = _snapshot(recorder, page_size=2)

    with pytest.raises(RuntimeError, match=r"summary pagination repeated a full page.*SERIAL1.*offset 2"):
        snapshot.load_interface_summaries([("SERIAL1", "Ethernet1/40")])


@pytest.mark.parametrize(
    "identity",
    [
        "SERIAL1/Ethernet1/1",
        ("", "Ethernet1/1"),
        ("SERIAL1", ""),
    ],
)
def test_interface_summary_identity_validation_is_lazy(identity: Any) -> None:
    """Invalid identities fail before a summary endpoint request."""
    recorder = _RequestRecorder([])
    snapshot = _snapshot(recorder)

    with pytest.raises(ValueError, match="Interface summary identities"):
        snapshot.load_interface_summaries([identity])

    assert recorder.calls == []


def test_load_switches_deduplicates_switch_ids() -> None:
    """Duplicate requested switch IDs do not create duplicate inventory GETs."""
    recorder = _RequestRecorder([{"interfaces": []}, {"interfaces": []}])
    snapshot = _snapshot(recorder)

    result = snapshot.load_switches(["SERIAL1", "SERIAL1", "SERIAL2"])

    assert set(result) == {"SERIAL1", "SERIAL2"}
    assert len(recorder.calls) == 2
    assert snapshot.request_stats["switches"] == 2


def test_paginated_fetch_uses_offset_and_stops_on_short_page() -> None:
    """All pages are combined and the next offset advances by returned rows."""
    recorder = _RequestRecorder(
        [
            {"interfaces": [_interface("Ethernet1/1", "ethernet", "accessHost"), _interface("Ethernet1/2", "ethernet", "accessHost")]},
            {"interfaces": [_interface("loopback10", "loopback", "loopback")]},
        ]
    )
    snapshot = _snapshot(recorder, page_size=2)

    result = snapshot.load_switch("SERIAL1")

    assert set(result) == {"ethernet1/1", "ethernet1/2", "loopback10"}
    assert "max=2" in recorder.calls[0]["path"]
    assert "offset=0" in recorder.calls[0]["path"]
    assert "sort=interfaceName%3Aasc" in recorder.calls[0]["path"]
    assert "max=2" in recorder.calls[1]["path"]
    assert "offset=2" in recorder.calls[1]["path"]
    assert "sort=interfaceName%3Aasc" in recorder.calls[1]["path"]
    assert snapshot.request_stats["interface_inventory_pages"] == 2


def test_paginated_fetch_stops_on_empty_page() -> None:
    """An exact-sized final data page is followed by one terminating empty page."""
    recorder = _RequestRecorder(
        [
            {"interfaces": [_interface("Ethernet1/1", "ethernet", "accessHost")]},
            {"interfaces": []},
        ]
    )
    snapshot = _snapshot(recorder, page_size=1)

    result = snapshot.load_switch("SERIAL1")

    assert set(result) == {"ethernet1/1"}
    assert len(recorder.calls) == 2
    assert "offset=1" in recorder.calls[1]["path"]


def test_paginated_fetch_rejects_a_repeated_full_page() -> None:
    """A controller that ignores offset fails safely instead of looping."""
    page = {"interfaces": [_interface("Ethernet1/1", "ethernet", "accessHost")]}
    recorder = _RequestRecorder([page, page])
    snapshot = _snapshot(recorder, page_size=1)

    with pytest.raises(RuntimeError, match="repeated a full page"):
        snapshot.load_switch("SERIAL1")


def test_invalidate_refresh_and_original_snapshot_lifecycle() -> None:
    """Refresh replaces current state, preserves the original diagnostic copy, and clears dirty state."""
    recorder = _RequestRecorder(
        [
            {"interfaces": [_interface("loopback10", "loopback", "loopback")]},
            {"interfaces": [_interface("loopback20", "loopback", "loopback")]},
        ]
    )
    snapshot = _snapshot(recorder)
    snapshot.load_switch("SERIAL1")
    snapshot.mark_dirty("SERIAL1")

    assert snapshot.dirty_switches == {"SERIAL1"}
    refreshed = snapshot.refresh("SERIAL1")

    assert set(refreshed["SERIAL1"]) == {"loopback20"}
    assert snapshot.dirty_switches == set()
    assert set(snapshot.original_interfaces_by_switch["SERIAL1"]) == {"loopback10"}
    assert snapshot.request_stats["interface_inventory_gets"] == 2


def test_two_interface_families_share_one_switch_get() -> None:
    """Injected snapshot sharing reduces two family reads to one switch GET."""
    recorder = _RequestRecorder(
        [
            {
                "interfaces": [
                    _interface("Ethernet1/1", "ethernet", "accessHost"),
                    _interface("loopback10", "loopback", "loopback"),
                ]
            }
        ]
    )
    snapshot = _snapshot(recorder)
    params = {"fabric_name": "fabric_1", "state": "merged", "config": [], "check_mode": False}
    ethernet = EthernetAccessInterfaceOrchestrator(rest_send=RestSend(params), interface_state_snapshot=snapshot)
    loopback = LoopbackInterfaceOrchestrator(rest_send=RestSend(params), interface_state_snapshot=snapshot)

    ethernet_state = ethernet._switch_interfaces("SERIAL1")
    ethernet_state["ethernet1/1"]["switchIp"] = "192.0.2.10"
    loopback_state = loopback._switch_interfaces("SERIAL1")

    assert len(recorder.calls) == 1
    assert "switchIp" not in loopback_state["ethernet1/1"]
    assert ethernet.fabric_context is loopback.fabric_context
    assert ethernet.state_snapshot is loopback.state_snapshot


def test_ten_interface_families_share_one_switch_get() -> None:
    """Ten family orchestrators reduce ten inventory reads to one shared GET."""
    recorder = _RequestRecorder([{"interfaces": [_interface("Ethernet1/1", "ethernet", "accessHost")]}])
    snapshot = _snapshot(recorder)
    params = {"fabric_name": "fabric_1", "state": "merged", "config": [], "check_mode": False}
    orchestrator_classes = [
        EthernetAccessInterfaceOrchestrator,
        EthernetTrunkHostInterfaceOrchestrator,
        LoopbackInterfaceOrchestrator,
        PortChannelAccessInterfaceOrchestrator,
        PortChannelTrunkHostInterfaceOrchestrator,
        SubinterfaceManagedInterfaceOrchestrator,
        SubinterfaceUnmanagedInterfaceOrchestrator,
        SviInterfaceOrchestrator,
        AccessVpcHostInterfaceOrchestrator,
        TrunkVpcHostInterfaceOrchestrator,
    ]

    for orchestrator_class in orchestrator_classes:
        orchestrator = orchestrator_class(rest_send=RestSend(dict(params)), interface_state_snapshot=snapshot)
        assert "ethernet1/1" in orchestrator._switch_interfaces("SERIAL1")

    assert len(recorder.calls) == 1
    assert snapshot.request_stats["interface_inventory_cache_hits"] == 9


def test_orchestrator_rejects_snapshot_from_another_fabric() -> None:
    """Injection cannot cross the snapshot's fabric validity boundary."""
    recorder = _RequestRecorder([])
    snapshot = _snapshot(recorder, fabric_name="fabric_1")
    params = {"fabric_name": "fabric_2", "state": "merged", "config": [], "check_mode": False}

    with pytest.raises(ValueError, match="does not match orchestrator fabric"):
        EthernetAccessInterfaceOrchestrator(rest_send=RestSend(params), interface_state_snapshot=snapshot)


def test_apply_overlay_atomically_updates_current_but_not_original_state() -> None:
    """Known successful upserts/deletes update only the current snapshot."""
    recorder = _RequestRecorder([{"interfaces": [_interface("Ethernet1/1", "ethernet", "accessHost"), _interface("loopback10", "loopback", "loopback")]}])
    snapshot = _snapshot(recorder)
    snapshot.load_switch("SERIAL1")

    updated_ethernet = _interface("Ethernet1/1", "ethernet", "trunkHost")
    result = snapshot.apply_overlay(
        "SERIAL1",
        upserts=[updated_ethernet, _interface("loopback20", "loopback", "loopback")],
        deletes=["LOOPBACK10"],
    )

    assert set(result) == {"ethernet1/1", "loopback20"}
    assert snapshot.policy_type(result["ethernet1/1"]) == "trunkHost"
    assert set(snapshot.original_interfaces_by_switch["SERIAL1"]) == {"ethernet1/1", "loopback10"}
    assert snapshot.policy_type(snapshot.original_interfaces_by_switch["SERIAL1"]["ethernet1/1"]) == "accessHost"
    assert snapshot.request_stats["snapshot_overlays"] == 1


def test_apply_overlay_validation_is_atomic_and_rejects_dirty_state() -> None:
    """An invalid or dirty overlay cannot partially alter cached state."""
    recorder = _RequestRecorder([{"interfaces": [_interface("Ethernet1/1", "ethernet", "accessHost")]}])
    snapshot = _snapshot(recorder)
    before = snapshot.load_switch("SERIAL1")

    with pytest.raises(ValueError, match="non-empty interfaceName"):
        snapshot.apply_overlay("SERIAL1", upserts=[{"interfaceType": "loopback"}], deletes=["Ethernet1/1"])
    assert snapshot.load_switch("SERIAL1") == before

    snapshot.mark_dirty("SERIAL1")
    with pytest.raises(RuntimeError, match="dirty switch"):
        snapshot.apply_overlay("SERIAL1", upserts=[_interface("loopback10", "loopback", "loopback")])


def test_dirty_switch_is_refetched_automatically_on_next_read() -> None:
    """A stale marker prevents a later family from consuming cached pre-mutation state."""
    recorder = _RequestRecorder(
        [
            {"interfaces": [_interface("loopback10", "loopback", "loopback")]},
            {"interfaces": [_interface("loopback20", "loopback", "loopback")]},
        ]
    )
    snapshot = _snapshot(recorder)
    snapshot.load_switch("SERIAL1")
    snapshot.mark_dirty("SERIAL1")

    result = snapshot.load_switch("SERIAL1")
