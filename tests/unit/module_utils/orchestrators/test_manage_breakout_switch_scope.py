# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Explicit switch filtering without trusting a vPC-expanded controller reply.

The paired-leaf shape is 54 physical Ethernet parents per switch. Scripted
replies exercise wire scope and strict response identity; they do not emulate
the controller implementing its filter or establish live-device convergence.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_guarded_workflows import combined, summary_calls, topology
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_interfaces import (
    OTHER_SERIAL,
    SERIAL,
    action,
    assert_switch_inventory_get,
    group,
    inventory,
    item,
    response,
    run,
    switch_inventory,
    writes,
)

PARENT = "Ethernet1/53"
PORTS = tuple("Ethernet1/" + str(port) for port in range(1, 55))


def scoped_filter(base, serial):
    return base + " AND switchId:" + serial


@pytest.mark.parametrize("verify", [False, True])
def test_vpc_leaf_request_filters_both_switch_parameter_and_explicit_query_identity(verify):
    script = [topology(native=PORTS if verify else (PARENT,)), action(item(PARENT))]
    if verify:
        script.append(topology(PARENT, native=tuple(port for port in PORTS if port != PARENT)))
    report, calls = run(
        script,
        config=[group(PARENT)],
        verify={"enabled": verify},
        platform_inventory=switch_inventory(inventory(vpcConfigured=True)["DATA"]),
    )
    assert report["failed"] is False and report["changed"] is True
    assert len(writes(calls)) == 1
    for call in summary_calls(calls):
        query = parse_qs(urlsplit(call["path"]).query)
        assert query["switchId"] == [SERIAL]
        base = "interfaceType:ethernet" if verify else "interfaceName:*" + PARENT + "*"
        assert query["filter"] == [scoped_filter(base, SERIAL)]
        assert call["payload"] is None


def test_explicit_scope_is_present_on_every_page_of_a_paired_leaf_inventory():
    rows = topology(native=PORTS)["DATA"]["interfaces"]
    pages = [
        response({"interfaces": rows[:27], "meta": {"counts": {"total": 54, "remaining": 27}}}),
        response({"interfaces": rows[27:], "meta": {"counts": {"total": 54, "remaining": 0}}}),
    ]
    report, calls = run(
        [*pages, action(item(PARENT)), topology(PARENT, native=tuple(port for port in PORTS if port != PARENT))],
        config=[group(PARENT)],
        verify={"enabled": True},
        platform_inventory=switch_inventory(inventory(vpcConfigured=True)["DATA"]),
    )
    assert report["failed"] is False
    assert [parse_qs(urlsplit(call["path"]).query)["offset"] for call in summary_calls(calls)] == [["0"], ["27"], ["0"]]
    assert all(parse_qs(urlsplit(call["path"]).query)["filter"] == [scoped_filter("interfaceType:ethernet", SERIAL)] for call in summary_calls(calls))


@pytest.mark.parametrize("stage", ["initial", "post_action"])
def test_a_controller_still_returning_the_vpc_peer_is_rejected_not_silently_filtered(stage):
    if stage == "initial":
        script = [combined(topology(native=PORTS), topology(native=PORTS, switch=OTHER_SERIAL))]
    else:
        script = [topology(native=PORTS), action(item(PARENT)), combined(topology(PARENT), topology(PARENT, switch=OTHER_SERIAL))]
    report, calls = run(script, config=[group(PARENT)], verify={"enabled": True}, platform_inventory=switch_inventory(inventory(vpcConfigured=True)["DATA"]))
    assert report["failed"] is True
    assert "unexpected switch identity" in report["msg"]
    assert len(writes(calls)) == (0 if stage == "initial" else 1)
    assert report["changed"] is (stage == "post_action")
    assert report.get("recovery", []) == []
    assert report.get("after", []) == [] and report["after_status"] == "unknown"
    if stage == "post_action":
        assert report["verification"]["complete"] is False
    assert all(parse_qs(urlsplit(call["path"]).query)["filter"] == [scoped_filter("interfaceType:ethernet", SERIAL)] for call in summary_calls(calls))


def test_global_override_discovery_remains_unscoped_but_each_action_guard_is_scoped():
    report, calls = run(
        [
            combined(topology(PARENT), topology(PARENT, switch=OTHER_SERIAL)),
            switch_inventory(inventory()["DATA"], inventory(OTHER_SERIAL)["DATA"]),
            action(item(PARENT + "/1"), item(PARENT + "/1", switch=OTHER_SERIAL)),
            topology(native=(PARENT,)),
            topology(native=(PARENT,), switch=OTHER_SERIAL),
        ],
        state="overridden",
        config=[],
        verify={"enabled": True},
        platform_inventory=None,
    )
    assert report["failed"] is False and report["changed"] is True
    inventory_calls = [call for call in calls if urlsplit(call["path"]).path.endswith("/switches")]
    assert len(inventory_calls) == 1
    assert_switch_inventory_get(inventory_calls[0])
    queries = [parse_qs(urlsplit(call["path"]).query) for call in summary_calls(calls)]
    assert "switchId" not in queries[0] and queries[0]["filter"] == ["interfaceType:ethernet"]
    assert [query["switchId"] for query in queries[1:]] == [[SERIAL], [OTHER_SERIAL]]
    assert [query["filter"] for query in queries[1:]] == [
        [scoped_filter("interfaceType:ethernet", SERIAL)],
        [scoped_filter("interfaceType:ethernet", OTHER_SERIAL)],
    ]


def test_switch_filter_keeps_the_live_verified_bare_serial_syntax():
    serial = "FLM271702LT"
    report, calls = run(
        [topology(native=(PARENT,), switch=serial), action(item(PARENT, switch=serial))],
        config=[group(PARENT, switch=serial)],
        verify={"enabled": False},
    )
    assert report["failed"] is False
    query = parse_qs(urlsplit(summary_calls(calls)[0]["path"]).query)
    assert query["switchId"] == [serial]
    assert query["filter"] == [scoped_filter("interfaceName:*" + PARENT + "*", serial)]
