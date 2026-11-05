# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""FEX names do not become breakout families when discovery flags lag.

These scripted controller responses exercise interface namespaces, not hardware
capability or a claim that a particular switch has a slot 99.
"""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_readiness import (
    BREAKOUT,
    FAST,
    P21,
    P23,
    REMOVE,
    SERIAL,
    VERIFY,
    action,
    clock,
    combined,
    group,
    intent_topology,
    item,
    run,
    summary_calls,
    topology,
    writes,
)


@pytest.mark.parametrize("slot", [100, 101, 999])
def test_active_intended_fex_rows_with_false_fex_flag_do_not_create_families(clock, slot):
    fex_parent = f"Ethernet{slot}/1"
    ghost = intent_topology(fex_parent)
    report, calls = run(
        [combined(topology(native=(P21,)), ghost), action(item(P21)), combined(topology(P21), ghost)],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is False and report["changed"] is True
    assert {row["interface_name"] for row in report["before"]} == {P21}
    assert {row["interface_name"] for row in report["after"]} == {P21}
    assert report["after"][0]["broken_out"] is True
    assert report["recovery"] == []
    assert [call["path"] for call in writes(calls)] == [BREAKOUT]
    assert len(summary_calls(calls)) == 2
    assert clock.sleeps == []


@pytest.mark.parametrize("selector", ["Ethernet101/1", "Ethernet101/1/1"])
def test_response_only_delete_rejects_fex_namespace_even_with_false_flag(clock, selector):
    report, calls = run(
        [topology("Ethernet101/1")],
        state="deleted",
        config=[group(selector, breakout_map=None)],
        verify=FAST,
    )
    assert report["failed"] is True and report["changed"] is False
    assert "FEX interface 'Ethernet101/1/1'" in report["msg"]
    assert "cannot be safely classified as a breakout resource" in report["msg"]
    assert writes(calls) == []
    assert len(summary_calls(calls)) == 1
    assert clock.sleeps == []


def test_ignoring_fex_intent_does_not_hide_real_unrequested_breakout(clock):
    ghost = intent_topology("Ethernet101/1")
    after = combined(intent_topology(P21, P23, ready_children=(P21 + "/1",)), ghost)
    report, calls = run(
        [combined(topology(native=(P21, P23)), ghost), action(item(P21)), after, action(item(P21 + "/1"))],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True and report["changed"] is True
    assert "Unexpected breakout family 'Ethernet1/23'" in report["msg"]
    assert "include all affected parents (Ethernet1/21, Ethernet1/23) in config" in report["msg"]
    assert {row["interface_name"] for row in report["before"]} == {P21}
    assert {row["interface_name"] for row in report["observed_before_recovery"]} == {P21, P23}
    assert report["recovery"][0]["status"] == "response_confirmed"
    assert [call["path"] for call in writes(calls)] == [BREAKOUT, REMOVE]
    assert writes(calls)[1]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P21 + "/1"}]}
    assert len(summary_calls(calls)) == 2
    assert calls[-1]["verb"] == HttpVerbEnum.POST
    assert clock.sleeps == []


@pytest.mark.parametrize("state", ["merged", "deleted"])
def test_slot_99_remains_within_breakout_namespace(clock, state):
    parent = "Ethernet99/1"
    if state == "merged":
        scripted = [topology(native=(parent,)), action(item(parent)), intent_topology(parent)]
        config = [group(parent)]
    else:
        scripted = [topology(parent), action(item(parent + "/1"))]
        config = [group(parent + "/1", breakout_map=None)]
    report, calls = run(scripted, state=state, config=config, verify=VERIFY if state == "merged" else FAST)
    assert report["failed"] is False and report["changed"] is True
    assert report.get("recovery", []) == []
    assert writes(calls)[0]["path"] == (BREAKOUT if state == "merged" else REMOVE)
    assert len(writes(calls)) == 1
    assert len(summary_calls(calls)) == (2 if state == "merged" else 1)
    if state == "merged":
        assert report["after"][0]["interface_name"] == parent
        assert report["after"][0]["broken_out"] is True
        assert report["after"][0]["evidence"] == "controller_intent"
    else:
        assert writes(calls)[0]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": parent + "/1"}]}
    assert clock.sleeps == []
