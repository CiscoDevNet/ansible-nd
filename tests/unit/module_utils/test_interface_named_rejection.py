# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# SPDX-License-Identifier: GPL-3.0-or-later

"""Named synchronous rejection receipts must fail closed on ambiguity."""

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.interface_named_rejection import named_sync_rejections
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_executor import InterfaceExecutionItem, InterfaceWorkflowExecutor

TARGETS = [("SERIAL1", "vlan3991"), ("SERIAL2", "Ethernet1/31.992")]


def response():
    return {
        "METHOD": "POST",
        "RETURN_CODE": 207,
        "DATA": {"results": [{"name": "SERIAL1:vlan3991", "status": "failed"}, {"name": "SERIAL2~Ethernet1/31.992", "status": "success"}]},
    }


@pytest.mark.parametrize("status", ["failed", "failure", "error", " ERROR "])
@pytest.mark.parametrize("separator", [":", "~"])
def test_complete_exact_result_emits_only_explicit_named_negative(status, separator):
    raw = response()
    raw["DATA"]["results"][0].update(name="serial1" + separator + "VLAN3991", status=status)

    proof = named_sync_rejections(raw, TARGETS)

    assert proof == {
        ("SERIAL1", "vlan3991"): {
            "version": 1,
            "source": "native_named_sync_rejection_v1",
            "action": "create",
            "switch_id": "SERIAL1",
            "interface_name": "vlan3991",
            "http_status": 207,
            "response_status": status.strip().casefold(),
        }
    }


@pytest.mark.parametrize("bare_success", [False, True])
def test_bare_negative_binds_only_to_one_authoritative_mutation_request_switch(bare_success):
    """ND mixes qualified successes with bare failures on one-switch POSTs."""
    targets = [("SERIAL1", "vlan3991"), ("SERIAL1", "loopback153")]
    raw = response()
    raw["DATA"]["results"] = [
        {"name": "vlan3991", "status": "failed"},
        {"name": "loopback153" if bare_success else "SERIAL1~loopback153", "status": "success"},
    ]

    proof = named_sync_rejections(raw, targets)

    assert list(proof) == [("SERIAL1", "vlan3991")]
    assert proof[("SERIAL1", "vlan3991")]["switch_id"] == "SERIAL1"


@pytest.mark.parametrize("fault", ["multiple_switches", "foreign_qualified", "foreign_explicit", "duplicate_alias", "missing", "unknown"])
def test_single_switch_bare_name_binding_retains_all_exactness_guards(fault):
    targets = [("SERIAL1", "vlan3991"), ("SERIAL1", "loopback153")]
    raw = response()
    rows = [{"name": "vlan3991", "status": "failed"}, {"name": "SERIAL1~loopback153", "status": "success"}]
    raw["DATA"]["results"] = rows
    if fault == "multiple_switches":
        targets[1] = ("SERIAL2", "loopback153")
        rows[1]["name"] = "SERIAL2~loopback153"
    elif fault == "foreign_qualified":
        rows[1]["name"] = "SERIAL2~loopback153"
    elif fault == "foreign_explicit":
        rows[0]["switchId"] = "SERIAL2"
    elif fault == "duplicate_alias":
        rows[1]["name"] = "SERIAL1~vlan3991"
    elif fault == "missing":
        rows.pop()
    else:
        rows[1]["status"] = "pending"

    assert named_sync_rejections(raw, targets) == {}


@pytest.mark.parametrize(
    "fault",
    [
        "no_response",
        "timeout",
        "flat500",
        "put",
        "missing_method",
        "missing_row",
        "extra_row",
        "duplicate",
        "contradiction",
        "foreign",
        "plain_name",
        "pair_name",
        "mixed_separator",
        "unknown_status",
        "pending_status",
        "null_status",
        "wrong_switch",
        "wrong_interface",
        "missing_results",
        "malformed_row",
    ],
)
def test_unknown_incomplete_duplicate_or_contradictory_outcome_has_no_negative_proof(fault):
    raw = response()
    rows = raw["DATA"]["results"]
    if fault == "no_response":
        raw = {}
    elif fault == "timeout":
        raw.pop("RETURN_CODE")
    elif fault == "flat500":
        raw["RETURN_CODE"] = 500
    elif fault == "put":
        raw["METHOD"] = "PUT"
    elif fault == "missing_method":
        raw.pop("METHOD")
    elif fault == "missing_row":
        rows.pop()
    elif fault == "extra_row":
        rows.append({"name": "FOREIGN~vlan3991", "status": "error"})
    elif fault == "duplicate":
        rows[1] = deepcopy(rows[0])
    elif fault == "contradiction":
        rows[1] = {"name": rows[0]["name"], "status": "success"}
    elif fault in {"foreign", "plain_name", "pair_name", "mixed_separator"}:
        rows[0]["name"] = {
            "foreign": "FOREIGN:vlan3991",
            "plain_name": "vlan3991",
            "pair_name": "SERIAL1~SERIAL2~vlan3991",
            "mixed_separator": "SERIAL1:SERIAL2~vlan3991",
        }[fault]
    elif fault in {"unknown_status", "pending_status", "null_status"}:
        rows[0]["status"] = {"unknown_status": "unknown", "pending_status": "accepted", "null_status": None}[fault]
    elif fault == "wrong_switch":
        rows[0]["switchId"] = "OTHER"
    elif fault == "wrong_interface":
        rows[0]["interfaceName"] = "vlan2091"
    elif fault == "missing_results":
        raw["DATA"].pop("results")
    else:
        rows[0] = "not a result"

    assert named_sync_rejections(raw, TARGETS) == {}


def test_rejection_attaches_only_to_failed_logical_create_not_generic_failed_status():
    items = [
        InterfaceExecutionItem(0, "svi", "create", "192.0.2.1", "SERIAL1", "vlan3991", status="failed"),
        InterfaceExecutionItem(1, "subinterface_unmanaged", "create", "192.0.2.2", "SERIAL2", "Ethernet1/31.992", status="succeeded"),
    ]
    InterfaceWorkflowExecutor._record_named_create_rejections(items, response())
    assert items[0].to_dict()["rejection"]["switch_id"] == "SERIAL1"
    assert "rejection" not in items[1].to_dict()
    items[0].rejection = None
    raw = response()
    raw["DATA"]["results"].pop()
    InterfaceWorkflowExecutor._record_named_create_rejections(items, raw)
    assert "rejection" not in items[0].to_dict()


@pytest.mark.parametrize("action,family", [("update", "svi"), ("transition", "svi"), ("create", "ethernet_access"), ("create", "vpc_access")])
def test_rejection_scope_does_not_grant_other_operations_cancel_authority(action, family):
    items = [
        InterfaceExecutionItem(0, family, action, "192.0.2.1", "SERIAL1", "vlan3991", status="failed"),
        InterfaceExecutionItem(1, "subinterface_unmanaged", "create", "192.0.2.2", "SERIAL2", "Ethernet1/31.992", status="succeeded"),
    ]
    InterfaceWorkflowExecutor._record_named_create_rejections(items, response())
    assert "rejection" not in items[0].to_dict()
