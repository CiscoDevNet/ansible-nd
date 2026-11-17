# -*- coding: utf-8 -*-

"""Unit tests for the Interface preview integration validation plugin."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from ansible.plugins.action import ActionBase
from ansible_collections.cisco.nd.plugins.action.tests.integration.nd_interface_preview_validate import (
    ActionModule,
    _extract_diffs,
)


@pytest.fixture
def action_plugin():
    plugin = ActionModule.__new__(ActionModule)
    plugin._task = SimpleNamespace(args={})
    return plugin


def _run(plugin, **args):
    plugin._task.args = args
    with patch.object(ActionBase, "run", return_value={}):
        return plugin.run(task_vars={})


def _preview(
    switch_id="SN1",
    interface_name="Ethernet1/1",
    pending_lines=0,
    status="success",
):
    return {
        "switchId": switch_id,
        "interfaceName": interface_name,
        "status": status,
        "message": "Configuration preview completed",
        "combinedConfigs": [
            {
                "configType": "running",
                "config": "interface Ethernet1/1\n  no shutdown\n",
                "lines": 2,
            },
            {
                "configType": "pending",
                "config": "interface Ethernet1/1\n",
                "lines": pending_lines,
            },
            {
                "configType": "expected",
                "config": "interface Ethernet1/1\n  switchport mode trunk\n",
                "lines": 2,
            },
        ],
    }


def _malformed_preview(malformation: str) -> dict:
    entry = _preview()
    if malformation == "missing_combined_configs":
        entry.pop("combinedConfigs")
    elif malformation == "missing_pending_entry":
        entry["combinedConfigs"] = [config for config in entry["combinedConfigs"] if config["configType"] != "pending"]
    elif malformation == "missing_lines":
        entry["combinedConfigs"][1].pop("lines")
    else:
        entry["combinedConfigs"][1]["lines"] = "not-an-integer"
    return entry


def test_extracts_documented_and_wrapped_preview_shapes():
    entry = _preview()
    assert _extract_diffs({"current": {"configurationDiffs": [entry]}}) == [entry]
    assert _extract_diffs({"result": {"items": [entry]}}) == [entry]
    assert _extract_diffs(entry) == [entry]


def test_clean_preview_and_config_fragments_pass(action_plugin):
    result = _run(
        action_plugin,
        nd_data={"current": {"configurationDiffs": [_preview()]}},
        test_data=[
            {
                "switch_id": "SN1",
                "interface_name": "eth1/1",
                "pending": "clean",
                "expected_contains": ["switchport mode trunk"],
                "running_contains": ["no shutdown"],
            }
        ],
    )

    assert result.get("failed", False) is False
    assert result["changed"] is False
    assert not any(result["report"].values())


def test_pending_preview_is_detected(action_plugin):
    result = _run(
        action_plugin,
        nd_data={"configurationDiffs": [_preview(pending_lines=3)]},
        test_data={
            "switch_id": "SN1",
            "interface_name": "Ethernet1/1",
            "pending": "present",
        },
    )

    assert result.get("failed", False) is False


def test_numeric_string_pending_lines_retain_compatibility(action_plugin):
    result = _run(
        action_plugin,
        nd_data={"configurationDiffs": [_preview(pending_lines="0")]},
        test_data={
            "switch_id": "SN1",
            "interface_name": "Ethernet1/1",
            "pending": "clean",
        },
    )

    assert result.get("failed", False) is False


@pytest.mark.parametrize(
    "malformation",
    [
        "missing_combined_configs",
        "missing_pending_entry",
        "missing_lines",
        "non_integer_lines",
    ],
)
@pytest.mark.parametrize("pending", ["clean", "present"])
def test_missing_or_invalid_pending_data_fails(action_plugin, malformation, pending):
    result = _run(
        action_plugin,
        nd_data={"configurationDiffs": [_malformed_preview(malformation)]},
        test_data={
            "switch_id": "SN1",
            "interface_name": "Ethernet1/1",
            "pending": pending,
        },
    )

    assert result["failed"] is True
    assert result["report"]["pending_mismatches"] == [
        {
            "interface": "SN1/Ethernet1/1",
            "expected": pending,
            "pending_lines": None,
        }
    ]


@pytest.mark.parametrize(
    "malformation",
    [
        "missing_combined_configs",
        "missing_pending_entry",
        "missing_lines",
        "non_integer_lines",
    ],
)
def test_pending_ignore_allows_missing_or_invalid_pending_data(action_plugin, malformation):
    result = _run(
        action_plugin,
        nd_data={"configurationDiffs": [_malformed_preview(malformation)]},
        test_data={
            "switch_id": "SN1",
            "interface_name": "Ethernet1/1",
            "pending": "ignore",
        },
    )

    assert result.get("failed", False) is False
    assert result["report"]["pending_mismatches"] == []


def test_missing_failed_and_pending_mismatch_are_reported(action_plugin):
    result = _run(
        action_plugin,
        nd_data={
            "configurationDiffs": [
                _preview(pending_lines=2, status="failed"),
            ]
        },
        test_data=[
            {
                "switch_id": "SN1",
                "interface_name": "Ethernet1/1",
                "pending": "clean",
            },
            {
                "switch_id": "SN2",
                "interface_name": "Ethernet1/2",
            },
        ],
    )

    assert result["failed"] is True
    assert result["report"]["missing"] == ["SN2/Ethernet1/2"]
    assert result["report"]["failed_status"][0]["interface"] == "SN1/Ethernet1/1"
    assert result["report"]["pending_mismatches"][0]["pending_lines"] == 2


def test_duplicate_preview_entries_and_missing_fragments_fail(action_plugin):
    entry = _preview()
    result = _run(
        action_plugin,
        nd_data={"configurationDiffs": [entry, entry]},
        test_data={
            "switch_id": "SN1",
            "interface_name": "Ethernet1/1",
            "expected_contains": ["feature-not-present"],
        },
    )

    assert result["failed"] is True
    assert result["report"]["duplicates"] == ["SN1/Ethernet1/1"]
    assert result["report"]["config_fragments_missing"][0]["fragment"] == ("feature-not-present")


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ({}, "'nd_data' is required"),
        ({"nd_data": {}, "test_data": []}, "non-empty"),
        (
            {
                "nd_data": {},
                "test_data": [{"switch_id": "SN1"}],
            },
            "requires switch_id and interface_name",
        ),
        (
            {
                "nd_data": {},
                "test_data": [
                    {
                        "switch_id": "SN1",
                        "interface_name": "Ethernet1/1",
                        "pending": "unknown",
                    }
                ],
            },
            "pending must be one of",
        ),
    ],
)
def test_invalid_contracts_fail_cleanly(action_plugin, args, message):
    result = _run(action_plugin, **args)

    assert result["failed"] is True
    assert result["changed"] is False
    assert message in result["msg"]


def test_upstream_preview_failure_is_reported(action_plugin):
    result = _run(
        action_plugin,
        nd_data={"failed": True, "msg": "preview unavailable"},
        test_data={"switch_id": "SN1", "interface_name": "Ethernet1/1"},
    )

    assert result["failed"] is True
    assert "preview unavailable" in result["msg"]
