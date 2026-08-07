# -*- coding: utf-8 -*-

"""Unit tests for the Interface Group live-state validation action plugin."""

from __future__ import absolute_import, division, print_function

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from ansible.plugins.action import ActionBase
from ansible_collections.cisco.nd.plugins.action.tests.integration._nd_interface_group_validate import (
    ActionModule,
    _extract_groups,
    _normalise_group,
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


def _group(name="ANSIBLE-IG-PC"):
    return {
        "interfaceGroupName": name,
        "type": "portChannel",
        "networkNames": ["Network-B", "Network-A"],
        "switchInterfaces": [
            {
                "switchId": "SN1",
                "interfaceNames": ["Port-channel502", "Port-channel501"],
            }
        ],
    }


def test_extracts_get_one_and_list_responses():
    single = _group()
    assert _extract_groups({"current": single}) == [single]
    assert _extract_groups({"current": {"interfaceGroupDetails": [single]}}) == [single]
    assert _extract_groups({"gathered": [single]}) == [single]
    assert _extract_groups({"first_run_result": {"gathered": [single]}}) == [single]


def test_normalises_nested_association_and_order():
    model = _normalise_group(
        {
            "interfaceGroupName": "ANSIBLE-IG-PC",
            "type": "portChannel",
            "interfaceGroupAssociation": {
                "networkNames": ["Network-B", "Network-A", "Network-A"],
                "switchInterfaces": [
                    {
                        "switchId": "SN1",
                        "interfaceNames": ["Port-channel502", "Port-channel501"],
                    }
                ],
            },
        }
    )

    assert model["networks"] == ["Network-A", "Network-B"]
    assert model["switch_interfaces"] == {"SN1": ["Port-channel501", "Port-channel502"]}


def test_normalises_ethernet_attribute_aliases():
    model = _normalise_group(
        {
            "interfaceGroupName": "ANSIBLE-IG-ETH-POLICY",
            "ethernetAttributes": {
                "adminStatus": True,
                "nativeVlan": 10,
                "vPCOrphanPort": False,
            },
        }
    )

    assert model["ethernet_attributes"] == {
        "admin_status": True,
        "native_vlan": 10,
        "vpc_orphan_port": False,
    }


def test_custom_template_validation_accepts_controller_scalar_echoes(action_plugin):
    result = _run(
        action_plugin,
        nd_data={
            "current": {
                "interfaceGroupName": "ANSIBLE-IG-ETH-CUSTOM",
                "type": "ethernet",
                "policyDetails": {
                    "policyType": "userDefinedSharedTrunk",
                    "templateName": "dupe_shared_trunk_host",
                    "templateConfig": {
                        "ADMIN_STATE": "true",
                        "NATIVE_VLAN": "1",
                        "POLICY_ID": "POLICY-SHARED-1",
                    },
                },
            }
        },
        test_data=[
            {
                "interface_group_name": "ANSIBLE-IG-ETH-CUSTOM",
                "type": "ethernetCustom",
                "template_name": "dupe_shared_trunk_host",
                "template_config": {
                    "ADMIN_STATE": True,
                    "NATIVE_VLAN": None,
                },
            }
        ],
        mode="exact",
    )

    assert result.get("failed", False) is False


def test_normalises_live_generic_ethernet_policy_shape():
    model = _normalise_group(
        {
            "interfaceGroupName": "ANSIBLE-IG-ETH-POLICY",
            "type": "ethernet",
            "policyDetails": {
                "policyId": "POLICY-SHARED-1",
                "policyType": "sharedTrunkHost",
                "ethernetAttributes": {
                    "adminState": True,
                    "allowedVlans": "100-200",
                    "autoNegotiate": False,
                    "portTypeEdgeTrunk": True,
                },
            },
        }
    )

    assert model["type"] == "ethernetWithPolicy"
    assert model["ethernet_attributes"] == {
        "admin_status": True,
        "auto_negotiation": "off",
        "port_type_fast": True,
        "trunk_allowed_vlans": "100-200",
    }


def test_normalises_live_custom_ethernet_policy_shape():
    model = _normalise_group(
        {
            "interfaceGroupName": "ANSIBLE-IG-ETH-CUSTOM",
            "type": "ethernet",
            "policyDetails": {
                "policyType": "userDefinedSharedTrunk",
                "templateName": "int_shared_custom_trunk_host",
                "templateConfig": {
                    "adminStatus": True,
                    "extraConfig": "logging event port link-status",
                },
            },
        }
    )

    assert model["type"] == "ethernetCustom"
    assert model["template_name"] == "int_shared_custom_trunk_host"
    assert model["template_config"] == {
        "adminStatus": True,
        "extraConfig": "logging event port link-status",
    }


def test_subset_mode_accepts_additive_state(action_plugin):
    result = _run(
        action_plugin,
        nd_data={"current": _group()},
        test_data=[
            {
                "interface_group_name": "ANSIBLE-IG-PC",
                "networks": ["Network-A"],
                "switch_interfaces": [
                    {
                        "switch_id": "SN1",
                        "interface_names": ["Port-channel501"],
                    }
                ],
            }
        ],
        mode="subset",
    )

    assert result.get("failed", False) is False
    assert result["report"]["mismatches"] == []


def test_exact_mode_detects_removed_collection_members(action_plugin):
    result = _run(
        action_plugin,
        nd_data={"current": _group()},
        test_data=[
            {
                "interface_group_name": "ANSIBLE-IG-PC",
                "networks": ["Network-A"],
                "switch_interfaces": [
                    {
                        "switch_id": "SN1",
                        "interface_names": ["Port-channel501"],
                    }
                ],
            }
        ],
        mode="exact",
    )

    assert result["failed"] is True
    assert {item["field"] for item in result["report"]["mismatches"]} == {
        "networks",
        "switch_interfaces",
    }


def test_vpc_member_accepts_opposite_peer_echo_and_normalises_name(action_plugin):
    result = _run(
        action_plugin,
        nd_data={
            "current": {
                "interfaceGroupName": "ANSIBLE-IG-VPC",
                "type": "vpc",
                "switchInterfaces": [{"switchId": "SN2", "interfaceNames": ["vPC200"]}],
            }
        },
        test_data=[
            {
                "interface_group_name": "ANSIBLE-IG-VPC",
                "type": "vpc",
                "switch_interfaces": [{"switch_id": "SN1", "interface_names": ["vpc200"]}],
            }
        ],
        mode="exact",
        vpc_peer_switch_ids={"SN1": "SN2"},
    )

    assert result.get("failed", False) is False
    assert result["groups"][0]["switch_interfaces"] == {"SN2": ["vPC200"]}


def test_mixed_any_group_canonicalises_only_vpc_member(action_plugin):
    result = _run(
        action_plugin,
        nd_data={
            "current": {
                "interfaceGroupName": "ANSIBLE-IG-ANY",
                "type": "any",
                "switchInterfaces": [
                    {"switchId": "SN1", "interfaceNames": ["Ethernet1/3"]},
                    {
                        "switchId": "SN2",
                        "interfaceNames": ["vPC200", "Port-channel504"],
                    },
                ],
            }
        },
        test_data=[
            {
                "interface_group_name": "ANSIBLE-IG-ANY",
                "type": "any",
                "switch_interfaces": [
                    {
                        "switch_id": "SN1",
                        "interface_names": ["Ethernet1/3", "vpc200"],
                    },
                    {
                        "switch_id": "SN2",
                        "interface_names": ["Port-channel504"],
                    },
                ],
            }
        ],
        mode="exact",
        vpc_peer_switch_ids={"SN1": "SN2"},
    )

    assert result.get("failed", False) is False


@pytest.mark.parametrize(
    ("interface_name", "actual_switch_id"),
    [("Ethernet1/3", "SN2"), ("Port-channel504", "SN2"), ("vPC200", "SN3")],
)
def test_peer_mapping_does_not_hide_non_vpc_or_unrelated_switch_mismatch(action_plugin, interface_name, actual_switch_id):
    result = _run(
        action_plugin,
        nd_data={
            "current": {
                "interfaceGroupName": "ANSIBLE-IG-ANY",
                "type": "any",
                "switchInterfaces": [
                    {
                        "switchId": actual_switch_id,
                        "interfaceNames": [interface_name],
                    }
                ],
            }
        },
        test_data=[
            {
                "interface_group_name": "ANSIBLE-IG-ANY",
                "switch_interfaces": [{"switch_id": "SN1", "interface_names": [interface_name]}],
            }
        ],
        mode="exact",
        vpc_peer_switch_ids={"SN1": "SN2"},
    )

    assert result["failed"] is True
    assert result["report"]["mismatches"][0]["field"] == "switch_interfaces"


@pytest.mark.parametrize(
    "peer_mapping",
    [[], {"": "SN2"}, {"SN1": ""}, {"SN1": "SN1"}],
)
def test_invalid_vpc_peer_mapping_fails_cleanly(action_plugin, peer_mapping):
    result = _run(
        action_plugin,
        nd_data={},
        vpc_peer_switch_ids=peer_mapping,
    )

    assert result["changed"] is False
    assert result["failed"] is True
    assert "vpc_peer_switch_ids" in result["msg"]


def test_absent_and_missing_are_reported(action_plugin):
    result = _run(
        action_plugin,
        nd_data={"current": {"interfaceGroupDetails": [_group()]}},
        test_data=[{"interface_group_name": "ANSIBLE-IG-MISSING"}],
        absent=["ANSIBLE-IG-PC"],
    )

    assert result["failed"] is True
    assert result["report"]["missing"] == ["ANSIBLE-IG-MISSING"]
    assert result["report"]["unexpected_present"] == ["ANSIBLE-IG-PC"]


def test_scoped_type_and_unique_members_invariants(action_plugin):
    second = _group("ANSIBLE-IG-PC-2")
    result = _run(
        action_plugin,
        nd_data={
            "current": {
                "interfaceGroupDetails": [
                    _group(),
                    second,
                    {
                        "interfaceGroupName": "UNRELATED",
                        "type": "ethernetWithPolicy",
                    },
                ]
            }
        },
        scope_prefix="ANSIBLE-IG-",
        invariants={
            "total_count": 2,
            "required_types": ["portChannel"],
            "unique_group_names": True,
            "unique_members": True,
        },
    )

    assert result["failed"] is True
    assert "members assigned to multiple groups" in result["report"]["invariant_failures"][0]


def test_invalid_mode_and_missing_data_fail_cleanly(action_plugin):
    missing = _run(action_plugin)
    invalid = _run(action_plugin, nd_data={}, mode="replace")

    assert missing["changed"] is False
    assert missing["failed"] is True
    assert invalid["failed"] is True
    assert "mode must be one of" in invalid["msg"]


def test_unknown_arguments_are_rejected(action_plugin):
    result = _run(action_plugin, nd_data={}, expected_stats=200)

    assert result["failed"] is True
    assert "unsupported argument" in result["msg"]


def test_upstream_nd_query_failure_is_reported(action_plugin):
    result = _run(
        action_plugin,
        nd_data={"failed": True, "msg": "controller unavailable"},
    )

    assert result["failed"] is True
    assert "controller unavailable" in result["msg"]


def test_all_scoped_invariants_report_precise_failures(action_plugin):
    result = _run(
        action_plugin,
        nd_data={
            "current": {
                "interfaceGroupDetails": [
                    _group(),
                    _group(),
                    {
                        "interfaceGroupName": "ANSIBLE-IG-OTHER",
                        "type": "vpc",
                    },
                    {
                        "interfaceGroupName": "UNRELATED",
                        "type": "ethernetWithPolicy",
                    },
                ]
            }
        },
        scope_prefix="ANSIBLE-IG-",
        invariants={
            "total_count": 2,
            "min_count": 5,
            "max_count": 1,
            "required_types": ["ethernetCustom"],
            "unique_group_names": True,
        },
    )

    failures = result["report"]["invariant_failures"]
    assert result["failed"] is True
    assert any("total_count=2, got 3" in item for item in failures)
    assert any("min_count=5" in item for item in failures)
    assert any("max_count=1" in item for item in failures)
    assert any("missing required type(s): ethernetCustom" in item for item in failures)
    assert any("duplicate interface group name(s)" in item for item in failures)
    assert all("UNRELATED" not in item for item in failures)


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ({"nd_data": {}, "test_data": "invalid"}, "test_data must be"),
        ({"nd_data": {}, "test_data": [1]}, "entries must be dictionaries"),
        ({"nd_data": {}, "invariants": []}, "invariants must be a dictionary"),
        (
            {"nd_data": {}, "invariants": {"unsupported": True}},
            "unsupported invariant",
        ),
    ],
)
def test_invalid_comparison_contracts_fail_cleanly(action_plugin, args, message):
    result = _run(action_plugin, **args)

    assert result["changed"] is False
    assert result["failed"] is True
    assert message in result["msg"]


def test_absent_dictionary_alias_and_serialized_output(action_plugin):
    result = _run(
        action_plugin,
        nd_data={"result": {"interfaceGroupDetails": [_group()]}},
        absent=[{"interfaceGroupName": "MISSING"}],
        test_data=[{"interface_group_name": "ANSIBLE-IG-PC"}],
        mode="subset",
    )

    assert result.get("failed", False) is False
    assert result["report"]["unexpected_present"] == []
    assert result["groups"] == [
        {
            "interface_group_name": "ANSIBLE-IG-PC",
            "type": "portChannel",
            "networks": ["Network-A", "Network-B"],
            "switch_interfaces": {"SN1": ["Port-channel501", "Port-channel502"]},
        }
    ]


def test_subset_dictionary_comparison_detects_nested_mismatch(action_plugin):
    actual = _group()
    actual["templateConfig"] = {
        "nested": {"value": "actual", "preserved": True},
    }
    result = _run(
        action_plugin,
        nd_data={"current": actual},
        test_data=[
            {
                "interface_group_name": "ANSIBLE-IG-PC",
                "template_config": {"nested": {"value": "expected"}},
            }
        ],
        mode="subset",
    )

    assert result["failed"] is True
    assert result["report"]["mismatches"][0]["field"] == "template_config"


def test_unreadable_top_level_description_is_not_projected(action_plugin):
    actual = _group()
    actual["description"] = "Controller write-only value"
    result = _run(
        action_plugin,
        nd_data={"current": actual},
        test_data=[
            {
                "interface_group_name": "ANSIBLE-IG-PC",
            }
        ],
    )

    assert result.get("failed", False) is False
    assert "description" not in result["groups"][0]


def test_consistent_count_invariant_validates_members_and_networks(action_plugin):
    group = _group()
    group["interfaceCount"] = 2
    group["networkCount"] = 2
    passing = _run(
        action_plugin,
        nd_data={"interfaceGroupDetails": [group]},
        invariants={"consistent_counts": True},
    )

    assert passing.get("failed", False) is False

    group["interfaceCount"] = 1
    group.pop("networkCount")
    failing = _run(
        action_plugin,
        nd_data={"interfaceGroupDetails": [group]},
        invariants={"consistent_counts": True},
    )

    assert failing["failed"] is True
    assert any("expected interface_count=2, got 1" in item for item in failing["report"]["invariant_failures"])
    assert any("missing network_count" in item for item in failing["report"]["invariant_failures"])
