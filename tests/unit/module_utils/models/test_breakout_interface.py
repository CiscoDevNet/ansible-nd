# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pure breakout input-contract tests without controller or device assumptions."""

from __future__ import annotations

from copy import deepcopy

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_breakout_interfaces.breakout_interface import BreakoutInterfaceModel, expand_config


def _group(**changes):
    group = {"switch_id": "FDO222425SE", "interface_names": ["Ethernet1/50"], "breakout_map": "25g-4x"}
    group.update(changes)
    return group


@pytest.mark.parametrize("switch_id", ["FDO222425SE", "192.0.2.10", "2001:db8::10"])
def test_serial_and_management_ip_inputs_are_preserved(switch_id):
    models = expand_config([_group(switch_id=f" {switch_id} ")], "merged")
    assert models[0].switch_id == switch_id


def test_group_expansion_is_ordered_normalized_and_does_not_modify_input():
    raw = [_group(interface_names=[" ethernet01/050 ", "Ethernet1/51"], breakout_map=" 25G-4X "), _group(switch_id="192.0.2.11")]
    original = deepcopy(raw)
    models = expand_config(raw, "merged")
    assert [(item.switch_id, item.interface_name, item.breakout_map) for item in models] == [
        ("FDO222425SE", "Ethernet1/50", "25g-4x"),
        ("FDO222425SE", "Ethernet1/51", "25g-4x"),
        ("192.0.2.11", "Ethernet1/50", "25g-4x"),
    ]
    assert raw == original


@pytest.mark.parametrize("breakout_map", ["50g-2x", "100g-4x", "200g-2x", "new-map-supported-by-controller"])
def test_nonblank_maps_are_not_limited_to_a_hardware_or_map_allowlist(breakout_map):
    assert expand_config([_group(breakout_map=breakout_map)], "merged")[0].breakout_map == breakout_map


def test_deleted_uses_same_native_parent_without_a_map():
    model = expand_config([{"switch_id": "FDO222425SE", "interface_names": ["Ethernet1/50"]}], "deleted")[0]
    assert model.interface_name == "Ethernet1/50"
    assert model.breakout_map is None
    assert model.requested_child is None


@pytest.mark.parametrize(
    "selector,parent,child",
    [
        ("Ethernet1/50/1", "Ethernet1/50", "Ethernet1/50/1"),
        (" ethernet01/0050/0002 ", "Ethernet1/50", "Ethernet1/50/2"),
        ("ETHERNET02/00099/00010", "Ethernet2/99", "Ethernet2/99/10"),
        ("Ethernet101/1/1", "Ethernet101/1", "Ethernet101/1/1"),
    ],
)
def test_deleted_child_selector_normalizes_to_canonical_family_without_hardware_assumptions(selector, parent, child):
    raw = [{"switch_id": "FDO222425SE", "interface_names": [selector]}]
    original = deepcopy(raw)
    model = expand_config(raw, "deleted")[0]
    assert model.interface_name == parent
    assert model.requested_child == child
    assert model.breakout_map is None
    assert raw == original


@pytest.mark.parametrize(
    "selector",
    [
        "Ethernet1/50/0",
        "Ethernet0/50/1",
        "Ethernet1/0/1",
        "Ethernet1/50/-1",
        "Ethernet1/50/1.100",
        "Ethernet1/50.100",
        "Ethernet1/50/1/1",
        "Ethernet1/50/1extra",
        "Ethernet1/50/",
        "Ethernet1/50//1",
    ],
)
def test_deleted_rejects_non_positive_dotted_or_four_part_selectors(selector):
    with pytest.raises(ValueError):
        expand_config([{"switch_id": "FDO222425SE", "interface_names": [selector]}], "deleted")


@pytest.mark.parametrize("selectors", [["Ethernet1/50", "Ethernet1/50/1"], ["Ethernet1/50/2", "Ethernet1/50/1"], ["Ethernet1/50/1", "ethernet01/0050/0001"]])
def test_deleted_duplicate_parent_family_aliases_within_group_are_rejected(selectors):
    with pytest.raises(ValueError, match="specified more than once"):
        expand_config([{"switch_id": "FDO222425SE", "interface_names": selectors}], "deleted")


@pytest.mark.parametrize("selectors", [["Ethernet1/50", "Ethernet1/50/1"], ["Ethernet1/50/2", "Ethernet1/50/1"]])
def test_deleted_duplicate_parent_family_aliases_across_groups_are_rejected(selectors):
    with pytest.raises(ValueError, match="specified more than once"):
        expand_config(
            [
                {"switch_id": "FDO222425SE", "interface_names": [selectors[0]]},
                {"switch_id": "fdo222425se", "interface_names": [selectors[1]]},
            ],
            "deleted",
        )


def test_deleted_distinct_child_families_and_same_family_on_other_switch_are_valid():
    models = expand_config(
        [
            {"switch_id": "FDO222425SE", "interface_names": ["Ethernet1/50/2", "Ethernet1/51/1"]},
            {"switch_id": "FDO222425SF", "interface_names": ["Ethernet1/50/1"]},
        ],
        "deleted",
    )
    assert [model.interface_name for model in models] == ["Ethernet1/50", "Ethernet1/51", "Ethernet1/50"]


def test_requested_child_is_internal_and_excluded_from_every_serialization_mode():
    model = expand_config([{"switch_id": "FDO222425SE", "interface_names": ["Ethernet1/50/2"]}], "deleted")[0]
    for dump in [model.model_dump(), model.model_dump(by_alias=True), model.to_payload(), model.to_config(), model.to_diff_dict()]:
        assert "requested_child" not in dump and "requestedChild" not in dump
    assert "requested_child" not in model.model_dump_json()
    assert model.model_copy(deep=True).requested_child == "Ethernet1/50/2"
    assert model.to_payload() == {"switchId": "FDO222425SE", "interfaceName": "Ethernet1/50"}


def test_internal_child_selector_must_belong_to_canonical_parent():
    with pytest.raises(ValueError, match="must belong"):
        BreakoutInterfaceModel(switch_id="FDO222425SE", interface_name="Ethernet1/50", requested_child="Ethernet1/51/1")


def test_requested_child_is_not_a_public_config_option():
    assert "requested_child" not in BreakoutInterfaceModel.get_argument_spec()["config"]["options"]
    with pytest.raises(ValueError, match="Unsupported"):
        expand_config([{"switch_id": "FDO222425SE", "interface_names": ["Ethernet1/50"], "requested_child": "Ethernet1/50/1"}], "deleted")


def test_ansible_unset_optional_map_is_accepted_for_deleted():
    assert expand_config([_group(breakout_map=None)], "deleted")[0].breakout_map is None


@pytest.mark.parametrize("state", ["replaced", "overridden", "gathered", "query", ""])
def test_only_merged_and_deleted_are_supported(state):
    with pytest.raises(ValueError, match="state must be merged or deleted"):
        expand_config([_group()], state)


@pytest.mark.parametrize("raw", [None, [], {}, "Ethernet1/50", [None], ["Ethernet1/50"]])
def test_config_requires_nonempty_list_of_groups(raw):
    with pytest.raises(ValueError):
        expand_config(raw, "merged")


@pytest.mark.parametrize("names", [None, [], "Ethernet1/50", {}, [None], [""], ["   "], [50]])
def test_interface_names_require_nonempty_list_of_parent_names(names):
    with pytest.raises(ValueError):
        expand_config([_group(interface_names=names)], "merged")


@pytest.mark.parametrize(
    "name",
    [
        "Ethernet1/50/1",
        "Ethernet1/50.100",
        "Ethernet1/50/1.100",
        "Ethernet101/1/1",
        "Ethernet0/1",
        "Ethernet1/0",
        "port-channel10",
        "Ethernet50",
        "Ethernet1/-1",
        "Ethernet1/50extra",
    ],
)
def test_merged_rejects_non_parent_children_dotted_and_three_part_names(name):
    with pytest.raises(ValueError):
        expand_config([_group(interface_names=[name])], "merged")


def test_parent_syntax_does_not_impose_a_hardware_slot_limit():
    assert expand_config([_group(interface_names=["Ethernet101/1"])], "merged")[0].interface_name == "Ethernet101/1"


@pytest.mark.parametrize("switch_id", [None, "", "  ", 123, False])
def test_switch_identifier_is_required_and_nonempty(switch_id):
    with pytest.raises(ValueError, match="switch_id"):
        expand_config([_group(switch_id=switch_id)], "merged")


@pytest.mark.parametrize("breakout_map", [None, "", "   ", 25, False])
def test_merged_requires_nonblank_string_map(breakout_map):
    with pytest.raises(ValueError, match="breakout_map"):
        expand_config([_group(breakout_map=breakout_map)], "merged")


@pytest.mark.parametrize("breakout_map", ["25g-4x", "", "   ", 25])
def test_deleted_rejects_a_supplied_map(breakout_map):
    with pytest.raises(ValueError, match="must be omitted"):
        expand_config([_group(breakout_map=breakout_map)], "deleted")


def test_duplicate_parent_within_group_is_case_insensitive():
    with pytest.raises(ValueError, match="specified more than once"):
        expand_config([_group(interface_names=["Ethernet1/50", "ethernet1/50"])], "merged")


def test_duplicate_parent_across_groups_is_case_insensitive():
    with pytest.raises(ValueError, match="specified more than once"):
        expand_config([_group(), _group(switch_id="fdo222425se", interface_names=["ethernet01/050"])], "merged")


def test_same_parent_on_different_switches_is_valid():
    assert len(expand_config([_group(), _group(switch_id="FDO222425SF")], "merged")) == 2


def test_input_unknown_options_are_rejected():
    with pytest.raises(ValueError, match="Unsupported"):
        expand_config([_group(deploy=True)], "merged")


def test_model_aliases_and_copy_do_not_invent_a_breakout_map():
    model = BreakoutInterfaceModel(switchId="FDO222425SE", interfaceName="ethernet1/50")
    assert model.interface_name == "Ethernet1/50"
    assert model.model_copy(deep=True).breakout_map is None
    assert model.to_payload() == {"switchId": "FDO222425SE", "interfaceName": "Ethernet1/50"}


def test_argument_spec_has_grouped_dual_identifier_contract_and_no_map_choices():
    spec = BreakoutInterfaceModel.get_argument_spec()
    assert spec["fabric_name"]["required"] is True
    assert spec["state"]["choices"] == ["merged", "deleted"]
    assert spec["config"]["options"]["switch_id"]["type"] == "str"
    assert "choices" not in spec["config"]["options"]["breakout_map"]
    assert spec["verify"]["options"]["enabled"]["default"] is False
