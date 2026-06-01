# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from ansible_collections.cisco.nd.plugins.module_utils.common.data import (
    coerce_dict_list,
    copy_dict_items,
    get_params,
    parse_value,
    try_int,
)


class _ModuleLike:
    def __init__(self, params: dict[str, object]) -> None:
        self.params = params


class _ModelLike:
    def model_dump(self, by_alias: bool = False, exclude_none: bool = False) -> dict[str, bool]:
        return {
            "by_alias": by_alias,
            "exclude_none": exclude_none,
        }


def test_common_data_get_params_accepts_dict_and_module_like_object():
    params = {"state": "merged"}

    assert get_params(params) is params
    assert get_params(_ModuleLike(params)) is params
    assert get_params(object()) == {}


class _BrokenStr:
    def __str__(self) -> str:
        raise RuntimeError("cannot stringify")


def test_common_data_parse_value_supports_json_and_python_literal_strings():
    assert parse_value('{"DATA": [{"name": "BLUE"}]}') == {"DATA": [{"name": "BLUE"}]}
    assert parse_value("{'DATA': [{'name': 'BLUE'}]}") == {"DATA": [{"name": "BLUE"}]}
    assert parse_value({"already": "parsed"}) == {"already": "parsed"}
    assert parse_value("") is None
    assert parse_value("", default="") == ""
    assert parse_value("not-json") is None
    assert parse_value(_BrokenStr()) is None


def test_common_data_coerce_dict_list_handles_controller_response_shapes():
    assert coerce_dict_list([{"a": 1}, "skip", {"b": 2}]) == [{"a": 1}, {"b": 2}]
    assert coerce_dict_list({"DATA": [{"a": 1}, 2]}) == [{"a": 1}]
    assert coerce_dict_list({"vrfs": [{"name": "BLUE"}]}, list_keys=("vrfs", "DATA")) == [{"name": "BLUE"}]
    assert coerce_dict_list({"DATA": {"not": "a list"}}) == []


def test_common_data_copy_dict_items_copies_dicts_and_model_dump_items():
    source = [{"interface": "Ethernet1/1"}, _ModelLike(), object()]

    copied = copy_dict_items(source)

    assert copied == [
        {"interface": "Ethernet1/1"},
        {"by_alias": False, "exclude_none": True},
    ]
    assert copied[0] is not source[0]


def test_common_data_try_int_returns_none_for_invalid_values():
    assert try_int("42") == 42
    assert try_int(7) == 7
    assert try_int(None) is None
    assert try_int("not-int") is None
