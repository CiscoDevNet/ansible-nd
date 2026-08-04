# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Deeksha Pandey (@deekpand) <deekpand@cisco.com>


"""Unit tests for generic gathered-state local and Lucene filtering."""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import (
    GatheredLuceneSpec,
    build_lucene_expressions,
    filter_gathered_response,
    format_lucene_value,
    validate_gathered_filters,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import (
    LoopbackInterfaceModel,
)


def _response(
    switch_ip: str = "192.0.2.10",
    interface_name: str = "loopback101",
    admin_state: bool = True,
    description: str = "primary loopback",
) -> dict:
    return {
        "switchIp": switch_ip,
        "interfaceName": interface_name,
        "interfaceType": "loopback",
        "configData": {
            "mode": "managed",
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {
                    "adminState": admin_state,
                    "ip": "10.101.0.1/32",
                    "description": description,
                    "policyType": "loopback",
                },
            },
        },
    }


def _filter(responses, filters):
    return filter_gathered_response(
        response_data=responses,
        filters=filters,
        model_class=LoopbackInterfaceModel,
        normalize_filter=LoopbackInterfaceModel.normalize_gathered_filter,
    )


def _lucene_spec() -> GatheredLuceneSpec:
    return GatheredLuceneSpec(
        base_terms=(
            ("interfaceType", "loopback"),
            ("policyType", "loopback"),
        ),
        field_map={
            ("interface_name",): "interfaceName",
        },
    )


def test_lucene_without_filters_returns_base_expression():
    assert build_lucene_expressions([], _lucene_spec()) == ["interfaceType:loopback AND policyType:loopback"]


def test_lucene_supported_fields_are_combined_with_and():
    assert build_lucene_expressions(
        [{"interface_name": "loopback101"}],
        _lucene_spec(),
    ) == ["interfaceType:loopback AND policyType:loopback AND interfaceName:loopback101"]


def test_lucene_multiple_items_remain_separate_expressions():
    assert build_lucene_expressions(
        [
            {"interface_name": "loopback101"},
            {"interface_name": "loopback102"},
        ],
        _lucene_spec(),
    ) == [
        "interfaceType:loopback AND policyType:loopback AND interfaceName:loopback101",
        "interfaceType:loopback AND policyType:loopback AND interfaceName:loopback102",
    ]


def test_lucene_unmapped_fields_fall_back_to_base_and_deduplicate():
    assert build_lucene_expressions(
        [
            {"config_data": {"network_os": {"policy": {"description": "first"}}}},
            {"config_data": {"network_os": {"policy": {"description": "second"}}}},
        ],
        _lucene_spec(),
    ) == ["interfaceType:loopback AND policyType:loopback"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, "true"),
        (False, "false"),
        (0, "0"),
        ("loopback101", "loopback101"),
        ("nx-os", '"nx-os"'),
        ('contains "quotes"', '"contains \\"quotes\\""'),
    ],
)
def test_format_lucene_value(value, expected):
    assert format_lucene_value(value) == expected


def test_no_filters_returns_all_responses():
    responses = [_response(), _response(interface_name="loopback102")]

    assert _filter(responses, []) == responses


def test_one_filter_item_uses_and_semantics_and_normalizes_name():
    responses = [
        _response(),
        _response(switch_ip="192.0.2.11"),
        _response(interface_name="loopback102"),
    ]

    result = _filter(
        responses,
        [{"switch_ip": "192.0.2.10", "interface_name": "Loopback101"}],
    )

    assert result == [responses[0]]


def test_ansible_injected_null_values_do_not_become_criteria():
    responses = [_response(), _response(interface_name="loopback102")]

    result = _filter(
        responses,
        [{"switch_ip": None, "interface_name": "Loopback101"}],
    )

    assert result == [responses[0]]


def test_multiple_filter_items_use_or_semantics():
    responses = [
        _response(),
        _response(interface_name="loopback102"),
        _response(interface_name="loopback103"),
    ]

    result = _filter(
        responses,
        [{"interface_name": "loopback101"}, {"interface_name": "loopback102"}],
    )

    assert result == responses[:2]


def test_nested_false_value_is_an_active_filter():
    responses = [
        _response(admin_state=False),
        _response(interface_name="loopback102", admin_state=True),
    ]
    filters = [{"config_data": {"network_os": {"policy": {"admin_state": False}}}}]

    assert _filter(responses, filters) == [responses[0]]


def test_duplicate_identifiers_are_returned_once():
    response = _response()

    assert _filter([response, dict(response)], [{"interface_name": "loopback101"}]) == [response]


def test_nonmatching_filter_returns_empty_list():
    assert _filter([_response()], [{"interface_name": "loopback999"}]) == []


@pytest.mark.parametrize("filter_item", [{}, {"switch_ip": None}, {"interface_name": ""}])
def test_empty_filter_item_is_rejected(filter_item):
    with pytest.raises(ValueError, match="at least one filtering criterion"):
        _filter([_response()], [filter_item])


def test_validate_rejects_non_dict_filters_item():
    with pytest.raises(ValueError, match="must be a dictionary.*index 0"):
        validate_gathered_filters(
            filters=["not_a_dict"],
            normalize_filter=None,
            supported_properties=("switch_ip",),
        )


def test_validate_rejects_unsupported_properties():
    with pytest.raises(ValueError, match="unsupported properties.*'extra_field'"):
        validate_gathered_filters(
            filters=[{"extra_field": "value"}],
            normalize_filter=None,
            supported_properties=("switch_ip", "interface_name"),
        )


def test_validate_rejects_nested_unsupported_property():
    with pytest.raises(ValueError, match="unsupported properties.*'config_data.network_os.policy.extra_config'"):
        validate_gathered_filters(
            filters=[{"config_data": {"network_os": {"policy": {"extra_config": "value"}}}}],
            normalize_filter=None,
            supported_properties=LoopbackInterfaceModel.gathered_filter_properties,
        )


def test_validate_skips_property_check_when_supported_properties_empty():
    # Backward compatibility: empty tuple means no property restriction
    # Should only fail on active-value check if filter is empty, not on property check
    validate_gathered_filters(
        filters=[{"any_fields": "any_value"}],
        normalize_filter=None,
        supported_properties=(),
    )
