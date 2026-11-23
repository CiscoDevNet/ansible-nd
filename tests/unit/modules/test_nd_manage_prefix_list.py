from __future__ import annotations

import re

from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import validate_gathered_filters
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_prefix_list.manage_prefix_list import PrefixListModel
from ansible_collections.cisco.nd.plugins.modules import nd_manage_prefix_list

EXPECTED_RETURN_KEYS = (
    "changed",
    "output_level",
    "before",
    "after",
    "diff",
    "proposed",
    "logs",
    "msg",
)


def _normalize_gathered_config(config: dict) -> list[dict]:
    result = ArgumentSpecValidator(PrefixListModel.get_argument_spec()).validate(
        {
            "fabric_name": "fabric-1",
            "state": "gathered",
            "config": [config],
        }
    )
    assert result.error_messages == []

    return validate_gathered_filters(
        filters=result.validated_parameters["config"],
        normalize_filter=PrefixListModel.normalize_gathered_filter,
        supported_properties=PrefixListModel.gathered_filter_properties,
        supported_aliases=PrefixListModel.gathered_filter_aliases,
    )


def _return_entry(name: str) -> str:
    pattern = rf"^{name}:\n(?P<body>(?:  .+\n)+)"
    match = re.search(pattern, nd_manage_prefix_list.RETURN, re.MULTILINE)
    assert match is not None, f"{name!r} is missing from RETURN"
    return match.group("body")


def test_nd_manage_prefix_list_return_documents_state_machine_contract() -> None:
    for key in EXPECTED_RETURN_KEYS:
        body = _return_entry(key)
        assert "description:" in body
        assert "returned:" in body
        assert "type:" in body

    assert "elements: dict" in _return_entry("before")
    assert "elements: dict" in _return_entry("after")
    assert "elements: dict" in _return_entry("diff")
    assert "elements: dict" in _return_entry("proposed")
    assert "elements: str" in _return_entry("logs")


def test_gathered_parser_aliases_match_canonical_fields() -> None:
    canonical = _normalize_gathered_config(
        {
            "ip_version": "ipv4",
            "tenant_name": "TENANT1",
            "name": "LIST1",
        }
    )
    aliases = _normalize_gathered_config(
        {
            "ipVersion": "ipv4",
            "tenantName": "TENANT1",
            "name": "LIST1",
        }
    )

    expected = [
        {
            "ip_version": "ipv4",
            "tenant_name": "TENANT1",
            "name": "LIST1",
        }
    ]

    assert canonical == expected
    assert aliases == expected
