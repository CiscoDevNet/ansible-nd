from __future__ import annotations

from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import validate_gathered_filters
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_extended_community_list.manage_extended_community_list import ExtendedCommunityListModel
from ansible_collections.cisco.nd.plugins.modules import nd_manage_extended_community_list


def _normalize_gathered_config(config: dict) -> list[dict]:
    result = ArgumentSpecValidator(ExtendedCommunityListModel.get_argument_spec()).validate(
        {
            "fabric_name": "fabric-1",
            "state": "gathered",
            "config": [config],
        }
    )
    assert result.error_messages == []

    return validate_gathered_filters(
        filters=result.validated_parameters["config"],
        normalize_filter=ExtendedCommunityListModel.normalize_gathered_filter,
        supported_properties=ExtendedCommunityListModel.gathered_filter_properties,
        supported_aliases=ExtendedCommunityListModel.gathered_filter_aliases,
    )


def test_nd_manage_extended_community_list_documents_packed_route_target_normalization() -> None:
    """Verify module documentation describes the canonical route-target representation."""
    documentation = nd_manage_extended_community_list.DOCUMENTATION

    assert "Comma-separated route targets in one list item are accepted and normalized to separate values" in documentation


def test_nd_manage_extended_community_list_documents_standard_selector_requirement() -> None:
    """Verify module documentation describes the standard-entry selector requirement."""
    documentation = nd_manage_extended_community_list.DOCUMENTATION

    assert "Standard entries require at least one non-empty selector collection" in documentation


def test_gathered_parser_alias_matches_canonical_tenant_name() -> None:
    canonical = _normalize_gathered_config(
        {
            "tenant_name": "TENANT1",
            "name": "LIST1",
        }
    )
    alias = _normalize_gathered_config(
        {
            "tenantName": "TENANT1",
            "name": "LIST1",
        }
    )

    expected = [
        {
            "tenant_name": "TENANT1",
            "name": "LIST1",
        }
    ]

    assert canonical == expected
    assert alias == expected
