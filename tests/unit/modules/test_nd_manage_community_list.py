from __future__ import annotations

from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import validate_gathered_filters
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_community_list.manage_community_list import CommunityListModel
from ansible_collections.cisco.nd.plugins.modules import nd_manage_community_list


def _normalize_gathered_config(config: dict) -> list[dict]:
    result = ArgumentSpecValidator(CommunityListModel.get_argument_spec()).validate(
        {
            "fabric_name": "fabric-1",
            "state": "gathered",
            "config": [config],
        }
    )
    assert result.error_messages == []

    return validate_gathered_filters(
        filters=result.validated_parameters["config"],
        normalize_filter=CommunityListModel.normalize_gathered_filter,
        supported_properties=CommunityListModel.gathered_filter_properties,
        supported_aliases=CommunityListModel.gathered_filter_aliases,
    )


def test_nd_manage_community_list_documents_standard_entry_match_requirement() -> None:
    """Verify module documentation does not advertise controller-rejected match-all entries."""
    documentation = nd_manage_community_list.DOCUMENTATION

    assert "must set at least one explicit community number or enable at least one well-known community flag" in documentation
    assert "valid (match all communities)" not in documentation


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
