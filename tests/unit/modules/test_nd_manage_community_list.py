from __future__ import annotations

from ansible_collections.cisco.nd.plugins.modules import nd_manage_community_list


def test_nd_manage_community_list_documents_standard_entry_match_requirement() -> None:
    """Verify module documentation does not advertise controller-rejected match-all entries."""
    documentation = nd_manage_community_list.DOCUMENTATION

    assert "must set at least one explicit community number or enable at least one well-known community flag" in documentation
    assert "valid (match all communities)" not in documentation
