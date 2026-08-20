from __future__ import annotations

from ansible_collections.cisco.nd.plugins.modules import nd_manage_extended_community_list


def test_nd_manage_extended_community_list_documents_packed_route_target_normalization() -> None:
    """Verify module documentation describes the canonical route-target representation."""
    documentation = nd_manage_extended_community_list.DOCUMENTATION

    assert "Comma-separated route targets in one list item are accepted and normalized to separate values" in documentation


def test_nd_manage_extended_community_list_documents_standard_selector_requirement() -> None:
    """Verify module documentation describes the standard-entry selector requirement."""
    documentation = nd_manage_extended_community_list.DOCUMENTATION

    assert "Standard entries require at least one non-empty selector collection" in documentation
