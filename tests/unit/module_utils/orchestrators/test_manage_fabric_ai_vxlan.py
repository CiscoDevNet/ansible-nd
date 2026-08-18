# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for AI/ML fabric orchestrators."""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

from urllib.parse import unquote

from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ebgp_vxlan import (
    ManageAiEbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ibgp_vxlan import (
    ManageAiIbgpVxlanFabricOrchestrator,
)


def test_manage_fabric_ai_vxlan_00010(monkeypatch) -> None:
    """
    # Summary

    Verify AI eBGP query_all uses the shared _request flow and filters AI fabrics.
    """
    instance = ManageAiEbgpVxlanFabricOrchestrator(rest_send=RestSend({"check_mode": False, "state": "merged"}))
    captured = {}

    def fake_request(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return {
            "fabrics": [
                {"name": "ai1", "management": {"type": "aimlVxlanEbgp"}},
                {"name": "std1", "management": {"type": "vxlanEbgp"}},
            ]
        }

    monkeypatch.setattr(instance, "_request", fake_request)

    result = instance.query_all()

    assert captured["kwargs"]["not_found_ok"] is True
    assert result == [{"name": "ai1", "management": {"type": "aimlVxlanEbgp"}}]


def test_manage_fabric_ai_vxlan_00020(monkeypatch) -> None:
    """
    # Summary

    Verify AI iBGP query_all uses the shared _request flow and filters AI fabrics.
    """
    instance = ManageAiIbgpVxlanFabricOrchestrator(rest_send=RestSend({"check_mode": False, "state": "merged"}))
    captured = {}

    def fake_request(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return {
            "fabrics": [
                {"name": "ai1", "management": {"type": "aimlVxlanIbgp"}},
                {"name": "std1", "management": {"type": "vxlanIbgp"}},
            ]
        }

    monkeypatch.setattr(instance, "_request", fake_request)

    result = instance.query_all()

    assert captured["kwargs"]["not_found_ok"] is True
    assert result == [{"name": "ai1", "management": {"type": "aimlVxlanIbgp"}}]


def test_manage_fabric_ai_vxlan_00030(monkeypatch) -> None:
    """
    # Summary

    Verify AI eBGP gathered filters use the exact endpoint for fabric_name-only
    filters and Lucene for other properties. Preserves OR semantics, rejects
    other fabric types, and deduplicates overlapping API results.
    """
    instance = ManageAiEbgpVxlanFabricOrchestrator(rest_send=RestSend({"check_mode": False, "state": "gathered"}))
    requested_paths = []
    expected_fabric = {"name": "ai1", "management": {"type": "aimlVxlanEbgp"}}

    def fake_request(*args, **kwargs):
        requested_paths.append(unquote(kwargs["path"]))
        # Exact endpoint returns a single fabric dict; list endpoint returns {"fabrics": [...]}
        if "/fabrics/ai1" in kwargs["path"]:
            return expected_fabric
        return {
            "fabrics": [
                expected_fabric,
                {"name": "standard1", "management": {"type": "vxlanEbgp"}},
            ]
        }

    monkeypatch.setattr(instance, "_request", fake_request)

    result = instance.query_all(
        gathered_filters=[
            {"fabric_name": "ai1"},
            {"license_tier": "premier"},
        ]
    )

    assert requested_paths == [
        "/api/v1/manage/fabrics/ai1",
        "/api/v1/manage/fabrics?filter=type:aimlVxlanEbgp AND licenseTier:premier&max=500&offset=0",
    ]
    assert result == [expected_fabric]


def test_manage_fabric_ai_vxlan_00040(monkeypatch) -> None:
    """
    # Summary

    Verify AI eBGP gathered filtering falls back to a type-only paginated
    query when the Lucene expression limit is exceeded.
    """
    instance = ManageAiEbgpVxlanFabricOrchestrator(rest_send=RestSend({"check_mode": False, "state": "gathered"}))
    requested_paths = []
    expected_fabric = {"name": "ai1", "management": {"type": "aimlVxlanEbgp"}}

    def fake_request(*args, **kwargs):
        requested_paths.append(unquote(kwargs["path"]))
        return {
            "fabrics": [expected_fabric],
        }

    monkeypatch.setattr(instance, "_request", fake_request)

    result = instance.query_all(
        gathered_filters=[
            {"license_tier": "premier"},
            {"license_tier": "advantage"},
            {"license_tier": "essentials"},
            {"license_tier": "addon"},
        ]
    )

    # Should fall back to type-only query, not an unfiltered query
    assert len(requested_paths) == 1
    assert "type:aimlVxlanEbgp" in requested_paths[0]
    assert result == [expected_fabric]


def test_manage_fabric_ai_vxlan_00050(monkeypatch) -> None:
    """
    # Summary

    Verify AI iBGP gathered filters use the exact endpoint for fabric_name-only
    filters and Lucene for other properties. Preserves OR semantics, rejects
    other fabric types, and deduplicates overlapping API results.
    """
    instance = ManageAiIbgpVxlanFabricOrchestrator(rest_send=RestSend({"check_mode": False, "state": "gathered"}))
    requested_paths = []
    expected_fabric = {"name": "ai1", "management": {"type": "aimlVxlanIbgp"}}

    def fake_request(*args, **kwargs):
        requested_paths.append(unquote(kwargs["path"]))
        if "/fabrics/ai1" in kwargs["path"]:
            return expected_fabric
        return {
            "fabrics": [
                expected_fabric,
                {"name": "standard1", "management": {"type": "vxlanIbgp"}},
            ]
        }

    monkeypatch.setattr(instance, "_request", fake_request)

    result = instance.query_all(
        gathered_filters=[
            {"fabric_name": "ai1"},
            {"license_tier": "premier"},
        ]
    )

    assert requested_paths == [
        "/api/v1/manage/fabrics/ai1",
        "/api/v1/manage/fabrics?filter=type:aimlVxlanIbgp AND licenseTier:premier&max=500&offset=0",
    ]
    assert result == [expected_fabric]


def test_manage_fabric_ai_vxlan_00060(monkeypatch) -> None:
    """
    # Summary

    Verify AI iBGP gathered filtering falls back to a type-only paginated
    query when the Lucene expression limit is exceeded.
    """
    instance = ManageAiIbgpVxlanFabricOrchestrator(rest_send=RestSend({"check_mode": False, "state": "gathered"}))
    requested_paths = []
    expected_fabric = {"name": "ai1", "management": {"type": "aimlVxlanIbgp"}}

    def fake_request(*args, **kwargs):
        requested_paths.append(unquote(kwargs["path"]))
        return {
            "fabrics": [expected_fabric],
        }

    monkeypatch.setattr(instance, "_request", fake_request)

    result = instance.query_all(
        gathered_filters=[
            {"license_tier": "premier"},
            {"license_tier": "advantage"},
            {"license_tier": "essentials"},
            {"license_tier": "addon"},
        ]
    )

    # Should fall back to type-only query, not an unfiltered query
    assert len(requested_paths) == 1
    assert "type:aimlVxlanIbgp" in requested_paths[0]
    assert result == [expected_fabric]
