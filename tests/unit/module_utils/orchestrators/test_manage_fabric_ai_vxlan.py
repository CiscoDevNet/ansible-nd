# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for AI/ML fabric orchestrators."""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

from unittest.mock import MagicMock

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
