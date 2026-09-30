# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for Routed fabric orchestrators."""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_routed import (
    ManageAiRoutedFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_routed import (
    ManageRoutedFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


@pytest.mark.parametrize(
    "orchestrator_class,fabric_type,other_type",
    (
        (ManageRoutedFabricOrchestrator, "routed", "aimlRouted"),
        (ManageAiRoutedFabricOrchestrator, "aimlRouted", "routed"),
    ),
)
def test_manage_fabric_routed_00010(monkeypatch, orchestrator_class, fabric_type, other_type) -> None:
    """Verify each orchestrator returns only its exact Routed fabric family."""
    instance = orchestrator_class(rest_send=RestSend({"check_mode": False, "state": "merged"}))
    captured = {}

    def fake_request(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return {
            "fabrics": [
                {"name": "wanted", "management": {"type": fabric_type}},
                {"name": "other", "management": {"type": other_type}},
                {"name": "vxlan", "management": {"type": "vxlanEbgp"}},
            ]
        }

    monkeypatch.setattr(instance, "_request", fake_request)

    assert instance.query_all() == [{"name": "wanted", "management": {"type": fabric_type}}]
    assert captured["kwargs"]["not_found_ok"] is True


@pytest.mark.parametrize(
    "orchestrator_class,response",
    (
        (ManageRoutedFabricOrchestrator, {}),
        (ManageAiRoutedFabricOrchestrator, {"fabrics": None}),
    ),
)
def test_manage_fabric_routed_00020(monkeypatch, orchestrator_class, response) -> None:
    """Verify absent and null fabric collections normalize to an empty result."""
    instance = orchestrator_class(rest_send=RestSend({"check_mode": False, "state": "merged"}))
    monkeypatch.setattr(instance, "_request", lambda *args, **kwargs: response)

    assert instance.query_all() == []
