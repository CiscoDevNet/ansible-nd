# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for the Campus iBGP VXLAN fabric orchestrator."""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import (
    EpManageFabricsDelete,
    EpManageFabricsGet,
    EpManageFabricsListGet,
    EpManageFabricsPost,
    EpManageFabricsPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_campus_ibgp_vxlan import (
    FabricCampusIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions.mixin import (
    ConfigActionsMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_campus_ibgp_vxlan import (
    ManageCampusIbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


def _orchestrator() -> ManageCampusIbgpVxlanFabricOrchestrator:
    return ManageCampusIbgpVxlanFabricOrchestrator(rest_send=RestSend({"check_mode": False, "state": "merged"}))


def test_manage_fabric_campus_ibgp_vxlan_orchestrator_00010() -> None:
    """The Campus orchestrator exposes the established fabric model and endpoints."""
    instance = _orchestrator()

    assert ManageCampusIbgpVxlanFabricOrchestrator.model_class is FabricCampusIbgpVxlanModel
    assert "model_class" not in ManageCampusIbgpVxlanFabricOrchestrator.model_fields
    assert isinstance(instance, ConfigActionsMixin)
    assert instance.create_endpoint is EpManageFabricsPost
    assert instance.update_endpoint is EpManageFabricsPut
    assert instance.delete_endpoint is EpManageFabricsDelete
    assert instance.query_one_endpoint is EpManageFabricsGet
    assert instance.query_all_endpoint is EpManageFabricsListGet


def test_manage_fabric_campus_ibgp_vxlan_orchestrator_00020(monkeypatch) -> None:
    """query_all uses the shared endpoint and returns only vxlanCampus fabrics."""
    instance = _orchestrator()
    captured = {}

    def fake_request(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return {
            "fabrics": [
                {"name": "campus1", "management": {"type": "vxlanCampus"}},
                {"name": "ibgp1", "management": {"type": "vxlanIbgp"}},
                {"name": "external1", "management": {"type": "externalConnectivity"}},
                {"name": "missing-management"},
            ]
        }

    monkeypatch.setattr(instance, "_request", fake_request)

    result = instance.query_all()

    endpoint = EpManageFabricsListGet()
    assert captured["args"] == ()
    assert captured["kwargs"] == {
        "path": endpoint.path,
        "verb": endpoint.verb,
        "not_found_ok": True,
    }
    assert result == [{"name": "campus1", "management": {"type": "vxlanCampus"}}]


@pytest.mark.parametrize("response", ({}, {"fabrics": None}, {"fabrics": []}))
def test_manage_fabric_campus_ibgp_vxlan_orchestrator_00030(monkeypatch, response: dict) -> None:
    """query_all normalizes absent, null, and empty fabric lists to an empty list."""
    instance = _orchestrator()
    monkeypatch.setattr(instance, "_request", lambda **kwargs: response)

    assert instance.query_all() == []


def test_manage_fabric_campus_ibgp_vxlan_orchestrator_00040(monkeypatch) -> None:
    """query_all adds Campus context when the shared request fails."""
    instance = _orchestrator()

    def fail_request(**kwargs):
        raise RuntimeError("controller unavailable")

    monkeypatch.setattr(instance, "_request", fail_request)

    with pytest.raises(Exception, match="Query all failed: controller unavailable"):
        instance.query_all()
