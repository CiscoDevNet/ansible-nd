# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_multi_cluster_fabric_group_vxlan endpoint usage and
orchestrator wiring.

Tests that the ManageMultiClusterFabricGroupVxlanOrchestrator is correctly wired
to the OneManage EpOneManageFabrics* endpoints and that the custom query_all
filtering (via the shared _request flow) selects only multi-cluster fabric group
resources.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics import (
    EpOneManageFabricsConfigSavePost,
    EpOneManageFabricsDelete,
    EpOneManageFabricsDeployPost,
    EpOneManageFabricsFabricNameGet,
    EpOneManageFabricsListGet,
    EpOneManageFabricsPost,
    EpOneManageFabricsPut,
    EpOneManageFabricsSwitchActionsDeployPost,
    EpOneManageFabricsSwitchesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_multi_cluster_fabric_group_vxlan import (
    ManageMultiClusterFabricGroupVxlanOrchestrator,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)


def _orchestrator() -> ManageMultiClusterFabricGroupVxlanOrchestrator:
    return ManageMultiClusterFabricGroupVxlanOrchestrator(rest_send=RestSend({"check_mode": False, "state": "merged"}))


# =============================================================================
# Test: Orchestrator Endpoint Wiring
# =============================================================================


def test_manage_mcfg_vxlan_endpoints_00010():
    """Verify orchestrator is wired to the OneManage endpoint classes."""
    with does_not_raise():
        orch = _orchestrator()
    assert orch.create_endpoint is EpOneManageFabricsPost
    assert orch.update_endpoint is EpOneManageFabricsPut
    assert orch.delete_endpoint is EpOneManageFabricsDelete
    assert orch.query_one_endpoint is EpOneManageFabricsFabricNameGet
    assert orch.query_all_endpoint is EpOneManageFabricsListGet


def test_manage_mcfg_vxlan_endpoints_00020():
    """Verify create endpoint produces correct OneManage collection path and verb."""
    with does_not_raise():
        ep = EpOneManageFabricsPost()
    assert ep.path == "/api/v1/oneManage/manage/fabrics"
    assert ep.verb == HttpVerbEnum.POST


def test_manage_mcfg_vxlan_endpoints_00030():
    """Verify query_one endpoint produces correct path for a fabric group name."""
    with does_not_raise():
        ep = EpOneManageFabricsFabricNameGet()
        ep.fabric_name = "my-mcfg"
    assert ep.path == "/api/v1/oneManage/manage/fabrics/my-mcfg"
    assert ep.verb == HttpVerbEnum.GET


def test_manage_mcfg_vxlan_endpoints_00040():
    """Verify update endpoint produces correct path for a fabric group name."""
    with does_not_raise():
        ep = EpOneManageFabricsPut()
        ep.fabric_name = "my-mcfg"
    assert ep.path == "/api/v1/oneManage/manage/fabrics/my-mcfg"
    assert ep.verb == HttpVerbEnum.PUT


def test_manage_mcfg_vxlan_endpoints_00050():
    """Verify delete endpoint produces correct path for a fabric group name."""
    with does_not_raise():
        ep = EpOneManageFabricsDelete()
        ep.fabric_name = "my-mcfg"
    assert ep.path == "/api/v1/oneManage/manage/fabrics/my-mcfg"
    assert ep.verb == HttpVerbEnum.DELETE


def test_manage_mcfg_vxlan_endpoints_00060():
    """Verify query_all list endpoint produces correct path (no filter)."""
    with does_not_raise():
        ep = EpOneManageFabricsListGet()
    assert ep.path == "/api/v1/oneManage/manage/fabrics"
    assert ep.verb == HttpVerbEnum.GET


def test_manage_mcfg_vxlan_endpoints_00070():
    """Verify query_all list endpoint applies the category filter."""
    with does_not_raise():
        ep = EpOneManageFabricsListGet()
        ep.category = "multiClusterFabricGroup"
    assert ep.path == "/api/v1/oneManage/manage/fabrics?category=multiClusterFabricGroup"


def test_manage_mcfg_vxlan_endpoints_00080():
    """Verify set_identifiers on the item base sets fabric_name for CRUD wiring."""
    with does_not_raise():
        ep = EpOneManageFabricsPut()
        ep.set_identifiers("my-mcfg")
    assert ep.fabric_name == "my-mcfg"
    assert ep.path == "/api/v1/oneManage/manage/fabrics/my-mcfg"


# =============================================================================
# Test: config_actions hook overrides target the OneManage surface
# =============================================================================


def test_manage_mcfg_vxlan_endpoints_00090():
    """Verify config-action hooks return the OneManage endpoint variants."""
    orch = _orchestrator()
    assert isinstance(orch._config_save_endpoint("my-mcfg"), EpOneManageFabricsConfigSavePost)
    assert isinstance(orch._deploy_global_endpoint("my-mcfg"), EpOneManageFabricsDeployPost)
    assert isinstance(orch._switches_endpoint("my-mcfg"), EpOneManageFabricsSwitchesGet)
    assert isinstance(orch._switch_deploy_endpoint("my-mcfg"), EpOneManageFabricsSwitchActionsDeployPost)


# =============================================================================
# Test: Orchestrator query_all Filtering (shared _request flow)
# =============================================================================


def test_manage_mcfg_vxlan_endpoints_00100(monkeypatch):
    """Verify query_all returns only multi-cluster fabric groups from mixed results."""
    orch = _orchestrator()

    def fake_request(*args, **kwargs):
        return {
            "fabrics": [
                {"name": "mcfg1", "category": "multiClusterFabricGroup", "management": {"type": "vxlan"}},
                {"name": "fg1", "category": "fabricGroup", "management": {"type": "vxlan"}},
                {"name": "mcfg2", "category": "multiClusterFabricGroup", "management": {"type": "vxlan"}},
                {"name": "f1", "category": "fabric", "management": {"type": "vxlanEbgp"}},
            ]
        }

    monkeypatch.setattr(orch, "_request", fake_request)
    result = orch.query_all()
    assert len(result) == 2
    assert result[0]["name"] == "mcfg1"
    assert result[1]["name"] == "mcfg2"


def test_manage_mcfg_vxlan_endpoints_00110(monkeypatch):
    """Verify query_all returns empty list when no multi-cluster fabric groups exist."""
    orch = _orchestrator()
    monkeypatch.setattr(
        orch,
        "_request",
        lambda *a, **k: {
            "fabrics": [
                {"name": "fg1", "category": "fabricGroup", "management": {"type": "vxlan"}},
                {"name": "f1", "category": "fabric", "management": {"type": "vxlanEbgp"}},
            ]
        },
    )
    assert orch.query_all() == []


def test_manage_mcfg_vxlan_endpoints_00120(monkeypatch):
    """Verify query_all returns empty list when API returns empty fabrics list."""
    orch = _orchestrator()
    monkeypatch.setattr(orch, "_request", lambda *a, **k: {"fabrics": []})
    assert orch.query_all() == []


def test_manage_mcfg_vxlan_endpoints_00130(monkeypatch):
    """Verify query_all handles missing 'fabrics' key gracefully."""
    orch = _orchestrator()
    monkeypatch.setattr(orch, "_request", lambda *a, **k: {})
    assert orch.query_all() == []


def test_manage_mcfg_vxlan_endpoints_00140(monkeypatch):
    """Verify query_all handles None fabrics value gracefully."""
    orch = _orchestrator()
    monkeypatch.setattr(orch, "_request", lambda *a, **k: {"fabrics": None})
    assert orch.query_all() == []


def test_manage_mcfg_vxlan_endpoints_00160(monkeypatch):
    """Verify query_all wraps and re-raises errors from the request flow."""
    orch = _orchestrator()

    def boom(*args, **kwargs):
        raise ConnectionError("API unreachable")

    monkeypatch.setattr(orch, "_request", boom)
    with pytest.raises(Exception, match="Query all failed"):
        orch.query_all()


def test_manage_mcfg_vxlan_endpoints_00170(monkeypatch):
    """Verify query_all requests the multiClusterFabricGroup-filtered path via the shared flow."""
    orch = _orchestrator()
    captured = {}

    def fake_request(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return {"fabrics": []}

    monkeypatch.setattr(orch, "_request", fake_request)
    orch.query_all()
    assert captured["kwargs"].get("not_found_ok") is True
    assert captured["kwargs"]["path"] == "/api/v1/oneManage/manage/fabrics?category=multiClusterFabricGroup"
