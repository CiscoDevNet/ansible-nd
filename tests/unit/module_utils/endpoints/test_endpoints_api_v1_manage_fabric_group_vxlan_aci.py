# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabric_group_vxlan_aci endpoint usage and orchestrator wiring.

Tests that the ManageFabricGroupVxlanAciOrchestrator is correctly wired to the
shared EpManageFabrics* endpoints, that the custom query_all filtering (via the
shared _request flow) selects only VXLAN-to-ACI fabric group resources, and that
the model exposes the expected argument spec.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import (
    EpManageFabricsDelete,
    EpManageFabricsGet,
    EpManageFabricsListGet,
    EpManageFabricsPost,
    EpManageFabricsPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_group_vxlan_aci import (
    ManageFabricGroupVxlanAciOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_vxlan_aci import (
    FabricGroupVxlanAciModel,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)


def _orchestrator() -> ManageFabricGroupVxlanAciOrchestrator:
    return ManageFabricGroupVxlanAciOrchestrator(rest_send=RestSend({"check_mode": False, "state": "merged"}))


def _management_options() -> dict:
    spec = FabricGroupVxlanAciModel.get_argument_spec()
    return spec["config"]["options"]["management"]["options"]


# =============================================================================
# Test: Orchestrator Endpoint Wiring
# =============================================================================


def test_manage_fabric_group_vxlan_aci_endpoints_00010():
    """Verify orchestrator is wired to the correct endpoint classes."""
    with does_not_raise():
        orch = _orchestrator()
        assert orch.create_endpoint is EpManageFabricsPost
        assert orch.update_endpoint is EpManageFabricsPut
        assert orch.delete_endpoint is EpManageFabricsDelete
        assert orch.query_one_endpoint is EpManageFabricsGet
        assert orch.query_all_endpoint is EpManageFabricsListGet


def test_manage_fabric_group_vxlan_aci_endpoints_00020():
    """Verify create endpoint produces correct path and verb for fabric groups."""
    with does_not_raise():
        ep = EpManageFabricsPost()
        assert ep.path == "/api/v1/manage/fabrics"
        assert ep.verb == HttpVerbEnum.POST


def test_manage_fabric_group_vxlan_aci_endpoints_00030():
    """Verify query_one endpoint produces correct path for a fabric group name."""
    with does_not_raise():
        ep = EpManageFabricsGet()
        ep.fabric_name = "my-fg"
        assert ep.path == "/api/v1/manage/fabrics/my-fg"
        assert ep.verb == HttpVerbEnum.GET


def test_manage_fabric_group_vxlan_aci_endpoints_00040():
    """Verify update endpoint produces correct path for a fabric group name."""
    with does_not_raise():
        ep = EpManageFabricsPut()
        ep.fabric_name = "my-fg"
        assert ep.path == "/api/v1/manage/fabrics/my-fg"
        assert ep.verb == HttpVerbEnum.PUT


def test_manage_fabric_group_vxlan_aci_endpoints_00050():
    """Verify delete endpoint produces correct path for a fabric group name."""
    with does_not_raise():
        ep = EpManageFabricsDelete()
        ep.fabric_name = "my-fg"
        assert ep.path == "/api/v1/manage/fabrics/my-fg"
        assert ep.verb == HttpVerbEnum.DELETE


def test_manage_fabric_group_vxlan_aci_endpoints_00060():
    """Verify query_all endpoint produces correct path (list all fabrics)."""
    with does_not_raise():
        ep = EpManageFabricsListGet()
        assert ep.path == "/api/v1/manage/fabrics"
        assert ep.verb == HttpVerbEnum.GET


# =============================================================================
# Test: Orchestrator query_all Filtering (shared _request flow)
# =============================================================================


def test_manage_fabric_group_vxlan_aci_endpoints_00100(monkeypatch):
    """Verify query_all returns only VXLAN-to-ACI fabric groups from mixed results."""
    orch = _orchestrator()

    def fake_request(*args, **kwargs):
        return {
            "fabrics": [
                {"name": "fg1", "category": "fabricGroup", "management": {"type": "vxlanAci"}},
                {"name": "fg2", "category": "fabricGroup", "management": {"type": "vxlan"}},
                {"name": "fg3", "category": "fabricGroup", "management": {"type": "vxlanAci"}},
                {"name": "fg4", "category": "fabricGroup", "management": {"type": "classic"}},
                {"name": "f1", "category": "fabric", "management": {"type": "vxlanEbgp"}},
            ]
        }

    monkeypatch.setattr(orch, "_request", fake_request)
    result = orch.query_all()
    assert len(result) == 2
    assert result[0]["name"] == "fg1"
    assert result[1]["name"] == "fg3"


def test_manage_fabric_group_vxlan_aci_endpoints_00110(monkeypatch):
    """Verify query_all returns empty list when no VXLAN-to-ACI fabric groups exist."""
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


def test_manage_fabric_group_vxlan_aci_endpoints_00120(monkeypatch):
    """Verify query_all returns empty list when API returns empty fabrics list."""
    orch = _orchestrator()
    monkeypatch.setattr(orch, "_request", lambda *a, **k: {"fabrics": []})
    assert orch.query_all() == []


def test_manage_fabric_group_vxlan_aci_endpoints_00130(monkeypatch):
    """Verify query_all handles missing 'fabrics' key gracefully."""
    orch = _orchestrator()
    monkeypatch.setattr(orch, "_request", lambda *a, **k: {})
    assert orch.query_all() == []


def test_manage_fabric_group_vxlan_aci_endpoints_00140(monkeypatch):
    """Verify query_all handles None fabrics value gracefully."""
    orch = _orchestrator()
    monkeypatch.setattr(orch, "_request", lambda *a, **k: {"fabrics": None})
    assert orch.query_all() == []


def test_manage_fabric_group_vxlan_aci_endpoints_00150(monkeypatch):
    """Verify query_all excludes fabrics with missing management key."""
    orch = _orchestrator()
    monkeypatch.setattr(
        orch,
        "_request",
        lambda *a, **k: {
            "fabrics": [
                {"name": "fg-no-mgmt", "category": "fabricGroup"},
                {"name": "fg-ok", "category": "fabricGroup", "management": {"type": "vxlanAci"}},
            ]
        },
    )
    result = orch.query_all()
    assert len(result) == 1
    assert result[0]["name"] == "fg-ok"


def test_manage_fabric_group_vxlan_aci_endpoints_00160(monkeypatch):
    """Verify query_all wraps and re-raises errors from the request flow."""
    orch = _orchestrator()

    def boom(*args, **kwargs):
        raise ConnectionError("API unreachable")

    monkeypatch.setattr(orch, "_request", boom)
    with pytest.raises(Exception, match="Query all failed"):
        orch.query_all()


def test_manage_fabric_group_vxlan_aci_endpoints_00170(monkeypatch):
    """Verify query_all requests the fabricGroup-filtered path via the shared flow."""
    orch = _orchestrator()
    captured = {}

    def fake_request(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return {"fabrics": []}

    monkeypatch.setattr(orch, "_request", fake_request)
    orch.query_all()
    assert captured["kwargs"].get("not_found_ok") is True
    assert captured["kwargs"]["path"] == "/api/v1/manage/fabrics?category=fabricGroup"


# =============================================================================
# Test: Model / Argument Spec
# =============================================================================


def test_manage_fabric_group_vxlan_aci_model_00200():
    """Verify the model sets the vxlanAci discriminator and propagates the name."""
    with does_not_raise():
        model = FabricGroupVxlanAciModel(fabric_name="fg1")
        assert model.category == "fabricGroup"
        assert model.management.type == "vxlanAci"
        assert model.management.name == "fg1"


def test_manage_fabric_group_vxlan_aci_model_00210():
    """Verify read-only securityGroupStatus is excluded from the argument spec."""
    options = _management_options()
    assert "security_group_status" not in options
    assert "type" not in options  # single-value Literal discriminator excluded


def test_manage_fabric_group_vxlan_aci_model_00220():
    """Verify constrained choices match the VXLAN-to-ACI schema (no routeServer/off)."""
    options = _management_options()
    assert options["multisite_overlay_inter_connect_type"]["choices"] == ["manual", "directPeering"]
    assert options["security_group_tag"]["choices"] == ["loose", "strict"]


def test_manage_fabric_group_vxlan_aci_model_00230():
    """Verify securityGroupStatus is excluded from diff comparison."""
    with does_not_raise():
        model = FabricGroupVxlanAciModel(fabric_name="fg1", management={"securityGroupStatus": "enabled"})
        diff = model.to_diff_dict()
        assert "securityGroupStatus" not in diff.get("management", {})
