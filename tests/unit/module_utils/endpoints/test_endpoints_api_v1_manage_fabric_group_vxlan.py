# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabric_group_vxlan endpoint usage and orchestrator wiring.

Tests that the ManageFabricGroupVxlanOrchestrator is correctly wired to the
shared EpManageFabrics* endpoints and that the custom query_all filtering
correctly selects only VXLAN fabric group resources.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest
from unittest.mock import MagicMock

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import (
    EpManageFabricsDelete,
    EpManageFabricsGet,
    EpManageFabricsListGet,
    EpManageFabricsPost,
    EpManageFabricsPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_group_vxlan import (
    ManageFabricGroupVxlanOrchestrator,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: Orchestrator Endpoint Wiring
# =============================================================================


def test_manage_fabric_group_vxlan_endpoints_00010():
    """
    # Summary

    Verify orchestrator is wired to the correct endpoint classes.

    ## Test

    - create_endpoint is EpManageFabricsPost
    - update_endpoint is EpManageFabricsPut
    - delete_endpoint is EpManageFabricsDelete
    - query_one_endpoint is EpManageFabricsGet
    - query_all_endpoint is EpManageFabricsListGet
    """
    mock_sender = MagicMock(spec=NDModule)
    with does_not_raise():
        orch = ManageFabricGroupVxlanOrchestrator(sender=mock_sender)
    assert orch.create_endpoint is EpManageFabricsPost
    assert orch.update_endpoint is EpManageFabricsPut
    assert orch.delete_endpoint is EpManageFabricsDelete
    assert orch.query_one_endpoint is EpManageFabricsGet
    assert orch.query_all_endpoint is EpManageFabricsListGet


def test_manage_fabric_group_vxlan_endpoints_00020():
    """
    # Summary

    Verify create endpoint produces correct path and verb for fabric groups.

    ## Test

    - EpManageFabricsPost path is /api/v1/manage/fabrics
    - verb is POST
    """
    with does_not_raise():
        ep = EpManageFabricsPost()
    assert ep.path == "/api/v1/manage/fabrics"
    assert ep.verb == HttpVerbEnum.POST


def test_manage_fabric_group_vxlan_endpoints_00030():
    """
    # Summary

    Verify query_one endpoint produces correct path for a fabric group name.

    ## Test

    - EpManageFabricsGet with fabric_name "my-fg" returns /api/v1/manage/fabrics/my-fg
    - verb is GET
    """
    with does_not_raise():
        ep = EpManageFabricsGet()
        ep.fabric_name = "my-fg"
    assert ep.path == "/api/v1/manage/fabrics/my-fg"
    assert ep.verb == HttpVerbEnum.GET


def test_manage_fabric_group_vxlan_endpoints_00040():
    """
    # Summary

    Verify update endpoint produces correct path for a fabric group name.

    ## Test

    - EpManageFabricsPut with fabric_name "my-fg" returns /api/v1/manage/fabrics/my-fg
    - verb is PUT
    """
    with does_not_raise():
        ep = EpManageFabricsPut()
        ep.fabric_name = "my-fg"
    assert ep.path == "/api/v1/manage/fabrics/my-fg"
    assert ep.verb == HttpVerbEnum.PUT


def test_manage_fabric_group_vxlan_endpoints_00050():
    """
    # Summary

    Verify delete endpoint produces correct path for a fabric group name.

    ## Test

    - EpManageFabricsDelete with fabric_name "my-fg" returns /api/v1/manage/fabrics/my-fg
    - verb is DELETE
    """
    with does_not_raise():
        ep = EpManageFabricsDelete()
        ep.fabric_name = "my-fg"
    assert ep.path == "/api/v1/manage/fabrics/my-fg"
    assert ep.verb == HttpVerbEnum.DELETE


def test_manage_fabric_group_vxlan_endpoints_00060():
    """
    # Summary

    Verify query_all endpoint produces correct path (list all fabrics).

    ## Test

    - EpManageFabricsListGet path is /api/v1/manage/fabrics
    - verb is GET
    """
    with does_not_raise():
        ep = EpManageFabricsListGet()
    assert ep.path == "/api/v1/manage/fabrics"
    assert ep.verb == HttpVerbEnum.GET


# =============================================================================
# Test: Orchestrator query_all Filtering
# =============================================================================


def test_manage_fabric_group_vxlan_endpoints_00100():
    """
    # Summary

    Verify query_all returns only VXLAN fabric groups from mixed results.

    ## Test

    - API returns fabrics of mixed types (fabricGroup/vxlan, fabric/vxlanIbgp, fabricGroup/other)
    - query_all filters to only category=fabricGroup AND management.type=vxlan
    """
    mock_sender = MagicMock(spec=NDModule)
    mock_sender.query_obj.return_value = {
        "fabrics": [
            {"name": "fg1", "category": "fabricGroup", "management": {"type": "vxlan"}},
            {"name": "f1", "category": "fabric", "management": {"type": "vxlanIbgp"}},
            {"name": "fg2", "category": "fabricGroup", "management": {"type": "vxlan"}},
            {"name": "fg3", "category": "fabricGroup", "management": {"type": "other"}},
            {"name": "f2", "category": "fabric", "management": {"type": "vxlanEbgp"}},
        ]
    }
    orch = ManageFabricGroupVxlanOrchestrator(sender=mock_sender)
    result = orch.query_all()
    assert len(result) == 2
    assert result[0]["name"] == "fg1"
    assert result[1]["name"] == "fg2"


def test_manage_fabric_group_vxlan_endpoints_00110():
    """
    # Summary

    Verify query_all returns empty list when no VXLAN fabric groups exist.

    ## Test

    - API returns fabrics but none are fabricGroup/vxlan
    - query_all returns empty list
    """
    mock_sender = MagicMock(spec=NDModule)
    mock_sender.query_obj.return_value = {
        "fabrics": [
            {"name": "f1", "category": "fabric", "management": {"type": "vxlanIbgp"}},
            {"name": "f2", "category": "fabric", "management": {"type": "vxlanEbgp"}},
        ]
    }
    orch = ManageFabricGroupVxlanOrchestrator(sender=mock_sender)
    result = orch.query_all()
    assert result == []


def test_manage_fabric_group_vxlan_endpoints_00120():
    """
    # Summary

    Verify query_all returns empty list when API returns empty fabrics list.

    ## Test

    - API returns {"fabrics": []}
    - query_all returns empty list
    """
    mock_sender = MagicMock(spec=NDModule)
    mock_sender.query_obj.return_value = {"fabrics": []}
    orch = ManageFabricGroupVxlanOrchestrator(sender=mock_sender)
    result = orch.query_all()
    assert result == []


def test_manage_fabric_group_vxlan_endpoints_00130():
    """
    # Summary

    Verify query_all handles missing 'fabrics' key gracefully.

    ## Test

    - API returns {} (no fabrics key)
    - query_all returns empty list
    """
    mock_sender = MagicMock(spec=NDModule)
    mock_sender.query_obj.return_value = {}
    orch = ManageFabricGroupVxlanOrchestrator(sender=mock_sender)
    result = orch.query_all()
    assert result == []


def test_manage_fabric_group_vxlan_endpoints_00140():
    """
    # Summary

    Verify query_all handles None fabrics value gracefully.

    ## Test

    - API returns {"fabrics": None}
    - query_all returns empty list
    """
    mock_sender = MagicMock(spec=NDModule)
    mock_sender.query_obj.return_value = {"fabrics": None}
    orch = ManageFabricGroupVxlanOrchestrator(sender=mock_sender)
    result = orch.query_all()
    assert result == []


def test_manage_fabric_group_vxlan_endpoints_00150():
    """
    # Summary

    Verify query_all excludes fabrics with missing management key.

    ## Test

    - API returns a fabric with category=fabricGroup but no management key
    - That fabric is excluded from results
    """
    mock_sender = MagicMock(spec=NDModule)
    mock_sender.query_obj.return_value = {
        "fabrics": [
            {"name": "fg-no-mgmt", "category": "fabricGroup"},
            {"name": "fg-ok", "category": "fabricGroup", "management": {"type": "vxlan"}},
        ]
    }
    orch = ManageFabricGroupVxlanOrchestrator(sender=mock_sender)
    result = orch.query_all()
    assert len(result) == 1
    assert result[0]["name"] == "fg-ok"


def test_manage_fabric_group_vxlan_endpoints_00160():
    """
    # Summary

    Verify query_all raises exception when sender raises an error.

    ## Test

    - sender.query_obj raises an exception
    - query_all wraps and re-raises it
    """
    mock_sender = MagicMock(spec=NDModule)
    mock_sender.query_obj.side_effect = ConnectionError("API unreachable")
    orch = ManageFabricGroupVxlanOrchestrator(sender=mock_sender)
    with pytest.raises(Exception, match="Query all failed"):
        orch.query_all()


def test_manage_fabric_group_vxlan_endpoints_00170():
    """
    # Summary

    Verify query_all calls sender.query_obj with the correct path.

    ## Test

    - query_all invokes sender.query_obj with /api/v1/manage/fabrics?category=fabricGroup
    """
    mock_sender = MagicMock(spec=NDModule)
    mock_sender.query_obj.return_value = {"fabrics": []}
    orch = ManageFabricGroupVxlanOrchestrator(sender=mock_sender)
    orch.query_all()
    mock_sender.query_obj.assert_called_once_with("/api/v1/manage/fabrics?category=fabricGroup")
