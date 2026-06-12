# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for ND Manage VRF endpoint classes."""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrf_actions import (
    EpManageFabricsVrfActionsDeployPost,
    EpManageFabricsVrfActionsExportPost,
    EpManageFabricsVrfActionsImportPost,
    EpManageFabricsVrfActionsPreviewPost,
    EpManageFabricsVrfActionsRemovePost,
    EpManageFabricsVrfActionsStretchPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrf_attachments import (
    EpManageFabricsVrfAttachmentsExportPost,
    EpManageFabricsVrfAttachmentsImportPost,
    EpManageFabricsVrfAttachmentsPost,
    EpManageFabricsVrfAttachmentsQueryPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrf_flow_rules import (
    EpManageFabricsVrfFlowRulesTenantsGet,
    EpManageFabricsVrfFlowRulesVrfsGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs import (
    EpManageFabricsVrfPreInformationGet,
    EpManageFabricsVrfsGet,
    EpManageFabricsVrfsPost,
    EpManageFabricsVrfsVrfNameDelete,
    EpManageFabricsVrfsVrfNameGet,
    EpManageFabricsVrfsVrfNamePut,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


def test_manage_vrfs_00010() -> None:
    """Verify VRF pre-information endpoint path and verb."""
    endpoint = EpManageFabricsVrfPreInformationGet(fabric_name="fab1")

    assert endpoint.class_name == "EpManageFabricsVrfPreInformationGet"
    assert endpoint.path == "/api/v1/manage/fabrics/fab1/vrfPreInformation"
    assert endpoint.verb == HttpVerbEnum.GET


def test_manage_vrfs_00020() -> None:
    """Verify VRF list endpoint query parameters."""
    endpoint = EpManageFabricsVrfsGet(fabric_name="fab1")
    endpoint.endpoint_params.max = 25
    endpoint.endpoint_params.offset = 10
    endpoint.endpoint_params.sort = "vrfName:asc"

    assert endpoint.class_name == "EpManageFabricsVrfsGet"
    assert endpoint.path == "/api/v1/manage/fabrics/fab1/vrfs?offset=10&max=25&sort=vrfName:asc"
    assert endpoint.verb == HttpVerbEnum.GET


def test_manage_vrfs_00030() -> None:
    """Verify create VRF path includes ticket ID."""
    endpoint = EpManageFabricsVrfsPost(fabric_name="fab1")
    endpoint.endpoint_params.ticket_id = "CHG123"

    assert endpoint.path == "/api/v1/manage/fabrics/fab1/vrfs?ticketId=CHG123"
    assert endpoint.verb == HttpVerbEnum.POST


def test_manage_vrfs_00040() -> None:
    """Verify single-VRF CRUD paths."""
    get_endpoint = EpManageFabricsVrfsVrfNameGet(fabric_name="fab1", vrf_name="vrf1")
    get_endpoint.endpoint_params.fetch_members_info = True
    put_endpoint = EpManageFabricsVrfsVrfNamePut(fabric_name="fab1", vrf_name="vrf1")
    delete_endpoint = EpManageFabricsVrfsVrfNameDelete(fabric_name="fab1", vrf_name="vrf1")
    delete_endpoint.endpoint_params.ticket_id = "CHG123"

    assert get_endpoint.path == "/api/v1/manage/fabrics/fab1/vrfs/vrf1?fetchMembersInfo=true"
    assert get_endpoint.verb == HttpVerbEnum.GET
    assert put_endpoint.path == "/api/v1/manage/fabrics/fab1/vrfs/vrf1"
    assert put_endpoint.verb == HttpVerbEnum.PUT
    assert delete_endpoint.path == "/api/v1/manage/fabrics/fab1/vrfs/vrf1?ticketId=CHG123"
    assert delete_endpoint.verb == HttpVerbEnum.DELETE


def test_manage_vrfs_00050() -> None:
    """Verify missing fabric or VRF identifiers raise ValueError."""
    with pytest.raises(ValueError, match="fabric_name must be set"):
        _ = EpManageFabricsVrfsGet().path
    with pytest.raises(ValueError, match="vrf_name must be set"):
        _ = EpManageFabricsVrfsVrfNameGet(fabric_name="fab1").path


def test_manage_vrf_actions_00100() -> None:
    """Verify VRF action endpoint paths and verbs."""
    deploy = EpManageFabricsVrfActionsDeployPost(fabric_name="fab1")
    deploy.endpoint_params.ticket_id = "CHG123"
    export = EpManageFabricsVrfActionsExportPost(fabric_name="fab1")
    import_ = EpManageFabricsVrfActionsImportPost(fabric_name="fab1")
    preview = EpManageFabricsVrfActionsPreviewPost(fabric_name="fab1")
    remove = EpManageFabricsVrfActionsRemovePost(fabric_name="fab1")
    stretch = EpManageFabricsVrfActionsStretchPost(fabric_name="fab1")

    assert deploy.path == "/api/v1/manage/fabrics/fab1/vrfActions/deploy?ticketId=CHG123"
    assert deploy.verb == HttpVerbEnum.POST
    assert export.path == "/api/v1/manage/fabrics/fab1/vrfActions/export"
    assert import_.path == "/api/v1/manage/fabrics/fab1/vrfActions/import"
    assert preview.path == "/api/v1/manage/fabrics/fab1/vrfActions/preview"
    assert remove.path == "/api/v1/manage/fabrics/fab1/vrfActions/remove"
    assert stretch.path == "/api/v1/manage/fabrics/fab1/vrfActions/stretch"


def test_manage_vrf_attachments_00200() -> None:
    """Verify VRF attachment endpoint paths and query parameters."""
    attach = EpManageFabricsVrfAttachmentsPost(fabric_name="fab1")
    attach.endpoint_params.ticket_id = "CHG123"
    export = EpManageFabricsVrfAttachmentsExportPost(fabric_name="fab1")
    import_ = EpManageFabricsVrfAttachmentsImportPost(fabric_name="fab1")
    query = EpManageFabricsVrfAttachmentsQueryPost(fabric_name="fab1")
    query.endpoint_params.max = 100
    query.endpoint_params.include_all = True

    assert attach.path == "/api/v1/manage/fabrics/fab1/vrfAttachments?ticketId=CHG123"
    assert attach.verb == HttpVerbEnum.POST
    assert export.path == "/api/v1/manage/fabrics/fab1/vrfAttachments/export"
    assert import_.path == "/api/v1/manage/fabrics/fab1/vrfAttachments/import"
    assert query.path == "/api/v1/manage/fabrics/fab1/vrfAttachments/query?max=100&includeAll=true"
    assert query.verb == HttpVerbEnum.POST


def test_manage_vrf_flow_rules_00300() -> None:
    """Verify VRF flow-rule endpoint paths and query parameters."""
    tenants = EpManageFabricsVrfFlowRulesTenantsGet(fabric_name="fab1")
    vrfs = EpManageFabricsVrfFlowRulesVrfsGet(fabric_name="fab1")
    vrfs.endpoint_params.tenant_name = "tenant1"

    assert tenants.path == "/api/v1/manage/fabrics/fab1/vrfFlowRules/tenants"
    assert tenants.verb == HttpVerbEnum.GET
    assert vrfs.path == "/api/v1/manage/fabrics/fab1/vrfFlowRules/vrfs?tenantName=tenant1"
    assert vrfs.verb == HttpVerbEnum.GET
