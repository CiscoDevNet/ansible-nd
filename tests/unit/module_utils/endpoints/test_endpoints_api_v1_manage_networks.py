# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for ND Manage network endpoint classes."""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_network_actions import (
    EpManageFabricsNetworkActionsDeployPost,
    EpManageFabricsNetworkActionsProposeMulticastIpGet,
    EpManageFabricsNetworkActionsStretchPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_network_attachments import (
    EpManageFabricsNetworkAttachmentsExportPost,
    EpManageFabricsNetworkAttachmentsPost,
    EpManageFabricsNetworkAttachmentsQueryPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_networks import (
    EpManageFabricsNetworkPreInformationGet,
    EpManageFabricsNetworksGet,
    EpManageFabricsNetworksNetworkNameDelete,
    EpManageFabricsNetworksNetworkNameGet,
    EpManageFabricsNetworksNetworkNamePut,
    EpManageFabricsNetworksPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


def test_manage_networks_00010() -> None:
    """Verify network pre-information endpoint path and verb."""
    endpoint = EpManageFabricsNetworkPreInformationGet(fabric_name="fab1")

    assert endpoint.path == "/api/v1/manage/fabrics/fab1/networkPreInformation"
    assert endpoint.verb == HttpVerbEnum.GET


def test_manage_networks_00020() -> None:
    """Verify network list query parameters."""
    endpoint = EpManageFabricsNetworksGet(fabric_name="fab1")
    endpoint.endpoint_params.max = 25
    endpoint.endpoint_params.offset = 10
    endpoint.endpoint_params.sort = "networkName:asc"
    endpoint.endpoint_params.service_network = True

    assert endpoint.path == "/api/v1/manage/fabrics/fab1/networks?offset=10&max=25&sort=networkName:asc&serviceNetwork=true"
    assert endpoint.verb == HttpVerbEnum.GET


def test_manage_networks_00030() -> None:
    """Verify create network path includes ticket ID."""
    endpoint = EpManageFabricsNetworksPost(fabric_name="fab1")
    endpoint.endpoint_params.ticket_id = "CHG123"

    assert endpoint.path == "/api/v1/manage/fabrics/fab1/networks?ticketId=CHG123"
    assert endpoint.verb == HttpVerbEnum.POST


def test_manage_networks_00040() -> None:
    """Verify single-network CRUD paths."""
    get_endpoint = EpManageFabricsNetworksNetworkNameGet(fabric_name="fab1", network_name="net1")
    get_endpoint.endpoint_params.fetch_members = True
    put_endpoint = EpManageFabricsNetworksNetworkNamePut(fabric_name="fab1", network_name="net1")
    delete_endpoint = EpManageFabricsNetworksNetworkNameDelete(fabric_name="fab1", network_name="net1")
    delete_endpoint.endpoint_params.ticket_id = "CHG123"

    assert get_endpoint.path == "/api/v1/manage/fabrics/fab1/networks/net1?fetchMembers=true"
    assert put_endpoint.path == "/api/v1/manage/fabrics/fab1/networks/net1"
    assert delete_endpoint.path == "/api/v1/manage/fabrics/fab1/networks/net1?ticketId=CHG123"


def test_manage_networks_00050() -> None:
    """Verify missing fabric or network identifiers raise ValueError."""
    with pytest.raises(ValueError, match="fabric_name must be set"):
        EpManageFabricsNetworksGet().path
    with pytest.raises(ValueError, match="network_name must be set"):
        EpManageFabricsNetworksNetworkNameGet(fabric_name="fab1").path


def test_manage_network_actions_00100() -> None:
    """Verify network action endpoint paths and verbs."""
    deploy = EpManageFabricsNetworkActionsDeployPost(fabric_name="fab1")
    deploy.endpoint_params.ticket_id = "CHG123"
    propose = EpManageFabricsNetworkActionsProposeMulticastIpGet(fabric_name="fab1")
    stretch = EpManageFabricsNetworkActionsStretchPost(fabric_name="fab1")

    assert deploy.path == "/api/v1/manage/fabrics/fab1/networkActions/deploy?ticketId=CHG123"
    assert deploy.verb == HttpVerbEnum.POST
    assert propose.path == "/api/v1/manage/fabrics/fab1/networkActions/proposeMulticastIp"
    assert propose.verb == HttpVerbEnum.GET
    assert stretch.path == "/api/v1/manage/fabrics/fab1/networkActions/stretch"
    assert stretch.verb == HttpVerbEnum.POST


def test_manage_network_attachments_00200() -> None:
    """Verify network attachment endpoint paths and query parameters."""
    attach = EpManageFabricsNetworkAttachmentsPost(fabric_name="fab1")
    attach.endpoint_params.ticket_id = "CHG123"
    export = EpManageFabricsNetworkAttachmentsExportPost(fabric_name="fab1")
    export.endpoint_params.cluster_name = "cluster1"
    query = EpManageFabricsNetworkAttachmentsQueryPost(fabric_name="fab1")
    query.endpoint_params.max = 100
    query.endpoint_params.include_all = True
    query.endpoint_params.is_consolidated = False

    assert attach.path == "/api/v1/manage/fabrics/fab1/networkAttachments?ticketId=CHG123"
    assert attach.verb == HttpVerbEnum.POST
    assert export.path == "/api/v1/manage/fabrics/fab1/networkAttachments/export?clusterName=cluster1"
    assert export.verb == HttpVerbEnum.POST
    assert query.path == "/api/v1/manage/fabrics/fab1/networkAttachments/query?max=100&isConsolidated=false&includeAll=true"
    assert query.verb == HttpVerbEnum.POST
