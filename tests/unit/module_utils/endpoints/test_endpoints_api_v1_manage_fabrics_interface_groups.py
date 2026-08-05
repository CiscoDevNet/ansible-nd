# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for ND Manage Interface Groups endpoint classes."""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_interface_groups import (
    EpManageFabricsInterfaceGroupsActionsRemovePost,
    EpManageFabricsInterfaceGroupsGet,
    EpManageFabricsInterfaceGroupsInterfaceGroupNameDelete,
    EpManageFabricsInterfaceGroupsInterfaceGroupNameGet,
    EpManageFabricsInterfaceGroupsInterfaceGroupNamePut,
    EpManageFabricsInterfaceGroupsPost,
    InterfaceGroupGetEndpointParams,
    InterfaceGroupMutationEndpointParams,
    InterfaceGroupsGetEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


@pytest.mark.parametrize(
    ("endpoint", "class_name", "path", "verb"),
    [
        (
            EpManageFabricsInterfaceGroupsGet(fabric_name="fab1"),
            "EpManageFabricsInterfaceGroupsGet",
            "/api/v1/manage/fabrics/fab1/interfaceGroups",
            HttpVerbEnum.GET,
        ),
        (
            EpManageFabricsInterfaceGroupsPost(fabric_name="fab1"),
            "EpManageFabricsInterfaceGroupsPost",
            "/api/v1/manage/fabrics/fab1/interfaceGroups",
            HttpVerbEnum.POST,
        ),
        (
            EpManageFabricsInterfaceGroupsActionsRemovePost(fabric_name="fab1"),
            "EpManageFabricsInterfaceGroupsActionsRemovePost",
            "/api/v1/manage/fabrics/fab1/interfaceGroups/actions/remove",
            HttpVerbEnum.POST,
        ),
        (
            EpManageFabricsInterfaceGroupsInterfaceGroupNameGet(
                fabric_name="fab1", interface_group_name="group1"
            ),
            "EpManageFabricsInterfaceGroupsInterfaceGroupNameGet",
            "/api/v1/manage/fabrics/fab1/interfaceGroups/group1",
            HttpVerbEnum.GET,
        ),
        (
            EpManageFabricsInterfaceGroupsInterfaceGroupNamePut(
                fabric_name="fab1", interface_group_name="group1"
            ),
            "EpManageFabricsInterfaceGroupsInterfaceGroupNamePut",
            "/api/v1/manage/fabrics/fab1/interfaceGroups/group1",
            HttpVerbEnum.PUT,
        ),
        (
            EpManageFabricsInterfaceGroupsInterfaceGroupNameDelete(
                fabric_name="fab1", interface_group_name="group1"
            ),
            "EpManageFabricsInterfaceGroupsInterfaceGroupNameDelete",
            "/api/v1/manage/fabrics/fab1/interfaceGroups/group1",
            HttpVerbEnum.DELETE,
        ),
    ],
)
def test_manage_interface_groups_00005(
    endpoint, class_name: str, path: str, verb: HttpVerbEnum
) -> None:
    """Verify every Interface Groups endpoint has a query-free path and identity."""
    assert endpoint.class_name == class_name
    assert endpoint.path == path
    assert endpoint.verb == verb
    assert endpoint.endpoint_params.to_query_string() == ""


def test_manage_interface_groups_00010() -> None:
    """
    # Summary

    Verify list query parameters use the API's camelCase names.

    ## Test

    - Build the list path with every supported query parameter.

    ## Classes and Methods

    - EpManageFabricsInterfaceGroupsGet.path
    """
    endpoint = EpManageFabricsInterfaceGroupsGet(fabric_name="fab1")
    endpoint.endpoint_params.cluster_name = "cluster-a"
    endpoint.endpoint_params.filter = "type:portChannel"
    endpoint.endpoint_params.max = 25
    endpoint.endpoint_params.offset = 10
    endpoint.endpoint_params.sort = "interfaceGroupName:asc"

    path, query = endpoint.path.split("?", 1)
    assert path == "/api/v1/manage/fabrics/fab1/interfaceGroups"
    assert set(query.split("&")) == {
        "clusterName=cluster-a",
        "filter=type%3AportChannel",
        "max=25",
        "offset=10",
        "sort=interfaceGroupName%3Aasc",
    }
    assert endpoint.verb == HttpVerbEnum.GET


def test_manage_interface_groups_00020() -> None:
    """
    # Summary

    Verify create endpoint path and mutation query parameters.

    ## Test

    - Include clusterName and ticketId on the bulk-create path.

    ## Classes and Methods

    - EpManageFabricsInterfaceGroupsPost.path
    """
    endpoint = EpManageFabricsInterfaceGroupsPost(fabric_name="fab1")
    endpoint.endpoint_params.cluster_name = "cluster-a"
    endpoint.endpoint_params.ticket_id = "CHG_123"

    path, query = endpoint.path.split("?", 1)
    assert path == "/api/v1/manage/fabrics/fab1/interfaceGroups"
    assert set(query.split("&")) == {"clusterName=cluster-a", "ticketId=CHG_123"}
    assert endpoint.verb == HttpVerbEnum.POST


def test_manage_interface_groups_00030() -> None:
    """
    # Summary

    Verify bulk remove endpoint path and verb.

    ## Test

    - Build the actions/remove path with ticketId.

    ## Classes and Methods

    - EpManageFabricsInterfaceGroupsActionsRemovePost.path
    """
    endpoint = EpManageFabricsInterfaceGroupsActionsRemovePost(fabric_name="fab1")
    endpoint.endpoint_params.ticket_id = "CHG123"

    assert (
        endpoint.path
        == "/api/v1/manage/fabrics/fab1/interfaceGroups/actions/remove?ticketId=CHG123"
    )
    assert endpoint.verb == HttpVerbEnum.POST


def test_manage_interface_groups_00040() -> None:
    """
    # Summary

    Verify single-group GET percent-encodes path identifiers.

    ## Test

    - Use fabric and group names containing reserved path characters.

    ## Classes and Methods

    - EpManageFabricsInterfaceGroupsInterfaceGroupNameGet.path
    """
    endpoint = EpManageFabricsInterfaceGroupsInterfaceGroupNameGet(
        fabric_name="fabric/one",
        interface_group_name="server group/1",
    )
    endpoint.endpoint_params.cluster_name = "cluster-a"

    assert (
        endpoint.path
        == "/api/v1/manage/fabrics/fabric%2Fone/interfaceGroups/server%20group%2F1?clusterName=cluster-a"
    )
    assert endpoint.verb == HttpVerbEnum.GET


def test_manage_interface_groups_00050() -> None:
    """
    # Summary

    Verify single-group PUT and DELETE paths and verbs.

    ## Test

    - Build the named PUT path with ticketId and the named DELETE path.

    ## Classes and Methods

    - EpManageFabricsInterfaceGroupsInterfaceGroupNamePut.path
    - EpManageFabricsInterfaceGroupsInterfaceGroupNameDelete.path
    """
    put_endpoint = EpManageFabricsInterfaceGroupsInterfaceGroupNamePut(
        fabric_name="fab1",
        interface_group_name="group1",
    )
    put_endpoint.endpoint_params.ticket_id = "CHG123"
    delete_endpoint = EpManageFabricsInterfaceGroupsInterfaceGroupNameDelete(
        fabric_name="fab1",
        interface_group_name="group1",
    )

    assert (
        put_endpoint.path
        == "/api/v1/manage/fabrics/fab1/interfaceGroups/group1?ticketId=CHG123"
    )
    assert put_endpoint.verb == HttpVerbEnum.PUT
    assert delete_endpoint.path == "/api/v1/manage/fabrics/fab1/interfaceGroups/group1"
    assert delete_endpoint.verb == HttpVerbEnum.DELETE


def test_manage_interface_groups_00060() -> None:
    """
    # Summary

    Verify fabric and group identifiers are required before building paths.

    ## Test

    - Access list and named paths with their required identifiers missing.

    ## Classes and Methods

    - EpManageFabricsInterfaceGroupsGet.path
    - EpManageFabricsInterfaceGroupsInterfaceGroupNameGet.path
    """
    with pytest.raises(ValueError, match="fabric_name must be set"):
        EpManageFabricsInterfaceGroupsGet().path
    with pytest.raises(ValueError, match="interface_group_name must be set"):
        EpManageFabricsInterfaceGroupsInterfaceGroupNameGet(fabric_name="fab1").path

    endpoint = EpManageFabricsInterfaceGroupsInterfaceGroupNameGet(fabric_name="fab1")
    endpoint.set_identifiers("group1")
    assert endpoint.path == "/api/v1/manage/fabrics/fab1/interfaceGroups/group1"


def test_manage_interface_groups_00070() -> None:
    """
    # Summary

    Verify endpoint parameter models reject unsupported query parameters.

    ## Test

    - Supply one unsupported field to each query-parameter model.

    ## Classes and Methods

    - InterfaceGroupsGetEndpointParams.__init__()
    - InterfaceGroupGetEndpointParams.__init__()
    - InterfaceGroupMutationEndpointParams.__init__()
    """
    with pytest.raises(ValueError):
        InterfaceGroupsGetEndpointParams(unsupported="value")
    with pytest.raises(ValueError):
        InterfaceGroupGetEndpointParams(ticket_id="not-supported")
    with pytest.raises(ValueError):
        InterfaceGroupMutationEndpointParams(filter="not-supported")


@pytest.mark.parametrize("ticket_id", ["123-invalid", "invalid ticket", "A" * 65])
def test_manage_interface_groups_00080(ticket_id: str) -> None:
    """
    # Summary

    Verify ticket IDs follow the supported constraints.

    ## Test

    - Reject an invalid leading character, embedded space, and excessive length.

    ## Classes and Methods

    - InterfaceGroupMutationEndpointParams.__init__()
    """
    with pytest.raises(ValueError):
        InterfaceGroupMutationEndpointParams(ticket_id=ticket_id)


@pytest.mark.parametrize(
    "endpoint",
    [
        EpManageFabricsInterfaceGroupsPost(fabric_name="fab1"),
        EpManageFabricsInterfaceGroupsActionsRemovePost(fabric_name="fab1"),
        EpManageFabricsInterfaceGroupsInterfaceGroupNamePut(
            fabric_name="fab1", interface_group_name="group1"
        ),
        EpManageFabricsInterfaceGroupsInterfaceGroupNameDelete(
            fabric_name="fab1", interface_group_name="group1"
        ),
    ],
)
def test_manage_interface_groups_00090(endpoint) -> None:
    """Verify all mutation endpoints forward cluster and ticket parameters."""
    endpoint.endpoint_params.cluster_name = "cluster-a"
    endpoint.endpoint_params.ticket_id = "CHG123"

    query = endpoint.path.split("?", 1)[1]
    assert set(query.split("&")) == {"clusterName=cluster-a", "ticketId=CHG123"}
