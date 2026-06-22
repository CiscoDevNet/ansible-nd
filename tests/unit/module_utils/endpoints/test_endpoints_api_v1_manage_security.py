# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for security endpoint classes."""

from __future__ import absolute_import, annotations, division, print_function

from contextlib import contextmanager

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.security import (
    EpManageSecurityAssociationsAttach,
    EpManageSecurityAssociationsGet,
    EpManageSecurityAssociationsListGet,
    EpManageSecurityContractsGet,
    EpManageSecurityFabricDeploy,
    EpManageSecurityGroupsGet,
    EpManageSecurityGroupsListGet,
    EpManageSecurityProtocolDefinitionsGet,
    EpManageSecurityProtocolDefinitionsListGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


def test_security_endpoint_00010():
    """Verify resource GET endpoint encodes fabric and resource path segments."""
    with does_not_raise():
        instance = EpManageSecurityGroupsGet()
        instance.fabric_name = "fabric/one"
        instance.set_identifiers("tenant/security group")
        result = instance.path
    assert result == "/api/v1/manage/fabrics/fabric%2Fone/securityGroups/tenant%2Fsecurity%20group"
    assert instance.verb == HttpVerbEnum.GET


def test_security_endpoint_00020():
    """Verify list endpoint includes cluster and pagination query parameters."""
    with does_not_raise():
        instance = EpManageSecurityGroupsListGet()
        instance.fabric_name = "SITE1"
        instance.endpoint_params.cluster_name = "cluster-a"
        instance.endpoint_params.offset = 10
        instance.endpoint_params.max = 100
        result = instance.path
    assert result == "/api/v1/manage/fabrics/SITE1/securityGroups?clusterName=cluster-a&offset=10&max=100"
    assert instance.verb == HttpVerbEnum.GET


def test_security_endpoint_00030():
    """Verify required fabric_name is enforced."""
    instance = EpManageSecurityContractsGet()
    instance.set_identifiers("allow_web")
    with pytest.raises(ValueError, match="fabric_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_security_endpoint_00040():
    """Verify required resource name is enforced."""
    instance = EpManageSecurityProtocolDefinitionsGet()
    instance.fabric_name = "SITE1"
    with pytest.raises(ValueError, match="resource_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_security_endpoint_00050():
    """Verify resource-specific paths."""
    protocol = EpManageSecurityProtocolDefinitionsListGet()
    protocol.fabric_name = "SITE1"
    contract = EpManageSecurityContractsGet()
    contract.fabric_name = "SITE1"
    contract.set_identifiers("allow_web")
    association = EpManageSecurityAssociationsGet()
    association.fabric_name = "SITE1"
    association.set_identifiers("web_to_app")

    assert protocol.path == "/api/v1/manage/fabrics/SITE1/securityProtocolDefinitions"
    assert contract.path == "/api/v1/manage/fabrics/SITE1/securityContracts/allow_web"
    assert association.path == "/api/v1/manage/fabrics/SITE1/securityAssociations/web_to_app"


def test_security_endpoint_00060():
    """Verify action endpoint path and verb."""
    instance = EpManageSecurityAssociationsAttach()
    instance.fabric_name = "SITE1"
    instance.endpoint_params.cluster_name = "cluster-a"

    assert instance.path == "/api/v1/manage/fabrics/SITE1/securityAssociationActions/attach?clusterName=cluster-a"
    assert instance.verb == HttpVerbEnum.POST


def test_security_endpoint_00070():
    """Verify fabric deploy query parameters for config_actions.type global."""
    instance = EpManageSecurityFabricDeploy()
    instance.fabric_name = "SITE1"
    instance.endpoint_params.cluster_name = "cluster-a"
    instance.endpoint_params.incl_all_fabric_groups_switches = True

    assert instance.path == (
        "/api/v1/manage/fabrics/SITE1/actions/deploy?"
        "clusterName=cluster-a&forceShowRun=true&inclAllFabricGroupsSwitches=true"
    )
    assert instance.verb == HttpVerbEnum.POST

