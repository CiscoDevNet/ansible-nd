# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabrics_switchactions.py

Tests the ND Manage Fabrics Switch Actions endpoint classes.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switchactions import (
    EpManageFabricsSwitchActionsChangeRolesPost,
    EpManageFabricsSwitchActionsImportBootstrapPost,
    EpManageFabricsSwitchActionsPreProvisionPost,
    EpManageFabricsSwitchActionsRediscoverPost,
    EpManageFabricsSwitchActionsRemovePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: EpManageFabricsSwitchActionsRemovePost
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_switchactions_00100():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsRemovePost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageFabricsSwitchActionsRemovePost.__init__()
    - EpManageFabricsSwitchActionsRemovePost.class_name
    - EpManageFabricsSwitchActionsRemovePost.verb
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchActionsRemovePost()
    assert instance.class_name == "EpManageFabricsSwitchActionsRemovePost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_fabrics_switchactions_00110():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsRemovePost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManageFabricsSwitchActionsRemovePost.path
    """
    instance = EpManageFabricsSwitchActionsRemovePost()
    with pytest.raises(ValueError):
        instance.path


def test_endpoints_api_v1_manage_fabrics_switchactions_00120():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsRemovePost path without query params

    ## Test

    - path returns correct endpoint path

    ## Classes and Methods

    - EpManageFabricsSwitchActionsRemovePost.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchActionsRemovePost()
        instance.fabric_name = "MyFabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/switchActions/remove"


def test_endpoints_api_v1_manage_fabrics_switchactions_00130():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsRemovePost path with force and ticket_id

    ## Test

    - path includes force and ticketId in query string when set

    ## Classes and Methods

    - EpManageFabricsSwitchActionsRemovePost.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchActionsRemovePost()
        instance.fabric_name = "MyFabric"
        instance.endpoint_params.force = True
        instance.endpoint_params.ticket_id = "CHG12345"
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/MyFabric/switchActions/remove?")
    assert "force=true" in result
    assert "ticketId=CHG12345" in result


# =============================================================================
# Test: EpManageFabricsSwitchActionsChangeRolesPost
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_switchactions_00200():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsChangeRolesPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageFabricsSwitchActionsChangeRolesPost.__init__()
    - EpManageFabricsSwitchActionsChangeRolesPost.class_name
    - EpManageFabricsSwitchActionsChangeRolesPost.verb
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchActionsChangeRolesPost()
    assert instance.class_name == "EpManageFabricsSwitchActionsChangeRolesPost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_fabrics_switchactions_00210():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsChangeRolesPost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManageFabricsSwitchActionsChangeRolesPost.path
    """
    instance = EpManageFabricsSwitchActionsChangeRolesPost()
    with pytest.raises(ValueError):
        instance.path


def test_endpoints_api_v1_manage_fabrics_switchactions_00220():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsChangeRolesPost path without query params

    ## Test

    - path returns correct endpoint path

    ## Classes and Methods

    - EpManageFabricsSwitchActionsChangeRolesPost.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchActionsChangeRolesPost()
        instance.fabric_name = "MyFabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/switchActions/changeRoles"


def test_endpoints_api_v1_manage_fabrics_switchactions_00230():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsChangeRolesPost path with ticket_id

    ## Test

    - path includes ticketId in query string when set

    ## Classes and Methods

    - EpManageFabricsSwitchActionsChangeRolesPost.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchActionsChangeRolesPost()
        instance.fabric_name = "MyFabric"
        instance.endpoint_params.ticket_id = "CHG12345"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/switchActions/changeRoles?ticketId=CHG12345"


# =============================================================================
# Test: EpManageFabricsSwitchActionsImportBootstrapPost
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_switchactions_00300():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsImportBootstrapPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageFabricsSwitchActionsImportBootstrapPost.__init__()
    - EpManageFabricsSwitchActionsImportBootstrapPost.class_name
    - EpManageFabricsSwitchActionsImportBootstrapPost.verb
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchActionsImportBootstrapPost()
    assert instance.class_name == "EpManageFabricsSwitchActionsImportBootstrapPost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_fabrics_switchactions_00310():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsImportBootstrapPost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManageFabricsSwitchActionsImportBootstrapPost.path
    """
    instance = EpManageFabricsSwitchActionsImportBootstrapPost()
    with pytest.raises(ValueError):
        instance.path


def test_endpoints_api_v1_manage_fabrics_switchactions_00320():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsImportBootstrapPost path without query params

    ## Test

    - path returns correct endpoint path

    ## Classes and Methods

    - EpManageFabricsSwitchActionsImportBootstrapPost.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchActionsImportBootstrapPost()
        instance.fabric_name = "MyFabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/switchActions/importBootstrap"


def test_endpoints_api_v1_manage_fabrics_switchactions_00330():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsImportBootstrapPost path with cluster_name and ticket_id

    ## Test

    - path includes clusterName and ticketId in query string when set

    ## Classes and Methods

    - EpManageFabricsSwitchActionsImportBootstrapPost.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchActionsImportBootstrapPost()
        instance.fabric_name = "MyFabric"
        instance.endpoint_params.cluster_name = "cluster1"
        instance.endpoint_params.ticket_id = "CHG12345"
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/MyFabric/switchActions/importBootstrap?")
    assert "clusterName=cluster1" in result
    assert "ticketId=CHG12345" in result


# =============================================================================
# Test: EpManageFabricsSwitchActionsPreProvisionPost
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_switchactions_00400():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsPreProvisionPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageFabricsSwitchActionsPreProvisionPost.__init__()
    - EpManageFabricsSwitchActionsPreProvisionPost.class_name
    - EpManageFabricsSwitchActionsPreProvisionPost.verb
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchActionsPreProvisionPost()
    assert instance.class_name == "EpManageFabricsSwitchActionsPreProvisionPost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_fabrics_switchactions_00410():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsPreProvisionPost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManageFabricsSwitchActionsPreProvisionPost.path
    """
    instance = EpManageFabricsSwitchActionsPreProvisionPost()
    with pytest.raises(ValueError):
        instance.path


def test_endpoints_api_v1_manage_fabrics_switchactions_00420():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsPreProvisionPost path without query params

    ## Test

    - path returns correct endpoint path

    ## Classes and Methods

    - EpManageFabricsSwitchActionsPreProvisionPost.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchActionsPreProvisionPost()
        instance.fabric_name = "MyFabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/switchActions/preProvision"


def test_endpoints_api_v1_manage_fabrics_switchactions_00430():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsPreProvisionPost path with cluster_name and ticket_id

    ## Test

    - path includes clusterName and ticketId in query string when set

    ## Classes and Methods

    - EpManageFabricsSwitchActionsPreProvisionPost.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchActionsPreProvisionPost()
        instance.fabric_name = "MyFabric"
        instance.endpoint_params.cluster_name = "cluster1"
        instance.endpoint_params.ticket_id = "CHG12345"
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/MyFabric/switchActions/preProvision?")
    assert "clusterName=cluster1" in result
    assert "ticketId=CHG12345" in result


# =============================================================================
# Test: EpManageFabricsSwitchActionsRediscoverPost
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_switchactions_00700():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsRediscoverPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageFabricsSwitchActionsRediscoverPost.__init__()
    - EpManageFabricsSwitchActionsRediscoverPost.class_name
    - EpManageFabricsSwitchActionsRediscoverPost.verb
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchActionsRediscoverPost()
    assert instance.class_name == "EpManageFabricsSwitchActionsRediscoverPost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_fabrics_switchactions_00710():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsRediscoverPost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManageFabricsSwitchActionsRediscoverPost.path
    """
    instance = EpManageFabricsSwitchActionsRediscoverPost()
    with pytest.raises(ValueError):
        instance.path


def test_endpoints_api_v1_manage_fabrics_switchactions_00720():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsRediscoverPost path without query params

    ## Test

    - path returns correct endpoint path

    ## Classes and Methods

    - EpManageFabricsSwitchActionsRediscoverPost.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchActionsRediscoverPost()
        instance.fabric_name = "MyFabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/switchActions/rediscover"


def test_endpoints_api_v1_manage_fabrics_switchactions_00730():
    """
    # Summary

    Verify EpManageFabricsSwitchActionsRediscoverPost path with ticket_id

    ## Test

    - path includes ticketId in query string when set

    ## Classes and Methods

    - EpManageFabricsSwitchActionsRediscoverPost.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchActionsRediscoverPost()
        instance.fabric_name = "MyFabric"
        instance.endpoint_params.ticket_id = "CHG12345"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/switchActions/rediscover?ticketId=CHG12345"
