# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_tor.py

Tests the ND Manage Access/ToR Association endpoint classes.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_tor import (
    EpManageTorAssociatePost,
    EpManageTorDisassociatePost,
    EpManageTorAssociationsGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: EpManageTorAssociatePost
# =============================================================================


def test_endpoints_api_v1_manage_tor_00010():
    """
    # Summary

    Verify EpManageTorAssociatePost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST
    """
    with does_not_raise():
        instance = EpManageTorAssociatePost()
    assert instance.class_name == "EpManageTorAssociatePost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_tor_00020():
    """
    # Summary

    Verify EpManageTorAssociatePost path with fabric_name

    ## Test

    - path returns correct associate endpoint when fabric_name is set
    """
    with does_not_raise():
        instance = EpManageTorAssociatePost()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/accessAssociationActions/associate"


def test_endpoints_api_v1_manage_tor_00030():
    """
    # Summary

    Verify EpManageTorAssociatePost path without fabric_name raises ValueError

    ## Test

    - Accessing path without setting fabric_name raises ValueError
    """
    with pytest.raises(ValueError):
        instance = EpManageTorAssociatePost()
        result = instance.path  # noqa: F841


def test_endpoints_api_v1_manage_tor_00040():
    """
    # Summary

    Verify EpManageTorAssociatePost set_identifiers with composite tuple

    ## Test

    - set_identifiers extracts fabric_name from first element of composite tuple
    """
    with does_not_raise():
        instance = EpManageTorAssociatePost()
        instance.set_identifiers(("test-fabric", "SERIAL1", "SERIAL2"))
        result = instance.path
    assert instance.fabric_name == "test-fabric"
    assert result == "/api/v1/manage/fabrics/test-fabric/accessAssociationActions/associate"


def test_endpoints_api_v1_manage_tor_00050():
    """
    # Summary

    Verify EpManageTorAssociatePost set_identifiers with string

    ## Test

    - set_identifiers accepts a plain string as fabric_name
    """
    with does_not_raise():
        instance = EpManageTorAssociatePost()
        instance.set_identifiers("simple-fabric")
        result = instance.path
    assert instance.fabric_name == "simple-fabric"
    assert result == "/api/v1/manage/fabrics/simple-fabric/accessAssociationActions/associate"


# =============================================================================
# Test: EpManageTorDisassociatePost
# =============================================================================


def test_endpoints_api_v1_manage_tor_00100():
    """
    # Summary

    Verify EpManageTorDisassociatePost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST
    """
    with does_not_raise():
        instance = EpManageTorDisassociatePost()
    assert instance.class_name == "EpManageTorDisassociatePost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_tor_00110():
    """
    # Summary

    Verify EpManageTorDisassociatePost path with fabric_name

    ## Test

    - path returns correct disassociate endpoint when fabric_name is set
    """
    with does_not_raise():
        instance = EpManageTorDisassociatePost()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/accessAssociationActions/disassociate"


def test_endpoints_api_v1_manage_tor_00120():
    """
    # Summary

    Verify EpManageTorDisassociatePost path without fabric_name raises ValueError

    ## Test

    - Accessing path without setting fabric_name raises ValueError
    """
    with pytest.raises(ValueError):
        instance = EpManageTorDisassociatePost()
        result = instance.path  # noqa: F841


def test_endpoints_api_v1_manage_tor_00130():
    """
    # Summary

    Verify EpManageTorDisassociatePost set_identifiers with composite tuple

    ## Test

    - set_identifiers extracts fabric_name from first element of composite tuple
    """
    with does_not_raise():
        instance = EpManageTorDisassociatePost()
        instance.set_identifiers(("prod-fabric", "SN1", "SN2"))
    assert instance.fabric_name == "prod-fabric"
    assert instance.path == "/api/v1/manage/fabrics/prod-fabric/accessAssociationActions/disassociate"


# =============================================================================
# Test: EpManageTorAssociationsGet
# =============================================================================


def test_endpoints_api_v1_manage_tor_00200():
    """
    # Summary

    Verify EpManageTorAssociationsGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET
    """
    with does_not_raise():
        instance = EpManageTorAssociationsGet()
    assert instance.class_name == "EpManageTorAssociationsGet"
    assert instance.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_manage_tor_00210():
    """
    # Summary

    Verify EpManageTorAssociationsGet path with fabric_name

    ## Test

    - path returns correct associations endpoint when fabric_name is set
    """
    with does_not_raise():
        instance = EpManageTorAssociationsGet()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/accessAssociations"


def test_endpoints_api_v1_manage_tor_00220():
    """
    # Summary

    Verify EpManageTorAssociationsGet path without fabric_name raises ValueError

    ## Test

    - Accessing path without setting fabric_name raises ValueError
    """
    with pytest.raises(ValueError):
        instance = EpManageTorAssociationsGet()
        result = instance.path  # noqa: F841


def test_endpoints_api_v1_manage_tor_00230():
    """
    # Summary

    Verify EpManageTorAssociationsGet set_identifiers with composite tuple

    ## Test

    - set_identifiers extracts fabric_name from first element of composite tuple
    """
    with does_not_raise():
        instance = EpManageTorAssociationsGet()
        instance.set_identifiers(("query-fabric", "SN1", "SN2"))
    assert instance.fabric_name == "query-fabric"
    assert instance.path == "/api/v1/manage/fabrics/query-fabric/accessAssociations"
