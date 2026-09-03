# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage tenant_fabric_associations endpoints.

Tests the ND Manage Tenant Fabric Associations endpoint classes
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.tenant_fabric_associations import (
    EpManageTenantFabricAssociationsGet,
    EpManageTenantFabricAssociationsPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: EpManageTenantFabricAssociationsGet
# =============================================================================


def test_endpoints_api_v1_manage_tenant_fabric_associations_00010():
    """
    # Summary

    Verify EpManageTenantFabricAssociationsGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpManageTenantFabricAssociationsGet.__init__()
    - EpManageTenantFabricAssociationsGet.verb
    - EpManageTenantFabricAssociationsGet.class_name
    """
    with does_not_raise():
        instance = EpManageTenantFabricAssociationsGet()
    assert instance.class_name == "EpManageTenantFabricAssociationsGet"
    assert instance.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_manage_tenant_fabric_associations_00020():
    """
    # Summary

    Verify EpManageTenantFabricAssociationsGet path

    ## Test

    - path returns "/api/v1/manage/tenantFabricAssociations"

    ## Classes and Methods

    - EpManageTenantFabricAssociationsGet.path
    """
    with does_not_raise():
        instance = EpManageTenantFabricAssociationsGet()
        result = instance.path
    assert result == "/api/v1/manage/tenantFabricAssociations"


def test_endpoints_api_v1_manage_tenant_fabric_associations_00030():
    """
    # Summary

    Verify EpManageTenantFabricAssociationsGet set_identifiers is a no-op

    ## Test

    - set_identifiers does not change the path (collection-level endpoint)

    ## Classes and Methods

    - EpManageTenantFabricAssociationsGet.set_identifiers()
    - EpManageTenantFabricAssociationsGet.path
    """
    with does_not_raise():
        instance = EpManageTenantFabricAssociationsGet()
        instance.set_identifiers(("fabric1", "tenant1"))
        result = instance.path
    assert result == "/api/v1/manage/tenantFabricAssociations"


# =============================================================================
# Test: EpManageTenantFabricAssociationsPost
# =============================================================================


def test_endpoints_api_v1_manage_tenant_fabric_associations_00100():
    """
    # Summary

    Verify EpManageTenantFabricAssociationsPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageTenantFabricAssociationsPost.__init__()
    - EpManageTenantFabricAssociationsPost.verb
    - EpManageTenantFabricAssociationsPost.class_name
    """
    with does_not_raise():
        instance = EpManageTenantFabricAssociationsPost()
    assert instance.class_name == "EpManageTenantFabricAssociationsPost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_tenant_fabric_associations_00110():
    """
    # Summary

    Verify EpManageTenantFabricAssociationsPost path

    ## Test

    - path returns "/api/v1/manage/tenantFabricAssociations" for POST

    ## Classes and Methods

    - EpManageTenantFabricAssociationsPost.path
    """
    with does_not_raise():
        instance = EpManageTenantFabricAssociationsPost()
        result = instance.path
    assert result == "/api/v1/manage/tenantFabricAssociations"


# =============================================================================
# Test: Both endpoint verbs
# =============================================================================


def test_endpoints_api_v1_manage_tenant_fabric_associations_00200():
    """
    # Summary

    Verify GET and POST endpoints have same path but different verbs

    ## Test

    - Both endpoints return the same base path
    - Verbs are different (GET vs POST)

    ## Classes and Methods

    - EpManageTenantFabricAssociationsGet
    - EpManageTenantFabricAssociationsPost
    """
    with does_not_raise():
        get_ep = EpManageTenantFabricAssociationsGet()
        post_ep = EpManageTenantFabricAssociationsPost()

    assert get_ep.path == post_ep.path
    assert get_ep.path == "/api/v1/manage/tenantFabricAssociations"
    assert get_ep.verb == HttpVerbEnum.GET
    assert post_ep.verb == HttpVerbEnum.POST
