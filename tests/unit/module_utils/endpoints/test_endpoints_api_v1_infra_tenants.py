# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for infra tenants endpoints.

Tests the ND Infra Tenants endpoint classes
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra.tenants import (
    EpInfraTenantsDelete,
    EpInfraTenantsGet,
    EpInfraTenantsPost,
    EpInfraTenantsPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: EpInfraTenantsGet
# =============================================================================


def test_endpoints_api_v1_infra_tenants_00010():
    """
    # Summary

    Verify EpInfraTenantsGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpInfraTenantsGet.__init__()
    - EpInfraTenantsGet.verb
    - EpInfraTenantsGet.class_name
    """
    with does_not_raise():
        instance = EpInfraTenantsGet()
    assert instance.class_name == "EpInfraTenantsGet"
    assert instance.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_infra_tenants_00020():
    """
    # Summary

    Verify EpInfraTenantsGet path without tenant_name

    ## Test

    - path returns "/api/v1/infra/tenants" when tenant_name is None

    ## Classes and Methods

    - EpInfraTenantsGet.path
    """
    with does_not_raise():
        instance = EpInfraTenantsGet()
        result = instance.path
    assert result == "/api/v1/infra/tenants"


def test_endpoints_api_v1_infra_tenants_00030():
    """
    # Summary

    Verify EpInfraTenantsGet path with tenant_name

    ## Test

    - path returns "/api/v1/infra/tenants/tenant1" when tenant_name is set

    ## Classes and Methods

    - EpInfraTenantsGet.path
    - EpInfraTenantsGet.tenant_name
    """
    with does_not_raise():
        instance = EpInfraTenantsGet()
        instance.tenant_name = "tenant1"
        result = instance.path
    assert result == "/api/v1/infra/tenants/tenant1"


def test_endpoints_api_v1_infra_tenants_00040():
    """
    # Summary

    Verify EpInfraTenantsGet tenant_name can be set at instantiation

    ## Test

    - tenant_name can be provided during instantiation

    ## Classes and Methods

    - EpInfraTenantsGet.__init__()
    """
    with does_not_raise():
        instance = EpInfraTenantsGet(tenant_name="my_tenant")
    assert instance.tenant_name == "my_tenant"
    assert instance.path == "/api/v1/infra/tenants/my_tenant"


# =============================================================================
# Test: EpInfraTenantsPost
# =============================================================================


def test_endpoints_api_v1_infra_tenants_00100():
    """
    # Summary

    Verify EpInfraTenantsPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpInfraTenantsPost.__init__()
    - EpInfraTenantsPost.verb
    - EpInfraTenantsPost.class_name
    """
    with does_not_raise():
        instance = EpInfraTenantsPost()
    assert instance.class_name == "EpInfraTenantsPost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_infra_tenants_00110():
    """
    # Summary

    Verify EpInfraTenantsPost path

    ## Test

    - path returns "/api/v1/infra/tenants" for POST

    ## Classes and Methods

    - EpInfraTenantsPost.path
    """
    with does_not_raise():
        instance = EpInfraTenantsPost()
        result = instance.path
    assert result == "/api/v1/infra/tenants"


def test_endpoints_api_v1_infra_tenants_00120():
    """
    # Summary

    Verify EpInfraTenantsPost path with tenant_name

    ## Test

    - path returns "/api/v1/infra/tenants/tenant1" when tenant_name is set

    ## Classes and Methods

    - EpInfraTenantsPost.path
    - EpInfraTenantsPost.tenant_name
    """
    with does_not_raise():
        instance = EpInfraTenantsPost()
        instance.tenant_name = "tenant1"
        result = instance.path
    assert result == "/api/v1/infra/tenants/tenant1"


# =============================================================================
# Test: EpInfraTenantsPut
# =============================================================================


def test_endpoints_api_v1_infra_tenants_00200():
    """
    # Summary

    Verify EpInfraTenantsPut basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is PUT

    ## Classes and Methods

    - EpInfraTenantsPut.__init__()
    - EpInfraTenantsPut.verb
    - EpInfraTenantsPut.class_name
    """
    with does_not_raise():
        instance = EpInfraTenantsPut()
    assert instance.class_name == "EpInfraTenantsPut"
    assert instance.verb == HttpVerbEnum.PUT


def test_endpoints_api_v1_infra_tenants_00210():
    """
    # Summary

    Verify EpInfraTenantsPut path with tenant_name

    ## Test

    - path returns "/api/v1/infra/tenants/tenant1" when tenant_name is set

    ## Classes and Methods

    - EpInfraTenantsPut.path
    - EpInfraTenantsPut.tenant_name
    """
    with does_not_raise():
        instance = EpInfraTenantsPut()
        instance.tenant_name = "tenant1"
        result = instance.path
    assert result == "/api/v1/infra/tenants/tenant1"


def test_endpoints_api_v1_infra_tenants_00220():
    """
    # Summary

    Verify EpInfraTenantsPut with complex tenant_name

    ## Test

    - tenant_name with special characters is handled correctly

    ## Classes and Methods

    - EpInfraTenantsPut.path
    """
    with does_not_raise():
        instance = EpInfraTenantsPut(tenant_name="my-tenant_123")
    assert instance.path == "/api/v1/infra/tenants/my-tenant_123"


# =============================================================================
# Test: EpInfraTenantsDelete
# =============================================================================


def test_endpoints_api_v1_infra_tenants_00300():
    """
    # Summary

    Verify EpInfraTenantsDelete basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is DELETE

    ## Classes and Methods

    - EpInfraTenantsDelete.__init__()
    - EpInfraTenantsDelete.verb
    - EpInfraTenantsDelete.class_name
    """
    with does_not_raise():
        instance = EpInfraTenantsDelete()
    assert instance.class_name == "EpInfraTenantsDelete"
    assert instance.verb == HttpVerbEnum.DELETE


def test_endpoints_api_v1_infra_tenants_00310():
    """
    # Summary

    Verify EpInfraTenantsDelete path with tenant_name

    ## Test

    - path returns "/api/v1/infra/tenants/tenant1" when tenant_name is set

    ## Classes and Methods

    - EpInfraTenantsDelete.path
    - EpInfraTenantsDelete.tenant_name
    """
    with does_not_raise():
        instance = EpInfraTenantsDelete()
        instance.tenant_name = "tenant1"
        result = instance.path
    assert result == "/api/v1/infra/tenants/tenant1"


def test_endpoints_api_v1_infra_tenants_00320():
    """
    # Summary

    Verify EpInfraTenantsDelete without tenant_name

    ## Test

    - path returns base path when tenant_name is None

    ## Classes and Methods

    - EpInfraTenantsDelete.path
    """
    with does_not_raise():
        instance = EpInfraTenantsDelete()
        result = instance.path
    assert result == "/api/v1/infra/tenants"


# =============================================================================
# Test: All HTTP methods on same endpoint
# =============================================================================


def test_endpoints_api_v1_infra_tenants_00400():
    """
    # Summary

    Verify all HTTP methods work correctly on same resource

    ## Test

    - GET, POST, PUT, DELETE all return correct paths for same tenant_name

    ## Classes and Methods

    - EpInfraTenantsGet
    - EpInfraTenantsPost
    - EpInfraTenantsPut
    - EpInfraTenantsDelete
    """
    tenant_name = "test_tenant"

    with does_not_raise():
        get_ep = EpInfraTenantsGet(tenant_name=tenant_name)
        post_ep = EpInfraTenantsPost(tenant_name=tenant_name)
        put_ep = EpInfraTenantsPut(tenant_name=tenant_name)
        delete_ep = EpInfraTenantsDelete(tenant_name=tenant_name)

    expected_path = "/api/v1/infra/tenants/test_tenant"
    assert get_ep.path == expected_path
    assert post_ep.path == expected_path
    assert put_ep.path == expected_path
    assert delete_ep.path == expected_path

    assert get_ep.verb == HttpVerbEnum.GET
    assert post_ep.verb == HttpVerbEnum.POST
    assert put_ep.verb == HttpVerbEnum.PUT
    assert delete_ep.verb == HttpVerbEnum.DELETE


# =============================================================================
# Test: Pydantic validation
# =============================================================================


def test_endpoints_api_v1_infra_tenants_00500():
    """
    # Summary

    Verify Pydantic validation for tenant_name

    ## Test

    - Empty string is rejected for tenant_name (min_length=1)

    ## Classes and Methods

    - EpInfraTenantsGet.__init__()
    """
    with pytest.raises(ValueError):
        EpInfraTenantsGet(tenant_name="")


def test_endpoints_api_v1_infra_tenants_00510():
    """
    # Summary

    Verify set_identifiers method

    ## Test

    - set_identifiers correctly sets tenant_name

    ## Classes and Methods

    - EpInfraTenantsGet.set_identifiers()
    """
    with does_not_raise():
        instance = EpInfraTenantsGet()
        instance.set_identifiers("my_tenant")
    assert instance.tenant_name == "my_tenant"
    assert instance.path == "/api/v1/infra/tenants/my_tenant"
