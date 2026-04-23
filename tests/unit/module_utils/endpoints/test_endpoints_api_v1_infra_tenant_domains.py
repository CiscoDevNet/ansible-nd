# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for infra tenant_domains endpoints.

Tests the ND Infra Tenant Domains endpoint classes
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra.tenant_domains import (
    EpInfraTenantDomainsDelete,
    EpInfraTenantDomainsGet,
    EpInfraTenantDomainsPost,
    EpInfraTenantDomainsPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: EpInfraTenantDomainsGet
# =============================================================================


def test_endpoints_api_v1_infra_tenant_domains_00010():
    """
    # Summary

    Verify EpInfraTenantDomainsGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpInfraTenantDomainsGet.__init__()
    - EpInfraTenantDomainsGet.verb
    - EpInfraTenantDomainsGet.class_name
    """
    with does_not_raise():
        instance = EpInfraTenantDomainsGet()
    assert instance.class_name == "EpInfraTenantDomainsGet"
    assert instance.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_infra_tenant_domains_00020():
    """
    # Summary

    Verify EpInfraTenantDomainsGet path without tenant_domain_name

    ## Test

    - path returns "/api/v1/infra/tenantDomains" when tenant_domain_name is None

    ## Classes and Methods

    - EpInfraTenantDomainsGet.path
    """
    with does_not_raise():
        instance = EpInfraTenantDomainsGet()
        result = instance.path
    assert result == "/api/v1/infra/tenantDomains"


def test_endpoints_api_v1_infra_tenant_domains_00030():
    """
    # Summary

    Verify EpInfraTenantDomainsGet path with tenant_domain_name

    ## Test

    - path returns "/api/v1/infra/tenantDomains/myDomain" when tenant_domain_name is set

    ## Classes and Methods

    - EpInfraTenantDomainsGet.path
    - EpInfraTenantDomainsGet.tenant_domain_name
    """
    with does_not_raise():
        instance = EpInfraTenantDomainsGet()
        instance.tenant_domain_name = "myDomain"
        result = instance.path
    assert result == "/api/v1/infra/tenantDomains/myDomain"


def test_endpoints_api_v1_infra_tenant_domains_00040():
    """
    # Summary

    Verify EpInfraTenantDomainsGet tenant_domain_name can be set at instantiation

    ## Test

    - tenant_domain_name can be provided during instantiation

    ## Classes and Methods

    - EpInfraTenantDomainsGet.__init__()
    """
    with does_not_raise():
        instance = EpInfraTenantDomainsGet(tenant_domain_name="infraDomain")
    assert instance.tenant_domain_name == "infraDomain"
    assert instance.path == "/api/v1/infra/tenantDomains/infraDomain"


# =============================================================================
# Test: EpInfraTenantDomainsPost
# =============================================================================


def test_endpoints_api_v1_infra_tenant_domains_00100():
    """
    # Summary

    Verify EpInfraTenantDomainsPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpInfraTenantDomainsPost.__init__()
    - EpInfraTenantDomainsPost.verb
    - EpInfraTenantDomainsPost.class_name
    """
    with does_not_raise():
        instance = EpInfraTenantDomainsPost()
    assert instance.class_name == "EpInfraTenantDomainsPost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_infra_tenant_domains_00110():
    """
    # Summary

    Verify EpInfraTenantDomainsPost path

    ## Test

    - path returns "/api/v1/infra/tenantDomains" for POST

    ## Classes and Methods

    - EpInfraTenantDomainsPost.path
    """
    with does_not_raise():
        instance = EpInfraTenantDomainsPost()
        result = instance.path
    assert result == "/api/v1/infra/tenantDomains"


def test_endpoints_api_v1_infra_tenant_domains_00120():
    """
    # Summary

    Verify EpInfraTenantDomainsPost path with tenant_domain_name

    ## Test

    - path returns "/api/v1/infra/tenantDomains/myDomain" when tenant_domain_name is set

    ## Classes and Methods

    - EpInfraTenantDomainsPost.path
    - EpInfraTenantDomainsPost.tenant_domain_name
    """
    with does_not_raise():
        instance = EpInfraTenantDomainsPost()
        instance.tenant_domain_name = "myDomain"
        result = instance.path
    assert result == "/api/v1/infra/tenantDomains/myDomain"


# =============================================================================
# Test: EpInfraTenantDomainsPut
# =============================================================================


def test_endpoints_api_v1_infra_tenant_domains_00200():
    """
    # Summary

    Verify EpInfraTenantDomainsPut basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is PUT

    ## Classes and Methods

    - EpInfraTenantDomainsPut.__init__()
    - EpInfraTenantDomainsPut.verb
    - EpInfraTenantDomainsPut.class_name
    """
    with does_not_raise():
        instance = EpInfraTenantDomainsPut()
    assert instance.class_name == "EpInfraTenantDomainsPut"
    assert instance.verb == HttpVerbEnum.PUT


def test_endpoints_api_v1_infra_tenant_domains_00210():
    """
    # Summary

    Verify EpInfraTenantDomainsPut path with tenant_domain_name

    ## Test

    - path returns "/api/v1/infra/tenantDomains/myDomain" when tenant_domain_name is set

    ## Classes and Methods

    - EpInfraTenantDomainsPut.path
    - EpInfraTenantDomainsPut.tenant_domain_name
    """
    with does_not_raise():
        instance = EpInfraTenantDomainsPut()
        instance.tenant_domain_name = "myDomain"
        result = instance.path
    assert result == "/api/v1/infra/tenantDomains/myDomain"


def test_endpoints_api_v1_infra_tenant_domains_00220():
    """
    # Summary

    Verify EpInfraTenantDomainsPut with complex tenant_domain_name

    ## Test

    - tenant_domain_name with special characters is handled correctly

    ## Classes and Methods

    - EpInfraTenantDomainsPut.path
    """
    with does_not_raise():
        instance = EpInfraTenantDomainsPut(tenant_domain_name="my-domain_123")
    assert instance.path == "/api/v1/infra/tenantDomains/my-domain_123"


# =============================================================================
# Test: EpInfraTenantDomainsDelete
# =============================================================================


def test_endpoints_api_v1_infra_tenant_domains_00300():
    """
    # Summary

    Verify EpInfraTenantDomainsDelete basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is DELETE

    ## Classes and Methods

    - EpInfraTenantDomainsDelete.__init__()
    - EpInfraTenantDomainsDelete.verb
    - EpInfraTenantDomainsDelete.class_name
    """
    with does_not_raise():
        instance = EpInfraTenantDomainsDelete()
    assert instance.class_name == "EpInfraTenantDomainsDelete"
    assert instance.verb == HttpVerbEnum.DELETE


def test_endpoints_api_v1_infra_tenant_domains_00310():
    """
    # Summary

    Verify EpInfraTenantDomainsDelete path with tenant_domain_name

    ## Test

    - path returns "/api/v1/infra/tenantDomains/myDomain" when tenant_domain_name is set

    ## Classes and Methods

    - EpInfraTenantDomainsDelete.path
    - EpInfraTenantDomainsDelete.tenant_domain_name
    """
    with does_not_raise():
        instance = EpInfraTenantDomainsDelete()
        instance.tenant_domain_name = "myDomain"
        result = instance.path
    assert result == "/api/v1/infra/tenantDomains/myDomain"


def test_endpoints_api_v1_infra_tenant_domains_00320():
    """
    # Summary

    Verify EpInfraTenantDomainsDelete without tenant_domain_name

    ## Test

    - path returns base path when tenant_domain_name is None

    ## Classes and Methods

    - EpInfraTenantDomainsDelete.path
    """
    with does_not_raise():
        instance = EpInfraTenantDomainsDelete()
        result = instance.path
    assert result == "/api/v1/infra/tenantDomains"


# =============================================================================
# Test: All HTTP methods on same endpoint
# =============================================================================


def test_endpoints_api_v1_infra_tenant_domains_00400():
    """
    # Summary

    Verify all HTTP methods work correctly on same resource

    ## Test

    - GET, POST, PUT, DELETE all return correct paths for same tenant_domain_name

    ## Classes and Methods

    - EpInfraTenantDomainsGet
    - EpInfraTenantDomainsPost
    - EpInfraTenantDomainsPut
    - EpInfraTenantDomainsDelete
    """
    domain_name = "test_domain"

    with does_not_raise():
        get_ep = EpInfraTenantDomainsGet(tenant_domain_name=domain_name)
        post_ep = EpInfraTenantDomainsPost(tenant_domain_name=domain_name)
        put_ep = EpInfraTenantDomainsPut(tenant_domain_name=domain_name)
        delete_ep = EpInfraTenantDomainsDelete(tenant_domain_name=domain_name)

    expected_path = "/api/v1/infra/tenantDomains/test_domain"
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


def test_endpoints_api_v1_infra_tenant_domains_00500():
    """
    # Summary

    Verify Pydantic validation for tenant_domain_name

    ## Test

    - Empty string is rejected for tenant_domain_name (min_length=1)

    ## Classes and Methods

    - EpInfraTenantDomainsGet.__init__()
    """
    with pytest.raises(ValueError):
        EpInfraTenantDomainsGet(tenant_domain_name="")


def test_endpoints_api_v1_infra_tenant_domains_00510():
    """
    # Summary

    Verify set_identifiers method

    ## Test

    - set_identifiers correctly sets tenant_domain_name

    ## Classes and Methods

    - EpInfraTenantDomainsGet.set_identifiers()
    """
    with does_not_raise():
        instance = EpInfraTenantDomainsGet()
        instance.set_identifiers("my_domain")
    assert instance.tenant_domain_name == "my_domain"
    assert instance.path == "/api/v1/infra/tenantDomains/my_domain"
