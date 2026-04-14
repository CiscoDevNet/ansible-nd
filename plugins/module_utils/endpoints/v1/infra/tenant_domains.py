# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Infra Tenant Domains endpoint models.

This module contains endpoint definitions for Tenant Domain operations in the ND Infra API.
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import Literal, Optional
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BaseModel,
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class TenantDomainNameMixin(BaseModel):
    """Mixin for endpoints that require tenant_domain_name parameter."""

    tenant_domain_name: Optional[str] = Field(default=None, min_length=1, max_length=63, description="Tenant domain name")


class _EpInfraTenantDomainsBase(TenantDomainNameMixin, NDEndpointBaseModel):
    """
    Base class for ND Infra Tenant Domains endpoints.

    Provides common functionality for all HTTP methods on the /api/v1/infra/tenantDomains endpoint.
    """

    @property
    def path(self) -> str:
        """
        # Summary

        Build the /api/v1/infra/tenantDomains endpoint path.

        ## Returns

        - Complete endpoint path string, optionally including tenant_domain_name
        """
        if self.tenant_domain_name is not None:
            return BasePath.path("tenantDomains", self.tenant_domain_name)
        return BasePath.path("tenantDomains")

    def set_identifiers(self, identifier: IdentifierKey = None):
        self.tenant_domain_name = identifier


class EpInfraTenantDomainsGet(_EpInfraTenantDomainsBase):
    """
    # Summary

    ND Infra Tenant Domains GET Endpoint

    ## Description

    Endpoint to retrieve tenant domains from the ND Infra service.
    Optionally retrieve a specific tenant domain by name.

    ## Path

    - /api/v1/infra/tenantDomains
    - /api/v1/infra/tenantDomains/{tenantDomainName}

    ## Verb

    - GET
    """

    class_name: Literal["EpInfraTenantDomainsGet"] = Field(
        default="EpInfraTenantDomainsGet", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpInfraTenantDomainsPost(_EpInfraTenantDomainsBase):
    """
    # Summary

    ND Infra Tenant Domains POST Endpoint

    ## Description

    Endpoint to create a tenant domain in the ND Infra service.

    ## Path

    - /api/v1/infra/tenantDomains

    ## Verb

    - POST
    """

    class_name: Literal["EpInfraTenantDomainsPost"] = Field(
        default="EpInfraTenantDomainsPost", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class EpInfraTenantDomainsPut(_EpInfraTenantDomainsBase):
    """
    # Summary

    ND Infra Tenant Domains PUT Endpoint

    ## Description

    Endpoint to update a tenant domain in the ND Infra service.

    ## Path

    - /api/v1/infra/tenantDomains/{tenantDomainName}

    ## Verb

    - PUT
    """

    class_name: Literal["EpInfraTenantDomainsPut"] = Field(
        default="EpInfraTenantDomainsPut", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.PUT


class EpInfraTenantDomainsDelete(_EpInfraTenantDomainsBase):
    """
    # Summary

    ND Infra Tenant Domains DELETE Endpoint

    ## Description

    Endpoint to delete a tenant domain from the ND Infra service.

    ## Path

    - /api/v1/infra/tenantDomains/{tenantDomainName}

    ## Verb

    - DELETE
    """

    class_name: Literal["EpInfraTenantDomainsDelete"] = Field(
        default="EpInfraTenantDomainsDelete", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.DELETE
