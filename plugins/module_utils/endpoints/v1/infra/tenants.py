# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Infra Tenants endpoint models.

This module contains endpoint definitions for Tenant operations in the ND Infra API.
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


class TenantNameMixin(BaseModel):
    """Mixin for endpoints that require tenant_name parameter."""

    tenant_name: Optional[str] = Field(default=None, min_length=1, max_length=63, description="Tenant name")


class _EpInfraTenantsBase(TenantNameMixin, NDEndpointBaseModel):
    """
    Base class for ND Infra Tenants endpoints.

    Provides common functionality for all HTTP methods on the /api/v1/infra/tenants endpoint.
    """

    @property
    def path(self) -> str:
        """
        # Summary

        Build the /api/v1/infra/tenants endpoint path.

        ## Returns

        - Complete endpoint path string, optionally including tenant_name
        """
        if self.tenant_name is not None:
            return BasePath.path("tenants", self.tenant_name)
        return BasePath.path("tenants")

    def set_identifiers(self, identifier: IdentifierKey = None):
        self.tenant_name = identifier


class EpInfraTenantsGet(_EpInfraTenantsBase):
    """
    # Summary

    ND Infra Tenants GET Endpoint

    ## Description

    Endpoint to retrieve tenants from the ND Infra service.
    Optionally retrieve a specific tenant by name.

    ## Path

    - /api/v1/infra/tenants
    - /api/v1/infra/tenants/{tenantName}

    ## Verb

    - GET
    """

    class_name: Literal["EpInfraTenantsGet"] = Field(default="EpInfraTenantsGet", frozen=True, description="Class name for backward compatibility")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpInfraTenantsPost(_EpInfraTenantsBase):
    """
    # Summary

    ND Infra Tenants POST Endpoint

    ## Description

    Endpoint to create a tenant in the ND Infra service.

    ## Path

    - /api/v1/infra/tenants

    ## Verb

    - POST
    """

    class_name: Literal["EpInfraTenantsPost"] = Field(default="EpInfraTenantsPost", frozen=True, description="Class name for backward compatibility")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class EpInfraTenantsPut(_EpInfraTenantsBase):
    """
    # Summary

    ND Infra Tenants PUT Endpoint

    ## Description

    Endpoint to update a tenant in the ND Infra service.

    ## Path

    - /api/v1/infra/tenants/{tenantName}

    ## Verb

    - PUT
    """

    class_name: Literal["EpInfraTenantsPut"] = Field(default="EpInfraTenantsPut", frozen=True, description="Class name for backward compatibility")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.PUT


class EpInfraTenantsDelete(_EpInfraTenantsBase):
    """
    # Summary

    ND Infra Tenants DELETE Endpoint

    ## Description

    Endpoint to delete a tenant from the ND Infra service.

    ## Path

    - /api/v1/infra/tenants/{tenantName}

    ## Verb

    - DELETE
    """

    class_name: Literal["EpInfraTenantsDelete"] = Field(default="EpInfraTenantsDelete", frozen=True, description="Class name for backward compatibility")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.DELETE
