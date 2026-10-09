# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Tenant Fabric Associations endpoint models.

This module contains endpoint definitions for Tenant Fabric Association
operations in the ND Manage API.

## Endpoints

- `EpManageTenantFabricAssociationsGet` - List all tenant fabric associations
  (GET /api/v1/manage/tenantFabricAssociations)
- `EpManageTenantFabricAssociationsPost` - Create or delete tenant fabric associations
  (POST /api/v1/manage/tenantFabricAssociations)
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import Literal
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class _EpManageTenantFabricAssociationsBase(NDEndpointBaseModel):
    """
    Base class for ND Manage Tenant Fabric Associations endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/tenantFabricAssociations endpoint.
    """

    @property
    def path(self) -> str:
        """
        # Summary

        Build the /api/v1/manage/tenantFabricAssociations endpoint path.

        ## Returns

        - Complete endpoint path string
        """
        return BasePath.path("tenantFabricAssociations")

    def set_identifiers(self, identifier: IdentifierKey = None):
        pass


class EpManageTenantFabricAssociationsGet(_EpManageTenantFabricAssociationsBase):
    """
    # Summary

    ND Manage Tenant Fabric Associations GET Endpoint

    ## Description

    Endpoint to retrieve all tenant fabric associations from the ND Manage service.

    ## Path

    - /api/v1/manage/tenantFabricAssociations

    ## Verb

    - GET
    """

    class_name: Literal["EpManageTenantFabricAssociationsGet"] = Field(
        default="EpManageTenantFabricAssociationsGet", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpManageTenantFabricAssociationsPost(_EpManageTenantFabricAssociationsBase):
    """
    # Summary

    ND Manage Tenant Fabric Associations POST Endpoint

    ## Description

    Endpoint to create or delete tenant fabric associations in the ND Manage service.
    The request body contains an 'items' array where each item includes an 'associate'
    boolean flag (true = create, false = delete).

    ## Path

    - /api/v1/manage/tenantFabricAssociations

    ## Verb

    - POST
    """

    class_name: Literal["EpManageTenantFabricAssociationsPost"] = Field(
        default="EpManageTenantFabricAssociationsPost", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
