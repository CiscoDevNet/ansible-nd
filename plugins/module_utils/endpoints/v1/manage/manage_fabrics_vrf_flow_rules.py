# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric VRF Flow Rules endpoint models.

This module contains endpoint definitions for VRF flow rule operations
within fabrics in the ND Manage API. These endpoints are ACI fabric specific.

Endpoints covered:
- List ACI tenant flow telemetry VRF rules
- List ACI fabric flow telemetry VRF rules
"""

from __future__ import annotations

__author__ = "Akshayanat C S"


from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    FabricNameMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)

# ============================================================================
# Endpoint-specific query parameter classes
# ============================================================================


class VrfFlowRulesNoParamsEndpointParams(EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for VRF flow rules endpoints that accept no extra query parameters.

    ## Usage

    ```python
    params = VrfFlowRulesNoParamsEndpointParams()
    query_string = params.to_query_string()
    # Returns: ""
    ```
    """


class VrfFlowRulesVrfsEndpointParams(EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for the VRF flow rules VRFs endpoint.

    ## Parameters

    - tenant_name: ACI tenant name to filter VRFs by (optional)

    ## Usage

    ```python
    params = VrfFlowRulesVrfsEndpointParams(tenant_name="MyTenant")
    query_string = params.to_query_string()
    # Returns: "tenantName=MyTenant"
    ```
    """

    tenant_name: str | None = Field(default=None, min_length=1, description="ACI tenant name")


# ============================================================================
# VRF Flow Rules Endpoints
# ============================================================================


class _EpManageFabricsVrfFlowRulesBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for Fabric VRF Flow Rules endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics/{fabricName}/vrfFlowRules endpoint.
    """

    @property
    def _base_path(self) -> str:
        """Build the base endpoint path."""
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "vrfFlowRules")


class EpManageFabricsVrfFlowRulesTenantsGet(_EpManageFabricsVrfFlowRulesBase):
    """
    # Summary

    List ACI Tenant Flow Telemetry VRF Rules Endpoint

    ## Description

    Endpoint to list all the tenants for a given fabric. ACI only.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfFlowRules/tenants

    ## Verb

    - GET

    ## Usage

    ```python
    # List ACI tenant flow telemetry VRF rules
    request = EpManageFabricsVrfFlowRulesTenantsGet()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfFlowRules/tenants
    ```
    """

    class_name: Literal["EpManageFabricsVrfFlowRulesTenantsGet"] = Field(
        default="EpManageFabricsVrfFlowRulesTenantsGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfFlowRulesNoParamsEndpointParams = Field(
        default_factory=VrfFlowRulesNoParamsEndpointParams,
        description="Endpoint-specific query parameters",
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path.

        ## Returns

        - Complete endpoint path string
        """
        return f"{self._base_path}/tenants"

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpManageFabricsVrfFlowRulesVrfsGet(_EpManageFabricsVrfFlowRulesBase):
    """
    # Summary

    List ACI Fabric Flow Telemetry VRF Rules Endpoint

    ## Description

    Endpoint to list all the VRFs under a specified tenant for a given fabric. ACI only.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfFlowRules/vrfs
    - /api/v1/manage/fabrics/{fabricName}/vrfFlowRules/vrfs?tenantName=MyTenant

    ## Verb

    - GET

    ## Query Parameters

    - tenant_name: ACI tenant name to filter VRFs by (optional)

    ## Usage

    ```python
    # List ACI fabric flow telemetry VRF rules
    request = EpManageFabricsVrfFlowRulesVrfsGet()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # List with tenant filter
    request = EpManageFabricsVrfFlowRulesVrfsGet()
    request.fabric_name = "MyFabric"
    request.endpoint_params.tenant_name = "MyTenant"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfFlowRules/vrfs?tenantName=MyTenant
    ```
    """

    class_name: Literal["EpManageFabricsVrfFlowRulesVrfsGet"] = Field(
        default="EpManageFabricsVrfFlowRulesVrfsGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfFlowRulesVrfsEndpointParams = Field(
        default_factory=VrfFlowRulesVrfsEndpointParams,
        description="Endpoint-specific query parameters",
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional query string.

        ## Returns

        - Complete endpoint path string, optionally including query parameters
        """
        base = f"{self._base_path}/vrfs"
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base}?{query_string}"
        return base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET
