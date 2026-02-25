# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Switches endpoint models.

This module contains endpoint definitions for switch-related operations
in the ND Manage API.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from typing import Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.ep.base_paths_manage import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.ep.query_params import CompositeQueryParams, EndpointQueryParams, LuceneQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.pydantic_compat import BaseModel, ConfigDict, Field

# Common config for basic validation
COMMON_CONFIG = ConfigDict(validate_assignment=True)


class SwitchesEndpointParams(EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for switches endpoint.

    ## Parameters

    - fabric_name: Name of the fabric (optional, max 64 chars)
    - switch_id: Serial Number or Id of the switch/leaf (optional)
    - hostname: Name of the hostname (optional)

    ## Usage

    ```python
    params = SwitchesEndpointParams(fabric_name="fabric1", switch_id="101")
    query_string = params.to_query_string()
    # Returns: "fabricName=fabric1&switchId=101"
    ```
    """
    model_config = COMMON_CONFIG

    fabric_name: Optional[str] = Field(default=None, min_length=1, max_length=64, description="Name of the fabric")
    switch_id: Optional[str] = Field(default=None, min_length=1, description="Serial Number or Id of the switch/leaf")
    hostname: Optional[str] = Field(default=None, min_length=1, description="Name of the hostname")


class EpApiV1ManageSwitchesGet(BaseModel):
    """
    # Summary

    ND Manage Inventory Switches GET Endpoint

    ## Description

    Endpoint to retrieve switches globally from the ND Manage service.
    Supports both endpoint-specific parameters (fabric_name, switch_id, hostname)
    and Lucene-style filtering (filter, max, offset, sort).

    ## Path

    - /api/v1/manage/inventory/switches
    - /api/v1/manage/inventory/switches?fabricName=fabric1
    - /api/v1/manage/inventory/switches?switchId=101
    - /api/v1/manage/inventory/switches?hostname=switch1
    - /api/v1/manage/inventory/switches?filter=prop1:value1 AND prop2:value2
    - /api/v1/manage/inventory/switches?fabricName=fabric1&max=10&offset=0&sort=hostname:asc

    ## Verb

    - GET

    ## Usage

    ```python
    # Get all switches globally
    request = EpApiV1ManageSwitchesGet()
    path = request.path
    verb = request.verb

    # Get switches for specific fabric
    request = EpApiV1ManageSwitchesGet()
    request.endpoint_params.fabric_name = "fabric1"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/inventory/switches?fabricName=fabric1

    # Get switch by ID
    request = EpApiV1ManageSwitchesGet()
    request.endpoint_params.switch_id = "101"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/inventory/switches?switchId=101

    # Get switches with pagination and sorting
    request = EpApiV1ManageSwitchesGet()
    request.lucene_params.max = 10
    request.lucene_params.offset = 0
    request.lucene_params.sort = "hostname:asc"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/inventory/switches?max=10&offset=0&sort=hostname:asc

    # Get switches with complex filter
    request = EpApiV1ManageSwitchesGet()
    request.endpoint_params.fabric_name = "fabric1"
    request.lucene_params.filter = "role:leaf AND status:active"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/inventory/switches?fabricName=fabric1&filter=role:leaf AND status:active

    # Combine endpoint params and Lucene params
    request = EpApiV1ManageSwitchesGet()
    request.endpoint_params.fabric_name = "fabric1"
    request.endpoint_params.hostname = "switch1"
    request.lucene_params.filter = "role:leaf"
    request.lucene_params.max = 50
    request.lucene_params.sort = "hostname:asc"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/inventory/switches?fabricName=fabric1&hostname=switch1&filter=role:leaf&max=50&sort=hostname:asc
    ```
    """

    model_config = COMMON_CONFIG

    endpoint_params: SwitchesEndpointParams = Field(default_factory=SwitchesEndpointParams, description="Endpoint-specific query parameters")
    lucene_params: LuceneQueryParams = Field(default_factory=LuceneQueryParams, description="Lucene-style filtering query parameters")

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional query string.

        ## Returns

        - Complete endpoint path string, optionally including query parameters
        """
        base_path = BasePath.nd_manage_inventory("switches")

        # Build composite query string
        composite = CompositeQueryParams()
        composite.add(self.endpoint_params)
        composite.add(self.lucene_params)

        query_string = composite.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET
