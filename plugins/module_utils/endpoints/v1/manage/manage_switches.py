# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Switches endpoint models.

This module contains endpoint definitions for switch-related operations
in the ND Manage API.

## Endpoints

- `EpManageSwitchesListGet` - List switches in a fabric with optional Lucene filtering
  (GET /api/v1/manage/fabrics/{fabric_name}/switches)
- `EpManageSwitchActionsDeploy` - Deploy all pending switch configuration
  (POST /api/v1/manage/fabrics/{fabric_name}/switchActions/deploy)
"""

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import LuceneQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class _EpManageSwitchesBase(FabricNameMixin, NDEndpointBaseModel):
    """
    # Summary

    Base class for ND Manage Switches endpoints.

    Provides common functionality for all HTTP methods on the
    `/api/v1/manage/fabrics/{fabric_name}/switches` endpoint.

    ## Raises

    ### ValueError

    - If `fabric_name` is not set before accessing `path`.
    """

    lucene_params: LuceneQueryParams = Field(default_factory=LuceneQueryParams, description="Lucene-style query parameters for filtering")

    def set_identifiers(self, identifier: IdentifierKey = None):
        """
        # Summary

        Set `fabric_name` from `identifier`.

        ## Raises

        None
        """
        self.fabric_name = identifier

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path for manage switches operations.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        segments = ["fabrics", self.fabric_name, "switches"]
        base_path = BasePath.path(*segments)
        query_string = self.lucene_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path


class EpManageSwitchesListGet(_EpManageSwitchesBase):
    """
    # Summary

    List switches in a fabric with optional Lucene filtering.

    ## Description

    Endpoint to list switches belonging to a specific fabric. Supports Lucene-style filter queries for narrowing results, e.g. filtering by
    `fabricManagementIp` to resolve a switch IP to its serial number / switch ID.

    ## Path

    - `/api/v1/manage/fabrics/{fabric_name}/switches`
    - `/api/v1/manage/fabrics/{fabric_name}/switches?filter=fabricManagementIp%3A192.168.12.151`

    ## Verb

    - GET

    ## Raises

    ### ValueError

    - If `fabric_name` is not set when accessing `path`.

    ## Usage

    ```python
    # List all switches in a fabric
    ep = EpManageSwitchesListGet()
    ep.fabric_name = "fabric_1"
    path = ep.path
    # Path: /api/v1/manage/fabrics/fabric_1/switches

    # Filter switches by management IP
    ep = EpManageSwitchesListGet()
    ep.fabric_name = "fabric_1"
    ep.lucene_params.filter = "fabricManagementIp:192.168.12.151"
    path = ep.path
    # Path: /api/v1/manage/fabrics/fabric_1/switches?filter=fabricManagementIp%3A192.168.12.151
    ```
    """

    class_name: Literal["EpManageSwitchesListGet"] = Field(default="EpManageSwitchesListGet", frozen=True, description="Class name for backward compatibility")

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.GET`.

        ## Raises

        None
        """
        return HttpVerbEnum.GET


class EpManageSwitchActionsDeploy(FabricNameMixin, NDEndpointBaseModel):
    """
    # Summary

    Deploy all pending switch configuration to one or more switches.

    Deploys the full pending configuration for the given switches, including interface, policy, routing, and any other
    staged changes. This is faster than per-interface deploy but has a broader blast radius.

    - Path: `/api/v1/manage/fabrics/{fabric_name}/switchActions/deploy`
    - Verb: POST
    - Body: `{"switchIds": ["serial1", "serial2"]}`

    ## Raises

    ### ValueError

    - Via `path` property if `fabric_name` is not set.
    """

    class_name: Literal["EpManageSwitchActionsDeploy"] = Field(
        default="EpManageSwitchActionsDeploy", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the switch deploy endpoint path.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        return BasePath.path("fabrics", self.fabric_name, "switchActions", "deploy")

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.POST`.

        ## Raises

        None
        """
        return HttpVerbEnum.POST
