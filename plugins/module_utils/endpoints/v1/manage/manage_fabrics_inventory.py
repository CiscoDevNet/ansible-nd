# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabrics Inventory endpoint models.

This module contains endpoint definitions for fabric inventory operations
in the ND Manage API.

Endpoints covered:
- Inventory discover status
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
__author__ = "Akshayanat C S"
# pylint: enable=invalid-name

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    FabricNameMixin,
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


class _EpManageFabricsInventoryBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for Fabric Inventory endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics/{fabricName}/inventory endpoint family.
    """

    @property
    def _base_path(self) -> str:
        """Build the base endpoint path."""
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name)


class EpManageFabricsInventoryDiscoverGet(_EpManageFabricsInventoryBase):
    """
    # Summary

    Fabric Inventory Discover Endpoint

    ## Description

    Endpoint to get discovery status for switches in a fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/inventory/discover

    ## Verb

    - GET

    ## Usage

    ```python
    request = EpManageFabricsInventoryDiscoverGet()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb
    ```
    """

    class_name: Literal["EpManageFabricsInventoryDiscoverGet"] = Field(
        default="EpManageFabricsInventoryDiscoverGet", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """Build the endpoint path."""
        return f"{self._base_path}/inventory/discover"

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET
