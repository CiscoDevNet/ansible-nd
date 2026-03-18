# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat Chengam Saravanan (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric Discovery endpoint models.

This module contains endpoint definitions for switch discovery operations
within fabrics in the ND Manage API.

Endpoints covered:
- Shallow discovery
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
__author__ = "Akshayanat Chengam Saravanan"
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


class _EpManageFabricDiscoveryBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for Fabric Discovery endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics/{fabricName}/actions/shallowDiscovery endpoint.
    """

    @property
    def _base_path(self) -> str:
        """Build the base endpoint path."""
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "actions", "shallowDiscovery")


class EpManageFabricShallowDiscoveryPost(_EpManageFabricDiscoveryBase):
    """
    # Summary

    Shallow Discovery Endpoint

    ## Description

    Endpoint to shallow discover switches given seed switches with hop count.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/actions/shallowDiscovery

    ## Verb

    - POST

    ## Usage

    ```python
    request = EpManageFabricShallowDiscoveryPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb
    ```
    """

    class_name: Literal["EpManageFabricShallowDiscoveryPost"] = Field(
        default="EpManageFabricShallowDiscoveryPost", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """Build the endpoint path."""
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
