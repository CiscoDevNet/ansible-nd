# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Switches endpoint models.

This module contains endpoint definitions for switch query operations
in the ND Manage API.
"""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BaseModel,
    ConfigDict,
    Field,
)

# Common config for basic validation
COMMON_CONFIG = ConfigDict(validate_assignment=True)


class EpManageFabricSwitchesGet(BaseModel):
    """
    # Summary

    ND Manage Fabrics Switches GET Endpoint

    ## Description

    Endpoint to retrieve all switches for the given fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/switches
    - /api/v1/manage/fabrics/{fabricName}/switches?max=10000

    ## Verb

    - GET

    ## Usage

    ```python
    ep = EpManageFabricSwitchesGet(fabric_name="fabric1")
    path = ep.path
    verb = ep.verb
    # Path will be: /api/v1/manage/fabrics/fabric1/switches?max=10000

    ep = EpManageFabricSwitchesGet(fabric_name="fabric1", max=500)
    path = ep.path
    # Path will be: /api/v1/manage/fabrics/fabric1/switches?max=500
    ```
    """

    model_config = COMMON_CONFIG

    fabric_name: str = Field(min_length=1, max_length=64, description="Name of the fabric")
    max: int = Field(default=10000, ge=1, description="Maximum number of switches to return")

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with max query parameter.

        ## Returns

        - Complete endpoint path string including max query parameter
        """
        base_path = BasePath.path("fabrics", self.fabric_name, "switches")
        return f"{base_path}?max={self.max}"

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET
