
# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Switches endpoint models.

This module contains endpoint definitions for switch query operations
in the ND Manage API.
"""

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BaseModel,
    ConfigDict,
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    FabricNameMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    LuceneQueryParams,
)

# Common config for basic validation
COMMON_CONFIG = ConfigDict(validate_assignment=True)


class EpManageFabricSwitchesGet(FabricNameMixin, LuceneQueryParams, NDEndpointBaseModel):
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

    class_name: Literal["EpManageFabricSwitchesGet"] = Field(
        default="EpManageFabricSwitchesGet", description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional query string.

        ## Returns

        - Complete endpoint path string, optionally including query parameters
        """
        base_path = BasePath.path("fabrics", self.fabric_name, "switches")
        query_string = self.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET
