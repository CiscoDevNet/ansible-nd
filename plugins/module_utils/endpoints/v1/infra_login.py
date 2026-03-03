# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Infra Login endpoint model.

This module contains the endpoint definition for the ND Infra login operation.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.base_paths_infra import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.pydantic_compat import (
    BaseModel,
    ConfigDict,
    Field,
)


class EpInfraLoginPost(BaseModel):
    """
    # Summary

    ND Infra Login POST Endpoint

    ## Description

    Endpoint to authenticate against the ND Infra login service.

    ## Path

    - /api/v1/infra/login

    ## Verb

    - POST

    ## Usage

    ```python
    request = EpInfraLoginPost()
    path = request.path
    verb = request.verb
    ```

    ## Raises

    None
    """

    model_config = ConfigDict(validate_assignment=True)

    api_version: Literal["v1"] = Field(default="v1", description="ND API version for this endpoint")
    min_controller_version: str = Field(default="3.0.0", description="Minimum ND version supporting this endpoint")
    class_name: Literal["EpInfraLoginPost"] = Field(default="EpInfraLoginPost", description="Class name for backward compatibility")

    @property
    def path(self) -> str:
        """
        # Summary

        Return the endpoint path.

        ## Returns

        - Complete endpoint path string

        ## Raises

        None
        """
        return BasePath.nd_infra("login")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
