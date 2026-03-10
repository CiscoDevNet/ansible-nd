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

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class EpInfraLoginPost(NDEndpointBaseModel):
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
        return BasePath.path("login")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
