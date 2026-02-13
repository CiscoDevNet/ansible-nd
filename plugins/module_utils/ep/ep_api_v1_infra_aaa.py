"""
ND Infra AAA endpoint models.

This module contains endpoint definitions for AAA-related operations
in the ND Infra API.
"""

# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name
__author__ = "Allen Robel"

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.ep.base_paths_infra import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.ep.endpoint_mixins import LoginIdMixin
from ansible_collections.cisco.nd.plugins.module_utils.pydantic_compat import BaseModel, ConfigDict, Field

# Common config for basic validation
COMMON_CONFIG = ConfigDict(validate_assignment=True)


class _EpApiV1InfraAaaLocalUsersBase(LoginIdMixin, BaseModel):
    """
    Base class for ND Infra AAA Local Users endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/infra/aaa/localUsers endpoint.
    """

    model_config = COMMON_CONFIG

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path.

        ## Returns

        - Complete endpoint path string, optionally including login_id
        """
        if self.login_id is not None:
            return BasePath.nd_infra_aaa("localUsers", self.login_id)
        return BasePath.nd_infra_aaa("localUsers")


class EpApiV1InfraAaaLocalUsersGet(_EpApiV1InfraAaaLocalUsersBase):
    """
    # Summary

    ND Infra AAA Local Users GET Endpoint

    ## Description

    Endpoint to retrieve local users from the ND Infra AAA service.
    Optionally retrieve a specific local user by login_id.

    ## Path

    - /api/v1/infra/aaa/localUsers
    - /api/v1/infra/aaa/localUsers/{login_id}

    ## Verb

    - GET

    ## Usage

    ```python
    # Get all local users
    request = EpApiV1InfraAaaLocalUsersGet()
    path = request.path
    verb = request.verb

    # Get specific local user
    request = EpApiV1InfraAaaLocalUsersGet()
    request.login_id = "admin"
    path = request.path
    verb = request.verb
    ```
    """

    class_name: Literal["EpApiV1InfraAaaLocalUsersGet"] = Field(default="EpApiV1InfraAaaLocalUsersGet", description="Class name for backward compatibility")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpApiV1InfraAaaLocalUsersPost(_EpApiV1InfraAaaLocalUsersBase):
    """
    # Summary

    ND Infra AAA Local Users POST Endpoint

    ## Description

    Endpoint to create a local user in the ND Infra AAA service.

    ## Path

    - /api/v1/infra/aaa/localUsers

    ## Verb

    - POST

    ## Usage

    ```python
    request = EpApiV1InfraAaaLocalUsersPost()
    path = request.path
    verb = request.verb
    ```
    """

    class_name: Literal["EpApiV1InfraAaaLocalUsersPost"] = Field(default="EpApiV1InfraAaaLocalUsersPost", description="Class name for backward compatibility")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class EpApiV1InfraAaaLocalUsersPut(_EpApiV1InfraAaaLocalUsersBase):
    """
    # Summary

    ND Infra AAA Local Users PUT Endpoint

    ## Description

    Endpoint to update a local user in the ND Infra AAA service.

    ## Path

    - /api/v1/infra/aaa/localUsers/{login_id}

    ## Verb

    - PUT

    ## Usage

    ```python
    request = EpApiV1InfraAaaLocalUsersPut()
    request.login_id = "admin"
    path = request.path
    verb = request.verb
    ```
    """

    class_name: Literal["EpApiV1InfraAaaLocalUsersPut"] = Field(default="EpApiV1InfraAaaLocalUsersPut", description="Class name for backward compatibility")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.PUT


class EpApiV1InfraAaaLocalUsersDelete(_EpApiV1InfraAaaLocalUsersBase):
    """
    # Summary

    ND Infra AAA Local Users DELETE Endpoint

    ## Description

    Endpoint to delete a local user from the ND Infra AAA service.

    ## Path

    - /api/v1/infra/aaa/localUsers/{login_id}

    ## Verb

    - DELETE

    ## Usage

    ```python
    request = EpApiV1InfraAaaLocalUsersDelete()
    request.login_id = "admin"
    path = request.path
    verb = request.verb
    ```
    """

    class_name: Literal["EpApiV1InfraAaaLocalUsersDelete"] = Field(
        default="EpApiV1InfraAaaLocalUsersDelete", description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.DELETE
