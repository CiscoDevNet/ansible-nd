# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Infra AAA Local Users endpoint models.

This module contains endpoint definitions for AAA Local Users operations in the ND Infra API.
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import Literal
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import LoginIdMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra.base_path import BasePath

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class _EpInfraAaaLocalUsersBase(LoginIdMixin, NDEndpointBaseModel):
    """
    Base class for ND Infra AAA Local Users endpoints.

    Provides common functionality for all HTTP methods on the /api/v1/infra/aaa/localUsers endpoint.
    """

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path.

        ## Returns

        - Complete endpoint path string, optionally including login_id
        """
        if self.login_id is not None:
            return BasePath.path("aaa", "localUsers", self.login_id)
        return BasePath.path("aaa", "localUsers")

    def set_identifiers(self, identifier: IdentifierKey = None):
        self.login_id = identifier


class EpInfraAaaLocalUsersGet(_EpInfraAaaLocalUsersBase):
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

    class_name: Literal["EpInfraAaaLocalUsersGet"] = Field(default="EpInfraAaaLocalUsersGet", frozen=True, description="Class name for backward compatibility")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpInfraAaaLocalUsersPost(_EpInfraAaaLocalUsersBase):
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

    class_name: Literal["EpInfraAaaLocalUsersPost"] = Field(
        default="EpInfraAaaLocalUsersPost", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class EpInfraAaaLocalUsersPut(_EpInfraAaaLocalUsersBase):
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

    class_name: Literal["EpInfraAaaLocalUsersPut"] = Field(default="EpInfraAaaLocalUsersPut", frozen=True, description="Class name for backward compatibility")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.PUT


class EpInfraAaaLocalUsersDelete(_EpInfraAaaLocalUsersBase):
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

    class_name: Literal["EpInfraAaaLocalUsersDelete"] = Field(
        default="EpInfraAaaLocalUsersDelete", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.DELETE
