# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>
# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Infra AAA LocalUsers endpoint models.

This module contains endpoint definitions for LocalUsers-related operations
in the ND Infra AAA API.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import Literal, Final
from ansible_collections.cisco.nd.plugins.module_utils.api_endpoints.mixins import LoginIdMixin
from ansible_collections.cisco.nd.plugins.module_utils.api_endpoints.enums import VerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.api_endpoints.base import NDBaseSmartEndpoint, NDBasePath
from pydantic import Field
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class _EpApiV1InfraAaaLocalUsersBase(LoginIdMixin, NDBaseSmartEndpoint):
    """
    Base class for ND Infra AAA Local Users endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/infra/aaa/localUsers endpoint.
    """

    # TODO: Remove it
    base_path: Final = NDBasePath.nd_infra_aaa("localUsers")

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path.

        ## Returns

        - Complete endpoint path string, optionally including login_id
        """
        if self.login_id is not None:
            return NDBasePath.nd_infra_aaa("localUsers", self.login_id)
        return self.base_path

    def set_identifiers(self, identifier: IdentifierKey = None):
        self.login_id = identifier


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
    """

    class_name: Literal["EpApiV1InfraAaaLocalUsersGet"] = Field(
        default="EpApiV1InfraAaaLocalUsersGet",
        description="Class name for backward compatibility",
        frozen=True,
    )

    @property
    def verb(self) -> VerbEnum:
        """Return the HTTP verb for this endpoint."""
        return VerbEnum.GET


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
    """

    class_name: Literal["EpApiV1InfraAaaLocalUsersPost"] = Field(
        default="EpApiV1InfraAaaLocalUsersPost",
        description="Class name for backward compatibility",
        frozen=True,
    )

    @property
    def verb(self) -> VerbEnum:
        """Return the HTTP verb for this endpoint."""
        return VerbEnum.POST


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
    """

    class_name: Literal["EpApiV1InfraAaaLocalUsersPut"] = Field(
        default="EpApiV1InfraAaaLocalUsersPut",
        description="Class name for backward compatibility",
        frozen=True,
    )

    @property
    def verb(self) -> VerbEnum:
        """Return the HTTP verb for this endpoint."""
        return VerbEnum.PUT


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
    """

    class_name: Literal["EpApiV1InfraAaaLocalUsersDelete"] = Field(
        default="EpApiV1InfraAaaLocalUsersDelete",
        description="Class name for backward compatibility",
        frozen=True,
    )

    @property
    def verb(self) -> VerbEnum:
        """Return the HTTP verb for this endpoint."""
        return VerbEnum.DELETE
