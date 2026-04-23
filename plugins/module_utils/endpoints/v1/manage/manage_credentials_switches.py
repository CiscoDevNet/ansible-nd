# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Credentials endpoint models.

This module contains endpoint definitions for switch credential operations
in the ND Manage API.

Endpoints covered:
- List switch credentials
- Create switch credentials
- Remove switch credentials
- Validate switch credentials
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
__author__ = "Akshayanat C S"
# pylint: enable=invalid-name

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    TicketIdMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
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


class CredentialsSwitchesEndpointParams(TicketIdMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for credentials switches endpoint.

    ## Parameters

    - ticket_id: Change control ticket ID (optional, from `TicketIdMixin`)

    ## Usage

    ```python
    params = CredentialsSwitchesEndpointParams(ticket_id="CHG12345")
    query_string = params.to_query_string()
    # Returns: "ticketId=CHG12345"
    ```
    """


class _EpManageCredentialsSwitchesBase(NDEndpointBaseModel):
    """
    Base class for Credentials Switches endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/credentials/switches endpoint.
    """

    @property
    def _base_path(self) -> str:
        """Build the base endpoint path."""
        return BasePath.path("credentials", "switches")


class EpManageCredentialsSwitchesPost(_EpManageCredentialsSwitchesBase):
    """
    # Summary

    Create Switch Credentials Endpoint

    ## Description

    Endpoint to save switch credentials for the user.

    ## Path

    - /api/v1/manage/credentials/switches
    - /api/v1/manage/credentials/switches?ticketId=CHG12345

    ## Verb

    - POST

    ## Query Parameters

    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    # Create credentials without ticket
    request = EpManageCredentialsSwitchesPost()
    path = request.path
    verb = request.verb

    # Create credentials with change control ticket
    request = EpManageCredentialsSwitchesPost()
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/credentials/switches?ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageCredentialsSwitchesPost"] = Field(
        default="EpManageCredentialsSwitchesPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: CredentialsSwitchesEndpointParams = Field(
        default_factory=CredentialsSwitchesEndpointParams,
        description="Endpoint-specific query parameters",
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional query string.

        ## Returns

        - Complete endpoint path string, optionally including query parameters
        """
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
