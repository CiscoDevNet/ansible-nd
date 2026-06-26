# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared query parameter models for fabric switch action endpoints."""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    TicketIdMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)


class SwitchActionsTicketEndpointParams(TicketIdMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for switch action endpoints that accept a ticket ID.

    ## Parameters

    - ticket_id: Change control ticket ID (optional, from `TicketIdMixin`)

    ## Usage

    ```python
    params = SwitchActionsTicketEndpointParams(ticket_id="CHG12345")
    query_string = params.to_query_string()
    # Returns: "ticketId=CHG12345"
    ```
    """
