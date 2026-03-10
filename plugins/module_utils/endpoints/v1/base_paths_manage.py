# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Centralized base paths for ND Manage API endpoints.

/api/v1/manage

This module provides a single location to manage all API Manage base paths,
allowing easy modification when API paths change. All endpoint classes
should use these path builders for consistency.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Final


class BasePath:
    """
    # Summary

    API Endpoints for ND Manage

    ## Description

    Provides centralized endpoint definitions for all ND Manage API endpoints.
    This allows API path changes to be managed in a single location.

    ## Usage

    ```python
    from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base_paths_manage import BasePath

    # Get a complete base path for ND Manage
    path = BasePath.path("inventory", "switches")
    # Returns: /api/v1/manage/inventory/switches
    ```

    ## Design Notes

    - All base paths are defined as class constants for easy modification
    - Helper methods compose paths from base constants
    - Use these methods in Pydantic endpoint models to ensure consistency
    - If ND Manage changes base API paths, only this class needs updating
    """

    API: Final = "/api/v1/manage"

    @classmethod
    def path(cls, *segments: str) -> str:
        """
        # Summary

        Build ND manage API path.

        ## Parameters

        - segments: Path segments to append after /api/v1/manage

        ## Returns

        - Complete ND manage API path

        ## Example

        ```python
        path = BasePath.path("inventory", "switches")
        # Returns: /api/v1/manage/inventory/switches
        ```
        """
        if not segments:
            return cls.API
        return f"{cls.API}/{'/'.join(segments)}"
