# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

"""
Centralized base paths for ND Manage API endpoints.

/api/v1/manage

This module provides a single location to manage all API Manage base paths,
allowing easy modification when API paths change. All endpoint classes
should use these path builders for consistency.
"""
__author__ = "Allen Robel"

from typing import Final

from ansible_collections.cisco.nd.plugins.module_utils.ep.base_path import ND_MANAGE_API


class BasePath:
    """
    # Summary

    API Endpoints for ND Manage

    ## Description

    Provides centralized endpoint definitions for all ND Manage API endpoints.
    This allows API path changes to be managed in a single location.

    ## Usage

    ```python
    from ansible_collections.cisco.nd.plugins.module_utils.ep.base_paths_manage import BasePath

    # Get a complete base path for ND Manage
    path = BasePath.nd_manage("inventory", "switches")
    # Returns: /api/v1/manage/inventory/switches

    # Leverage a convenience method
    path = BasePath.nd_manage_inventory("switches")
    # Returns: /api/v1/manage/inventory/switches
    ```

    ## Design Notes

    - All base paths are defined as class constants for easy modification
    - Helper methods compose paths from base constants
    - Use these methods in Pydantic endpoint models to ensure consistency
    - If ND Manage changes base API paths, only this class needs updating
    """

    API: Final = ND_MANAGE_API

    @classmethod
    def nd_manage(cls, *segments: str) -> str:
        """
        # Summary

        Build ND manage API path.

        ## Parameters

        - segments: Path segments to append after /api/v1/manage

        ## Returns

        - Complete ND manage API path

        ## Example

        ```python
        path = BasePath.nd_manage("inventory", "switches")
        # Returns: /api/v1/manage/inventory/switches
        ```
        """
        if not segments:
            return cls.API
        return f"{cls.API}/{'/'.join(segments)}"

    @classmethod
    def nd_manage_inventory(cls, *segments: str) -> str:
        """
        # Summary

        Build ND manage inventory API path.

        ## Parameters

        - segments: Path segments to append after inventory (e.g., "switches")

        ## Returns

        - Complete ND manage inventory path

        ## Example

        ```python
        path = BasePath.nd_manage_inventory("switches")
        # Returns: /api/v1/manage/inventory/switches
        ```
        """
        return cls.nd_manage("inventory", *segments)
