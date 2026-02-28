# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Centralized base paths for ND Infra API endpoints.

/api/v1/infra

This module provides a single location to manage all API Infra base paths,
allowing easy modification when API paths change. All endpoint classes
should use these path builders for consistency.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from typing import Final

from ansible_collections.cisco.nd.plugins.module_utils.ep.base_path import ApiPath


class BasePath:
    """
    # Summary

    API Endpoints for ND Infra

    ## Description

    Provides centralized endpoint definitions for all ND Infra API endpoints.
    This allows API path changes to be managed in a single location.

    ## Usage

    ```python
    from ansible_collections.cisco.nd.plugins.module_utils.ep.base_paths_infra import BasePath

    # Get a complete base path for ND Infra
    path = BasePath.nd_infra("aaa", "localUsers")
    # Returns: /api/v1/infra/aaa/localUsers

    # Leverage a convenience method
    path = BasePath.nd_infra_aaa("localUsers")
    # Returns: /api/v1/infra/aaa/localUsers
    ```

    ## Design Notes

    - All base paths are defined as class constants for easy modification
    - Helper methods compose paths from base constants
    - Use these methods in Pydantic endpoint models to ensure consistency
    - If ND Infra changes base API paths, only this class needs updating
    """

    API: Final = ApiPath.INFRA.value

    @classmethod
    def nd_infra(cls, *segments: str) -> str:
        """
        # Summary

        Build ND infra API path.

        ## Parameters

        - segments: Path segments to append after /api/v1/infra

        ## Returns

        - Complete ND infra API path

        ## Example

        ```python
        path = BasePath.nd_infra("aaa", "localUsers")
        # Returns: /api/v1/infra/aaa/localUsers
        ```
        """
        if not segments:
            return cls.API
        return f"{cls.API}/{'/'.join(segments)}"

    @classmethod
    def nd_infra_aaa(cls, *segments: str) -> str:
        """
        # Summary

        Build ND infra AAA API path.

        ## Parameters

        - segments: Path segments to append after aaa (e.g., "localUsers")

        ## Returns

        - Complete ND infra AAA path

        ## Example

        ```python
        path = BasePath.nd_infra_aaa("localUsers")
        # Returns: /api/v1/infra/aaa/localUsers
        ```
        """
        return cls.nd_infra("aaa", *segments)

    @classmethod
    def nd_infra_clusterhealth(cls, *segments: str) -> str:
        """
        # Summary

        Build ND infra clusterhealth API path.

        ## Parameters

        - segments: Path segments to append after clusterhealth (e.g., "config", "status")

        ## Returns

        - Complete ND infra clusterhealth path

        ## Example

        ```python
        path = BasePath.nd_infra_clusterhealth("config")
        # Returns: /api/v1/infra/clusterhealth/config
        ```
        """
        return cls.nd_infra("clusterhealth", *segments)
