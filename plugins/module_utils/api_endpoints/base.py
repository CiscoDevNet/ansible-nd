# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>
# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from abc import ABC, abstractmethod
from pydantic import BaseModel, ConfigDict
from typing import Final, Union, Tuple, Any

IdentifierKey = Union[str, int, Tuple[Any, ...], None]

# TODO: Rename it to APIEndpoint
# NOTE: This is a very minimalist endpoint package -> needs to be enhanced
class NDBaseSmartEndpoint(BaseModel, ABC):

    # TODO: maybe to be modified in the future
    model_config = ConfigDict(validate_assignment=True)

    # TODO: to remove
    base_path: str

    @abstractmethod
    @property
    def path(self) -> str:
        pass

    @abstractmethod
    @property
    def verb(self) -> str:
        pass

    # TODO: Maybe to be modifed to be more Pydantic (low priority)
    # TODO: Maybe change function's name (low priority)
    # NOTE: function to set endpoints attribute fields from identifiers -> acts as the bridge between Models and Endpoints for API Request Orchestration
    @abstractmethod
    def set_identifiers(self, identifier: IdentifierKey = None):
        pass


class NDBasePath:
    """
    # Summary

    Centralized API Base Paths

    ## Description

    Provides centralized base path definitions for all ND API endpoints.
    This allows API path changes to be managed in a single location.

    ## Usage

    ```python
    # Get a complete base path
    path = BasePath.control_fabrics("MyFabric", "config-deploy")
    # Returns: /appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/MyFabric/config-deploy

    # Build custom paths
    path = BasePath.v1("custom", "endpoint")
    # Returns: /appcenter/cisco/ndfc/api/v1/custom/endpoint
    ```

    ## Design Notes

    - All base paths are defined as class constants for easy modification
    - Helper methods compose paths from base constants
    - Use these methods in Pydantic endpoint models to ensure consistency
    - If NDFC changes base API paths, only this class needs updating
    """

    # Root API paths
    NDFC_API: Final = "/appcenter/cisco/ndfc/api"
    ND_INFRA_API: Final = "/api/v1/infra"
    ONEMANAGE: Final = "/onemanage"
    LOGIN: Final = "/login"

    @classmethod
    def api(cls, *segments: str) -> str:
        """
        # Summary

        Build path from NDFC API root.

        ## Parameters

        - segments: Path segments to append

        ## Returns

        - Complete path string

        ## Example

        ```python
        path = BasePath.api("custom", "endpoint")
        # Returns: /appcenter/cisco/ndfc/api/custom/endpoint
        ```
        """
        if not segments:
            return cls.NDFC_API
        return f"{cls.NDFC_API}/{'/'.join(segments)}"

    @classmethod
    def v1(cls, *segments: str) -> str:
        """
        # Summary

        Build v1 API path.

        ## Parameters

        - segments: Path segments to append after v1

        ## Returns

        - Complete v1 API path

        ## Example

        ```python
        path = BasePath.v1("lan-fabric", "rest")
        # Returns: /appcenter/cisco/ndfc/api/v1/lan-fabric/rest
        ```
        """
        return cls.api("v1", *segments)

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
            return cls.ND_INFRA_API
        return f"{cls.ND_INFRA_API}/{'/'.join(segments)}"

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
