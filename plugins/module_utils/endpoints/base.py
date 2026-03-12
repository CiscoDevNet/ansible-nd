# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>
# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Base endpoint model for all ND API endpoints.

Provides ``NDEndpointBaseModel``, the required base class for every
concrete endpoint definition.  It centralizes ``model_config``,
version metadata, and enforces that subclasses define ``path``,
``verb``, and ``class_name``.
"""

from __future__ import absolute_import, annotations, division, print_function


from abc import ABC, abstractmethod
from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BaseModel,
    ConfigDict,
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class NDEndpointBaseModel(BaseModel, ABC):
    """
    # Summary

    Abstract base model for all ND API endpoint definitions.

    ## Description

    Centralizes common configuration and version metadata that every endpoint shares. Subclasses **must** define `path`, `verb`, and `class_name`.

    ## Fields (inherited by all endpoints)

    - `api_version` — API version string (default `"v1"`)
    - `min_controller_version` — minimum ND controller version (default `"3.0.0"`)

    ## Abstract members (must be defined by subclasses)

    - `path` — `@property` returning the endpoint URL path
    - `verb` — `@property` returning the `HttpVerbEnum` for this endpoint
    - `class_name` — Pydantic field (typically a `Literal` type) identifying the concrete class

    ## Usage

    ```python
    class EpInfraLoginPost(NDEndpointBaseModel):
        class_name: Literal["EpInfraLoginPost"] = Field(
            default="EpInfraLoginPost",
            description="Class name for backward compatibility",
        )

        @property
        def path(self) -> str:
            return BasePath.path("login")

        @property
        def verb(self) -> HttpVerbEnum:
            return HttpVerbEnum.POST
    ```
    """

    model_config = ConfigDict(validate_assignment=True)

    def __init_subclass__(cls, **kwargs: object) -> None:
        """
        # Summary

        Enforce that concrete subclasses define a `class_name` field.

        ## Description

        Fires at class definition time. Skips abstract subclasses (those with remaining abstract methods) and only checks concrete endpoint classes.

        ## Raises

        ### TypeError

        - If a concrete subclass does not define a `class_name` field in its annotations
        """
        super().__init_subclass__(**kwargs)
        # Compute abstract methods manually because __abstractmethods__
        # is not yet set on cls when __init_subclass__ fires (ABCMeta
        # sets it after type.__new__ returns).
        abstracts = {name for name, value in vars(cls).items() if getattr(value, "__isabstractmethod__", False)}
        for base in cls.__bases__:
            for name in getattr(base, "__abstractmethods__", set()):
                if getattr(getattr(cls, name, None), "__isabstractmethod__", False):
                    abstracts.add(name)
        if abstracts:
            return
        if "class_name" not in getattr(cls, "__annotations__", {}):
            raise TypeError(
                f"{cls.__name__} must define a 'class_name' field. "
                f'Example: class_name: Literal["{cls.__name__}"] = '
                f'Field(default="{cls.__name__}", frozen=True, description="...")'
            )

    # Version metadata — shared by all endpoints
    api_version: Literal["v1"] = Field(default="v1", description="ND API version for this endpoint")
    min_controller_version: str = Field(default="3.0.0", description="Minimum ND version supporting this endpoint")

    @property
    @abstractmethod
    def path(self) -> str:
        """
        # Summary

        Return the endpoint URL path.

        ## Raises

        None
        """

    @property
    @abstractmethod
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return the HTTP verb for this endpoint.

        ## Raises

        None
        """

    # NOTE: function to set endpoints attribute fields from identifiers -> acts as the bridge between Models and Endpoints for API Request Orchestration
    @abstractmethod
    def set_identifiers(self, identifier: IdentifierKey = None):
        pass
