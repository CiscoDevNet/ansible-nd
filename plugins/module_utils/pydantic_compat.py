# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Pydantic compatibility layer.

This module provides a single location for Pydantic imports with fallback
implementations when Pydantic is not available. This ensures consistent
behavior across all modules and follows the DRY principle.
"""
# pylint: disable=too-few-public-methods

from __future__ import absolute_import, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name
__author__ = "Allen Robel"

import traceback
from typing import TYPE_CHECKING, Any, Callable, Union

if TYPE_CHECKING:
    # Type checkers always see the real Pydantic types
    from pydantic import BaseModel, ConfigDict, Field, field_validator
else:
    # Runtime: try to import, with fallback
    try:
        from pydantic import BaseModel, ConfigDict, Field, field_validator
    except ImportError:
        HAS_PYDANTIC = False
        PYDANTIC_IMPORT_ERROR: Union[str, None] = traceback.format_exc()  # pylint: disable=invalid-name

        # Fallback: Minimal BaseModel replacement
        class BaseModel:
            """Fallback BaseModel when pydantic is not available."""

            model_config = {"validate_assignment": False, "use_enum_values": False}

            def __init__(self, **kwargs):
                """Accept keyword arguments and set them as attributes."""
                for key, value in kwargs.items():
                    setattr(self, key, value)

            def model_dump(self, exclude_none: bool = False, exclude_defaults: bool = False) -> dict:  # pylint: disable=unused-argument
                """Return a dictionary of field names and values.

                Args:
                    exclude_none: If True, exclude fields with None values
                    exclude_defaults: Accepted for API compatibility but not implemented in fallback
                """
                result = {}
                for key, value in self.__dict__.items():
                    if exclude_none and value is None:
                        continue
                    result[key] = value
                return result

        # Fallback: ConfigDict that does nothing
        def ConfigDict(**kwargs) -> dict:  # pylint: disable=unused-argument,invalid-name
            """Pydantic ConfigDict fallback when pydantic is not available."""
            return kwargs

        # Fallback: Field that does nothing
        def Field(**kwargs) -> Any:  # pylint: disable=unused-argument,invalid-name
            """Pydantic Field fallback when pydantic is not available."""
            if "default_factory" in kwargs:
                return kwargs["default_factory"]()
            return kwargs.get("default")

        # Fallback: field_validator decorator that does nothing
        def field_validator(*args, **kwargs) -> Callable[..., Any]:  # pylint: disable=unused-argument,invalid-name
            """Pydantic field_validator fallback when pydantic is not available."""

            def decorator(func):
                return func

            return decorator

    else:
        HAS_PYDANTIC = True
        PYDANTIC_IMPORT_ERROR = None  # pylint: disable=invalid-name

# Set HAS_PYDANTIC for when TYPE_CHECKING is True
if TYPE_CHECKING:
    HAS_PYDANTIC = True
    PYDANTIC_IMPORT_ERROR = None

__all__ = [
    "BaseModel",
    "ConfigDict",
    "Field",
    "field_validator",
    "HAS_PYDANTIC",
    "PYDANTIC_IMPORT_ERROR",
]
