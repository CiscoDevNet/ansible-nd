# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# pylint: disable=too-few-public-methods
"""
# Summary

Pydantic compatibility layer.

This module provides a single location for Pydantic imports with fallback
implementations when Pydantic is not available. This ensures consistent
behavior across all modules and follows the DRY principle.

## Usage

### Importing

Rather than importing directly from pydantic, import from this module:

```python
from ansible_collections.cisco.nd.plugins.module_utils.pydantic_compat import BaseModel
```

This ensure that Ansible sanity tests will not fail due to missing Pydantic dependencies.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import traceback
from typing import TYPE_CHECKING, Any, Callable, Union

if TYPE_CHECKING:
    # Type checkers always see the real Pydantic types
    from pydantic import (
        AfterValidator,
        BaseModel,
        BeforeValidator,
        ConfigDict,
        Field,
        PydanticExperimentalWarning,
        StrictBool,
        ValidationError,
        field_serializer,
        field_validator,
        model_validator,
        validator,
    )
else:
    # Runtime: try to import, with fallback
    try:
        from pydantic import (
            AfterValidator,
            BaseModel,
            BeforeValidator,
            ConfigDict,
            Field,
            PydanticExperimentalWarning,
            StrictBool,
            ValidationError,
            field_serializer,
            field_validator,
            model_validator,
            validator,
        )
    except ImportError:
        HAS_PYDANTIC = False  # pylint: disable=invalid-name
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

        # Fallback: field_serializer decorator that does nothing
        def field_serializer(*args, **kwargs):  # pylint: disable=unused-argument
            """Pydantic field_serializer fallback when pydantic is not available."""

            def decorator(func):
                return func

            return decorator

        # Fallback: field_validator decorator that does nothing
        def field_validator(*args, **kwargs) -> Callable[..., Any]:  # pylint: disable=unused-argument,invalid-name
            """Pydantic field_validator fallback when pydantic is not available."""

            def decorator(func):
                return func

            return decorator

        # Fallback: AfterValidator that returns the function unchanged
        def AfterValidator(func):  # pylint: disable=invalid-name
            """Pydantic AfterValidator fallback when pydantic is not available."""
            return func

        # Fallback: BeforeValidator that returns the function unchanged
        def BeforeValidator(func):  # pylint: disable=invalid-name
            """Pydantic BeforeValidator fallback when pydantic is not available."""
            return func

        # Fallback: PydanticExperimentalWarning
        PydanticExperimentalWarning = Warning

        # Fallback: StrictBool
        StrictBool = bool

        # Fallback: ValidationError
        class ValidationError(Exception):
            """
            Pydantic ValidationError fallback when pydantic is not available.
            """

            def __init__(self, message="A custom error occurred."):
                self.message = message
                super().__init__(self.message)

            def __str__(self):
                return f"ValidationError: {self.message}"

        # Fallback: model_validator decorator that does nothing
        def model_validator(*args, **kwargs):  # pylint: disable=unused-argument
            """Pydantic model_validator fallback when pydantic is not available."""

            def decorator(func):
                return func

            return decorator

        # Fallback: validator decorator that does nothing
        def validator(*args, **kwargs):  # pylint: disable=unused-argument
            """Pydantic validator fallback when pydantic is not available."""

            def decorator(func):
                return func

            return decorator

    else:
        HAS_PYDANTIC = True  # pylint: disable=invalid-name
        PYDANTIC_IMPORT_ERROR = None  # pylint: disable=invalid-name

# Set HAS_PYDANTIC for when TYPE_CHECKING is True
if TYPE_CHECKING:
    HAS_PYDANTIC = True  # pylint: disable=invalid-name
    PYDANTIC_IMPORT_ERROR = None  # pylint: disable=invalid-name

__all__ = [
    "AfterValidator",
    "BaseModel",
    "BeforeValidator",
    "ConfigDict",
    "Field",
    "HAS_PYDANTIC",
    "PYDANTIC_IMPORT_ERROR",
    "PydanticExperimentalWarning",
    "StrictBool",
    "ValidationError",
    "field_serializer",
    "field_validator",
    "model_validator",
    "validator",
]
