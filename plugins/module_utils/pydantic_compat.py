# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Compatibility shim for pydantic imports.

This provides a single import path that works both with and without the
pydantic package installed, while keeping type checkers happy.
"""

from __future__ import absolute_import, division, print_function

from typing import cast

try:
    from pydantic import BaseModel as PydanticBaseModel, ConfigDict
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False
    from ansible_collections.cisco.nd.plugins.module_utils.third_party.pydantic import (
        BaseModel as PydanticBaseModel,
        ConfigDict,
    )  # type: ignore[assignment]

# Cast to a class object so type checkers do not treat this as a union.
BaseModel = cast(type, PydanticBaseModel)

__all__ = ["BaseModel", "ConfigDict", "HAS_PYDANTIC"]
