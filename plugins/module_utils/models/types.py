# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import re
from typing import Annotated

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BeforeValidator, Field

_FABRIC_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def _validate_fabric_name(value: str) -> str:
    """Validate that a fabric name contains only letters, digits, underscores, and hyphens."""
    if not _FABRIC_NAME_RE.match(value):
        raise ValueError(f"Fabric name can only contain letters, numbers, underscores, and hyphens, got: {value}")
    return value


NdFabricName = Annotated[
    str,
    Field(alias="name", min_length=1, max_length=64, description="Fabric name"),
    BeforeValidator(_validate_fabric_name),
]
