# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
RemoveResourcesByIdsRequest - Request model for remove-by-IDs action.

Standalone model (no composite model fields). Contains only List[int].

Endpoint: POST /fabrics/{fabricName}/resources/actions/remove
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import Any, ClassVar, Dict, List

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field


class RemoveResourcesByIdsRequest(NDBaseModel):
    """
    Request body for POST /fabrics/{fabricName}/resources/actions/remove.

    At least one resource ID must be provided.
    """

    identifiers: ClassVar[List[str]] = []

    resource_ids: List[int] = Field(
        alias="resourceIds",
        min_length=1,
        description="Array of resource IDs to remove. Must contain at least one ID.",
    )

    def to_payload(self) -> Dict[str, Any]:
        """Convert to API payload format."""
        return self.model_dump(by_alias=True, exclude_none=True)


__all__ = ["RemoveResourcesByIdsRequest"]
