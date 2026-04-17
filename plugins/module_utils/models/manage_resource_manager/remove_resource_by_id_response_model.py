# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
RemoveByIdResponse - Individual item in remove-by-IDs response.

Standalone model (no composite model fields). All fields are primitives.

Endpoint: POST /fabrics/{fabricName}/resources/actions/remove (response item)
"""

from __future__ import annotations

from typing import Any, ClassVar, List, Optional

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field


class RemoveResourcesByIdResponse(NDBaseModel):
    """
    Individual resource removal response item for POST .../actions/remove.
    """

    identifiers: ClassVar[List[str]] = []

    resource_value: Optional[str] = Field(
        default=None,
        alias="resourceValue",
        description="Unique value of the removed resource",
    )
    status: Optional[str] = Field(
        default=None,
        description="Status of the resource delete request",
    )
    message: Optional[str] = Field(
        default=None,
        description="Optional details describing a resource delete failure",
    )


class RemoveResourcesByIdsResponse(NDBaseModel):
    """
    Response body for POST - /api/v1/manage/fabrics/{fabricName}/resources/actions/remove

    Composite: contains List[RemoveResourcesByIdResponse].
    """

    identifiers: ClassVar[List[str]] = []

    resources: List[RemoveResourcesByIdResponse] = Field(default_factory=list, description="List of resource data")

    @classmethod
    def from_response(cls, response: Any) -> "RemoveResourcesByIdsResponse":
        """Create instance from a raw API response dict.

        Accepts the raw dict returned by nd.request() for the batch POST
        endpoint.  If the response already has a ``resources`` key it is
        validated directly; a bare list is wrapped automatically.
        """
        if isinstance(response, list):
            return cls.model_validate({"resources": response})
        if isinstance(response, dict):
            return cls.model_validate(response)
        return cls(resources=[])
