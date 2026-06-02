# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric Update Group endpoint models.

This module contains endpoint definitions for fabric update group operations
under the ND Manage Fabric Software Management API.

## Endpoints

- `EpFabricUpdateGroupListGet` - List update groups in a fabric
  (GET /api/v1/manage/fabrics/{fabric_name}/updateGroups)
- `EpFabricUpdateGroupGet` - Get a specific update group by name
  (GET /api/v1/manage/fabrics/{fabric_name}/updateGroups/{update_group_name})
- `EpFabricUpdateGroupPut` - Update an existing update group
  (PUT /api/v1/manage/fabrics/{fabric_name}/updateGroups/{update_group_name})
- `EpFabricUpdateGroupDelete` - Delete an update group
  (DELETE /api/v1/manage/fabrics/{fabric_name}/updateGroups/{update_group_name})
"""

from __future__ import annotations

from typing import ClassVar, Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin, UpdateGroupNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class _EpFabricUpdateGroupBase(UpdateGroupNameMixin, FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for ND Manage Fabric Update Group endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics/{fabric_name}/updateGroups endpoint.

    Subclasses may override:
    - ``_require_update_group_name``: set to ``False`` for collection-level endpoints
      (list, create) that do not include an update group name in the path.
    """

    _require_update_group_name: ClassVar[bool] = True

    def set_identifiers(self, identifier: IdentifierKey = None):
        self.update_group_name = identifier

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with required fabric_name and optional update_group_name.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set when accessing `path`
        - If `update_group_name` is required but not set
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        if self._require_update_group_name and self.update_group_name is None:
            raise ValueError(f"{type(self).__name__}.path: update_group_name must be set before accessing path.")
        segments = ["fabrics", quote(self.fabric_name, safe=""), "updateGroups"]
        if self.update_group_name is not None:
            segments.append(quote(self.update_group_name, safe=""))
        return BasePath.path(*segments)


class EpFabricUpdateGroupListGet(_EpFabricUpdateGroupBase):
    """
    # Summary

    ND Manage Fabric Update Group List GET endpoint.

    ## Path

    - `/api/v1/manage/fabrics/{fabric_name}/updateGroups`

    ## Verb

    - GET

    ## Usage

    ```python
    ep = EpFabricUpdateGroupListGet()
    ep.fabric_name = "SITE1"
    rest_send.path = ep.path
    rest_send.verb = ep.verb
    ```
    """

    _require_update_group_name: ClassVar[bool] = False

    class_name: Literal["EpFabricUpdateGroupListGet"] = Field(
        default="EpFabricUpdateGroupListGet", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpFabricUpdateGroupGet(_EpFabricUpdateGroupBase):
    """
    # Summary

    ND Manage Fabric Update Group GET endpoint.

    ## Path

    - `/api/v1/manage/fabrics/{fabric_name}/updateGroups/{update_group_name}`

    ## Verb

    - GET
    """

    class_name: Literal["EpFabricUpdateGroupGet"] = Field(default="EpFabricUpdateGroupGet", frozen=True, description="Class name for backward compatibility")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpFabricUpdateGroupPut(_EpFabricUpdateGroupBase):
    """
    # Summary

    ND Manage Fabric Update Group PUT endpoint.

    ## Path

    - `/api/v1/manage/fabrics/{fabric_name}/updateGroups/{update_group_name}`

    ## Verb

    - PUT
    """

    class_name: Literal["EpFabricUpdateGroupPut"] = Field(default="EpFabricUpdateGroupPut", frozen=True, description="Class name for backward compatibility")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.PUT


class EpFabricUpdateGroupDelete(_EpFabricUpdateGroupBase):
    """
    # Summary

    ND Manage Fabric Update Group DELETE endpoint.

    ## Path

    - `/api/v1/manage/fabrics/{fabric_name}/updateGroups/{update_group_name}`

    ## Verb

    - DELETE
    """

    class_name: Literal["EpFabricUpdateGroupDelete"] = Field(
        default="EpFabricUpdateGroupDelete", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.DELETE
