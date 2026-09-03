# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric Group Members endpoint models.

This module contains endpoint definitions for fabric group member operations
in the ND Manage API.

## Endpoints

- `EpManageFabricGroupMembersGet` - List members of a fabric group
  (GET /api/v1/manage/fabrics/{fabric_name}/members)
- `EpManageFabricGroupMembersAddPost` - Add members to a fabric group
  (POST /api/v1/manage/fabrics/{fabric_name}/actions/addMembers)
- `EpManageFabricGroupMembersRemovePost` - Remove members from a fabric group
  (POST /api/v1/manage/fabrics/{fabric_name}/actions/removeMembers)
"""

from __future__ import annotations

__metaclass__ = type

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import EndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class _EpManageFabricGroupMembersBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for ND Manage Fabric Group Members endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics/{fabric_name}/members and
    /api/v1/manage/fabrics/{fabric_name}/actions/addMembers|removeMembers endpoints.

    Subclasses override ``_path_suffix`` to build the correct path.
    """

    _path_suffix: ClassVar[str] = "members"

    endpoint_params: EndpointQueryParams = Field(default_factory=EndpointQueryParams, description="Endpoint-specific query parameters")

    def set_identifiers(self, identifier: IdentifierKey = None):
        self.fabric_name = identifier

    @property
    def path(self) -> str:
        """
        Build the endpoint path including fabric name and path suffix.

        Raises ValueError if fabric_name is not set.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        base_path = BasePath.path("fabrics", self.fabric_name, self._path_suffix)
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path


class EpManageFabricGroupMembersGet(_EpManageFabricGroupMembersBase):
    """
    # Summary

    ND Manage Fabric Group Members GET Endpoint

    ## Description

    Endpoint to retrieve members of a fabric group from the ND Manage service.
    The fabric name (group name) is a required path parameter.

    ## Path

    - /api/v1/manage/fabrics/{fabric_name}/members

    ## Verb

    - GET

    ## Raises

    - `ValueError` if `fabric_name` is not set when accessing `path`

    ## Usage

    ```python
    request = EpManageFabricGroupMembersGet()
    request.fabric_name = "my-fabric-group"
    path = request.path
    verb = request.verb
    # Path: /api/v1/manage/fabrics/my-fabric-group/members
    ```
    """

    _path_suffix: ClassVar[str] = "members"

    class_name: Literal["EpManageFabricGroupMembersGet"] = Field(
        default="EpManageFabricGroupMembersGet",
        description="Class name for backward compatibility",
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpManageFabricGroupMembersAddPost(_EpManageFabricGroupMembersBase):
    """
    # Summary

    ND Manage Fabric Group Members Add POST Endpoint

    ## Description

    Endpoint to add members to a fabric group via the ND Manage service.
    The fabric name (group name) is a required path parameter.

    ## Path

    - /api/v1/manage/fabrics/{fabric_name}/actions/addMembers

    ## Verb

    - POST

    ## Request Body (application/json)

    ```json
    {
      "members": [
        { "name": "member-fabric-name" }
      ]
    }
    ```

    ## Raises

    - `ValueError` if `fabric_name` is not set when accessing `path`

    ## Usage

    ```python
    request = EpManageFabricGroupMembersAddPost()
    request.fabric_name = "my-fabric-group"
    path = request.path
    verb = request.verb
    # Path: /api/v1/manage/fabrics/my-fabric-group/actions/addMembers
    ```
    """

    _path_suffix: ClassVar[str] = "actions/addMembers"

    class_name: Literal["EpManageFabricGroupMembersAddPost"] = Field(
        default="EpManageFabricGroupMembersAddPost",
        description="Class name for backward compatibility",
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class EpManageFabricGroupMembersRemovePost(_EpManageFabricGroupMembersBase):
    """
    # Summary

    ND Manage Fabric Group Members Remove POST Endpoint

    ## Description

    Endpoint to remove members from a fabric group via the ND Manage service.
    The fabric name (group name) is a required path parameter.

    ## Path

    - /api/v1/manage/fabrics/{fabric_name}/actions/removeMembers

    ## Verb

    - POST

    ## Request Body (application/json)

    ```json
    {
      "members": [
        { "name": "member-fabric-name" }
      ]
    }
    ```

    ## Raises

    - `ValueError` if `fabric_name` is not set when accessing `path`

    ## Usage

    ```python
    request = EpManageFabricGroupMembersRemovePost()
    request.fabric_name = "my-fabric-group"
    path = request.path
    verb = request.verb
    # Path: /api/v1/manage/fabrics/my-fabric-group/actions/removeMembers
    ```
    """

    _path_suffix: ClassVar[str] = "actions/removeMembers"

    class_name: Literal["EpManageFabricGroupMembersRemovePost"] = Field(
        default="EpManageFabricGroupMembersRemovePost",
        description="Class name for backward compatibility",
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
