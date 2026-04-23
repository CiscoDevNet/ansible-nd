# Copyright: (c) 2026, Slawomir Kaszlikowski

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Access Control List endpoint models.

Endpoints for ACL operations in the ND Manage API.

Endpoints:
- EpManageAclsGet   - List all ACLs for a fabric
  (GET /api/v1/manage/fabrics/{fabricName}/accessControlLists)
- EpManageAclPost   - Create an ACL for a fabric
  (POST /api/v1/manage/fabrics/{fabricName}/accessControlLists)
- EpManageAclGet    - Get a specific ACL
  (GET /api/v1/manage/fabrics/{fabricName}/accessControlLists/{aclName})
- EpManageAclPut    - Update a specific ACL
  (PUT /api/v1/manage/fabrics/{fabricName}/accessControlLists/{aclName})
- EpManageAclDelete - Delete a specific ACL
  (DELETE /api/v1/manage/fabrics/{fabricName}/accessControlLists/{aclName})
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import ClassVar, Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class _EpManageAclBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for ND Manage ACL endpoints.

    All ACL endpoints require a fabric_name path parameter.
    Item-level endpoints also require an acl_name path parameter.
    """

    acl_name: Optional[str] = Field(default=None, description="ACL name")

    def set_identifiers(self, identifier: IdentifierKey = None):
        if isinstance(identifier, tuple) and len(identifier) >= 2:
            self.fabric_name = identifier[0]
            self.acl_name = identifier[1]
        elif isinstance(identifier, tuple) and len(identifier) == 1:
            self.fabric_name = identifier[0]
        elif isinstance(identifier, str):
            self.fabric_name = identifier

    def _build_collection_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("{0}.path: fabric_name must be set before accessing path.".format(type(self).__name__))
        return BasePath.path("fabrics", self.fabric_name, "accessControlLists")

    def _build_item_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("{0}.path: fabric_name must be set before accessing path.".format(type(self).__name__))
        if self.acl_name is None:
            raise ValueError("{0}.path: acl_name must be set before accessing path.".format(type(self).__name__))
        return BasePath.path("fabrics", self.fabric_name, "accessControlLists", self.acl_name)


class EpManageAclsGet(_EpManageAclBase):
    """
    GET /api/v1/manage/fabrics/{fabricName}/accessControlLists

    List all ACLs for a fabric.
    """

    class_name: Literal["EpManageAclsGet"] = Field(
        default="EpManageAclsGet",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return self._build_collection_path()

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageAclPost(_EpManageAclBase):
    """
    POST /api/v1/manage/fabrics/{fabricName}/accessControlLists

    Create one or more ACLs for a fabric.
    """

    class_name: Literal["EpManageAclPost"] = Field(
        default="EpManageAclPost",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return self._build_collection_path()

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageAclGet(_EpManageAclBase):
    """
    GET /api/v1/manage/fabrics/{fabricName}/accessControlLists/{aclName}

    Get a specific ACL by name.
    """

    class_name: Literal["EpManageAclGet"] = Field(
        default="EpManageAclGet",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return self._build_item_path()

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageAclPut(_EpManageAclBase):
    """
    PUT /api/v1/manage/fabrics/{fabricName}/accessControlLists/{aclName}

    Update an existing ACL.
    """

    class_name: Literal["EpManageAclPut"] = Field(
        default="EpManageAclPut",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return self._build_item_path()

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT


class EpManageAclDelete(_EpManageAclBase):
    """
    DELETE /api/v1/manage/fabrics/{fabricName}/accessControlLists/{aclName}

    Delete an existing ACL.
    """

    class_name: Literal["EpManageAclDelete"] = Field(
        default="EpManageAclDelete",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return self._build_item_path()

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE
