# Copyright: (c) 2026, Slawomir Kaszlikowski

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage L3Out endpoint models.

Endpoints for L3Out (Layer-3 Out) operations in the ND Manage API.

Endpoints:
- EpManageL3OutsGet   - List all L3Outs for a fabric
  (GET /api/v1/manage/fabrics/{fabricName}/l3Outs)
- EpManageL3OutPost   - Create L3Out(s) for a fabric
  (POST /api/v1/manage/fabrics/{fabricName}/l3Outs)
- EpManageL3OutGet    - Get a specific L3Out
  (GET /api/v1/manage/fabrics/{fabricName}/l3Outs/{l3OutName})
- EpManageL3OutPut    - Update a specific L3Out
  (PUT /api/v1/manage/fabrics/{fabricName}/l3Outs/{l3OutName})
- EpManageL3OutDelete - Delete a specific L3Out
  (DELETE /api/v1/manage/fabrics/{fabricName}/l3Outs/{l3OutName})
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import ClassVar, Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    FabricNameMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class _EpManageL3OutBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for ND Manage L3Out endpoints.

    All L3Out endpoints require a fabric_name path parameter.
    Item-level endpoints also require an l3out_name path parameter.
    """

    l3out_name: Optional[str] = Field(default=None, description="L3Out name")

    def set_identifiers(self, identifier: IdentifierKey = None):
        if isinstance(identifier, tuple) and len(identifier) >= 2:
            self.fabric_name = identifier[0]
            self.l3out_name = identifier[1]
        elif isinstance(identifier, tuple) and len(identifier) == 1:
            self.fabric_name = identifier[0]
        elif isinstance(identifier, str):
            self.fabric_name = identifier

    def _build_collection_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError(
                "{0}.path: fabric_name must be set before accessing path.".format(
                    type(self).__name__
                )
            )
        return BasePath.path("fabrics", self.fabric_name, "l3Outs")

    def _build_item_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError(
                "{0}.path: fabric_name must be set before accessing path.".format(
                    type(self).__name__
                )
            )
        if self.l3out_name is None:
            raise ValueError(
                "{0}.path: l3out_name must be set before accessing path.".format(
                    type(self).__name__
                )
            )
        return BasePath.path("fabrics", self.fabric_name, "l3Outs", self.l3out_name)


class EpManageL3OutsGet(_EpManageL3OutBase):
    """
    GET /api/v1/manage/fabrics/{fabricName}/l3Outs

    List all L3Outs for a fabric.
    """

    class_name: Literal["EpManageL3OutsGet"] = Field(
        default="EpManageL3OutsGet",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return self._build_collection_path()

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageL3OutPost(_EpManageL3OutBase):
    """
    POST /api/v1/manage/fabrics/{fabricName}/l3Outs

    Create one or more L3Outs for a fabric.
    """

    class_name: Literal["EpManageL3OutPost"] = Field(
        default="EpManageL3OutPost",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return self._build_collection_path()

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageL3OutGet(_EpManageL3OutBase):
    """
    GET /api/v1/manage/fabrics/{fabricName}/l3Outs/{l3OutName}

    Get a specific L3Out by name.
    """

    class_name: Literal["EpManageL3OutGet"] = Field(
        default="EpManageL3OutGet",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return self._build_item_path()

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageL3OutPut(_EpManageL3OutBase):
    """
    PUT /api/v1/manage/fabrics/{fabricName}/l3Outs/{l3OutName}

    Update an existing L3Out.
    """

    class_name: Literal["EpManageL3OutPut"] = Field(
        default="EpManageL3OutPut",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return self._build_item_path()

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT


class EpManageL3OutDelete(_EpManageL3OutBase):
    """
    DELETE /api/v1/manage/fabrics/{fabricName}/l3Outs/{l3OutName}

    Delete an existing L3Out.
    """

    class_name: Literal["EpManageL3OutDelete"] = Field(
        default="EpManageL3OutDelete",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return self._build_item_path()

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE
