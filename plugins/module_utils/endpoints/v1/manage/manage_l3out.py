# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage L3Out endpoint models.

Endpoints for L3Out (Layer-3 Out) operations in the ND Manage API.

Endpoints:
- EpManageL3OutsGet   - List all L3Outs (optionally filtered by fabric via query param)
  (GET /api/v1/manage/l3Outs?fabricName={fabricName})
- EpManageL3OutPost   - Create L3Out(s)
  (POST /api/v1/manage/l3Outs)
- EpManageL3OutGet    - Get a specific L3Out by name
  (GET /api/v1/manage/l3Outs/{l3OutName})
- EpManageL3OutPut    - Update a specific L3Out
  (PUT /api/v1/manage/l3Outs/{l3OutName})
- EpManageL3OutDelete - Delete a specific L3Out
  (DELETE /api/v1/manage/l3Outs/{l3OutName})
- EpManageL3OutAttach - Attach/detach L3Outs
  (POST /api/v1/manage/l3OutActions/attach)
- EpManageL3OutBulkDelete - Bulk delete L3Outs
  (POST /api/v1/manage/l3OutActions/remove)
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import Literal, Optional

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

    L3Out endpoints use l3out_name as the primary identifier in the path.
    Fabric name is optional and used only for filtering in list operations
    (as a query parameter, NOT in the path).
    """

    l3out_name: Optional[str] = Field(default=None, description="L3Out name")

    def set_identifiers(self, identifier: IdentifierKey = None):
        """
        Set identifiers for L3Out operations.

        For L3Out, the identifier can be:
        - A tuple of (fabric_name, l3out_name) - fabric_name used for query filtering
        - A tuple of (l3out_name,) - just the L3Out name
        - A string - either fabric_name (for list) or l3out_name (for item operations)
        """
        if isinstance(identifier, tuple) and len(identifier) >= 2:
            self.fabric_name = identifier[0]
            self.l3out_name = identifier[1]
        elif isinstance(identifier, tuple) and len(identifier) == 1:
            # Single item in tuple - context-dependent
            # For item operations, this would be l3out_name
            self.l3out_name = identifier[0]
        elif isinstance(identifier, str):
            # Single string - context-dependent
            # Subclasses should interpret this appropriately
            pass

    def _build_collection_path(self) -> str:
        """Build path for collection operations: /api/v1/manage/l3Outs"""
        return BasePath.path("l3Outs")

    def _build_item_path(self) -> str:
        """Build path for item operations: /api/v1/manage/l3Outs/{l3OutName}"""
        if self.l3out_name is None:
            raise ValueError(
                "{0}.path: l3out_name must be set before accessing path.".format(
                    type(self).__name__
                )
            )
        return BasePath.path("l3Outs", self.l3out_name)


class EpManageL3OutsGet(_EpManageL3OutBase):
    """
    GET /api/v1/manage/l3Outs?fabricName={fabricName}

    List all L3Outs. Optionally filter by fabric name using query parameter.
    The fabricName query param is rendered into the path by the endpoint,
    keeping query-string construction out of the orchestrator.
    """

    class_name: Literal["EpManageL3OutsGet"] = Field(
        default="EpManageL3OutsGet",
        frozen=True,
        description="Class name for backward compatibility",
    )

    def set_identifiers(self, identifier: IdentifierKey = None):
        """For list operations, identifier is the optional fabric_name for filtering."""
        if isinstance(identifier, tuple) and len(identifier) >= 1:
            self.fabric_name = identifier[0]
        elif isinstance(identifier, str):
            self.fabric_name = identifier

    @property
    def path(self) -> str:
        base_path = self._build_collection_path()
        if self.fabric_name:
            return f"{base_path}?fabricName={self.fabric_name}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageL3OutPost(_EpManageL3OutBase):
    """
    POST /api/v1/manage/l3Outs

    Create one or more L3Outs.

    Request body format:
        {"l3Outs": [{...l3out1...}, {...l3out2...}]}

    Response: GenericBulkResponse (HTTP 207 multi-status)
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


class EpManageL3OutBulkDelete(NDEndpointBaseModel):
    """
    POST /api/v1/manage/l3OutActions/remove

    Bulk delete multiple L3Outs in a single request.

    Request body format:
        {"l3OutNames": ["L3Out1", "L3Out2"]}

    Response: GenericBulkResponse (HTTP 207 multi-status)
    """

    class_name: Literal["EpManageL3OutBulkDelete"] = Field(
        default="EpManageL3OutBulkDelete",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return BasePath.path("l3OutActions", "remove")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageL3OutGet(_EpManageL3OutBase):
    """
    GET /api/v1/manage/l3Outs/{l3OutName}

    Get a specific L3Out by name.
    """

    class_name: Literal["EpManageL3OutGet"] = Field(
        default="EpManageL3OutGet",
        frozen=True,
        description="Class name for backward compatibility",
    )

    def set_identifiers(self, identifier: IdentifierKey = None):
        """For get operations, identifier is the l3out_name."""
        if isinstance(identifier, tuple) and len(identifier) >= 2:
            # (fabric_name, l3out_name) - fabric_name ignored for path
            self.fabric_name = identifier[0]
            self.l3out_name = identifier[1]
        elif isinstance(identifier, tuple) and len(identifier) == 1:
            self.l3out_name = identifier[0]
        elif isinstance(identifier, str):
            self.l3out_name = identifier

    @property
    def path(self) -> str:
        return self._build_item_path()

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageL3OutPut(_EpManageL3OutBase):
    """
    PUT /api/v1/manage/l3Outs/{l3OutName}

    Update an existing L3Out.
    """

    class_name: Literal["EpManageL3OutPut"] = Field(
        default="EpManageL3OutPut",
        frozen=True,
        description="Class name for backward compatibility",
    )

    def set_identifiers(self, identifier: IdentifierKey = None):
        """For put operations, identifier is the l3out_name."""
        if isinstance(identifier, tuple) and len(identifier) >= 2:
            self.fabric_name = identifier[0]
            self.l3out_name = identifier[1]
        elif isinstance(identifier, tuple) and len(identifier) == 1:
            self.l3out_name = identifier[0]
        elif isinstance(identifier, str):
            self.l3out_name = identifier

    @property
    def path(self) -> str:
        return self._build_item_path()

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT


class EpManageL3OutDelete(_EpManageL3OutBase):
    """
    DELETE /api/v1/manage/l3Outs/{l3OutName}

    Delete an existing L3Out.
    """

    class_name: Literal["EpManageL3OutDelete"] = Field(
        default="EpManageL3OutDelete",
        frozen=True,
        description="Class name for backward compatibility",
    )

    def set_identifiers(self, identifier: IdentifierKey = None):
        """For delete operations, identifier is the l3out_name."""
        if isinstance(identifier, tuple) and len(identifier) >= 2:
            self.fabric_name = identifier[0]
            self.l3out_name = identifier[1]
        elif isinstance(identifier, tuple) and len(identifier) == 1:
            self.l3out_name = identifier[0]
        elif isinstance(identifier, str):
            self.l3out_name = identifier

    @property
    def path(self) -> str:
        return self._build_item_path()

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE


class EpManageL3OutAttach(NDEndpointBaseModel):
    """
    POST /api/v1/manage/l3OutActions/attach

    Attach or detach L3Outs to/from fabrics.

    Request body format:
        "attachments": [
            {"name": "L3Out1", "attach": true},
            {"name": "L3Out2", "attach": false}
        ]
    """

    class_name: Literal["EpManageL3OutAttach"] = Field(
        default="EpManageL3OutAttach",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return BasePath.path("l3OutActions", "attach")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST
