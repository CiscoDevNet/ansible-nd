# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""ND Manage Fabric Interface Groups endpoint models.

Endpoints covered:
- List interface groups in a fabric
- Create interface groups in bulk
- Remove interface groups in bulk
- Get, update, and delete a single interface group
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    ClusterNameMixin,
    FabricNameMixin,
    FilterMixin,
    InterfaceGroupNameMixin,
    MaxMixin,
    OffsetMixin,
    TicketIdMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class InterfaceGroupsGetEndpointParams(ClusterNameMixin, FilterMixin, MaxMixin, OffsetMixin, EndpointQueryParams):
    """Query parameters for listing interface groups."""

    model_config = ConfigDict(extra="forbid")

    sort: str | None = Field(default=None, min_length=1, description="Sort field and direction")


class InterfaceGroupGetEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """Query parameters for retrieving a single interface group."""

    model_config = ConfigDict(extra="forbid")


class InterfaceGroupMutationEndpointParams(ClusterNameMixin, TicketIdMixin, EndpointQueryParams):
    """Query parameters for interface group mutation endpoints."""

    model_config = ConfigDict(extra="forbid")

    ticket_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z][a-zA-Z0-9_-]+$",
        description="Change Control Ticket Id",
    )


class _EpManageFabricsInterfaceGroupsBase(FabricNameMixin, NDEndpointBaseModel):
    """Base class for ``/api/v1/manage/fabrics/{fabricName}/interfaceGroups``."""

    @property
    def _base_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", quote(self.fabric_name, safe=""), "interfaceGroups")


class EpManageFabricsInterfaceGroupsGet(_EpManageFabricsInterfaceGroupsBase):
    """GET ``/fabrics/{fabricName}/interfaceGroups``."""

    class_name: Literal["EpManageFabricsInterfaceGroupsGet"] = Field(
        default="EpManageFabricsInterfaceGroupsGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: InterfaceGroupsGetEndpointParams = Field(default_factory=InterfaceGroupsGetEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageFabricsInterfaceGroupsPost(_EpManageFabricsInterfaceGroupsBase):
    """POST ``/fabrics/{fabricName}/interfaceGroups``."""

    class_name: Literal["EpManageFabricsInterfaceGroupsPost"] = Field(
        default="EpManageFabricsInterfaceGroupsPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: InterfaceGroupMutationEndpointParams = Field(default_factory=InterfaceGroupMutationEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageFabricsInterfaceGroupsActionsRemovePost(_EpManageFabricsInterfaceGroupsBase):
    """POST ``/fabrics/{fabricName}/interfaceGroups/actions/remove``."""

    class_name: Literal["EpManageFabricsInterfaceGroupsActionsRemovePost"] = Field(
        default="EpManageFabricsInterfaceGroupsActionsRemovePost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: InterfaceGroupMutationEndpointParams = Field(default_factory=InterfaceGroupMutationEndpointParams)

    @property
    def path(self) -> str:
        path = f"{self._base_path}/actions/remove"
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class _EpManageFabricsInterfaceGroupsInterfaceGroupNameBase(
    FabricNameMixin,
    InterfaceGroupNameMixin,
    NDEndpointBaseModel,
):
    """Base class for a single named interface group endpoint."""

    @property
    def _base_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        if self.interface_group_name is None:
            raise ValueError("interface_group_name must be set before accessing path")
        return BasePath.path(
            "fabrics",
            quote(self.fabric_name, safe=""),
            "interfaceGroups",
            quote(self.interface_group_name, safe=""),
        )

    def set_identifiers(self, identifier: IdentifierKey = None):
        """Set the named-resource identifier used by state-machine callers."""
        self.interface_group_name = identifier


class EpManageFabricsInterfaceGroupsInterfaceGroupNameGet(_EpManageFabricsInterfaceGroupsInterfaceGroupNameBase):
    """GET ``/fabrics/{fabricName}/interfaceGroups/{interfaceGroupName}``."""

    class_name: Literal["EpManageFabricsInterfaceGroupsInterfaceGroupNameGet"] = Field(
        default="EpManageFabricsInterfaceGroupsInterfaceGroupNameGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: InterfaceGroupGetEndpointParams = Field(default_factory=InterfaceGroupGetEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageFabricsInterfaceGroupsInterfaceGroupNamePut(_EpManageFabricsInterfaceGroupsInterfaceGroupNameBase):
    """PUT ``/fabrics/{fabricName}/interfaceGroups/{interfaceGroupName}``."""

    class_name: Literal["EpManageFabricsInterfaceGroupsInterfaceGroupNamePut"] = Field(
        default="EpManageFabricsInterfaceGroupsInterfaceGroupNamePut",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: InterfaceGroupMutationEndpointParams = Field(default_factory=InterfaceGroupMutationEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT


class EpManageFabricsInterfaceGroupsInterfaceGroupNameDelete(_EpManageFabricsInterfaceGroupsInterfaceGroupNameBase):
    """DELETE ``/fabrics/{fabricName}/interfaceGroups/{interfaceGroupName}``."""

    class_name: Literal["EpManageFabricsInterfaceGroupsInterfaceGroupNameDelete"] = Field(
        default="EpManageFabricsInterfaceGroupsInterfaceGroupNameDelete",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: InterfaceGroupMutationEndpointParams = Field(default_factory=InterfaceGroupMutationEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE
