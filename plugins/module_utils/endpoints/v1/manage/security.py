# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Endpoint models for Nexus Dashboard Manage Security and Segmentation APIs."""

from __future__ import annotations

from enum import Enum
from typing import ClassVar, Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import ClusterNameMixin, FabricNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import EndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class SecurityListEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """Query parameters shared by security list endpoints."""

    offset: int | None = Field(default=None, ge=0, description="Pagination offset")
    max: int | None = Field(default=None, ge=1, description="Maximum results")
    sort: str | None = Field(default=None, min_length=1, description="Sort field and direction")
    filter: str | None = Field(default=None, min_length=1, description="Lucene filter expression")

    def to_query_string(self) -> str:
        """Return URL-encoded query parameters."""
        params = []
        for field_name, field_value in self.model_dump(exclude_none=True).items():
            api_key = self._to_camel_case(field_name)
            safe_chars = ":" if field_name == "filter" else ""
            params.append(f"{api_key}={quote(_query_value(field_value), safe=safe_chars)}")
        return "&".join(params)


class SecurityActionEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """Query parameters shared by security action endpoints."""

    def to_query_string(self) -> str:
        """Return URL-encoded query parameters."""
        params = []
        for field_name, field_value in self.model_dump(exclude_none=True).items():
            api_key = self._to_camel_case(field_name)
            params.append(f"{api_key}={quote(_query_value(field_value), safe='')}")
        return "&".join(params)


class SecurityDeployEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """Query parameters for fabric deploy after security resource updates."""

    force_show_run: bool | None = Field(default=True, description="Force show running config during deployment")
    incl_all_fabric_groups_switches: bool | None = Field(
        default=None,
        description="Include all switches in fabric groups",
    )

    def to_query_string(self) -> str:
        """Return URL-encoded query parameters."""
        params = []
        for field_name, field_value in self.model_dump(exclude_none=True).items():
            api_key = self._to_camel_case(field_name)
            params.append(f"{api_key}={quote(_query_value(field_value), safe='')}")
        return "&".join(params)


def _query_value(value: object) -> str:
    """Convert query value to an API string before URL encoding."""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


class _SecurityResourceEndpointBase(FabricNameMixin, NDEndpointBaseModel):
    """Base endpoint for fabric-scoped security resources."""

    resource_path: ClassVar[str]
    resource_name: str | None = Field(default=None, min_length=1, description="Security resource name")
    _require_resource_name: ClassVar[bool] = True

    endpoint_params: SecurityListEndpointParams = Field(
        default_factory=SecurityListEndpointParams,
        description="Endpoint query parameters",
    )

    @property
    def path(self) -> str:
        """Return the endpoint path with encoded path segments and optional query string."""
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        if self._require_resource_name and self.resource_name is None:
            raise ValueError(f"{type(self).__name__}.path: resource_name must be set before accessing path.")

        segments = ["fabrics", quote(self.fabric_name, safe=""), self.resource_path]
        if self.resource_name is not None:
            segments.append(quote(self.resource_name, safe=""))
        path = BasePath.path(*segments)
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{path}?{query_string}"
        return path

    def set_identifiers(self, identifier: IdentifierKey = None):
        """Set the resource name identifier."""
        self.resource_name = identifier


class _SecurityActionEndpointBase(FabricNameMixin, NDEndpointBaseModel):
    """Base endpoint for fabric-scoped security action APIs."""

    action_path: ClassVar[str]
    class_name: Literal["_SecurityActionEndpointBase"] = Field(default="_SecurityActionEndpointBase", frozen=True)

    endpoint_params: SecurityActionEndpointParams = Field(
        default_factory=SecurityActionEndpointParams,
        description="Endpoint query parameters",
    )

    @property
    def path(self) -> str:
        """Return the action endpoint path with encoded fabric name."""
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        path = BasePath.path("fabrics", quote(self.fabric_name, safe=""), self.action_path)
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return POST for all security action endpoints."""
        return HttpVerbEnum.POST


class _SecurityFabricActionEndpointBase(FabricNameMixin, NDEndpointBaseModel):
    """Base endpoint for fabric config-save and deploy actions."""

    action_name: ClassVar[str]
    class_name: Literal["_SecurityFabricActionEndpointBase"] = Field(default="_SecurityFabricActionEndpointBase", frozen=True)
    endpoint_params: EndpointQueryParams = Field(default_factory=EndpointQueryParams)

    @property
    def path(self) -> str:
        """Return the fabric action endpoint path with query parameters."""
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        path = BasePath.path("fabrics", quote(self.fabric_name, safe=""), "actions", self.action_name)
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return POST for fabric action endpoints."""
        return HttpVerbEnum.POST


class EpManageSecurityProtocolDefinitionsListGet(_SecurityResourceEndpointBase):
    """GET /fabrics/{fabricName}/securityProtocolDefinitions."""

    resource_path: ClassVar[str] = "securityProtocolDefinitions"
    _require_resource_name: ClassVar[bool] = False
    class_name: Literal["EpManageSecurityProtocolDefinitionsListGet"] = Field(default="EpManageSecurityProtocolDefinitionsListGet", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageSecurityProtocolDefinitionsPost(_SecurityResourceEndpointBase):
    """POST /fabrics/{fabricName}/securityProtocolDefinitions."""

    resource_path: ClassVar[str] = "securityProtocolDefinitions"
    _require_resource_name: ClassVar[bool] = False
    class_name: Literal["EpManageSecurityProtocolDefinitionsPost"] = Field(default="EpManageSecurityProtocolDefinitionsPost", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageSecurityProtocolDefinitionsGet(_SecurityResourceEndpointBase):
    """GET /fabrics/{fabricName}/securityProtocolDefinitions/{protocolDefinitionName}."""

    resource_path: ClassVar[str] = "securityProtocolDefinitions"
    class_name: Literal["EpManageSecurityProtocolDefinitionsGet"] = Field(default="EpManageSecurityProtocolDefinitionsGet", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageSecurityProtocolDefinitionsPut(_SecurityResourceEndpointBase):
    """PUT /fabrics/{fabricName}/securityProtocolDefinitions/{protocolDefinitionName}."""

    resource_path: ClassVar[str] = "securityProtocolDefinitions"
    class_name: Literal["EpManageSecurityProtocolDefinitionsPut"] = Field(default="EpManageSecurityProtocolDefinitionsPut", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT


class EpManageSecurityProtocolDefinitionsDelete(_SecurityResourceEndpointBase):
    """DELETE /fabrics/{fabricName}/securityProtocolDefinitions/{protocolDefinitionName}."""

    resource_path: ClassVar[str] = "securityProtocolDefinitions"
    class_name: Literal["EpManageSecurityProtocolDefinitionsDelete"] = Field(default="EpManageSecurityProtocolDefinitionsDelete", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE


class EpManageSecurityProtocolDefinitionsRemove(_SecurityActionEndpointBase):
    """POST /fabrics/{fabricName}/securityProtocolDefinitionActions/remove."""

    action_path: ClassVar[str] = "securityProtocolDefinitionActions/remove"
    class_name: Literal["EpManageSecurityProtocolDefinitionsRemove"] = Field(default="EpManageSecurityProtocolDefinitionsRemove", frozen=True)


class EpManageSecurityContractsListGet(_SecurityResourceEndpointBase):
    """GET /fabrics/{fabricName}/securityContracts."""

    resource_path: ClassVar[str] = "securityContracts"
    _require_resource_name: ClassVar[bool] = False
    class_name: Literal["EpManageSecurityContractsListGet"] = Field(default="EpManageSecurityContractsListGet", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageSecurityContractsPost(_SecurityResourceEndpointBase):
    """POST /fabrics/{fabricName}/securityContracts."""

    resource_path: ClassVar[str] = "securityContracts"
    _require_resource_name: ClassVar[bool] = False
    class_name: Literal["EpManageSecurityContractsPost"] = Field(default="EpManageSecurityContractsPost", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageSecurityContractsGet(_SecurityResourceEndpointBase):
    """GET /fabrics/{fabricName}/securityContracts/{contractName}."""

    resource_path: ClassVar[str] = "securityContracts"
    class_name: Literal["EpManageSecurityContractsGet"] = Field(default="EpManageSecurityContractsGet", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageSecurityContractsPut(_SecurityResourceEndpointBase):
    """PUT /fabrics/{fabricName}/securityContracts/{contractName}."""

    resource_path: ClassVar[str] = "securityContracts"
    class_name: Literal["EpManageSecurityContractsPut"] = Field(default="EpManageSecurityContractsPut", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT


class EpManageSecurityContractsDelete(_SecurityResourceEndpointBase):
    """DELETE /fabrics/{fabricName}/securityContracts/{contractName}."""

    resource_path: ClassVar[str] = "securityContracts"
    class_name: Literal["EpManageSecurityContractsDelete"] = Field(default="EpManageSecurityContractsDelete", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE


class EpManageSecurityContractsRemove(_SecurityActionEndpointBase):
    """POST /fabrics/{fabricName}/securityContractActions/remove."""

    action_path: ClassVar[str] = "securityContractActions/remove"
    class_name: Literal["EpManageSecurityContractsRemove"] = Field(default="EpManageSecurityContractsRemove", frozen=True)


class EpManageSecurityGroupsListGet(_SecurityResourceEndpointBase):
    """GET /fabrics/{fabricName}/securityGroups."""

    resource_path: ClassVar[str] = "securityGroups"
    _require_resource_name: ClassVar[bool] = False
    class_name: Literal["EpManageSecurityGroupsListGet"] = Field(default="EpManageSecurityGroupsListGet", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageSecurityGroupsPost(_SecurityResourceEndpointBase):
    """POST /fabrics/{fabricName}/securityGroups."""

    resource_path: ClassVar[str] = "securityGroups"
    _require_resource_name: ClassVar[bool] = False
    class_name: Literal["EpManageSecurityGroupsPost"] = Field(default="EpManageSecurityGroupsPost", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageSecurityGroupsGet(_SecurityResourceEndpointBase):
    """GET /fabrics/{fabricName}/securityGroups/{securityGroupName}."""

    resource_path: ClassVar[str] = "securityGroups"
    class_name: Literal["EpManageSecurityGroupsGet"] = Field(default="EpManageSecurityGroupsGet", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageSecurityGroupsPut(_SecurityResourceEndpointBase):
    """PUT /fabrics/{fabricName}/securityGroups/{securityGroupName}."""

    resource_path: ClassVar[str] = "securityGroups"
    class_name: Literal["EpManageSecurityGroupsPut"] = Field(default="EpManageSecurityGroupsPut", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT


class EpManageSecurityGroupsDelete(_SecurityResourceEndpointBase):
    """DELETE /fabrics/{fabricName}/securityGroups/{securityGroupName}."""

    resource_path: ClassVar[str] = "securityGroups"
    class_name: Literal["EpManageSecurityGroupsDelete"] = Field(default="EpManageSecurityGroupsDelete", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE


class EpManageSecurityGroupsRemove(_SecurityActionEndpointBase):
    """POST /fabrics/{fabricName}/securityGroupActions/remove."""

    action_path: ClassVar[str] = "securityGroupActions/remove"
    class_name: Literal["EpManageSecurityGroupsRemove"] = Field(default="EpManageSecurityGroupsRemove", frozen=True)


class EpManageSecurityGroupsAttach(_SecurityActionEndpointBase):
    """POST /fabrics/{fabricName}/securityGroupActions/attach."""

    action_path: ClassVar[str] = "securityGroupActions/attach"
    class_name: Literal["EpManageSecurityGroupsAttach"] = Field(default="EpManageSecurityGroupsAttach", frozen=True)


class EpManageSecurityGroupsDetach(_SecurityActionEndpointBase):
    """POST /fabrics/{fabricName}/securityGroupActions/detach."""

    action_path: ClassVar[str] = "securityGroupActions/detach"
    class_name: Literal["EpManageSecurityGroupsDetach"] = Field(default="EpManageSecurityGroupsDetach", frozen=True)


class EpManageSecurityAssociationsListGet(_SecurityResourceEndpointBase):
    """GET /fabrics/{fabricName}/securityAssociations."""

    resource_path: ClassVar[str] = "securityAssociations"
    _require_resource_name: ClassVar[bool] = False
    class_name: Literal["EpManageSecurityAssociationsListGet"] = Field(default="EpManageSecurityAssociationsListGet", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageSecurityAssociationsPost(_SecurityResourceEndpointBase):
    """POST /fabrics/{fabricName}/securityAssociations."""

    resource_path: ClassVar[str] = "securityAssociations"
    _require_resource_name: ClassVar[bool] = False
    class_name: Literal["EpManageSecurityAssociationsPost"] = Field(default="EpManageSecurityAssociationsPost", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageSecurityAssociationsGet(_SecurityResourceEndpointBase):
    """GET /fabrics/{fabricName}/securityAssociations/{securityAssociationName}."""

    resource_path: ClassVar[str] = "securityAssociations"
    class_name: Literal["EpManageSecurityAssociationsGet"] = Field(default="EpManageSecurityAssociationsGet", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageSecurityAssociationsPut(_SecurityResourceEndpointBase):
    """PUT /fabrics/{fabricName}/securityAssociations/{securityAssociationName}."""

    resource_path: ClassVar[str] = "securityAssociations"
    class_name: Literal["EpManageSecurityAssociationsPut"] = Field(default="EpManageSecurityAssociationsPut", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT


class EpManageSecurityAssociationsDelete(_SecurityResourceEndpointBase):
    """DELETE /fabrics/{fabricName}/securityAssociations/{securityAssociationName}."""

    resource_path: ClassVar[str] = "securityAssociations"
    class_name: Literal["EpManageSecurityAssociationsDelete"] = Field(default="EpManageSecurityAssociationsDelete", frozen=True)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE


class EpManageSecurityAssociationsRemove(_SecurityActionEndpointBase):
    """POST /fabrics/{fabricName}/securityAssociationActions/remove."""

    action_path: ClassVar[str] = "securityAssociationActions/remove"
    class_name: Literal["EpManageSecurityAssociationsRemove"] = Field(default="EpManageSecurityAssociationsRemove", frozen=True)


class EpManageSecurityAssociationsAttach(_SecurityActionEndpointBase):
    """POST /fabrics/{fabricName}/securityAssociationActions/attach."""

    action_path: ClassVar[str] = "securityAssociationActions/attach"
    class_name: Literal["EpManageSecurityAssociationsAttach"] = Field(default="EpManageSecurityAssociationsAttach", frozen=True)


class EpManageSecurityAssociationsDetach(_SecurityActionEndpointBase):
    """POST /fabrics/{fabricName}/securityAssociationActions/detach."""

    action_path: ClassVar[str] = "securityAssociationActions/detach"
    class_name: Literal["EpManageSecurityAssociationsDetach"] = Field(default="EpManageSecurityAssociationsDetach", frozen=True)


class EpManageSecurityFabricConfigSave(_SecurityFabricActionEndpointBase):
    """POST /fabrics/{fabricName}/actions/configSave."""

    action_name: ClassVar[str] = "configSave"
    endpoint_params: SecurityActionEndpointParams = Field(default_factory=SecurityActionEndpointParams)
    class_name: Literal["EpManageSecurityFabricConfigSave"] = Field(default="EpManageSecurityFabricConfigSave", frozen=True)


class EpManageSecurityFabricDeploy(_SecurityFabricActionEndpointBase):
    """POST /fabrics/{fabricName}/actions/deploy."""

    action_name: ClassVar[str] = "deploy"
    endpoint_params: SecurityDeployEndpointParams = Field(default_factory=SecurityDeployEndpointParams)
    class_name: Literal["EpManageSecurityFabricDeploy"] = Field(default="EpManageSecurityFabricDeploy", frozen=True)
