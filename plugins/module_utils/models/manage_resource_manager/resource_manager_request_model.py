
# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
ResourceModel - GET response model for a single resource allocation.

COMPOSITE model: contains Union[FabricScope, DeviceScope, DeviceInterfaceScope,
LinkScope, DevicePairScope] as the scope_details field.

Based on OpenAPI schema: resourceDetailsGet (allOf resourceDataBase + createTimestamp)
Discriminator mapping (scopeType):
  'fabric'          -> FabricScope
  'device'          -> DeviceScope
  'deviceInterface' -> DeviceInterfaceScope
  'link'            -> LinkScope
  'devicePair'      -> DevicePairScope

Endpoints:
  GET    /fabrics/{fabricName}/resources
  GET    /fabrics/{fabricName}/resources/{resourceId}
  DELETE /fabrics/{fabricName}/resources/{resourceId}
"""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any, ClassVar, Dict, List, Literal, Optional, Union

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field, field_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_validators import (
    ResourceValidators,
)


class FabricScope(NDNestedModel):
    """
    Scope details for resources under Fabric scope.

    Based on OpenAPI schema: fabricScope
    Required: scopeType (enum: 'fabric')
    """

    identifiers: ClassVar[List[str]] = []

    scope_type: Literal["fabric"] = Field(
        default="fabric",
        alias="scopeType",
        description="Scope level: must be 'fabric'",
    )
    fabric_name: Optional[str] = Field(
        default=None,
        alias="fabricName",
        description="Name of the fabric",
    )

    @field_validator("fabric_name", mode="before")
    @classmethod
    def validate_fabric_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = str(v).strip()
        return v if v else None


class DeviceScope(NDNestedModel):
    """
    Scope details for resources under Device scope.

    Based on OpenAPI schema: deviceScope
    Required: scopeType (enum: 'device')
    """

    identifiers: ClassVar[List[str]] = []

    scope_type: Literal["device"] = Field(
        default="device",
        alias="scopeType",
        description="Scope level: must be 'device'",
    )
    switch_name: Optional[str] = Field(
        default=None,
        alias="switchName",
        description="Name of the switch",
    )
    switch_id: Optional[str] = Field(
        default=None,
        alias="switchId",
        description="Serial number of the switch",
    )
    switch_ip: Optional[str] = Field(
        default=None,
        alias="switchIp",
        description="IP address of the switch",
    )

    @field_validator("switch_name", mode="before")
    @classmethod
    def validate_switch_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return str(v).strip() or None

    @field_validator("switch_id", mode="before")
    @classmethod
    def validate_switch_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return str(v).strip() or None

    @field_validator("switch_ip", mode="before")
    @classmethod
    def validate_switch_ip(cls, v: Optional[str]) -> Optional[str]:
        return ResourceValidators.validate_ip_address(v)


class DeviceInterfaceScope(NDNestedModel):
    """
    Scope details for resources under DeviceInterface scope.

    Based on OpenAPI schema: deviceInterfaceScope
    Required: scopeType (enum: 'deviceInterface')
    """

    identifiers: ClassVar[List[str]] = []

    scope_type: Literal["deviceInterface"] = Field(
        default="deviceInterface",
        alias="scopeType",
        description="Scope level: must be 'deviceInterface'",
    )
    switch_name: Optional[str] = Field(
        default=None,
        alias="switchName",
        description="Name of the switch",
    )
    switch_id: Optional[str] = Field(
        default=None,
        alias="switchId",
        description="Serial number of the switch",
    )
    switch_ip: Optional[str] = Field(
        default=None,
        alias="switchIp",
        description="IP address of the switch",
    )
    interface_name: Optional[str] = Field(
        default=None,
        alias="interfaceName",
        description="Interface name",
    )

    @field_validator("switch_name", mode="before")
    @classmethod
    def validate_switch_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return str(v).strip() or None

    @field_validator("switch_id", mode="before")
    @classmethod
    def validate_switch_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return str(v).strip() or None

    @field_validator("switch_ip", mode="before")
    @classmethod
    def validate_switch_ip(cls, v: Optional[str]) -> Optional[str]:
        return ResourceValidators.validate_ip_address(v)

    @field_validator("interface_name", mode="before")
    @classmethod
    def validate_interface_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return str(v).strip() or None


class LinkScope(NDNestedModel):
    """
    Scope details for resources under Link scope.

    Based on OpenAPI schema: linkScope
    Required: scopeType (enum: 'link')
    """

    identifiers: ClassVar[List[str]] = []

    scope_type: Literal["link"] = Field(
        default="link",
        alias="scopeType",
        description="Scope level: must be 'link'",
    )
    src_switch_name: Optional[str] = Field(
        default=None,
        alias="srcSwitchName",
        description="Name of the source switch",
    )
    src_switch_id: Optional[str] = Field(
        default=None,
        alias="srcSwitchId",
        description="Serial number of the source switch",
    )
    src_switch_ip: Optional[str] = Field(
        default=None,
        alias="srcSwitchIp",
        description="IP address of the source switch",
    )
    src_interface_name: Optional[str] = Field(
        default=None,
        alias="srcInterfaceName",
        description="Source interface name",
    )
    dst_switch_name: Optional[str] = Field(
        default=None,
        alias="dstSwitchName",
        description="Name of the destination switch",
    )
    dst_switch_id: Optional[str] = Field(
        default=None,
        alias="dstSwitchId",
        description="Serial number of the destination switch",
    )
    dst_switch_ip: Optional[str] = Field(
        default=None,
        alias="dstSwitchIp",
        description="IP address of the destination switch",
    )
    dst_interface_name: Optional[str] = Field(
        default=None,
        alias="dstInterfaceName",
        description="Destination interface name",
    )

    @field_validator("src_switch_name", "dst_switch_name", mode="before")
    @classmethod
    def validate_switch_names(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return str(v).strip() or None

    @field_validator("src_switch_id", "dst_switch_id", mode="before")
    @classmethod
    def validate_switch_ids(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return str(v).strip() or None

    @field_validator("src_switch_ip", "dst_switch_ip", mode="before")
    @classmethod
    def validate_switch_ips(cls, v: Optional[str]) -> Optional[str]:
        return ResourceValidators.validate_ip_address(v)

    @field_validator("src_interface_name", "dst_interface_name", mode="before")
    @classmethod
    def validate_interface_names(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return str(v).strip() or None


class DevicePairScope(NDNestedModel):
    """
    Scope details for resources under DevicePair scope.

    Based on OpenAPI schema: devicePairScope
    Required: scopeType (enum: 'devicePair')
    """

    identifiers: ClassVar[List[str]] = []

    scope_type: Literal["devicePair"] = Field(
        default="devicePair",
        alias="scopeType",
        description="Scope level: must be 'devicePair'",
    )
    src_switch_name: Optional[str] = Field(
        default=None,
        alias="srcSwitchName",
        description="Name of the source switch",
    )
    src_switch_id: Optional[str] = Field(
        default=None,
        alias="srcSwitchId",
        description="Serial number of the source switch",
    )
    src_switch_ip: Optional[str] = Field(
        default=None,
        alias="srcSwitchIp",
        description="IP address of the source switch",
    )
    dst_switch_name: Optional[str] = Field(
        default=None,
        alias="dstSwitchName",
        description="Name of the destination switch",
    )
    dst_switch_id: Optional[str] = Field(
        default=None,
        alias="dstSwitchId",
        description="Serial number of the destination switch",
    )
    dst_switch_ip: Optional[str] = Field(
        default=None,
        alias="dstSwitchIp",
        description="IP address of the destination switch",
    )
    peer_resource_id: Optional[int] = Field(
        default=None,
        alias="peerResourceId",
        description="Resource ID on the destination switch",
        ge=0,
    )

    @field_validator("src_switch_name", "dst_switch_name", mode="before")
    @classmethod
    def validate_switch_names(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return str(v).strip() or None

    @field_validator("src_switch_id", "dst_switch_id", mode="before")
    @classmethod
    def validate_switch_ids(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return str(v).strip() or None

    @field_validator("src_switch_ip", "dst_switch_ip", mode="before")
    @classmethod
    def validate_switch_ips(cls, v: Optional[str]) -> Optional[str]:
        return ResourceValidators.validate_ip_address(v)

    @field_validator("peer_resource_id", mode="before")
    @classmethod
    def validate_peer_resource_id(cls, v: Optional[Any]) -> Optional[int]:
        if v is None:
            return None
        try:
            val = int(v)
        except (ValueError, TypeError):
            raise ValueError(f"peer_resource_id must be an integer, got: {v!r}")
        if val < 0:
            raise ValueError(f"peer_resource_id must be >= 0, got: {val}")
        return val


class ResourceManagerRequest(NDNestedModel):
    """
    Schema for GET APIs that contain resource allocation details.

    Based on OpenAPI schema: resourceDetailsGet (allOf resourceDataBase + createTimestamp)
    Composite: scope_details is discriminated by scopeType.

    Path: GET    /fabrics/{fabricName}/resources
    Path: GET    /fabrics/{fabricName}/resources/{resourceId}
    Path: DELETE /fabrics/{fabricName}/resources/{resourceId}
    """

    identifiers: ClassVar[List[str]] = ["resource_id"]
    identifier_strategy: ClassVar[Literal["single"]] = "single"
    exclude_from_diff: ClassVar[List[str]] = []

    pool_name: Optional[str] = Field(
        default=None,
        alias="poolName",
        description="Pool under which the resource is allocated",
    )
    pool_type: Optional[str] = Field(
        default=None,
        alias="poolType",
        description="Type of pool: ID, IP, or SUBNET",
    )
    scope_details: Optional[Union[FabricScope, DeviceScope, DeviceInterfaceScope, LinkScope, DevicePairScope]] = Field(
        default=None,
        alias="scopeDetails",
        description="Scope details; discriminated by scopeType",
    )
    is_pre_allocated: Optional[bool] = Field(
        default=False,
        alias="isPreAllocated",
        description="true if the resource is pre-allocated (reserved) to an entity",
    )
    entity_name: Optional[str] = Field(
        default=None,
        alias="entityName",
        description="Name by which the resource is allocated",
    )
    resource_value: Optional[str] = Field(
        default=None,
        alias="resourceValue",
        description="Resource value: an ID, IP address, or subnet/CIDR",
    )
    resource_id: Optional[int] = Field(
        default=None,
        alias="resourceId",
        description="Unique identifier of the allocated resource",
        ge=0,
    )
    vrf_name: Optional[str] = Field(
        default="default",
        alias="vrfName",
        description="VRF name when the pool is VRF-scoped; 'default' otherwise",
    )
    create_timestamp: Optional[str] = Field(
        default=None,
        alias="createTimestamp",
        description="Timestamp when the resource was allocated or reserved",
    )

    @field_validator("pool_name", mode="before")
    @classmethod
    def validate_pool_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = str(v).strip()
        return v if v else None

    @field_validator("entity_name", mode="before")
    @classmethod
    def validate_entity_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = str(v).strip()
        return v if v else None

    @field_validator("resource_value", mode="before")
    @classmethod
    def validate_resource_value(cls, v: Optional[str]) -> Optional[str]:
        """Validate resource_value: accepts an integer ID string, IPv4/v6 address,
        or CIDR subnet notation. Opaque string values are passed through."""
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        # Try integer ID
        try:
            int(v)
            return v
        except ValueError:
            pass
        # Try IP address
        try:
            ip_address(v)
            return v
        except ValueError:
            pass
        # Try CIDR
        try:
            return ResourceValidators.validate_cidr(v)
        except ValueError:
            pass
        # Fall through: return as-is (opaque string used by some pool types)
        return v

    @field_validator("resource_id", mode="before")
    @classmethod
    def validate_resource_id(cls, v: Optional[Any]) -> Optional[int]:
        if v is None:
            return None
        try:
            val = int(v)
        except (ValueError, TypeError):
            raise ValueError(f"resource_id must be an integer, got: {v!r}")
        if val < 0:
            raise ValueError(f"resource_id must be >= 0, got: {val}")
        return val

    @field_validator("vrf_name", mode="before")
    @classmethod
    def validate_vrf_name(cls, v: Optional[str]) -> str:
        if v is None:
            return "default"
        v = str(v).strip()
        return v if v else "default"

    @field_validator("create_timestamp", mode="before")
    @classmethod
    def validate_create_timestamp(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return str(v).strip() or None

    @field_validator("is_pre_allocated", mode="before")
    @classmethod
    def validate_is_pre_allocated(cls, v: Any) -> bool:
        if isinstance(v, bool):
            return v
        if v is None:
            return False
        if isinstance(v, str):
            lower = v.strip().lower()
            if lower in ("true", "yes", "1"):
                return True
            if lower in ("false", "no", "0"):
                return False
        raise ValueError(f"is_pre_allocated must be a boolean, got: {v!r}")

    @field_validator("scope_details", mode="before")
    @classmethod
    def route_scope_details(cls, v: Any) -> Any:
        """Route scopeDetails dict to the correct nested scope model based on scopeType.

        scopeType discriminator mapping (from OpenAPI spec):
          'fabric'          -> FabricScope
          'device'          -> DeviceScope
          'deviceInterface' -> DeviceInterfaceScope
          'link'            -> LinkScope
          'devicePair'      -> DevicePairScope
        """
        if v is None or not isinstance(v, dict):
            return v
        scope_type = v.get("scopeType")
        if scope_type is None:
            return v
        model_map = {
            "fabric": FabricScope,
            "device": DeviceScope,
            "deviceInterface": DeviceInterfaceScope,
            "link": LinkScope,
            "devicePair": DevicePairScope,
        }
        target_cls = model_map.get(scope_type)
        if target_cls is None:
            raise ValueError(f"Unknown scopeType: {scope_type!r}. " f"Allowed values: {list(model_map.keys())}")
        return target_cls.model_validate(v)

    def to_payload(self) -> Dict[str, Any]:
        """Convert to API payload format."""
        return self.model_dump(by_alias=True, exclude_none=True)

    @classmethod
    def from_response(cls, response: Dict[str, Any]) -> "ResourceModel":
        """Create model instance from API response.

        Handles the resourceDetailsGet schema which is an allOf of
        resourceDataBase and a createTimestamp extension.

        Args:
            response: Response dict from the resources API.

        Returns:
            ResourceModel instance.
        """
        return cls.model_validate(response)

    def to_config_dict(self) -> Dict[str, Any]:
        """Return a user-facing configuration dictionary for this resource.

        Produces a consistent dict suitable for display and diff output.
        Scope-specific fields are flattened into top-level keys so callers
        need not inspect scope_details directly.

        Returns:
            Dict with resource identity and scope-specific details.
        """
        scope = self.scope_details
        scope_type = scope.scope_type if scope is not None else None

        config: Dict[str, Any] = {
            "resource_id": self.resource_id,
            "pool_name": self.pool_name,
            "resource_value": self.resource_value,
            "entity_name": self.entity_name,
            "vrf_name": self.vrf_name,
            "is_pre_allocated": self.is_pre_allocated,
            "create_timestamp": self.create_timestamp,
            "scope_type": scope_type,
        }

        if isinstance(scope, FabricScope):
            config["fabric_name"] = scope.fabric_name
        elif isinstance(scope, DeviceInterfaceScope):
            config["switch_name"] = scope.switch_name
            config["switch_id"] = scope.switch_id
            config["switch_ip"] = scope.switch_ip
            config["interface_name"] = scope.interface_name
        elif isinstance(scope, DeviceScope):
            config["switch_name"] = scope.switch_name
            config["switch_id"] = scope.switch_id
            config["switch_ip"] = scope.switch_ip
        elif isinstance(scope, LinkScope):
            config["src_switch_name"] = scope.src_switch_name
            config["src_switch_id"] = scope.src_switch_id
            config["src_switch_ip"] = scope.src_switch_ip
            config["src_interface_name"] = scope.src_interface_name
            config["dst_switch_name"] = scope.dst_switch_name
            config["dst_switch_id"] = scope.dst_switch_id
            config["dst_switch_ip"] = scope.dst_switch_ip
            config["dst_interface_name"] = scope.dst_interface_name
        elif isinstance(scope, DevicePairScope):
            config["src_switch_name"] = scope.src_switch_name
            config["src_switch_id"] = scope.src_switch_id
            config["src_switch_ip"] = scope.src_switch_ip
            config["dst_switch_name"] = scope.dst_switch_name
            config["dst_switch_id"] = scope.dst_switch_id
            config["dst_switch_ip"] = scope.dst_switch_ip
            config["peer_resource_id"] = scope.peer_resource_id

        return config


class ResourceManagerBatchRequest(NDBaseModel):
    """
    Request body for POST /fabrics/{fabricName}/resources using Ansible-style config.

    Composite: contains List[ResourceManagerRequest].
    Each item is validated with ResourceManagerRequest before submission.
    """

    identifiers: ClassVar[List[str]] = []

    resources: List[ResourceManagerRequest] = Field(description="Array of resource configs to allocate")

    def to_payload(self) -> Dict[str, Any]:
        """Convert to API payload format."""
        return self.model_dump(by_alias=True, exclude_none=True)
