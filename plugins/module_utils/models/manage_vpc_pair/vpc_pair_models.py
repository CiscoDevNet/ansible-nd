# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)



"""
Pydantic models for VPC pair management in Nexus Dashboard 4.x API.

This module provides comprehensive models covering all 34 OpenAPI schemas
organized into functional domains:
- Configuration Domain: VPC pairing and lifecycle management
- Inventory Domain: VPC pair listing and discovery
- Monitoring Domain: Health, status, and operational metrics
- Consistency Domain: Configuration consistency validation
- Validation Domain: Support checks and peer recommendations
"""

from typing import List, Dict, Any, Optional, Union, ClassVar, Literal
try:
    from typing import Self
except ImportError:  # pragma: no cover - Python < 3.11
    Self = Any  # type: ignore[misc,assignment]
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vpc_pair.vpc_pair_base import (
    FlexibleBool,
    FlexibleInt,
    FlexibleListStr,
    SwitchPairKeyMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vpc_pair.vpc_pair_common import (
    validate_distinct_switches,
    validate_non_empty_switch_id,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import (
    NDBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)

# Import enums from centralized location
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.enums import (
    VpcActionEnum,
    KeepAliveVrfEnum,
    VpcRoleEnum,
    ComponentTypeOverviewEnum,
)

# ============================================================================
# NESTED MODELS (No Identifiers)
# ============================================================================


class SwitchInfo(NDNestedModel):
    """Generic switch information for both peers."""

    switch: str = Field(alias="switch", description="Switch value")
    peer_switch: str = Field(alias="peerSwitch", description="Peer switch value")


class SwitchIntInfo(NDNestedModel):
    """Generic switch integer information for both peers."""

    switch: FlexibleInt = Field(alias="switch", description="Switch value")
    peer_switch: FlexibleInt = Field(alias="peerSwitch", description="Peer switch value")


class SwitchBoolInfo(NDNestedModel):
    """Generic switch boolean information for both peers."""

    switch: FlexibleBool = Field(alias="switch", description="Switch value")
    peer_switch: FlexibleBool = Field(alias="peerSwitch", description="Peer switch value")


class SyncCounts(NDNestedModel):
    """Sync status counts."""

    in_sync: FlexibleInt = Field(default=0, alias="inSync", description="In-sync items")
    pending: FlexibleInt = Field(default=0, alias="pending", description="Pending items")
    out_of_sync: FlexibleInt = Field(default=0, alias="outOfSync", description="Out-of-sync items")
    in_progress: FlexibleInt = Field(default=0, alias="inProgress", description="In-progress items")


class AnomaliesCount(NDNestedModel):
    """Anomaly counts by severity."""

    critical: FlexibleInt = Field(default=0, alias="critical", description="Critical anomalies")
    major: FlexibleInt = Field(default=0, alias="major", description="Major anomalies")
    minor: FlexibleInt = Field(default=0, alias="minor", description="Minor anomalies")
    warning: FlexibleInt = Field(default=0, alias="warning", description="Warning anomalies")


class HealthMetrics(NDNestedModel):
    """Health metrics for both switches."""

    switch: str = Field(alias="switch", description="Switch health status")
    peer_switch: str = Field(alias="peerSwitch", description="Peer switch health status")


class ResourceMetrics(NDNestedModel):
    """Resource utilization metrics."""

    switch: FlexibleInt = Field(alias="switch", description="Switch metric value")
    peer_switch: FlexibleInt = Field(alias="peerSwitch", description="Peer switch metric value")


class InterfaceStatusCounts(NDNestedModel):
    """Interface status counts."""

    up: FlexibleInt = Field(alias="up", description="Interfaces in up state")
    down: FlexibleInt = Field(alias="down", description="Interfaces in down state")


class LogicalInterfaceCounts(NDNestedModel):
    """Logical interface type counts."""

    port_channel: FlexibleInt = Field(alias="portChannel", description="Port channel interfaces")
    loopback: FlexibleInt = Field(alias="loopback", description="Loopback interfaces")
    vpc: FlexibleInt = Field(alias="vPC", description="VPC interfaces")
    vlan: FlexibleInt = Field(alias="vlan", description="VLAN interfaces")
    nve: FlexibleInt = Field(alias="nve", description="NVE interfaces")


class ResponseCounts(NDNestedModel):
    """Response metadata counts."""

    total: FlexibleInt = Field(alias="total", description="Total count")
    remaining: FlexibleInt = Field(alias="remaining", description="Remaining count")


# ============================================================================
# VPC PAIR DETAILS MODELS (Nested Template Configuration)
# ============================================================================


class VpcPairDetailsDefault(NDNestedModel):
    """
    Default template VPC pair configuration.

    OpenAPI: vpcPairDetailsDefault
    """

    type: Literal["default"] = Field(default="default", alias="type", description="Template type")
    domain_id: Optional[FlexibleInt] = Field(default=None, alias="domainId", description="VPC domain ID")
    switch_keep_alive_local_ip: Optional[str] = Field(default=None, alias="switchKeepAliveLocalIp", description="Peer-1 keep-alive IP")
    peer_switch_keep_alive_local_ip: Optional[str] = Field(default=None, alias="peerSwitchKeepAliveLocalIp", description="Peer-2 keep-alive IP")
    keep_alive_vrf: Optional[KeepAliveVrfEnum] = Field(default=None, alias="keepAliveVrf", description="Keep-alive VRF")
    keep_alive_hold_timeout: Optional[FlexibleInt] = Field(default=3, alias="keepAliveHoldTimeout", description="Keep-alive hold timeout")
    enable_mirror_config: Optional[FlexibleBool] = Field(default=False, alias="enableMirrorConfig", description="Enable config mirroring")
    is_vpc_plus: Optional[FlexibleBool] = Field(default=False, alias="isVpcPlus", description="VPC+ topology")
    fabric_path_switch_id: Optional[FlexibleInt] = Field(default=None, alias="fabricPathSwitchId", description="FabricPath switch ID")
    is_vteps: Optional[FlexibleBool] = Field(default=False, alias="isVteps", description="Configure NVE source loopback")
    nve_interface: Optional[FlexibleInt] = Field(default=1, alias="nveInterface", description="NVE interface")
    switch_source_loopback: Optional[FlexibleInt] = Field(default=None, alias="switchSourceLoopback", description="Peer-1 source loopback")
    peer_switch_source_loopback: Optional[FlexibleInt] = Field(default=None, alias="peerSwitchSourceLoopback", description="Peer-2 source loopback")
    switch_primary_ip: Optional[str] = Field(default=None, alias="switchPrimaryIp", description="Peer-1 primary IP")
    peer_switch_primary_ip: Optional[str] = Field(default=None, alias="peerSwitchPrimaryIp", description="Peer-2 primary IP")
    loopback_secondary_ip: Optional[str] = Field(default=None, alias="loopbackSecondaryIp", description="Secondary loopback IP")
    switch_domain_config: Optional[str] = Field(default=None, alias="switchDomainConfig", description="Peer-1 domain config CLI")
    peer_switch_domain_config: Optional[str] = Field(default=None, alias="peerSwitchDomainConfig", description="Peer-2 domain config CLI")
    switch_po_id: Optional[FlexibleInt] = Field(default=None, alias="switchPoId", description="Peer-1 port-channel ID")
    peer_switch_po_id: Optional[FlexibleInt] = Field(default=None, alias="peerSwitchPoId", description="Peer-2 port-channel ID")
    switch_member_interfaces: Optional[FlexibleListStr] = Field(default=None, alias="switchMemberInterfaces", description="Peer-1 member interfaces")
    peer_switch_member_interfaces: Optional[FlexibleListStr] = Field(default=None, alias="peerSwitchMemberInterfaces", description="Peer-2 member interfaces")
    po_mode: Optional[str] = Field(default="active", alias="poMode", description="Port-channel mode")
    switch_po_description: Optional[str] = Field(default=None, alias="switchPoDescription", description="Peer-1 port-channel description")
    peer_switch_po_description: Optional[str] = Field(default=None, alias="peerSwitchPoDescription", description="Peer-2 port-channel description")
    admin_state: Optional[FlexibleBool] = Field(default=True, alias="adminState", description="Admin state")
    allowed_vlans: Optional[str] = Field(default="all", alias="allowedVlans", description="Allowed VLANs")
    switch_native_vlan: Optional[FlexibleInt] = Field(default=None, alias="switchNativeVlan", description="Peer-1 native VLAN")
    peer_switch_native_vlan: Optional[FlexibleInt] = Field(default=None, alias="peerSwitchNativeVlan", description="Peer-2 native VLAN")
    switch_po_config: Optional[str] = Field(default=None, alias="switchPoConfig", description="Peer-1 port-channel freeform config")
    peer_switch_po_config: Optional[str] = Field(default=None, alias="peerSwitchPoConfig", description="Peer-2 port-channel freeform config")
    fabric_name: Optional[str] = Field(default=None, alias="fabricName", description="Fabric name")


class VpcPairDetailsCustom(NDNestedModel):
    """
    Custom template VPC pair configuration.

    OpenAPI: vpcPairDetailsCustom
    """

    type: Literal["custom"] = Field(default="custom", alias="type", description="Template type")
    template_name: str = Field(alias="templateName", description="Name of the custom template")
    template_config: Dict[str, Any] = Field(alias="templateConfig", description="Free-form configuration")


# ============================================================================
# CONFIGURATION DOMAIN MODELS
# ============================================================================


class VpcPairBase(SwitchPairKeyMixin, NDBaseModel):
    """
    Base schema for VPC pairing with common properties.

    Identifier: (switch_id, peer_switch_id) - composite
    OpenAPI: vpcPairBase

    Note: The nd_vpc_pair module uses a separate VpcPairModel class (not this one) because:
    - Module uses NDBaseModel base class for framework integration
    - Module needs strict bool types, this uses FlexibleBool for API flexibility
    See plugins/modules/nd_vpc_pair.py VpcPairModel for the module-specific implementation.
    """

    # Identifier configuration
    identifiers: ClassVar[List[str]] = ["switch_id", "peer_switch_id"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical"]] = "composite"

    # Fields with validation constraints
    switch_id: str = Field(
        alias="switchId",
        description="Switch serial number (Peer-1)",
        min_length=3,
        max_length=64
    )
    peer_switch_id: str = Field(
        alias="peerSwitchId",
        description="Peer switch serial number (Peer-2)",
        min_length=3,
        max_length=64
    )
    use_virtual_peer_link: FlexibleBool = Field(default=False, alias="useVirtualPeerLink", description="Virtual peer link present")
    vpc_pair_details: Optional[Union[VpcPairDetailsDefault, VpcPairDetailsCustom]] = Field(
        default=None, discriminator="type", alias="vpcPairDetails", description="VPC pair configuration details"
    )

    @field_validator("switch_id", "peer_switch_id")
    @classmethod
    def validate_switch_id_format(cls, v: str) -> str:
        """
        Validate switch ID is not empty or whitespace.

        Args:
            v: Switch ID value

        Returns:
            Stripped switch ID

        Raises:
            ValueError: If switch ID is empty or whitespace
        """
        return validate_non_empty_switch_id(v)

    @model_validator(mode="after")
    def validate_different_switches(self) -> Self:
        """
        Ensure switch_id and peer_switch_id are different.

        Returns:
            Validated model instance

        Raises:
            ValueError: If switch_id equals peer_switch_id
        """
        validate_distinct_switches(
            self.switch_id, self.peer_switch_id, "switch_id", "peer_switch_id"
        )
        return self

    def to_payload(self) -> Dict[str, Any]:
        """Convert to API payload format."""
        return self.model_dump(by_alias=True, exclude_none=True)

    @classmethod
    def from_response(cls, response: Dict[str, Any]) -> Self:
        """Create instance from API response."""
        return cls.model_validate(response)


class VpcPairingRequest(SwitchPairKeyMixin, NDBaseModel):
    """
    Request schema for pairing VPC switches.

    Identifier: (switch_id, peer_switch_id) - composite
    OpenAPI: vpcPairingRequest
    """

    # Identifier configuration
    identifiers: ClassVar[List[str]] = ["switch_id", "peer_switch_id"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical"]] = "composite"

    # Fields with validation constraints
    vpc_action: VpcActionEnum = Field(default=VpcActionEnum.PAIR, alias="vpcAction", description="Action to pair")
    switch_id: str = Field(
        alias="switchId",
        description="Switch serial number (Peer-1)",
        min_length=3,
        max_length=64
    )
    peer_switch_id: str = Field(
        alias="peerSwitchId",
        description="Peer switch serial number (Peer-2)",
        min_length=3,
        max_length=64
    )
    use_virtual_peer_link: FlexibleBool = Field(default=False, alias="useVirtualPeerLink", description="Virtual peer link present")
    vpc_pair_details: Optional[Union[VpcPairDetailsDefault, VpcPairDetailsCustom]] = Field(
        default=None, discriminator="type", alias="vpcPairDetails", description="VPC pair configuration details"
    )

    @field_validator("switch_id", "peer_switch_id")
    @classmethod
    def validate_switch_id_format(cls, v: str) -> str:
        """
        Validate switch ID is not empty or whitespace.

        Args:
            v: Switch ID value

        Returns:
            Stripped switch ID

        Raises:
            ValueError: If switch ID is empty or whitespace
        """
        return validate_non_empty_switch_id(v)

    @model_validator(mode="after")
    def validate_different_switches(self) -> Self:
        """
        Ensure switch_id and peer_switch_id are different.

        Returns:
            Validated model instance

        Raises:
            ValueError: If switch_id equals peer_switch_id
        """
        validate_distinct_switches(
            self.switch_id, self.peer_switch_id, "switch_id", "peer_switch_id"
        )
        return self

    def to_payload(self) -> Dict[str, Any]:
        """Convert to API payload format."""
        return self.model_dump(by_alias=True, exclude_none=True)

    @classmethod
    def from_response(cls, response: Dict[str, Any]) -> Self:
        """Create instance from API response."""
        return cls.model_validate(response)


class VpcUnpairingRequest(NDBaseModel):
    """
    Request schema for unpairing VPC switches.

    Identifier: N/A (no specific switch IDs in unpair request)
    OpenAPI: vpcUnpairingRequest
    """

    # No identifiers for unpair request
    identifiers: ClassVar[List[str]] = []

    # Fields
    vpc_action: VpcActionEnum = Field(default=VpcActionEnum.UNPAIR, alias="vpcAction", description="Action to unpair")

    def get_identifier_value(self) -> str:
        """Override - unpair doesn't have identifiers."""
        return "unpair"

    def to_payload(self) -> Dict[str, Any]:
        """Convert to API payload format."""
        return self.model_dump(by_alias=True, exclude_none=True)

    @classmethod
    def from_response(cls, response: Dict[str, Any]) -> Self:
        """Create instance from API response."""
        return cls.model_validate(response)


# ============================================================================
# MONITORING DOMAIN MODELS
# ============================================================================


class VpcPairsInfoBase(NDNestedModel):
    """
    VPC pair information base.

    OpenAPI: vpcPairsInfoBase
    """

    switch_name: SwitchInfo = Field(alias="switchName", description="Switch name")
    ip_address: SwitchInfo = Field(alias="ipAddress", description="IP address")
    fabric_name: str = Field(alias="fabricName", description="Fabric name")
    connectivity_status: SwitchInfo = Field(alias="connectivityStatus", description="Connectivity status")
    maintenance_mode: SwitchInfo = Field(alias="maintenanceMode", description="Maintenance mode")
    uptime: SwitchInfo = Field(alias="uptime", description="Switch uptime")
    switch_id: SwitchInfo = Field(alias="switchId", description="Switch serial number")
    model: SwitchInfo = Field(alias="model", description="Switch model")
    switch_role: SwitchInfo = Field(alias="switchRole", description="Switch role")
    is_consistent: SwitchBoolInfo = Field(alias="isConsistent", description="Consistency status")
    domain_id: SwitchIntInfo = Field(alias="domainId", description="Domain ID")
    platform_type: SwitchInfo = Field(alias="platformType", description="Platform type")


class VpcPairHealthBase(NDNestedModel):
    """
    VPC pair health information.

    OpenAPI: vpcPairHealthBase
    """

    switch_id: str = Field(alias="switchId", description="Switch serial number")
    peer_switch_id: str = Field(alias="peerSwitchId", description="Peer switch serial number")
    health: HealthMetrics = Field(alias="health", description="Health status")
    cpu: ResourceMetrics = Field(alias="cpu", description="CPU utilization")
    memory: ResourceMetrics = Field(alias="memory", description="Memory utilization")
    temperature: ResourceMetrics = Field(alias="temperature", description="Temperature in Celsius")


class VpcPairsVxlanBase(NDNestedModel):
    """
    VPC pairs VXLAN details.

    OpenAPI: vpcPairsVxlanBase
    """

    switch_id: str = Field(alias="switchId", description="Peer1 switch serial number")
    peer_switch_id: str = Field(alias="peerSwitchId", description="Peer2 switch serial number")
    routing_loopback: SwitchInfo = Field(alias="routingLoopback", description="Routing loopback")
    routing_loopback_status: SwitchInfo = Field(alias="routingLoopbackStatus", description="Routing loopback status")
    routing_loopback_primary_ip: SwitchInfo = Field(alias="routingLoopbackPrimaryIp", description="Routing loopback primary IP")
    routing_loopback_secondary_ip: Optional[SwitchInfo] = Field(default=None, alias="routingLoopbackSecondaryIp", description="Routing loopback secondary IP")
    vtep_loopback: SwitchInfo = Field(alias="vtepLoopback", description="VTEP loopback")
    vtep_loopback_status: SwitchInfo = Field(alias="vtepLoopbackStatus", description="VTEP loopback status")
    vtep_loopback_primary_ip: SwitchInfo = Field(alias="vtepLoopbackPrimaryIp", description="VTEP loopback primary IP")
    vtep_loopback_secondary_ip: Optional[SwitchInfo] = Field(default=None, alias="vtepLoopbackSecondaryIp", description="VTEP loopback secondary IP")
    nve_interface: SwitchInfo = Field(alias="nveInterface", description="NVE interface")
    nve_status: SwitchInfo = Field(alias="nveStatus", description="NVE status")
    multisite_loopback: Optional[SwitchInfo] = Field(default=None, alias="multisiteLoopback", description="Multisite loopback")
    multisite_loopback_status: Optional[SwitchInfo] = Field(default=None, alias="multisiteLoopbackStatus", description="Multisite loopback status")
    multisite_loopback_primary_ip: Optional[SwitchInfo] = Field(default=None, alias="multisiteLoopbackPrimaryIp", description="Multisite loopback primary IP")


class VpcPairsOverlayBase(NDNestedModel):
    """
    VPC pairs overlay base.

    OpenAPI: vpcPairsOverlayBase
    """

    network_count: SyncCounts = Field(alias="networkCount", description="Network count")
    vrf_count: SyncCounts = Field(alias="vrfCount", description="VRF count")


class VpcPairsInventoryBase(NDNestedModel):
    """
    VPC pair inventory base.

    OpenAPI: vpcPairsInventoryBase
    """

    switch_id: str = Field(alias="switchId", description="Peer1 switch serial number")
    peer_switch_id: str = Field(alias="peerSwitchId", description="Peer2 switch serial number")
    admin_status: InterfaceStatusCounts = Field(alias="adminStatus", description="Admin status")
    operational_status: InterfaceStatusCounts = Field(alias="operationalStatus", description="Operational status")
    sync_status: Dict[str, FlexibleInt] = Field(alias="syncStatus", description="Sync status")
    logical_interfaces: LogicalInterfaceCounts = Field(alias="logicalInterfaces", description="Logical interfaces")


class VpcPairsModuleBase(NDNestedModel):
    """
    VPC pair module base.

    OpenAPI: vpcPairsModuleBase
    """

    switch_id: str = Field(alias="switchId", description="Peer1 switch serial number")
    peer_switch_id: str = Field(alias="peerSwitchId", description="Peer2 switch serial number")
    module_information: Dict[str, str] = Field(default_factory=dict, alias="moduleInformation", description="VPC pair module information")
    fex_details: Dict[str, str] = Field(default_factory=dict, alias="fexDetails", description="Fex details name-value pair(s)")


class VpcPairAnomaliesBase(NDNestedModel):
    """
    VPC pair anomalies information.

    OpenAPI: vpcPairAnomaliesBase
    """

    switch_id: str = Field(alias="switchId", description="Peer1 switch serial number")
    peer_switch_id: str = Field(alias="peerSwitchId", description="Peer2 switch serial number")
    anomalies_count: AnomaliesCount = Field(alias="anomaliesCount", description="Anomaly counts by severity")


# ============================================================================
# CONSISTENCY DOMAIN MODELS
# ============================================================================


class CommonVpcConsistencyParams(NDNestedModel):
    """
    Common consistency parameters for VPC domain.

    OpenAPI: commonVpcConsistencyParams
    """

    # Basic identifiers
    switch_name: str = Field(alias="switchName", description="Switch name")
    ip_address: str = Field(alias="ipAddress", description="IP address")
    domain_id: FlexibleInt = Field(alias="domainId", description="Domain ID")

    # Port channel info
    peer_link_port_channel: FlexibleInt = Field(alias="peerLinkPortChannel", description="Port channel peer link")
    port_channel_name: Optional[str] = Field(default=None, alias="portChannelName", description="Port channel name")
    description: Optional[str] = Field(default=None, alias="description", description="Port channel description")

    # VPC system parameters
    system_mac_address: str = Field(alias="systemMacAddress", description="System MAC address")
    system_priority: FlexibleInt = Field(alias="systemPriority", description="System priority")
    udp_port: FlexibleInt = Field(alias="udpPort", description="UDP port")
    interval: FlexibleInt = Field(alias="interval", description="Interval")
    timeout: FlexibleInt = Field(alias="timeout", description="Timeout")

    # Additional fields (simplified - add as needed)
    # NOTE: OpenAPI has many more fields - add them as required


class VpcPairConsistency(NDNestedModel):
    """
    VPC pair consistency check results.

    OpenAPI: vpcPairConsistency
    """

    switch_id: str = Field(alias="switchId", description="Primary switch serial number")
    peer_switch_id: str = Field(alias="peerSwitchId", description="Secondary switch serial number")
    type2_consistency: FlexibleBool = Field(alias="type2Consistency", description="Type-2 consistency status")
    type2_consistency_reason: str = Field(alias="type2ConsistencyReason", description="Consistency reason")
    timestamp: Optional[FlexibleInt] = Field(default=None, alias="timestamp", description="Timestamp of check")
    primary_parameters: CommonVpcConsistencyParams = Field(alias="primaryParameters", description="Primary switch consistency parameters")
    secondary_parameters: CommonVpcConsistencyParams = Field(alias="secondaryParameters", description="Secondary switch consistency parameters")
    is_consistent: Optional[FlexibleBool] = Field(default=None, alias="isConsistent", description="Overall consistency")
    is_discovered: Optional[FlexibleBool] = Field(default=None, alias="isDiscovered", description="Whether pair is discovered")


# ============================================================================
# VALIDATION DOMAIN MODELS
# ============================================================================


class VpcPairRecommendation(NDNestedModel):
    """
    Recommendation information for a switch.

    OpenAPI: vpcPairRecommendation
    """

    hostname: str = Field(alias="hostname", description="Logical name of switch")
    ip_address: str = Field(alias="ipAddress", description="IP address of switch")
    switch_id: str = Field(alias="switchId", description="Serial number of the switch")
    software_version: str = Field(alias="softwareVersion", description="NXOS version of switch")
    fabric_name: str = Field(alias="fabricName", description="Fabric name")
    recommendation_reason: str = Field(alias="recommendationReason", description="Recommendation message")
    block_selection: FlexibleBool = Field(alias="blockSelection", description="Block selection")
    platform_type: str = Field(alias="platformType", description="Platform type of switch")
    use_virtual_peer_link: FlexibleBool = Field(alias="useVirtualPeerLink", description="Virtual peer link available")
    is_current_peer: FlexibleBool = Field(alias="isCurrentPeer", description="Device is current peer")
    is_recommended: FlexibleBool = Field(alias="isRecommended", description="Recommended device")


# ============================================================================
# INVENTORY DOMAIN MODELS
# ============================================================================


class VpcPairBaseSwitchDetails(NDNestedModel):
    """
    Base fields for VPC pair records.

    OpenAPI: vpcPairBaseSwitchDetails
    """

    domain_id: FlexibleInt = Field(alias="domainId", description="Domain ID of the VPC")
    switch_id: str = Field(alias="switchId", description="Serial number of the switch")
    switch_name: str = Field(alias="switchName", description="Hostname of the switch")
    peer_switch_id: str = Field(alias="peerSwitchId", description="Serial number of the peer switch")
    peer_switch_name: str = Field(alias="peerSwitchName", description="Hostname of the peer switch")


class VpcPairIntended(VpcPairBaseSwitchDetails):
    """
    Intended VPC pair record.

    OpenAPI: vpcPairIntended
    """

    type: Literal["intendedPairs"] = Field(default="intendedPairs", alias="type", description="Type identifier")


class VpcPairDiscovered(VpcPairBaseSwitchDetails):
    """
    Discovered VPC pair record.

    OpenAPI: vpcPairDiscovered
    """

    type: Literal["discoveredPairs"] = Field(default="discoveredPairs", alias="type", description="Type identifier")
    switch_vpc_role: VpcRoleEnum = Field(alias="switchVpcRole", description="VPC role of the switch")
    peer_switch_vpc_role: VpcRoleEnum = Field(alias="peerSwitchVpcRole", description="VPC role of the peer switch")
    intended_peer_name: str = Field(alias="intendedPeerName", description="Name of the intended peer switch")
    description: str = Field(alias="description", description="Description of any discrepancies or issues")


class Metadata(NDNestedModel):
    """
    Metadata for pagination and links.

    OpenAPI: Metadata
    """

    counts: ResponseCounts = Field(alias="counts", description="Count information")
    links: Optional[Dict[str, str]] = Field(default=None, alias="links", description="Pagination links (next, previous)")


class VpcPairsResponse(NDNestedModel):
    """
    Response schema for listing VPC pairs.

    OpenAPI: vpcPairsResponse
    """

    vpc_pairs: List[Union[VpcPairIntended, VpcPairDiscovered]] = Field(alias="vpcPairs", description="List of VPC pairs")
    meta: Metadata = Field(alias="meta", description="Response metadata")


# ============================================================================
# WRAPPER MODELS WITH COMPONENT TYPE
# ============================================================================


class VpcPairsInfo(NDNestedModel):
    """VPC pairs information wrapper."""

    component_type: ComponentTypeOverviewEnum = Field(default=ComponentTypeOverviewEnum.PAIRS_INFO, alias="componentType", description="Type of the component")
    info: VpcPairsInfoBase = Field(alias="info", description="VPC pair info")


class VpcPairHealth(NDNestedModel):
    """VPC pair health wrapper."""

    component_type: ComponentTypeOverviewEnum = Field(default=ComponentTypeOverviewEnum.HEALTH, alias="componentType", description="Type of the component")
    health: VpcPairHealthBase = Field(alias="health", description="Health details")


class VpcPairsModule(NDNestedModel):
    """VPC pairs module wrapper."""

    component_type: ComponentTypeOverviewEnum = Field(default=ComponentTypeOverviewEnum.MODULE, alias="componentType", description="Type of the component")
    module: VpcPairsModuleBase = Field(alias="module", description="Module details")


class VpcPairAnomalies(NDNestedModel):
    """VPC pair anomalies wrapper."""

    component_type: ComponentTypeOverviewEnum = Field(default=ComponentTypeOverviewEnum.ANOMALIES, alias="componentType", description="Type of the component")
    anomalies: VpcPairAnomaliesBase = Field(alias="anomalies", description="Anomalies details")


class VpcPairsVxlan(NDNestedModel):
    """VPC pairs VXLAN wrapper."""

    component_type: ComponentTypeOverviewEnum = Field(default=ComponentTypeOverviewEnum.VXLAN, alias="componentType", description="Type of the component")
    vxlan: VpcPairsVxlanBase = Field(alias="vxlan", description="VXLAN details")


class VpcPairsOverlay(NDNestedModel):
    """VPC overlay details wrapper."""

    component_type: ComponentTypeOverviewEnum = Field(default=ComponentTypeOverviewEnum.OVERLAY, alias="componentType", description="Type of the component")
    overlay: VpcPairsOverlayBase = Field(alias="overlay", description="Overlay details")


class VpcPairsInventory(NDNestedModel):
    """VPC pairs inventory details wrapper."""

    component_type: ComponentTypeOverviewEnum = Field(default=ComponentTypeOverviewEnum.INVENTORY, alias="componentType", description="Type of the component")
    inventory: VpcPairsInventoryBase = Field(alias="inventory", description="Inventory details")


class FullOverview(NDNestedModel):
    """Full VPC overview response."""

    component_type: ComponentTypeOverviewEnum = Field(default=ComponentTypeOverviewEnum.FULL, alias="componentType", description="Type of the component")
    anomalies: VpcPairAnomaliesBase = Field(alias="anomalies", description="VPC pair anomalies")
    health: VpcPairHealthBase = Field(alias="health", description="VPC pair health")
    module: VpcPairsModuleBase = Field(alias="module", description="VPC pair module")
    vxlan: VpcPairsVxlanBase = Field(alias="vxlan", description="VPC pair VXLAN")
    overlay: VpcPairsOverlayBase = Field(alias="overlay", description="VPC pair overlay")
    pairs_info: VpcPairsInfoBase = Field(alias="pairsInfo", description="VPC pair info")
    inventory: VpcPairsInventoryBase = Field(alias="inventory", description="VPC pair inventory")


# ============================================================================
# BACKWARD COMPATIBILITY CONTAINER (NdVpcPairSchema)
# ============================================================================


class NdVpcPairSchema:
    """
    Backward compatibility container for all VPC pair schemas.

    This provides a namespace similar to the old structure where models
    were nested inside a container class. Allows imports like:

        from model_playbook_vpc_pair_nested import NdVpcPairSchema
        vpc_pair = NdVpcPairSchema.VpcPairBase(**data)
    """

    # Base classes
    VpcPairBaseModel = NDBaseModel
    VpcPairNestedModel = NDNestedModel

    # Enumerations (these are class variable type hints, not assignments)
    # VpcRole = VpcRoleEnum  # Commented out - not needed
    # TemplateType = VpcPairTypeEnum  # Commented out - not needed
    # KeepAliveVrf = KeepAliveVrfEnum  # Commented out - not needed
    # VpcAction = VpcActionEnum  # Commented out - not needed
    # ComponentType = ComponentTypeOverviewEnum  # Commented out - not needed

    # Nested helper models
    SwitchInfo = SwitchInfo
    SwitchIntInfo = SwitchIntInfo
    SwitchBoolInfo = SwitchBoolInfo
    SyncCounts = SyncCounts
    AnomaliesCount = AnomaliesCount
    HealthMetrics = HealthMetrics
    ResourceMetrics = ResourceMetrics
    InterfaceStatusCounts = InterfaceStatusCounts
    LogicalInterfaceCounts = LogicalInterfaceCounts
    ResponseCounts = ResponseCounts

    # VPC pair details (template configuration)
    VpcPairDetailsDefault = VpcPairDetailsDefault
    VpcPairDetailsCustom = VpcPairDetailsCustom

    # Configuration domain
    VpcPairBase = VpcPairBase
    VpcPairingRequest = VpcPairingRequest
    VpcUnpairingRequest = VpcUnpairingRequest

    # Monitoring domain
    VpcPairsInfoBase = VpcPairsInfoBase
    VpcPairHealthBase = VpcPairHealthBase
    VpcPairsVxlanBase = VpcPairsVxlanBase
    VpcPairsOverlayBase = VpcPairsOverlayBase
    VpcPairsInventoryBase = VpcPairsInventoryBase
    VpcPairsModuleBase = VpcPairsModuleBase
    VpcPairAnomaliesBase = VpcPairAnomaliesBase

    # Monitoring domain wrappers
    VpcPairsInfo = VpcPairsInfo
    VpcPairHealth = VpcPairHealth
    VpcPairsModule = VpcPairsModule
    VpcPairAnomalies = VpcPairAnomalies
    VpcPairsVxlan = VpcPairsVxlan
    VpcPairsOverlay = VpcPairsOverlay
    VpcPairsInventory = VpcPairsInventory
    FullOverview = FullOverview

    # Consistency domain
    CommonVpcConsistencyParams = CommonVpcConsistencyParams
    VpcPairConsistency = VpcPairConsistency

    # Validation domain
    VpcPairRecommendation = VpcPairRecommendation

    # Inventory domain
    VpcPairBaseSwitchDetails = VpcPairBaseSwitchDetails
    VpcPairIntended = VpcPairIntended
    VpcPairDiscovered = VpcPairDiscovered
    Metadata = Metadata
    VpcPairsResponse = VpcPairsResponse
