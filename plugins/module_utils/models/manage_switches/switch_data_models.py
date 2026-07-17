# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Switch inventory data models (API response representations).

Based on OpenAPI schema for Nexus Dashboard Manage APIs v1.1.332.
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import PlatformType
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.enums import (
    AdvisoryLevel,
    AnomalyLevel,
    ConfigSyncStatus,
    DiscoveryStatus,
    RemoteCredentialStore,
    SwitchRole,
    SystemMode,
    VpcRole,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.validators import validate_ip_address
from .validators import require_serial_number


class TelemetryIpCollection(NDNestedModel):
    """
    Inband and out-of-band telemetry IP addresses for a switch.
    """

    identifiers: ClassVar[list[str]] = []
    inband_ipv4_address: str | None = Field(default=None, alias="inbandIpV4Address", description="Inband IPv4 address")
    inband_ipv6_address: str | None = Field(default=None, alias="inbandIpV6Address", description="Inband IPv6 address")
    out_of_band_ipv4_address: str | None = Field(
        default=None,
        alias="outOfBandIpV4Address",
        description="Out of band IPv4 address",
    )
    out_of_band_ipv6_address: str | None = Field(
        default=None,
        alias="outOfBandIpV6Address",
        description="Out of band IPv6 address",
    )


class VpcData(NDNestedModel):
    """
    vPC pair configuration and operational status for a switch.
    """

    identifiers: ClassVar[list[str]] = []
    vpc_domain: int = Field(alias="vpcDomain", ge=1, le=1000, description="vPC domain ID")
    peer_switch_id: str = Field(alias="peerSwitchId", description="vPC peer switch serial number")
    consistent_status: bool | None = Field(
        default=None,
        alias="consistentStatus",
        description="Flag to indicate the vPC status is consistent",
    )
    intended_peer_name: str | None = Field(
        default=None,
        alias="intendedPeerName",
        description="Intended vPC host name for pre-provisioned peer switch",
    )
    keep_alive_status: str | None = Field(default=None, alias="keepAliveStatus", description="vPC peer keep alive status")
    peer_link_status: str | None = Field(default=None, alias="peerLinkStatus", description="vPC peer link status")
    peer_name: str | None = Field(default=None, alias="peerName", description="vPC peer switch name")
    vpc_role: VpcRole | None = Field(default=None, alias="vpcRole", description="The vPC role")

    @field_validator("peer_switch_id", mode="before")
    @classmethod
    def validate_peer_serial(cls, v: str) -> str:
        return require_serial_number(v, "peer_switch_id")


class SwitchMetadata(NDNestedModel):
    """
    Internal database identifiers associated with a switch record.
    """

    identifiers: ClassVar[list[str]] = []
    switch_db_id: int | None = Field(default=None, alias="switchDbId", description="Database Id of the switch")
    switch_uuid: str | None = Field(default=None, alias="switchUuid", description="Internal unique Id of the switch")


class AdditionalSwitchData(NDNestedModel):
    """
    Platform-specific additional data for NX-OS switches.
    """

    identifiers: ClassVar[list[str]] = []
    usage: str | None = Field(default="others", description="The usage of additional data")
    config_sync_status: ConfigSyncStatus | None = Field(default=None, alias="configSyncStatus", description="Configuration sync status")
    discovery_status: DiscoveryStatus | None = Field(default=None, alias="discoveryStatus", description="Discovery status")
    domain_name: str | None = Field(default=None, alias="domainName", description="Domain name")
    smart_switch: bool | None = Field(
        default=None,
        alias="smartSwitch",
        description="Flag that indicates if the switch is equipped with DPUs or not",
    )
    hypershield_connectivity_status: str | None = Field(
        default=None,
        alias="hypershieldConnectivityStatus",
        description="Smart switch connectivity status to hypershield controller",
    )
    hypershield_tenant: str | None = Field(default=None, alias="hypershieldTenant", description="Hypershield tenant name")
    hypershield_integration_name: str | None = Field(
        default=None,
        alias="hypershieldIntegrationName",
        description="Hypershield Integration Id",
    )
    source_interface_name: str | None = Field(
        default=None,
        alias="sourceInterfaceName",
        description="Source interface for switch discovery",
    )
    source_vrf_name: str | None = Field(
        default=None,
        alias="sourceVrfName",
        description="Source VRF for switch discovery",
    )
    platform_type: PlatformType | None = Field(default=None, alias="platformType", description="Platform type of the switch")
    discovered_system_mode: SystemMode | None = Field(default=None, alias="discoveredSystemMode", description="Discovered system mode")
    intended_system_mode: SystemMode | None = Field(default=None, alias="intendedSystemMode", description="Intended system mode")
    scalable_unit: str | None = Field(default=None, alias="scalableUnit", description="Name of the scalable unit")
    system_mode: SystemMode | None = Field(default=None, alias="systemMode", description="System mode")
    vendor: str | None = Field(default=None, description="Vendor of the switch")
    username: str | None = Field(default=None, description="Discovery user name")
    remote_credential_store: RemoteCredentialStore | None = Field(default=None, alias="remoteCredentialStore")
    meta: SwitchMetadata | None = Field(default=None, description="Switch metadata")


class AdditionalAciSwitchData(NDNestedModel):
    """
    Platform-specific additional data for ACI leaf and spine switches.
    """

    identifiers: ClassVar[list[str]] = []
    usage: str | None = Field(default="aci", description="The usage of additional data")
    admin_status: Literal["inService", "outOfService"] | None = Field(default=None, alias="adminStatus", description="Admin status")
    health_score: int | None = Field(
        default=None,
        alias="healthScore",
        ge=1,
        le=100,
        description="Switch health score",
    )
    last_reload_time: str | None = Field(
        default=None,
        alias="lastReloadTime",
        description="Timestamp when the system is last reloaded",
    )
    last_software_update_time: str | None = Field(
        default=None,
        alias="lastSoftwareUpdateTime",
        description="Timestamp when the software is last updated",
    )
    node_id: int | None = Field(default=None, alias="nodeId", ge=1, description="Node ID")
    node_status: Literal["active", "inActive"] | None = Field(default=None, alias="nodeStatus", description="Node status")
    pod_id: int | None = Field(default=None, alias="podId", ge=1, description="Pod ID")
    remote_leaf_group_name: str | None = Field(default=None, alias="remoteLeafGroupName", description="Remote leaf group name")
    switch_added: str | None = Field(
        default=None,
        alias="switchAdded",
        description="Timestamp when the switch is added",
    )
    tep_pool: str | None = Field(default=None, alias="tepPool", description="TEP IP pool")


class Metadata(NDNestedModel):
    """
    Pagination and result-count metadata from a list API response.
    """

    identifiers: ClassVar[list[str]] = []

    counts: dict[str, int] | None = Field(default=None, description="Count information including total and remaining")


class SwitchDataModel(NDBaseModel):
    """
    Inventory record for a single switch as returned by the fabric switches API.

    Path: GET /fabrics/{fabricName}/switches
    """

    identifiers: ClassVar[list[str]] = ["switch_id"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"
    exclude_from_diff: ClassVar[set] = {"system_up_time", "anomaly_level", "advisory_level", "alert_suspend"}
    switch_id: str = Field(
        alias="switchId",
        description="Serial number of Switch or Node Id of ACI switch",
    )
    serial_number: str | None = Field(
        default=None,
        alias="serialNumber",
        description="Serial number of switch or APIC controller node",
    )
    additional_data: AdditionalSwitchData | AdditionalAciSwitchData | None = Field(default=None, alias="additionalData", description="Additional switch data")
    advisory_level: AdvisoryLevel | None = Field(default=None, alias="advisoryLevel")
    anomaly_level: AnomalyLevel | None = Field(default=None, alias="anomalyLevel")
    alert_suspend: str | None = Field(default=None, alias="alertSuspend")
    fabric_management_ip: str | None = Field(
        default=None,
        alias="fabricManagementIp",
        description="Switch IPv4/v6 address used for management",
    )
    fabric_name: str | None = Field(default=None, alias="fabricName", description="Fabric name", max_length=64)
    fabric_type: str | None = Field(default=None, alias="fabricType", description="Fabric type")
    hostname: str | None = Field(default=None, description="Switch host name")
    model: str | None = Field(default=None, description="Model of switch or APIC controller node")
    software_version: str | None = Field(
        default=None,
        alias="softwareVersion",
        description="Software version of switch or APIC controller node",
    )
    switch_role: SwitchRole | None = Field(default=None, alias="switchRole")
    system_up_time: str | None = Field(default=None, alias="systemUpTime", description="System up time")
    vpc_configured: bool | None = Field(
        default=None,
        alias="vpcConfigured",
        description="Flag to indicate switch is part of a vPC domain",
    )
    vpc_data: VpcData | None = Field(default=None, alias="vpcData")
    telemetry_ip_collection: TelemetryIpCollection | None = Field(default=None, alias="telemetryIpCollection")

    @field_validator("additional_data", mode="before")
    @classmethod
    def parse_additional_data(cls, v: Any) -> Any:
        """Route additionalData to the correct nested model.

        The ND API may omit the ``usage`` field for non-ACI switches.
        Default to ``"others"`` so Pydantic selects ``AdditionalSwitchData``
        and coerces ``discoveryStatus`` / ``systemMode`` as proper enums.
        """
        if v is None or not isinstance(v, dict):
            return v
        if "usage" not in v:
            v = {**v, "usage": "others"}
        return v

    @field_validator("switch_id", mode="before")
    @classmethod
    def validate_switch_id(cls, v: str) -> str:
        return require_serial_number(v, "switch_id")

    @field_validator("fabric_management_ip", mode="before")
    @classmethod
    def validate_mgmt_ip(cls, v: str | None) -> str | None:
        return validate_ip_address(v)

    def to_payload(self) -> dict[str, Any]:
        """Convert to API payload format."""
        return self.model_dump(by_alias=True, exclude_none=True)

    @classmethod
    def from_response(cls, response: dict[str, Any]) -> "SwitchDataModel":
        """
        Create model instance from API response.

        Handles two response formats:
        1. Inventory API format: {switchId, fabricManagementIp, switchRole, ...}
        2. Discovery API format: {serialNumber, ip, hostname, model, softwareVersion, status, ...}

        Args:
            response: Response dict from either inventory or discovery API

        Returns:
            SwitchDataModel instance
        """
        # Detect format and transform if needed
        if "switchId" in response or "fabricManagementIp" in response:
            # Already in inventory format - use as-is
            return cls.model_validate(response)

        # Discovery format - transform to inventory format
        transformed = {
            "switchId": response.get("serialNumber"),
            "serialNumber": response.get("serialNumber"),
            "fabricManagementIp": response.get("ip"),
            "hostname": response.get("hostname"),
            "model": response.get("model"),
            "softwareVersion": response.get("softwareVersion"),
            "mode": response.get("mode", "Normal"),
        }

        # Only add switchRole if present in response (avoid overwriting with None)
        if "switchRole" in response:
            transformed["switchRole"] = response["switchRole"]
        elif "role" in response:
            transformed["switchRole"] = response["role"]

        return cls.model_validate(transformed)

    def to_config_dict(self) -> dict[str, Any]:
        """Return this inventory record using the 7 standard user-facing fields.

        Produces a consistent dict for previous/current output keys. All 7
        fields are always present (None when not available). Credential fields
        are never included.

        Returns:
            Dict with keys: seed_ip, serial_number, hostname, model,
            role, software_version, mode.
        """
        ad = self.additional_data
        return {
            "seed_ip": self.fabric_management_ip or self.switch_id or "",
            "serial_number": self.serial_number,
            "hostname": self.hostname,
            "model": self.model,
            "role": self.switch_role,
            "software_version": self.software_version,
            "mode": (ad.system_mode if ad and hasattr(ad, "system_mode") else None),
        }
