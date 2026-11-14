# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Annotated, Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.models.release_metadata import (
    NDMinimumVersion,
)

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import (
    CoppPolicyEnum,
    DhcpProtocolVersionEnum,
    FabricTypeEnum,
    PowerRedundancyModeEnum,
    TelemetryCollectionTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_common import (
    BootstrapSubnetModel,
    FabricDhcpGatewayAddress,
    FabricIPv4CIDR,
    FabricManagementModel,
    NetflowSamplerModel,
    NetflowSettingsModel,
    RequiredFabricIPAddress,
    ScheduledBackupTime,
    TelemetrySettingsModel,
    validate_bgp_asn_template_value,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_base import (
    FabricBaseModel,
)

FabricCliText = Annotated[str, StringConstraints(strip_whitespace=False)]

"""
# Comprehensive Pydantic models for External Connectivity fabric management via Nexus Dashboard

This module provides comprehensive Pydantic models for creating, updating, and deleting
External Connectivity fabrics through the Nexus Dashboard (ND) API.

## Models Overview

- `ExternalConnectivityManagementModel` - External Connectivity specific management settings
- `FabricExternalConnectivityModel` - Complete fabric creation model

## Usage

```python
# Create a new External Connectivity fabric
fabric_data = {
    "name": "MyExtFabric",
    "location": {"latitude": 37.7749, "longitude": -122.4194},
    "management": {
        "type": "externalConnectivity",
        "bgp_asn": "65001",
    }
}
fabric = FabricExternalConnectivityModel(**fabric_data)
```
"""


class ExternalNetflowSettingsModel(NetflowSettingsModel):
    """External NetFlow settings, including template-supported samplers."""

    netflow_sampler_collection: list[NetflowSamplerModel] | None = Field(
        alias="netflowSamplerCollection",
        description="List of NetFlow samplers",
        default=None,
    )


class ExternalConnectivityManagementModel(FabricManagementModel):
    """
    # Summary

    Comprehensive External Connectivity fabric management configuration.

    This model contains all settings specific to External Connectivity fabric types including
    BGP configuration, bootstrap settings, and advanced features.

    ## Raises

    - `ValueError` - If BGP ASN or IP ranges are invalid
    - `TypeError` - If required string fields are not provided
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow",
    )

    _argspec_exclude_fields: ClassVar[set[str]] = {"name"}
    ipv6_management_minimum_nd_version: ClassVar[str | None] = None

    # Hidden Hypershield proxy response values are not public parameters. Keep
    # their writable state across full replacement while gathered output omits it.
    _opaque_replacement_fields: ClassVar[set[str]] = {
        "hypershieldConnectivityProxyServer",
        "hypershieldConnectivityProxyServerPort",
    }
    replacement_preserve_fields: ClassVar[set[str]] = _opaque_replacement_fields
    config_exclude_fields: ClassVar[set[str]] = _opaque_replacement_fields

    empty_string_means_unset: ClassVar[bool] = True

    # Fabric Type (required for discriminated union)
    type: Literal[FabricTypeEnum.EXTERNAL_CONNECTIVITY] = Field(
        description="Fabric management type",
        default=FabricTypeEnum.EXTERNAL_CONNECTIVITY,
    )

    # Core Configuration
    bgp_asn: str | None = Field(
        alias="bgpAsn",
        description="Autonomous system number 1-4294967295 | 1-65535[.0-65535]",
        min_length=1,
        max_length=11,
        default=None,
    )

    # Name under management section is optional — propagated from FabricExternalConnectivityModel.fabric_name during validation
    name: str | None = Field(description="Fabric name", min_length=1, max_length=64, default=None)

    # AAA
    aaa: bool = Field(
        description="Include AAA configs from Advanced tab during device bootup",
        default=False,
    )

    # SSH
    advanced_ssh_option: bool = Field(
        alias="advancedSshOption",
        description="Enable only, when IP Authorization is enabled in the AAA Server",
        default=False,
    )

    # Loopback
    allow_same_loopback_ip_on_switches: bool = Field(
        alias="allowSameLoopbackIpOnSwitches",
        description="Allow the same loopback IP address to be configured on multiple switches (e.g. RP loopback IP)",
        default=False,
    )

    # Smart Switch
    allow_smart_switch_onboarding: bool = Field(
        alias="allowSmartSwitchOnboarding",
        description="Enable onboarding of smart switches to Hypershield for firewall service",
        default=False,
    )

    # Bootstrap Subnet Collection
    bootstrap_subnet_collection: list[BootstrapSubnetModel] = Field(
        alias="bootstrapSubnetCollection",
        description="List of IPv4 or IPv6 subnets to be used for bootstrap",
        default_factory=list,
    )

    # CDP
    cdp: bool = Field(description="Enable CDP on management interface", default=False)

    # CoPP Policy
    copp_policy: CoppPolicyEnum = Field(
        alias="coppPolicy",
        description="Fabric wide CoPP policy. Customized CoPP policy should be provided when 'manual' is selected.",
        default=CoppPolicyEnum.MANUAL,
    )

    # BGP Configuration
    create_bgp_config: bool = Field(
        alias="createBgpConfig",
        description="Generate BGP configuration for core and edge routers",
        default=True,
    )

    # Bootstrap Settings
    day0_bootstrap: bool = Field(
        alias="day0Bootstrap",
        description="Support day 0 touchless switch bringup",
        default=False,
    )
    day0_plug_and_play: bool = Field(
        alias="day0PlugAndPlay",
        description="Enable Plug n Play for Catalyst 9000 switches",
        default=False,
    )

    # DHCP
    dhcp_end_address: FabricDhcpGatewayAddress = Field(
        alias="dhcpEndAddress",
        description="DHCP Scope End Address For Switch POAP",
        default=None,
    )
    dhcp_protocol_version: DhcpProtocolVersionEnum = Field(
        alias="dhcpProtocolVersion",
        description="IP protocol version for Local DHCP Server",
        default=DhcpProtocolVersionEnum.DHCPV4,
    )
    dhcp_start_address: FabricDhcpGatewayAddress = Field(
        alias="dhcpStartAddress",
        description="DHCP Scope Start Address For Switch POAP",
        default=None,
    )

    # DNS
    dns_collection: list[Annotated[RequiredFabricIPAddress, Field(min_length=3, max_length=40)]] = Field(
        alias="dnsCollection",
        description="List of IPv4 and IPv6 DNS addresses",
        default_factory=list,
    )
    dns_vrf_collection: list[Annotated[str, Field(min_length=1, max_length=80)]] = Field(
        alias="dnsVrfCollection",
        description="DNS Server VRFs. One VRF for all DNS servers or a list of VRFs, one per DNS server",
        default_factory=list,
    )

    # Domain
    domain_name: str = Field(
        alias="domainName",
        description="Domain name for DHCP server PnP block",
        default="",
        json_schema_extra={
            "nd_string_constraints": {
                "allow_empty": True,
                "pattern": r"^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,6}$",
            }
        },
    )

    # DPU Pinning
    enable_dpu_pinning: bool = Field(
        alias="enableDpuPinning",
        description="Enable pinning of VRFs and networks to specific DPUs on smart switches",
        default=False,
    )

    # Extra Config
    extra_config_aaa: FabricCliText = Field(
        alias="extraConfigAaa",
        description="Additional CLIs for AAA Configuration",
        default="",
    )
    extra_config_fabric: FabricCliText = Field(
        alias="extraConfigFabric",
        description="Additional CLIs for all switches",
        default="",
    )
    extra_config_nxos_bootstrap: FabricCliText = Field(
        alias="extraConfigNxosBootstrap",
        description="Additional CLIs required during device bootup/login e.g. AAA/Radius (NX-OS)",
        default="",
    )
    extra_config_xe_bootstrap: FabricCliText = Field(
        alias="extraConfigXeBootstrap",
        description="Additional CLIs required during device bootup/login e.g. AAA/Radius (IOS-XE)",
        default="",
    )

    # Inband Management
    inband_day0_bootstrap: bool = Field(
        alias="inbandDay0Bootstrap",
        description="Support day 0 touchless switch bringup via inband management",
        default=False,
    )
    inband_management: bool = Field(
        alias="inbandManagement",
        description="Import switches with reachability over the switch front-panel ports",
        default=False,
    )

    # Interface Statistics
    interface_statistics_load_interval: int = Field(
        alias="interfaceStatisticsLoadInterval",
        description="Interface Statistics Load Interval Time in seconds",
        ge=5,
        le=300,
        default=10,
    )

    # Local DHCP Server
    local_dhcp_server: bool = Field(
        alias="localDhcpServer",
        description="Automatic IP Assignment For POAP from Local DHCP Server",
        default=False,
    )

    # Management
    management_gateway: FabricDhcpGatewayAddress = Field(
        alias="managementGateway",
        description="Default Gateway For Management VRF On The Switch",
        default=None,
    )
    management_ipv4_prefix: int = Field(
        alias="managementIpv4Prefix",
        description="Switch Mgmt IP Subnet Prefix if ipv4",
        ge=8,
        le=30,
        default=24,
    )
    management_ipv6_prefix: int = Field(
        alias="managementIpv6Prefix",
        description="Switch Management IP Subnet Prefix if ipv6",
        ge=64,
        le=126,
        default=64,
    )

    # Monitored Mode
    monitored_mode: bool = Field(
        alias="monitoredMode",
        description="If enabled, fabric is only monitored. No configuration will be deployed",
        default=True,
    )

    # MPLS Handoff
    mpls_handoff: bool = Field(alias="mplsHandoff", description="Enable MPLS Handoff", default=False)
    mpls_loopback_identifier: int = Field(
        alias="mplsLoopbackIdentifier",
        description="Underlay MPLS Loopback Identifier",
        ge=0,
        le=1023,
        default=101,
    )
    mpls_loopback_ip_range: FabricIPv4CIDR = Field(
        alias="mplsLoopbackIpRange",
        description="MPLS Loopback IP Address Range",
        default="10.102.0.0/25",
    )

    # Netflow Settings
    netflow_settings: ExternalNetflowSettingsModel = Field(
        alias="netflowSettings",
        description="Settings associated with netflow",
        default_factory=ExternalNetflowSettingsModel,
    )

    # NX-API Settings
    nxapi: bool = Field(description="Enable NX-API over HTTPS", default=False)
    nxapi_http: bool = Field(alias="nxapiHttp", description="Enable NX-API over HTTP", default=False)
    nxapi_http_port: int = Field(
        alias="nxapiHttpPort",
        description="HTTP port for NX-API",
        ge=1,
        le=65535,
        default=80,
    )
    nxapi_https_port: int = Field(
        alias="nxapiHttpsPort",
        description="HTTPS port for NX-API",
        ge=1,
        le=65535,
        default=443,
    )

    # Performance Monitoring
    performance_monitoring: bool = Field(
        alias="performanceMonitoring",
        description="If enabled, switch metrics are collected through periodic SNMP polling. Alternative to real-time telemetry",
        default=False,
    )

    # Power Redundancy
    power_redundancy_mode: PowerRedundancyModeEnum = Field(
        alias="powerRedundancyMode",
        description="Default Power Supply Mode for NX-OS Switches",
        default=PowerRedundancyModeEnum.REDUNDANT,
    )

    # PTP
    ptp: bool = Field(description="Enable Precision Time Protocol (PTP)", default=False)
    ptp_domain_id: int = Field(
        alias="ptpDomainId",
        description="Multiple Independent PTP Clocking Subdomains on a Single Network",
        ge=0,
        le=127,
        default=0,
    )
    ptp_loopback_id: int = Field(
        alias="ptpLoopbackId",
        description="Precision Time Protocol Source Loopback Id",
        ge=0,
        le=1023,
        default=0,
    )

    # Backup / Restore
    real_time_backup: bool | None = Field(
        alias="realTimeBackup",
        description="Hourly Fabric Backup only if there is any config deployment since last backup",
        default=None,
    )

    # Interface Statistics Collection
    real_time_interface_statistics_collection: bool = Field(
        alias="realTimeInterfaceStatisticsCollection",
        description="Enable Real Time Interface Statistics Collection. Valid for NX-OS only",
        default=False,
    )

    # Scheduled Backup
    scheduled_backup: bool | None = Field(
        alias="scheduledBackup",
        description="Enable backup at the specified time daily",
        default=None,
    )
    scheduled_backup_time: ScheduledBackupTime = Field(
        alias="scheduledBackupTime",
        description="Time (UTC) in 24 hour format to take a daily backup if enabled (00:00 to 23:59)",
        default=None,
    )

    # SNMP
    snmp_trap: bool = Field(
        alias="snmpTrap",
        description="Configure Nexus Dashboard as a receiver for SNMP traps",
        default=True,
    )

    # Sub-Interface
    sub_interface_dot1q_range: str = Field(
        alias="subInterfaceDot1qRange",
        description="Per aggregation dot1q range for VRF-Lite connectivity (minimum: 2, maximum: 4093)",
        default="2-511",
        json_schema_extra={"nd_integer_range": {"minimum": 2, "maximum": 4093}},
    )

    # Hypershield / Connectivity
    connectivity_domain_name: str | None = Field(
        alias="connectivityDomainName",
        description="Domain name to connect to Hypershield",
        default=None,
        min_length=1,
        max_length=63,
        json_schema_extra={"nd_string_constraints": {"pattern": r"^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,6}$"}},
    )
    hypershield_connectivity_source_intf: str | None = Field(
        alias="hypershieldConnectivitySourceIntf",
        description="Loopback interface on smart switch for communication with Hypershield",
        min_length=1,
        max_length=40,
        default=None,
    )

    # Additional controls present in the ND 4.3.1 External_Fabric template.
    ai_monitoring: Annotated[bool | None, NDMinimumVersion("4.3.1")] = Field(
        alias="aiMonitoring",
        description="Enable AI monitoring features.",
        default=False,
    )
    allow_smart_switch_ha: Annotated[bool | None, NDMinimumVersion("4.3.1")] = Field(
        alias="allowSmartSwitchHA",
        description="Enable high availability configuration for smart switches.",
        default=False,
    )
    auto_smart_switch_vpc_pair_ha: Annotated[bool | None, NDMinimumVersion("4.3.1")] = Field(
        alias="autoSmartSwitchVpcPairHA",
        description="Enable automatic high availability configuration for smart-switch vPC pairs.",
        default=False,
    )
    enable_remote_switch_backup: Annotated[bool | None, NDMinimumVersion("4.3.1")] = Field(
        alias="enableRemoteSwitchBackup",
        description="Enable remote switch backup.",
        default=False,
    )
    hypershield_ha_peer_link_subnet: Annotated[FabricIPv4CIDR, NDMinimumVersion("4.3.1")] = Field(
        alias="hypershieldHAPeerLinkSubnet",
        description="IPv4 subnet pool for HA peer-link connectivity.",
        default="10.12.0.0/22",
    )
    hypershield_ha_peer_link_subnet_granularity: Annotated[Literal["/30", "/31"] | None, NDMinimumVersion("4.3.1")] = Field(
        alias="hypershieldHAPeerLinkSubnetGranularity",
        description="Subnet prefix size for HA peer-link allocations.",
        default="/30",
    )
    hypershield_ha_source_intf: Annotated[str | None, NDMinimumVersion("4.3.1")] = Field(
        alias="hypershieldHASourceIntf",
        description="Loopback interface used as the HA source.",
        min_length=3,
        max_length=40,
        default="loopback1023",
    )
    hypershield_ha_source_subnet: Annotated[FabricIPv4CIDR, NDMinimumVersion("4.3.1")] = Field(
        alias="hypershieldHASourceSubnet",
        description="IPv4 subnet pool for the HA source loopback.",
        default="10.11.0.0/23",
    )
    hypershield_ha_vlan: Annotated[int | None, NDMinimumVersion("4.3.1")] = Field(
        alias="hypershieldHAVlan",
        description="VLAN used for smart-switch HA communication.",
        ge=2,
        le=4094,
        default=3601,
    )
    use_hypershield_source_loopback_for_ha: Annotated[bool | None, NDMinimumVersion("4.3.1")] = Field(
        alias="useHypershieldSourceLoopbackForHA",
        description="Reuse the Hypershield source loopback for HA.",
        default=False,
    )
    ios_xe_tor_bootstrap_vlan: Annotated[int | None, NDMinimumVersion("4.3.1")] = Field(
        alias="iosXeTorBootstrapVlan",
        description="Catalyst ToR bootstrap VLAN for inband PnP.",
        ge=1,
        le=4094,
        default=1,
    )
    remote_storage_server: Annotated[str | None, NDMinimumVersion("4.3.1")] = Field(
        alias="remoteStorageServer",
        description="Name of the remote storage configured in Nexus Dashboard.",
        max_length=63,
        pattern=r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$",
        default=None,
    )
    software_update_in_monitored_mode: Annotated[bool | None, NDMinimumVersion("4.3.1")] = Field(
        alias="softwareUpdateInMonitoredMode",
        description="Allow image management while the fabric is in monitored mode.",
        default=False,
    )
    strict_config_compliance_mode: Annotated[bool | None, NDMinimumVersion("4.3.1")] = Field(
        alias="strictConfigComplianceMode",
        description="Enable bidirectional configuration compliance checks.",
        default=False,
    )

    @field_validator("bgp_asn")
    @classmethod
    def validate_bgp_asn(cls, value: str | None) -> str | None:
        """
        # Summary

        Validate BGP ASN format and range.

        ## Description

        Accepts a decimal ASN (1-4294967295), including the native template's
        optional leading plus sign, or unsigned dotted four-byte ASN notation.
        Normalize a leading plus sign so API payload and response state use
        the same unsigned decimal spelling.

        ## Raises

        - `ValueError` - If the value does not match the expected ASN format
        """
        if value is not None and value.startswith("+") and not value[1:].isdigit():
            raise ValueError("A leading plus sign is only supported for decimal BGP ASNs")
        validate_bgp_asn_template_value(value)
        return value[1:] if value is not None and value.startswith("+") else value


class ExternalTelemetrySettingsModel(TelemetrySettingsModel):
    """External telemetry settings managed through the fabric CRUD endpoint."""

    _argspec_exclude_fields: ClassVar[set[str]] = {"energy_management"}

    energy_management: ClassVar[None] = None

    @model_validator(mode="before")
    @classmethod
    def exclude_unmanaged_energy_settings(cls, data: Any, info: ValidationInfo) -> Any:
        """Discard response-only energy settings and reject them as writable input."""
        if not isinstance(data, dict):
            return data
        keys = {"energy_management", "energyManagement"}.intersection(data)
        if not keys:
            return data
        if (info.context or {}).get("mode") != "response":
            if any(data[key] is not None for key in keys):
                raise ValueError("energy_management is not managed by the External fabric module")
            return data
        return {key: value for key, value in data.items() if key not in keys}


class FabricExternalConnectivityModel(FabricBaseModel):
    """
    # Summary

    Complete model for creating a new External Connectivity fabric.

    This model combines all necessary components for fabric creation including
    basic fabric properties, management settings, telemetry, and streaming configuration.

    ## Raises

    - `ValueError` - If required fields are missing or invalid
    - `TypeError` - If field types don't match expected types
    """

    _fabric_type: ClassVar[FabricTypeEnum] = FabricTypeEnum.EXTERNAL_CONNECTIVITY
    _argspec_exclude_fields: ClassVar[set[str]] = {"alert_suspend"}

    alert_suspend: ClassVar[None] = None
    telemetry_settings: ExternalTelemetrySettingsModel | None = Field(alias="telemetrySettings", description="Telemetry configuration", default=None)
    telemetry_collection_type: TelemetryCollectionTypeEnum = Field(
        alias="telemetryCollectionType",
        description="Telemetry collection method.",
        default=TelemetryCollectionTypeEnum.OUT_OF_BAND,
    )

    # Core Management Configuration
    management: ExternalConnectivityManagementModel | None = Field(description="External Connectivity management configuration", default=None)

    @model_validator(mode="before")
    @classmethod
    def exclude_unmanaged_alert_state(cls, data: Any, info: ValidationInfo) -> Any:
        """Discard response-only alert state and reject it as writable input."""
        if not isinstance(data, dict):
            return data
        keys = {"alert_suspend", "alertSuspend"}.intersection(data)
        if not keys:
            return data
        if (info.context or {}).get("mode") != "response":
            if any(data[key] is not None for key in keys):
                raise ValueError("alert_suspend is not managed by the External fabric module")
            return data
        return {key: value for key, value in data.items() if key not in keys}

    @field_validator("telemetry_settings", mode="before")
    @classmethod
    def use_external_telemetry_settings(cls, value: Any, info: ValidationInfo) -> Any:
        """Narrow shared settings without materializing separately managed energy defaults."""
        if isinstance(value, dict) and value and set(value) <= {"energy_management", "energyManagement"} and (info.context or {}).get("mode") == "response":
            return None
        if isinstance(value, TelemetrySettingsModel) and not isinstance(value, ExternalTelemetrySettingsModel):
            if "energy_management" in value.model_fields_set and (info.context or {}).get("mode") != "response":
                raise ValueError("energy_management is not managed by the External fabric module")
            return value.model_dump(exclude={"energy_management"}, exclude_unset=True)
        return value
