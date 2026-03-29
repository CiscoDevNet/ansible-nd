# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Common Pydantic models shared across fabric types (iBGP, eBGP, External Connectivity).

## Models

- `LocationModel` - Geographic location coordinates
- `NetflowExporterModel` - Netflow exporter configuration
- `NetflowRecordModel` - Netflow record configuration
- `NetflowMonitorModel` - Netflow monitor configuration
- `NetflowSettingsModel` - Complete netflow settings
- `BootstrapSubnetModel` - Bootstrap subnet configuration
- `TelemetryFlowCollectionModel` - Telemetry flow collection settings
- `TelemetryMicroburstModel` - Microburst detection configuration
- `TelemetryAnalysisSettingsModel` - Telemetry analysis configuration
- `TelemetryEnergyManagementModel` - Energy management telemetry
- `TelemetryNasExportSettingsModel` - NAS export settings
- `TelemetryNasModel` - NAS telemetry configuration
- `TelemetrySettingsModel` - Complete telemetry configuration
- `ExternalStreamingSettingsModel` - External streaming configuration
"""

from __future__ import absolute_import, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import re
from typing import List, Dict, Any

from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
)


# Regex from OpenAPI schema: bgpAsn accepts plain integers (1-4294967295) and
# dotted four-byte ASN notation (1-65535).(0-65535)
BGP_ASN_RE = re.compile(
    r"^(([1-9]{1}[0-9]{0,8}|[1-3]{1}[0-9]{1,9}|[4]{1}([0-1]{1}[0-9]{8}"
    r"|[2]{1}([0-8]{1}[0-9]{7}|[9]{1}([0-3]{1}[0-9]{6}|[4]{1}([0-8]{1}[0-9]{5}"
    r"|[9]{1}([0-5]{1}[0-9]{4}|[6]{1}([0-6]{1}[0-9]{3}|[7]{1}([0-1]{1}[0-9]{2}"
    r"|[2]{1}([0-8]{1}[0-9]{1}|[9]{1}[0-5]{1})))))))))"
    r"|([1-5]\d{4}|[1-9]\d{0,3}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])"
    r"(\.([1-5]\d{4}|[1-9]\d{0,3}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]|0))?)$"
)


class LocationModel(NDNestedModel):
    """
    # Summary

    Geographic location coordinates for the fabric.

    ## Raises

    - `ValueError` - If latitude or longitude are outside valid ranges
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    latitude: float = Field(description="Latitude coordinate (-90 to 90)", ge=-90.0, le=90.0)
    longitude: float = Field(description="Longitude coordinate (-180 to 180)", ge=-180.0, le=180.0)


class NetflowExporterModel(NDNestedModel):
    """
    # Summary

    Netflow exporter configuration for telemetry.

    ## Raises

    - `ValueError` - If UDP port is outside valid range or IP address is invalid
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    exporter_name: str = Field(alias="exporterName", description="Name of the netflow exporter")
    exporter_ip: str = Field(alias="exporterIp", description="IP address of the netflow collector")
    vrf: str = Field(description="VRF name for the exporter", default="management")
    source_interface_name: str = Field(alias="sourceInterfaceName", description="Source interface name")
    udp_port: int = Field(alias="udpPort", description="UDP port for netflow export", ge=1, le=65535)


class NetflowRecordModel(NDNestedModel):
    """
    # Summary

    Netflow record configuration defining flow record templates.

    ## Raises

    None
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    record_name: str = Field(alias="recordName", description="Name of the netflow record")
    record_template: str = Field(alias="recordTemplate", description="Template type for the record")
    layer2_record: bool = Field(alias="layer2Record", description="Enable layer 2 record fields", default=False)


class NetflowMonitorModel(NDNestedModel):
    """
    # Summary

    Netflow monitor configuration linking records to exporters.

    ## Raises

    None
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    monitor_name: str = Field(alias="monitorName", description="Name of the netflow monitor")
    record_name: str = Field(alias="recordName", description="Associated record name")
    exporter1_name: str = Field(alias="exporter1Name", description="Primary exporter name")
    exporter2_name: str = Field(alias="exporter2Name", description="Secondary exporter name", default="")


class NetflowSettingsModel(NDNestedModel):
    """
    # Summary

    Complete netflow configuration including exporters, records, and monitors.

    ## Raises

    - `ValueError` - If netflow lists are inconsistent with netflow enabled state
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    netflow: bool = Field(description="Enable netflow collection", default=False)
    netflow_exporter_collection: List[NetflowExporterModel] = Field(
        alias="netflowExporterCollection", description="List of netflow exporters", default_factory=list
    )
    netflow_record_collection: List[NetflowRecordModel] = Field(alias="netflowRecordCollection", description="List of netflow records", default_factory=list)
    netflow_monitor_collection: List[NetflowMonitorModel] = Field(
        alias="netflowMonitorCollection", description="List of netflow monitors", default_factory=list
    )


class BootstrapSubnetModel(NDNestedModel):
    """
    # Summary

    Bootstrap subnet configuration for fabric initialization.

    ## Raises

    - `ValueError` - If IP addresses or subnet prefix are invalid
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    start_ip: str = Field(alias="startIp", description="Starting IP address of the bootstrap range")
    end_ip: str = Field(alias="endIp", description="Ending IP address of the bootstrap range")
    default_gateway: str = Field(alias="defaultGateway", description="Default gateway for bootstrap subnet")
    subnet_prefix: int = Field(alias="subnetPrefix", description="Subnet prefix length", ge=8, le=30)


class TelemetryFlowCollectionModel(NDNestedModel):
    """
    # Summary

    Telemetry flow collection configuration.

    ## Raises

    None
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    traffic_analytics: str = Field(alias="trafficAnalytics", description="Traffic analytics state", default="enabled")
    traffic_analytics_scope: str = Field(alias="trafficAnalyticsScope", description="Traffic analytics scope", default="intraFabric")
    operating_mode: str = Field(alias="operatingMode", description="Operating mode", default="flowTelemetry")
    udp_categorization: str = Field(alias="udpCategorization", description="UDP categorization", default="enabled")


class TelemetryMicroburstModel(NDNestedModel):
    """
    # Summary

    Microburst detection configuration.

    ## Raises

    None
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    microburst: bool = Field(description="Enable microburst detection", default=False)
    sensitivity: str = Field(description="Microburst sensitivity level", default="low")


class TelemetryAnalysisSettingsModel(NDNestedModel):
    """
    # Summary

    Telemetry analysis configuration.

    ## Raises

    None
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    is_enabled: bool = Field(alias="isEnabled", description="Enable telemetry analysis", default=False)


class TelemetryEnergyManagementModel(NDNestedModel):
    """
    # Summary

    Energy management telemetry configuration.

    ## Raises

    None
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    cost: float = Field(description="Energy cost per unit", default=1.2)


class TelemetryNasExportSettingsModel(NDNestedModel):
    """
    # Summary

    NAS export settings for telemetry.

    ## Raises

    None
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    export_type: str = Field(alias="exportType", description="Export type", default="full")
    export_format: str = Field(alias="exportFormat", description="Export format", default="json")


class TelemetryNasModel(NDNestedModel):
    """
    # Summary

    NAS (Network Attached Storage) telemetry configuration.

    ## Raises

    None
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    server: str = Field(description="NAS server address", default="")
    export_settings: TelemetryNasExportSettingsModel = Field(
        alias="exportSettings", description="NAS export settings", default_factory=TelemetryNasExportSettingsModel
    )


class TelemetrySettingsModel(NDNestedModel):
    """
    # Summary

    Complete telemetry configuration for the fabric.

    ## Raises

    None
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    flow_collection: TelemetryFlowCollectionModel = Field(
        alias="flowCollection", description="Flow collection settings", default_factory=TelemetryFlowCollectionModel
    )
    microburst: TelemetryMicroburstModel = Field(description="Microburst detection settings", default_factory=TelemetryMicroburstModel)
    analysis_settings: TelemetryAnalysisSettingsModel = Field(
        alias="analysisSettings", description="Analysis settings", default_factory=TelemetryAnalysisSettingsModel
    )
    nas: TelemetryNasModel = Field(description="NAS telemetry configuration", default_factory=TelemetryNasModel)
    energy_management: TelemetryEnergyManagementModel = Field(
        alias="energyManagement", description="Energy management settings", default_factory=TelemetryEnergyManagementModel
    )


class ExternalStreamingSettingsModel(NDNestedModel):
    """
    # Summary

    External streaming configuration for events and data export.

    ## Raises

    None
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    email: List[Dict[str, Any]] = Field(description="Email streaming configuration", default_factory=list)
    message_bus: List[Dict[str, Any]] = Field(alias="messageBus", description="Message bus configuration", default_factory=list)
    syslog: Dict[str, Any] = Field(
        description="Syslog streaming configuration", default_factory=lambda: {"collectionSettings": {"anomalies": []}, "facility": "", "servers": []}
    )
    webhooks: List[Dict[str, Any]] = Field(description="Webhook configuration", default_factory=list)


# Export all models for external use
__all__ = [
    "LocationModel",
    "NetflowExporterModel",
    "NetflowRecordModel",
    "NetflowMonitorModel",
    "NetflowSettingsModel",
    "BootstrapSubnetModel",
    "TelemetryFlowCollectionModel",
    "TelemetryMicroburstModel",
    "TelemetryAnalysisSettingsModel",
    "TelemetryEnergyManagementModel",
    "TelemetryNasExportSettingsModel",
    "TelemetryNasModel",
    "TelemetrySettingsModel",
    "ExternalStreamingSettingsModel",
    "BGP_ASN_RE",
]
