# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Common Pydantic models shared across fabric types (iBGP, eBGP, External Connectivity).

## Models

- `BootstrapSubnetModel` - Bootstrap subnet configuration
- `ExternalStreamingSettingsModel` - External streaming configuration
- `LocationModel` - Geographic location coordinates
- `NetflowExporterModel` - Netflow exporter configuration
- `NetflowMonitorModel` - Netflow monitor configuration
- `NetflowRecordModel` - Netflow record configuration
- `NetflowSettingsModel` - Complete netflow settings
- `TelemetryAnalysisSettingsModel` - Telemetry analysis configuration
- `TelemetryEnergyManagementModel` - Energy management telemetry
- `TelemetryFlowCollectionModel` - Telemetry flow collection settings
- `TelemetryMicroburstModel` - Microburst detection configuration
- `TelemetryNasExportSettingsModel` - NAS export settings
- `TelemetryNasModel` - NAS telemetry configuration
- `TelemetrySettingsModel` - Complete telemetry configuration
"""

from __future__ import annotations

import ipaddress
import re
from copy import deepcopy
from typing import Annotated, Any, ClassVar, Optional

from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import (
    TelemetryMicroburstSensitivityEnum,
    TelemetryNasExportFormatEnum,
    TelemetryNasExportTypeEnum,
    TelemetryTrafficAnalyticsEnum,
    TelemetryTrafficAnalyticsScopeEnum,
    TelemetryUdpCategorizationEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationInfo,
    model_validator,
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

SITE_ID_MAX_ND_4_2 = 4294967295
SITE_ID_MAX_ND_4_3_1 = 281474976710655

SCHEDULED_BACKUP_TIME_RE = r"^([01]\d|2[0-3]):([0-5]\d)$"
FABRIC_INTERFACE_RE = (
    r"^(([Ee]([Tt][Hh][Ee][Rr][Nn][Ee][Tt])?|[Ee][Tt][Hh])\d+/\d+(-\d+)?|" + r"([Pp][Oo]|[Pp][Oo][Rr][Tt][-]?[Cc][Hh][Aa][Nn][Nn][Ee][Ll])\d+(-\d+)?)$"
)


def validate_fabric_ip_address(value: str | None) -> str | None:
    """Validate a bare IPv4 or IPv6 address while preserving its spelling."""
    # ND represents an unset optional address as either an omitted property or
    # an empty string, depending on release and fabric template. Normalize both
    # to the model's unset value so gathered reads remain replayable.
    if value in (None, ""):
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError as err:
        raise ValueError(f"{value!r} is not a valid IPv4 or IPv6 address") from err
    return value


def validate_fabric_ipv4_address(value: str | None) -> str | None:
    """Validate a bare IPv4 address while preserving its spelling."""
    # ND represents an unset optional address as either an omitted property or
    # an empty string, depending on release and fabric template. Normalize both
    # to the model's unset value so gathered reads remain replayable.
    if value in (None, ""):
        return None
    try:
        ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ValueError) as err:
        raise ValueError(f"{value!r} is not a valid IPv4 address") from err
    return value


def validate_fabric_dhcp_gateway_address(value: str | None) -> str | None:
    """Validate a DHCP scope or management gateway address for replay.

    Release and controller-installation support is checked by the fabric
    orchestrator before sending a user-supplied IPv6 value.  This validator
    must be context-independent because merged updates validate assignment on
    an existing response model without the original ``from_config`` context.
    """
    return validate_fabric_ip_address(value)


def validate_fabric_ipv4_cidr(value: str | None) -> str | None:
    """Validate IPv4 CIDR notation while preserving its spelling."""
    if value is None:
        return value
    if "/" not in value:
        raise ValueError(f"{value!r} is not valid IPv4 CIDR notation")
    try:
        ipaddress.IPv4Interface(value)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as err:
        raise ValueError(f"{value!r} is not valid IPv4 CIDR notation") from err
    return value


def validate_multicast_group_subnet(value: str | None) -> str | None:
    """Validate the common 8-30 IPv4 CIDR contract for multicast pools."""
    value = validate_fabric_ipv4_cidr(value)
    if value is None:
        return value
    prefix = ipaddress.IPv4Interface(value).network.prefixlen
    if not 8 <= prefix <= 30:
        raise ValueError(f"Multicast group subnet prefix must be between 8 and 30, got {prefix}")
    return value


# Optional is intentional in these runtime Annotated expressions.  It avoids
# pylint interpreting ``str | None`` at import time under older target settings.
FabricIPAddress = Annotated[Optional[str], BeforeValidator(validate_fabric_ip_address)]
RequiredFabricIPAddress = Annotated[str, BeforeValidator(validate_fabric_ip_address)]
FabricIPv4Address = Annotated[Optional[str], BeforeValidator(validate_fabric_ipv4_address)]
FabricDhcpGatewayAddress = Annotated[Optional[str], BeforeValidator(validate_fabric_dhcp_gateway_address)]
RequiredFabricIPv4Address = Annotated[str, BeforeValidator(validate_fabric_ipv4_address)]
FabricIPv4CIDR = Annotated[Optional[str], BeforeValidator(validate_fabric_ipv4_cidr)]
MulticastGroupSubnet = Annotated[Optional[str], BeforeValidator(validate_multicast_group_subnet)]
ScheduledBackupTime = Annotated[Optional[str], Field(pattern=SCHEDULED_BACKUP_TIME_RE)]
FabricInterfaceName = Annotated[str, Field(pattern=FABRIC_INTERFACE_RE)]


def validate_bgp_asn_value(value: str | None) -> str | None:
    """Validate a BGP ASN when it is present in a partial fabric proposal."""
    if value is None:
        return value
    if not BGP_ASN_RE.fullmatch(value):
        raise ValueError(f"Invalid BGP ASN '{value}'. Expected a plain integer " "(1-4294967295) or dotted notation (1-65535.0-65535).")
    return value


def validate_site_id_value(value: str | None) -> str | None:
    """Validate the site ID syntax and the largest value supported by ND."""
    if value in (None, ""):
        return value
    if "." in value:
        if not BGP_ASN_RE.fullmatch(value):
            raise ValueError(f"Invalid dotted site ID: {value}")
        return value
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise ValueError(f"Site ID must be a non-zero decimal without leading zeros or dotted ASN notation, got: {value}")
    site_id = int(value)
    if site_id > SITE_ID_MAX_ND_4_3_1:
        raise ValueError(f"Site ID must be between 1 and {SITE_ID_MAX_ND_4_3_1}, got: {site_id}")
    return value


def bgp_asn_to_site_id(value: str) -> str:
    """Return the asplain site ID corresponding to an ASN."""
    if "." not in value:
        return value
    high, low = value.split(".")
    return str(int(high) * 65536 + int(low))


def default_site_id_from_bgp_asn(management: Any) -> None:
    """Default site ID without treating an omitted value as a merge update."""
    if management is None or management.site_id not in (None, "") or management.bgp_asn is None:
        return

    site_id_was_supplied = "site_id" in management.model_fields_set
    management.site_id = bgp_asn_to_site_id(management.bgp_asn)
    if not site_id_was_supplied:
        management.model_fields_set.discard("site_id")


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
    subnet_prefix: int = Field(alias="subnetPrefix", description="IPv4 prefix 8-30 or IPv6 prefix 64-126")

    @model_validator(mode="after")
    def validate_address_family_and_prefix(self) -> "BootstrapSubnetModel":
        """Require valid same-family addresses and the matching prefix range."""
        parsed = {}
        for field_name in ("start_ip", "end_ip", "default_gateway"):
            value = getattr(self, field_name)
            try:
                parsed[field_name] = ipaddress.ip_address(value)
            except ValueError as err:
                raise ValueError(f"{field_name} must be a valid IPv4 or IPv6 address, got {value!r}") from err

        versions = {address.version for address in parsed.values()}
        if len(versions) != 1:
            raise ValueError("start_ip, end_ip, and default_gateway must use the same IP address family")

        version = versions.pop()
        minimum, maximum = (8, 30) if version == 4 else (64, 126)
        if not minimum <= self.subnet_prefix <= maximum:
            raise ValueError(f"IPv{version} bootstrap subnet_prefix must be between {minimum} and {maximum}, got {self.subnet_prefix}")
        return self


class ExternalStreamingSettingsModel(NDNestedModel):
    """
    # Summary

    External streaming configuration for events and data export.

    ## Raises

    None
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    email: list[dict[str, Any]] = Field(description="Email streaming configuration", default_factory=list)
    message_bus: list[dict[str, Any]] = Field(alias="messageBus", description="Message bus configuration", default_factory=list)
    syslog: dict[str, Any] = Field(
        description="Syslog streaming configuration", default_factory=lambda: {"collectionSettings": {"anomalies": []}, "facility": "", "servers": []}
    )
    webhooks: list[dict[str, Any]] = Field(description="Webhook configuration", default_factory=list)


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
    exporter_ip: RequiredFabricIPAddress = Field(alias="exporterIp", description="IP address of the netflow collector")
    vrf: str = Field(description="VRF name for the exporter", default="management")
    source_interface_name: str = Field(alias="sourceInterfaceName", description="Source interface name")
    udp_port: int | None = Field(alias="udpPort", description="UDP port for netflow export", ge=1, le=65535, default=None)


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


class NetflowSettingsModel(NDNestedModel):
    """
    # Summary

    Complete netflow configuration including exporters, records, and monitors.

    ## Raises

    - `ValueError` - If netflow lists are inconsistent with netflow enabled state
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    netflow: bool = Field(description="Enable netflow collection", default=False)
    netflow_exporter_collection: list[NetflowExporterModel] = Field(
        alias="netflowExporterCollection", description="List of netflow exporters", default_factory=list
    )
    netflow_record_collection: list[NetflowRecordModel] = Field(alias="netflowRecordCollection", description="List of netflow records", default_factory=list)
    netflow_monitor_collection: list[NetflowMonitorModel] = Field(
        alias="netflowMonitorCollection", description="List of netflow monitors", default_factory=list
    )


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


class TelemetryFlowCollectionModel(NDNestedModel):
    """
    # Summary

    Telemetry flow collection configuration.

    ## Raises

    None
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    # These writable OpenAPI roots are not exposed as public Ansible options.
    # A full replacement must nevertheless carry their controller-returned
    # values forward.  Keep them out of normal module output while allowing
    # prepare_for_replacement() to copy the sanitized response values.
    replacement_preserve_fields: ClassVar[set[str]] = {
        "flowCollectionModes",
        "flowRules",
        "trafficAnalyticsRules",
    }
    config_exclude_fields: ClassVar[set[str]] = replacement_preserve_fields

    traffic_analytics: TelemetryTrafficAnalyticsEnum = Field(
        alias="trafficAnalytics",
        description="Traffic analytics state",
        default=TelemetryTrafficAnalyticsEnum.ENABLED,
    )
    traffic_analytics_scope: TelemetryTrafficAnalyticsScopeEnum = Field(
        alias="trafficAnalyticsScope",
        description="Traffic analytics scope",
        default=TelemetryTrafficAnalyticsScopeEnum.INTRA_FABRIC,
    )
    udp_categorization: TelemetryUdpCategorizationEnum = Field(
        alias="udpCategorization",
        description="UDP categorization",
        default=TelemetryUdpCategorizationEnum.ENABLED,
    )

    @model_validator(mode="before")
    @classmethod
    def strip_read_only_response_data(cls, data: Any, info: ValidationInfo) -> Any:
        """Drop controller-only telemetry data before it can reach a PUT.

        The three opaque writable roots above are retained for exact-state
        replacement, but their response-only identifiers are not legal PUT
        input.  The remaining top-level keys are wholly read-only and are
        discarded.  Work on a deep copy so parsing a response never mutates the
        endpoint result retained by callers.
        """
        if not isinstance(data, dict) or (info.context or {}).get("mode") != "response":
            return data

        cleaned = deepcopy(data)
        for key in (
            "flowCollectionCapabilities",
            "flow_collection_capabilities",
            "operatingMode",
            "operating_mode",
            "trafficAnalyticsCompatibilityProtocol",
            "traffic_analytics_compatibility_protocol",
        ):
            cleaned.pop(key, None)

        flow_rules = cleaned.get("flowRules", cleaned.get("flow_rules"))
        if isinstance(flow_rules, dict):
            for collection_key in (
                "vrfFlowRules",
                "vrf_flow_rules",
                "interfaceFlowRules",
                "interface_flow_rules",
                "l3OutFlowRules",
                "l3_out_flow_rules",
            ):
                rules = flow_rules.get(collection_key)
                if not isinstance(rules, list):
                    continue
                for rule in rules:
                    if not isinstance(rule, dict):
                        continue
                    rule.pop("uuid", None)
                    attributes = rule.get("attributes")
                    if isinstance(attributes, list):
                        for attribute in attributes:
                            if isinstance(attribute, dict):
                                attribute.pop("attributeId", None)
                                attribute.pop("attribute_id", None)
                    if collection_key not in {"interfaceFlowRules", "interface_flow_rules"}:
                        continue
                    interfaces = rule.get("interfaceCollection", rule.get("interface_collection"))
                    if isinstance(interfaces, list):
                        for interface in interfaces:
                            if isinstance(interface, dict):
                                interface.pop("switchId", None)
                                interface.pop("switch_id", None)

        traffic_analytics_rules = cleaned.get("trafficAnalyticsRules", cleaned.get("traffic_analytics_rules"))
        if isinstance(traffic_analytics_rules, dict):
            interface_rules = traffic_analytics_rules.get("interfaceRules", traffic_analytics_rules.get("interface_rules"))
            if isinstance(interface_rules, list):
                for rule in interface_rules:
                    if not isinstance(rule, dict):
                        continue
                    rule.pop("uuid", None)
                    interfaces = rule.get("interfaceCollection", rule.get("interface_collection"))
                    if isinstance(interfaces, list):
                        for interface in interfaces:
                            if isinstance(interface, dict):
                                interface.pop("switchId", None)
                                interface.pop("switch_id", None)
        return cleaned


class TelemetryMicroburstModel(NDNestedModel):
    """
    # Summary

    Microburst detection configuration.

    ## Raises

    None
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    microburst: bool = Field(description="Enable microburst detection", default=False)
    sensitivity: TelemetryMicroburstSensitivityEnum = Field(
        description="Microburst sensitivity level",
        default=TelemetryMicroburstSensitivityEnum.LOW,
    )


class TelemetryNasExportSettingsModel(NDNestedModel):
    """
    # Summary

    NAS export settings for telemetry.

    ## Raises

    None
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    export_type: TelemetryNasExportTypeEnum = Field(
        alias="exportType",
        description="Export type",
        default=TelemetryNasExportTypeEnum.FULL,
    )
    export_format: TelemetryNasExportFormatEnum = Field(
        alias="exportFormat",
        description="Export format",
        default=TelemetryNasExportFormatEnum.JSON,
    )


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
