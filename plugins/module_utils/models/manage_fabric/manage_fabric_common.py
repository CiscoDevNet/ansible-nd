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
from typing import Annotated, Any, ClassVar, Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.release_metadata import NDMinimumVersion
from ansible_collections.cisco.nd.plugins.module_utils.models.types import validate_ipv6_cidr
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import (
    TelemetryMicroburstSensitivityEnum,
    TelemetryNasExportFormatEnum,
    TelemetryNasExportTypeEnum,
    TelemetryTrafficAnalyticsEnum,
    TelemetryTrafficAnalyticsScopeEnum,
    TelemetryUdpCategorizationEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    AfterValidator,
    BeforeValidator,
    ConfigDict,
    FieldSerializationInfo,
    Field,
    SecretStr,
    SerializationInfo,
    ValidationInfo,
    field_validator,
    field_serializer,
    model_serializer,
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
KEYCHAIN_LIFETIME_TIME_RE = r"^([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$"
KEYCHAIN_LIFETIME_DATE_RE = r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(0[1-9]|[12][0-9]|3[01])\s+(199[3-9]|20[0-2][0-9]|203[0-5])$"
FABRIC_INTERFACE_RE = (
    r"^(([Ee]([Tt][Hh][Ee][Rr][Nn][Ee][Tt])?|[Ee][Tt][Hh])\d+/\d+(-\d+)?|" + r"([Pp][Oo]|[Pp][Oo][Rr][Tt][-]?[Cc][Hh][Aa][Nn][Nn][Ee][Ll])\d+(-\d+)?)$"
)
INTEGER_RANGE_RE = re.compile(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*\Z")


def validate_bounded_integer_range(value: str | None, minimum: int, maximum: int, field_name: str) -> str | None:
    """Validate comma-separated integer values/ranges against inclusive bounds."""
    if value is None:
        return value
    if not isinstance(value, str) or INTEGER_RANGE_RE.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a comma-separated list of integers or integer ranges")

    for part in value.split(","):
        bounds = part.split("-")
        start = int(bounds[0])
        end = int(bounds[-1])
        if start > end:
            raise ValueError(f"{field_name} range start must not exceed its end")
        if start < minimum or end > maximum:
            raise ValueError(f"{field_name} values must be between {minimum} and {maximum}")
    return value


def validate_secret_string_constraints(value: Any, field_name: str, constraints: dict[str, Any]) -> Any:
    """Validate constraints on secret text before wrapping it in SecretStr.

    Error messages intentionally omit the supplied value.
    """
    if value is None:
        return value
    raw = value.get_secret_value() if isinstance(value, SecretStr) else value
    if not isinstance(raw, str):
        return value
    if raw == "" and constraints.get("allow_empty"):
        return value
    minimum = constraints.get("min_length")
    maximum = constraints.get("max_length")
    pattern = constraints.get("pattern")
    if minimum is not None and len(raw) < minimum:
        raise ValueError(f"{field_name} must contain at least {minimum} characters")
    if maximum is not None and len(raw) > maximum:
        raise ValueError(f"{field_name} must contain at most {maximum} characters")
    if pattern is not None and re.fullmatch(pattern, raw) is None:
        raise ValueError(f"{field_name} does not match the required format")
    return value


class FabricManagementModel(NDNestedModel):
    """Apply declarative native-template constraints across fabric models."""

    ipv6_management_minimum_nd_version: ClassVar[str | None] = "4.3.1"

    def _scrub_reverse_diff_dict(self, data: dict[str, Any]) -> None:
        """Treat omitted newer-release defaults as deterministic default echoes.

        Older responses acquire current-model defaults during parsing. A
        version-filtered proposal must not interpret those synthesized values
        as settings to remove. Explicit nondefault values still participate in
        forward comparisons and removal detection.
        """
        super()._scrub_reverse_diff_dict(data)
        for name, field in type(self).model_fields.items():
            if field.is_required() or field.default_factory is not None or field.default is None:
                continue
            if not any(isinstance(item, NDMinimumVersion) for item in field.metadata):
                continue
            alias = field.alias or name
            if alias in data and data[alias] == field.default:
                data.pop(alias)

    @field_validator("*", mode="before", check_fields=False)
    @classmethod
    def validate_template_constraints(cls, value: Any, info: ValidationInfo) -> Any:
        """Validate template-only constraints declared in Field JSON metadata."""
        field_info = cls.model_fields.get(info.field_name)
        extra = field_info.json_schema_extra if field_info is not None else None
        if not isinstance(extra, dict):
            return value

        bounds = extra.get("nd_integer_range")
        if isinstance(bounds, dict):
            value = validate_bounded_integer_range(
                value,
                bounds["minimum"],
                bounds["maximum"],
                info.field_name,
            )

        string_constraints = extra.get("nd_string_constraints")
        if isinstance(string_constraints, dict):
            value = validate_secret_string_constraints(value, info.field_name, string_constraints)

        allowed_values = extra.get("nd_discrete_values")
        if isinstance(allowed_values, list):
            normalized_value = value
            if isinstance(value, str):
                normalized_value = next(
                    (candidate for candidate in allowed_values if str(candidate) == value),
                    value,
                )
            if normalized_value not in allowed_values:
                raise ValueError(f"{info.field_name} must be one of {', '.join(map(str, allowed_values))}")
        return value


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


def normalize_anycast_gateway_mac(value: str) -> str:
    """Validate a complete 48-bit MAC address and return lowercase dotted notation."""
    patterns = (
        r"(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}",
        r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}",
        r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}",
        r"[0-9a-fA-F]{12}",
    )
    if not any(re.fullmatch(pattern, value) for pattern in patterns):
        raise ValueError(f"Invalid MAC address format, expected a 48-bit MAC address, got: {value}")
    digits = re.sub(r"[.:-]", "", value).lower()
    return f"{digits[:4]}.{digits[4:8]}.{digits[8:]}"


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


def validate_fabric_ipv6_address(value: str | None) -> str | None:
    """Validate a bare IPv6 address while preserving its spelling."""
    if value is None:
        return value
    try:
        ipaddress.IPv6Address(value)
    except (ipaddress.AddressValueError, ValueError) as err:
        raise ValueError(f"{value!r} is not a valid IPv6 address") from err
    return value


def validate_fabric_ipv4_cidr(value: str | None) -> str | None:
    """Validate IPv4 CIDR notation while preserving its spelling."""
    if value is None:
        return value
    if "/" not in value:
        raise ValueError(f"{value!r} is not valid IPv4 CIDR notation")
    try:
        ipaddress.IPv4Interface(value)
    except (
        ipaddress.AddressValueError,
        ipaddress.NetmaskValueError,
        ValueError,
    ) as err:
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


def validate_fabric_ipv6_multicast_group_subnet(value: str | None) -> str | None:
    """Validate the native 112-128 IPv6 multicast pool prefix contract."""
    value = validate_ipv6_cidr(value)
    if value is None:
        return value
    prefix = ipaddress.IPv6Interface(value).network.prefixlen
    if not 112 <= prefix <= 128:
        raise ValueError(f"IPv6 multicast group subnet prefix must be between 112 and 128, got {prefix}")
    return value


# Optional is intentional in these runtime Annotated expressions.  It avoids
# pylint interpreting ``str | None`` at import time under older target settings.
FabricIPAddress = Annotated[Optional[str], BeforeValidator(validate_fabric_ip_address)]
RequiredFabricIPAddress = Annotated[str, BeforeValidator(validate_fabric_ip_address)]
FabricIPv4Address = Annotated[Optional[str], BeforeValidator(validate_fabric_ipv4_address)]
FabricDhcpGatewayAddress = Annotated[Optional[str], BeforeValidator(validate_fabric_dhcp_gateway_address)]
RequiredFabricIPv4Address = Annotated[str, BeforeValidator(validate_fabric_ipv4_address)]
RequiredFabricBareIPv4Address = Annotated[str, Field(min_length=1), AfterValidator(validate_fabric_ipv4_address)]
RequiredFabricIPv6Address = Annotated[str, AfterValidator(validate_fabric_ipv6_address)]
FabricIPv4CIDR = Annotated[Optional[str], BeforeValidator(validate_fabric_ipv4_cidr)]
RequiredFabricIPv4CIDR = Annotated[str, AfterValidator(validate_fabric_ipv4_cidr)]
RequiredFabricIPv6CIDR = Annotated[str, AfterValidator(validate_ipv6_cidr)]
MulticastGroupSubnet = Annotated[Optional[str], BeforeValidator(validate_multicast_group_subnet)]
RequiredFabricIPv6MulticastGroupSubnet = Annotated[str, AfterValidator(validate_fabric_ipv6_multicast_group_subnet)]
ScheduledBackupTime = Annotated[Optional[str], Field(pattern=SCHEDULED_BACKUP_TIME_RE)]
FabricInterfaceName = Annotated[str, Field(pattern=FABRIC_INTERFACE_RE)]


def validate_bgp_asn_value(value: str | None) -> str | None:
    """Validate a BGP ASN when it is present in a partial fabric proposal."""
    if value is None:
        return value
    if not BGP_ASN_RE.fullmatch(value):
        raise ValueError(f"Invalid BGP ASN '{value}'. Expected a plain integer " "(1-4294967295) or dotted notation (1-65535.0-65535).")
    return value


def validate_bgp_asn_template_value(value: str | None) -> str | None:
    """Validate a template ASN, including the optional leading plus sign."""
    if value is None:
        return value
    candidate = value[1:] if value.startswith("+") else value
    validate_bgp_asn_value(candidate)
    return value


def validate_bgp_asn_range(value: str | None) -> str | None:
    """Validate one template BGP ASN range with inclusive ASN endpoints."""
    if value is None:
        return value
    parts = value.split("-")
    if len(parts) != 2:
        raise ValueError("bgp_asn_range must contain a start and end ASN separated by '-'")
    validate_bgp_asn_template_value(parts[0])
    validate_bgp_asn_template_value(parts[1])
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


class KeychainKeyEntryModel(NDNestedModel):
    """Shared IS-IS, OSPF, and PIM keychain entry."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow",
    )

    key_id: int = Field(alias="keyId", description="Key identifier (0 to 65535).", ge=0, le=65535)
    key_type: Literal["6", "7"] = Field(alias="keyType", description="Key type: 6 or 7.", default="7")
    key_string: SecretStr = Field(
        alias="keyString",
        description="Key material.",
        json_schema_extra={
            "secret": True,
            "nd_string_constraints": {
                "min_length": 1,
                "max_length": 255,
                "pattern": r"^\S+$",
            },
        },
    )
    crypto_algorithm: (
        Literal[
            "3des",
            "aes",
            "hmac-sha-1",
            "hmac-sha-256",
            "hmac-sha-384",
            "hmac-sha-512",
            "md5",
        ]
        | None
    ) = Field(alias="cryptoAlgorithm", description="Cryptographic algorithm.", default=None)
    accept_lifetime_start: str | None = Field(
        alias="acceptLifetimeStart",
        description="Accept lifetime start time.",
        pattern=KEYCHAIN_LIFETIME_TIME_RE,
        default=None,
    )
    accept_lifetime_start_date: str | None = Field(
        alias="acceptLifetimeStartDate",
        description="Accept lifetime start date.",
        pattern=KEYCHAIN_LIFETIME_DATE_RE,
        default=None,
    )
    accept_lifetime_end_mode: Literal["duration", "infinite", "endTime"] | None = Field(
        alias="acceptLifetimeEndMode",
        description="Accept lifetime end mode.",
        default=None,
    )
    accept_lifetime_duration: int | None = Field(
        alias="acceptLifetimeDuration",
        description="Accept lifetime duration in seconds.",
        ge=1,
        le=2147483646,
        default=None,
    )
    accept_lifetime_end: str | None = Field(
        alias="acceptLifetimeEnd",
        description="Accept lifetime end time.",
        pattern=KEYCHAIN_LIFETIME_TIME_RE,
        default=None,
    )
    accept_lifetime_end_date: str | None = Field(
        alias="acceptLifetimeEndDate",
        description="Accept lifetime end date.",
        pattern=KEYCHAIN_LIFETIME_DATE_RE,
        default=None,
    )
    accept_lifetime_local: bool | None = Field(
        alias="acceptLifetimeLocal",
        description="Interpret the accept lifetime in local time.",
        default=False,
    )
    send_lifetime_start: str | None = Field(
        alias="sendLifetimeStart",
        description="Send lifetime start time.",
        pattern=KEYCHAIN_LIFETIME_TIME_RE,
        default=None,
    )
    send_lifetime_start_date: str | None = Field(
        alias="sendLifetimeStartDate",
        description="Send lifetime start date.",
        pattern=KEYCHAIN_LIFETIME_DATE_RE,
        default=None,
    )
    send_lifetime_end_mode: Literal["duration", "infinite", "endTime"] | None = Field(
        alias="sendLifetimeEndMode", description="Send lifetime end mode.", default=None
    )
    send_lifetime_duration: int | None = Field(
        alias="sendLifetimeDuration",
        description="Send lifetime duration in seconds.",
        ge=1,
        le=2147483646,
        default=None,
    )
    send_lifetime_end: str | None = Field(
        alias="sendLifetimeEnd",
        description="Send lifetime end time.",
        pattern=KEYCHAIN_LIFETIME_TIME_RE,
        default=None,
    )
    send_lifetime_end_date: str | None = Field(
        alias="sendLifetimeEndDate",
        description="Send lifetime end date.",
        pattern=KEYCHAIN_LIFETIME_DATE_RE,
        default=None,
    )
    send_lifetime_local: bool | None = Field(
        alias="sendLifetimeLocal",
        description="Interpret the send lifetime in local time.",
        default=False,
    )

    @field_validator("key_string", mode="before")
    @classmethod
    def validate_key_material(cls, value: Any) -> Any:
        """Validate plaintext constraints before Pydantic wraps the secret."""
        constraints = cls.model_fields["key_string"].json_schema_extra["nd_string_constraints"]
        return validate_secret_string_constraints(value, "key_string", constraints)

    @field_serializer("key_string")
    def serialize_key_string(self, value: SecretStr, info: FieldSerializationInfo) -> str:
        """Reveal key material only in an API payload."""
        if (info.context or {}).get("mode") == "payload":
            return value.get_secret_value()
        return "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"


class BootstrapSubnetModel(NDNestedModel):
    """
    # Summary

    Bootstrap subnet configuration for fabric initialization.

    ## Raises

    - `ValueError` - If IP addresses or subnet prefix are invalid
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow",
    )

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

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow",
    )

    email: list[dict[str, Any]] = Field(description="Email streaming configuration", default_factory=list)
    message_bus: list[dict[str, Any]] = Field(
        alias="messageBus",
        description="Message bus configuration",
        default_factory=list,
    )
    syslog: dict[str, Any] = Field(
        description="Syslog streaming configuration",
        default_factory=lambda: {
            "collectionSettings": {"anomalies": []},
            "facility": "",
            "servers": [],
        },
    )
    webhooks: list[dict[str, Any]] = Field(description="Webhook configuration", default_factory=list)


class LocationModel(NDNestedModel):
    """
    # Summary

    Geographic location coordinates for the fabric.

    ## Raises

    - `ValueError` - If latitude or longitude are outside valid ranges
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow",
    )

    latitude: float = Field(description="Latitude coordinate (-90 to 90)", ge=-90.0, le=90.0)
    longitude: float = Field(description="Longitude coordinate (-180 to 180)", ge=-180.0, le=180.0)


class NetflowExporterModel(NDNestedModel):
    """
    # Summary

    Netflow exporter configuration for telemetry.

    ## Raises

    - `ValueError` - If UDP port is outside valid range or IP address is invalid
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow",
    )

    exporter_name: str = Field(alias="exporterName", description="Name of the netflow exporter")
    exporter_ip: RequiredFabricIPv4Address = Field(alias="exporterIp", description="IP address of the netflow collector")
    vrf: str = Field(description="VRF name for the exporter", default="management")
    source_interface_name: str = Field(alias="sourceInterfaceName", description="Source interface name")
    udp_port: int | None = Field(
        alias="udpPort",
        description="UDP port for netflow export",
        ge=1,
        le=65535,
        default=None,
    )


class NetflowMonitorModel(NDNestedModel):
    """
    # Summary

    Netflow monitor configuration linking records to exporters.

    ## Raises

    None
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow",
    )

    monitor_name: str = Field(alias="monitorName", description="Name of the netflow monitor")
    record_name: str = Field(alias="recordName", description="Associated record name")
    exporter1_name: str = Field(alias="exporter1Name", description="Primary exporter name")
    exporter2_name: str = Field(alias="exporter2Name", description="Secondary exporter name", default="")


class NetflowSamplerModel(NDNestedModel):
    """NetFlow sampler configuration used by External Connectivity fabrics."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow",
    )

    sampler_name: str | None = Field(alias="samplerName", description="Name of the sampler", default=None)
    num_samples: int | None = Field(
        alias="numSamples",
        description="Samples per sampling operation (1 to 63).",
        ge=1,
        le=63,
        default=None,
    )
    sampling_rate: int | None = Field(
        alias="samplingRate",
        description="Packets per sampling operation (1 to 131071).",
        ge=1,
        le=131071,
        default=None,
    )


class NetflowRecordModel(NDNestedModel):
    """
    # Summary

    Netflow record configuration defining flow record templates.

    ## Raises

    None
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow",
    )

    record_name: str = Field(alias="recordName", description="Name of the netflow record")
    record_template: str = Field(
        alias="recordTemplate",
        description="Template type for the record",
        json_schema_extra={
            "nd_release_constraints": [
                {
                    "maximum_exclusive_version": "4.3.1",
                    "choices": ["netflowIpv4Record", "netflowLayer2Record"],
                }
            ]
        },
    )
    layer2_record: bool = Field(alias="layer2Record", description="Enable layer 2 record fields", default=False)

    _record_template_wire_values: ClassVar[dict[str, str]] = {
        "netflowIpv4Record": "netflow_ipv4_record",
        "netflowLayer2Record": "netflow_l2_record",
    }
    _record_template_public_values: ClassVar[dict[str, str]] = {
        "netflow_ipv4_record": "netflowIpv4Record",
        "netflow_l2_record": "netflowLayer2Record",
    }

    @field_serializer("record_template")
    def serialize_record_template(self, value: str, info: FieldSerializationInfo) -> str:
        """Keep public enum spellings replayable and use native template names on wire."""
        if (info.context or {}).get("mode") == "config":
            return self._record_template_public_values.get(value, value)
        return self._record_template_wire_values.get(value, value)


class NetflowSettingsModel(NDNestedModel):
    """
    # Summary

    Complete netflow configuration including exporters, records, and monitors.

    ## Raises

    - `ValueError` - If netflow lists are inconsistent with netflow enabled state
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow",
    )

    netflow: bool = Field(description="Enable netflow collection", default=False)
    netflow_exporter_collection: list[NetflowExporterModel] = Field(
        alias="netflowExporterCollection",
        description="List of netflow exporters",
        default_factory=list,
    )
    netflow_record_collection: list[NetflowRecordModel] = Field(
        alias="netflowRecordCollection",
        description="List of netflow records",
        default_factory=list,
    )
    netflow_monitor_collection: list[NetflowMonitorModel] = Field(
        alias="netflowMonitorCollection",
        description="List of netflow monitors",
        default_factory=list,
    )


class TelemetryAnalysisSettingsModel(NDNestedModel):
    """
    # Summary

    Telemetry analysis configuration.

    ## Raises

    None
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow",
    )

    is_enabled: bool = Field(alias="isEnabled", description="Enable telemetry analysis", default=False)


class TelemetryEnergyManagementModel(NDNestedModel):
    """
    # Summary

    Energy management telemetry configuration.

    ## Raises

    None
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow",
    )

    cost: float = Field(description="Energy cost per unit", default=0.1)


class TelemetryFlowCollectionModel(NDNestedModel):
    """
    # Summary

    Telemetry flow collection configuration.

    ## Raises

    None
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow",
    )

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
        default=TelemetryTrafficAnalyticsEnum.DISABLED,
    )
    traffic_analytics_scope: TelemetryTrafficAnalyticsScopeEnum = Field(
        alias="trafficAnalyticsScope",
        description="Traffic analytics scope",
        default=TelemetryTrafficAnalyticsScopeEnum.INTRA_FABRIC,
    )
    udp_categorization: TelemetryUdpCategorizationEnum = Field(
        alias="udpCategorization",
        description="UDP categorization",
        default=TelemetryUdpCategorizationEnum.DISABLED,
    )

    @model_serializer(mode="wrap")
    def serialize_required_flow_collection_modes(self, handler, info: SerializationInfo) -> Any:
        """Supply the required wire object without adding public or comparison state."""
        data = handler(self)
        if isinstance(data, dict):
            data = self._apply_payload_defaults(data, info)
            if (info.context or {}).get("mode") == "payload":
                data.setdefault("flowCollectionModes", {})
        return data

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
                    if collection_key not in {
                        "interfaceFlowRules",
                        "interface_flow_rules",
                    }:
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

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow",
    )

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

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow",
    )

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

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow",
    )

    server: str = Field(description="Configured NAS server name", default="")
    export_settings: TelemetryNasExportSettingsModel = Field(
        alias="exportSettings",
        description="NAS export settings",
        default_factory=TelemetryNasExportSettingsModel,
    )


class TelemetrySettingsModel(NDNestedModel):
    """
    # Summary

    Complete telemetry configuration for the fabric.

    ## Raises

    None
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow",
    )

    flow_collection: TelemetryFlowCollectionModel = Field(
        alias="flowCollection",
        description="Flow collection settings",
        default_factory=TelemetryFlowCollectionModel,
    )
    microburst: TelemetryMicroburstModel = Field(
        description="Microburst detection settings",
        default_factory=TelemetryMicroburstModel,
    )
    analysis_settings: TelemetryAnalysisSettingsModel = Field(
        alias="analysisSettings",
        description="Analysis settings",
        default_factory=TelemetryAnalysisSettingsModel,
    )
    nas: TelemetryNasModel | None = Field(description="NAS telemetry configuration", default=None)
    energy_management: TelemetryEnergyManagementModel = Field(
        alias="energyManagement",
        description="Energy management settings",
        default_factory=TelemetryEnergyManagementModel,
    )
