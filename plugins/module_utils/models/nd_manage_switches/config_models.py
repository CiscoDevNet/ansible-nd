# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat Chengam Saravanan (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible playbook configuration models.

These models represent the user-facing configuration schema used in Ansible
playbooks for normal switch addition, POAP, and RMA operations.

"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import socket
from ipaddress import ip_address
from pydantic import Field, ValidationInfo, computed_field, field_validator, model_validator
from typing import Any, Dict, List, Optional, ClassVar, Literal, Union
from typing_extensions import Self

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel

from ansible_collections.cisco.nd.plugins.module_utils.models.nd_manage_switches.enums import (
    PlatformType,
    SnmpV3AuthProtocol,
    SwitchRole,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nd_manage_switches.validators import SwitchValidators


class ConfigDataModel(NDNestedModel):
    """
    Hardware and gateway network data required for POAP and RMA operations.

    Maps to config.poap.config_data and config.rma.config_data in the playbook.
    """
    identifiers: ClassVar[List[str]] = []

    models: List[str] = Field(
        ...,
        alias="models",
        min_length=1,
        description="List of model of modules in switch to Bootstrap/Pre-provision/RMA"
    )
    gateway: str = Field(
        ...,
        description="Gateway IP with mask for the switch (e.g., 192.168.0.1/24)"
    )

    @field_validator('models', mode='before')
    @classmethod
    def validate_models_list(cls, v: Any) -> List[str]:
        """Validate models is a non-empty list of strings."""
        if v is None:
            raise ValueError(
                "'models' is required in config_data. "
                "Provide a list of module model strings, "
                "e.g. models: [N9K-X9364v, N9K-vSUP]"
            )
        if not isinstance(v, list):
            raise ValueError(
                f"'models' must be a list of module model strings, got: {type(v).__name__}. "
                f"e.g. models: [N9K-X9364v, N9K-vSUP]"
            )
        if len(v) == 0:
            raise ValueError(
                "'models' list cannot be empty. "
                "Provide at least one module model string, "
                "e.g. models: [N9K-X9364v, N9K-vSUP]"
            )
        return v

    @field_validator('gateway', mode='before')
    @classmethod
    def validate_gateway(cls, v: str) -> str:
        """Validate gateway is a valid CIDR."""
        if not v or not v.strip():
            raise ValueError("gateway cannot be empty")
        return SwitchValidators.validate_cidr(v)


class POAPConfigModel(NDNestedModel):
    """
    POAP configuration entry for a single switch in the playbook config list.

    Supports Bootstrap (serial_number only), Pre-provision (preprovision_serial only),
    and Swap (both serial fields) operation modes.
    """
    identifiers: ClassVar[List[str]] = []

    # Discovery credentials
    discovery_username: Optional[str] = Field(
        default=None,
        alias="discoveryUsername",
        description="Username for device discovery during POAP"
    )
    discovery_password: Optional[str] = Field(
        default=None,
        alias="discoveryPassword",
        description="Password for device discovery during POAP"
    )

    # Bootstrap operation - requires actual switch serial number
    serial_number: Optional[str] = Field(
        default=None,
        alias="serialNumber",
        min_length=1,
        description="Serial number of switch to Bootstrap"
    )

    # Pre-provision operation - requires pre-provision serial number
    preprovision_serial: Optional[str] = Field(
        default=None,
        alias="preprovisionSerial",
        min_length=1,
        description="Serial number of switch to Pre-provision"
    )

    # Common fields for both operations
    model: Optional[str] = Field(
        default=None,
        description="Model of switch to Bootstrap/Pre-provision"
    )
    version: Optional[str] = Field(
        default=None,
        description="Software version of switch to Bootstrap/Pre-provision"
    )
    hostname: Optional[str] = Field(
        default=None,
        description="Hostname of switch to Bootstrap/Pre-provision"
    )
    image_policy: Optional[str] = Field(
        default=None,
        alias="imagePolicy",
        description="Name of the image policy to be applied on switch"
    )
    config_data: Optional[ConfigDataModel] = Field(
        default=None,
        alias="configData",
        description=(
            "Basic config data of switch to Bootstrap/Pre-provision. "
            "'models' (list of module models) and 'gateway' (IP with mask) are mandatory."
        ),
    )

    @model_validator(mode='after')
    def validate_operation_type(self) -> Self:
        """Validate serial_number / preprovision_serial combinations.

        Allowed combinations:
        - serial_number only → Bootstrap
        - preprovision_serial only → Pre-provision
        - both serial_number AND preprovision_serial → Swap (change serial
          number of an existing pre-provisioned switch)
        - neither → error
        """
        has_serial = bool(self.serial_number)
        has_preprov = bool(self.preprovision_serial)

        if not has_serial and not has_preprov:
            raise ValueError(
                "Either 'serial_number' (for Bootstrap / Swap) or 'preprovision_serial' "
                "(for Pre-provision / Swap) must be provided."
            )

        return self

    @model_validator(mode='after')
    def validate_required_fields_for_non_swap(self) -> Self:
        """Validate model/version/hostname/config_data for pre-provision operations.

        Pre-provision (preprovision_serial only):
          model, version, hostname, config_data are all mandatory because the
          controller has no physical switch to pull these values from.

        Bootstrap (serial_number only):
          These fields are optional — they can be omitted and the module will
          pull them from the bootstrap GET API response at runtime.  If
          provided, they are validated against the bootstrap data before import.

        Swap (both serials present):
          No check needed — the swap API only requires the new serial number.
        """
        has_serial = bool(self.serial_number)
        has_preprov = bool(self.preprovision_serial)

        # Pre-provision only: all four descriptor fields are mandatory
        if has_preprov and not has_serial:
            missing = []
            if not self.model:
                missing.append("model")
            if not self.version:
                missing.append("version")
            if not self.hostname:
                missing.append("hostname")
            if not self.config_data:
                missing.append("config_data")
            if missing:
                raise ValueError(
                    f"model, version, hostname and config_data are required for "
                    f"Pre-provisioning a switch. Missing: {', '.join(missing)}"
                )
        return self

    @model_validator(mode='after')
    def validate_discovery_credentials_pair(self) -> Self:
        """Validate that discovery_username and discovery_password are both set or both absent.

        Mirrors the dcnm_inventory.py bidirectional check:
          - discovery_username set → discovery_password required
          - discovery_password set → discovery_username required
        """
        has_user = bool(self.discovery_username)
        has_pass = bool(self.discovery_password)
        if has_user and not has_pass:
            raise ValueError(
                "discovery_password must be set when discovery_username is specified"
            )
        if has_pass and not has_user:
            raise ValueError(
                "discovery_username must be set when discovery_password is specified"
            )
        return self

    @field_validator('serial_number', 'preprovision_serial', mode='before')
    @classmethod
    def validate_serial_numbers(cls, v: Optional[str]) -> Optional[str]:
        """Validate serial numbers are not empty strings."""
        return SwitchValidators.validate_serial_number(v)


class RMAConfigModel(NDNestedModel):
    """
    RMA configuration entry for replacing a single switch via bootstrap.

    The switch being replaced must be in maintenance mode and either shut down
    or disconnected from the network before initiating the RMA operation.
    """
    identifiers: ClassVar[List[str]] = []

    # Discovery credentials
    discovery_username: Optional[str] = Field(
        default=None,
        alias="discoveryUsername",
        description="Username for device discovery during POAP and RMA discovery"
    )
    discovery_password: Optional[str] = Field(
        default=None,
        alias="discoveryPassword",
        description="Password for device discovery during POAP and RMA discovery"
    )

    # Required fields for RMA
    serial_number: str = Field(
        ...,
        alias="serialNumber",
        min_length=1,
        description="Serial number of switch to Bootstrap for RMA"
    )
    old_serial: str = Field(
        ...,
        alias="oldSerial",
        min_length=1,
        description="Serial number of switch to be replaced by RMA"
    )
    model: Optional[str] = Field(
        default=None,
        min_length=1,
        description="Model of switch to Bootstrap for RMA. If omitted, sourced from bootstrap API."
    )
    version: Optional[str] = Field(
        default=None,
        min_length=1,
        description="Software version of switch to Bootstrap for RMA. If omitted, sourced from bootstrap API."
    )

    # Optional fields
    image_policy: Optional[str] = Field(
        default=None,
        alias="imagePolicy",
        description="Name of the image policy to be applied on switch during Bootstrap for RMA"
    )

    # Optional config data for RMA (models list + gateway); sourced from bootstrap API if omitted
    config_data: Optional[ConfigDataModel] = Field(
        default=None,
        alias="configData",
        description=(
            "Basic config data of switch to Bootstrap for RMA. "
            "'models' (list of module models) and 'gateway' (IP with mask) are mandatory "
            "when provided. If omitted, sourced from bootstrap API."
        ),
    )

    @field_validator('serial_number', 'old_serial', mode='before')
    @classmethod
    def validate_serial_numbers(cls, v: str) -> str:
        """Validate serial numbers are not empty."""
        result = SwitchValidators.validate_serial_number(v)
        if result is None:
            raise ValueError("Serial number cannot be empty")
        return result

    @model_validator(mode='after')
    def validate_discovery_credentials_pair(self) -> Self:
        """Validate that discovery_username and discovery_password are both set or both absent.

        Mirrors the dcnm_inventory.py bidirectional check:
          - discovery_username set → discovery_password required
          - discovery_password set → discovery_username required
        """
        has_user = bool(self.discovery_username)
        has_pass = bool(self.discovery_password)
        if has_user and not has_pass:
            raise ValueError(
                "discovery_password must be set when discovery_username is specified"
            )
        if has_pass and not has_user:
            raise ValueError(
                "discovery_username must be set when discovery_password is specified"
            )
        return self


class SwitchConfigModel(NDBaseModel):
    """
    Per-switch configuration entry in the Ansible playbook config list.

    Supports normal switch addition, POAP (Bootstrap and Pre-provision), and RMA
    operations. The operation type is derived from the presence of poap or rma fields.
    """
    identifiers: ClassVar[List[str]] = ["seed_ip"]

    # Fields excluded from diff — only seed_ip + role are compared
    exclude_from_diff: ClassVar[List[str]] = [
        "user_name", "password", "auth_proto", "max_hops",
        "preserve_config", "platform_type", "poap", "rma",
        "operation_type",
        "switch_id", "serial_number", "mode", "hostname",
        "model", "software_version",
    ]

    # Required fields
    seed_ip: str = Field(
        ...,
        alias="seedIp",
        min_length=1,
        description="Seed IP address or DNS name of the switch"
    )

    # Optional fields — required for merged/overridden, optional for query/deleted
    user_name: Optional[str] = Field(
        default=None,
        alias="userName",
        description="Login username to the switch (required for merged/overridden states)"
    )
    password: Optional[str] = Field(
        default=None,
        description="Login password to the switch (required for merged/overridden states)"
    )

    # Optional fields with defaults
    auth_proto: SnmpV3AuthProtocol = Field(
        default=SnmpV3AuthProtocol.MD5,
        alias="authProto",
        description="Authentication protocol to use"
    )
    max_hops: int = Field(
        default=0,
        alias="maxHops",
        ge=0,
        le=7,
        description="Maximum hops to reach the switch (deprecated, defaults to 0)"
    )
    role: Optional[SwitchRole] = Field(
        default=None,
        description="Role to assign to the switch. None means not specified (uses controller default)."
    )
    preserve_config: bool = Field(
        default=False,
        alias="preserveConfig",
        description="Set to false for greenfield, true for brownfield deployment"
    )
    platform_type: PlatformType = Field(
        default=PlatformType.NX_OS,
        alias="platformType",
        description="Platform type of the switch (nx-os, ios-xe, etc.)"
    )

    # POAP and RMA configurations
    poap: Optional[List[POAPConfigModel]] = Field(
        default=None,
        description="POAP (PowerOn Auto Provisioning) configurations for Bootstrap/Pre-provision"
    )
    rma: Optional[List[RMAConfigModel]] = Field(
        default=None,
        description="RMA (Return Material Authorization) configurations for switch replacement"
    )

    # Computed fields

    @computed_field
    @property
    def operation_type(self) -> Literal["normal", "poap", "rma"]:
        """Determine the operation type from this config.

        Returns:
            ``'poap'`` if POAP configs are present,
            ``'rma'`` if RMA configs are present,
            ``'normal'`` otherwise.
        """
        if self.poap:
            return "poap"
        if self.rma:
            return "rma"
        return "normal"

    # API-derived fields (populated by from_response, never set by users)
    switch_id: Optional[str] = Field(
        default=None,
        alias="switchId",
        description="Serial number / switch ID from inventory API"
    )
    serial_number: Optional[str] = Field(
        default=None,
        alias="serialNumber",
        description="Serial number from inventory API"
    )
    mode: Optional[str] = Field(
        default=None,
        description="Switch mode from inventory API (Normal, Migration, etc.)"
    )
    hostname: Optional[str] = Field(
        default=None,
        description="Switch hostname from inventory API"
    )
    model: Optional[str] = Field(
        default=None,
        description="Switch model from inventory API"
    )
    software_version: Optional[str] = Field(
        default=None,
        alias="softwareVersion",
        description="Software version from inventory API"
    )

    def to_config_dict(self) -> Dict[str, Any]:
        """Return the playbook config as a dict with all credentials stripped.

        Returns:
            Dict of config fields with ``user_name``, ``password``,
            ``discovery_username``, and ``discovery_password`` excluded.
        """
        return self.to_config(exclude={
            "user_name": True,
            "password": True,
            "poap": {"__all__": {"discovery_username": True, "discovery_password": True}},
            "rma": {"__all__": {"discovery_username": True, "discovery_password": True}},
        })

    @model_validator(mode='before')
    @classmethod
    def reject_auth_proto_for_poap_rma(cls, data: Any) -> Any:
        """Reject non-MD5 auth_proto when POAP or RMA is configured.

        POAP, Pre-provision, and RMA operations always use MD5 internally.
        If the user explicitly supplies a non-MD5 ``auth_proto`` (or
        ``authProto``) alongside ``poap`` or ``rma``, raise an error so
        they know the field is not user-configurable for these operation
        types.

        Note: Ansible argspec injects the default ``"MD5"`` even when the
        user omits ``auth_proto``, so we must allow MD5 through.
        """
        if not isinstance(data, dict):
            return data

        has_poap = bool(data.get("poap"))
        has_rma = bool(data.get("rma"))

        if has_poap or has_rma:
            # Check both snake_case (Ansible playbook) and camelCase (API) keys
            auth_val = data.get("auth_proto") or data.get("authProto")
            if auth_val is not None:
                # Normalize to lowercase for comparison
                normalized = str(auth_val).strip().lower()
                if normalized not in ("md5", ""):
                    op = "POAP" if has_poap else "RMA"
                    raise ValueError(
                        f"'auth_proto' must not be specified for {op} operations. "
                        f"The authentication protocol is always MD5 and is set "
                        f"automatically. Received: '{auth_val}'"
                    )

        return data

    @model_validator(mode='after')
    def validate_poap_rma_mutual_exclusion(self) -> Self:
        """Validate that POAP and RMA are mutually exclusive."""
        if self.poap and self.rma:
            raise ValueError("Cannot specify both 'poap' and 'rma' configurations for the same switch")

        return self

    @model_validator(mode='after')
    def validate_poap_rma_credentials(self) -> Self:
        """Validate credentials for POAP and RMA operations."""
        if self.poap or self.rma:
            # POAP/RMA require credentials
            if not self.user_name or not self.password:
                raise ValueError(
                    "For POAP and RMA operations, user_name and password are required"
                )
            # For POAP and RMA, username should be 'admin'
            if self.user_name != "admin":
                raise ValueError("For POAP and RMA operations, user_name should be 'admin'")

        return self

    @model_validator(mode='after')
    def apply_state_defaults(self, info: ValidationInfo) -> Self:
        """Apply state-aware defaults and enforcement using validation context.

        When ``context={"state": "merged"}`` (or ``"overridden"``) is passed
        to ``model_validate()``, the model:
        - Defaults ``role`` to ``SwitchRole.LEAF`` when not specified.
        - Enforces that ``user_name`` and ``password`` are provided.

        For ``query`` / ``deleted`` (or no context), fields remain as-is.
        """
        state = (info.context or {}).get("state") if info else None

        # POAP only allowed with merged or query
        if self.poap and state not in (None, "merged", "query"):
            raise ValueError(
                f"POAP operations require 'merged' or 'query' state, "
                f"got '{state}' (switch: {self.seed_ip})"
            )

        # RMA only allowed with merged
        if self.rma and state not in (None, "merged"):
            raise ValueError(
                f"RMA operations require 'merged' state, "
                f"got '{state}' (switch: {self.seed_ip})"
            )

        if state in ("merged", "overridden"):
            if self.role is None:
                self.role = SwitchRole.LEAF
            if not self.user_name or not self.password:
                raise ValueError(
                    f"user_name and password are required "
                    f"for '{state}' state "
                    f"(switch: {self.seed_ip})"
                )
        return self

    @field_validator('seed_ip', mode='before')
    @classmethod
    def validate_seed_ip(cls, v: str) -> str:
        """Resolve seed_ip to an IP address.

        Accepts IPv4, IPv6, or a DNS name / hostname.  When the input
        is not a valid IP address a DNS lookup is performed and the
        resolved IPv4 address is returned so that downstream code
        always works with a clean IP.
        """
        if not v or not v.strip():
            raise ValueError("seed_ip cannot be empty")

        v = v.strip()

        # Fast path: already a valid IP address
        try:
            ip_address(v)
            return v
        except ValueError:
            pass

        # Not an IP — attempt DNS resolution (IPv4 first, then IPv6)
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                addr_info = socket.getaddrinfo(v, None, family)
                if addr_info:
                    return addr_info[0][4][0]
            except socket.gaierror:
                continue

        raise ValueError(
            f"'{v}' is not a valid IP address and could not be resolved via DNS"
        )

    @field_validator('poap', 'rma', mode='before')
    @classmethod
    def validate_lists_not_empty(cls, v: Optional[List]) -> Optional[List]:
        """Validate that if POAP or RMA lists are provided, they are not empty."""
        if v is not None and len(v) == 0:
            raise ValueError("POAP/RMA list cannot be empty if provided")
        return v

    @field_validator('auth_proto', mode='before')
    @classmethod
    def normalize_auth_proto(cls, v: Union[str, SnmpV3AuthProtocol, None]) -> SnmpV3AuthProtocol:
        """Normalize auth_proto to handle case-insensitive input (MD5, md5, etc.)."""
        return SnmpV3AuthProtocol.normalize(v)

    @field_validator('role', mode='before')
    @classmethod
    def normalize_role(cls, v: Union[str, SwitchRole, None]) -> Optional[SwitchRole]:
        """Normalize role for case-insensitive and underscore-to-camelCase matching.
        Returns None when not specified (distinguishes from explicit 'leaf')."""
        if v is None:
            return None
        return SwitchRole.normalize(v)

    @field_validator('platform_type', mode='before')
    @classmethod
    def normalize_platform_type(cls, v: Union[str, PlatformType, None]) -> PlatformType:
        """Normalize platform_type for case-insensitive matching (NX_OS, nx-os, etc.)."""
        return PlatformType.normalize(v)

    @classmethod
    def validate_no_mixed_operations(
        cls, configs: List["SwitchConfigModel"]
    ) -> None:
        """Validate that a list of configs does not mix operation types.

        POAP, RMA, and normal switch operations cannot be combined
        in the same Ansible task.  Call this after validating all
        individual configs.

        Args:
            configs: List of validated SwitchConfigModel instances.

        Raises:
            ValueError: If more than one operation type is present.
        """
        op_types = {cfg.operation_type for cfg in configs}
        if len(op_types) > 1:
            raise ValueError(
                "Mixed operation types detected: "
                f"{', '.join(sorted(op_types))}. "
                "POAP, RMA, and normal switch operations "
                "cannot be mixed in the same task. "
                "Please separate them into different tasks."
            )

    def to_payload(self) -> Dict[str, Any]:
        """Convert to API payload format.

        Excludes API-derived fields that are not part of the user config.
        """
        return self.model_dump(
            by_alias=True,
            exclude_none=True,
            exclude={
                "switch_id", "serial_number", "mode",
                "hostname", "model", "software_version",
            },
        )

    @classmethod
    def from_response(cls, response: Dict[str, Any]) -> Self:
        """Create model instance from inventory or discovery API response.

        Handles two formats:
        1. Inventory API: {switchId, fabricManagementIp, switchRole, ...}
        2. Discovery API: {serialNumber, ip, hostname, ...}
        """
        mapped: Dict[str, Any] = {}

        # seed_ip from fabricManagementIp (inventory) or ip (discovery)
        ip = response.get("fabricManagementIp") or response.get("ip")
        if ip:
            mapped["seedIp"] = ip

        # role from switchRole
        role = response.get("switchRole")
        if role:
            mapped["role"] = role

        # Direct API fields
        direct_fields = (
            "switchId", "serialNumber", "softwareVersion",
            "mode", "hostname", "model",
        )
        for key in direct_fields:
            if key in response and response[key] is not None:
                mapped[key] = response[key]

        return cls.model_validate(mapped)


__all__ = [
    "ConfigDataModel",
    "POAPConfigModel",
    "RMAConfigModel",
    "SwitchConfigModel",
]
