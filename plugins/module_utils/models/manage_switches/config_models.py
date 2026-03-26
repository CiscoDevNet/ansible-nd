# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

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

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.enums import (
    PlatformType,
    SnmpV3AuthProtocol,
    SwitchRole,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.validators import SwitchValidators


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
    """Bootstrap POAP config for a single switch.

    Used when ``poap`` is specified alone (bootstrap-only operation).
    ``serial_number`` and ``hostname`` are mandatory; all other fields are optional.
    Model, version, and config data are sourced from the bootstrap API at runtime.
    If the bootstrap API reports a different hostname or role, the API value overrides
    the user-provided value and a warning is logged.
    """
    identifiers: ClassVar[List[str]] = []

    # Mandatory
    serial_number: str = Field(
        ...,
        alias="serialNumber",
        min_length=1,
        description="Serial number of the physical switch to Bootstrap"
    )
    hostname: str = Field(
        ...,
        description="Hostname for the switch during bootstrap"
    )

    # Optional
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
    image_policy: Optional[str] = Field(
        default=None,
        alias="imagePolicy",
        description="Name of the image policy to be applied on switch"
    )

    @model_validator(mode='after')
    def validate_discovery_credentials_pair(self) -> Self:
        """Validate that discovery_username and discovery_password are both set or both absent."""
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

    @field_validator('serial_number', mode='before')
    @classmethod
    def validate_serial_number_field(cls, v: str) -> str:
        """Validate serial_number is not empty."""
        result = SwitchValidators.validate_serial_number(v)
        if result is None:
            raise ValueError("serial_number cannot be empty")
        return result


class PreprovisionConfigModel(NDNestedModel):
    """Pre-provision config for a single switch.

    Used when ``preprovision`` is specified alone.
    All five fields — ``serial_number``, ``model``, ``version``, ``hostname``,
    and ``config_data`` — are mandatory because the controller has no physical
    switch to pull these values from.
    """
    identifiers: ClassVar[List[str]] = []

    # Mandatory
    serial_number: str = Field(
        ...,
        alias="serialNumber",
        min_length=1,
        description="Serial number of switch to Pre-provision"
    )
    model: str = Field(
        ...,
        min_length=1,
        description="Model of switch to Pre-provision"
    )
    version: str = Field(
        ...,
        min_length=1,
        description="Software version of switch to Pre-provision"
    )
    hostname: str = Field(
        ...,
        description="Hostname for the switch during pre-provision"
    )
    config_data: ConfigDataModel = Field(
        ...,
        alias="configData",
        description=(
            "Basic config data of switch to Pre-provision. "
            "'models' (list of module models) and 'gateway' (IP with mask) are mandatory."
        ),
    )

    # Optional
    discovery_username: Optional[str] = Field(
        default=None,
        alias="discoveryUsername",
        description="Username for device discovery during pre-provision"
    )
    discovery_password: Optional[str] = Field(
        default=None,
        alias="discoveryPassword",
        description="Password for device discovery during pre-provision"
    )
    image_policy: Optional[str] = Field(
        default=None,
        alias="imagePolicy",
        description="Image policy to apply during pre-provision"
    )

    @model_validator(mode='after')
    def validate_discovery_credentials_pair(self) -> Self:
        """Validate that discovery_username and discovery_password are both set or both absent."""
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

    @field_validator('serial_number', mode='before')
    @classmethod
    def validate_serial_number_field(cls, v: str) -> str:
        """Validate serial_number is not empty."""
        result = SwitchValidators.validate_serial_number(v)
        if result is None:
            raise ValueError("serial_number cannot be empty")
        return result


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
    new_serial_number: str = Field(
        ...,
        alias="newSerialNumber",
        min_length=1,
        description="Serial number of the new/replacement switch to Bootstrap for RMA"
    )
    old_serial_number: str = Field(
        ...,
        alias="oldSerialNumber",
        min_length=1,
        description="Serial number of the existing switch to be replaced by RMA"
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

    @field_validator('new_serial_number', 'old_serial_number', mode='before')
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

    Supports normal switch addition, POAP (Bootstrap), Pre-provision, Swap
    (both poap+preprovision), and RMA operations. The operation type is derived
    from the presence of poap, preprovision, and/or rma fields.
    """
    identifiers: ClassVar[List[str]] = ["seed_ip"]

    # Fields excluded from diff — only seed_ip + role are compared
    exclude_from_diff: ClassVar[List[str]] = [
        "username", "password", "auth_proto",
        "preserve_config", "platform_type", "poap", "preprovision", "rma",
        "operation_type",
    ]

    # Required fields
    seed_ip: str = Field(
        ...,
        alias="seedIp",
        min_length=1,
        description="Seed IP address or DNS name of the switch"
    )

    # Optional fields — required for merged/overridden, optional for query/deleted
    username: Optional[str] = Field(
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

    # POAP, Pre-provision and RMA configurations
    poap: Optional[POAPConfigModel] = Field(
        default=None,
        description="Bootstrap POAP config (serial_number + hostname mandatory)"
    )
    preprovision: Optional[PreprovisionConfigModel] = Field(
        default=None,
        description="Pre-provision config (serial_number, model, version, hostname, config_data all mandatory)"
    )
    rma: Optional[List[RMAConfigModel]] = Field(
        default=None,
        description="RMA (Return Material Authorization) configurations for switch replacement"
    )

    # Computed fields

    @computed_field
    @property
    def operation_type(self) -> Literal["normal", "poap", "preprovision", "swap", "rma"]:
        """Determine the operation type from this config.

        Returns:
            ``'swap'`` if both poap and preprovision are present,
            ``'poap'`` if only bootstrap poap is present,
            ``'preprovision'`` if only preprovision is present,
            ``'rma'`` if RMA configs are present,
            ``'normal'`` otherwise.
        """
        if self.poap and self.preprovision:
            return "swap"
        if self.poap:
            return "poap"
        if self.preprovision:
            return "preprovision"
        if self.rma:
            return "rma"
        return "normal"

    def to_config_dict(self) -> Dict[str, Any]:
        """Return the playbook config as a dict with all credentials stripped.

        Returns:
            Dict of config fields with ``username``, ``password``,
            ``discovery_username``, and ``discovery_password`` excluded.
        """
        return self.to_config(exclude={
            "username": True,
            "password": True,
            "poap": {"discovery_username": True, "discovery_password": True},
            "preprovision": {"discovery_username": True, "discovery_password": True},
            "rma": {"__all__": {"discovery_username": True, "discovery_password": True}},
        })

    @model_validator(mode='after')
    def reject_auth_proto_for_special_ops(self) -> Self:
        """Reject non-MD5 auth_proto when POAP, Pre-provision, Swap or RMA is configured.

        These operations always use MD5 internally. By validating mode='after',
        all inputs have already been coerced by Pydantic into a typed
        SnmpV3AuthProtocol value, so a direct enum comparison is safe.
        """
        if (self.poap or self.preprovision or self.rma) and self.auth_proto != SnmpV3AuthProtocol.MD5:
            if self.poap or self.preprovision:
                op = "POAP/Pre-provision"
            else:
                op = "RMA"
            raise ValueError(
                f"'auth_proto' must not be specified for {op} operations. "
                f"The authentication protocol is always MD5 and is set "
                f"automatically. Received: '{self.auth_proto.value}'"
            )
        return self

    @model_validator(mode='after')
    def validate_special_ops_exclusion(self) -> Self:
        """Validate mutually exclusive operation combinations.

        Allowed:
          - poap only (Bootstrap)
          - preprovision only (Pre-provision)
          - poap + preprovision (Swap)
          - rma (RMA)
        Not allowed:
          - rma combined with poap or preprovision
        """
        if self.rma and (self.poap or self.preprovision):
            raise ValueError(
                "Cannot specify 'rma' together with 'poap' or 'preprovision' "
                "for the same switch"
            )
        return self

    @model_validator(mode='after')
    def validate_special_ops_credentials(self) -> Self:
        """Validate credentials for POAP, Pre-provision, Swap and RMA operations."""
        if self.poap or self.preprovision or self.rma:
            if not self.username or not self.password:
                raise ValueError(
                    "For POAP, Pre-provision, and RMA operations, username and password are required"
                )
            if self.username != "admin":
                raise ValueError(
                    "For POAP, Pre-provision, and RMA operations, username should be 'admin'"
                )
        return self

    @model_validator(mode='after')
    def apply_state_defaults(self, info: ValidationInfo) -> Self:
        """Apply state-aware defaults and enforcement using validation context.

        When ``context={"state": "merged"}`` (or ``"overridden"``) is passed
        to ``model_validate()``, the model:
        - Defaults ``role`` to ``SwitchRole.LEAF`` when not specified.
        - Enforces that ``username`` and ``password`` are provided.

        For ``query`` / ``deleted`` (or no context), fields remain as-is.
        """
        state = (info.context or {}).get("state") if info else None

        # POAP/Pre-provision/Swap only allowed with merged
        if (self.poap or self.preprovision) and state not in (None, "merged"):
            raise ValueError(
                f"POAP/Pre-provision operations require 'merged' state, "
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
            if not self.username or not self.password:
                raise ValueError(
                    f"username and password are required "
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

    @field_validator('rma', mode='before')
    @classmethod
    def validate_rma_list_not_empty(cls, v: Optional[List]) -> Optional[List]:
        """Validate that if RMA list is provided, it is not empty."""
        if v is not None and len(v) == 0:
            raise ValueError("RMA list cannot be empty if provided")
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

    def to_payload(self) -> Dict[str, Any]:
        """Convert to API payload format."""
        return self.model_dump(
            by_alias=True,
            exclude_none=True,
        )

    @classmethod
    def from_switch_data(cls, sw: Any) -> "SwitchConfigModel":
        """Build a config-shaped entry from a live inventory record.

        Only the fields recoverable from the ND inventory API are populated.
        Credentials (username, password) are intentionally omitted.

        Args:
            sw: A SwitchDataModel instance from the fabric inventory.

        Returns:
            SwitchConfigModel instance with seed_ip, role, and platform_type
            populated from live data.

        Raises:
            ValueError: If the inventory record is missing a management IP,
                making it impossible to construct a valid config entry.
        """
        if not sw.fabric_management_ip:
            raise ValueError(
                f"Switch {sw.switch_id!r} has no fabric_management_ip — "
                "cannot build a gathered config entry without a seed IP."
            )

        platform_type = (
            sw.additional_data.platform_type
            if sw.additional_data and hasattr(sw.additional_data, "platform_type")
            else None
        )

        data: Dict[str, Any] = {"seed_ip": sw.fabric_management_ip}
        if sw.switch_role is not None:
            data["role"] = sw.switch_role
        if platform_type is not None:
            data["platform_type"] = platform_type

        return cls.model_validate(data)

    def to_gathered_dict(self) -> Dict[str, Any]:
        """Return a config dict suitable for gathered output.

        platform_type is excluded (internal detail not needed by the user).
        username and password are replaced with placeholders so the returned
        data is immediately usable as ``config:`` input after substituting
        real credentials.

        Returns:
            Dict with seed_ip, role, auth_proto, preserve_config,
            username set to ``"<username>"``, password set to ``"<password>"``.
        """
        result = self.to_config(exclude={
                    "platform_type": True,
                    "poap": True,
                    "preprovision": True,
                    "rma": True,
                    "operation_type": True,
                })
        result["username"] = "<username>"
        result["password"] = "<password>"
        return result

    @classmethod
    def get_argument_spec(cls) -> Dict[str, Any]:
        """Return the Ansible argument spec for nd_manage_switches."""
        return dict(
            fabric=dict(type="str", required=True),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "overridden", "deleted", "gathered"],
            ),
            save=dict(type="bool", default=True),
            deploy=dict(type="bool", default=True),
            config=dict(type="list", elements="dict"),
        )


__all__ = [
    "ConfigDataModel",
    "POAPConfigModel",
    "PreprovisionConfigModel",
    "RMAConfigModel",
    "SwitchConfigModel",
]
