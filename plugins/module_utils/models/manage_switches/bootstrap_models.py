# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Bootstrap (POAP) switch models for import operations.

Based on OpenAPI schema for Nexus Dashboard Manage APIs v1.1.332.
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    computed_field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.enums import (
    RemoteCredentialStore,
    SnmpV3AuthProtocol,
    SwitchRole,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.validators import (
    require_hostname,
    validate_cidr_optional,
    validate_ip_address,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.validators import require_bootstrap_identity_fields, require_serial_number


class BootstrapBaseData(NDNestedModel):
    """
    Device-reported data embedded in a bootstrap API entry.
    """

    identifiers: ClassVar[list[str]] = []
    gateway_ip_mask: str | None = Field(default=None, alias="gatewayIpMask", description="Gateway IP address with mask")
    models: list[str] | None = Field(default=None, description="Supported models for switch")

    @field_validator("gateway_ip_mask", mode="before")
    @classmethod
    def validate_gateway(cls, v: str | None) -> str | None:
        return validate_cidr_optional(v)


class BootstrapBaseModel(NDBaseModel):
    """
    Common hardware properties shared across bootstrap, pre-provision, and RMA operations.
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"
    gateway_ip_mask: str | None = Field(default=None, alias="gatewayIpMask", description="Gateway IP address with mask")
    model: str | None = Field(default=None, description="Model of the bootstrap switch")
    software_version: str | None = Field(
        default=None,
        alias="softwareVersion",
        description="Software version of the bootstrap switch",
    )
    software_image: str | None = Field(
        default=None,
        alias="softwareImage",
        description="Software image file for the bootstrap switch",
    )
    switch_role: SwitchRole | None = Field(default=None, alias="switchRole")
    data: BootstrapBaseData | None = Field(default=None, description="Additional bootstrap data")

    @field_validator("gateway_ip_mask", mode="before")
    @classmethod
    def validate_gateway(cls, v: str | None) -> str | None:
        return validate_cidr_optional(v)


class BootstrapCredentialModel(NDBaseModel):
    """
    Credential properties for a switch bootstrap or pre-provision operation.

    When useNewCredentials is true, separate discovery credentials are used for
    post-bootstrap switch discovery instead of the admin password.
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"
    exclude_from_diff: ClassVar[list[str]] = ["password", "discovery_password"]
    password: str = Field(description="Switch password to be set during bootstrap for admin user")
    discovery_auth_protocol: SnmpV3AuthProtocol = Field(alias="discoveryAuthProtocol")
    use_new_credentials: bool = Field(
        default=False,
        alias="useNewCredentials",
        description="If True, use discoveryUsername and discoveryPassword",
    )
    discovery_username: str | None = Field(
        default=None,
        alias="discoveryUsername",
        description="Username to be used for switch discovery post bootstrap",
    )
    discovery_password: str | None = Field(
        default=None,
        alias="discoveryPassword",
        description="Password associated with the corresponding switch discovery user",
    )
    remote_credential_store: RemoteCredentialStore = Field(
        default=RemoteCredentialStore.LOCAL,
        alias="remoteCredentialStore",
        description="Type of credential store for discovery credentials",
    )
    remote_credential_store_key: str | None = Field(
        default=None,
        alias="remoteCredentialStoreKey",
        description="Remote credential store key for discovery credentials",
    )

    @model_validator(mode="after")
    def validate_credentials(self) -> "BootstrapCredentialModel":
        """Validate credential configuration logic."""
        if self.use_new_credentials:
            if self.remote_credential_store == RemoteCredentialStore.CYBERARK:
                if not self.remote_credential_store_key:
                    raise ValueError("remote_credential_store_key is required when remote_credential_store is 'cyberark'")
            elif self.remote_credential_store == RemoteCredentialStore.LOCAL:
                if not self.discovery_username or not self.discovery_password:
                    raise ValueError(
                        "discovery_username and discovery_password are required when remote_credential_store is 'local' and use_new_credentials is True"
                    )
        return self


class BootstrapImportSpecificModel(NDBaseModel):
    """
    Switch-identifying fields returned by the bootstrap GET API prior to import.
    """

    identifiers: ClassVar[list[str]] = ["serial_number"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"
    hostname: str = Field(description="Hostname of the bootstrap switch")
    ip: str = Field(description="IP address of the bootstrap switch")
    serial_number: str = Field(alias="serialNumber", description="Serial number of the bootstrap switch")
    in_inventory: bool = Field(
        alias="inInventory",
        description="True if the bootstrap switch is in inventory",
    )
    public_key: str = Field(alias="publicKey", description="Public Key")
    finger_print: str = Field(alias="fingerPrint", description="Fingerprint")
    dhcp_bootstrap_ip: str | None = Field(
        default=None,
        alias="dhcpBootstrapIp",
        description="This is used for device day-0 bring-up when using inband reachability",
    )
    seed_switch: bool = Field(default=False, alias="seedSwitch", description="Use as seed switch")

    @field_validator("hostname", mode="before")
    @classmethod
    def validate_host(cls, v: str) -> str:
        return require_hostname(v)

    @field_validator("ip", "dhcp_bootstrap_ip", mode="before")
    @classmethod
    def validate_ip(cls, v: str | None) -> str | None:
        return validate_ip_address(v)

    @field_validator("serial_number", mode="before")
    @classmethod
    def validate_serial(cls, v: str) -> str:
        return require_serial_number(v)

    @model_validator(mode="after")
    def validate_bootstrap_identity_fields(self) -> "BootstrapImportSpecificModel":
        """Ensure ND has reported call-home identity fields for this switch."""
        require_bootstrap_identity_fields(self.serial_number, self.public_key, self.finger_print)
        return self


class BootstrapImportSwitchModel(NDBaseModel):
    """
    Request payload for importing a single POAP bootstrap switch into the fabric.

    Path: POST /fabrics/{fabricName}/switchActions/importBootstrap
    """

    identifiers: ClassVar[list[str]] = ["serial_number"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"
    exclude_from_diff: ClassVar[list[str]] = ["password", "discovery_password"]

    serial_number: str = Field(alias="serialNumber", description="Serial number of the bootstrap switch")
    model: str | None = Field(default=None, description="Model of the bootstrap switch")
    software_version: str | None = Field(
        default=None,
        alias="softwareVersion",
        description="Software version of the bootstrap switch",
    )
    software_image: str | None = Field(
        default=None,
        alias="softwareImage",
        description="Software image file for the bootstrap switch",
    )
    hostname: str = Field(description="Hostname of the bootstrap switch")
    ip: str = Field(description="IP address of the bootstrap switch")
    password: str = Field(description="Switch password to be set during bootstrap for admin user")
    discovery_auth_protocol: SnmpV3AuthProtocol = Field(alias="discoveryAuthProtocol")
    discovery_username: str | None = Field(default=None, alias="discoveryUsername")
    discovery_password: str | None = Field(default=None, alias="discoveryPassword")
    remote_credential_store: RemoteCredentialStore = Field(
        default=RemoteCredentialStore.LOCAL,
        alias="remoteCredentialStore",
        description="Type of credential store for discovery credentials",
    )
    remote_credential_store_key: str | None = Field(
        default=None,
        alias="remoteCredentialStoreKey",
        description="Remote credential store key for discovery credentials",
    )
    data: dict[str, Any] | None = Field(
        default=None,
        description="Bootstrap configuration data block (gatewayIpMask, models)",
    )
    fingerprint: str = Field(
        default="",
        alias="fingerPrint",
        description="SSH fingerprint from bootstrap GET API",
    )
    public_key: str = Field(
        default="",
        alias="publicKey",
        description="SSH public key from bootstrap GET API",
    )
    dhcp_bootstrap_ip: str | None = Field(
        default=None,
        alias="dhcpBootstrapIp",
        description="Used for device day-0 bring-up when using inband reachability",
    )
    seed_switch: bool = Field(
        default=False,
        alias="seedSwitch",
        description="Use as seed switch",
    )
    in_inventory: bool = Field(default=False, alias="inInventory")
    switch_role: SwitchRole | None = Field(default=None, alias="switchRole")
    gateway_ip_mask: str | None = Field(default=None, alias="gatewayIpMask", description="Gateway IP address with mask")

    @field_validator("ip", "dhcp_bootstrap_ip", mode="before")
    @classmethod
    def validate_ip_field(cls, v: str | None) -> str | None:
        return validate_ip_address(v)

    @field_validator("hostname", mode="before")
    @classmethod
    def validate_host(cls, v: str) -> str:
        return require_hostname(v)

    @field_validator("serial_number", mode="before")
    @classmethod
    def validate_serial(cls, v: str) -> str:
        return require_serial_number(v)

    @model_validator(mode="after")
    def validate_bootstrap_identity_fields(self) -> "BootstrapImportSwitchModel":
        """Ensure ND has reported call-home identity fields before import."""
        require_bootstrap_identity_fields(self.serial_number, self.public_key, self.fingerprint)
        return self

    @computed_field(alias="useNewCredentials")
    @property
    def use_new_credentials(self) -> bool:
        """Derive useNewCredentials from discoveryUsername and discoveryPassword."""
        return bool(self.discovery_username and self.discovery_password)

    def to_payload(self) -> dict[str, Any]:
        """Convert to API payload format matching importBootstrap spec."""
        return self.model_dump(by_alias=True, exclude_none=True)

    @classmethod
    def from_response(cls, response: dict[str, Any]) -> "BootstrapImportSwitchModel":
        """Create model instance from API response."""
        return cls.model_validate(response)


class ImportBootstrapSwitchesRequestModel(NDBaseModel):
    """
    Request body wrapping a list of bootstrap switch payloads for bulk POAP import.

    Path: POST /fabrics/{fabricName}/switchActions/importBootstrap
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"
    switches: list[BootstrapImportSwitchModel] = Field(description="PowerOn Auto Provisioning switches")

    def to_payload(self) -> dict[str, Any]:
        """Convert to API payload format."""
        return {"switches": [s.to_payload() for s in self.switches]}
