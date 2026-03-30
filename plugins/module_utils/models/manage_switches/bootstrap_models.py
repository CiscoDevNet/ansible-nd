# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Bootstrap (POAP) switch models for import operations.

Based on OpenAPI schema for Nexus Dashboard Manage APIs v1.1.332.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import Any, Dict, List, Optional, ClassVar, Literal
from typing_extensions import Self

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
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.validators import (
    SwitchValidators,
)


class BootstrapBaseData(NDNestedModel):
    """
    Device-reported data embedded in a bootstrap API entry.
    """

    identifiers: ClassVar[List[str]] = []
    gateway_ip_mask: Optional[str] = Field(
        default=None, alias="gatewayIpMask", description="Gateway IP address with mask"
    )
    models: Optional[List[str]] = Field(
        default=None, description="Supported models for switch"
    )

    @field_validator("gateway_ip_mask", mode="before")
    @classmethod
    def validate_gateway(cls, v: Optional[str]) -> Optional[str]:
        return SwitchValidators.validate_cidr(v)


class BootstrapBaseModel(NDBaseModel):
    """
    Common hardware and policy properties shared across bootstrap, pre-provision, and RMA operations.
    """

    identifiers: ClassVar[List[str]] = []
    identifier_strategy: ClassVar[
        Optional[Literal["single", "composite", "hierarchical", "singleton"]]
    ] = "singleton"
    gateway_ip_mask: str = Field(
        ..., alias="gatewayIpMask", description="Gateway IP address with mask"
    )
    model: str = Field(..., description="Model of the bootstrap switch")
    software_version: str = Field(
        ...,
        alias="softwareVersion",
        description="Software version of the bootstrap switch",
    )
    image_policy: Optional[str] = Field(
        default=None,
        alias="imagePolicy",
        description="Image policy associated with the switch during bootstrap",
    )
    switch_role: Optional[SwitchRole] = Field(default=None, alias="switchRole")
    data: Optional[BootstrapBaseData] = Field(
        default=None, description="Additional bootstrap data"
    )

    @field_validator("gateway_ip_mask", mode="before")
    @classmethod
    def validate_gateway(cls, v: str) -> str:
        result = SwitchValidators.validate_cidr(v)
        if result is None:
            raise ValueError("gateway_ip_mask cannot be empty")
        return result


class BootstrapCredentialModel(NDBaseModel):
    """
    Credential properties for a switch bootstrap or pre-provision operation.

    When useNewCredentials is true, separate discovery credentials are used for
    post-bootstrap switch discovery instead of the admin password.
    """

    identifiers: ClassVar[List[str]] = []
    identifier_strategy: ClassVar[
        Optional[Literal["single", "composite", "hierarchical", "singleton"]]
    ] = "singleton"
    exclude_from_diff: ClassVar[List[str]] = ["password", "discovery_password"]
    password: str = Field(
        ..., description="Switch password to be set during bootstrap for admin user"
    )
    discovery_auth_protocol: SnmpV3AuthProtocol = Field(
        ..., alias="discoveryAuthProtocol"
    )
    use_new_credentials: bool = Field(
        default=False,
        alias="useNewCredentials",
        description="If True, use discoveryUsername and discoveryPassword",
    )
    discovery_username: Optional[str] = Field(
        default=None,
        alias="discoveryUsername",
        description="Username to be used for switch discovery post bootstrap",
    )
    discovery_password: Optional[str] = Field(
        default=None,
        alias="discoveryPassword",
        description="Password associated with the corresponding switch discovery user",
    )
    remote_credential_store: RemoteCredentialStore = Field(
        default=RemoteCredentialStore.LOCAL,
        alias="remoteCredentialStore",
        description="Type of credential store for discovery credentials",
    )
    remote_credential_store_key: Optional[str] = Field(
        default=None,
        alias="remoteCredentialStoreKey",
        description="Remote credential store key for discovery credentials",
    )

    @model_validator(mode="after")
    def validate_credentials(self) -> Self:
        """Validate credential configuration logic."""
        if self.use_new_credentials:
            if self.remote_credential_store == RemoteCredentialStore.CYBERARK:
                if not self.remote_credential_store_key:
                    raise ValueError(
                        "remote_credential_store_key is required when "
                        "remote_credential_store is 'cyberark'"
                    )
            elif self.remote_credential_store == RemoteCredentialStore.LOCAL:
                if not self.discovery_username or not self.discovery_password:
                    raise ValueError(
                        "discovery_username and discovery_password are required when "
                        "remote_credential_store is 'local' and use_new_credentials is True"
                    )
        return self


class BootstrapImportSpecificModel(NDBaseModel):
    """
    Switch-identifying fields returned by the bootstrap GET API prior to import.
    """

    identifiers: ClassVar[List[str]] = []
    identifier_strategy: ClassVar[
        Optional[Literal["single", "composite", "hierarchical", "singleton"]]
    ] = "singleton"
    hostname: str = Field(..., description="Hostname of the bootstrap switch")
    ip: str = Field(..., description="IP address of the bootstrap switch")
    serial_number: str = Field(
        ..., alias="serialNumber", description="Serial number of the bootstrap switch"
    )
    in_inventory: bool = Field(
        ...,
        alias="inInventory",
        description="True if the bootstrap switch is in inventory",
    )
    public_key: str = Field(..., alias="publicKey", description="Public Key")
    finger_print: str = Field(..., alias="fingerPrint", description="Fingerprint")
    dhcp_bootstrap_ip: Optional[str] = Field(
        default=None,
        alias="dhcpBootstrapIp",
        description="This is used for device day-0 bring-up when using inband reachability",
    )
    seed_switch: bool = Field(
        default=False, alias="seedSwitch", description="Use as seed switch"
    )

    @field_validator("hostname", mode="before")
    @classmethod
    def validate_host(cls, v: str) -> str:
        result = SwitchValidators.validate_hostname(v)
        if result is None:
            raise ValueError("hostname cannot be empty")
        return result

    @field_validator("ip", "dhcp_bootstrap_ip", mode="before")
    @classmethod
    def validate_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return SwitchValidators.validate_ip_address(v)

    @field_validator("serial_number", mode="before")
    @classmethod
    def validate_serial(cls, v: str) -> str:
        result = SwitchValidators.validate_serial_number(v)
        if result is None:
            raise ValueError("serial_number cannot be empty")
        return result


class BootstrapImportSwitchModel(NDBaseModel):
    """
    Request payload for importing a single POAP bootstrap switch into the fabric.

    Path: POST /fabrics/{fabricName}/switchActions/importBootstrap
    """

    identifiers: ClassVar[List[str]] = ["serial_number"]
    identifier_strategy: ClassVar[
        Optional[Literal["single", "composite", "hierarchical", "singleton"]]
    ] = "single"
    exclude_from_diff: ClassVar[List[str]] = ["password", "discovery_password"]

    serial_number: str = Field(
        ..., alias="serialNumber", description="Serial number of the bootstrap switch"
    )
    model: str = Field(..., description="Model of the bootstrap switch")
    software_version: str = Field(
        ...,
        alias="softwareVersion",
        description="Software version of the bootstrap switch",
    )
    hostname: str = Field(..., description="Hostname of the bootstrap switch")
    ip: str = Field(..., description="IP address of the bootstrap switch")
    password: str = Field(
        ..., description="Switch password to be set during bootstrap for admin user"
    )
    discovery_auth_protocol: SnmpV3AuthProtocol = Field(
        ..., alias="discoveryAuthProtocol"
    )
    discovery_username: Optional[str] = Field(default=None, alias="discoveryUsername")
    discovery_password: Optional[str] = Field(default=None, alias="discoveryPassword")
    remote_credential_store: RemoteCredentialStore = Field(
        default=RemoteCredentialStore.LOCAL,
        alias="remoteCredentialStore",
        description="Type of credential store for discovery credentials",
    )
    remote_credential_store_key: Optional[str] = Field(
        default=None,
        alias="remoteCredentialStoreKey",
        description="Remote credential store key for discovery credentials",
    )
    data: Optional[Dict[str, Any]] = Field(
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
    re_add: bool = Field(
        default=False,
        alias="reAdd",
        description="Whether to re-add an already-seen switch",
    )
    in_inventory: bool = Field(default=False, alias="inInventory")
    image_policy: Optional[str] = Field(
        default=None,
        alias="imagePolicy",
        description="Image policy associated with the switch during bootstrap",
    )
    switch_role: Optional[SwitchRole] = Field(default=None, alias="switchRole")
    gateway_ip_mask: str = Field(
        ..., alias="gatewayIpMask", description="Gateway IP address with mask"
    )

    @field_validator("ip", mode="before")
    @classmethod
    def validate_ip_field(cls, v: str) -> str:
        result = SwitchValidators.validate_ip_address(v)
        if result is None:
            raise ValueError(f"Invalid IP address: {v}")
        return result

    @field_validator("hostname", mode="before")
    @classmethod
    def validate_host(cls, v: str) -> str:
        result = SwitchValidators.validate_hostname(v)
        if result is None:
            raise ValueError("hostname cannot be empty")
        return result

    @field_validator("serial_number", mode="before")
    @classmethod
    def validate_serial(cls, v: str) -> str:
        result = SwitchValidators.validate_serial_number(v)
        if result is None:
            raise ValueError("serial_number cannot be empty")
        return result

    @computed_field(alias="useNewCredentials")
    @property
    def use_new_credentials(self) -> bool:
        """Derive useNewCredentials from discoveryUsername and discoveryPassword."""
        return bool(self.discovery_username and self.discovery_password)

    def to_payload(self) -> Dict[str, Any]:
        """Convert to API payload format matching importBootstrap spec."""
        return self.model_dump(by_alias=True, exclude_none=True)

    @classmethod
    def from_response(cls, response: Dict[str, Any]) -> Self:
        """Create model instance from API response."""
        return cls.model_validate(response)


class ImportBootstrapSwitchesRequestModel(NDBaseModel):
    """
    Request body wrapping a list of bootstrap switch payloads for bulk POAP import.

    Path: POST /fabrics/{fabricName}/switchActions/importBootstrap
    """

    identifiers: ClassVar[List[str]] = []
    identifier_strategy: ClassVar[
        Optional[Literal["single", "composite", "hierarchical", "singleton"]]
    ] = "singleton"
    switches: List[BootstrapImportSwitchModel] = Field(
        ..., description="PowerOn Auto Provisioning switches"
    )

    def to_payload(self) -> Dict[str, Any]:
        """Convert to API payload format."""
        return {"switches": [s.to_payload() for s in self.switches]}


__all__ = [
    "BootstrapBaseData",
    "BootstrapBaseModel",
    "BootstrapCredentialModel",
    "BootstrapImportSpecificModel",
    "BootstrapImportSwitchModel",
    "ImportBootstrapSwitchesRequestModel",
]
