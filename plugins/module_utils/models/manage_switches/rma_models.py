# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""RMA (Return Material Authorization) switch models.

Based on OpenAPI schema for Nexus Dashboard Manage APIs v1.1.332.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import Any, Dict, List, Optional, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    computed_field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.enums import (
    RemoteCredentialStore,
    SnmpV3AuthProtocol,
    SwitchRole,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.validators import (
    SwitchValidators,
)


class RMASwitchModel(NDBaseModel):
    """
    Request payload for provisioning a replacement (RMA) switch via bootstrap.

    Path: POST /fabrics/{fabricName}/switches/{switchId}/actions/provisionRMA
    """

    identifiers: ClassVar[List[str]] = ["new_switch_id"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"
    exclude_from_diff: ClassVar[List[str]] = ["password", "discovery_password"]
    # From bootstrapBase (all sourced from bootstrap API, not user config)
    gateway_ip_mask: Optional[str] = Field(default=None, alias="gatewayIpMask", description="Gateway IP address with mask")
    model: Optional[str] = Field(default=None, description="Model of the bootstrap switch")
    software_version: Optional[str] = Field(
        default=None,
        alias="softwareVersion",
        description="Software version of the bootstrap switch",
    )
    image_policy: Optional[str] = Field(
        default=None,
        alias="imagePolicy",
        description="Image policy associated with the switch during bootstrap",
    )
    switch_role: Optional[SwitchRole] = Field(default=None, alias="switchRole")

    # From bootstrapCredential
    password: str = Field(description="Switch password to be set during bootstrap for admin user")
    discovery_auth_protocol: SnmpV3AuthProtocol = Field(alias="discoveryAuthProtocol")
    discovery_username: Optional[str] = Field(default=None, alias="discoveryUsername")
    discovery_password: Optional[str] = Field(default=None, alias="discoveryPassword")
    remote_credential_store: RemoteCredentialStore = Field(default=RemoteCredentialStore.LOCAL, alias="remoteCredentialStore")
    remote_credential_store_key: Optional[str] = Field(default=None, alias="remoteCredentialStoreKey")

    # From RMASpecific
    hostname: str = Field(description="Hostname of the switch")
    ip: str = Field(description="IP address of the switch")
    new_switch_id: str = Field(alias="newSwitchId", description="SwitchId (serial number) of the replacement switch")
    old_switch_id: str = Field(alias="oldSwitchId", description="SwitchId (serial number) of the switch being replaced")
    public_key: str = Field(alias="publicKey", description="Public Key")
    finger_print: str = Field(alias="fingerPrint", description="Fingerprint")
    dhcp_bootstrap_ip: Optional[str] = Field(default=None, alias="dhcpBootstrapIp")
    seed_switch: bool = Field(default=False, alias="seedSwitch")
    data: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Bootstrap configuration data block (gatewayIpMask, models)",
    )

    @field_validator("gateway_ip_mask", mode="before")
    @classmethod
    def validate_gateway(cls, v: Optional[str]) -> Optional[str]:
        return SwitchValidators.validate_cidr_optional(v)

    @field_validator("hostname", mode="before")
    @classmethod
    def validate_host(cls, v: str) -> str:
        return SwitchValidators.require_hostname(v)

    @field_validator("ip", "dhcp_bootstrap_ip", mode="before")
    @classmethod
    def validate_ip(cls, v: Optional[str]) -> Optional[str]:
        return SwitchValidators.validate_ip_address(v)

    @field_validator("new_switch_id", mode="before")
    @classmethod
    def validate_serial(cls, v: str) -> str:
        return SwitchValidators.require_serial_number(v, "new_switch_id")

    @field_validator("old_switch_id", mode="before")
    @classmethod
    def validate_old_serial(cls, v: str) -> str:
        return SwitchValidators.require_serial_number(v, "old_switch_id")

    @computed_field(alias="useNewCredentials")
    @property
    def use_new_credentials(self) -> bool:
        """Derive useNewCredentials from discoveryUsername and discoveryPassword."""
        return bool(self.discovery_username and self.discovery_password)

    @model_validator(mode="after")
    def validate_rma_credentials(self) -> "RMASwitchModel":
        """Validate RMA credential configuration logic."""
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

    def to_payload(self) -> Dict[str, Any]:
        """Convert to API payload format."""
        return self.model_dump(by_alias=True, exclude_none=True)

    @classmethod
    def from_response(cls, response: Dict[str, Any]) -> "RMASwitchModel":
        """Create model instance from API response."""
        return cls.model_validate(response)


__all__ = [
    "RMASwitchModel",
]
