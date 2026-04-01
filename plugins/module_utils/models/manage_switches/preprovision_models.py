# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pre-provision switch models.

Based on OpenAPI schema for Nexus Dashboard Manage APIs v1.1.332.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import Any, Dict, List, Optional, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    computed_field,
    field_validator,
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


class PreProvisionSwitchModel(NDBaseModel):
    """
    Request payload for pre-provisioning a single switch in the fabric.

    Path: POST /fabrics/{fabricName}/switchActions/preProvision
    """

    identifiers: ClassVar[List[str]] = ["serial_number"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"
    exclude_from_diff: ClassVar[List[str]] = ["password", "discovery_password"]

    # --- preProvisionSpecific fields (required) ---
    serial_number: str = Field(
        ...,
        alias="serialNumber",
        description="Serial number of the switch to pre-provision",
    )
    hostname: str = Field(
        ...,
        description="Hostname of the switch to pre-provision",
    )
    ip: str = Field(
        ...,
        description="IP address of the switch to pre-provision",
    )

    # --- preProvisionSpecific fields (optional) ---
    dhcp_bootstrap_ip: Optional[str] = Field(
        default=None,
        alias="dhcpBootstrapIp",
        description="Used for device day-0 bring-up when using inband reachability",
    )
    seed_switch: bool = Field(
        default=False,
        alias="seedSwitch",
        description="Use as seed switch",
    )

    # --- bootstrapBase fields (required) ---
    model: str = Field(
        ...,
        description="Model of the switch to pre-provision",
    )
    software_version: str = Field(
        ...,
        alias="softwareVersion",
        description="Software version of the switch to pre-provision",
    )
    gateway_ip_mask: str = Field(
        ...,
        alias="gatewayIpMask",
        description="Gateway IP address with mask (e.g., 10.23.244.1/24)",
    )

    # --- bootstrapBase fields (optional) ---
    image_policy: Optional[str] = Field(
        default=None,
        alias="imagePolicy",
        description="Image policy associated with the switch during pre-provision",
    )
    switch_role: Optional[SwitchRole] = Field(
        default=None,
        alias="switchRole",
        description="Role to assign to the switch",
    )
    data: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Pre-provision configuration data block (gatewayIpMask, models)",
    )

    # --- bootstrapCredential fields (required) ---
    password: str = Field(
        ...,
        description="Switch password to be set during pre-provision for admin user",
    )
    discovery_auth_protocol: SnmpV3AuthProtocol = Field(
        ...,
        alias="discoveryAuthProtocol",
        description="SNMP authentication protocol for discovery",
    )

    # --- bootstrapCredential fields (optional) ---
    discovery_username: Optional[str] = Field(
        default=None,
        alias="discoveryUsername",
        description="Username for switch discovery post pre-provision",
    )
    discovery_password: Optional[str] = Field(
        default=None,
        alias="discoveryPassword",
        description="Password for switch discovery post pre-provision",
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

    # --- Validators ---

    @field_validator("ip", "dhcp_bootstrap_ip", mode="before")
    @classmethod
    def validate_ip(cls, v: Optional[str]) -> Optional[str]:
        return SwitchValidators.validate_ip_address(v)

    @field_validator("hostname", mode="before")
    @classmethod
    def validate_host(cls, v: str) -> str:
        return SwitchValidators.require_hostname(v)

    @field_validator("serial_number", mode="before")
    @classmethod
    def validate_serial(cls, v: str) -> str:
        return SwitchValidators.require_serial_number(v)

    @field_validator("gateway_ip_mask", mode="before")
    @classmethod
    def validate_gateway(cls, v: str) -> str:
        result = SwitchValidators.validate_cidr(v)
        if result is None:
            raise ValueError("gatewayIpMask must include subnet mask (e.g., 10.23.244.1/24)")
        return result

    @computed_field(alias="useNewCredentials")
    @property
    def use_new_credentials(self) -> bool:
        """Derive useNewCredentials from discoveryUsername and discoveryPassword."""
        return bool(self.discovery_username and self.discovery_password)

    def to_payload(self) -> Dict[str, Any]:
        """Convert to API payload format matching preProvision spec."""
        return self.model_dump(by_alias=True, exclude_none=True)

    @classmethod
    def from_response(cls, response: Dict[str, Any]) -> "PreProvisionSwitchModel":
        """Create model instance from API response."""
        return cls.model_validate(response)


class PreProvisionSwitchesRequestModel(NDBaseModel):
    """
    Request body wrapping a list of pre-provision payloads for bulk switch pre-provisioning.

    Path: POST /fabrics/{fabricName}/switchActions/preProvision
    """

    identifiers: ClassVar[List[str]] = []
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "singleton"
    switches: List[PreProvisionSwitchModel] = Field(
        ...,
        description="PowerOn Auto Provisioning switches",
    )

    def to_payload(self) -> Dict[str, Any]:
        """Convert to API payload format."""
        return {"switches": [s.to_payload() for s in self.switches]}


__all__ = [
    "PreProvisionSwitchModel",
    "PreProvisionSwitchesRequestModel",
]
