# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Switch action models (serial number change, IDs list, credentials).

Based on OpenAPI schema for Nexus Dashboard Manage APIs v1.1.332.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import List, Literal, Optional, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.validators import (
    SwitchValidators,
)


class SwitchCredentialsRequestModel(NDBaseModel):
    """
    Request body to save LAN credentials for one or more fabric switches.

    Supports local credentials or remote credential store (such as CyberArk).
    Path: POST /api/v1/manage/credentials/switches
    """

    identifiers: ClassVar[List[str]] = []
    identifier_strategy: ClassVar[
        Optional[Literal["single", "composite", "hierarchical", "singleton"]]
    ] = "singleton"

    switch_ids: List[str] = Field(
        ...,
        alias="switchIds",
        min_length=1,
        description="List of switch serial numbers",
    )
    switch_username: Optional[str] = Field(
        default=None, alias="switchUsername", description="Switch username"
    )
    switch_password: Optional[str] = Field(
        default=None, alias="switchPassword", description="Switch password"
    )
    remote_credential_store_key: Optional[str] = Field(
        default=None,
        alias="remoteCredentialStoreKey",
        description="Remote credential store key (e.g. CyberArk path)",
    )
    remote_credential_store_type: Optional[str] = Field(
        default=None,
        alias="remoteCredentialStoreType",
        description="Remote credential store type (e.g. 'cyberark')",
    )

    @field_validator("switch_ids", mode="before")
    @classmethod
    def validate_switch_ids(cls, v: List[str]) -> List[str]:
        """Validate all switch IDs."""
        if not v:
            raise ValueError("At least one switch ID is required")
        validated = []
        for serial in v:
            result = SwitchValidators.validate_serial_number(serial)
            if result:
                validated.append(result)
        if not validated:
            raise ValueError("No valid switch IDs provided")
        return validated

    @model_validator(mode="after")
    def validate_credentials(self) -> "SwitchCredentialsRequestModel":
        """Ensure either local or remote credentials are provided."""
        has_local = (
            self.switch_username is not None and self.switch_password is not None
        )
        has_remote = (
            self.remote_credential_store_key is not None
            and self.remote_credential_store_type is not None
        )
        if not has_local and not has_remote:
            raise ValueError(
                "Either local credentials (switchUsername + switchPassword) "
                "or remote credentials (remoteCredentialStoreKey + remoteCredentialStoreType) must be provided"
            )
        return self


class ChangeSwitchSerialNumberRequestModel(NDBaseModel):
    """
    Request body to update the serial number of an existing fabric switch.

    Path: POST /fabrics/{fabricName}/switches/{switchId}/actions/changeSwitchSerialNumber
    """

    identifiers: ClassVar[List[str]] = ["new_switch_id"]
    identifier_strategy: ClassVar[
        Optional[Literal["single", "composite", "hierarchical", "singleton"]]
    ] = "single"
    new_switch_id: str = Field(..., alias="newSwitchId", description="New switchId")

    @field_validator("new_switch_id", mode="before")
    @classmethod
    def validate_serial(cls, v: str) -> str:
        result = SwitchValidators.validate_serial_number(v)
        if result is None:
            raise ValueError("new_switch_id cannot be empty")
        return result


__all__ = [
    "SwitchCredentialsRequestModel",
    "ChangeSwitchSerialNumberRequestModel",
]
