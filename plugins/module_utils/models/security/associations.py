# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pydantic models for security associations."""

from __future__ import annotations

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field, model_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.security.base import ManageSecurityBaseModel, common_module_argument_spec


class SecurityAssociationModel(ManageSecurityBaseModel):
    """Top-level security association resource."""

    exclude_from_diff: ClassVar[set[str]] = {"config_sync_status"}
    payload_exclude_fields: ClassVar[set[str]] = {"config_sync_status"}

    contract_name: str | None = Field(default=None, alias="contractName", min_length=1)
    src_security_group_name: str | None = Field(default=None, alias="srcSecurityGroupName", min_length=1)
    src_vrf_name: str | None = Field(default=None, alias="srcVrfName", min_length=1)
    dst_security_group_name: str | None = Field(default=None, alias="dstSecurityGroupName", min_length=1)
    dst_vrf_name: str | None = Field(default=None, alias="dstVrfName", min_length=1)
    attach: bool | None = Field(default=None, alias="attach")
    config_sync_status: str | None = Field(default=None, alias="configSyncStatus")

    @model_validator(mode="after")
    def validate_same_vrf_when_known(self) -> "SecurityAssociationModel":
        """Inter-VRF security associations are not supported by the product."""
        if self.src_vrf_name and self.dst_vrf_name and self.src_vrf_name != self.dst_vrf_name:
            raise ValueError("src_vrf_name and dst_vrf_name must match; inter-VRF security associations are not supported")
        return self

    @classmethod
    def required_payload_fields(cls) -> tuple[str, ...]:
        """Return required create/update fields from the OpenAPI write schema."""
        return ("contract_name", "src_security_group_name", "dst_security_group_name")

    @classmethod
    def get_argument_spec(cls) -> dict:
        """Return Ansible argument spec for nd_manage_security_associations."""
        config_options = dict(
            name=dict(type="str", required=True),
            tenant_name=dict(type="str"),
            display_name=dict(type="str"),
            description=dict(type="str"),
            contract_name=dict(type="str"),
            src_security_group_name=dict(type="str"),
            src_vrf_name=dict(type="str"),
            dst_security_group_name=dict(type="str"),
            dst_vrf_name=dict(type="str"),
            attach=dict(type="bool"),
        )
        return common_module_argument_spec(config_options)

