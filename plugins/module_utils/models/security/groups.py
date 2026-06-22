# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pydantic models for security groups."""

from __future__ import annotations

import re
from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field, field_validator, model_validator
from ansible_collections.cisco.nd.plugins.module_utils.common.validators import validate_ip_or_cidr_as_cidr
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.security.base import ManageSecurityBaseModel, SecurityAciDataModel, common_module_argument_spec

SelectorType = Literal["connectedEndpoint", "externalSubnet", "network", "networkPort", "vm"]

_SECURITY_GROUP_UNSUPPORTED_CHARS = re.compile(r"[!@#$^=+{}]")


class SecurityGroupVmDataModel(NDNestedModel):
    """VM selector payload item.

    The OpenAPI schema references vmData but does not expose enough stable
    structure in the local spec helper output to safely hard-code every nested
    field yet, so accept a named VM item and preserve any extra controller keys.
    """

    name: str | None = Field(default=None, min_length=1)


class SecurityGroupSelectorModel(NDNestedModel):
    """Selector item for security group membership."""

    payload_exclude_fields: ClassVar[set[str]] = {"display_network_name", "switch_name", "vlan_id"}
    exclude_from_diff: ClassVar[set[str]] = {"display_network_name", "switch_name", "vlan_id"}

    type: SelectorType = Field(alias="type")
    vrf_name: str | None = Field(default=None, alias="vrfName", min_length=1)
    ip: str | None = Field(default=None, alias="ip", min_length=1)
    network_name: str | None = Field(default=None, alias="networkName", min_length=1)
    switch_id: str | None = Field(default=None, alias="switchId", min_length=1)
    interface_name: str | None = Field(default=None, alias="interfaceName", min_length=1)
    vm_data: list[dict] | None = Field(default=None, alias="vmData")

    display_network_name: str | None = Field(default=None, alias="displayNetworkName")
    switch_name: str | None = Field(default=None, alias="switchName")
    vlan_id: str | None = Field(default=None, alias="vlanId")

    @field_validator("ip")
    @classmethod
    def validate_selector_ip(cls, value: str | None) -> str | None:
        """Validate endpoint/subnet selector IP values."""
        return validate_ip_or_cidr_as_cidr(value)

    @model_validator(mode="after")
    def validate_type_specific_fields(self) -> "SecurityGroupSelectorModel":
        """Validate selector fields required by each selector type."""
        requirements = {
            "connectedEndpoint": ("vrf_name", "ip"),
            "externalSubnet": ("vrf_name", "ip"),
            "network": ("network_name",),
            "networkPort": ("network_name", "switch_id", "interface_name"),
            "vm": ("vm_data",),
        }
        missing = [field_name for field_name in requirements[self.type] if getattr(self, field_name, None) in (None, [], {})]
        if missing:
            raise ValueError(f"selector type {self.type!r} requires: {', '.join(missing)}")
        return self

    def _writeable_selector_data(self, **kwargs) -> dict[str, Any]:
        """Return selector fields that participate in write payloads and diffs."""
        data = self.model_dump(
            by_alias=True,
            exclude_none=True,
            exclude={"display_network_name", "switch_name", "vlan_id"},
            mode="json",
            **kwargs,
        )
        if self.type in ("network", "networkPort"):
            data.pop("vrfName", None)
        return data

    def to_payload(self, **kwargs) -> dict[str, Any]:
        """Convert selector to API payload format, excluding read-only fields."""
        return self._writeable_selector_data(**kwargs)

    def to_diff_dict(self, **kwargs) -> dict[str, Any]:
        """Convert selector to normalized diff format."""
        return self._writeable_selector_data(**kwargs)


class SecurityGroupModel(ManageSecurityBaseModel):
    """Top-level security group resource."""

    exclude_from_diff: ClassVar[set[str]] = {
        "type",
        "config_sync_status",
        "security_association_count",
        "selector_count",
        "connected_endpoint_selector_count",
        "external_subnet_selector_count",
        "network_selector_count",
        "network_port_selector_count",
        "vm_selector_count",
        "network_names",
    }
    payload_exclude_fields: ClassVar[set[str]] = exclude_from_diff

    id: int | None = Field(default=None, alias="id")
    attach: bool | None = Field(default=None, alias="attach")
    vrf_names: list[str] | None = Field(default=None, alias="vrfNames")
    selectors: list[SecurityGroupSelectorModel] | None = Field(default=None, alias="selectors")
    aci_data: SecurityAciDataModel | None = Field(default=None, alias="aciData")

    type: str | None = Field(default=None, alias="type")
    config_sync_status: str | None = Field(default=None, alias="configSyncStatus")
    security_association_count: int | None = Field(default=None, alias="securityAssociationCount")
    selector_count: int | None = Field(default=None, alias="selectorCount")
    connected_endpoint_selector_count: int | None = Field(default=None, alias="connectedEndpointSelectorCount")
    external_subnet_selector_count: int | None = Field(default=None, alias="externalSubnetSelectorCount")
    network_selector_count: int | None = Field(default=None, alias="networkSelectorCount")
    network_port_selector_count: int | None = Field(default=None, alias="networkPortSelectorCount")
    vm_selector_count: int | None = Field(default=None, alias="vmSelectorCount")
    network_names: list[str] | None = Field(default=None, alias="networkNames")

    @field_validator("name")
    @classmethod
    def validate_security_group_name(cls, value: str) -> str:
        """Reject characters the product documentation marks unsupported."""
        if _SECURITY_GROUP_UNSUPPORTED_CHARS.search(value):
            raise ValueError("security group name cannot contain any of these characters: ! @ # $ ^ = + { }")
        return value

    @classmethod
    def required_payload_fields(cls) -> tuple[str, ...]:
        """Return required create/update fields from the OpenAPI write schema."""
        return ("id", "vrf_names")

    def to_payload(self, **kwargs) -> dict[str, Any]:
        """Convert security group to API payload format with normalized selectors."""
        data = super().to_payload(**kwargs)
        if self.selectors is not None and "selectors" in data:
            data["selectors"] = [selector.to_payload() for selector in self.selectors]
        return data

    def to_diff_dict(self, **kwargs) -> dict[str, Any]:
        """Export security group for diff comparison with normalized selectors."""
        data = super().to_diff_dict(**kwargs)
        if self.selectors is not None and "selectors" in data:
            data["selectors"] = [selector.to_diff_dict() for selector in self.selectors]
        return data

    @classmethod
    def get_argument_spec(cls) -> dict:
        """Return Ansible argument spec for nd_manage_security_groups."""
        selector_options = dict(
            type=dict(type="str", required=True, choices=["connectedEndpoint", "externalSubnet", "network", "networkPort", "vm"]),
            vrf_name=dict(type="str"),
            ip=dict(type="str"),
            network_name=dict(type="str"),
            switch_id=dict(type="str"),
            interface_name=dict(type="str"),
            vm_data=dict(type="list", elements="dict"),
        )
        config_options = dict(
            name=dict(type="str", required=True),
            tenant_name=dict(type="str"),
            id=dict(type="int"),
            display_name=dict(type="str"),
            description=dict(type="str"),
            attach=dict(type="bool"),
            vrf_names=dict(type="list", elements="str"),
            selectors=dict(type="list", elements="dict", options=selector_options),
            aci_data=dict(
                type="dict",
                options=dict(
                    application_profile_name=dict(type="str"),
                ),
            ),
        )
        return common_module_argument_spec(config_options)
