# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pydantic models for security groups."""

from __future__ import annotations

import json
from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field, ValidationInfo, field_validator, model_validator
from ansible_collections.cisco.nd.plugins.module_utils.common.validators import validate_ip_or_cidr_as_cidr
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.security.base import ManageSecurityBaseModel, SecurityAciDataModel, common_module_argument_spec

SelectorType = Literal["connectedEndpoint", "externalSubnet", "network", "networkPort", "vm"]


class SecurityGroupVmDataModel(NDNestedModel):
    """vCenter VM NIC selector data shared by ND 4.2 and ND 4.3."""

    payload_exclude_fields: ClassVar[set[str]] = {
        "nic_name",
        "vm_name",
        "esxi_host",
        "vrf_name",
        "network_name",
        "switch_name",
        "switch_interface_name",
        "vlan_id",
        "ip_collection",
    }
    exclude_from_diff: ClassVar[set[str]] = payload_exclude_fields

    vm_data_type: Literal["vCenter"] = Field(default="vCenter", alias="vmDataType")
    v_center: str = Field(alias="vCenter", min_length=1)
    vm_uuid: str = Field(alias="vmUuid", min_length=1)
    nic_mac: str = Field(alias="nicMac", min_length=1)

    nic_name: str | None = Field(default=None, alias="nicName")
    vm_name: str | None = Field(default=None, alias="vmName")
    esxi_host: str | None = Field(default=None, alias="esxiHost")
    vrf_name: str | None = Field(default=None, alias="vrfName", max_length=94)
    network_name: str | None = Field(default=None, alias="networkName", max_length=128)
    switch_name: str | None = Field(default=None, alias="switchName")
    switch_interface_name: str | None = Field(default=None, alias="switchInterfaceName")
    vlan_id: str | None = Field(default=None, alias="vlanId")
    ip_collection: list[str] | None = Field(default=None, alias="ipCollection")


class SecurityGroupSelectorModel(NDNestedModel):
    """Selector item for security group membership."""

    payload_exclude_fields: ClassVar[set[str]] = {"display_network_name", "switch_name", "vlan_id"}
    exclude_from_diff: ClassVar[set[str]] = {"display_network_name", "switch_name", "vlan_id"}

    type: SelectorType = Field(alias="type")
    vrf_name: str | None = Field(default=None, alias="vrfName", min_length=1, max_length=94)
    ip: str | None = Field(default=None, alias="ip", min_length=1)
    network_name: str | None = Field(default=None, alias="networkName", min_length=1, max_length=128)
    switch_id: str | None = Field(default=None, alias="switchId", min_length=1)
    interface_name: str | None = Field(default=None, alias="interfaceName", min_length=1)
    vm_data: list[SecurityGroupVmDataModel] | None = Field(default=None, alias="vmData")

    display_network_name: str | None = Field(default=None, alias="displayNetworkName")
    switch_name: str | None = Field(default=None, alias="switchName")
    vlan_id: str | None = Field(default=None, alias="vlanId")

    @field_validator("ip")
    @classmethod
    def validate_selector_ip(cls, value: str | None) -> str | None:
        """Validate endpoint/subnet selector IP values."""
        return validate_ip_or_cidr_as_cidr(value)

    @field_validator("vm_data")
    @classmethod
    def validate_unique_vm_data(cls, value: list[SecurityGroupVmDataModel] | None) -> list[SecurityGroupVmDataModel] | None:
        """Reject duplicate VM NIC selector entries."""
        if value is None:
            return value
        seen: set[str] = set()
        for vm_data in value:
            canonical = json.dumps(vm_data.to_payload(), sort_keys=True)
            if canonical in seen:
                raise ValueError("vm_data entries must be unique")
            seen.add(canonical)
        return value

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
        if self.vm_data is not None and "vmData" in data:
            data["vmData"] = [vm_item.to_payload() for vm_item in self.vm_data]
        return data

    def to_payload(self, **kwargs) -> dict[str, Any]:
        """Convert selector to API payload format, excluding read-only fields."""
        return self._writeable_selector_data(**kwargs)

    def to_diff_dict(self, **kwargs) -> dict[str, Any]:
        """Convert selector to normalized diff format."""
        data = self._writeable_selector_data(**kwargs)
        if self.vm_data is not None and "vmData" in data:
            data["vmData"] = [vm_item.to_diff_dict() for vm_item in self.vm_data]
        return data


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

    name_max_length_42: ClassVar[int] = 115
    name_max_length_43: ClassVar[int] = 125
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {"attach": True}

    id: int | None = Field(default=None, alias="id", ge=0, le=65535)
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

    @model_validator(mode="before")
    @classmethod
    def normalize_controller_owned_vrf_names(cls, data: Any, info: ValidationInfo) -> Any:
        """Normalize the live controller's empty VRF sentinel on default groups."""
        if (info.context or {}).get("mode") != "response" or not isinstance(data, dict):
            return data
        group_id = data.get("id")
        group_type = data.get("type")
        controller_owned = (isinstance(group_id, int) and not isinstance(group_id, bool) and 0 <= group_id <= 15) or (
            isinstance(group_type, str) and group_type.casefold() in {"default", "defaultgroup"}
        )
        vrf_names = data.get("vrfNames", data.get("vrf_names"))
        if not controller_owned or vrf_names != [""]:
            return data
        normalized = dict(data)
        normalized.pop("vrfNames", None)
        normalized.pop("vrf_names", None)
        return normalized

    @property
    def is_controller_owned(self) -> bool:
        """Return whether ND owns this default/reserved security group."""
        return (self.id is not None and 0 <= self.id <= 15) or (isinstance(self.type, str) and self.type.casefold() in {"default", "defaultgroup"})

    @property
    def is_unsupported_policy(self) -> bool:
        """Use the shared state-machine read-only hook for controller-owned groups."""
        return self.is_controller_owned

    @property
    def exclude_from_gathered(self) -> bool:
        """Omit controller-owned groups that cannot be replayed as user config."""
        return self.is_controller_owned

    def describe_unsupported_policy(self) -> str:
        """Describe why a controller-owned group is protected from mutation."""
        return f"Controller-owned security group '{self.api_name}' (ID {self.id})"

    @field_validator("id")
    @classmethod
    def validate_user_security_group_id(cls, value: int | None, info: ValidationInfo) -> int | None:
        """Reserve IDs 0-15 for controller objects while accepting them on reads."""
        mode = (info.context or {}).get("mode")
        if mode == "config" and value is not None and value < 16:
            raise ValueError("security group id values 0 through 15 are reserved for controller-owned groups")
        return value

    @field_validator("vrf_names")
    @classmethod
    def validate_vrf_names(cls, value: list[str] | None) -> list[str] | None:
        """Validate each VRF name against the shared 94-character API limit."""
        if value is None:
            return value
        seen: set[str] = set()
        for vrf_name in value:
            if not vrf_name:
                raise ValueError("vrf_names entries must not be empty")
            if len(vrf_name) > 94:
                raise ValueError("vrf_names entries must be at most 94 characters")
            if vrf_name in seen:
                raise ValueError("vrf_names entries must be unique")
            seen.add(vrf_name)
        return value

    @field_validator("selectors")
    @classmethod
    def validate_unique_selectors(cls, value: list[SecurityGroupSelectorModel] | None) -> list[SecurityGroupSelectorModel] | None:
        """Enforce the OpenAPI uniqueItems contract for selectors."""
        if value is None:
            return value
        seen: set[str] = set()
        for selector in value:
            canonical = json.dumps(selector.to_payload(), sort_keys=True)
            if canonical in seen:
                raise ValueError("selectors entries must be unique")
            seen.add(canonical)
        return value

    def validate_required_payload_fields(self, require_id: bool = True) -> None:
        """Validate group fields, optionally allowing ND 4.3 create-time ID allocation."""
        required_fields = ["vrf_names"]
        if require_id:
            required_fields.insert(0, "id")
        missing = [field_name for field_name in required_fields if getattr(self, field_name, None) in (None, [], {})]
        if missing:
            raise ValueError(f"{self.name}: missing required field(s) for create/update: {', '.join(missing)}")

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
            vm_data=dict(
                type="list",
                elements="dict",
                options=dict(
                    vm_data_type=dict(type="str", default="vCenter", choices=["vCenter"], aliases=["vmDataType"]),
                    v_center=dict(type="str", required=True, aliases=["vCenter"]),
                    vm_uuid=dict(type="str", required=True, aliases=["vmUuid"]),
                    nic_mac=dict(type="str", required=True, aliases=["nicMac"]),
                ),
            ),
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
