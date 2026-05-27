# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from copy import deepcopy
from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel


class VrfLiteConnectionModel(NDNestedModel):
    """VRF Lite extension connection details for a single interface."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        validate_by_alias=True,
        validate_by_name=True,
        extra="ignore",
    )

    interface: str = Field(alias="interface", min_length=1, max_length=128)
    dot1q: int | None = Field(default=None, alias="dot1q", ge=1, le=4094)
    ipv4_addr: str | None = Field(default=None, alias="ipv4_addr")
    neighbor_ipv4: str | None = Field(default=None, alias="neighbor_ipv4")
    ipv6_addr: str | None = Field(default=None, alias="ipv6_addr")
    neighbor_ipv6: str | None = Field(default=None, alias="neighbor_ipv6")
    peer_vrf: str | None = Field(default=None, alias="peer_vrf")


class VrfLiteAttachmentModel(NDNestedModel):
    """Attachment data for one switch under a VRF."""

    exclude_from_diff: ClassVar[set[str]] = {"deploy"}

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        validate_by_alias=True,
        validate_by_name=True,
        extra="ignore",
    )

    ip_address: str = Field(alias="ip_address", min_length=1, max_length=128)
    deploy: bool | None = Field(default=None, alias="deploy")
    import_evpn_rt: str | None = Field(default=None, alias="import_evpn_rt")
    export_evpn_rt: str | None = Field(default=None, alias="export_evpn_rt")
    vrf_lite: list[VrfLiteConnectionModel] | None = Field(default=None, alias="vrf_lite")

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address_not_empty(cls, value: str) -> str:
        if value is None or not str(value).strip():
            raise ValueError("ip_address must be a non-empty string")
        return str(value).strip()

    def merge(self, other: "VrfLiteAttachmentModel") -> "VrfLiteAttachmentModel":
        """
        Merge another attachment model into this one.

        Custom behavior:
        - scalar fields follow NDBaseModel merge semantics (explicit fields only)
        - `vrf_lite` list is merged by interface so merged mode preserves
          existing interfaces not mentioned in the playbook input
        """
        if not isinstance(other, type(self)):
            raise TypeError("VrfLiteAttachmentModel.merge requires both models to be the same type")

        merged_data = self.model_dump(by_alias=False, exclude_none=False)
        incoming_data = other.model_dump(
            by_alias=False,
            exclude_none=False,
            exclude_unset=True,
        )

        for field, value in incoming_data.items():
            if field == "vrf_lite":
                continue
            if value is None:
                continue
            merged_data[field] = value

        if "vrf_lite" in incoming_data and incoming_data.get("vrf_lite") is not None:
            current_vrf_lite = self.vrf_lite or []
            incoming_vrf_lite = other.vrf_lite or []

            merged_vrf_lite = {}
            for item in current_vrf_lite:
                key = str(item.interface).strip().lower()
                merged_vrf_lite[key] = deepcopy(item)

            for item in incoming_vrf_lite:
                key = str(item.interface).strip().lower()
                existing_item = merged_vrf_lite.get(key)
                if existing_item is None:
                    merged_vrf_lite[key] = deepcopy(item)
                else:
                    merged_vrf_lite[key] = existing_item.merge(item)

            merged_data["vrf_lite"] = [
                item.model_dump(by_alias=False, exclude_none=False) for _key, item in sorted(merged_vrf_lite.items(), key=lambda kv: kv[0])
            ]

        return type(self).model_validate(merged_data, by_name=True, by_alias=True)


class VrfLiteModel(NDBaseModel):
    """Runtime model for nd_manage_vrf_lite state reconciliation."""

    identifiers: ClassVar[list[str]] = ["vrf_name"]
    identifier_strategy: ClassVar[Literal["single"]] = "single"
    exclude_from_diff: ClassVar[set[str]] = {"deploy"}

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        validate_by_alias=True,
        validate_by_name=True,
        extra="ignore",
    )

    vrf_name: str = Field(alias="vrf_name", min_length=1, max_length=64)
    vlan_id: int | None = Field(default=None, alias="vlan_id", ge=1, le=4094)
    deploy: bool | None = Field(default=None, alias="deploy")
    attach: list[VrfLiteAttachmentModel] | None = Field(default=None, alias="attach")

    @field_validator("vrf_name")
    @classmethod
    def validate_vrf_name(cls, value: str) -> str:
        if value is None or not str(value).strip():
            raise ValueError("vrf_name must be a non-empty string")
        return str(value).strip()

    def to_diff_dict(self, **kwargs) -> dict[str, Any]:
        """Exclude nested attachment deploy field from diff comparison."""
        return self.model_dump(
            by_alias=True,
            exclude_none=True,
            exclude={
                "deploy": True,
                "attach": {"__all__": {"deploy": True}},
            },
            mode="json",
            **kwargs,
        )

    @classmethod
    def from_response(cls, response: dict[str, Any], **kwargs) -> "VrfLiteModel":
        return cls.model_validate(response, by_alias=True, by_name=True, **kwargs)

    @classmethod
    def from_config(cls, ansible_config: dict[str, Any], **kwargs) -> "VrfLiteModel":
        return cls.model_validate(ansible_config, by_alias=True, by_name=True, **kwargs)

    @classmethod
    def get_argument_spec(cls) -> dict[str, Any]:
        """Return the Ansible argument spec for nd_manage_vrf_lite."""
        return VrfLitePlaybookConfigModel.get_argument_spec()

    def merge(self, other: "VrfLiteModel") -> "VrfLiteModel":
        """
        Merge another VrfLiteModel into this one.

        Custom behavior:
        - scalar fields follow NDBaseModel merge semantics (explicit fields only)
        - `attach` list is merged by `ip_address` instead of replacing the full list
        """
        if not isinstance(other, type(self)):
            raise TypeError("VrfLiteModel.merge requires both models to be the same type")

        merged_data = self.model_dump(by_alias=False, exclude_none=False)
        incoming_data = other.model_dump(by_alias=False, exclude_none=False, exclude_unset=True)

        for field, value in incoming_data.items():
            if field == "attach":
                continue
            if value is None:
                continue
            merged_data[field] = value

        if "attach" in incoming_data and incoming_data.get("attach") is not None:
            current_attach = self.attach or []
            incoming_attach = other.attach or []

            merged_attach = {}
            for item in current_attach:
                key = str(item.ip_address).strip().lower()
                merged_attach[key] = deepcopy(item)

            for item in incoming_attach:
                key = str(item.ip_address).strip().lower()
                existing_item = merged_attach.get(key)
                if existing_item is None:
                    merged_attach[key] = deepcopy(item)
                else:
                    merged_attach[key] = existing_item.merge(item)

            merged_data["attach"] = [item.model_dump(by_alias=False, exclude_none=False) for _key, item in sorted(merged_attach.items(), key=lambda kv: kv[0])]

        return type(self).model_validate(merged_data, by_name=True, by_alias=True)


class VrfLitePlaybookItemModel(BaseModel):
    """One config item under playbook `config`."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        validate_by_alias=True,
        validate_by_name=True,
        extra="ignore",
    )

    vrf_name: str = Field(alias="vrf_name", min_length=1, max_length=64)
    vlan_id: int | None = Field(default=None, alias="vlan_id", ge=1, le=4094)
    deploy: bool | None = Field(default=None, alias="deploy")
    attach: list[VrfLiteAttachmentModel] | None = Field(default=None, alias="attach")

    @field_validator("vrf_name")
    @classmethod
    def validate_vrf_name(cls, value: str) -> str:
        if value is None or not str(value).strip():
            raise ValueError("vrf_name must be a non-empty string")
        return str(value).strip()

    def to_runtime_config(self) -> dict[str, Any]:
        return self.model_dump(by_alias=False, exclude_none=True)


class VerifyConfigModel(BaseModel):
    """Verification controls for post-write refresh behavior."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra="ignore",
    )

    enabled: bool = Field(default=True)
    retries: int = Field(default=5, ge=1)
    timeout: int = Field(default=10, ge=1)


class ConfigActionsModel(BaseModel):
    """Config save/deploy controls for write workflows."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra="ignore",
    )

    save: bool = Field(default=True)
    deploy: bool = Field(default=True)
    type: Literal["switch", "global"] = Field(default="switch")

    @model_validator(mode="after")
    def validate_save_deploy_dependency(self) -> "ConfigActionsModel":
        if not self.save and self.deploy:
            raise ValueError("config_actions.deploy=true requires config_actions.save=true")
        return self


class VrfLitePlaybookConfigModel(BaseModel):
    """Top-level playbook model for nd_manage_vrf_lite."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        validate_by_alias=True,
        validate_by_name=True,
        extra="ignore",
    )

    state: Literal["merged", "replaced", "deleted", "overridden", "gathered"] = Field(default="merged")
    # TODO: Replace with the shared fabric_name Field once the collection adds it.
    fabric_name: str = Field(min_length=1)
    force: bool = Field(default=False)
    verify: VerifyConfigModel | None = Field(default=None)
    config_actions: ConfigActionsModel | None = Field(default=None)
    config: list[VrfLitePlaybookItemModel] | None = Field(default=None)

    @model_validator(mode="after")
    def validate_config_actions(self) -> "VrfLitePlaybookConfigModel":
        if self.config_actions and not self.config_actions.save and self.config_actions.deploy:
            raise ValueError("config_actions.deploy=true requires config_actions.save=true")
        return self

    def to_runtime_config(self) -> list[dict[str, Any]]:
        """Normalize playbook config into NDStateMachine runtime items."""
        return [item.to_runtime_config() for item in (self.config or [])]

    @classmethod
    def get_argument_spec(cls) -> dict[str, Any]:
        return dict(
            state=dict(type="str", default="merged", choices=["merged", "replaced", "deleted", "overridden", "gathered"]),
            fabric_name=dict(type="str", required=True),
            force=dict(type="bool", default=False),
            verify=dict(
                type="dict",
                required=False,
                options=dict(
                    enabled=dict(type="bool", default=True),
                    retries=dict(type="int", default=5),
                    timeout=dict(type="int", default=10),
                ),
            ),
            config_actions=dict(
                type="dict",
                required=False,
                options=dict(
                    save=dict(type="bool", default=True),
                    deploy=dict(type="bool", default=True),
                    type=dict(type="str", default="switch", choices=["switch", "global"]),
                ),
            ),
            config=dict(
                type="list",
                elements="dict",
                required=False,
                options=dict(
                    vrf_name=dict(type="str", required=True),
                    vlan_id=dict(type="int", required=False),
                    deploy=dict(type="bool", required=False),
                    attach=dict(
                        type="list",
                        elements="dict",
                        required=False,
                        options=dict(
                            ip_address=dict(type="str", required=True),
                            deploy=dict(type="bool", required=False),
                            import_evpn_rt=dict(type="str", required=False),
                            export_evpn_rt=dict(type="str", required=False),
                            vrf_lite=dict(
                                type="list",
                                elements="dict",
                                required=False,
                                options=dict(
                                    interface=dict(type="str", required=True),
                                    dot1q=dict(type="int", required=False),
                                    ipv4_addr=dict(type="str", required=False),
                                    neighbor_ipv4=dict(type="str", required=False),
                                    ipv6_addr=dict(type="str", required=False),
                                    neighbor_ipv6=dict(type="str", required=False),
                                    peer_vrf=dict(type="str", required=False),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )
