# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Playbook-facing Pydantic models for Interface Groups configuration."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BaseModel,
    ConfigDict,
    Field,
    SerializationInfo,
    ValidationInfo,
    field_validator,
    model_serializer,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    MtuEnum,
    SpeedEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.enums import (
    InterfaceGroupConfigActionType,
    InterfaceGroupState,
    InterfaceGroupType,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.validators import (
    InterfaceGroupValidators,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.types import (
    AsciiDescription,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import (
    config_actions_spec,
)


class InterfaceGroupSwitchInterfacesModel(NDNestedModel):
    """One switch and its member interfaces within an interface group."""

    switch_id: str = Field(
        alias="switchId",
        min_length=1,
        description="Switch serial number or management IP address",
    )
    interface_names: list[str] = Field(alias="interfaceNames", min_length=1, description="Member interface names")

    @field_validator("switch_id", mode="before")
    @classmethod
    def normalize_switch_id(cls, value):
        """Strip surrounding whitespace from switch identifiers."""
        return value.strip() if isinstance(value, str) else value

    @field_validator("interface_names", mode="before")
    @classmethod
    def normalize_interface_names(cls, value):
        """Canonicalize, de-duplicate, and sort interface names."""
        normalized = InterfaceGroupValidators.normalize_unique_strings(value)
        if normalized is None or not isinstance(normalized, list):
            return normalized
        return sorted({InterfaceGroupValidators.normalize_interface_name(item) for item in normalized})


class InterfaceGroupEthernetAttributesModel(NDNestedModel):
    """Validated shared Ethernet policy attributes supported by Interface Groups."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="forbid",
    )

    admin_status: bool | None = Field(default=None, alias="adminStatus")
    auto_negotiation: Literal["on", "off"] | None = Field(default=None, alias="autoNegotiation")
    bpdu_guard: Literal["enabled", "disabled", "default"] | None = Field(default=None, alias="bpduGuard")
    cdp: bool | None = Field(default=None)
    description: AsciiDescription = Field(default=None, max_length=254)
    extra_config: str | None = Field(default=None, alias="extraConfig")
    fex: bool | None = Field(default=None)
    mtu: MtuEnum | None = Field(default=None)
    native_vlan: int | None = Field(default=None, alias="nativeVlan", ge=1, le=4094)
    netflow: bool | None = Field(default=None)
    netflow_monitor: str | None = Field(default=None, alias="netflowMonitor")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler")
    port_duplex_mode: Literal["auto", "full", "half"] | None = Field(default=None, alias="portDuplexMode")
    port_type_fast: bool | None = Field(default=None, alias="portTypeFast")
    ptp: bool | None = Field(default=None)
    ptp_timestamp_tagging: bool | None = Field(default=None, alias="ptpTimestampTagging")
    speed: SpeedEnum | None = Field(default=None)
    trunk_allowed_vlans: str | None = Field(
        default=None,
        alias="trunkAllowedVlans",
        pattern=r"^all$|^none$|^((40(?:[0-8]\d|9[0-6])|[1-3]\d{2,3}|\d{2,3}|[1-9]){0,1}([,-]{1}|$))*$",
    )
    vpc_orphan_port: bool | None = Field(default=None, alias="vPCOrphanPort")


class InterfaceGroupConfigModel(NDBaseModel):
    """One playbook-facing Interface Group resource."""

    identifiers: ClassVar[list[str]] = ["interface_group_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"
    exclude_from_diff: ClassVar[set[str]] = {
        "deploy",
        "interface_count",
        "network_count",
        "policy_id",
    }
    payload_exclude_fields: ClassVar[set[str]] = {
        "deploy",
        "interface_count",
        "network_count",
        "policy_id",
    }
    config_exclude_fields: ClassVar[set[str]] = {
        "interface_count",
        "network_count",
        "policy_id",
    }

    interface_group_name: str = Field(alias="interfaceGroupName", min_length=1, description="Interface group name")
    type: InterfaceGroupType | None = Field(default=None, description="Interface group type")
    networks: list[str] | None = Field(
        default=None,
        alias="networkNames",
        description="Names of existing networks associated with the Interface Group",
    )
    switch_interfaces: list[InterfaceGroupSwitchInterfacesModel] | None = Field(
        default=None,
        alias="switchInterfaces",
        description="Switch and interface membership",
    )
    template_name: str | None = Field(default=None, alias="templateName", description="Custom ethernet template name")
    template_config: dict[str, Any] | None = Field(
        default=None,
        alias="templateConfig",
        description="Custom ethernet template inputs",
    )
    ethernet_attributes: InterfaceGroupEthernetAttributesModel | None = Field(
        default=None,
        alias="ethernetAttributes",
        description="Shared ethernet policy attributes",
    )
    deploy: bool | None = Field(
        default=None,
        description="Resource-level deploy flag; valid only when config_actions.type=resource",
    )
    interface_count: int | None = Field(
        default=None,
        alias="interfaceCount",
        ge=0,
        description="Controller-calculated interface count",
    )
    network_count: int | None = Field(
        default=None,
        alias="networkCount",
        ge=0,
        description="Controller-calculated network count",
    )
    policy_id: str | None = Field(
        default=None,
        alias="policyId",
        description="Controller-generated shared policy ID",
    )

    @classmethod
    def from_config(cls, ansible_config: dict[str, Any], **kwargs) -> "InterfaceGroupConfigModel":
        """Preserve explicit nulls inside opaque custom-template inputs."""
        template_config = ansible_config.get("template_config", ansible_config.get("templateConfig"))
        model = super().from_config(ansible_config, **kwargs)
        if isinstance(template_config, dict):
            model.template_config = deepcopy(template_config)
        return model

    @model_serializer(mode="wrap")
    def strip_operational_fields(self, handler, info: SerializationInfo):
        """Keep module-only and read-only fields out of nested request/config serialization."""
        data = handler(self)
        mode = (info.context or {}).get("mode")
        if mode == "payload":
            for key in (
                "deploy",
                "interfaceCount",
                "interface_count",
                "networkCount",
                "network_count",
                "policyId",
                "policy_id",
            ):
                data.pop(key, None)
        elif mode == "config":
            for key in (
                "interfaceCount",
                "interface_count",
                "networkCount",
                "network_count",
                "policyId",
                "policy_id",
            ):
                data.pop(key, None)
        return data

    @model_validator(mode="before")
    @classmethod
    def normalize_api_shape(cls, data, info: ValidationInfo):
        """Accept both flattened responses and the nested association response shape."""
        if not isinstance(data, dict):
            return data
        normalized = InterfaceGroupValidators.normalize_response_group(data) if (info.context or {}).get("mode") == "response" else dict(data)
        association = normalized.get("interfaceGroupAssociation") or normalized.get("interface_group_association")
        if isinstance(association, dict):
            if "networks" not in normalized and "networkNames" not in normalized:
                normalized["networkNames"] = association.get("networkNames", association.get("networks"))
            if "switch_interfaces" not in normalized and "switchInterfaces" not in normalized:
                normalized["switchInterfaces"] = association.get("switchInterfaces", association.get("switch_interfaces"))
        return normalized

    @field_validator("interface_group_name", "template_name", mode="before")
    @classmethod
    def strip_text_fields(cls, value):
        """Strip surrounding whitespace from user-facing string fields."""
        return value.strip() if isinstance(value, str) else value

    @field_validator("networks", mode="before")
    @classmethod
    def normalize_networks(cls, value):
        """De-duplicate and sort network associations for stable diffs."""
        return InterfaceGroupValidators.normalize_unique_strings(value)

    @field_validator("switch_interfaces", mode="before")
    @classmethod
    def merge_switch_entries(cls, value):
        """Merge repeated switch entries and de-duplicate their member interfaces."""
        if value is None or not isinstance(value, list):
            return value
        merged: dict[Any, list[Any]] = {}
        for item in value:
            if not isinstance(item, dict):
                return value
            switch_id = item.get("switch_id", item.get("switchId"))
            if isinstance(switch_id, str):
                switch_id = switch_id.strip()
            interface_names = item.get("interface_names", item.get("interfaceNames"))
            if not isinstance(interface_names, list):
                return value
            merged.setdefault(switch_id, []).extend(interface_names)
        return [
            {"switch_id": switch_id, "interface_names": interface_names}
            for switch_id, interface_names in sorted(merged.items(), key=lambda entry: str(entry[0]))
        ]

    @model_validator(mode="after")
    def validate_type_specific_fields(self) -> "InterfaceGroupConfigModel":
        """Validate member kinds and type-specific policy/template fields."""
        if self.type is None:
            return self

        allowed_member_kinds = {
            InterfaceGroupType.ANY.value: {"ethernet", "port_channel", "vpc"},
            InterfaceGroupType.ETHERNET_CUSTOM.value: {"ethernet"},
            InterfaceGroupType.ETHERNET_WITH_POLICY.value: {"ethernet"},
            InterfaceGroupType.ETHERNET_WITHOUT_POLICY.value: {"ethernet"},
            InterfaceGroupType.PORT_CHANNEL.value: {"port_channel"},
            InterfaceGroupType.VPC.value: {"vpc"},
        }[self.type]

        for switch_entry in self.switch_interfaces or []:
            for interface_name in switch_entry.interface_names:
                member_kind = InterfaceGroupValidators.interface_kind(interface_name)
                if member_kind not in allowed_member_kinds:
                    raise ValueError(f"interface '{interface_name}' is not valid for interface group type '{self.type}'")

        if self.type != InterfaceGroupType.ETHERNET_CUSTOM.value and (self.template_name is not None or self.template_config is not None):
            raise ValueError("template_name and template_config are valid only for type=ethernetCustom")
        if (
            self.type
            not in (
                InterfaceGroupType.ETHERNET_WITH_POLICY.value,
                InterfaceGroupType.ETHERNET_WITHOUT_POLICY.value,
            )
            and self.ethernet_attributes is not None
        ):
            raise ValueError("ethernet_attributes is valid only for ethernetWithPolicy or ethernetWithoutPolicy groups")
        if self.type == InterfaceGroupType.ETHERNET_WITH_POLICY.value and self.ethernet_attributes is None:
            object.__setattr__(
                self,
                "ethernet_attributes",
                InterfaceGroupEthernetAttributesModel(**InterfaceGroupValidators.ethernet_with_policy_defaults()),
            )
        if (
            self.type == InterfaceGroupType.ETHERNET_WITHOUT_POLICY.value
            and self.ethernet_attributes is not None
            and self.ethernet_attributes.model_dump(exclude_none=True)
        ):
            raise ValueError("ethernet_attributes must be empty for type=ethernetWithoutPolicy")
        return self

    @staticmethod
    def _merge_string_lists(current: list[str] | None, proposed: list[str]) -> list[str] | None:
        """Add proposed values without removing values already present."""
        if not proposed:
            return current
        return sorted(set(current or []) | set(proposed))

    @staticmethod
    def _merge_switch_interfaces(
        current: list[InterfaceGroupSwitchInterfacesModel] | None,
        proposed: list[InterfaceGroupSwitchInterfacesModel],
    ) -> list[dict[str, Any]] | None:
        """Add proposed switch members without removing existing switches or interfaces."""
        if not proposed:
            return current

        merged: dict[str, set[str]] = {}
        for switch_entry in [*(current or []), *proposed]:
            merged.setdefault(switch_entry.switch_id, set()).update(switch_entry.interface_names)

        return [
            {
                "switch_id": switch_id,
                "interface_names": sorted(interface_names),
            }
            for switch_id, interface_names in sorted(merged.items())
        ]

    @classmethod
    def _merge_dicts(cls, current: dict[str, Any] | None, proposed: dict[str, Any]) -> dict[str, Any] | None:
        """Recursively merge explicitly supplied dictionary keys."""
        if not proposed:
            return current

        merged = deepcopy(current or {})
        for key, value in proposed.items():
            if isinstance(merged.get(key), dict) and isinstance(value, dict):
                merged[key] = cls._merge_dicts(merged[key], value)
            else:
                merged[key] = deepcopy(value)
        return merged

    def get_diff(self, other: "NDBaseModel", exclude_unset: bool = False) -> bool:
        """Compare merged input using additive association semantics.

        ``NDStateMachine`` sets ``exclude_unset=True`` only for ``state=merged``.
        For that path, compare the existing model with the effective additive
        result rather than treating supplied lists as authoritative. Custom
        template inputs are compared separately because ND returns native
        YAML booleans and numbers as strings and injects additional keys.
        """
        if not isinstance(other, type(self)):
            return False

        template_config_supplied = "template_config" in other.model_fields_set
        if not template_config_supplied:
            if not exclude_unset:
                return super().get_diff(other, exclude_unset=exclude_unset)
            candidate = deepcopy(self)
            candidate.merge(other)
            return candidate.to_diff_dict() == self.to_diff_dict()

        current_template_config = self.template_config or {}
        proposed_template_config = other.template_config or {}
        template_matches = InterfaceGroupValidators.template_config_is_subset(
            proposed_template_config,
            current_template_config,
        )

        current_without_template = deepcopy(self)
        proposed_without_template = deepcopy(other)
        current_without_template.template_config = {}
        proposed_without_template.template_config = {}

        if not exclude_unset:
            return template_matches and NDBaseModel.get_diff(
                current_without_template,
                proposed_without_template,
                exclude_unset=False,
            )

        candidate = deepcopy(current_without_template)
        candidate.merge(proposed_without_template)
        return template_matches and candidate.to_diff_dict() == current_without_template.to_diff_dict()

    def merge(self, other: "NDBaseModel") -> "InterfaceGroupConfigModel":
        """Merge one Interface Group additively for ``state=merged``.

        Networks and switch members are unioned, while omitted values are
        preserved. Nested custom-template and Ethernet-policy dictionaries are
        merged by key. Removal remains available through ``replaced`` and
        ``overridden``, whose state-machine paths do not call this method.
        """
        if not isinstance(other, type(self)):
            raise TypeError(f"Cannot merge {type(other).__name__} into {type(self).__name__}. Both must be the same type.")

        for field_name in other.model_fields_set:
            value = getattr(other, field_name, None)
            if value is None:
                continue

            current = getattr(self, field_name)
            if field_name == "networks":
                setattr(self, field_name, self._merge_string_lists(current, value))
            elif field_name == "switch_interfaces":
                setattr(self, field_name, self._merge_switch_interfaces(current, value))
            elif field_name == "template_config":
                setattr(self, field_name, self._merge_dicts(current, value))
            elif isinstance(current, NDBaseModel) and isinstance(value, NDBaseModel):
                current.merge(value)
            else:
                setattr(self, field_name, value)

        return self


class InterfaceGroupConfigActionsModel(BaseModel):
    """Deployment controls supported by the Interface Groups module."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    deploy: bool = Field(default=True, description="Whether to deploy staged Interface Group changes")
    type: InterfaceGroupConfigActionType = Field(default=InterfaceGroupConfigActionType.SWITCH, description="Deployment scope")


class InterfaceGroupGatheredSwitchFilterModel(NDNestedModel):
    """Switch and optional member criteria used by ``state=gathered``."""

    switch_id: str = Field(
        alias="switchId",
        min_length=1,
        description="Switch serial number or management IP address",
    )
    interface_names: list[str] | None = Field(
        default=None,
        alias="interfaceNames",
        min_length=1,
        description="Optional member interfaces that must all be present",
    )

    @field_validator("switch_id", mode="before")
    @classmethod
    def normalize_switch_id(cls, value):
        """Strip surrounding whitespace from switch identifiers."""
        return value.strip() if isinstance(value, str) else value

    @field_validator("interface_names", mode="before")
    @classmethod
    def normalize_interface_names(cls, value):
        """Canonicalize, de-duplicate, and sort member filter values."""
        normalized = InterfaceGroupValidators.normalize_unique_strings(value)
        if normalized is None or not isinstance(normalized, list):
            return normalized
        return sorted({InterfaceGroupValidators.normalize_interface_name(item) for item in normalized})


class InterfaceGroupGatheredFilterModel(BaseModel):
    """One read-only Interface Group filter.

    Fields within one entry are combined with AND. Multiple entries are
    combined with OR by the orchestrator. ``model_fields_set`` is retained so
    explicit empty association lists remain distinguishable from omission.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="forbid",
    )

    interface_group_name: str | None = Field(
        default=None,
        alias="interfaceGroupName",
        min_length=1,
        description="Exact Interface Group name",
    )
    type: InterfaceGroupType | None = Field(default=None, description="Exact normalized Interface Group type")
    networks: list[str] | None = Field(
        default=None,
        alias="networkNames",
        description="Networks that must all be associated",
    )
    switch_interfaces: list[InterfaceGroupGatheredSwitchFilterModel] | None = Field(
        default=None,
        alias="switchInterfaces",
        description="Switches and optional members that must be associated",
    )
    template_name: str | None = Field(
        default=None,
        alias="templateName",
        min_length=1,
        description="Exact custom Ethernet template name",
    )
    template_config: dict[str, Any] | None = Field(
        default=None,
        alias="templateConfig",
        description="Custom-template key/value subset",
    )
    ethernet_attributes: InterfaceGroupEthernetAttributesModel | None = Field(
        default=None,
        alias="ethernetAttributes",
        description="Shared Ethernet attribute subset",
    )

    @field_validator("interface_group_name", "template_name", mode="before")
    @classmethod
    def strip_text_fields(cls, value):
        """Strip surrounding whitespace from scalar filter values."""
        return value.strip() if isinstance(value, str) else value

    @field_validator("networks", mode="before")
    @classmethod
    def normalize_networks(cls, value):
        """De-duplicate and sort network filter values."""
        return InterfaceGroupValidators.normalize_unique_strings(value)

    @model_validator(mode="after")
    def validate_filter(self) -> "InterfaceGroupGatheredFilterModel":
        """Reject ambiguous duplicate switches and incompatible type fields."""
        switch_ids: set[str] = set()
        for item in self.switch_interfaces or []:
            if item.switch_id in switch_ids:
                raise ValueError(f"duplicate switch_id '{item.switch_id}' in gathered filter")
            switch_ids.add(item.switch_id)

        if (
            self.type is not None
            and self.type != InterfaceGroupType.ETHERNET_CUSTOM.value
            and ("template_name" in self.model_fields_set or "template_config" in self.model_fields_set)
        ):
            raise ValueError("template_name and template_config filters require type=ethernetCustom when type is supplied")
        if (
            self.type is not None
            and self.type
            not in (
                InterfaceGroupType.ETHERNET_WITH_POLICY.value,
                InterfaceGroupType.ETHERNET_WITHOUT_POLICY.value,
            )
            and "ethernet_attributes" in self.model_fields_set
        ):
            raise ValueError("ethernet_attributes filter requires an Ethernet policy type when type is supplied")
        return self

    def to_filter_config(self) -> dict[str, Any]:
        """Return normalized filter data while preserving explicit empties."""
        return self.model_dump(
            by_alias=False,
            exclude_unset=True,
            exclude_none=True,
            mode="json",
        )


class InterfaceGroupModuleConfigModel(BaseModel):
    """Top-level input contract for ``nd_manage_interface_group``."""

    _config_input_keys: ClassVar[set[str]] = {
        "interface_group_name",
        "type",
        "networks",
        "switch_interfaces",
        "template_name",
        "template_config",
        "ethernet_attributes",
        "deploy",
    }
    _switch_interface_input_keys: ClassVar[set[str]] = {
        "switch_id",
        "interface_names",
    }

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="ignore",
    )

    fabric_name: str = Field(min_length=1, description="Fabric name")
    config: list[Any] = Field(default_factory=list, description="Interface group resources")
    config_actions: InterfaceGroupConfigActionsModel | None = Field(default=None, description="Deployment controls")
    state: InterfaceGroupState = Field(default=InterfaceGroupState.MERGED, description="Desired resource state")

    @model_validator(mode="before")
    @classmethod
    def remove_ansible_none_defaults(cls, data):
        """Validate raw argspec dictionaries and remove implicit ``None`` defaults.

        The shared response models intentionally tolerate additional controller
        fields. Module input must be stricter, so reject unsupported config and
        switch-interface keys here before nested models can ignore them.
        """
        if not isinstance(data, dict):
            return data
        normalized = dict(data)
        config = normalized.get("config")
        if config is None:
            normalized["config"] = []
            config = []
        if isinstance(config, list):
            normalized_config = []
            for config_index, item in enumerate(config):
                if not isinstance(item, dict):
                    normalized_config.append(item)
                    continue

                unknown_config_keys = set(item) - cls._config_input_keys
                if unknown_config_keys:
                    unknown = ", ".join(sorted(unknown_config_keys))
                    raise ValueError(f"unsupported option(s) in config[{config_index}]: {unknown}")

                normalized_item = {key: value for key, value in item.items() if value is not None}
                switch_interfaces = normalized_item.get("switch_interfaces")
                if isinstance(switch_interfaces, list):
                    for switch_index, switch_entry in enumerate(switch_interfaces):
                        if not isinstance(switch_entry, dict):
                            continue
                        unknown_switch_keys = set(switch_entry) - cls._switch_interface_input_keys
                        if unknown_switch_keys:
                            unknown = ", ".join(sorted(unknown_switch_keys))
                            raise ValueError("unsupported option(s) in " f"config[{config_index}].switch_interfaces[{switch_index}]: {unknown}")

                normalized_config.append(normalized_item)
            normalized["config"] = normalized_config
        return normalized

    @model_validator(mode="after")
    def validate_module_contract(self) -> "InterfaceGroupModuleConfigModel":
        """Validate state requirements, uniqueness, and deployment semantics."""
        state = self.state.value if isinstance(self.state, InterfaceGroupState) else self.state
        model_class = InterfaceGroupGatheredFilterModel if state == InterfaceGroupState.GATHERED.value else InterfaceGroupConfigModel
        validated_config = []
        for item in self.config:
            if isinstance(item, model_class):
                validated_config.append(item)
                continue
            if isinstance(item, BaseModel):
                item = item.model_dump(by_alias=False, exclude_unset=True, mode="python")
            validated_config.append(model_class.model_validate(item))
        object.__setattr__(self, "config", validated_config)

        if state == InterfaceGroupState.GATHERED.value:
            return self

        if not validated_config:
            raise ValueError(f"config is required when state={state}")

        group_names: set[str] = set()
        memberships: dict[tuple[str, str], str] = {}
        action_type = self.config_actions.type if self.config_actions else InterfaceGroupConfigActionType.SWITCH.value

        for item in validated_config:
            if item.interface_group_name in group_names:
                raise ValueError(f"duplicate interface_group_name '{item.interface_group_name}' in config")
            group_names.add(item.interface_group_name)

            if state in (
                InterfaceGroupState.REPLACED.value,
                InterfaceGroupState.OVERRIDDEN.value,
            ):
                if item.type is None:
                    raise ValueError(f"type is required for interface group '{item.interface_group_name}' when state={state}")
                if item.type == InterfaceGroupType.ETHERNET_CUSTOM.value and not item.template_name:
                    raise ValueError(f"template_name is required for ethernetCustom interface group '{item.interface_group_name}'")

            if "deploy" in item.model_fields_set and action_type != InterfaceGroupConfigActionType.RESOURCE.value:
                raise ValueError("config[].deploy is valid only when config_actions.type=resource")

            for switch_entry in item.switch_interfaces or []:
                for interface_name in switch_entry.interface_names:
                    membership = (switch_entry.switch_id, interface_name)
                    existing_group = memberships.get(membership)
                    if existing_group and existing_group != item.interface_group_name:
                        raise ValueError(
                            f"interface '{interface_name}' on switch '{switch_entry.switch_id}' is present in both "
                            f"'{existing_group}' and '{item.interface_group_name}'"
                        )
                    memberships[membership] = item.interface_group_name

        return self

    @classmethod
    def get_argument_spec(cls) -> dict[str, Any]:
        """Return structural Ansible validation; Pydantic enforces the full contract."""
        spec: dict[str, Any] = {
            "fabric_name": {"type": "str", "required": True, "aliases": ["fabric"]},
            "config": {
                "type": "list",
                "elements": "dict",
                "required": False,
                "options": {
                    "interface_group_name": {"type": "str", "required": False},
                    "type": {"type": "str", "choices": InterfaceGroupType.choices()},
                    "networks": {"type": "list", "elements": "str"},
                    "switch_interfaces": {
                        "type": "list",
                        "elements": "dict",
                        "options": {
                            "switch_id": {"type": "str", "required": True},
                            "interface_names": {
                                "type": "list",
                                "elements": "str",
                                "required": False,
                            },
                        },
                    },
                    "template_name": {"type": "str"},
                    "template_config": {"type": "dict"},
                    "ethernet_attributes": {"type": "dict"},
                    # No Ansible default here: explicit presence must remain distinguishable from omission.
                    # Runtime semantics default an omitted resource deploy flag to true when type=resource.
                    "deploy": {"type": "bool"},
                },
            },
            "state": {
                "type": "str",
                "default": "merged",
                "choices": InterfaceGroupState.choices(),
            },
        }
        config_actions = config_actions_spec(include=("deploy", "type"))
        config_actions["config_actions"]["options"]["type"]["choices"] = InterfaceGroupConfigActionType.choices()
        spec.update(config_actions)
        return spec

    def resource_deploy_enabled(self, item: InterfaceGroupConfigModel) -> bool:
        """Return the effective deploy decision for one Interface Group item."""
        actions = self.config_actions or InterfaceGroupConfigActionsModel()
        if not actions.deploy:
            return False
        if actions.type != InterfaceGroupConfigActionType.RESOURCE.value:
            return True
        return item.deploy is not False
