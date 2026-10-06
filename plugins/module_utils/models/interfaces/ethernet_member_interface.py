# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Internal models and policy metadata for safe ethernet port-channel member updates.

The public ethernet modules own host policies, while an attached physical port uses a
different controller policy (for example ``poMember``).  Serializing that record through
a host-policy model changes its policy discriminator and can detach the port.  This module
therefore models the member records exactly and offers a narrow, non-mutating overlay for
the three properties the controller permits the ethernet modules to manage in-place.

This is an internal serialization layer, not an Ansible argument-spec model.  Ownership
and parent-consistency checks remain the orchestrator's responsibility.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Callable, ClassVar, Literal, Mapping, Union

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    FecEnum,
    LacpRateEnum,
    PortChannelModeEnum,
    XePortChannelModeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_trunk_host_interface import (
    AllowedVlans,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.policy_base import (
    InterfacePolicyStrictBase,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_common import (
    normalize_port_channel_interface_name,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.types import (
    AsciiDescription,
)

SAFE_MEMBER_UPDATE_FIELDS = frozenset({"admin_state", "description", "extra_config"})
"""Python field names that may be changed without replacing a member policy."""

_SAFE_MEMBER_UPDATE_ALIASES = {
    "adminState": "admin_state",
    "description": "description",
    "extraConfig": "extra_config",
}

_EXTRA_CONFIG_COMMAND_SEPARATOR = re.compile(r"[;\r\n]+")


class MemberPolicyDisposition(str, Enum):
    """Safety classification used by ethernet orchestrators before planning a mutation."""

    SUPPORTED = "supported"
    PAIR_AWARE = "pair_aware"
    PROTECTED = "protected"
    NOT_MEMBER = "not_member"


@dataclass(frozen=True)
class MemberPolicyDescriptor:
    """Static relationship between a member policy and its owning parent policy."""

    policy_type: str
    family: Literal["access", "trunk", "routed"]
    network_os: Literal["nx-os", "ios-xe"]
    wire_mode: Literal["access", "trunk", "routed"]
    parent_interface_type: Literal["portChannel", "vpc"]
    parent_policy_types: tuple[str, ...]
    parent_wire_mode: Literal["access", "trunk", "routed"]
    parent_network_os: Literal["nx-os", "ios-xe"]
    parent_member_fields: tuple[str, ...] = ("ports",)
    pair_aware: bool = False
    required_host_policy_type: str | None = None
    conversion_module: str | None = None

    def __post_init__(self) -> None:
        """Require IOS-XE pre-attach guidance to be either complete or absent."""

        if (self.required_host_policy_type is None) != (self.conversion_module is None):
            raise ValueError(f"Member relationship {self.policy_type!r} must define both required_host_policy_type " "and conversion_module, or neither")

    @property
    def disposition(self) -> MemberPolicyDisposition:
        """Return the validation level required before this member may be updated."""

        if self.pair_aware:
            return MemberPolicyDisposition.PAIR_AWARE
        return MemberPolicyDisposition.SUPPORTED


class EthernetMemberModelError(ValueError):
    """Base exception for member classification, parsing, and safe-overlay failures."""


class UnsupportedMemberPolicyError(EthernetMemberModelError):
    """Raised when a record is not one of the explicitly modeled member policies."""


class UnsafeMemberUpdateError(EthernetMemberModelError):
    """Raised when a requested overlay could alter policy family or membership."""


class UnmodeledMemberConfigurationError(EthernetMemberModelError):
    """Raised when a full member PUT would silently discard nested configuration."""


class NexusPortChannelMemberPolicyBase(InterfacePolicyStrictBase):
    """Fields declared by the common NX-OS member templates."""

    port_channel_id: str = Field(
        alias="portChannelId",
        min_length=1,
        description="Owning port-channel identifier",
    )
    port_channel_mode: PortChannelModeEnum | None = Field(default=None, alias="portChannelMode", description="Port-channel mode")
    cdp: bool | None = Field(default=None, alias="cdp", description="Enable CDP")
    lacp_port_priority: int | None = Field(
        default=None,
        alias="lacpPortPriority",
        ge=1,
        le=65535,
        description="LACP port priority",
    )
    lacp_rate: LacpRateEnum | None = Field(default=None, alias="lacpRate", description="LACP packet rate")
    description: AsciiDescription = Field(
        default=None,
        alias="description",
        max_length=254,
        description="Interface description",
    )
    debounce_timer: int | None = Field(
        default=None,
        alias="debounceTimer",
        ge=0,
        le=20000,
        description="Link-down debounce timer",
    )
    debounce_linkup_timer: int | None = Field(
        default=None,
        alias="debounceLinkupTimer",
        ge=1000,
        le=10000,
        description="Link-up debounce timer",
    )
    fec: FecEnum | None = Field(default=None, alias="fec", description="Forward error correction mode")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional interface CLI")


class PoMemberPolicyModel(NexusPortChannelMemberPolicyBase):
    """NX-OS standalone trunk port-channel member (``poMember``)."""

    policy_type: Literal["poMember"] = Field(alias="policyType")
    allowed_vlans: AllowedVlans = Field(default=None, alias="allowedVlans", description="Allowed VLANs")


class AccessPoMemberPolicyModel(NexusPortChannelMemberPolicyBase):
    """NX-OS standalone access port-channel member (``accessPoMember``)."""

    policy_type: Literal["accessPoMember"] = Field(alias="policyType")


class L3PoMemberPolicyModel(InterfacePolicyStrictBase):
    """NX-OS standalone routed port-channel member (``l3PoMember``)."""

    policy_type: Literal["l3PoMember"] = Field(alias="policyType")
    port_channel_id: str = Field(
        alias="portChannelId",
        min_length=1,
        description="Owning port-channel identifier",
    )
    port_channel_mode: PortChannelModeEnum | None = Field(default=None, alias="portChannelMode", description="Port-channel mode")
    description: AsciiDescription = Field(
        default=None,
        alias="description",
        max_length=254,
        description="Interface description",
    )
    fec: FecEnum | None = Field(default=None, alias="fec", description="Forward error correction mode")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional interface CLI")


class IosXePortChannelMemberPolicyBase(InterfacePolicyStrictBase):
    """Fields confirmed on the IOS-XE port-channel member templates."""

    port_channel_id: str = Field(
        alias="portChannelId",
        min_length=1,
        description="Owning port-channel identifier",
    )
    port_channel_mode: XePortChannelModeEnum | None = Field(
        default=None,
        alias="portChannelMode",
        description="LACP or PAgP port-channel mode",
    )
    description: str | None = Field(
        default=None,
        alias="description",
        max_length=200,
        description="Interface description",
    )
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional interface CLI")


class IosXeAccessPoMemberPolicyModel(IosXePortChannelMemberPolicyBase):
    """IOS-XE standalone access port-channel member (``iosXeAccessPoMember``)."""

    policy_type: Literal["iosXeAccessPoMember"] = Field(alias="policyType")


class IosXeTrunkPoMemberPolicyModel(IosXePortChannelMemberPolicyBase):
    """IOS-XE standalone trunk port-channel member (``iosXeTrunkPoMember``)."""

    policy_type: Literal["iosXeTrunkPoMember"] = Field(alias="policyType")
    allowed_vlans: AllowedVlans = Field(default=None, alias="allowedVlans", description="Preserve the owning trunk port-channel's allowed VLANs")


class IosXeL3PoMemberPolicyModel(IosXePortChannelMemberPolicyBase):
    """IOS-XE standalone routed port-channel member (``iosXeL3PoMember``)."""

    policy_type: Literal["iosXeL3PoMember"] = Field(alias="policyType")


class VpcMemberPolicyModel(PoMemberPolicyModel):
    """NX-OS trunk vPC member; updates require proof from both peers."""

    policy_type: Literal["vpcMember"] = Field(alias="policyType")
    primary_interface: str | None = Field(default=None, alias="primaryInterface", description="Owning vPC interface")


class AccessVpcPoMemberPolicyModel(AccessPoMemberPolicyModel):
    """NX-OS access vPC member; updates require proof from both peers."""

    policy_type: Literal["accessVpcPoMember"] = Field(alias="policyType")
    primary_interface: str | None = Field(default=None, alias="primaryInterface", description="Owning vPC interface")


NexusMemberPolicyModel = Union[
    PoMemberPolicyModel,
    AccessPoMemberPolicyModel,
    L3PoMemberPolicyModel,
    VpcMemberPolicyModel,
    AccessVpcPoMemberPolicyModel,
]

IosXeMemberPolicyModel = Union[
    IosXeAccessPoMemberPolicyModel,
    IosXeTrunkPoMemberPolicyModel,
    IosXeL3PoMemberPolicyModel,
]


class NexusEthernetMemberNetworkOSModel(NDNestedModel):
    """NX-OS container for an exactly modeled member policy."""

    network_os_type: Literal["nx-os"] = Field(alias="networkOSType")
    policy: NexusMemberPolicyModel = Field(alias="policy", discriminator="policy_type")


class IosXeEthernetMemberNetworkOSModel(NDNestedModel):
    """IOS-XE container for an exactly modeled member policy."""

    network_os_type: Literal["ios-xe"] = Field(alias="networkOSType")
    policy: IosXeMemberPolicyModel = Field(alias="policy", discriminator="policy_type")


class EthernetMemberConfigDataModel(NDNestedModel):
    """Configuration envelope shared by the supported member records."""

    mode: Literal["access", "trunk", "routed"] = Field(alias="mode")
    network_os: NexusEthernetMemberNetworkOSModel | IosXeEthernetMemberNetworkOSModel = Field(
        alias="networkOS",
        discriminator="network_os_type",
    )


class EthernetMemberInterfaceModel(NDBaseModel):
    """Response-tolerant, payload-exact model for an existing ethernet member."""

    identifiers: ClassVar[list[str] | None] = ["interface_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"
    payload_exclude_fields: ClassVar[set[str]] = {"switch_ip"}

    switch_ip: str | None = Field(default=None, alias="switchIp")
    switch_id: str | None = Field(default=None, alias="switchId")
    interface_name: str = Field(alias="interfaceName", min_length=1)
    interface_type: Literal["ethernet"] = Field(default="ethernet", alias="interfaceType")
    config_data: EthernetMemberConfigDataModel = Field(alias="configData")

    @property
    def policy(self):
        """Return the concrete member policy branch."""

        return self.config_data.network_os.policy

    @property
    def policy_type(self) -> str:
        """Return the exact controller policy discriminator."""

        return self.policy.policy_type

    @property
    def descriptor(self) -> MemberPolicyDescriptor:
        """Return static family and parent metadata for this member policy."""

        descriptor = get_member_policy_descriptor(self.policy_type)
        if descriptor is None:  # Defensive: the discriminated model should make this unreachable.
            raise UnsupportedMemberPolicyError(f"Unsupported ethernet member policyType {self.policy_type!r}")
        return descriptor

    @property
    def normalized_port_channel_id(self) -> int | None:
        """Return the member's owning port-channel number in canonical integer form."""

        return normalize_port_channel_id(self.policy.port_channel_id)

    @model_validator(mode="after")
    def validate_policy_envelope(self):
        """Ensure the wire mode and network OS agree with the exact policy descriptor."""

        descriptor = self.descriptor
        actual_network_os = self.config_data.network_os.network_os_type
        if actual_network_os != descriptor.network_os:
            raise ValueError(f"policyType {self.policy_type!r} requires networkOSType {descriptor.network_os!r}; " f"got {actual_network_os!r}")
        if self.config_data.mode != descriptor.wire_mode:
            raise ValueError(f"policyType {self.policy_type!r} requires wire mode {descriptor.wire_mode!r}; " f"got {self.config_data.mode!r}")
        return self


_MEMBER_POLICY_RELATIONSHIPS = (
    MemberPolicyDescriptor(
        policy_type="poMember",
        family="trunk",
        network_os="nx-os",
        wire_mode="trunk",
        parent_interface_type="portChannel",
        parent_policy_types=("trunkPoHost",),
        parent_wire_mode="trunk",
        parent_network_os="nx-os",
    ),
    # Captured ND inventory reports accessPoMember intent with wire mode access.  Operational
    # data can independently report mode trunk after the interface joins the port-channel.
    MemberPolicyDescriptor(
        policy_type="accessPoMember",
        family="access",
        network_os="nx-os",
        wire_mode="access",
        parent_interface_type="portChannel",
        parent_policy_types=("accessPoHost",),
        parent_wire_mode="access",
        parent_network_os="nx-os",
    ),
    MemberPolicyDescriptor(
        policy_type="l3PoMember",
        family="routed",
        network_os="nx-os",
        wire_mode="routed",
        parent_interface_type="portChannel",
        parent_policy_types=("l3Po",),
        parent_wire_mode="routed",
        parent_network_os="nx-os",
    ),
    MemberPolicyDescriptor(
        policy_type="iosXeAccessPoMember",
        family="access",
        network_os="ios-xe",
        wire_mode="access",
        parent_interface_type="portChannel",
        parent_policy_types=("iosXeAccessPoHost",),
        parent_wire_mode="access",
        parent_network_os="ios-xe",
        required_host_policy_type="iosXeAccess",
        conversion_module="nd_interface_ethernet_access",
    ),
    MemberPolicyDescriptor(
        policy_type="iosXeTrunkPoMember",
        family="trunk",
        network_os="ios-xe",
        wire_mode="trunk",
        parent_interface_type="portChannel",
        parent_policy_types=("iosXeTrunkPoHost",),
        parent_wire_mode="trunk",
        parent_network_os="ios-xe",
        required_host_policy_type="iosXeTrunkHost",
        conversion_module="nd_interface_ethernet_trunk_host",
    ),
    MemberPolicyDescriptor(
        policy_type="iosXeL3PoMember",
        family="routed",
        network_os="ios-xe",
        wire_mode="routed",
        parent_interface_type="portChannel",
        parent_policy_types=("iosXeL3PortChannel",),
        parent_wire_mode="routed",
        parent_network_os="ios-xe",
        required_host_policy_type="iosXeRoutedHost",
        conversion_module="nd_interface_ethernet_routed",
    ),
    MemberPolicyDescriptor(
        policy_type="vpcMember",
        family="trunk",
        network_os="nx-os",
        wire_mode="trunk",
        parent_interface_type="vpc",
        parent_policy_types=("trunkVpcHost",),
        parent_wire_mode="trunk",
        parent_network_os="nx-os",
        parent_member_fields=("peer1MemberPorts", "peer2MemberPorts"),
        pair_aware=True,
    ),
    MemberPolicyDescriptor(
        policy_type="accessVpcPoMember",
        family="access",
        network_os="nx-os",
        wire_mode="access",
        parent_interface_type="vpc",
        parent_policy_types=("accessVpcHost",),
        parent_wire_mode="access",
        parent_network_os="nx-os",
        parent_member_fields=("peer1MemberPorts", "peer2MemberPorts"),
        pair_aware=True,
    ),
)
"""Single immutable source for every supported parent/member relationship."""


def _build_member_policy_indexes() -> tuple[Mapping[str, MemberPolicyDescriptor], Mapping[str, MemberPolicyDescriptor]]:
    """Build immutable member- and parent-keyed views, rejecting duplicate identities."""

    by_member: dict[str, MemberPolicyDescriptor] = {}
    by_parent: dict[str, MemberPolicyDescriptor] = {}
    for descriptor in _MEMBER_POLICY_RELATIONSHIPS:
        if descriptor.policy_type in by_member:
            raise RuntimeError(f"Duplicate member policy relationship for {descriptor.policy_type!r}")
        by_member[descriptor.policy_type] = descriptor
        for parent_policy_type in descriptor.parent_policy_types:
            if parent_policy_type in by_parent:
                raise RuntimeError(f"Duplicate parent policy relationship for {parent_policy_type!r}")
            by_parent[parent_policy_type] = descriptor
    return MappingProxyType(by_member), MappingProxyType(by_parent)


MEMBER_POLICY_BY_MEMBER_TYPE, MEMBER_POLICY_BY_PARENT_TYPE = _build_member_policy_indexes()
MEMBER_POLICY_DESCRIPTORS = MEMBER_POLICY_BY_MEMBER_TYPE
"""Compatibility name for the immutable member-keyed relationship registry."""


# Fail closed for every currently known internal, fabric-owned, specialized, or unsupported
# member template.  An unknown policy ending in "Member" is also protected by
# classify_member_policy(), so a new controller template cannot become writable by accident.
PROTECTED_MEMBER_POLICY_TYPES = frozenset(
    {
        "accessVpcMember",
        "csrMultisiteIfcMember",
        "dataBrokerPoMember",
        "dot1qTunnelPoMember",
        "dot1qTunnelVpcMember",
        "dot1qTunnelVpcPoMember",
        "fexPoMember",
        "iosXeInternalL3PoMember",
        "iosXeStackwiseLinkMember",
        "ipfmAccessPoMember",
        "ipfmTrunkPoMember",
        "l2DciLinkMember",
        "l3PoMemberInternal",
        "multiSiteLinkMember",
        "pvlanPoMember",
        "pvlanVpcMember",
        "trunkVpcMember",
        "uplinkPoMember",
        "vpcPeerLinkMember",
        "vpcUplinkMember",
        "vrfLiteLinkMember",
    }
)


def _is_boolean_response_echo(value: object) -> bool:
    """Return whether ND encoded a controller-owned Boolean echo safely.

    ND 4.2.1 returns a JSON Boolean for ``ptp`` while ND 4.3.1 returns the
    canonical lowercase strings ``"true"`` and ``"false"``.  Keep this
    qualification deliberately narrower than ordinary Boolean coercion so a
    new or malformed response shape still fails closed before a full PUT.
    """

    return isinstance(value, bool) or (isinstance(value, str) and value in {"true", "false"})


def _is_string_response_echo(value: object) -> bool:
    """Return whether ND encoded an ordinary response-only string."""

    return isinstance(value, str)


_RESPONSE_ONLY_POLICY_FIELDS: dict[str, Mapping[str, Callable[[object], bool]]] = {
    "accessPoMember": {"ptp": _is_boolean_response_echo, "portMode": _is_string_response_echo},
    "poMember": {"ptp": _is_boolean_response_echo},
    "accessVpcPoMember": {"ptp": _is_boolean_response_echo},
    "vpcMember": {"ptp": _is_boolean_response_echo},
    "l3PoMember": {"ptp": _is_boolean_response_echo},
}
"""Qualified controller echoes that may be discarded before a member PUT."""


def get_member_policy_descriptor(policy_type: object) -> MemberPolicyDescriptor | None:
    """Return exact metadata for a modeled member policy, otherwise ``None``."""

    if not isinstance(policy_type, str):
        return None
    return MEMBER_POLICY_DESCRIPTORS.get(policy_type)


def get_member_policy_descriptor_for_parent(policy_type: object) -> MemberPolicyDescriptor | None:
    """Return exact metadata for a modeled parent policy, otherwise ``None``."""

    if not isinstance(policy_type, str):
        return None
    return MEMBER_POLICY_BY_PARENT_TYPE.get(policy_type)


def classify_member_policy(policy_type: object) -> MemberPolicyDisposition:
    """Classify a policy without ever treating an unknown member template as writable."""

    descriptor = get_member_policy_descriptor(policy_type)
    if descriptor is not None:
        return descriptor.disposition
    if isinstance(policy_type, str) and (policy_type in PROTECTED_MEMBER_POLICY_TYPES or policy_type.endswith("Member")):
        return MemberPolicyDisposition.PROTECTED
    return MemberPolicyDisposition.NOT_MEMBER


def is_member_policy(policy_type: object) -> bool:
    """Return whether the policy is modeled or conservatively recognized as a member."""

    return classify_member_policy(policy_type) != MemberPolicyDisposition.NOT_MEMBER


def is_supported_member_policy(policy_type: object, *, include_pair_aware: bool = False) -> bool:
    """Return whether safe overlays are modeled, optionally including pair-aware policies."""

    disposition = classify_member_policy(policy_type)
    if disposition == MemberPolicyDisposition.SUPPORTED:
        return True
    return include_pair_aware and disposition == MemberPolicyDisposition.PAIR_AWARE


def normalize_port_channel_id(value: object) -> int | None:
    """Normalize through the shared port-channel name contract; operational ``-1`` means unset.

    Valid configured identities are 1 through 4096. ``None``, an empty string, and ND's
    documented integer/string ``-1`` sentinel return ``None``. Zero and every other
    negative value are invalid rather than alternate unset sentinels, so ownership
    validation cannot silently accept malformed operational evidence.
    """

    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError(f"Invalid port-channel identifier {value!r}")
    if value == -1 or (isinstance(value, str) and value.strip() in {"", "-1"}):
        return None
    normalized = normalize_port_channel_interface_name(value)
    if not isinstance(normalized, str) or not normalized.startswith("port-channel"):
        raise ValueError(f"Invalid port-channel identifier {value!r}")
    suffix = normalized.removeprefix("port-channel")
    if not suffix.isdigit():
        raise ValueError(f"Invalid port-channel identifier {value!r}")
    return int(suffix)


def policy_type_from_interface_record(record: Mapping[str, object]) -> str | None:
    """Read ``configData.networkOS.policy.policyType`` from an interface record."""

    config_data = record.get("configData")
    if not isinstance(config_data, Mapping):
        return None
    network_os = config_data.get("networkOS")
    if not isinstance(network_os, Mapping):
        return None
    policy = network_os.get("policy")
    if not isinstance(policy, Mapping):
        return None
    policy_type = policy.get("policyType")
    return policy_type if isinstance(policy_type, str) else None


def _declared_field_aliases(model: object) -> frozenset[str]:
    """Return one Pydantic model's complete wire-key set."""

    model_fields = getattr(type(model), "model_fields", None)
    if not isinstance(model_fields, Mapping):
        raise UnmodeledMemberConfigurationError(f"Cannot inspect declared fields for member model {type(model).__name__}")
    return frozenset(str(getattr(field, "alias", None) or name) for name, field in model_fields.items())


def _validate_nested_member_configuration(
    record: Mapping[str, object],
    model: EthernetMemberInterfaceModel,
) -> None:
    """Fail closed when model reconstruction would drop unclassified config intent.

    Top-level inventory metadata is response-only by construction. Nested configData,
    networkOS, and policy mappings form the full PUT body, so every key there must be
    modeled or explicitly qualified as a response-only controller echo.
    """

    config_data = record.get("configData")
    if not isinstance(config_data, Mapping):
        raise UnmodeledMemberConfigurationError("Member record lacks a valid configData mapping")
    network_os = config_data.get("networkOS")
    if not isinstance(network_os, Mapping):
        raise UnmodeledMemberConfigurationError("Member record lacks a valid configData.networkOS mapping")
    policy = network_os.get("policy")
    if not isinstance(policy, Mapping):
        raise UnmodeledMemberConfigurationError("Member record lacks a valid configData.networkOS.policy mapping")

    checks = (
        ("configData", config_data, model.config_data, {}),
        ("configData.networkOS", network_os, model.config_data.network_os, {}),
        (
            "configData.networkOS.policy",
            policy,
            model.policy,
            _RESPONSE_ONLY_POLICY_FIELDS.get(model.policy_type, {}),
        ),
    )
    violations: list[str] = []
    for path, raw_mapping, nested_model, response_only in checks:
        for key in set(raw_mapping) - _declared_field_aliases(nested_model):
            validator = response_only.get(key) if isinstance(key, str) else None
            if validator is None or not validator(raw_mapping[key]):
                violations.append(f"{path}.{key!s}")
    if violations:
        raise UnmodeledMemberConfigurationError(
            f"Cannot safely update member policy {model.policy_type!r}: unclassified or malformed nested "
            f"configuration fields would be omitted from the full PUT: {sorted(violations)!r}"
        )


def parse_member_interface_response(
    record: Mapping[str, object],
) -> EthernetMemberInterfaceModel:
    """Parse a modeled member response while stripping controller-only fields.

    Protected and unknown member policies are rejected with their safety classification in
    the error. Qualified response-only echoes such as NX-OS ``ptp`` and top-level inventory
    metadata are discarded. Any other unmodeled nested configuration fails closed.
    """

    policy_type = policy_type_from_interface_record(record)
    disposition = classify_member_policy(policy_type)
    if disposition not in {
        MemberPolicyDisposition.SUPPORTED,
        MemberPolicyDisposition.PAIR_AWARE,
    }:
        raise UnsupportedMemberPolicyError(f"Cannot model ethernet member policyType {policy_type!r}; classification is {disposition.value!r}")
    model = EthernetMemberInterfaceModel.from_response(dict(record))
    _validate_nested_member_configuration(record, model)
    return model


def _is_cli_abbreviation(token: str, command: str, minimum_length: int) -> bool:
    """Return whether token is a conservative, ordinary CLI abbreviation."""

    return len(token) >= minimum_length and command.startswith(token)


def _extra_config_command_changes_membership(command: str) -> bool:
    """Classify one normalized interface CLI command without executing it."""

    tokens = command.casefold().split()
    if not tokens:
        return False

    first = tokens[0]
    if _is_cli_abbreviation(first, "exit", 2) or _is_cli_abbreviation(first, "end", 2):
        return True
    if _is_cli_abbreviation(first, "default-interface", len("default-i")):
        return True

    command_index = 0
    if first == "no" or _is_cli_abbreviation(first, "default", 3):
        command_index = 1
    if command_index < len(tokens):
        candidate = tokens[command_index]
        if _is_cli_abbreviation(candidate, "channel-group", 2):
            return True
        if _is_cli_abbreviation(candidate, "interface", 3):
            return True

    if first == "do":
        command_index = 1
    else:
        command_index = 0
    return command_index < len(tokens) and _is_cli_abbreviation(tokens[command_index], "configure", 4)


def _extra_config_changes_membership(extra_config: str) -> bool:
    """Reject membership commands and attempts to escape the interface context.

    NX-OS accepts newlines, carriage returns, and semicolons as command boundaries.
    Inspect every command segment so a safe-looking prefix cannot hide a later
    channel-group/default-interface operation. Ordinary NX-OS abbreviations are
    treated the same as their full commands. Context-changing commands are also
    rejected because subsequent text could target the parent or another interface.
    """
    for segment in _EXTRA_CONFIG_COMMAND_SEPARATOR.split(extra_config):
        command = segment.strip()
        if not command or command.startswith("!"):
            continue
        if _extra_config_command_changes_membership(command):
            return True
    return False


def normalize_safe_member_updates(updates: Mapping[str, object]) -> dict[str, object]:
    """Normalize safe snake/camel-case update keys and reject membership-changing CLI."""

    normalized: dict[str, object] = {}
    for supplied_key, value in updates.items():
        key = _SAFE_MEMBER_UPDATE_ALIASES.get(supplied_key, supplied_key)
        if key not in SAFE_MEMBER_UPDATE_FIELDS:
            raise UnsafeMemberUpdateError(f"Port-channel members may update only {sorted(SAFE_MEMBER_UPDATE_FIELDS)}; got {supplied_key!r}")
        if key in normalized:
            raise UnsafeMemberUpdateError(f"Member update supplies {key!r} more than once")
        normalized[key] = value

    extra_config = normalized.get("extra_config")
    if isinstance(extra_config, str) and _extra_config_changes_membership(extra_config):
        raise UnsafeMemberUpdateError("extra_config for an attached member must not change channel-group membership or default the interface")
    return normalized


def build_member_update_payload(
    member: Mapping[str, object] | EthernetMemberInterfaceModel,
    updates: Mapping[str, object],
    *,
    switch_id: str | None = None,
    pair_validated: bool = False,
) -> dict[str, object]:
    """Return a member-preserving PUT payload with only safe requested fields overlaid.

    The supplied model/record is never mutated.  Pair-aware vPC policies additionally require
    the caller to attest that both peer records and their common parent were validated.
    """

    raw_policy: Mapping[str, object] | None = None
    if isinstance(member, Mapping):
        raw_config_data = member.get("configData")
        raw_network_os = raw_config_data.get("networkOS") if isinstance(raw_config_data, Mapping) else None
        candidate_policy = raw_network_os.get("policy") if isinstance(raw_network_os, Mapping) else None
        raw_policy = candidate_policy if isinstance(candidate_policy, Mapping) else None

    model = member if isinstance(member, EthernetMemberInterfaceModel) else parse_member_interface_response(member)
    descriptor = model.descriptor
    if descriptor.pair_aware and not pair_validated:
        raise UnsafeMemberUpdateError(f"policyType {descriptor.policy_type!r} requires pair-aware ownership validation before update")

    normalized_updates = normalize_safe_member_updates(updates)
    if "extra_config" not in normalized_updates:
        existing_extra_config = raw_policy.get("extraConfig") if raw_policy is not None else model.policy.extra_config
        if isinstance(existing_extra_config, str) and _extra_config_changes_membership(existing_extra_config):
            raise UnsafeMemberUpdateError(
                "Existing extraConfig for an attached member changes channel-group membership or interface context; "
                "refusing to reconstruct it in a safe member PUT. Replace it explicitly with safe extra_config first."
            )
    updated = model.model_copy(deep=True)
    for field_name, value in normalized_updates.items():
        setattr(updated.policy, field_name, value)

    payload = updated.to_payload()
    payload_policy = payload["configData"]["networkOS"]["policy"]
    if raw_policy is not None:
        # NDBaseModel strips surrounding whitespace from strings during response
        # validation.  Full-policy member PUTs must not rewrite an untouched
        # description or CLI block merely because another safe field changed.
        # Explicit user updates still flow through normal model validation.
        for field_name, wire_name in (("description", "description"), ("extra_config", "extraConfig")):
            raw_value = raw_policy.get(wire_name)
            if field_name not in normalized_updates and isinstance(raw_value, str):
                payload_policy[wire_name] = raw_value
    resolved_switch_id = switch_id if switch_id is not None else updated.switch_id
    if resolved_switch_id is not None:
        payload["switchId"] = resolved_switch_id
    return payload
