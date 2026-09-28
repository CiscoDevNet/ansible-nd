# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Ethernet trunk-mode host interface Pydantic models for Nexus Dashboard (NX-OS `trunkHost`, IOS-XE `iosXeTrunkHost`; issue #535).

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload
structure for ethernet trunk-mode host interfaces. The playbook config uses the same nesting so that
`to_payload()` and `from_response()` work via standard Pydantic serialization with no custom
wrapping or flattening.

## Model Hierarchy

- `EthernetTrunkHostInterfaceModel` (top-level, `NDBaseModel`)
    - `switch_ip` (composite identifier)
    - `interface_name` (composite identifier)
    - `interface_type` (hardcoded: "ethernet")
    - `config_data` -> `EthernetTrunkHostConfigDataModel`
        - `mode` (hardcoded: "trunk")
        - `network_os` -> `EthernetTrunkHostNetworkOSModel | XeEthernetTrunkHostNetworkOSModel` (discriminated union on
          `network_os_type`; injected as `nx-os` when omitted so pre-#535 playbooks are unchanged)
            - `EthernetTrunkHostNetworkOSModel` (`network_os_type: "nx-os"`)
                - `policy` -> `EthernetTrunkHostPolicyModel` (`policy_type: "trunkHost"`, injected when omitted)
                    - `vlan_mapping_entries` -> list[`EthernetTrunkHostVlanMappingEntryModel`]
            - `XeEthernetTrunkHostNetworkOSModel` (`network_os_type: "ios-xe"`)
                - `policy` -> `XeEthernetTrunkHostPolicyModel` (`policy_type: "iosXeTrunkHost"`, injected when omitted)

`policy_type` is optional on input: each network OS has exactly one managed trunk-host policy type today, so it is derived from
`network_os_type` (`ethernet_common.default_policy_type`). An explicit value is still accepted and validated.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, ClassVar, Literal, Optional  # Optional needed for Annotated runtime expr (see types.py)

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BeforeValidator,
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    BpduFilterEnum,
    BpduGuardEnum,
    DuplexModeEnum,
    FecEnum,
    LinkTypeEnum,
    MtuEnum,
    SpeedEnum,
    StormControlActionEnum,
    TrunkHostPolicyTypeEnum,
    XeEthernetSpeedEnum,
    XeTrunkHostPolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_common import (
    default_network_os_type,
    default_policy_type,
    normalize_ethernet_interface_name,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.policy_base import InterfacePolicyStrictBase
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.storm_control import StormControlMutexMixin
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription

# Shape regex: "none", "all", or comma-separated VLAN ids/ranges. Range bounds are validated separately.
_ALLOWED_VLANS_SHAPE = re.compile(r"^(none|all|(\d+(-\d+)?)(,\d+(-\d+)?)*)$")
# Single VLAN id or range token (e.g. "100" or "100-200"). Range bounds are validated separately.
_VLAN_ID_OR_RANGE_SHAPE = re.compile(r"^\d+(-\d+)?$")

# Public argspec `speed` choices: the union of the NX-OS and IOS-XE speed enums, in NX order with the XE-only extras appended.
# The Ansible argspec cannot express the per-policy_type subset (that stays with the Pydantic branch models), but listing the
# union lets ansible-doc / schema consumers discover every accepted spelling (PR #550 review).
_NX_SPEED_CHOICES: list[str] = [e.value for e in SpeedEnum]
_SPEED_ARGSPEC_CHOICES: list[str] = _NX_SPEED_CHOICES + [e.value for e in XeEthernetSpeedEnum if e.value not in _NX_SPEED_CHOICES]


def _validate_vlan_id_or_range(token: str, field_name: str) -> None:
    """
    # Summary

    Validate a single VLAN id or range token (e.g. `"100"` or `"100-200"`) and confirm every id is in 1..4094 and any range has start <= end.

    Shared helper used by `_validate_allowed_vlans` (per comma-split token) and `_validate_customer_vlan_id_list` (per list element).
    `field_name` is interpolated into error messages so callers see which field surfaced the failure.

    ## Raises

    ### ValueError

    - If `token` does not match `\\d+(-\\d+)?`.
    - If any VLAN id is outside 1..4094.
    - If a range has start greater than end.
    """
    if not _VLAN_ID_OR_RANGE_SHAPE.match(token):
        raise ValueError(f"{field_name} entry {token!r} must be a VLAN id or range (e.g. '100' or '100-200')")
    if "-" in token:
        start_str, end_str = token.split("-", 1)
        start, end = int(start_str), int(end_str)
        if not 1 <= start <= 4094 or not 1 <= end <= 4094:
            raise ValueError(f"{field_name} range {token!r} is out of bounds; VLAN ids must be in 1..4094")
        if start > end:
            raise ValueError(f"{field_name} range {token!r} has start greater than end")
    else:
        vid = int(token)
        if not 1 <= vid <= 4094:
            raise ValueError(f"{field_name} id {vid} is out of bounds; VLAN ids must be in 1..4094")


def _validate_allowed_vlans(value):
    """
    # Summary

    Validate `allowed_vlans` matches `"none"`, `"all"`, or a comma-separated list of VLAN ids/ranges where every id is in 1..4094 and every range start <= end.
    ND returns single-id values as JSON ints (e.g. `250`) but accepts both forms on input; this validator coerces int -> str so round-trips and idempotency
    comparisons are stable.

    Used as the `BeforeValidator` payload for the `AllowedVlans` Annotated type.

    ## Raises

    ### ValueError

    - If `value` is a non-empty string that does not match the expected shape.
    - If any VLAN id is outside 1..4094.
    - If any range has start greater than end.
    """
    if value is None or value == "":
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str):
        return value
    if value in ("none", "all"):
        return value
    if not _ALLOWED_VLANS_SHAPE.match(value):
        raise ValueError(f"allowed_vlans must be 'none', 'all', or a comma-separated list of VLAN ids/ranges (e.g. '1-200,500-2000,3000'); got {value!r}")
    for token in value.split(","):
        _validate_vlan_id_or_range(token, "allowed_vlans")
    return value


def _validate_customer_vlan_id_list(value):
    """
    # Summary

    Validate `customer_vlan_id` is a list of non-empty VLAN id or range strings where every id is in 1..4094 and every range start <= end.
    Used in `vlanMappingEntries` to identify which customer VLAN ids map to a provider VLAN id.
    ND returns single-id values as JSON ints (e.g. `250`); this validator coerces int -> str per entry, mirroring `_validate_allowed_vlans`,
    so GET responses round-trip and idempotency comparisons stay stable.

    Used as the `BeforeValidator` payload for the `CustomerVlanIdList` Annotated type.

    ## Raises

    ### ValueError

    - If any list entry is not a non-empty string (after int coercion).
    - If any entry is not a VLAN id or range, has an id outside 1..4094, or has a reversed range.
    """
    if value is None:
        return value
    if not isinstance(value, list):
        return value
    coerced = []
    for entry in value:
        if isinstance(entry, int) and not isinstance(entry, bool):
            entry = str(entry)
        if not isinstance(entry, str) or not entry:
            raise ValueError(f"customer_vlan_id entries must be non-empty strings (VLAN id or range); got {entry!r}")
        _validate_vlan_id_or_range(entry, "customer_vlan_id")
        coerced.append(entry)
    return coerced


# TODO: After all per-policy interface modules (ethernet_trunk_host, svi, port_channel_trunk_host, ...) merge to develop, consolidate
# AllowedVlans, CustomerVlanIdList, and the _validate_vlan_id_or_range helper into models/types.py so the sibling modules can share
# a single source of truth. Also introduce a shared `VlanId` type (1..4094) in the same PR and replace per-field `Field(ge=1, le=4094)`
# constraints (native_vlan, customer_inner_vlan_id, provider_vlan_id, access_vlan, ...) — the constraint is already enforced today,
# this is cosmetic/consistency cleanup. Each branch currently carries its own copy of the validators because adding VLAN-specific code
# to the loopback base branch (where types.py lives) is out of that branch's scope. Tracked in CiscoDevNet/ansible-nd#347.
# The ethernet interface-name normalizer already lives in `ethernet_common.normalize_ethernet_interface_name` (shared by the
# access, trunk-host, and routed models); loopback_interface.py still needs a different rule (it lowercases the whole name to match
# ND's GET form), so the eventual shared helper (issue #353) must be parameterized (canonical prefixes + an expand-vs-lowercase policy).
# See AsciiDescription comment in models/types.py for why Optional[...] is used at runtime instead of `... | None`.
AllowedVlans = Annotated[Optional[str], BeforeValidator(_validate_allowed_vlans)]
"""Trunk allowed-VLANs spec (`str | None`): 'none', 'all', or comma-separated VLAN ids/ranges in 1..4094."""

CustomerVlanIdList = Annotated[Optional[list[str]], BeforeValidator(_validate_customer_vlan_id_list)]
"""Customer VLAN id list (`list[str] | None`): each entry is a VLAN id or range in 1..4094 (e.g. `['100', '200-300']`)."""


class EthernetTrunkHostVlanMappingEntryModel(NDNestedModel):
    """
    # Summary

    A single VLAN mapping entry for selective dot1q-tunnel on an ethernet trunkHost interface. Maps to an element of the
    `configData.networkOS.policy.vlanMappingEntries` list in the ND API.

    ## Raises

    None
    """

    customer_inner_vlan_id: int | None = Field(default=None, alias="customerInnerVlanId", ge=1, le=4094, description="Customer inner VLAN")
    customer_vlan_id: CustomerVlanIdList = Field(
        default=None,
        alias="customerVlanId",
        description="Customer VLAN ids / ranges for selective dot1q-tunnel; each entry is a VLAN id or range string in 1..4094 (e.g. ['100', '200-300'])",
    )
    dot1q_tunnel: bool | None = Field(default=None, alias="dot1qTunnel", description="Selective dot1q-tunnel")
    provider_vlan_id: int | None = Field(default=None, alias="providerVlanId", ge=1, le=4094, description="Provider VLAN")


class EthernetTrunkHostPolicyModel(StormControlMutexMixin):
    """
    # Summary

    Policy fields for an ethernet trunkHost interface. Maps directly to the `configData.networkOS.policy` object in the ND API.

    ## Raises

    ### ValueError

    - If `allowed_vlans` is not `none`, `all`, or a comma-separated list of VLAN ids / ranges
    - If both the percentage and pps level are set for the same storm-control class in a non-response context (via `StormControlMutexMixin`)
    """

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND 4.2.1 `int_trunk_host` template defaults (schema-sourced via nd-openapi `intTrunkHostTemplate`). ND echoes these
    # for every field the user never set; the reverse pass of `get_diff` normalizes existing-side matches to absent
    # so replaced/overridden removal detection (issue #410) stays idempotent against default echoes.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        "adminState": True,
        "allowedVlans": "none",
        "bpduFilter": "default",
        "bpduGuard": "default",
        "cdp": True,
        "debounceTimer": 100,
        "duplexMode": "auto",
        "errorDetectionAcl": True,
        "fec": "auto",
        "linkType": "auto",
        "monitor": False,
        "mtu": "jumbo",
        "negotiateAuto": True,
        "netflow": False,
        "orphanPort": False,
        "pfc": False,
        "portTypeEdgeTrunk": True,
        "qos": False,
        "speed": "auto",
        "stormControl": False,
        "stormControlAction": "default",
        "vlanMapping": False,
    }

    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")
    allowed_vlans: AllowedVlans = Field(
        default=None,
        alias="allowedVlans",
        description="Allowed VLANs on the trunk: 'none', 'all', or comma-separated VLAN ids/ranges in 1..4094 (e.g. '1-200,500-2000,3000')",
    )
    bandwidth: int | None = Field(default=None, alias="bandwidth", ge=1, le=100000000, description="Bandwidth in kilobits")
    bpdu_filter: BpduFilterEnum | None = Field(default=None, alias="bpduFilter", description="Configure spanning-tree BPDU filter")
    bpdu_guard: BpduGuardEnum | None = Field(default=None, alias="bpduGuard", description="Enable spanning-tree BPDU guard")
    cdp: bool | None = Field(default=None, alias="cdp", description="Enable CDP on the interface")
    debounce_timer: int | None = Field(default=None, alias="debounceTimer", ge=0, le=20000, description="Link debounce timer in milliseconds")
    debounce_linkup_timer: int | None = Field(
        default=None, alias="debounceLinkupTimer", ge=1000, le=10000, description="Link debounce link-up timer in milliseconds"
    )
    description: AsciiDescription = Field(default=None, alias="description", max_length=254, description="Interface description")
    duplex_mode: DuplexModeEnum | None = Field(default=None, alias="duplexMode", description="Port duplex mode")
    error_detection_acl: bool | None = Field(default=None, alias="errorDetectionAcl", description="Enable error detection for ACL installation failures")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    fec: FecEnum | None = Field(default=None, alias="fec", description="Forward error correction mode")
    inherit_bandwidth: int | None = Field(
        default=None, alias="inheritBandwidth", ge=1, le=100000000, description="Inherit bandwidth in kilobits for sub-interfaces"
    )
    link_type: LinkTypeEnum | None = Field(default=None, alias="linkType", description="Spanning-tree link type")
    monitor: bool | None = Field(default=None, alias="monitor", description="Enable switchport monitor for SPAN/ERSPAN")
    mtu: MtuEnum | None = Field(default=None, alias="mtu", description="Interface MTU")
    native_vlan: int | None = Field(default=None, alias="nativeVlan", ge=1, le=4094, description="Native VLAN for the trunk interface")
    negotiate_auto: bool | None = Field(default=None, alias="negotiateAuto", description="Enable link auto-negotiation")
    netflow: bool | None = Field(default=None, alias="netflow", description="Enable Netflow on the interface")
    netflow_monitor: str | None = Field(default=None, alias="netflowMonitor", description="Layer 2 Netflow monitor name")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler", description="Netflow sampler name")
    orphan_port: bool | None = Field(default=None, alias="orphanPort", description="Enable vPC orphan port")
    pfc: bool | None = Field(default=None, alias="pfc", description="Enable priority flow control")
    policy_type: Literal["trunkHost"] = Field(
        alias="policyType", description="Trunk-host policy template discriminator; injected as `trunkHost` when omitted (see `default_policy_type`)"
    )

    @model_validator(mode="before")
    @classmethod
    def default_policy_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `policyType: trunkHost` when the input omits the discriminator (`ethernet_common.default_policy_type`).

        ## Raises

        None
        """
        return default_policy_type(data, TrunkHostPolicyTypeEnum.TRUNK_HOST.value)

    port_type_edge_trunk: bool | None = Field(default=None, alias="portTypeEdgeTrunk", description="Enable spanning-tree edge port behavior")
    qos: bool | None = Field(default=None, alias="qos", description="Enable QoS configuration for this interface")
    qos_policy: str | None = Field(default=None, alias="qosPolicy", description="Custom QoS policy name")
    queuing_policy: str | None = Field(default=None, alias="queuingPolicy", description="Custom queuing policy name")
    speed: SpeedEnum | None = Field(default=None, alias="speed", description="Interface speed")
    storm_control: bool | None = Field(default=None, alias="stormControl", description="Enable traffic storm control")
    storm_control_action: StormControlActionEnum | None = Field(
        default=None, alias="stormControlAction", description="Storm control action on threshold violation"
    )
    storm_control_broadcast_level: float | None = Field(
        default=None,
        alias="stormControlBroadcastLevel",
        ge=0.0,
        le=100.0,
        description="Broadcast storm control level in percentage (0.00-100.00)",
    )
    storm_control_broadcast_level_pps: int | None = Field(
        default=None,
        alias="stormControlBroadcastLevelPps",
        ge=0,
        le=200000000,
        description="Broadcast storm control level in packets per second",
    )
    storm_control_multicast_level: float | None = Field(
        default=None,
        alias="stormControlMulticastLevel",
        ge=0.0,
        le=100.0,
        description="Multicast storm control level in percentage (0.00-100.00)",
    )
    storm_control_multicast_level_pps: int | None = Field(
        default=None,
        alias="stormControlMulticastLevelPps",
        ge=0,
        le=200000000,
        description="Multicast storm control level in packets per second",
    )
    storm_control_unicast_level: float | None = Field(
        default=None,
        alias="stormControlUnicastLevel",
        ge=0.0,
        le=100.0,
        description="Unicast storm control level in percentage (0.00-100.00)",
    )
    storm_control_unicast_level_pps: int | None = Field(
        default=None,
        alias="stormControlUnicastLevelPps",
        ge=0,
        le=200000000,
        description="Unicast storm control level in packets per second",
    )
    vlan_mapping: bool | None = Field(default=None, alias="vlanMapping", description="Enable VLAN mapping on the interface")
    vlan_mapping_entries: list[EthernetTrunkHostVlanMappingEntryModel] | None = Field(
        default=None, alias="vlanMappingEntries", description="List of VLAN mapping entries; required when `vlan_mapping` is true"
    )

    @model_validator(mode="after")
    def _validate_vlan_mapping_entries_present(self) -> EthernetTrunkHostPolicyModel:
        """
        # Summary

        Reject enabling `vlan_mapping` without supplying any `vlan_mapping_entries`.

        The DOCUMENTATION and field description state that `vlan_mapping_entries` is required when `vlan_mapping` is true. Enforcing it at the model
        layer fails an incomplete policy early with a clear error instead of accepting it and deferring the outcome to a later layer or to ND.

        ## Raises

        ### ValueError

        - If `vlan_mapping` is true and `vlan_mapping_entries` is missing or empty.
        """
        if self.vlan_mapping is True and not self.vlan_mapping_entries:
            raise ValueError("vlan_mapping_entries must be provided when vlan_mapping is true.")
        return self


class XeEthernetTrunkHostPolicyModel(InterfacePolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeTrunkHost` template (`ios_xe_int_trunk_host`). Maps to `configData.networkOS.policy` where
    `policyType == "iosXeTrunkHost"`. A strict subset of the NX-OS branch: no `native_vlan` / `vlan_mapping`, `description` max
    length is 200, `mtu` is an integer 1500-9216 (NX-OS takes the `default` / `jumbo` enum), and `speed` uses the XE enum. The
    4.3.1-only `deviceTrackingPolicy` / `flowMonitors` fields are deliberately not modeled while both 4.2.1 and 4.3.1 are supported.

    ## Raises

    ### ValueError

    - If `allowed_vlans` is not `none`, `all`, or a comma-separated list of VLAN ids / ranges (shared `AllowedVlans` parser)
    """

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND `ios_xe_int_trunk_host` template defaults (schema-sourced via nd-openapi `iosXeIntTrunkHostTemplate`, identical on
    # 4.2.1 and 4.3.1), in the model's dumped form. The orchestrator derives its unconfigured-default query filter from this table.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        **InterfacePolicyStrictBase.reverse_diff_defaults,
        "allowedVlans": "none",
        "bpduGuard": "default",
        "mtu": 1500,
        "speed": "auto",
    }

    policy_type: Literal["iosXeTrunkHost"] = Field(
        alias="policyType",
        description="IOS-XE trunk-host policy template discriminator; injected as `iosXeTrunkHost` when omitted (see `default_policy_type`)",
    )

    @model_validator(mode="before")
    @classmethod
    def default_policy_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `policyType: iosXeTrunkHost` when the input omits the discriminator (`ethernet_common.default_policy_type`).

        ## Raises

        None
        """
        return default_policy_type(data, XeTrunkHostPolicyTypeEnum.IOS_XE_TRUNK_HOST.value)

    allowed_vlans: AllowedVlans = Field(
        default=None,
        alias="allowedVlans",
        description="Allowed VLANs: 'none', 'all', or a comma-separated list of VLAN ids/ranges (e.g. '1-200,500-2000,3000')",
    )
    bpdu_guard: BpduGuardEnum | None = Field(default=None, alias="bpduGuard", description="Enable spanning-tree BPDU guard")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=200, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    mtu: int | None = Field(default=None, alias="mtu", ge=1500, le=9216, description="Interface MTU (1500-9216)")
    speed: XeEthernetSpeedEnum | None = Field(default=None, alias="speed", description="Interface speed")

    @field_validator("mtu", mode="before")
    @classmethod
    def coerce_mtu(cls, value):
        """
        # Summary

        Coerce a numeric-string `mtu` to `int`. The shared argspec `mtu` option is `str`-typed so the NX-OS branch can take its
        `default` / `jumbo` enum, which means an IOS-XE value arrives from Ansible as e.g. `"9000"`. Non-numeric strings are left
        for the `int` field to reject with a clear error.

        ## Raises

        None
        """
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
        return value


class XeEthernetTrunkHostNetworkOSModel(NDNestedModel):
    """
    # Summary

    IOS-XE branch of the network-OS container for a trunk-mode ethernet interface. Selected from the outer union when
    `networkOSType == "ios-xe"`.

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field. The Literal constrains the value.
    network_os_type: Literal["ios-xe"] = Field(default="ios-xe", alias="networkOSType", description="Network OS (platform) type discriminator")
    policy: XeEthernetTrunkHostPolicyModel | None = Field(default=None, alias="policy")


class EthernetTrunkHostNetworkOSModel(NDNestedModel):
    """
    # Summary

    NX-OS branch of the network-OS container for a trunk-mode ethernet interface. Selected from the outer union when
    `networkOSType == "nx-os"` (the injected default when the input omits it).

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field. The Literal constrains the value.
    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType", description="Network OS (platform) type discriminator")
    policy: EthernetTrunkHostPolicyModel | None = Field(default=None, alias="policy")


class EthernetTrunkHostConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for a trunk-mode ethernet interface. Maps to `configData` in the ND API.

    ## Raises

    None
    """

    mode: Literal["trunk"] = Field(default="trunk", alias="mode", frozen=True)
    network_os: EthernetTrunkHostNetworkOSModel | XeEthernetTrunkHostNetworkOSModel = Field(
        default_factory=EthernetTrunkHostNetworkOSModel, alias="networkOS", discriminator="network_os_type"
    )

    @model_validator(mode="before")
    @classmethod
    def default_network_os_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `networkOSType: nx-os` on the `network_os` input when it omits the discriminator (key absent, or `None` as the
        argspec passes an omitted option), so playbooks written before the IOS-XE branch existed keep selecting the NX-OS branch
        (`ethernet_common.default_network_os_type`).

        ## Raises

        None
        """
        if not isinstance(data, dict):
            return data
        for key in ("network_os", "networkOS"):
            if isinstance(data.get(key), dict):
                return {**data, key: default_network_os_type(data[key])}
        return data


class EthernetTrunkHostInterfaceModel(NDBaseModel):
    """
    # Summary

    Trunk-mode ethernet host interface configuration for Nexus Dashboard (NX-OS `trunkHost` or IOS-XE `iosXeTrunkHost`).

    Uses a composite identifier (`switch_ip`, `interface_name`). The nested model structure mirrors the ND Manage
    Interfaces API payload, so `to_payload()` and `from_response()` work via standard Pydantic serialization.

    ## Raises

    None
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[list[str] | None] = ["switch_ip", "interface_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "composite"

    # --- Serialization Configuration ---

    payload_exclude_fields: ClassVar[set[str]] = {"switch_ip"}

    # --- Fields ---

    switch_ip: str = Field(alias="switchIp")
    interface_name: str = Field(alias="interfaceName")
    interface_type: Literal["ethernet"] = Field(default="ethernet", alias="interfaceType", frozen=True)
    config_data: EthernetTrunkHostConfigDataModel | None = Field(default=None, alias="configData")

    @property
    def policy_type(self) -> str | None:
        """
        # Summary

        The `policy_type` discriminator from `config_data.network_os.policy`, or `None` when `config_data` or `policy` is
        unset (e.g. a `state: deleted` identifier-only item).

        ## Raises

        None
        """
        if self.config_data is None or self.config_data.network_os.policy is None:
            return None
        return self.config_data.network_os.policy.policy_type

    @field_validator("interface_name", mode="before")
    @classmethod
    def normalize_interface_name(cls, value):
        """
        # Summary

        Normalize the leading alphabetic prefix of an interface name to its wire-canonical form so that user-supplied casing or
        abbreviations round-trip against the wire (`ethernet_common.normalize_ethernet_interface_name`). Examples:

        - `ethernet1/1`, `ETHERNET1/1`, `eth1/1`, `e1/1` -> `Ethernet1/1`
        - `gigabitethernet1/0/1`, `gi1/0/1` -> `GigabitEthernet1/0/1`
        - `Ethernet1/1.10` -> `Ethernet1/1.10` (idempotent; digits and separators preserved verbatim)

        An ambiguous or unrecognized prefix (e.g. `t1/1`, `TenGigabitEthernet1/1/1`) passes through verbatim - never
        re-cased - so correctly-typed names of interface families outside the canonical list are not corrupted.

        ## Raises

        None
        """
        return normalize_ethernet_interface_name(value)

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict:
        """
        # Summary

        Return the Ansible argument spec for the `nd_interface_ethernet_trunk_host` module.

        ## Raises

        None
        """
        return dict(
            fabric_name=dict(type="str", required=True),
            config=dict(
                type="list",
                elements="dict",
                required=True,
                options=dict(
                    switch_ip=dict(type="str", required=True),
                    interface_names=dict(type="list", elements="str", required=True),
                    config_data=dict(
                        type="dict",
                        options=dict(
                            network_os=dict(
                                type="dict",
                                options=dict(
                                    network_os_type=dict(type="str", default="nx-os", choices=["nx-os", "ios-xe"]),
                                    policy=dict(
                                        type="dict",
                                        options=dict(
                                            policy_type=dict(
                                                type="str",
                                                choices=[TrunkHostPolicyTypeEnum.TRUNK_HOST.value, XeTrunkHostPolicyTypeEnum.IOS_XE_TRUNK_HOST.value],
                                            ),
                                            admin_state=dict(type="bool"),
                                            allowed_vlans=dict(type="str"),
                                            bandwidth=dict(type="int"),
                                            bpdu_filter=dict(type="str", choices=[e.value for e in BpduFilterEnum]),
                                            bpdu_guard=dict(type="str", choices=[e.value for e in BpduGuardEnum]),
                                            cdp=dict(type="bool"),
                                            debounce_timer=dict(type="int"),
                                            debounce_linkup_timer=dict(type="int"),
                                            description=dict(type="str"),
                                            duplex_mode=dict(type="str", choices=[e.value for e in DuplexModeEnum]),
                                            error_detection_acl=dict(type="bool"),
                                            extra_config=dict(type="str"),
                                            fec=dict(type="str", choices=[e.value for e in FecEnum]),
                                            inherit_bandwidth=dict(type="int"),
                                            link_type=dict(type="str", choices=[e.value for e in LinkTypeEnum]),
                                            monitor=dict(type="bool"),
                                            mtu=dict(type="str"),
                                            native_vlan=dict(type="int"),
                                            negotiate_auto=dict(type="bool"),
                                            netflow=dict(type="bool"),
                                            netflow_monitor=dict(type="str"),
                                            netflow_sampler=dict(type="str"),
                                            orphan_port=dict(type="bool"),
                                            pfc=dict(type="bool"),
                                            port_type_edge_trunk=dict(type="bool"),
                                            qos=dict(type="bool"),
                                            qos_policy=dict(type="str"),
                                            queuing_policy=dict(type="str"),
                                            speed=dict(type="str", choices=_SPEED_ARGSPEC_CHOICES),
                                            storm_control=dict(type="bool"),
                                            storm_control_action=dict(type="str", choices=[e.value for e in StormControlActionEnum]),
                                            storm_control_broadcast_level=dict(type="float"),
                                            storm_control_broadcast_level_pps=dict(type="int"),
                                            storm_control_multicast_level=dict(type="float"),
                                            storm_control_multicast_level_pps=dict(type="int"),
                                            storm_control_unicast_level=dict(type="float"),
                                            storm_control_unicast_level_pps=dict(type="int"),
                                            vlan_mapping=dict(type="bool"),
                                            vlan_mapping_entries=dict(
                                                type="list",
                                                elements="dict",
                                                options=dict(
                                                    customer_inner_vlan_id=dict(type="int"),
                                                    customer_vlan_id=dict(type="list", elements="str"),
                                                    dot1q_tunnel=dict(type="bool"),
                                                    provider_vlan_id=dict(type="int"),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "replaced", "overridden", "deleted"],
            ),
        )
