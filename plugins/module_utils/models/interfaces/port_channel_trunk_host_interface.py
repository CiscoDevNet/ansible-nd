# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Port-channel trunk-host interface Pydantic models for Nexus Dashboard (NX-OS `trunkPoHost`, IOS-XE `iosXeTrunkPoHost`; issue #537).

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload
structure for port-channel trunk-host interfaces. The playbook config uses the same nesting
so that `to_payload()` and `from_response()` work via standard Pydantic serialization with no
custom wrapping or flattening.

The port-channel policy is the single source of truth for member configuration. Member ethernet
interfaces inherit trunk-mode settings from the port-channel; users do not pre-configure members.

## Model Hierarchy

- `PortChannelTrunkHostInterfaceModel` (top-level, `NDBaseModel`)
    - `switch_ip` (composite identifier)
    - `interface_name` (composite identifier; e.g. `port-channel501`)
    - `interface_type` (hardcoded: "portChannel")
    - `config_data` -> `PortChannelTrunkHostConfigDataModel`
        - `mode` (hardcoded: "trunk")
        - `network_os` -> `PortChannelTrunkHostNetworkOSModel | XePortChannelTrunkHostNetworkOSModel` (discriminated union on
          `network_os_type`; injected as `nx-os` when omitted so pre-#537 playbooks are unchanged)
            - `PortChannelTrunkHostNetworkOSModel` (`network_os_type: "nx-os"`)
                - `policy` -> `PortChannelTrunkHostPolicyModel` (`policy_type: "trunkPoHost"`, injected when omitted)
                    - `admin_state`, `allowed_vlans`, `native_vlan`, `ports`, `port_channel_mode`, `lacp_rate`,
                      `bpdu_guard`, `description`, `vlan_mapping`, `vlan_mapping_entries`, etc.
            - `XePortChannelTrunkHostNetworkOSModel` (`network_os_type: "ios-xe"`)
                - `policy` -> `XePortChannelTrunkHostPolicyModel` (`policy_type: "iosXeTrunkPoHost"`, injected when omitted)

`policy_type` is optional on input: each network OS has exactly one managed trunk-host port-channel policy type today, so it is
derived from `network_os_type` (`ethernet_common.default_policy_type`). An explicit value is still accepted and validated.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, ClassVar, Literal, Optional  # Optional needed for Annotated runtime expr (see types.py)

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BeforeValidator,
    Field,
    SerializationInfo,
    field_validator,
    model_serializer,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    BpduFilterEnum,
    BpduGuardEnum,
    DuplexModeEnum,
    LacpRateEnum,
    LinkTypeEnum,
    MtuEnum,
    PortChannelModeEnum,
    SpeedEnum,
    StormControlActionEnum,
    TrunkPoHostPolicyTypeEnum,
    XePortChannelModeEnum,
    XeTrunkPoHostPolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_common import (
    default_network_os_type,
    default_policy_type,
    normalize_member_interface_names,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.policy_base import InterfacePolicyStrictBase
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.storm_control import StormControlMutexMixin
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription

# Shape regex: "none", "all", or comma-separated VLAN ids/ranges. Range bounds are validated separately.
_ALLOWED_VLANS_SHAPE = re.compile(r"^(none|all|(\d+(-\d+)?)(,\d+(-\d+)?)*)$")
# Single VLAN id or range token (e.g. "100" or "100-200"). Range bounds are validated separately.
_VLAN_ID_OR_RANGE_SHAPE = re.compile(r"^\d+(-\d+)?$")

# The lowercase identifier form (`port-channel103`) with its numeric id captured, used to rebuild ND's IOS-XE
# create-side canonical spelling `Port-channel103` in payload-mode dumps only.
_XE_CREATE_NAME_RE = re.compile(r"^port-channel(\d+)$")


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
    # TODO(4.2.1) interface-get-field-normalization
    # ND echoes a single-id allowed_vlans as a JSON int (e.g. 250) on GET even though POST/PUT accept (and the
    # spec types it as) a string. We coerce int -> str here so a GET response round-trips against the str the
    # user supplied and idempotency comparisons stay stable. Remove when the GET-side retype is fixed.
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

    Used as the `BeforeValidator` payload for the `CustomerVlanIdList` Annotated type.

    ## Raises

    ### ValueError

    - If any list entry is not a non-empty string.
    - If any entry is not a VLAN id or range, has an id outside 1..4094, or has a reversed range.
    """
    if value is None:
        return value
    if not isinstance(value, list):
        return value
    for entry in value:
        if not isinstance(entry, str) or not entry:
            raise ValueError(f"customer_vlan_id entries must be non-empty strings (VLAN id or range); got {entry!r}")
        _validate_vlan_id_or_range(entry, "customer_vlan_id")
    return value


# TODO: After all per-policy interface modules (ethernet_trunk_host, svi, ...) merge to develop, consolidate
# AllowedVlans, CustomerVlanIdList, and the _validate_vlan_id_or_range helper into models/types.py so the
# sibling modules can share a single source of truth. Also introduce a shared `VlanId` type (1..4094) in the
# same PR and replace per-field `Field(ge=1, le=4094)` constraints (native_vlan, customer_inner_vlan_id,
# provider_vlan_id, access_vlan, ...) — the constraint is already enforced today, this is cosmetic/consistency
# cleanup. Each branch currently carries its own copy of the validators because adding VLAN-specific code to the
# loopback base branch (where types.py lives) is out of that branch's scope. Tracked in CiscoDevNet/ansible-nd#347.
# See AsciiDescription comment in models/types.py for why Optional[...] is used at runtime instead of `... | None`.
AllowedVlans = Annotated[Optional[str], BeforeValidator(_validate_allowed_vlans)]
"""Trunk allowed-VLANs spec (`str | None`): 'none', 'all', or comma-separated VLAN ids/ranges in 1..4094."""

CustomerVlanIdList = Annotated[Optional[list[str]], BeforeValidator(_validate_customer_vlan_id_list)]
"""Customer VLAN id list (`list[str] | None`): each entry is a VLAN id or range in 1..4094 (e.g. `['100', '200-300']`)."""


class PortChannelTrunkHostVlanMappingEntryModel(NDNestedModel):
    """
    # Summary

    A single VLAN mapping entry for a trunk port-channel. Maps to one element of `policy.vlanMappingEntries`
    in the ND API. Use entries to translate customer VLAN ids to provider VLAN ids, optionally with selective
    dot1q-tunnel mode.

    ## Raises

    None
    """

    customer_inner_vlan_id: int | None = Field(
        default=None, alias="customerInnerVlanId", ge=1, le=4094, description="Inner customer VLAN id (selective dot1q-tunnel only)"
    )
    customer_vlan_id: CustomerVlanIdList = Field(
        default=None,
        alias="customerVlanId",
        description="Customer VLAN id list; each entry is a VLAN id or range string in 1..4094 (e.g. ['100', '200-300'])",
    )
    dot1q_tunnel: bool | None = Field(default=None, alias="dot1qTunnel", description="Use selective dot1q-tunnel mode for this entry")
    provider_vlan_id: int | None = Field(default=None, alias="providerVlanId", ge=1, le=4094, description="Provider VLAN id")


class PortChannelTrunkHostPolicyModel(StormControlMutexMixin):
    """
    # Summary

    Policy fields for the NX-OS `trunkPoHost` template (`int_port_channel_trunk_host`). Maps directly to the
    `configData.networkOS.policy` object in the ND API where `policyType == "trunkPoHost"`.

    The `ports` field carries the list of member interface names (e.g. `Ethernet1/1`). Member interfaces inherit
    trunk-mode configuration from this policy; modifying a member's standalone configuration while it is a
    port-channel member is restricted by the ethernet orchestrators.

    ## Raises

    ### ValueError

    - If `allowed_vlans` is set and does not match `none`, `all`, or comma-separated VLAN ranges.
    - If `netflow` is true and `netflow_monitor` is missing or empty.
    """

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND 4.2.1 `int_port_channel_trunk_host` template defaults (schema-sourced via nd-openapi `intPortChannelTrunkHostTemplate`). ND echoes these
    # for every field the user never set; the reverse pass of `get_diff` normalizes existing-side matches to absent
    # so replaced/overridden removal detection (issue #410) stays idempotent against default echoes.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        "adminState": True,
        "allowedVlans": "none",
        "bpduFilter": "default",
        "bpduGuard": "enable",
        "cdp": True,
        "copyDescription": False,
        "duplexMode": "auto",
        "lacpPortPriority": 32768,
        "lacpRate": "normal",
        "lacpSuspend": False,
        "linkType": "auto",
        "monitor": False,
        "mtu": "jumbo",
        "negotiateAuto": True,
        "netflow": False,
        "orphanPort": False,
        "pfc": False,
        "portChannelMode": "active",
        "portTypeEdgeTrunk": True,
        "qos": False,
        "speed": "auto",
        "stormControl": False,
        "stormControlAction": "default",
        "vlanMapping": False,
    }

    # `ptp` is deliberately NOT modeled (deviation: interface-get-undocumented-ptp-field). ND injects a `ptp`
    # boolean into every port-channel policy GET even though intPortChannelTrunkHostTemplate declares no such
    # property. Lab probes (2026-08-12, SITE1, ND 4.2.1.10) covered all three fabric-PTP regimes — disabled,
    # enabled-not-deployed, and fully deployed — and in every regime a client-sent `ptp` is persist-but-inert:
    # ND stores and echoes it but generates zero pending CLI. ND's own PTP CLI lands only on physical interfaces
    # (never under port-channels, matching NX-OS's per-physical-port PTP model), and the fabric-PTP deploy
    # rewrites the stored value fabric-wide regardless of per-interface intent, so exposing the field would fake
    # per-interface control. The injected echo is dropped at parse time by `extra="ignore"`, same as the sibling
    # ethernet/vPC models. Do not re-add the field from wire observation alone; it belongs only if a future
    # template declares it.

    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")
    allowed_vlans: AllowedVlans = Field(
        default=None,
        alias="allowedVlans",
        description="Trunk allowed VLANs ('none', 'all', or comma-separated VLAN ids/ranges in 1..4094, e.g. '100-200,300')",
    )
    bandwidth: int | None = Field(default=None, alias="bandwidth", ge=1, le=100000000, description="Interface bandwidth in kilobits per second")
    bpdu_filter: BpduFilterEnum | None = Field(default=None, alias="bpduFilter", description="Configure spanning-tree BPDU filter")
    bpdu_guard: BpduGuardEnum | None = Field(default=None, alias="bpduGuard", description="Enable spanning-tree BPDU guard")
    cdp: bool | None = Field(default=None, alias="cdp", description="Enable CDP on the interface")
    copy_description: bool | None = Field(default=None, alias="copyDescription", description="Propagate the port-channel description to all member interfaces")
    description: AsciiDescription = Field(default=None, alias="description", max_length=254, description="Interface description")
    duplex_mode: DuplexModeEnum | None = Field(default=None, alias="duplexMode", description="Port duplex mode")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    inherit_bandwidth: int | None = Field(
        default=None, alias="inheritBandwidth", ge=1, le=100000000, description="Inherited interface bandwidth in kilobits per second"
    )
    lacp_port_priority: int | None = Field(default=None, alias="lacpPortPriority", ge=1, le=65535, description="LACP port priority (1-65535, default 32768)")
    lacp_rate: LacpRateEnum | None = Field(default=None, alias="lacpRate", description="LACP rate (normal=30s, fast=1s)")
    lacp_suspend: bool | None = Field(default=None, alias="lacpSuspend", description="Suspend port if LACP PDUs not received")
    link_type: LinkTypeEnum | None = Field(default=None, alias="linkType", description="Spanning-tree link type")
    monitor: bool | None = Field(default=None, alias="monitor", description="Enable switchport monitor for SPAN/ERSPAN")
    mtu: MtuEnum | None = Field(default=None, alias="mtu", description="Interface MTU")
    native_vlan: int | None = Field(default=None, alias="nativeVlan", ge=1, le=4094, description="Trunk native VLAN id")
    negotiate_auto: bool | None = Field(default=None, alias="negotiateAuto", description="Enable link auto-negotiation")
    netflow: bool | None = Field(default=None, alias="netflow", description="Enable Netflow on the interface")
    netflow_monitor: str | None = Field(default=None, alias="netflowMonitor", description="Layer 2 Netflow monitor name (required when `netflow=true`)")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler", description="Netflow sampler name")
    orphan_port: bool | None = Field(
        default=None, alias="orphanPort", description="Configure as a vPC orphan port (suspended by secondary peer on vPC failure)"
    )
    pfc: bool | None = Field(default=None, alias="pfc", description="Enable Priority Flow Control")
    policy_type: Literal["trunkPoHost"] = Field(
        alias="policyType",
        description="Trunk-host port-channel policy template discriminator; injected as `trunkPoHost` when omitted (see `default_policy_type`)",
    )

    @model_validator(mode="before")
    @classmethod
    def default_policy_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `policyType: trunkPoHost` when the input omits the discriminator (`ethernet_common.default_policy_type`).

        ## Raises

        None
        """
        return default_policy_type(data, TrunkPoHostPolicyTypeEnum.TRUNK_PO_HOST.value)

    port_channel_mode: PortChannelModeEnum | None = Field(default=None, alias="portChannelMode", description="Port-channel mode (on/active/passive)")
    port_type_edge_trunk: bool | None = Field(default=None, alias="portTypeEdgeTrunk", description="Configure as edge trunk port (PortFast on trunk)")
    ports: list[str] | None = Field(default=None, alias="ports", description="Member interface names (e.g. ['Ethernet1/1', 'Ethernet1/2'])")
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
    vlan_mapping: bool | None = Field(default=None, alias="vlanMapping", description="Enable VLAN mapping on the trunk")
    vlan_mapping_entries: list[PortChannelTrunkHostVlanMappingEntryModel] | None = Field(
        default=None, alias="vlanMappingEntries", description="VLAN mapping entries (used when vlan_mapping is enabled)"
    )

    # --- Validators ---

    @model_validator(mode="after")
    def _validate_netflow_monitor_present(self) -> PortChannelTrunkHostPolicyModel:
        """
        # Summary

        Reject enabling `netflow` without supplying a `netflow_monitor`.

        The DOCUMENTATION and field description state that `netflow_monitor` is required when `netflow` is true. Enforcing it at the model layer
        fails an incomplete policy early with a clear error instead of pushing a netflow config with no monitor and deferring the outcome to ND.

        ## Raises

        ### ValueError

        - If `netflow` is true and `netflow_monitor` is missing or empty.
        """
        if self.netflow is True and not self.netflow_monitor:
            raise ValueError("netflow_monitor must be provided when netflow is true.")
        return self

    @field_validator("ports", mode="before")
    @classmethod
    def normalize_ports(cls, value):
        """
        # Summary

        Normalize each member name to its wire-canonical prefix through the shared cross-OS helper
        (`ethernet_common.normalize_member_interface_names`): `e1/1` / `eth1/1` -> `Ethernet1/1`, `gi1/0/4` -> `GigabitEthernet1/0/4`,
        any other family verbatim. Members are always physical ethernet ports; matching the wire key exactly keeps idempotency.

        ## Raises

        None
        """
        return normalize_member_interface_names(value)


class XePortChannelTrunkHostPolicyModel(InterfacePolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeTrunkPoHost` template (`ios_xe_int_port_channel_trunk_host`). Maps to `configData.networkOS.policy`
    where `policyType == "iosXeTrunkPoHost"`. A strict subset of the NX-OS branch: no `native_vlan` / `vlan_mapping` / LACP / storm-control /
    QoS block, `description` max length 200, `mtu` an integer 1500-9198, `port_channel_mode` adds the PAgP `auto` / `desirable` values. The
    4.3.1-only `deviceTrackingPolicy` / `flowMonitors` fields are deliberately not modeled while both 4.2.1 and 4.3.1 are supported. ND
    injects a read-only `portChannelId` on the echo, dropped by the read-mode stripping in `InterfacePolicyStrictBase`.

    ## Raises

    ### ValueError

    - If `allowed_vlans` is not `none`, `all`, or a comma-separated list of VLAN ids / ranges (shared `AllowedVlans` parser)
    """

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND `ios_xe_int_port_channel_trunk_host` template defaults as ECHOED (lab 2026-09-15, 4.2.1.10 and 4.3.1.175); no mtu is injected.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        **InterfacePolicyStrictBase.reverse_diff_defaults,
        "allowedVlans": "none",
        "bpduGuard": "enable",
        "portChannelMode": "active",
    }
    # ND 4.3.1 rejects an iosXeTrunkPoHost create that omits allowedVlans ("Validation failed for following fields: [allowedVlans]",
    # lab 2026-09-15); 4.2.1 stores "none" either way. Payload-only: see `NDBaseModel.payload_defaults` (issue #564 class).
    payload_defaults: ClassVar[dict[str, Any]] = {"allowedVlans": "none"}

    policy_type: Literal["iosXeTrunkPoHost"] = Field(
        alias="policyType", description="IOS-XE trunk port-channel policy template discriminator; injected as `iosXeTrunkPoHost` when omitted"
    )

    @model_validator(mode="before")
    @classmethod
    def default_policy_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `policyType: iosXeTrunkPoHost` when the input omits the discriminator (`ethernet_common.default_policy_type`).

        ## Raises

        None
        """
        return default_policy_type(data, XeTrunkPoHostPolicyTypeEnum.IOS_XE_TRUNK_PO_HOST.value)

    allowed_vlans: AllowedVlans = Field(
        default=None,
        alias="allowedVlans",
        description="Trunk allowed VLANs ('none', 'all', or comma-separated VLAN ids/ranges in 1..4094)",
    )
    bpdu_guard: BpduGuardEnum | None = Field(default=None, alias="bpduGuard", description="Enable spanning-tree BPDU guard")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=200, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    mtu: int | None = Field(default=None, alias="mtu", ge=1500, le=9198, description="Port-channel MTU (1500-9198)")
    port_channel_mode: XePortChannelModeEnum | None = Field(
        default=None, alias="portChannelMode", description="Port-channel mode (on/active/passive/auto/desirable)"
    )
    ports: list[str] | None = Field(default=None, alias="ports", description="Member interface names (e.g. ['GigabitEthernet1/0/4'])")

    @field_validator("mtu", mode="before")
    @classmethod
    def coerce_mtu(cls, value):
        """
        # Summary

        Coerce a numeric-string `mtu` to `int`: the shared argspec `mtu` option is `str`-typed so the NX-OS branch can take its
        `default` / `jumbo` enum. Non-numeric strings are left for the `int` field to reject.

        ## Raises

        None
        """
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
        return value

    @field_validator("ports", mode="before")
    @classmethod
    def normalize_ports(cls, value):
        """
        # Summary

        Normalize each member name through `ethernet_common.normalize_member_interface_names` (see the NX-OS branch).

        ## Raises

        None
        """
        return normalize_member_interface_names(value)


class XePortChannelTrunkHostNetworkOSModel(NDNestedModel):
    """
    # Summary

    IOS-XE branch of the network-OS container for a trunk-host port-channel. Selected from the outer union when
    `networkOSType == "ios-xe"`.

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field. The Literal constrains the value.
    network_os_type: Literal["ios-xe"] = Field(default="ios-xe", alias="networkOSType", description="Network OS (platform) type discriminator")
    policy: XePortChannelTrunkHostPolicyModel | None = Field(default=None, alias="policy")


class PortChannelTrunkHostNetworkOSModel(NDNestedModel):
    """
    # Summary

    NX-OS branch of the network-OS container for a trunk-host port-channel. Maps to `configData.networkOS` in the ND API.
    Selected from the outer union when `networkOSType == "nx-os"` (the injected default when the input omits it).

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field. The Literal constrains the value.
    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType", description="Network OS (platform) type discriminator")
    policy: PortChannelTrunkHostPolicyModel | None = Field(default=None, alias="policy")


class PortChannelTrunkHostConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for a trunk-host port-channel interface. Maps to `configData` in the ND API.

    ## Raises

    None
    """

    mode: Literal["trunk"] = Field(default="trunk", alias="mode", frozen=True)
    network_os: PortChannelTrunkHostNetworkOSModel | XePortChannelTrunkHostNetworkOSModel = Field(
        default_factory=PortChannelTrunkHostNetworkOSModel, alias="networkOS", discriminator="network_os_type"
    )

    @model_validator(mode="before")
    @classmethod
    def default_network_os_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `networkOSType: nx-os` on the `network_os` input when it omits the discriminator (key absent, or `None` as the argspec
        passes an omitted option), so playbooks written before the IOS-XE branch existed keep selecting the NX-OS branch
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


class PortChannelTrunkHostInterfaceModel(NDBaseModel):
    """
    # Summary

    Trunk-host port-channel interface configuration for Nexus Dashboard (NX-OS `trunkPoHost` or IOS-XE `iosXeTrunkPoHost`).

    Uses a composite identifier (`switch_ip`, `interface_name`). The nested model structure mirrors the ND Manage
    Interfaces API payload, so `to_payload()` and `from_response()` work via standard Pydantic serialization.

    The `interface_name` is the port-channel's own name (e.g. `port-channel501`), not a member interface. Member
    interfaces are listed in `config_data.network_os.policy.ports`.

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
    interface_type: Literal["portChannel"] = Field(default="portChannel", alias="interfaceType", frozen=True)
    config_data: PortChannelTrunkHostConfigDataModel | None = Field(default=None, alias="configData")

    @property
    def policy_type(self) -> str | None:
        """
        # Summary

        The `policy_type` discriminator from `config_data.network_os.policy`, or `None` when `config_data` or `policy` is unset
        (e.g. a `state: deleted` identifier-only item).

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

        Normalize the port-channel interface name to lowercase to match ND API convention (e.g. `Port-Channel501` ->
        `port-channel501`).

        ## Raises

        None
        """
        if isinstance(value, str):
            return value.lower()
        return value

    @model_serializer(mode="wrap")
    def _canonical_xe_create_name(self, handler, info: SerializationInfo):
        """
        # Summary

        Emit the IOS-XE canonical spelling `Port-channel<N>` as `interfaceName` in payload-mode dumps of the `ios-xe` branch, leaving the
        lowercase identifier untouched in config and diff dumps and for the NX-OS branch. Also applies `payload_defaults` (this wrap
        serializer replaces `NDBaseModel._serialize_with_payload_defaults`).

        ## Raises

        ### AssertionError

        - If the wrapped handler returns a non-`dict` (model-level serialization always yields a dict).
        """
        # TODO(4.2.1) xe-port-channel-create-requires-canonical-name
        # ND rejects an IOS-XE port-channel create whose interfaceName is lowercase (generic policy-execution 500 / 207-failed) but echoes
        # the created interface lowercased; GET/PUT/remove accept the lowercase name. Rewrite only the write body.
        result = handler(self)
        if not isinstance(result, dict):
            raise AssertionError(f"Expected dict from model serialization, got {type(result).__name__}")
        result = self._apply_payload_defaults(result, info)
        if (info.context or {}).get("mode") != "payload":
            return result
        network_os = self.config_data.network_os if self.config_data is not None else None
        if network_os is None or network_os.network_os_type != "ios-xe":
            return result
        name = result.get("interfaceName")
        match = _XE_CREATE_NAME_RE.match(name) if isinstance(name, str) else None
        if match:
            result["interfaceName"] = f"Port-channel{match.group(1)}"
        return result

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict:
        """
        # Summary

        Return the Ansible argument spec for the `nd_interface_port_channel_trunk_host` module.

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
                    interface_name=dict(type="str", required=True),
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
                                                choices=[
                                                    TrunkPoHostPolicyTypeEnum.TRUNK_PO_HOST.value,
                                                    XeTrunkPoHostPolicyTypeEnum.IOS_XE_TRUNK_PO_HOST.value,
                                                ],
                                            ),
                                            admin_state=dict(type="bool"),
                                            allowed_vlans=dict(type="str"),
                                            bandwidth=dict(type="int"),
                                            bpdu_filter=dict(type="str", choices=[e.value for e in BpduFilterEnum]),
                                            bpdu_guard=dict(type="str", choices=[e.value for e in BpduGuardEnum]),
                                            cdp=dict(type="bool"),
                                            copy_description=dict(type="bool"),
                                            description=dict(type="str"),
                                            duplex_mode=dict(type="str", choices=[e.value for e in DuplexModeEnum]),
                                            extra_config=dict(type="str"),
                                            inherit_bandwidth=dict(type="int"),
                                            lacp_port_priority=dict(type="int"),
                                            lacp_rate=dict(type="str", choices=[e.value for e in LacpRateEnum]),
                                            lacp_suspend=dict(type="bool"),
                                            link_type=dict(type="str", choices=[e.value for e in LinkTypeEnum]),
                                            monitor=dict(type="bool"),
                                            # str with no choices: the NX-OS branch takes the default/jumbo enum,
                                            # the IOS-XE branch an int (the branch models validate the form).
                                            mtu=dict(type="str"),
                                            native_vlan=dict(type="int"),
                                            negotiate_auto=dict(type="bool"),
                                            netflow=dict(type="bool"),
                                            netflow_monitor=dict(type="str"),
                                            netflow_sampler=dict(type="str"),
                                            orphan_port=dict(type="bool"),
                                            pfc=dict(type="bool"),
                                            # Superset of both branches' modes; the NX-OS branch model rejects the PAgP auto/desirable values.
                                            port_channel_mode=dict(type="str", choices=[e.value for e in XePortChannelModeEnum]),
                                            port_type_edge_trunk=dict(type="bool"),
                                            ports=dict(type="list", elements="str"),
                                            qos=dict(type="bool"),
                                            qos_policy=dict(type="str"),
                                            queuing_policy=dict(type="str"),
                                            speed=dict(type="str", choices=[e.value for e in SpeedEnum]),
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
