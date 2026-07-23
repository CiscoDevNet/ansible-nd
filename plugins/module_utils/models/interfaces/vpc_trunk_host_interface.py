# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
vPC trunk (trunkVpcHost) interface Pydantic models for Nexus Dashboard.

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload
structure for vPC trunkVpcHost interfaces (`int_vpc_trunk_host.template`). The playbook
config uses the same nesting so that `to_payload()` and `from_response()` work via standard
Pydantic serialization with no custom wrapping or flattening.

A vPC trunk-host interface spans two switches in a vPC pair. The user supplies one peer's
management IP as `switch_ip`; the orchestrator auto-resolves the peer serial via the
`vpcPair` endpoint and injects it as `peerSwitchId` in the payload. Per-peer policy fields
use the ND-native `peer1_*` / `peer2_*` naming where `peer1` corresponds to `switch_ip`
(the switch in the URL path) and `peer2` corresponds to the auto-resolved peer.

## Model Hierarchy

- `TrunkVpcHostInterfaceModel` (top-level, `NDBaseModel`)
    - `switch_ip` (routing field; excluded from diff/payload)
    - `interface_name` (identifier; e.g. `vpc100`)
    - `interface_type` (frozen: "vpc")
    - `config_data` -> `TrunkVpcHostConfigDataModel`
        - `mode` (frozen: "trunk")
        - `network_os` -> `TrunkVpcHostNetworkOSModel`
            - `network_os_type` (frozen: "nx-os")
            - `policy` -> `TrunkVpcHostPolicyModel`
                - `policy_type` (frozen: "trunkVpcHost")
                - `peer_switch_id` (orchestrator-injected; not in argspec)
                - single user-facing `allowed_vlans`, `native_vlan` (fanned out to per-peer keys on write)
                - per-peer fields: `peer1_*` / `peer2_*` (member_ports, port_channel_id, descriptions, configuration)
                - `vlan_mapping`, `vlan_mapping_entries`
                - shared fields: `admin_state`, `cdp`, `lacp_*`, `mtu`, etc.
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
    TrunkVpcHostPolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.storm_control import StormControlMutexMixin
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription

# Shape regex: "none", "all", or comma-separated VLAN ids/ranges. Range bounds are validated separately.
_ALLOWED_VLANS_SHAPE = re.compile(r"^(none|all|(\d+(-\d+)?)(,\d+(-\d+)?)*)$")
# Single VLAN id or range token (e.g. "100" or "100-200"). Range bounds are validated separately.
_VLAN_ID_OR_RANGE_SHAPE = re.compile(r"^\d+(-\d+)?$")

# Splits an interface name into its leading alphabetic prefix and the rest (digits/separators).
_INTERFACE_NAME_PREFIX_RE = re.compile(r"^([A-Za-z]+)(.*)$")

# Member interfaces of a vPC are always physical ethernet ports, so the canonical wire prefix is always
# "Ethernet". Any case-insensitive NX-OS abbreviation (e.g. "e", "eth", "ether") expands to the full form so
# user input matches the wire key and idempotency holds.
_CANONICAL_MEMBER_TYPE = "Ethernet"


def _validate_vlan_id_or_range(token: str, field_name: str) -> None:
    """
    # Summary

    Validate a single VLAN id or range token (e.g. `"100"` or `"100-200"`) and confirm every id is in 1..4094 and any range has start <= end.

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


# TODO: After all per-policy interface modules merge to develop, consolidate AllowedVlans, CustomerVlanIdList,
# and _validate_vlan_id_or_range into models/types.py so siblings share a single source of truth. This module
# carries its own copy to keep the vpc stack self-contained. Tracked in CiscoDevNet/ansible-nd#347.
AllowedVlans = Annotated[Optional[str], BeforeValidator(_validate_allowed_vlans)]
"""Trunk allowed-VLANs spec (`str | None`): 'none', 'all', or comma-separated VLAN ids/ranges in 1..4094."""

CustomerVlanIdList = Annotated[Optional[list[str]], BeforeValidator(_validate_customer_vlan_id_list)]
"""Customer VLAN id list (`list[str] | None`): each entry is a VLAN id or range in 1..4094 (e.g. `['100', '200-300']`)."""


class TrunkVpcHostVlanMappingEntryModel(NDNestedModel):
    """
    # Summary

    A single VLAN mapping entry for a vPC trunk host. Maps to one element of `policy.vlanMappingEntries` in the
    ND API. Entries translate customer VLAN ids to a provider VLAN id, optionally using selective dot1q-tunnel mode.

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


class TrunkVpcHostPolicyModel(StormControlMutexMixin):
    """
    # Summary

    Policy fields for a vPC `trunkVpcHost` interface. Maps directly to the `configData.networkOS.policy` object in the ND API.

    Per-peer fields use the API-native `peer1*` / `peer2*` naming. `peer1` corresponds to the switch in the URL path
    (the user-supplied `switch_ip`); `peer2` corresponds to the auto-resolved peer (the value of `peerSwitchId`).

    `peer_switch_id` is set by the orchestrator from the vPC pair record. It is not exposed in the module argument spec.

    ND enforces wire-side consistency between `peer1AllowedVlans`/`peer2AllowedVlans` and between `peer1NativeVlan`/`peer2NativeVlan`
    (HTTP 400 on divergent values, lab-verified 2026-05-13). The model exposes single `allowed_vlans` and `native_vlan` user fields
    and fans them out to the per-peer keys at payload-serialization time. The GET response collapses the per-peer pair back to a
    single key, so the diff matches the wire echo without further normalization.

    ## Raises

    ### ValueError

    - If `allowed_vlans` is set and does not match `none`, `all`, or comma-separated VLAN ranges.
    """

    # `peerSwitchId` is orchestrator-injected (resolved from the vPC pair record; not in the argspec), so the
    # proposed config can never express it. ND echoes it on reads; without this exclusion the reverse pass of
    # `get_diff` would count it as a removal on every replaced/overridden run, breaking idempotency.
    reverse_diff_exclude: ClassVar[set[str]] = {"peerSwitchId"}

    # ND 4.2.1 `int_vpc_trunk_host` template defaults (schema-sourced via nd-openapi `intVpcTrunkHostTemplate`). ND echoes these
    # for every field the user never set; the reverse pass of `get_diff` normalizes existing-side matches to absent
    # so replaced/overridden removal detection (issue #410) stays idempotent against default echoes.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        "adminState": True,
        "bpduFilter": "default",
        "bpduGuard": "enable",
        "cdp": True,
        "copyDescription": False,
        "duplexMode": "auto",
        "lacpPortPriority": 32768,
        "lacpRate": "normal",
        "lacpSuspend": False,
        "lacpVpcConvergence": False,
        "linkType": "auto",
        "mirrorConfig": False,
        "mtu": "jumbo",
        "negotiateAuto": True,
        "netflow": False,
        "pfc": False,
        "portChannelMode": "active",
        "portTypeEdgeTrunk": True,
        "qos": False,
        "speed": "auto",
        "stormControl": False,
        "stormControlAction": "default",
        "vlanMapping": False,
    }

    # --- Policy Discriminator ---

    policy_type: TrunkVpcHostPolicyTypeEnum = Field(
        default=TrunkVpcHostPolicyTypeEnum.TRUNK_VPC_HOST,
        alias="policyType",
        frozen=True,
        description="Interface policy type (hardcoded for this module)",
    )

    # --- Orchestrator-Injected (Not In Argspec) ---

    peer_switch_id: str | None = Field(
        default=None,
        alias="peerSwitchId",
        description="Peer switch serial number, auto-resolved by the orchestrator from the vPC pair record",
    )

    # --- Trunk-Specific Single-Valued Fields (collapsed by ND on read; fanned out per-peer on write) ---
    # TODO(4.2.1) vpc-interface-peer-vlan-collapse
    # ND trunkVpcHost wire echoes single `allowedVlans` / `nativeVlan` even though the create schema requires
    # per-peer `peer1AllowedVlans` / `peer2AllowedVlans` and `peer1NativeVlan` / `peer2NativeVlan`. ND also rejects
    # divergent per-peer values at the API layer (HTTP 400 "should be consistent"). We expose single user-facing fields
    # and split them back to per-peer keys via `expand_per_peer_fields` for the write so idempotency matches the wire echo.

    allowed_vlans: AllowedVlans = Field(
        default=None,
        alias="allowedVlans",
        description="Trunk allowed VLANs ('none', 'all', or comma-separated VLAN ids/ranges in 1..4094, e.g. '100-200,300')",
    )
    native_vlan: int | None = Field(default=None, alias="nativeVlan", ge=1, le=4094, description="Trunk native VLAN id")

    # --- Per-Peer Fields (peer1 = switch_ip, peer2 = peer_switch_id) ---

    peer1_member_ports: list[str] | None = Field(default=None, alias="peer1MemberPorts", description="Member interface names on Peer-1")
    peer1_port_channel_configuration: str | None = Field(
        default=None, alias="peer1PortChannelConfiguration", description="Additional CLI for Peer-1's port-channel"
    )
    peer1_port_channel_description: AsciiDescription = Field(
        default=None, alias="peer1PortChannelDescription", max_length=254, description="Description for Peer-1's port-channel"
    )
    peer1_port_channel_id: int | None = Field(default=None, alias="peer1PortChannelId", ge=1, le=4096, description="Peer-1 vPC port-channel number")
    peer2_member_ports: list[str] | None = Field(default=None, alias="peer2MemberPorts", description="Member interface names on Peer-2")
    peer2_port_channel_configuration: str | None = Field(
        default=None, alias="peer2PortChannelConfiguration", description="Additional CLI for Peer-2's port-channel"
    )
    peer2_port_channel_description: AsciiDescription = Field(
        default=None, alias="peer2PortChannelDescription", max_length=254, description="Description for Peer-2's port-channel"
    )
    peer2_port_channel_id: int | None = Field(default=None, alias="peer2PortChannelId", ge=1, le=4096, description="Peer-2 vPC port-channel number")

    # --- VLAN Mapping ---

    vlan_mapping: bool | None = Field(default=None, alias="vlanMapping", description="Enable VLAN mapping on the trunk")
    vlan_mapping_entries: list[TrunkVpcHostVlanMappingEntryModel] | None = Field(
        default=None, alias="vlanMappingEntries", description="VLAN mapping entries (used when vlan_mapping is enabled)"
    )

    # --- Shared Policy Fields ---

    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")
    bandwidth: int | None = Field(default=None, alias="bandwidth", ge=1, le=100000000, description="Configured bandwidth value for the interface")
    bpdu_filter: BpduFilterEnum | None = Field(default=None, alias="bpduFilter", description="Configure spanning-tree BPDU filter")
    bpdu_guard: BpduGuardEnum | None = Field(default=None, alias="bpduGuard", description="Enable spanning-tree BPDU guard")
    cdp: bool | None = Field(default=None, alias="cdp", description="Enable CDP on the interface")
    copy_description: bool | None = Field(
        default=None,
        alias="copyDescription",
        description="Propagate the port-channel description to all member interfaces (per-peer)",
    )
    duplex_mode: DuplexModeEnum | None = Field(default=None, alias="duplexMode", description="Port duplex mode")
    inherit_bandwidth: int | None = Field(
        default=None,
        alias="inheritBandwidth",
        ge=1,
        le=100000000,
        description="Bandwidth value inherited by sub-interfaces",
    )
    lacp_port_priority: int | None = Field(default=None, alias="lacpPortPriority", ge=1, le=65535, description="LACP port priority (1-65535, default 32768)")
    lacp_rate: LacpRateEnum | None = Field(default=None, alias="lacpRate", description="LACP rate (normal=30s, fast=1s)")
    lacp_suspend: bool | None = Field(default=None, alias="lacpSuspend", description="Suspend port if LACP PDUs not received")
    lacp_vpc_convergence: bool | None = Field(default=None, alias="lacpVpcConvergence", description="Enable LACP convergence for vPC port-channels")
    link_type: LinkTypeEnum | None = Field(default=None, alias="linkType", description="Spanning-tree link type")
    mirror_config: bool | None = Field(default=None, alias="mirrorConfig", description="Copy Peer-1 config to Peer-2")
    mtu: MtuEnum | None = Field(default=None, alias="mtu", description="Interface MTU")
    negotiate_auto: bool | None = Field(default=None, alias="negotiateAuto", description="Enable link auto-negotiation")
    netflow: bool | None = Field(default=None, alias="netflow", description="Enable Netflow on the interface")
    netflow_monitor: str | None = Field(default=None, alias="netflowMonitor", description="Layer 2 Netflow monitor name")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler", description="Netflow sampler name (N7K only)")
    pfc: bool | None = Field(default=None, alias="pfc", description="Enable priority flow control")
    port_channel_mode: PortChannelModeEnum | None = Field(default=None, alias="portChannelMode", description="Port-channel mode (on/active/passive)")
    port_type_edge_trunk: bool | None = Field(
        default=None, alias="portTypeEdgeTrunk", description="Enable spanning-tree edge port (PortFast) behavior on trunk"
    )
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

    # --- Serializers ---

    # TODO(4.2.1) vpc-interface-peer-vlan-collapse
    # trunkVpcHost wire echoes single `allowedVlans` and `nativeVlan` even though the create schema
    # requires per-peer `peer1AllowedVlans` / `peer2AllowedVlans` and `peer1NativeVlan` / `peer2NativeVlan`. ND also
    # rejects divergent per-peer values at the API layer (HTTP 400 "should be consistent"). We expose single user
    # fields and split them back to the per-peer keys on the write side so idempotency works against the actual wire shape.
    @model_serializer(mode="wrap")
    def expand_per_peer_fields(self, handler, info: SerializationInfo):
        """
        # Summary

        Single wrap-mode model serializer for the policy block, applying two ND-specific adjustments keyed off the
        serialization `mode` context:

        - On payload serialization (`mode == "payload"`), split the single user-facing `allowedVlans` / `nativeVlan`
          into the per-peer `peer1AllowedVlans` / `peer2AllowedVlans` and `peer1NativeVlan` / `peer2NativeVlan` keys the
          ND create/update schema requires. ND collapses each pair back to a single field on read, so config / diff
          modes leave the fields as-is and the diff stays symmetric.
        - On config serialization (`mode == "config"`), drop the frozen, argspec-excluded `policy_type` so it does not
          leak into `before` / `after` / `gathered` output. Payload and diff modes keep the wire value so the POST/PUT
          body and the round-trip diff line up with what ND returns.

        ## Raises

        ### AssertionError

        - If the wrapped handler returns a non-`dict`. A model-level serializer always serializes to a `dict`, so this
          is an invariant check that fails loudly rather than silently mis-serializing.
        """
        data = handler(self)
        if not isinstance(data, dict):
            raise AssertionError(f"Expected dict from model serialization, got {type(data).__name__}")
        mode = (info.context or {}).get("mode", "payload")
        if mode == "payload":
            if "allowedVlans" in data:
                vlans = data.pop("allowedVlans")
                data["peer1AllowedVlans"] = vlans
                data["peer2AllowedVlans"] = vlans
            if "nativeVlan" in data:
                vlan = data.pop("nativeVlan")
                data["peer1NativeVlan"] = vlan
                data["peer2NativeVlan"] = vlan
        if mode == "config":
            data.pop("policy_type", None)
            data.pop("policyType", None)
        return data

    # --- Validators ---

    @field_validator("peer1_member_ports", "peer2_member_ports", mode="before")
    @classmethod
    def normalize_member_ports(cls, value):
        """
        # Summary

        Normalize each per-peer member interface name to ND's canonical `Ethernet` form so any user-supplied casing or
        NX-OS abbreviation round-trips against the wire form. Members are always physical ethernet ports. Examples:

        - `ethernet1/1` -> `Ethernet1/1`
        - `eth1/1` -> `Ethernet1/1` (abbreviation expanded)
        - `e1/1` -> `Ethernet1/1` (abbreviation expanded)
        - `Ethernet1/1` -> `Ethernet1/1` (idempotent)

        An abbreviated prefix that is not expanded would never match ND's `Ethernet...` wire key, silently breaking
        idempotency (the vPC re-deploys on every run). Only the leading alphabetic run is rewritten; digits and
        separators are preserved verbatim.

        ## Raises

        None
        """
        if not isinstance(value, list):
            return value
        return [cls._normalize_member_name(name) for name in value]

    @staticmethod
    def _normalize_member_name(name):
        """
        # Summary

        Normalize a single member interface name to ND's canonical `Ethernet` form (see `normalize_member_ports`).
        Non-string or empty values are returned unchanged.

        ## Raises

        None
        """
        if not isinstance(name, str) or not name:
            return name
        match = _INTERFACE_NAME_PREFIX_RE.match(name)
        if not match:
            return name
        prefix, rest = match.groups()
        if _CANONICAL_MEMBER_TYPE.lower().startswith(prefix.lower()):
            return _CANONICAL_MEMBER_TYPE + rest
        return prefix[0].upper() + prefix[1:].lower() + rest


class TrunkVpcHostNetworkOSModel(NDNestedModel):
    """
    # Summary

    Network OS container for a vPC `trunkVpcHost` interface. Maps to `configData.networkOS` in the ND API.

    ## Raises

    None
    """

    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType", frozen=True)
    policy: TrunkVpcHostPolicyModel | None = Field(default=None, alias="policy")


class TrunkVpcHostConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for a vPC `trunkVpcHost` interface. Maps to `configData` in the ND API.

    ## Raises

    None
    """

    mode: Literal["trunk"] = Field(default="trunk", alias="mode", frozen=True)
    network_os: TrunkVpcHostNetworkOSModel = Field(alias="networkOS")


class TrunkVpcHostInterfaceModel(NDBaseModel):
    """
    # Summary

    vPC `trunkVpcHost` interface configuration for Nexus Dashboard.

    The nested model structure mirrors the ND Manage Interfaces API payload, so `to_payload()` and `from_response()`
    work via standard Pydantic serialization. The `interface_name` is the vPC's own name (e.g. `vpc100`), not a member
    interface. Member interfaces are listed per-peer in `config_data.network_os.policy.peer1_member_ports` and
    `peer2_member_ports`.

    ## Raises

    None
    """

    # --- Identifier Configuration ---
    # TODO(4.2.1) vpc-interface-dual-peer-duplicate
    # A vPC interface is a single fabric-level resource, but ND echoes it from BOTH peer switches in
    # the per-switch `/interfaces` GET (with identical `configData` and only `switchId` / `peerSwitchId` swapping).
    # Using a composite (switch_ip, interface_name) identifier caused `_manage_override_deletions` to delete the
    # peer-side duplicate. The identifier is therefore `interface_name` only; `switch_ip` is kept as a field for
    # routing (URL-path resolution + peer-resolution) but is excluded from diff and dedup'd in `query_all`.

    identifiers: ClassVar[list[str] | None] = ["interface_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"

    # --- Serialization Configuration ---

    payload_exclude_fields: ClassVar[set[str]] = {"switch_ip"}
    exclude_from_diff: ClassVar[set[str]] = {"switch_ip"}

    # --- Fields ---

    switch_ip: str = Field(alias="switchIp")
    interface_name: str = Field(alias="interfaceName")
    interface_type: Literal["vpc"] = Field(default="vpc", alias="interfaceType", frozen=True)
    config_data: TrunkVpcHostConfigDataModel | None = Field(default=None, alias="configData")

    @field_validator("interface_name", mode="before")
    @classmethod
    def normalize_interface_name(cls, value):
        """
        # Summary

        Normalize the vPC interface name to lowercase to match ND API convention (e.g. `Vpc100` -> `vpc100`).

        ## Raises

        None
        """
        if isinstance(value, str):
            return value.lower()
        return value

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict:
        """
        # Summary

        Return the Ansible argument spec for the `nd_interface_vpc_trunk_host` module. Frozen scaffolding fields
        (`interface_type`, `mode`, `network_os_type`, `policy_type`) are intentionally NOT exposed. `peer_switch_id`
        is orchestrator-injected and NOT exposed.

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
                                    policy=dict(
                                        type="dict",
                                        options=dict(
                                            admin_state=dict(type="bool"),
                                            allowed_vlans=dict(type="str"),
                                            bandwidth=dict(type="int"),
                                            bpdu_filter=dict(type="str", choices=[e.value for e in BpduFilterEnum]),
                                            bpdu_guard=dict(type="str", choices=[e.value for e in BpduGuardEnum]),
                                            cdp=dict(type="bool"),
                                            copy_description=dict(type="bool"),
                                            duplex_mode=dict(type="str", choices=[e.value for e in DuplexModeEnum]),
                                            inherit_bandwidth=dict(type="int"),
                                            lacp_port_priority=dict(type="int"),
                                            lacp_rate=dict(type="str", choices=[e.value for e in LacpRateEnum]),
                                            lacp_suspend=dict(type="bool"),
                                            lacp_vpc_convergence=dict(type="bool"),
                                            link_type=dict(type="str", choices=[e.value for e in LinkTypeEnum]),
                                            mirror_config=dict(type="bool"),
                                            mtu=dict(type="str", choices=[e.value for e in MtuEnum]),
                                            native_vlan=dict(type="int"),
                                            negotiate_auto=dict(type="bool"),
                                            netflow=dict(type="bool"),
                                            netflow_monitor=dict(type="str"),
                                            netflow_sampler=dict(type="str"),
                                            peer1_member_ports=dict(type="list", elements="str"),
                                            peer1_port_channel_configuration=dict(type="str"),
                                            peer1_port_channel_description=dict(type="str"),
                                            peer1_port_channel_id=dict(type="int"),
                                            peer2_member_ports=dict(type="list", elements="str"),
                                            peer2_port_channel_configuration=dict(type="str"),
                                            peer2_port_channel_description=dict(type="str"),
                                            peer2_port_channel_id=dict(type="int"),
                                            pfc=dict(type="bool"),
                                            port_channel_mode=dict(type="str", choices=[e.value for e in PortChannelModeEnum]),
                                            port_type_edge_trunk=dict(type="bool"),
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
