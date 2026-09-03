# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
vPC access (accessVpcHost) interface Pydantic models for Nexus Dashboard.

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload
structure for vPC accessVpcHost interfaces (`int_vpc_access_host.template`). The playbook
config uses the same nesting so that `to_payload()` and `from_response()` work via standard
Pydantic serialization with no custom wrapping or flattening.

A vPC access interface spans two switches in a vPC pair. The user supplies one peer's
management IP as `switch_ip`; the orchestrator auto-resolves the peer serial via the
`vpcPair` endpoint and injects it as `peerSwitchId` in the payload. Per-peer policy fields
use the ND-native `peer1_*` / `peer2_*` naming where `peer1` corresponds to `switch_ip`
(the switch in the URL path) and `peer2` corresponds to the auto-resolved peer.

## Model Hierarchy

- `AccessVpcHostInterfaceModel` (top-level, `NDBaseModel`)
    - `switch_ip` (composite identifier; primary peer's management IP)
    - `interface_name` (composite identifier; e.g. `vpc100`)
    - `interface_type` (frozen: "vpc")
    - `config_data` -> `AccessVpcHostConfigDataModel`
        - `mode` (frozen: "access")
        - `network_os` -> `AccessVpcHostNetworkOSModel`
            - `network_os_type` (frozen: "nx-os")
            - `policy` -> `AccessVpcHostPolicyModel`
                - `policy_type` (frozen: "accessVpcHost")
                - `peer_switch_id` (orchestrator-injected; not in argspec)
                - per-peer fields: `peer1_*`, `peer2_*`
                - shared fields: `admin_state`, `cdp`, `lacp_rate`, `mtu`, etc.
"""

from __future__ import annotations

import re
from copy import deepcopy
from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    SerializationInfo,
    field_validator,
    model_serializer,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    AccessVpcHostPolicyTypeEnum,
    BpduFilterEnum,
    BpduGuardEnum,
    DuplexModeEnum,
    LacpRateEnum,
    LinkTypeEnum,
    MtuEnum,
    PortChannelModeEnum,
    SpeedEnum,
    StormControlActionEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.storm_control import StormControlMutexMixin
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription

# Splits an interface name into its leading alphabetic prefix and the rest (digits/separators).
_INTERFACE_NAME_PREFIX_RE = re.compile(r"^([A-Za-z]+)(.*)$")

# Member interfaces of a vPC are always physical ethernet ports, so the canonical wire prefix is always
# "Ethernet". Any case-insensitive NX-OS abbreviation (e.g. "e", "eth", "ether") expands to the full form so
# user input matches the wire key and idempotency holds.
_CANONICAL_MEMBER_TYPE = "Ethernet"


class AccessVpcHostPolicyModel(StormControlMutexMixin):
    """
    # Summary

    Policy fields for a vPC `accessVpcHost` interface. Maps directly to the `configData.networkOS.policy` object in the ND API.

    Per-peer fields use the API-native `peer1*` / `peer2*` naming. `peer1` corresponds to the switch in the URL path
    (the user-supplied `switch_ip`); `peer2` corresponds to the auto-resolved peer (the value of `peerSwitchId`).

    `peer_switch_id` is set by the orchestrator from the vPC pair record. It is not exposed in the module argument spec.

    ## Raises

    None
    """

    # --- Policy Discriminator ---

    policy_type: AccessVpcHostPolicyTypeEnum = Field(
        default=AccessVpcHostPolicyTypeEnum.ACCESS_VPC_HOST,
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

    # --- Shared (single-valued) access VLAN ---
    # TODO(4.2.1) vpc-interface-peer-vlan-collapse
    # ND accessVpcHost wire echoes a single `accessVlan` even though the create schema requires per-peer
    # `peer1AccessVlan` / `peer2AccessVlan`. See `serialize_policy` below for the split-on-write workaround.
    access_vlan: int | None = Field(default=None, alias="accessVlan", ge=1, le=4094, description="VLAN for the access port on both peers")

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
    port_type_edge_trunk: bool | None = Field(default=None, alias="portTypeEdgeTrunk", description="Enable spanning-tree edge port (PortFast) behavior")
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
    # accessVpcHost wire echoes a single `accessVlan` even though the create schema requires per-peer
    # `peer1AccessVlan` / `peer2AccessVlan`. We expose a single `access_vlan` to users and split it back to the
    # per-peer keys on the write side via this model_serializer so idempotency works against the actual wire shape.
    @model_serializer(mode="wrap")
    def serialize_policy(self, handler, info: SerializationInfo):
        """
        # Summary

        Single wrap-mode model serializer for the policy block, applying two ND-specific adjustments keyed off the
        serialization `mode` context:

        - On payload serialization (`mode == "payload"`), split the single user-facing `accessVlan` into the per-peer
          `peer1AccessVlan` / `peer2AccessVlan` keys the ND create/update schema requires. ND collapses the pair back
          to a single `accessVlan` on read, so config / diff modes leave the field as-is and the diff stays symmetric.
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
        if mode == "payload" and "accessVlan" in data:
            vlan = data.pop("accessVlan")
            data["peer1AccessVlan"] = vlan
            data["peer2AccessVlan"] = vlan
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


class AccessVpcHostNetworkOSModel(NDNestedModel):
    """
    # Summary

    Network OS container for a vPC `accessVpcHost` interface. Maps to `configData.networkOS` in the ND API.

    ## Raises

    None
    """

    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType", frozen=True)
    policy: AccessVpcHostPolicyModel | None = Field(default=None, alias="policy")


class AccessVpcHostConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for a vPC `accessVpcHost` interface. Maps to `configData` in the ND API.

    ## Raises

    None
    """

    mode: Literal["access"] = Field(default="access", alias="mode", frozen=True)
    network_os: AccessVpcHostNetworkOSModel = Field(alias="networkOS")


class AccessVpcHostInterfaceModel(NDBaseModel):
    """
    # Summary

    vPC `accessVpcHost` interface configuration for Nexus Dashboard.

    Uses a composite identifier (`switch_ip`, `interface_name`). The nested model structure mirrors the ND Manage
    Interfaces API payload, so `to_payload()` and `from_response()` work via standard Pydantic serialization.

    The `interface_name` is the vPC's own name (e.g. `vpc100`), not a member interface. Member interfaces are listed
    per-peer in `config_data.network_os.policy.peer1_member_ports` and `peer2_member_ports`.

    ## Raises

    None
    """

    # --- Identifier Configuration ---
    # TODO(4.2.1) vpc-interface-dual-peer-duplicate
    # A vPC interface is a single fabric-level resource, but ND echoes it from BOTH peer switches in the per-switch
    # `/interfaces` GET (with identical `configData` and only `switchId` / `peerSwitchId` swapping). Using a composite
    # (switch_ip, interface_name) identifier caused `_manage_override_deletions` to delete the peer-side duplicate. The
    # identifier is therefore `interface_name` only; `switch_ip` is kept as a field for routing (URL-path resolution +
    # peer-resolution) but is excluded from diff and dedup'd in `query_all`.

    identifiers: ClassVar[list[str] | None] = ["interface_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"

    # --- Gathered Filtering Configuration ---

    supports_gathered_filtering: ClassVar[bool] = True
    gathered_filter_properties: ClassVar[tuple[str, ...]] = (
        "switch_ip",
        "interface_name",
        "config_data.network_os.policy.admin_state",
        "config_data.network_os.policy.access_vlan",
        "config_data.network_os.policy.peer1_port_channel_id",
        "config_data.network_os.policy.peer2_port_channel_id",
    )

    # --- Serialization Configuration ---

    payload_exclude_fields: ClassVar[set[str]] = {"switch_ip"}
    exclude_from_diff: ClassVar[set[str]] = {"switch_ip"}

    # --- Fields ---

    switch_ip: str = Field(alias="switchIp")
    interface_name: str = Field(alias="interfaceName")
    interface_type: Literal["vpc"] = Field(default="vpc", alias="interfaceType", frozen=True)
    config_data: AccessVpcHostConfigDataModel | None = Field(default=None, alias="configData")

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

    @classmethod
    def normalize_gathered_filter(cls, filter_item: dict) -> dict:
        """
        # Summary

        Normalize a partial gathered-state filter.

        Gathered filters are not complete AccessVpcHostInterfaceModel instances, so
        the normal Pydantic interface_name validator does not run against them.

        ## Raises

        None
        """
        normalized = deepcopy(filter_item)
        interface_name = normalized.get("interface_name")
        if isinstance(interface_name, str):
            normalized["interface_name"] = interface_name.lower()
        return normalized

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict:
        """
        # Summary

        Return the Ansible argument spec for the `nd_interface_vpc_access` module. Frozen scaffolding fields
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
                required=False,
                options=dict(
                    switch_ip=dict(type="str", required=False),
                    interface_name=dict(type="str", required=False),
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
                                            negotiate_auto=dict(type="bool"),
                                            netflow=dict(type="bool"),
                                            netflow_monitor=dict(type="str"),
                                            netflow_sampler=dict(type="str"),
                                            access_vlan=dict(type="int"),
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
                choices=["merged", "replaced", "overridden", "deleted", "gathered"],
            ),
        )
