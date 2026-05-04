# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Port-channel trunk host (trunkPoHost) interface Pydantic models for Nexus Dashboard.

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload
structure for port-channel trunkPoHost interfaces. The playbook config uses the same nesting
so that `to_payload()` and `from_response()` work via standard Pydantic serialization with no
custom wrapping or flattening.

The port-channel policy is the single source of truth for member configuration. Member ethernet
interfaces inherit trunk-mode settings from the port-channel; users do not pre-configure members.

## Model Hierarchy

- `PortChannelTrunkHostInterfaceModel` (top-level, `NDBaseModel`)
    - `switch_ip` (composite identifier)
    - `interface_name` (composite identifier; e.g. `port-channel501`)
    - `interface_type` (default: "portChannel")
    - `config_data` -> `PortChannelTrunkHostConfigDataModel`
        - `mode` (default: "trunk")
        - `network_os` -> `PortChannelTrunkHostNetworkOSModel`
            - `network_os_type` (default: "nx-os")
            - `policy` -> `PortChannelTrunkHostPolicyModel`
                - `admin_state`, `allowed_vlans`, `native_vlan`, `ports`, `port_channel_mode`,
                  `lacp_rate`, `bpdu_guard`, `description`, `policy_type`, `vlan_mapping`,
                  `vlan_mapping_entries`, etc.
"""

from __future__ import annotations

import re
from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
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
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription

# Accepts: "none", "all", or comma-separated VLAN ids/ranges (e.g. "1-200,500-2000,3000").
ALLOWED_VLANS_PATTERN = re.compile(r"^(none|all|(\d+(-\d+)?)(,\d+(-\d+)?)*)$")


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
    customer_vlan_id: list[str] | None = Field(default=None, alias="customerVlanId", description="Customer VLAN id list (single id or range strings)")
    dot1q_tunnel: bool | None = Field(default=None, alias="dot1qTunnel", description="Use selective dot1q-tunnel mode for this entry")
    provider_vlan_id: int | None = Field(default=None, alias="providerVlanId", ge=1, le=4094, description="Provider VLAN id")


class PortChannelTrunkHostPolicyModel(NDNestedModel):
    """
    # Summary

    Policy fields for a port-channel trunkPoHost interface. Maps directly to the `configData.networkOS.policy`
    object in the ND API.

    The `ports` field carries the list of member interface names (e.g. `Ethernet1/1`). Member interfaces inherit
    trunk-mode configuration from this policy; modifying a member's standalone configuration while it is a
    port-channel member is restricted by the ethernet orchestrators.

    ## Raises

    ### ValueError

    - If `allowed_vlans` is set and does not match `none`, `all`, or comma-separated VLAN ranges.
    """

    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")
    allowed_vlans: str | None = Field(
        default=None,
        alias="allowedVlans",
        description="Trunk allowed VLANs ('none', 'all', or comma-separated VLAN ids/ranges, e.g. '100-200,300')",
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
    netflow_monitor: str | None = Field(default=None, alias="netflowMonitor", description="Layer 2 Netflow monitor name")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler", description="Netflow sampler name")
    orphan_port: bool | None = Field(
        default=None, alias="orphanPort", description="Configure as a vPC orphan port (suspended by secondary peer on vPC failure)"
    )
    pfc: bool | None = Field(default=None, alias="pfc", description="Enable Priority Flow Control")
    policy_type: TrunkPoHostPolicyTypeEnum = Field(default=TrunkPoHostPolicyTypeEnum.TRUNK_PO_HOST, alias="policyType", description="Interface policy type")
    port_channel_id: str | None = Field(default=None, alias="portChannelId", description="Port-channel id (response-only echo of interface_name)")
    port_channel_mode: PortChannelModeEnum | None = Field(default=None, alias="portChannelMode", description="Port-channel mode (on/active/passive)")
    port_type_edge_trunk: bool | None = Field(default=None, alias="portTypeEdgeTrunk", description="Configure as edge trunk port (PortFast on trunk)")
    ports: list[str] | None = Field(default=None, alias="ports", description="Member interface names (e.g. ['Ethernet1/1', 'Ethernet1/2'])")
    ptp: bool | None = Field(default=None, alias="ptp", description="Enable Precision Time Protocol on the interface")
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

    @field_validator("allowed_vlans", mode="before")
    @classmethod
    def validate_allowed_vlans(cls, value):
        """
        # Summary

        Coerce int responses to str, then validate `allowed_vlans` matches `"none"`, `"all"`, or a comma-separated
        list of VLAN ids/ranges. ND returns single-id values as JSON ints (e.g. `250`) but accepts both forms on
        input; the model normalizes on str so round-trips and idempotency comparisons are stable.

        ## Raises

        ### ValueError

        - If `value` is a non-empty string that does not match the expected pattern.
        """
        if value is None or value == "":
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            value = str(value)
        if not isinstance(value, str):
            return value
        if not ALLOWED_VLANS_PATTERN.match(value):
            raise ValueError(f"allowed_vlans must be 'none', 'all', or a comma-separated list of VLAN ids/ranges (e.g. '1-200,500-2000,3000'); got {value!r}")
        return value

    @field_validator("ports", mode="before")
    @classmethod
    def normalize_ports(cls, value):
        """
        # Summary

        Normalize each member interface name to ND API convention (e.g. `ethernet1/1` -> `Ethernet1/1`).

        ## Raises

        None
        """
        if value is None:
            return value
        if not isinstance(value, list):
            return value
        normalized = []
        for name in value:
            if isinstance(name, str) and name:
                normalized.append(name[0].upper() + name[1:])
            else:
                normalized.append(name)
        return normalized


class PortChannelTrunkHostNetworkOSModel(NDNestedModel):
    """
    # Summary

    Network OS container for a port-channel trunkPoHost interface. Maps to `configData.networkOS` in the ND API.

    ## Raises

    None
    """

    network_os_type: str = Field(default="nx-os", alias="networkOSType")
    policy: PortChannelTrunkHostPolicyModel | None = Field(default=None, alias="policy")


class PortChannelTrunkHostConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for a port-channel trunkPoHost interface. Maps to `configData` in the ND API.

    ## Raises

    None
    """

    mode: str = Field(default="trunk", alias="mode")
    network_os: PortChannelTrunkHostNetworkOSModel = Field(alias="networkOS")


class PortChannelTrunkHostInterfaceModel(NDBaseModel):
    """
    # Summary

    Port-channel trunkPoHost interface configuration for Nexus Dashboard.

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
    interface_type: str = Field(default="portChannel", alias="interfaceType")
    config_data: PortChannelTrunkHostConfigDataModel | None = Field(default=None, alias="configData")

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
                    interface_type=dict(type="str", default="portChannel"),
                    config_data=dict(
                        type="dict",
                        options=dict(
                            mode=dict(type="str", default="trunk"),
                            network_os=dict(
                                type="dict",
                                options=dict(
                                    network_os_type=dict(type="str", default="nx-os"),
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
                                            description=dict(type="str"),
                                            duplex_mode=dict(type="str", choices=[e.value for e in DuplexModeEnum]),
                                            extra_config=dict(type="str"),
                                            inherit_bandwidth=dict(type="int"),
                                            lacp_port_priority=dict(type="int"),
                                            lacp_rate=dict(type="str", choices=[e.value for e in LacpRateEnum]),
                                            lacp_suspend=dict(type="bool"),
                                            link_type=dict(type="str", choices=[e.value for e in LinkTypeEnum]),
                                            monitor=dict(type="bool"),
                                            mtu=dict(type="str", choices=[e.value for e in MtuEnum]),
                                            native_vlan=dict(type="int"),
                                            negotiate_auto=dict(type="bool"),
                                            netflow=dict(type="bool"),
                                            netflow_monitor=dict(type="str"),
                                            netflow_sampler=dict(type="str"),
                                            orphan_port=dict(type="bool"),
                                            pfc=dict(type="bool"),
                                            port_channel_mode=dict(type="str", choices=[e.value for e in PortChannelModeEnum]),
                                            port_type_edge_trunk=dict(type="bool"),
                                            ports=dict(type="list", elements="str"),
                                            ptp=dict(type="bool"),
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
