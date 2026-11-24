# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NX-OS dot1q-tunnel port-channel policy and interface models."""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
    model_validator,
)
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
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_common import (
    default_policy_type,
    normalize_member_interface_names,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.netflow import (
    NetflowAtomicMergeMixin,
    netflow_validation_suspended,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.policy_base import InterfacePolicyStrictBase
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_common import PortChannelInterfaceBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription


class PortChannelDot1qTunnelHostPolicyModel(NetflowAtomicMergeMixin, InterfacePolicyStrictBase):
    """
    # Summary

    Policy fields for the NX-OS `dot1qTunnelPoHost` template (`int_port_channel_dot1q_tunnel_host`). Maps directly to the
    `configData.networkOS.policy` object in the ND API where `policyType == "dot1qTunnelPoHost"`.

    The `ports` field carries the list of member interface names (e.g. `Ethernet1/1`). Member interfaces inherit
    dot1q-tunnel configuration from this policy; modifying a member's standalone configuration while it is a
    port-channel member is restricted by the ethernet orchestrators.

    ## Raises

    None
    """

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND 4.2.1 `int_port_channel_dot1q_tunnel_host` template defaults (schema-sourced via nd-openapi `intPortChannelDot1qTunnelHostTemplate`). ND echoes these
    # for every field the user never set; the reverse pass of `get_diff` normalizes existing-side matches to absent
    # so replaced/overridden removal detection (issue #410) stays idempotent against default echoes.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        "adminState": True,
        "bpduFilter": "enable",
        "bpduGuard": "enable",
        "cdp": True,
        "copyDescription": False,
        "duplexMode": "auto",
        "lacpPortPriority": 32768,
        "lacpRate": "normal",
        "lacpSuspend": False,
        "linkType": "auto",
        "mtu": "jumbo",
        "negotiateAuto": True,
        "netflow": False,
        "orphanPort": False,
        "pfc": False,
        "portChannelMode": "active",
        "portTypeEdgeTrunk": True,
        "ports": [],
        "qos": False,
        "speed": "auto",
        "stormControl": False,
        "stormControlAction": "default",
    }

    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")
    access_vlan: int | None = Field(default=None, alias="accessVlan", ge=1, le=4094, description="VLAN for this dot1q-tunnel port-channel")
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
    mtu: MtuEnum | None = Field(default=None, alias="mtu", description="Interface MTU")
    negotiate_auto: bool | None = Field(default=None, alias="negotiateAuto", description="Enable link auto-negotiation")
    netflow: bool | None = Field(default=None, alias="netflow", description="Enable Netflow on the interface")
    netflow_monitor: str | None = Field(default=None, alias="netflowMonitor", description="Layer 2 Netflow monitor name (required when `netflow=true`)")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler", description="Netflow sampler name")
    orphan_port: bool | None = Field(
        default=None, alias="orphanPort", description="Configure as a vPC orphan port (suspended by secondary peer on vPC failure)"
    )
    pfc: bool | None = Field(default=None, alias="pfc", description="Enable Priority Flow Control")
    policy_type: Literal["dot1qTunnelPoHost"] = Field(
        alias="policyType",
        description="Access port-channel policy template discriminator; injected as `dot1qTunnelPoHost` when omitted (see `default_policy_type`)",
    )

    @model_validator(mode="before")
    @classmethod
    def default_policy_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `policyType: dot1qTunnelPoHost` when the input omits the discriminator (`ethernet_common.default_policy_type`).

        ## Raises

        None
        """
        return default_policy_type(data, "dot1qTunnelPoHost")

    port_channel_mode: PortChannelModeEnum | None = Field(default=None, alias="portChannelMode", description="Port-channel mode (on/active/passive)")
    port_type_edge_trunk: bool | None = Field(default=None, alias="portTypeEdgeTrunk", description="Configure as edge trunk port (PortFast on trunk)")
    ports: list[str] = Field(default_factory=list, alias="ports", description="Member interface names (e.g. ['Ethernet1/1', 'Ethernet1/2'])")
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

    # --- Validators ---

    @model_validator(mode="after")
    def _validate_netflow_monitor_present(self) -> PortChannelDot1qTunnelHostPolicyModel:
        """
        # Summary

        Reject enabling `netflow` without supplying a `netflow_monitor`.

        The DOCUMENTATION and field description state that `netflow_monitor` is required when `netflow` is true. Enforcing it at the model layer
        fails an incomplete policy early with a clear error instead of pushing a netflow config with no monitor and deferring the outcome to ND.

        ## Raises

        ### ValueError

        - If `netflow` is true and `netflow_monitor` is missing or empty.
        """
        if netflow_validation_suspended():
            return self
        if self.netflow is True and not self.netflow_monitor:
            raise ValueError("netflow_monitor must be provided when netflow is true.")
        return self

    @field_validator("ports", mode="before")
    @classmethod
    def normalize_ports(cls, value):
        """
        # Summary

        Normalize each member name to its wire-canonical prefix through the shared cross-OS helper
        (`ethernet_common.normalize_member_interface_names`): `e1/1` / `eth1/1` -> `Ethernet1/1`, `gi1/0/2` -> `GigabitEthernet1/0/2`,
        any other family verbatim. Members are always physical ethernet ports; matching the wire key exactly keeps idempotency.

        ## Raises

        None
        """
        return normalize_member_interface_names(value)


class PortChannelDot1qTunnelHostNetworkOSModel(NDNestedModel):
    """NX-OS container for the dot1q-tunnel port-channel policy."""

    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType")
    policy: PortChannelDot1qTunnelHostPolicyModel | None = Field(default=None, alias="policy")


class PortChannelDot1qTunnelHostConfigDataModel(NDNestedModel):
    """ND mode and network OS for the dot1q-tunnel port-channel."""

    mode: Literal["dot1qTunnel"] = Field(default="dot1qTunnel", alias="mode", frozen=True)
    network_os: PortChannelDot1qTunnelHostNetworkOSModel = Field(alias="networkOS")


class PortChannelDot1qTunnelHostInterfaceModel(PortChannelInterfaceBaseModel):
    """
    # Summary

    NX-OS dot1q-tunnel port-channel configuration for Nexus Dashboard.

    Uses a composite identifier (`switch_ip`, `interface_name`). The nested model structure mirrors the ND Manage
    Interfaces API payload, so `to_payload()` and `from_response()` work via standard Pydantic serialization.

    The `interface_name` is the port-channel's own name (e.g. `port-channel501`), not a member interface. Member
    interfaces are listed in `config_data.network_os.policy.ports`.

    ## Raises

    None
    """

    config_data: PortChannelDot1qTunnelHostConfigDataModel | None = Field(default=None, alias="configData")

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict:
        """
        # Summary

        Return the Ansible argument spec for the `nd_interface_port_channel_dot1q_tunnel_host` module.

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
                    switch_ip=dict(type="str", required=True),
                    interface_name=dict(type="str", required=True),
                    config_data=dict(
                        type="dict",
                        options=dict(
                            network_os=dict(
                                type="dict",
                                options=dict(
                                    network_os_type=dict(type="str", default="nx-os", choices=["nx-os"]),
                                    policy=dict(
                                        type="dict",
                                        options=dict(
                                            policy_type=dict(
                                                type="str",
                                                choices=["dot1qTunnelPoHost"],
                                            ),
                                            admin_state=dict(type="bool"),
                                            access_vlan=dict(type="int"),
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
                                            mtu=dict(type="str", choices=[e.value for e in MtuEnum]),
                                            negotiate_auto=dict(type="bool"),
                                            netflow=dict(type="bool"),
                                            netflow_monitor=dict(type="str"),
                                            netflow_sampler=dict(type="str"),
                                            orphan_port=dict(type="bool"),
                                            pfc=dict(type="bool"),
                                            port_channel_mode=dict(type="str", choices=[e.value for e in PortChannelModeEnum]),
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
