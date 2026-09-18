# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Port-channel access-mode interface Pydantic models for Nexus Dashboard (NX-OS `accessPoHost`, IOS-XE `iosXeAccessPoHost`; issue #536).

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload
structure for access-mode port-channel interfaces. The playbook config uses the same nesting
so that `to_payload()` and `from_response()` work via standard Pydantic serialization with no
custom wrapping or flattening.

The port-channel policy is the single source of truth for member configuration. Member ethernet
interfaces inherit access-mode settings from the port-channel; users do not pre-configure members.

## Model Hierarchy

- `PortChannelAccessInterfaceModel` (top-level, `PortChannelInterfaceBaseModel`)
    - `switch_ip` (composite identifier)
    - `interface_name` (composite identifier; e.g. `port-channel501`)
    - `interface_type` (hardcoded: "portChannel")
    - `config_data` -> `PortChannelAccessConfigDataModel`
        - `mode` (hardcoded: "access")
        - `network_os` -> `PortChannelAccessNetworkOSModel | XePortChannelAccessNetworkOSModel` (discriminated union on
          `network_os_type`; injected as `nx-os` when omitted so pre-#536 playbooks are unchanged)
            - `PortChannelAccessNetworkOSModel` (`network_os_type: "nx-os"`)
                - `policy` -> `PortChannelAccessPolicyModel` (`policy_type: "accessPoHost"`, injected when omitted)
            - `XePortChannelAccessNetworkOSModel` (`network_os_type: "ios-xe"`)
                - `policy` -> `XePortChannelAccessPolicyModel` (`policy_type: "iosXeAccessPoHost"`, injected when omitted)

`policy_type` is optional on input: each network OS has exactly one managed access port-channel policy type today, so it is
derived from `network_os_type` (`ethernet_common.default_policy_type`). An explicit value is still accepted and validated.
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    AccessPoHostPolicyTypeEnum,
    BpduFilterEnum,
    BpduGuardEnum,
    DuplexModeEnum,
    LacpRateEnum,
    LinkTypeEnum,
    MtuEnum,
    PortChannelModeEnum,
    SpeedEnum,
    StormControlActionEnum,
    XeAccessPoHostPolicyTypeEnum,
    XePortChannelModeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_common import (
    default_network_os_type,
    default_policy_type,
    normalize_member_interface_names,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.policy_base import InterfacePolicyStrictBase
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_common import PortChannelInterfaceBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.storm_control import StormControlMutexMixin
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription


class PortChannelAccessPolicyModel(StormControlMutexMixin):
    """
    # Summary

    Policy fields for the NX-OS `accessPoHost` template (`int_port_channel_access_host`). Maps directly to the
    `configData.networkOS.policy` object in the ND API where `policyType == "accessPoHost"`.

    The `ports` field carries the list of member interface names (e.g. `Ethernet1/1`). Member interfaces inherit
    access-mode configuration from this policy; modifying a member's standalone configuration while it is a
    port-channel member is restricted by the ethernet orchestrators.

    ## Raises

    None
    """

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND 4.2.1 `int_port_channel_access_host` template defaults (schema-sourced via nd-openapi `intPortChannelAccessHostTemplate`). ND echoes these
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
    }

    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")
    access_vlan: int | None = Field(default=None, alias="accessVlan", ge=1, le=4094, description="VLAN for this access port-channel")
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
    negotiate_auto: bool | None = Field(default=None, alias="negotiateAuto", description="Enable link auto-negotiation")
    netflow: bool | None = Field(default=None, alias="netflow", description="Enable Netflow on the interface")
    netflow_monitor: str | None = Field(default=None, alias="netflowMonitor", description="Layer 2 Netflow monitor name (required when `netflow=true`)")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler", description="Netflow sampler name")
    orphan_port: bool | None = Field(
        default=None, alias="orphanPort", description="Configure as a vPC orphan port (suspended by secondary peer on vPC failure)"
    )
    pfc: bool | None = Field(default=None, alias="pfc", description="Enable Priority Flow Control")
    policy_type: Literal["accessPoHost"] = Field(
        alias="policyType",
        description="Access port-channel policy template discriminator; injected as `accessPoHost` when omitted (see `default_policy_type`)",
    )

    @model_validator(mode="before")
    @classmethod
    def default_policy_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `policyType: accessPoHost` when the input omits the discriminator (`ethernet_common.default_policy_type`).

        ## Raises

        None
        """
        return default_policy_type(data, AccessPoHostPolicyTypeEnum.ACCESS_PO_HOST.value)

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

    # --- Validators ---

    @model_validator(mode="after")
    def _validate_netflow_monitor_present(self) -> PortChannelAccessPolicyModel:
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
        (`ethernet_common.normalize_member_interface_names`): `e1/1` / `eth1/1` -> `Ethernet1/1`, `gi1/0/2` -> `GigabitEthernet1/0/2`,
        any other family verbatim. Members are always physical ethernet ports; matching the wire key exactly keeps idempotency.

        ## Raises

        None
        """
        return normalize_member_interface_names(value)


class XePortChannelAccessPolicyModel(InterfacePolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeAccessPoHost` template (`ios_xe_int_port_channel_access_host`). Maps to
    `configData.networkOS.policy` where `policyType == "iosXeAccessPoHost"`. A strict subset of the NX-OS branch: `description` max length
    is 200, `mtu` is an integer 1500-9198 (NX-OS takes the `default` / `jumbo` enum), `port_channel_mode` adds the PAgP `auto` /
    `desirable` values, and there is no LACP / storm-control / QoS block. The 4.3.1-only `deviceTrackingPolicy` / `flowMonitors` fields
    are deliberately not modeled while both 4.2.1 and 4.3.1 are supported. ND injects a read-only `portChannelId` on the echo, which the
    read-mode stripping in `InterfacePolicyStrictBase` drops.

    ## Raises

    None
    """

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND `ios_xe_int_port_channel_access_host` template defaults as ECHOED (lab 2026-09-15, 4.2.1.10 and 4.3.1.175): ND does not
    # inject an mtu for port-channels, so the table carries none.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        **InterfacePolicyStrictBase.reverse_diff_defaults,
        "bpduGuard": "default",
        "portChannelMode": "active",
    }

    policy_type: Literal["iosXeAccessPoHost"] = Field(
        alias="policyType", description="IOS-XE access port-channel policy template discriminator; injected as `iosXeAccessPoHost` when omitted"
    )

    @model_validator(mode="before")
    @classmethod
    def default_policy_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `policyType: iosXeAccessPoHost` when the input omits the discriminator (`ethernet_common.default_policy_type`).

        ## Raises

        None
        """
        return default_policy_type(data, XeAccessPoHostPolicyTypeEnum.IOS_XE_ACCESS_PO_HOST.value)

    access_vlan: int | None = Field(default=None, alias="accessVlan", ge=1, le=4094, description="VLAN for this access port-channel")
    bpdu_guard: BpduGuardEnum | None = Field(default=None, alias="bpduGuard", description="Enable spanning-tree BPDU guard")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=200, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    mtu: int | None = Field(default=None, alias="mtu", ge=1500, le=9198, description="Port-channel MTU (1500-9198)")
    port_channel_mode: XePortChannelModeEnum | None = Field(
        default=None, alias="portChannelMode", description="Port-channel mode (on/active/passive/auto/desirable)"
    )
    ports: list[str] | None = Field(default=None, alias="ports", description="Member interface names (e.g. ['GigabitEthernet1/0/2'])")

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


class XePortChannelAccessNetworkOSModel(NDNestedModel):
    """
    # Summary

    IOS-XE branch of the network-OS container for an access-mode port-channel. Selected from the outer union when
    `networkOSType == "ios-xe"`.

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field. The Literal constrains the value.
    network_os_type: Literal["ios-xe"] = Field(default="ios-xe", alias="networkOSType", description="Network OS (platform) type discriminator")
    policy: XePortChannelAccessPolicyModel | None = Field(default=None, alias="policy")


class PortChannelAccessNetworkOSModel(NDNestedModel):
    """
    # Summary

    NX-OS branch of the network-OS container for an access-mode port-channel. Maps to `configData.networkOS` in the ND API.
    Selected from the outer union when `networkOSType == "nx-os"` (the injected default when the input omits it).

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field. The Literal constrains the value.
    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType", description="Network OS (platform) type discriminator")
    policy: PortChannelAccessPolicyModel | None = Field(default=None, alias="policy")


class PortChannelAccessConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for an access-mode port-channel interface. Maps to `configData` in the ND API.

    ## Raises

    None
    """

    mode: Literal["access"] = Field(default="access", alias="mode", frozen=True)
    network_os: PortChannelAccessNetworkOSModel | XePortChannelAccessNetworkOSModel = Field(
        default_factory=PortChannelAccessNetworkOSModel, alias="networkOS", discriminator="network_os_type"
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


class PortChannelAccessInterfaceModel(PortChannelInterfaceBaseModel):
    """
    # Summary

    Access-mode port-channel interface configuration for Nexus Dashboard (NX-OS `accessPoHost` or IOS-XE `iosXeAccessPoHost`).

    Uses a composite identifier (`switch_ip`, `interface_name`). The nested model structure mirrors the ND Manage
    Interfaces API payload, so `to_payload()` and `from_response()` work via standard Pydantic serialization.

    The `interface_name` is the port-channel's own name (e.g. `port-channel501`), not a member interface. Member
    interfaces are listed in `config_data.network_os.policy.ports`.

    ## Raises

    None
    """

    config_data: PortChannelAccessConfigDataModel | None = Field(default=None, alias="configData")

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict:
        """
        # Summary

        Return the Ansible argument spec for the `nd_interface_port_channel_access` module.

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
                                                    AccessPoHostPolicyTypeEnum.ACCESS_PO_HOST.value,
                                                    XeAccessPoHostPolicyTypeEnum.IOS_XE_ACCESS_PO_HOST.value,
                                                ],
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
                                            monitor=dict(type="bool"),
                                            # str with no choices: the NX-OS branch takes the default/jumbo enum,
                                            # the IOS-XE branch an int (the branch models validate the form).
                                            mtu=dict(type="str"),
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
