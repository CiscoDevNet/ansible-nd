# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Routed (L3) port-channel interface Pydantic models for Nexus Dashboard (NX-OS `l3Po`, IOS-XE `iosXeL3PortChannel`; issue #549).

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload structure for routed port-channel
interfaces. The playbook config uses the same nesting so that `to_payload()` and `from_response()` work via standard Pydantic
serialization with no custom wrapping or flattening.

The port-channel policy is the single source of truth for member configuration. On NX-OS, ND re-homes the listed members onto the
port-channel. On IOS-XE, ND requires each member to already be a routed host (`iosXeRoutedHost`) before the port-channel is
created; `PortChannelBaseOrchestrator` verifies that before any write.

## Model Hierarchy

- `PortChannelRoutedInterfaceModel` (top-level, `PortChannelInterfaceBaseModel`)
    - `switch_ip` (composite identifier)
    - `interface_name` (composite identifier; e.g. `port-channel20`)
    - `interface_type` (hardcoded: "portChannel")
    - `config_data` -> `PortChannelRoutedConfigDataModel`
        - `mode` (hardcoded: "routed")
        - `network_os` -> `PortChannelRoutedNetworkOSModel | XePortChannelRoutedNetworkOSModel` (discriminated union on the required
          `network_os_type`)
            - `PortChannelRoutedNetworkOSModel` (`network_os_type: "nx-os"`)
                - `policy` -> `PortChannelRoutedPolicyModel` (`policy_type: "l3Po"`, injected when omitted)
            - `XePortChannelRoutedNetworkOSModel` (`network_os_type: "ios-xe"`)
                - `policy` -> `XePortChannelRoutedPolicyModel` (`policy_type: "iosXeL3PortChannel"`, injected when omitted)

`policy_type` is optional on input: each network OS has exactly one managed routed port-channel policy type today, so it is derived
from `network_os_type` (`ethernet_common.default_policy_type`). An explicit value is still accepted and validated.
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    PortChannelModeEnum,
    PortChannelRoutedPolicyTypeEnum,
    SpeedEnum,
    XePortChannelModeEnum,
    XePortChannelRoutedPolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_common import (
    default_policy_type,
    normalize_member_interface_names,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.policy_base import InterfacePolicyStrictBase
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_common import PortChannelInterfaceBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription, IPv4Host


class PortChannelRoutedPolicyModel(InterfacePolicyStrictBase):
    """
    # Summary

    Policy fields for the NX-OS `l3Po` template (`int_l3_port_channel`). Maps to `configData.networkOS.policy` where
    `policyType == "l3Po"`. The field set and ranges are identical on ND 4.2.1 and 4.3.1.

    The `ports` field carries the list of member interface names (e.g. `Ethernet1/10`); ND re-homes them onto the port-channel as
    `l3PoMember`. ND injects a read-only `portChannelId` on the echo, which the read-mode stripping in `InterfacePolicyStrictBase` drops.

    ## Raises

    None
    """

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND `int_l3_port_channel` template defaults (schema-sourced via nd-openapi `intL3PortChannelTemplate`, and as ECHOED for an l3Po
    # created without them: lab 2026-09-18, 4.2.1.10 and 4.3.1.175; 4.3.1 omits `pimDrPriority` from the echo). `routingTag` (coerced
    # to str on read) declares no default, so it has no entry.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        **InterfacePolicyStrictBase.reverse_diff_defaults,
        "copyDescription": False,
        "ipRedirects": False,
        "mtu": 9216,
        "netflow": False,
        "pfc": False,
        "pimDrPriority": 1,
        "pimSparse": False,
        "portChannelMode": "active",
        "qos": False,
        "speed": "auto",
    }

    policy_type: Literal["l3Po"] = Field(
        alias="policyType", description="Routed port-channel policy template discriminator; injected as `l3Po` when omitted (see `default_policy_type`)"
    )

    @model_validator(mode="before")
    @classmethod
    def default_policy_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `policyType: l3Po` when the input omits the discriminator (`ethernet_common.default_policy_type`).

        ## Raises

        None
        """
        return default_policy_type(data, PortChannelRoutedPolicyTypeEnum.L3_PO.value)

    copy_description: bool | None = Field(default=None, alias="copyDescription", description="Propagate the port-channel description to all member interfaces")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=254, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    ip: IPv4Host = Field(default=None, alias="ip", description="Interface IPv4 address (bare host form, e.g. 10.1.1.1; CIDR input is accepted and normalized)")
    ip_redirects: bool | None = Field(default=None, alias="ipRedirects", description="Disable IPv4 and IPv6 redirects on the interface")
    ipv6: str | None = Field(default=None, alias="ipv6", description="IPv6 address of the interface")
    ipv6_prefix: int | None = Field(default=None, alias="ipv6Prefix", ge=1, le=127, description="IPv6 prefix length used with `ipv6` (1-127)")
    mtu: int | None = Field(default=None, alias="mtu", ge=576, le=9216, description="Interface MTU (576-9216)")
    netflow: bool | None = Field(default=None, alias="netflow", description="Enable netflow (requires netflow enabled on the fabric)")
    netflow_monitor: str | None = Field(default=None, alias="netflowMonitor", description="Netflow monitor name")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler", description="Netflow sampler name (N7K only)")
    pfc: bool | None = Field(default=None, alias="pfc", description="Enable priority flow control")
    pim_dr_priority: int | None = Field(default=None, alias="pimDrPriority", ge=1, le=4294967295, description="PIM DR election priority")
    pim_sparse: bool | None = Field(default=None, alias="pimSparse", description="Enable PIM sparse mode")
    port_channel_mode: PortChannelModeEnum | None = Field(default=None, alias="portChannelMode", description="Port-channel mode (on/active/passive)")
    ports: list[str] | None = Field(default=None, alias="ports", description="Member interface names (e.g. ['Ethernet1/10', 'Ethernet1/11'])")
    prefix: int | None = Field(default=None, alias="prefix", ge=1, le=31, description="Netmask length for the IP address (1-31)")
    qos: bool | None = Field(default=None, alias="qos", description="Enable a QoS policy on the interface")
    qos_policy: str | None = Field(default=None, alias="qosPolicy", description="Custom QoS policy name (must be defined previously)")
    queuing_policy: str | None = Field(default=None, alias="queuingPolicy", description="Queuing policy name (must be defined previously)")
    routing_tag: str | None = Field(default=None, alias="routingTag", description="Routing tag associated with the interface IP")
    speed: SpeedEnum | None = Field(default=None, alias="speed", description="Interface speed")
    vrf: str | None = Field(default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name")

    # TODO(4.2.1) interface-get-field-normalization
    # ND 4.2.1 GET echoes the routed templates' routingTag as an integer even though the template defines it as a string (string in,
    # int out). Same drift as routedHost routingTag and loopback routeMapTag - keep the coerce validators in sync.
    @field_validator("routing_tag", mode="before")
    @classmethod
    def coerce_routing_tag(cls, value):
        """
        # Summary

        Coerce `routing_tag` to a string. The ND API returns this field as an integer, but the template defines it as a string.

        ## Raises

        None
        """
        if value is None:
            return value
        return str(value)

    @field_validator("ports", mode="before")
    @classmethod
    def normalize_ports(cls, value):
        """
        # Summary

        Normalize each member name to its wire-canonical prefix through the shared cross-OS helper
        (`ethernet_common.normalize_member_interface_names`): `e1/1` / `eth1/1` -> `Ethernet1/1`, any other family verbatim. Members are
        always physical ethernet ports; matching the wire key exactly keeps idempotency.

        ## Raises

        None
        """
        return normalize_member_interface_names(value)


class XePortChannelRoutedPolicyModel(InterfacePolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeL3PortChannel` template (`ios_xe_int_l3_port_channel`). Maps to `configData.networkOS.policy`
    where `policyType == "iosXeL3PortChannel"`. A strict subset of the NX-OS branch, identical on ND 4.2.1 and 4.3.1: IPv4 only,
    `description` max length 200, `mtu` 1500-9216, `prefix` 8-31, `port_channel_mode` adds the PAgP `auto` / `desirable` values, and
    there is no IPv6, PIM, QoS, netflow, speed or routing-tag field. ND injects a read-only `portChannelId` on the echo, which the
    read-mode stripping in `InterfacePolicyStrictBase` drops.

    ## Raises

    None
    """

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND `ios_xe_int_l3_port_channel` template defaults as ECHOED (lab 2026-09-18, 4.2.1.10 and 4.3.1.175): ND does not inject an
    # mtu for port-channels, so the table carries none.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        **InterfacePolicyStrictBase.reverse_diff_defaults,
        "portChannelMode": "active",
    }

    policy_type: Literal["iosXeL3PortChannel"] = Field(
        alias="policyType", description="IOS-XE routed port-channel policy template discriminator; injected as `iosXeL3PortChannel` when omitted"
    )

    @model_validator(mode="before")
    @classmethod
    def default_policy_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `policyType: iosXeL3PortChannel` when the input omits the discriminator (`ethernet_common.default_policy_type`).

        ## Raises

        None
        """
        return default_policy_type(data, XePortChannelRoutedPolicyTypeEnum.IOS_XE_L3_PORT_CHANNEL.value)

    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=200, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    ip: IPv4Host = Field(default=None, alias="ip", description="Interface IPv4 address (bare host form, e.g. 10.1.1.1; CIDR input is accepted and normalized)")
    mtu: int | None = Field(default=None, alias="mtu", ge=1500, le=9216, description="Port-channel MTU (1500-9216)")
    port_channel_mode: XePortChannelModeEnum | None = Field(
        default=None, alias="portChannelMode", description="Port-channel mode (on/active/passive/auto/desirable)"
    )
    ports: list[str] | None = Field(default=None, alias="ports", description="Member interface names (e.g. ['GigabitEthernet1/0/2'])")
    prefix: int | None = Field(default=None, alias="prefix", ge=8, le=31, description="Netmask length for the IP address (8-31)")
    vrf: str | None = Field(default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name")

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


class PortChannelRoutedNetworkOSModel(NDNestedModel):
    """
    # Summary

    NX-OS branch of the network-OS container for a routed port-channel. Selected from the outer union when
    `networkOSType == "nx-os"`.

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field, and required fields are always
    # explicitly set. The Literal constrains the value; same pattern as the policy_type discriminator.
    network_os_type: Literal["nx-os"] = Field(alias="networkOSType", description="Network OS (platform) type discriminator; required by the ND API schema")
    policy: PortChannelRoutedPolicyModel | None = Field(default=None, alias="policy")


class XePortChannelRoutedNetworkOSModel(NDNestedModel):
    """
    # Summary

    IOS-XE branch of the network-OS container for a routed port-channel. Selected from the outer union when
    `networkOSType == "ios-xe"`.

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field, and required fields are always
    # explicitly set. The Literal constrains the value; same pattern as the policy_type discriminator.
    network_os_type: Literal["ios-xe"] = Field(alias="networkOSType", description="Network OS (platform) type discriminator; required by the ND API schema")
    policy: XePortChannelRoutedPolicyModel | None = Field(default=None, alias="policy")


class PortChannelRoutedConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for a routed port-channel interface. Maps to `configData` in the ND API.

    ## Raises

    None
    """

    mode: Literal["routed"] = Field(default="routed", alias="mode", frozen=True)
    network_os: PortChannelRoutedNetworkOSModel | XePortChannelRoutedNetworkOSModel = Field(alias="networkOS", discriminator="network_os_type")


class PortChannelRoutedInterfaceModel(PortChannelInterfaceBaseModel):
    """
    # Summary

    Routed (L3) port-channel interface configuration for Nexus Dashboard (NX-OS `l3Po` or IOS-XE `iosXeL3PortChannel`).

    Inherits the composite identifier (`switch_ip`, `interface_name`), the lowercase name normalizer and the IOS-XE create-name rewrite
    from `PortChannelInterfaceBaseModel`. The nested model structure mirrors the ND Manage Interfaces API payload, so `to_payload()`
    and `from_response()` work via standard Pydantic serialization. Member interfaces are listed in
    `config_data.network_os.policy.ports`.

    ## Raises

    None
    """

    config_data: PortChannelRoutedConfigDataModel | None = Field(default=None, alias="configData")

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict:
        """
        # Summary

        Return the Ansible argument spec for the `nd_interface_port_channel_routed` module.

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
                                    network_os_type=dict(type="str", required=True, choices=["nx-os", "ios-xe"]),
                                    policy=dict(
                                        type="dict",
                                        options=dict(
                                            policy_type=dict(
                                                type="str",
                                                choices=[
                                                    PortChannelRoutedPolicyTypeEnum.L3_PO.value,
                                                    XePortChannelRoutedPolicyTypeEnum.IOS_XE_L3_PORT_CHANNEL.value,
                                                ],
                                            ),
                                            admin_state=dict(type="bool"),
                                            copy_description=dict(type="bool"),
                                            description=dict(type="str"),
                                            extra_config=dict(type="str"),
                                            ip=dict(type="str"),
                                            ip_redirects=dict(type="bool"),
                                            ipv6=dict(type="str"),
                                            ipv6_prefix=dict(type="int"),
                                            mtu=dict(type="int"),
                                            netflow=dict(type="bool"),
                                            netflow_monitor=dict(type="str"),
                                            netflow_sampler=dict(type="str"),
                                            pfc=dict(type="bool"),
                                            pim_dr_priority=dict(type="int"),
                                            pim_sparse=dict(type="bool"),
                                            # Superset of both branches' modes; the NX-OS branch model rejects the PAgP auto/desirable values.
                                            port_channel_mode=dict(type="str", choices=[e.value for e in XePortChannelModeEnum]),
                                            ports=dict(type="list", elements="str"),
                                            prefix=dict(type="int"),
                                            qos=dict(type="bool"),
                                            qos_policy=dict(type="str"),
                                            queuing_policy=dict(type="str"),
                                            routing_tag=dict(type="str"),
                                            speed=dict(type="str", choices=[e.value for e in SpeedEnum]),
                                            vrf=dict(type="str"),
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
