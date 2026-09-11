# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Ethernet access-mode interface Pydantic models for Nexus Dashboard (NX-OS `accessHost`, IOS-XE `iosXeAccess`; issue #534).

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload
structure for ethernet access-mode interfaces. The playbook config uses the same nesting so that
`to_payload()` and `from_response()` work via standard Pydantic serialization with no custom
wrapping or flattening.

## Model Hierarchy

- `EthernetAccessInterfaceModel` (top-level, `NDBaseModel`)
    - `switch_ip` (composite identifier)
    - `interface_name` (composite identifier)
    - `interface_type` (hardcoded: "ethernet")
    - `config_data` -> `EthernetAccessConfigDataModel`
        - `mode` (hardcoded: "access")
        - `network_os` -> `EthernetAccessNetworkOSModel | XeEthernetAccessNetworkOSModel` (discriminated union on `network_os_type`;
          injected as `nx-os` when omitted so pre-#534 playbooks are unchanged)
            - `EthernetAccessNetworkOSModel` (`network_os_type: "nx-os"`)
                - `policy` -> `EthernetAccessPolicyModel` (`policy_type: "accessHost"`, injected when omitted)
            - `XeEthernetAccessNetworkOSModel` (`network_os_type: "ios-xe"`)
                - `policy` -> `XeEthernetAccessPolicyModel` (`policy_type: "iosXeAccess"`, injected when omitted)

`policy_type` is optional on input: each network OS has exactly one managed access policy type today, so it is derived from
`network_os_type` (`ethernet_common.default_policy_type`). An explicit value is still accepted and validated.
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    AccessHostPolicyTypeEnum,
    BpduFilterEnum,
    BpduGuardEnum,
    DuplexModeEnum,
    FecEnum,
    LinkTypeEnum,
    MtuEnum,
    SpeedEnum,
    StormControlActionEnum,
    XeAccessHostPolicyTypeEnum,
    XeEthernetSpeedEnum,
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

# Public argspec `speed` choices: the union of the NX-OS and IOS-XE speed enums, in NX order with the XE-only extras appended.
# The Ansible argspec cannot express the per-policy_type subset (that stays with the Pydantic branch models), but listing the
# union lets ansible-doc / schema consumers discover every accepted spelling (PR #550 review).
_NX_SPEED_CHOICES: list[str] = [e.value for e in SpeedEnum]
_SPEED_ARGSPEC_CHOICES: list[str] = _NX_SPEED_CHOICES + [e.value for e in XeEthernetSpeedEnum if e.value not in _NX_SPEED_CHOICES]


class EthernetAccessPolicyModel(StormControlMutexMixin):
    """
    # Summary

    Policy fields for the NX-OS `accessHost` template (`int_access_host`). Maps directly to the `configData.networkOS.policy` object in
    the ND API where `policyType == "accessHost"`.

    ## Raises

    None
    """

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND 4.2.1 `int_access_host` template defaults (schema-sourced via nd-openapi `intAccessHostTemplate`). ND echoes these
    # for every field the user never set; the reverse pass of `get_diff` normalizes existing-side matches to absent
    # so replaced/overridden removal detection (issue #410) stays idempotent against default echoes.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        "adminState": True,
        "bpduFilter": "default",
        "bpduGuard": "enable",
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
    }

    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")
    access_vlan: int | None = Field(default=None, alias="accessVlan", ge=1, le=4094, description="VLAN for this access port")
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
    negotiate_auto: bool | None = Field(default=None, alias="negotiateAuto", description="Enable link auto-negotiation")
    netflow: bool | None = Field(default=None, alias="netflow", description="Enable Netflow on the interface")
    netflow_monitor: str | None = Field(default=None, alias="netflowMonitor", description="Layer 2 Netflow monitor name")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler", description="Netflow sampler name")
    orphan_port: bool | None = Field(default=None, alias="orphanPort", description="Enable vPC orphan port")
    pfc: bool | None = Field(default=None, alias="pfc", description="Enable priority flow control")
    policy_type: Literal["accessHost"] = Field(
        alias="policyType", description="Access-host policy template discriminator; injected as `accessHost` when omitted (see `default_policy_type`)"
    )

    @model_validator(mode="before")
    @classmethod
    def default_policy_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `policyType: accessHost` when the input omits the discriminator (`ethernet_common.default_policy_type`).

        ## Raises

        None
        """
        return default_policy_type(data, AccessHostPolicyTypeEnum.ACCESS_HOST.value)

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


class XeEthernetAccessPolicyModel(InterfacePolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeAccess` template (`ios_xe_int_access_host`). Maps to `configData.networkOS.policy` where
    `policyType == "iosXeAccess"`. A strict subset of the NX-OS branch: `description` max length is 200, `mtu` is an integer
    1500-9216 (NX-OS takes the `default` / `jumbo` enum), and `speed` uses the XE enum (`noNegotiate`, no 200/400/800Gb). The
    4.3.1-only `deviceTrackingPolicy` / `flowMonitors` fields are deliberately not modeled while both 4.2.1 and 4.3.1 are supported.

    ## Raises

    None
    """

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND `ios_xe_int_access_host` template defaults (schema-sourced via nd-openapi `iosXeIntAccessHostTemplate`, identical on
    # 4.2.1 and 4.3.1), in the model's dumped form. The orchestrator derives its unconfigured-default query filter from this table.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        **InterfacePolicyStrictBase.reverse_diff_defaults,
        "bpduGuard": "default",
        "mtu": 1500,
        "speed": "auto",
    }

    policy_type: Literal["iosXeAccess"] = Field(
        alias="policyType", description="IOS-XE access-host policy template discriminator; injected as `iosXeAccess` when omitted (see `default_policy_type`)"
    )

    @model_validator(mode="before")
    @classmethod
    def default_policy_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `policyType: iosXeAccess` when the input omits the discriminator (`ethernet_common.default_policy_type`).

        ## Raises

        None
        """
        return default_policy_type(data, XeAccessHostPolicyTypeEnum.IOS_XE_ACCESS.value)

    access_vlan: int | None = Field(default=None, alias="accessVlan", ge=1, le=4094, description="VLAN for this access port")
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


class XeEthernetAccessNetworkOSModel(NDNestedModel):
    """
    # Summary

    IOS-XE branch of the network-OS container for an access-mode ethernet interface. Selected from the outer union when
    `networkOSType == "ios-xe"`.

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field. The Literal constrains the value.
    network_os_type: Literal["ios-xe"] = Field(default="ios-xe", alias="networkOSType", description="Network OS (platform) type discriminator")
    policy: XeEthernetAccessPolicyModel | None = Field(default=None, alias="policy")


class EthernetAccessNetworkOSModel(NDNestedModel):
    """
    # Summary

    NX-OS branch of the network-OS container for an access-mode ethernet interface. Selected from the outer union when
    `networkOSType == "nx-os"` (the injected default when the input omits it).

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field. The Literal constrains the value.
    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType", description="Network OS (platform) type discriminator")
    policy: EthernetAccessPolicyModel | None = Field(default=None, alias="policy")


class EthernetAccessConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for an access-mode ethernet interface. Maps to `configData` in the ND API.

    ## Raises

    None
    """

    mode: Literal["access"] = Field(default="access", alias="mode", frozen=True)
    network_os: EthernetAccessNetworkOSModel | XeEthernetAccessNetworkOSModel = Field(
        default_factory=EthernetAccessNetworkOSModel, alias="networkOS", discriminator="network_os_type"
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


class EthernetAccessInterfaceModel(NDBaseModel):
    """
    # Summary

    Access-mode ethernet interface configuration for Nexus Dashboard (NX-OS `accessHost` or IOS-XE `iosXeAccess`).

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
    config_data: EthernetAccessConfigDataModel | None = Field(default=None, alias="configData")

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

        Return the Ansible argument spec for the `nd_interface_ethernet_access` module.

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
                                                choices=[AccessHostPolicyTypeEnum.ACCESS_HOST.value, XeAccessHostPolicyTypeEnum.IOS_XE_ACCESS.value],
                                            ),
                                            admin_state=dict(type="bool"),
                                            access_vlan=dict(type="int"),
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
