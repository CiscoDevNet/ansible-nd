# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Ethernet access (accessHost) interface Pydantic models for Nexus Dashboard.

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload
structure for ethernet accessHost interfaces. The playbook config uses the same nesting so that
`to_payload()` and `from_response()` work via standard Pydantic serialization with no custom
wrapping or flattening.

## Model Hierarchy

- `EthernetAccessInterfaceModel` (top-level, `NDBaseModel`)
    - `interface_name` (identifier)
    - `interface_type` (default: "ethernet")
    - `config_data` -> `EthernetAccessConfigDataModel`
        - `mode` (default: "access")
        - `network_os` -> `EthernetAccessNetworkOSModel`
            - `network_os_type` (default: "nx-os")
            - `policy` -> `EthernetAccessPolicyModel`
                - `admin_state`, `access_vlan`, `bpdu_guard`, `speed`, `policy_type`, etc.
"""

from typing import ClassVar, Dict, List, Literal, Optional, Set

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    FieldSerializationInfo,
    field_serializer,
    field_validator,
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
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel


class EthernetAccessPolicyModel(NDNestedModel):
    """
    # Summary

    Policy fields for an ethernet accessHost interface. Maps directly to the `configData.networkOS.policy` object in the ND API.

    ## Raises

    None
    """

    admin_state: Optional[bool] = Field(default=None, alias="adminState", description="Enable or disable the interface")
    access_vlan: Optional[int] = Field(default=None, alias="accessVlan", ge=1, le=4094, description="VLAN for this access port")
    bandwidth: Optional[int] = Field(default=None, alias="bandwidth", ge=1, le=100000000, description="Bandwidth in kilobits")
    bpdu_filter: Optional[BpduFilterEnum] = Field(default=None, alias="bpduFilter", description="Configure spanning-tree BPDU filter")
    bpdu_guard: Optional[BpduGuardEnum] = Field(default=None, alias="bpduGuard", description="Enable spanning-tree BPDU guard")
    cdp: Optional[bool] = Field(default=None, alias="cdp", description="Enable CDP on the interface")
    debounce_timer: Optional[int] = Field(default=None, alias="debounceTimer", ge=0, le=20000, description="Link debounce timer in milliseconds")
    debounce_linkup_timer: Optional[int] = Field(
        default=None, alias="debounceLinkupTimer", ge=1000, le=10000, description="Link debounce link-up timer in milliseconds"
    )
    description: Optional[str] = Field(default=None, alias="description", max_length=254, description="Interface description")
    duplex_mode: Optional[DuplexModeEnum] = Field(default=None, alias="duplexMode", description="Port duplex mode")
    error_detection_acl: Optional[bool] = Field(default=None, alias="errorDetectionAcl", description="Enable error detection for ACL installation failures")
    extra_config: Optional[str] = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    fec: Optional[FecEnum] = Field(default=None, alias="fec", description="Forward error correction mode")
    inherit_bandwidth: Optional[int] = Field(
        default=None, alias="inheritBandwidth", ge=1, le=100000000, description="Inherit bandwidth in kilobits for sub-interfaces"
    )
    link_type: Optional[LinkTypeEnum] = Field(default=None, alias="linkType", description="Spanning-tree link type")
    monitor: Optional[bool] = Field(default=None, alias="monitor", description="Enable switchport monitor for SPAN/ERSPAN")
    mtu: Optional[MtuEnum] = Field(default=None, alias="mtu", description="Interface MTU")
    negotiate_auto: Optional[bool] = Field(default=None, alias="negotiateAuto", description="Enable link auto-negotiation")
    netflow: Optional[bool] = Field(default=None, alias="netflow", description="Enable Netflow on the interface")
    netflow_monitor: Optional[str] = Field(default=None, alias="netflowMonitor", description="Layer 2 Netflow monitor name")
    netflow_sampler: Optional[str] = Field(default=None, alias="netflowSampler", description="Netflow sampler name")
    orphan_port: Optional[bool] = Field(default=None, alias="orphanPort", description="Enable vPC orphan port")
    pfc: Optional[bool] = Field(default=None, alias="pfc", description="Enable priority flow control")
    policy_type: Optional[AccessHostPolicyTypeEnum] = Field(default=None, alias="policyType", description="Interface policy type")
    port_type_edge_trunk: Optional[bool] = Field(default=None, alias="portTypeEdgeTrunk", description="Enable spanning-tree edge port behavior")
    qos: Optional[bool] = Field(default=None, alias="qos", description="Enable QoS configuration for this interface")
    qos_policy: Optional[str] = Field(default=None, alias="qosPolicy", description="Custom QoS policy name")
    queuing_policy: Optional[str] = Field(default=None, alias="queuingPolicy", description="Custom queuing policy name")
    speed: Optional[SpeedEnum] = Field(default=None, alias="speed", description="Interface speed")
    storm_control: Optional[bool] = Field(default=None, alias="stormControl", description="Enable traffic storm control")
    storm_control_action: Optional[StormControlActionEnum] = Field(
        default=None, alias="stormControlAction", description="Storm control action on threshold violation"
    )
    storm_control_broadcast_level: Optional[str] = Field(
        default=None, alias="stormControlBroadcastLevel", description="Broadcast storm control level in percentage (0.00-100.00)"
    )
    storm_control_broadcast_level_pps: Optional[int] = Field(
        default=None,
        alias="stormControlBroadcastLevelPps",
        ge=0,
        le=200000000,
        description="Broadcast storm control level in packets per second",
    )
    storm_control_multicast_level: Optional[str] = Field(
        default=None, alias="stormControlMulticastLevel", description="Multicast storm control level in percentage (0.00-100.00)"
    )
    storm_control_multicast_level_pps: Optional[int] = Field(
        default=None,
        alias="stormControlMulticastLevelPps",
        ge=0,
        le=200000000,
        description="Multicast storm control level in packets per second",
    )
    storm_control_unicast_level: Optional[str] = Field(
        default=None, alias="stormControlUnicastLevel", description="Unicast storm control level in percentage (0.00-100.00)"
    )
    storm_control_unicast_level_pps: Optional[int] = Field(
        default=None,
        alias="stormControlUnicastLevelPps",
        ge=0,
        le=200000000,
        description="Unicast storm control level in packets per second",
    )

    # --- Validators ---

    @field_validator("policy_type", mode="before")
    @classmethod
    def normalize_policy_type(cls, v):
        """
        # Summary

        Accept `policy_type` in either Ansible (`access_host`) or API (`accessHost`) format, normalizing to the API value for enum validation.

        ## Raises

        None
        """
        if v is None:
            return v
        ansible_to_api = {e.name.lower(): e.value for e in AccessHostPolicyTypeEnum}
        return ansible_to_api.get(v, v)

    # --- Serializers ---

    @field_serializer("policy_type")
    def serialize_policy_type(self, value: Optional[str], info: FieldSerializationInfo) -> Optional[str]:
        """
        # Summary

        Serialize `policy_type` to the API's camelCase value in payload mode, or the Ansible-friendly name in config mode.

        With `use_enum_values=True`, the stored value is the enum's `.value` string (e.g. `"accessHost"`).

        ## Raises

        None
        """
        if value is None:
            return None
        mode = (info.context or {}).get("mode", "payload")
        if mode == "config":
            reverse = {e.value: e.name.lower() for e in AccessHostPolicyTypeEnum}
            return reverse.get(value, value)
        return value


class EthernetAccessNetworkOSModel(NDNestedModel):
    """
    # Summary

    Network OS container for an ethernet accessHost interface. Maps to `configData.networkOS` in the ND API.

    ## Raises

    None
    """

    network_os_type: str = Field(default="nx-os", alias="networkOSType")
    policy: Optional[EthernetAccessPolicyModel] = Field(default=None, alias="policy")


class EthernetAccessConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for an ethernet accessHost interface. Maps to `configData` in the ND API.

    ## Raises

    None
    """

    mode: str = Field(default="access", alias="mode")
    network_os: EthernetAccessNetworkOSModel = Field(alias="networkOS")


class EthernetAccessInterfaceModel(NDBaseModel):
    """
    # Summary

    Ethernet accessHost interface configuration for Nexus Dashboard.

    Uses a composite identifier (`switch_ip`, `interface_name`). The nested model structure mirrors the ND Manage
    Interfaces API payload, so `to_payload()` and `from_response()` work via standard Pydantic serialization.

    ## Raises

    None
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[Optional[List[str]]] = ["switch_ip", "interface_name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "composite"

    # --- Serialization Configuration ---

    payload_exclude_fields: ClassVar[Set[str]] = {"switch_ip"}

    # --- Fields ---

    switch_ip: str = Field(alias="switchIp")
    interface_name: str = Field(alias="interfaceName")
    interface_type: str = Field(default="ethernet", alias="interfaceType")
    config_data: Optional[EthernetAccessConfigDataModel] = Field(default=None, alias="configData")

    @field_validator("interface_name", mode="before")
    @classmethod
    def normalize_interface_name(cls, v):
        """
        # Summary

        Normalize interface name to match ND API convention (e.g., ethernet1/1 -> Ethernet1/1).

        ## Raises

        None
        """
        if isinstance(v, str) and v:
            return v[0].upper() + v[1:]
        return v

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> Dict:
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
                    interface_type=dict(type="str", default="ethernet"),
                    config_data=dict(
                        type="dict",
                        options=dict(
                            mode=dict(type="str", default="access"),
                            network_os=dict(
                                type="dict",
                                options=dict(
                                    network_os_type=dict(type="str", default="nx-os"),
                                    policy=dict(
                                        type="dict",
                                        options=dict(
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
                                            mtu=dict(type="str", choices=[e.value for e in MtuEnum]),
                                            negotiate_auto=dict(type="bool"),
                                            netflow=dict(type="bool"),
                                            netflow_monitor=dict(type="str"),
                                            netflow_sampler=dict(type="str"),
                                            orphan_port=dict(type="bool"),
                                            pfc=dict(type="bool"),
                                            policy_type=dict(
                                                type="str",
                                                choices=[e.name.lower() for e in AccessHostPolicyTypeEnum],
                                                default="access_host",
                                            ),
                                            port_type_edge_trunk=dict(type="bool"),
                                            qos=dict(type="bool"),
                                            qos_policy=dict(type="str"),
                                            queuing_policy=dict(type="str"),
                                            speed=dict(type="str", choices=[e.value for e in SpeedEnum]),
                                            storm_control=dict(type="bool"),
                                            storm_control_action=dict(type="str", choices=[e.value for e in StormControlActionEnum]),
                                            storm_control_broadcast_level=dict(type="str"),
                                            storm_control_broadcast_level_pps=dict(type="int"),
                                            storm_control_multicast_level=dict(type="str"),
                                            storm_control_multicast_level_pps=dict(type="int"),
                                            storm_control_unicast_level=dict(type="str"),
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
