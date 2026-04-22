# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Ethernet trunk host (trunkHost) interface Pydantic models for Nexus Dashboard.

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload
structure for ethernet trunkHost interfaces. The playbook config uses the same nesting so that
`to_payload()` and `from_response()` work via standard Pydantic serialization with no custom
wrapping or flattening.

## Model Hierarchy

- `EthernetTrunkHostInterfaceModel` (top-level, `NDBaseModel`)
    - `interface_name` (identifier)
    - `interface_type` (default: "ethernet")
    - `config_data` -> `EthernetTrunkHostConfigDataModel`
        - `mode` (default: "trunk")
        - `network_os` -> `EthernetTrunkHostNetworkOSModel`
            - `network_os_type` (default: "nx-os")
            - `policy` -> `EthernetTrunkHostPolicyModel`
                - `admin_state`, `allowed_vlans`, `native_vlan`, `vlan_mapping`,
                  `vlan_mapping_entries`, `bpdu_guard`, `speed`, `policy_type`, etc.
                - `vlan_mapping_entries` -> List[`EthernetTrunkHostVlanMappingEntryModel`]
"""

import re
from typing import ClassVar, Dict, List, Literal, Optional, Set

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    FieldSerializationInfo,
    field_serializer,
    field_validator,
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
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel

ALLOWED_VLANS_PATTERN = r"^(none|all|(\d{1,4}(-\d{1,4})?)(,\d{1,4}(-\d{1,4})?)*)$"


class EthernetTrunkHostVlanMappingEntryModel(NDNestedModel):
    """
    # Summary

    A single VLAN mapping entry for selective dot1q-tunnel on an ethernet trunkHost interface. Maps to an element of the
    `configData.networkOS.policy.vlanMappingEntries` list in the ND API.

    ## Raises

    None
    """

    customer_inner_vlan_id: Optional[int] = Field(default=None, alias="customerInnerVlanId", ge=1, le=4094, description="Customer inner VLAN")
    customer_vlan_id: Optional[str] = Field(default=None, alias="customerVlanId", description="Customer VLAN id or VLAN range(s) for selective dot1q-tunnel")
    dot1q_tunnel: Optional[bool] = Field(default=None, alias="dot1qTunnel", description="Selective dot1q-tunnel")
    provider_vlan_id: Optional[int] = Field(default=None, alias="providerVlanId", ge=1, le=4094, description="Provider VLAN")


class EthernetTrunkHostPolicyModel(NDNestedModel):
    """
    # Summary

    Policy fields for an ethernet trunkHost interface. Maps directly to the `configData.networkOS.policy` object in the ND API.

    ## Raises

    ### ValueError

    - If `allowed_vlans` is not `none`, `all`, or a comma-separated list of VLAN ids / ranges
    """

    admin_state: Optional[bool] = Field(default=None, alias="adminState", description="Enable or disable the interface")
    allowed_vlans: Optional[str] = Field(
        default=None,
        alias="allowedVlans",
        description="Allowed VLANs on the trunk: 'none', 'all', or VLAN ranges (e.g., '1-200,500-2000,3000')",
    )
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
    native_vlan: Optional[int] = Field(default=None, alias="nativeVlan", ge=1, le=4094, description="Native VLAN for the trunk interface")
    negotiate_auto: Optional[bool] = Field(default=None, alias="negotiateAuto", description="Enable link auto-negotiation")
    netflow: Optional[bool] = Field(default=None, alias="netflow", description="Enable Netflow on the interface")
    netflow_monitor: Optional[str] = Field(default=None, alias="netflowMonitor", description="Layer 2 Netflow monitor name")
    netflow_sampler: Optional[str] = Field(default=None, alias="netflowSampler", description="Netflow sampler name")
    orphan_port: Optional[bool] = Field(default=None, alias="orphanPort", description="Enable vPC orphan port")
    pfc: Optional[bool] = Field(default=None, alias="pfc", description="Enable priority flow control")
    policy_type: Optional[TrunkHostPolicyTypeEnum] = Field(default=None, alias="policyType", description="Interface policy type")
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
    vlan_mapping: Optional[bool] = Field(default=None, alias="vlanMapping", description="Enable VLAN mapping on the interface")
    vlan_mapping_entries: Optional[List[EthernetTrunkHostVlanMappingEntryModel]] = Field(
        default=None, alias="vlanMappingEntries", description="List of VLAN mapping entries; required when `vlan_mapping` is true"
    )

    # --- Validators ---

    @field_validator("allowed_vlans", mode="before")
    @classmethod
    def validate_allowed_vlans(cls, value):
        """
        # Summary

        Validate that `allowed_vlans` is either `none`, `all`, or a comma-separated list of VLAN ids / ranges
        (e.g., `"1-200,500-2000,3000"`). Loose validation — the ND API performs range/ordering checks.

        ## Raises

        ### ValueError

        - If `value` is a non-empty string that does not match the expected format
        """
        if value is None:
            return value
        if not isinstance(value, str) or not re.match(ALLOWED_VLANS_PATTERN, value):
            raise ValueError(f"allowed_vlans must be 'none', 'all', or a comma-separated list of VLAN ids or ranges (e.g., '1-200,500-2000'), got: {value!r}")
        return value

    @field_validator("policy_type", mode="before")
    @classmethod
    def normalize_policy_type(cls, value):
        """
        # Summary

        Accept `policy_type` in either Ansible (`trunk_host`) or API (`trunkHost`) format, normalizing to the API value for enum validation.

        ## Raises

        None
        """
        if value is None:
            return value
        ansible_to_api = {e.name.lower(): e.value for e in TrunkHostPolicyTypeEnum}
        return ansible_to_api.get(value, value)

    # --- Serializers ---

    @field_serializer("policy_type")
    def serialize_policy_type(self, value: Optional[str], info: FieldSerializationInfo) -> Optional[str]:
        """
        # Summary

        Serialize `policy_type` to the API's camelCase value in payload mode, or the Ansible-friendly name in config mode.

        With `use_enum_values=True`, the stored value is the enum's `.value` string (e.g. `"trunkHost"`).

        ## Raises

        None
        """
        if value is None:
            return None
        mode = (info.context or {}).get("mode", "payload")
        if mode == "config":
            reverse = {e.value: e.name.lower() for e in TrunkHostPolicyTypeEnum}
            return reverse.get(value, value)
        return value


class EthernetTrunkHostNetworkOSModel(NDNestedModel):
    """
    # Summary

    Network OS container for an ethernet trunkHost interface. Maps to `configData.networkOS` in the ND API.

    ## Raises

    None
    """

    network_os_type: str = Field(default="nx-os", alias="networkOSType")
    policy: Optional[EthernetTrunkHostPolicyModel] = Field(default=None, alias="policy")


class EthernetTrunkHostConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for an ethernet trunkHost interface. Maps to `configData` in the ND API.

    ## Raises

    None
    """

    mode: str = Field(default="trunk", alias="mode")
    network_os: EthernetTrunkHostNetworkOSModel = Field(alias="networkOS")


class EthernetTrunkHostInterfaceModel(NDBaseModel):
    """
    # Summary

    Ethernet trunkHost interface configuration for Nexus Dashboard.

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
    config_data: Optional[EthernetTrunkHostConfigDataModel] = Field(default=None, alias="configData")

    @field_validator("interface_name", mode="before")
    @classmethod
    def normalize_interface_name(cls, value):
        """
        # Summary

        Normalize interface name to match ND API convention (e.g., ethernet1/1 -> Ethernet1/1).

        ## Raises

        None
        """
        if isinstance(value, str) and value:
            return value[0].upper() + value[1:]
        return value

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> Dict:
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
                    interface_type=dict(type="str", default="ethernet"),
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
                                            native_vlan=dict(type="int"),
                                            negotiate_auto=dict(type="bool"),
                                            netflow=dict(type="bool"),
                                            netflow_monitor=dict(type="str"),
                                            netflow_sampler=dict(type="str"),
                                            orphan_port=dict(type="bool"),
                                            pfc=dict(type="bool"),
                                            policy_type=dict(
                                                type="str",
                                                choices=[e.name.lower() for e in TrunkHostPolicyTypeEnum],
                                                default="trunk_host",
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
                                            vlan_mapping=dict(type="bool"),
                                            vlan_mapping_entries=dict(
                                                type="list",
                                                elements="dict",
                                                options=dict(
                                                    customer_inner_vlan_id=dict(type="int"),
                                                    customer_vlan_id=dict(type="str"),
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
