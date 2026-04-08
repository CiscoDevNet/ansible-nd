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
        - `mode` (default: "managed")
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
from ansible_collections.cisco.nd.plugins.module_utils.constants import NDConstantMapping
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel

ACCESS_HOST_POLICY_TYPE_MAPPING = NDConstantMapping(
    {
        "access_host": "accessHost",
    }
)


class EthernetAccessPolicyModel(NDNestedModel):
    """
    # Summary

    Policy fields for an ethernet accessHost interface. Maps directly to the `configData.networkOS.policy` object in the ND API.

    ## Raises

    None
    """

    admin_state: Optional[bool] = Field(default=None, alias="adminState")
    access_vlan: Optional[int] = Field(default=None, alias="accessVlan")
    bpdu_guard: Optional[str] = Field(default=None, alias="bpduGuard")
    cdp: Optional[bool] = Field(default=None, alias="cdp")
    description: Optional[str] = Field(default=None, alias="description")
    duplex_mode: Optional[str] = Field(default=None, alias="duplexMode")
    extra_config: Optional[str] = Field(default=None, alias="extraConfig")
    mtu: Optional[str] = Field(default=None, alias="mtu")
    netflow: Optional[bool] = Field(default=None, alias="netflow")
    netflow_monitor: Optional[str] = Field(default=None, alias="netflowMonitor")
    netflow_sampler: Optional[str] = Field(default=None, alias="netflowSampler")
    orphan_port: Optional[bool] = Field(default=None, alias="orphanPort")
    pfc: Optional[bool] = Field(default=None, alias="pfc")
    policy_type: Optional[str] = Field(default=None, alias="policyType")
    port_type_edge_trunk: Optional[bool] = Field(default=None, alias="portTypeEdgeTrunk")
    qos: Optional[bool] = Field(default=None, alias="qos")
    qos_policy: Optional[str] = Field(default=None, alias="qosPolicy")
    queuing_policy: Optional[str] = Field(default=None, alias="queuingPolicy")
    speed: Optional[str] = Field(default=None, alias="speed")

    # --- Serializers ---

    @field_serializer("policy_type")
    def serialize_policy_type(self, value: Optional[str], info: FieldSerializationInfo) -> Optional[str]:
        """
        # Summary

        Serialize `policy_type` to the API's camelCase value in payload mode, or keep the Ansible name in config mode.

        ## Raises

        None
        """
        if value is None:
            return None
        mode = (info.context or {}).get("mode", "payload")
        if mode == "config":
            return value
        return ACCESS_HOST_POLICY_TYPE_MAPPING.get_dict().get(value, value)

    # --- Validators ---

    @field_validator("policy_type", mode="before")
    @classmethod
    def normalize_policy_type(cls, v):
        """
        # Summary

        Accept `policy_type` in either Ansible (`access_host`) or API (`accessHost`) format, normalizing to Ansible names.

        ## Raises

        None
        """
        if v is None:
            return v
        reverse_mapping = {api: ansible for ansible, api in ACCESS_HOST_POLICY_TYPE_MAPPING.data.items() if ansible != api}
        return reverse_mapping.get(v, v)


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
                                            bpdu_guard=dict(type="str", choices=["enable", "disable", "default"]),
                                            cdp=dict(type="bool"),
                                            description=dict(type="str"),
                                            duplex_mode=dict(type="str", choices=["auto", "full", "half"]),
                                            extra_config=dict(type="str"),
                                            mtu=dict(type="str", choices=["default", "jumbo"]),
                                            netflow=dict(type="bool"),
                                            netflow_monitor=dict(type="str"),
                                            netflow_sampler=dict(type="str"),
                                            orphan_port=dict(type="bool"),
                                            pfc=dict(type="bool"),
                                            policy_type=dict(
                                                type="str",
                                                choices=ACCESS_HOST_POLICY_TYPE_MAPPING.get_original_data(),
                                                default="access_host",
                                            ),
                                            port_type_edge_trunk=dict(type="bool"),
                                            qos=dict(type="bool"),
                                            qos_policy=dict(type="str"),
                                            queuing_policy=dict(type="str"),
                                            speed=dict(
                                                type="str",
                                                choices=[
                                                    "auto",
                                                    "10Mb",
                                                    "100Mb",
                                                    "1Gb",
                                                    "2.5Gb",
                                                    "5Gb",
                                                    "10Gb",
                                                    "25Gb",
                                                    "40Gb",
                                                    "50Gb",
                                                    "100Gb",
                                                    "200Gb",
                                                    "400Gb",
                                                    "800Gb",
                                                ],
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
