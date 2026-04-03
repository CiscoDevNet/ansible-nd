# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Loopback interface Pydantic models for Nexus Dashboard.

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload
structure. The playbook config uses the same nesting so that `to_payload()` and `from_response()`
work via standard Pydantic serialization with no custom wrapping or flattening.

## Model Hierarchy

- `LoopbackInterfaceModel` (top-level, `NDBaseModel`)
    - `interface_name` (identifier)
    - `interface_type` (default: "loopback")
    - `config_data` -> `LoopbackConfigDataModel`
        - `mode` (default: "managed")
        - `network_os` -> `LoopbackNetworkOSModel`
            - `network_os_type` (default: "nx-os")
            - `policy` -> `LoopbackPolicyModel`
                - `admin_state`, `ip`, `ipv6`, `vrf`, `policy_type`, etc.
"""

from typing import Dict, List, Optional, ClassVar, Literal
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
    field_serializer,
    FieldSerializationInfo,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.constants import NDConstantMapping

LOOPBACK_POLICY_TYPE_MAPPING = NDConstantMapping(
    {
        "loopback": "loopback",
        "ipfm_loopback": "ipfmLoopback",
        "user_defined": "userDefined",
    }
)


class LoopbackPolicyModel(NDNestedModel):
    """
    # Summary

    Policy fields for a loopback interface. Maps directly to the `configData.networkOS.policy` object in the ND API.

    ## Raises

    None
    """

    admin_state: Optional[bool] = Field(default=None, alias="adminState")
    ip: Optional[str] = Field(default=None, alias="ip")
    ipv6: Optional[str] = Field(default=None, alias="ipv6")
    vrf: Optional[str] = Field(default=None, alias="vrfInterface")
    route_map_tag: Optional[int] = Field(default=None, alias="routeMapTag")
    link_state_routing_tag: Optional[str] = Field(default=None, alias="linkStateRoutingTag")
    description: Optional[str] = Field(default=None, alias="description")
    extra_config: Optional[str] = Field(default=None, alias="extraConfig")
    policy_type: Optional[str] = Field(default=None, alias="policyType")

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
        return LOOPBACK_POLICY_TYPE_MAPPING.get_dict().get(value, value)

    # --- Validators ---

    @field_validator("policy_type", mode="before")
    @classmethod
    def normalize_policy_type(cls, v):
        """
        # Summary

        Accept `policy_type` in either Ansible (`ipfm_loopback`) or API (`ipfmLoopback`) format, normalizing to Ansible names.

        ## Raises

        None
        """
        if v is None:
            return v
        reverse_mapping = {api: ansible for ansible, api in LOOPBACK_POLICY_TYPE_MAPPING.data.items() if ansible != api}
        return reverse_mapping.get(v, v)


class LoopbackNetworkOSModel(NDNestedModel):
    """
    # Summary

    Network OS container for a loopback interface. Maps to `configData.networkOS` in the ND API.

    ## Raises

    None
    """

    network_os_type: str = Field(default="nx-os", alias="networkOSType")
    policy: Optional[LoopbackPolicyModel] = Field(default=None, alias="policy")


class LoopbackConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for a loopback interface. Maps to `configData` in the ND API.

    ## Raises

    None
    """

    mode: str = Field(default="managed", alias="mode")
    network_os: LoopbackNetworkOSModel = Field(alias="networkOS")


class LoopbackInterfaceModel(NDBaseModel):
    """
    # Summary

    Loopback interface configuration for Nexus Dashboard.

    Uses a single identifier (`interface_name`). The nested model structure mirrors the ND Manage Interfaces API
    payload, so `to_payload()` and `from_response()` work via standard Pydantic serialization.

    ## Raises

    None
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[Optional[List[str]]] = ["interface_name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"

    # --- Fields ---

    interface_name: str = Field(alias="interfaceName")
    interface_type: str = Field(default="loopback", alias="interfaceType")
    config_data: Optional[LoopbackConfigDataModel] = Field(default=None, alias="configData")

    @field_validator("interface_name", mode="before")
    @classmethod
    def normalize_interface_name(cls, v):
        """
        # Summary

        Normalize interface name to lowercase to match ND API convention (e.g., Loopback0 -> loopback0).

        ## Raises

        None
        """
        if isinstance(v, str):
            return v.lower()
        return v

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> Dict:
        """
        # Summary

        Return the Ansible argument spec for the `nd_interface_loopback` module.

        ## Raises

        None
        """
        return dict(
            fabric_name=dict(type="str", required=True),
            switch_ip=dict(type="str", required=True),
            config=dict(
                type="list",
                elements="dict",
                required=True,
                options=dict(
                    interface_name=dict(type="str", required=True),
                    interface_type=dict(type="str", default="loopback"),
                    config_data=dict(
                        type="dict",
                        options=dict(
                            mode=dict(type="str", default="managed"),
                            network_os=dict(
                                type="dict",
                                options=dict(
                                    network_os_type=dict(type="str", default="nx-os"),
                                    policy=dict(
                                        type="dict",
                                        options=dict(
                                            admin_state=dict(type="bool"),
                                            ip=dict(type="str"),
                                            ipv6=dict(type="str"),
                                            vrf=dict(type="str"),
                                            route_map_tag=dict(type="int"),
                                            link_state_routing_tag=dict(type="str"),
                                            description=dict(type="str"),
                                            extra_config=dict(type="str"),
                                            policy_type=dict(
                                                type="str",
                                                choices=LOOPBACK_POLICY_TYPE_MAPPING.get_original_data(),
                                                default="loopback",
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
