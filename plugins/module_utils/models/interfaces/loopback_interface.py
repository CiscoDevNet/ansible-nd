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

import ipaddress
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

    admin_state: Optional[bool] = Field(default=None, alias="adminState", description="Enable or disable the interface")
    ip: Optional[str] = Field(default=None, alias="ip", description="Loopback IPv4 address in CIDR notation (e.g. 10.1.1.1/32)")
    ipv6: Optional[str] = Field(default=None, alias="ipv6", description="Loopback IPv6 address in CIDR notation")
    vrf: Optional[str] = Field(default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name")
    route_map_tag: Optional[str] = Field(default=None, alias="routeMapTag", description="Route-Map tag associated with interface IP")
    description: Optional[str] = Field(default=None, alias="description", min_length=1, max_length=254, description="Interface description")
    extra_config: Optional[str] = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    policy_type: Optional[str] = Field(default=None, alias="policyType", description="Interface policy type")

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
    def normalize_policy_type(cls, value):
        """
        # Summary

        Accept `policy_type` in either Ansible (`ipfm_loopback`) or API (`ipfmLoopback`) format, normalizing to Ansible names.

        ## Raises

        None
        """
        if value is None:
            return value
        reverse_mapping = {api: ansible for ansible, api in LOOPBACK_POLICY_TYPE_MAPPING.data.items() if ansible != api}
        return reverse_mapping.get(value, value)

    @field_validator("route_map_tag", mode="before")
    @classmethod
    def coerce_route_map_tag(cls, value):
        """
        # Summary

        Coerce `route_map_tag` to a string. The ND API returns this field as an integer, but the template defines it as a string.

        ## Raises

        None
        """
        if value is None:
            return value
        return str(value)

    @field_validator("ip", mode="before")
    @classmethod
    def validate_ipv4(cls, value):
        """
        # Summary

        Validate that `ip` is a valid IPv4 interface address in CIDR notation.

        ## Raises

        ### ValueError

        - If `value` is not a valid IPv4 interface address in CIDR notation
        """
        if value is None:
            return value
        try:
            ipaddress.IPv4Interface(value)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as err:
            raise ValueError(f"Invalid IPv4 address: {value!r}. Expected CIDR notation (e.g. '10.1.1.1/32').") from err
        return value

    @field_validator("ipv6", mode="before")
    @classmethod
    def validate_ipv6(cls, value):
        """
        # Summary

        Validate that `ipv6` is a valid IPv6 interface address in CIDR notation.

        ## Raises

        ### ValueError

        - If `value` is not a valid IPv6 interface address in CIDR notation
        """
        if value is None:
            return value
        try:
            ipaddress.IPv6Interface(value)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as err:
            raise ValueError(f"Invalid IPv6 address: {value!r}. Expected CIDR notation (e.g. '2001:db8::1/128').") from err
        return value


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

    identifiers: ClassVar[Optional[List[str]]] = ["switch_ip", "interface_name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "composite"

    # --- Serialization Configuration ---

    payload_exclude_fields: ClassVar[Set[str]] = {"switch_ip"}

    # --- Fields ---

    switch_ip: str = Field(alias="switchIp")
    interface_name: str = Field(alias="interfaceName")
    interface_type: str = Field(default="loopback", alias="interfaceType")
    config_data: Optional[LoopbackConfigDataModel] = Field(default=None, alias="configData")

    @field_validator("interface_name", mode="before")
    @classmethod
    def normalize_interface_name(cls, value):
        """
        # Summary

        Normalize interface name to lowercase to match ND API convention (e.g., Loopback0 -> loopback0).

        ## Raises

        None
        """
        if isinstance(value, str):
            return value.lower()
        return value

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
            config=dict(
                type="list",
                elements="dict",
                required=True,
                options=dict(
                    switch_ip=dict(type="str", required=True),
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
                                            route_map_tag=dict(type="str"),
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
