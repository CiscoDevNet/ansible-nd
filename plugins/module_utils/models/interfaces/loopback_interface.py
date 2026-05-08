# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Loopback interface Pydantic models for Nexus Dashboard.

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload
structure. The playbook config uses the same nesting so that `to_payload()` and `from_response()`
work via standard Pydantic serialization with no custom wrapping or flattening.

## Model Hierarchy

- `LoopbackInterfaceModel` (top-level, `NDBaseModel`)
    - `switch_ip` (composite identifier)
    - `interface_name` (composite identifier)
    - `interface_type` (hardcoded: "loopback")
    - `config_data` -> `LoopbackConfigDataModel`
        - `mode` (hardcoded: "managed")
        - `network_os` -> `LoopbackNetworkOSModel`
            - `network_os_type` (hardcoded: "nx-os")
            - `policy` -> `LoopbackPolicyModel`
                - `admin_state`, `ip`, `ipv6`, `vrf`, etc. (`policy_type` is hardcoded to "loopback";
                  `ipfmLoopback` and `userDefined` policy types will get dedicated modules)
"""

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription, IPv4CIDR, IPv6CIDR


class LoopbackPolicyModel(NDNestedModel):
    """
    # Summary

    Policy fields for a loopback interface. Maps directly to the `configData.networkOS.policy` object in the ND API.

    ## Raises

    None
    """

    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")
    ip: IPv4CIDR = Field(default=None, alias="ip", description="Loopback IPv4 address in CIDR notation (e.g. 10.1.1.1/32)")
    ipv6: IPv6CIDR = Field(default=None, alias="ipv6", description="Loopback IPv6 address in CIDR notation")
    vrf: str | None = Field(default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name")
    route_map_tag: str | None = Field(default=None, alias="routeMapTag", description="Route-Map tag associated with interface IP")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=254, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    policy_type: Literal["loopback"] = Field(default="loopback", alias="policyType", description="Loopback policy template (hardcoded for this module)")

    # --- Validators ---

    # TODO(ND 4.3): Remove this coercion once the ND 4.3 GET-side type drift is fixed.
    # ND 4.2 returns `routeMapTag` as an integer even though the template defines it as a string.
    # The same drift affects SVI `routingTag` - keep both validators in sync.
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


class LoopbackNetworkOSModel(NDNestedModel):
    """
    # Summary

    Network OS container for a loopback interface. Maps to `configData.networkOS` in the ND API.

    ## Raises

    None
    """

    network_os_type: str = Field(default="nx-os", alias="networkOSType")
    policy: LoopbackPolicyModel | None = Field(default=None, alias="policy")


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

    Uses a composite identifier (`switch_ip`, `interface_name`). The nested model structure mirrors the ND Manage Interfaces API
    payload, so `to_payload()` and `from_response()` work via standard Pydantic serialization.

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
    interface_type: str = Field(default="loopback", alias="interfaceType")
    config_data: LoopbackConfigDataModel | None = Field(default=None, alias="configData")

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
    def get_argument_spec(cls) -> dict:
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
                    config_data=dict(
                        type="dict",
                        options=dict(
                            network_os=dict(
                                type="dict",
                                options=dict(
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
