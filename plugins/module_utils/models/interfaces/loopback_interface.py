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
            - `policy` -> `LoopbackPolicyModel` (`policy_type: loopback | ipfmLoopback | mplsLoopback`)
                - `admin_state`, `ip`, `ipv6`, `vrf`, etc. (`policy_type` is required and discriminates the branch;
                  `ipfmLoopback` and `mplsLoopback` policy types get dedicated models sharing `LoopbackPolicyBase`)
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription, IPv4Host, IPv6CIDR


class LoopbackPolicyBase(NDNestedModel):
    """
    # Summary

    Shared policy fields common to every managed NX-OS loopback template. Sets `extra="forbid"` so fields belonging to a
    different `policy_type` are rejected, and strips `None`-valued keys first so unset flat-argspec options are not rejected.

    ## Raises

    None
    """

    model_config = ConfigDict(extra="forbid")

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND 4.2.1 echoes schema-declared template defaults for every field the user never set; the reverse pass of
    # `get_diff` normalizes existing-side matches to absent so replaced/overridden removal detection (issue #410)
    # stays idempotent against default echoes. `adminState` defaults to true on every loopback template.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        "adminState": True,
    }

    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")
    ip: IPv4Host = Field(default=None, alias="ip", description="Loopback IPv4 address (bare host form, e.g. 10.1.1.1; CIDR input is accepted and normalized)")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=254, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")

    @model_validator(mode="before")
    @classmethod
    def strip_none_valued_keys(cls, data):
        """
        # Summary

        Drop keys whose value is `None` before validation so unset flat-argspec options do not trip `extra="forbid"`.

        ## Raises

        None
        """
        if isinstance(data, dict):
            return {key: value for key, value in data.items() if value is not None}
        return data


class LoopbackPolicyModel(LoopbackPolicyBase):
    """
    # Summary

    Policy fields for the NX-OS `loopback` template. Maps to `configData.networkOS.policy` where `policyType == "loopback"`.

    ## Raises

    None
    """

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND 4.2.1 `int_loopback` template defaults (schema-sourced via nd-openapi `intLoopbackTemplate`). Values must be in
    # the model's DUMPED form: the schema declares routeMapTag as integer 12345, but `coerce_route_map_tag` stores it as
    # a string (ND 4.2.1 GET-side type drift), so the table holds "12345". ClassVar overrides replace the base table,
    # so `adminState` is restated here.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        "adminState": True,
        "routeMapTag": "12345",
    }

    policy_type: Literal["loopback"] = Field(alias="policyType", description="Loopback policy template discriminator")
    ipv6: IPv6CIDR = Field(default=None, alias="ipv6", description="Loopback IPv6 address in CIDR notation")
    vrf: str | None = Field(default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name")
    route_map_tag: str | None = Field(default=None, alias="routeMapTag", description="Route-Map tag associated with interface IP")

    # TODO(4.2.1): Remove coerce_route_map_tag once GET-side type drift is fixed.
    # ND 4.2.1 returns `routeMapTag` as an integer even though the template defines it as a string.
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


class SecondaryIpModel(NDNestedModel):
    """
    # Summary

    A secondary IPv4 address entry for an IPFM loopback (`secondaryIpList` item).

    ## Raises

    None
    """

    ip: str | None = Field(default=None, alias="ip", description="Secondary IPv4 address")
    prefix: int | None = Field(default=None, alias="prefix", ge=4, le=32, description="Subnet mask length (4-32)")


class IpfmLoopbackPolicyModel(LoopbackPolicyBase):
    """
    # Summary

    Policy fields for the NX-OS `ipfmLoopback` template (IP Fabric for Media). Maps to `configData.networkOS.policy` where
    `policyType == "ipfmLoopback"`.

    ## Raises

    None
    """

    policy_type: Literal["ipfmLoopback"] = Field(alias="policyType", description="IPFM loopback policy template discriminator")
    vrf: str | None = Field(default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name")
    advertise_loopback: bool | None = Field(default=None, alias="advertiseLoopback", description="Advertise loopback via OSPF/IS-IS")
    is_service_reflect: bool | None = Field(default=None, alias="isServiceReflect", description="Use loopback as service-reflect source")
    routing_tag: str | None = Field(default=None, alias="routingTag", description="Routing tag associated with the interface IP")
    secondary_ip_list: list[SecondaryIpModel] | None = Field(default=None, alias="secondaryIpList", description="Secondary IPv4 addresses")


class MplsLoopbackPolicyModel(LoopbackPolicyBase):
    """
    # Summary

    Policy fields for the NX-OS `mplsLoopback` template. Maps to `configData.networkOS.policy` where
    `policyType == "mplsLoopback"`. Note: `mplsLoopback` is lab-verified creatable but absent from the ND create-side
    discriminator enum (spec drift); modelled per the template and wire.

    ## Raises

    None
    """

    policy_type: Literal["mplsLoopback"] = Field(alias="policyType", description="MPLS loopback policy template discriminator")
    dci_routing_protocol: Literal["ospf", "isis"] | None = Field(default=None, alias="dciRoutingProtocol", description="DCI link-state routing protocol")
    dci_routing_tag: str | None = Field(default=None, alias="dciRoutingTag", description="DCI routing tag")
    ospf_area_id: str | None = Field(default=None, alias="ospfAreaId", min_length=1, max_length=15, description="OSPF area identifier")


class LoopbackNetworkOSModel(NDNestedModel):
    """
    # Summary

    Network OS container for a loopback interface. Maps to `configData.networkOS` in the ND API.

    ## Raises

    None
    """

    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType", frozen=True)
    policy: LoopbackPolicyModel | IpfmLoopbackPolicyModel | MplsLoopbackPolicyModel | None = Field(default=None, alias="policy", discriminator="policy_type")


class LoopbackConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for a loopback interface. Maps to `configData` in the ND API.

    ## Raises

    None
    """

    mode: Literal["managed"] = Field(default="managed", alias="mode", frozen=True)
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
    interface_type: Literal["loopback"] = Field(default="loopback", alias="interfaceType", frozen=True)
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
                                            policy_type=dict(type="str", required=True, choices=["loopback", "ipfmLoopback", "mplsLoopback"]),
                                            admin_state=dict(type="bool"),
                                            ip=dict(type="str"),
                                            description=dict(type="str"),
                                            extra_config=dict(type="str"),
                                            vrf=dict(type="str"),
                                            ipv6=dict(type="str"),
                                            route_map_tag=dict(type="str"),
                                            advertise_loopback=dict(type="bool"),
                                            is_service_reflect=dict(type="bool"),
                                            routing_tag=dict(type="str"),
                                            secondary_ip_list=dict(type="list", elements="dict", options=dict(ip=dict(type="str"), prefix=dict(type="int"))),
                                            dci_routing_protocol=dict(type="str", choices=["ospf", "isis"]),
                                            dci_routing_tag=dict(type="str"),
                                            ospf_area_id=dict(type="str"),
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
