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
        - `network_os` -> `NexusLoopbackNetworkOSModel | XeLoopbackNetworkOSModel` (outer discriminated union on `network_os_type`)
            - `NexusLoopbackNetworkOSModel` (`network_os_type: "nx-os"`)
                - `policy` -> `NexusLoopbackPolicyModel | IpfmLoopbackPolicyModel | MplsLoopbackPolicyModel` (`policy_type` discriminator)
                    - `admin_state`, `ip`, `ipv6`, `vrf`, etc. (`ipfmLoopback` and `mplsLoopback` policy types get dedicated
                      models sharing `NexusLoopbackPolicyBase`)
            - `XeLoopbackNetworkOSModel` (`network_os_type: "ios-xe"`)
                - `policy` -> `XeLoopbackPolicyModel | XeLoopbackShutNoshutPolicyModel | XeUnderlayLoopbackPolicyModel |
                  XeInternalLoopbackPolicyModel | CsrLoopbackPolicyModel | Csr1kvLoopbackPolicyModel` (`policy_type` discriminator)
                    - Each branch declares its own fields on `LoopbackPolicyStrictBase` (write-strict / read-tolerant; no NX-OS
                      fields shared)
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


class LoopbackPolicyStrictBase(NDNestedModel):
    """
    # Summary

    Write-strict / read-tolerant base for every managed loopback policy branch (NX-OS and IOS-XE). Sets `extra="forbid"` so fields belonging
    to a different `policy_type` are rejected, strips `None`-valued keys first so unset flat-argspec options are not rejected, and declares
    `admin_state` — the only field common to all loopback templates on both network OS types.

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

    @model_validator(mode="before")
    @classmethod
    def strip_none_valued_keys(cls, data, info):
        """
        # Summary

        Drop `None`-valued keys before validation so unset flat-argspec options do not trip `extra="forbid"`. On the read
        path (validation `context={"mode": "read"}`, set by `from_response`), also drop keys not declared on this model so
        ND-injected read-only keys (e.g. `linkStateRoutingTag`) do not trip `extra="forbid"` while write-side input stays strict.

        ## Raises

        None
        """
        if not isinstance(data, dict):
            return data
        data = {key: value for key, value in data.items() if value is not None}
        if info.context and info.context.get("mode") == "read":
            allowed = set(cls.model_fields) | {field.alias for field in cls.model_fields.values() if field.alias}
            data = {key: value for key, value in data.items() if key in allowed}
        return data


class NexusLoopbackPolicyBase(LoopbackPolicyStrictBase):
    """
    # Summary

    Shared policy fields common to every managed NX-OS loopback template. Inherits write-strict / read-tolerant behavior and
    `admin_state` from `LoopbackPolicyStrictBase`.

    ## Raises

    None
    """

    ip: IPv4Host = Field(default=None, alias="ip", description="Loopback IPv4 address (bare host form, e.g. 10.1.1.1; CIDR input is accepted and normalized)")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=254, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")


class NexusLoopbackPolicyModel(NexusLoopbackPolicyBase):
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


class IpfmLoopbackPolicyModel(NexusLoopbackPolicyBase):
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


class MplsLoopbackPolicyModel(NexusLoopbackPolicyBase):
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


class XeLoopbackPolicyModel(LoopbackPolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeLoopback` template (`ios_xe_int_loopback`). Maps to `configData.networkOS.policy` where
    `policyType == "iosXeLoopback"`.

    ## Raises

    None
    """

    policy_type: Literal["iosXeLoopback"] = Field(alias="policyType", description="IOS-XE loopback policy template discriminator")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=200, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    ip: IPv4Host = Field(default=None, alias="ip", description="Loopback IPv4 address (bare host form; CIDR input is accepted and normalized)")
    vrf: str | None = Field(default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name")


class XeLoopbackShutNoshutPolicyModel(LoopbackPolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeLoopbackShutNoshut` template (`ios_xe_int_loopback_admin_state`). The template carries only
    `adminState`, inherited from `LoopbackPolicyStrictBase`.

    ## Raises

    None
    """

    policy_type: Literal["iosXeLoopbackShutNoshut"] = Field(alias="policyType", description="IOS-XE admin-state-only loopback policy template discriminator")


class XeUnderlayLoopbackPolicyModel(LoopbackPolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeUnderlayLoopback` template (`ios_xe_int_underlay_loopback`). Unlike NX-OS `underlayLoopback`
    (system-provisioned, excluded), this policy type is in the XE create-side enum and therefore user-creatable.

    ## Raises

    None
    """

    policy_type: Literal["iosXeUnderlayLoopback"] = Field(alias="policyType", description="IOS-XE underlay loopback policy template discriminator")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=254, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    ip: IPv4Host = Field(default=None, alias="ip", description="Loopback IPv4 address (bare host form; CIDR input is accepted and normalized)")
    secondary_ip: str | None = Field(default=None, alias="secondaryIp", description="Secondary IP address of the NVE interface loopback")


class XeInternalLoopbackPolicyModel(LoopbackPolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeInternalLoopback` template (`ios_xe_int_loopback_internal`). `ip` and `ipv6` are plain strings —
    the ND 4.2.1 schema deliberately leaves them unvalidated for this template (no `format: ipv4`), so the model matches the schema.

    ## Raises

    None
    """

    policy_type: Literal["iosXeInternalLoopback"] = Field(alias="policyType", description="IOS-XE internal loopback policy template discriminator")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=200, description="Interface description")
    enable_pim: bool | None = Field(default=None, alias="enablePim", description="Enable PIM")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    ip: str | None = Field(default=None, alias="ip", description="Loopback IP address (unvalidated string per the ND schema for this template)")
    ipv6: str | None = Field(default=None, alias="ipv6", description="Loopback IPv6 address (unvalidated string per the ND schema for this template)")
    vrf: str | None = Field(default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name")


class CsrLoopbackPolicyModel(LoopbackPolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `csrLoopback` template (`csr_int_loopback`). The ND 4.2.1 OpenAPI READ schema lists this
    branch's discriminator as `csrIntLoopback`, but a live-lab probe (2026-07-18, ND 4.2.1, fabric ISN, switch WAN1) proved
    the wire actually echoes the create-side `csrLoopback` on the intent-path GET as well. The model uses the single
    wire-verified name; the drift is recorded in the bug-tracker vault.

    ## Raises

    None
    """

    policy_type: Literal["csrLoopback"] = Field(alias="policyType", description="CSR loopback policy template discriminator")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=254, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    ip: IPv4Host = Field(default=None, alias="ip", description="Loopback IPv4 address (bare host form; CIDR input is accepted and normalized)")
    vrf: str | None = Field(default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name")


class Csr1kvLoopbackPolicyModel(LoopbackPolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `csr1kvLoopback` template (`csr1kv_loopback`). The template carries only `adminState` and `extraConfig`.

    ## Raises

    None
    """

    policy_type: Literal["csr1kvLoopback"] = Field(alias="policyType", description="CSR1kv loopback policy template discriminator")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")


class NexusLoopbackNetworkOSModel(NDNestedModel):
    """
    # Summary

    NX-OS branch of the network-OS container for a loopback interface. Selected from the outer union when `networkOSType == "nx-os"`.

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field, and required fields are always
    # explicitly set. The Literal constrains the value; same pattern as the policy_type discriminator.
    network_os_type: Literal["nx-os"] = Field(alias="networkOSType", description="Network OS (platform) type discriminator; required by the ND API schema")
    policy: NexusLoopbackPolicyModel | IpfmLoopbackPolicyModel | MplsLoopbackPolicyModel | None = Field(
        default=None, alias="policy", discriminator="policy_type"
    )


class XeLoopbackNetworkOSModel(NDNestedModel):
    """
    # Summary

    IOS-XE branch of the network-OS container for a loopback interface. Selected from the outer union when `networkOSType == "ios-xe"`.

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field, and required fields are always
    # explicitly set. The Literal constrains the value; same pattern as the policy_type discriminator.
    network_os_type: Literal["ios-xe"] = Field(alias="networkOSType", description="Network OS (platform) type discriminator; required by the ND API schema")
    policy: (
        XeLoopbackPolicyModel
        | XeLoopbackShutNoshutPolicyModel
        | XeUnderlayLoopbackPolicyModel
        | XeInternalLoopbackPolicyModel
        | CsrLoopbackPolicyModel
        | Csr1kvLoopbackPolicyModel
        | None
    ) = Field(default=None, alias="policy", discriminator="policy_type")


class LoopbackConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for a loopback interface. Maps to `configData` in the ND API.

    ## Raises

    None
    """

    mode: Literal["managed"] = Field(default="managed", alias="mode", frozen=True)
    network_os: NexusLoopbackNetworkOSModel | XeLoopbackNetworkOSModel = Field(alias="networkOS", discriminator="network_os_type")


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

    @classmethod
    def from_response(cls, response, **kwargs):
        """
        # Summary

        Build a `LoopbackInterfaceModel` from an ND GET response, tagging validation `context={"mode": "read"}` so branch
        models tolerate ND-injected read-only policy keys (see `LoopbackPolicyStrictBase.strip_none_valued_keys`).

        ## Raises

        None
        """
        return cls.model_validate(response, by_alias=True, context={"mode": "read"}, **kwargs)

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
                                    network_os_type=dict(type="str", required=True, choices=["nx-os", "ios-xe"]),
                                    policy=dict(
                                        type="dict",
                                        options=dict(
                                            policy_type=dict(
                                                type="str",
                                                required=True,
                                                choices=[
                                                    "loopback",
                                                    "ipfmLoopback",
                                                    "mplsLoopback",
                                                    "iosXeLoopback",
                                                    "iosXeLoopbackShutNoshut",
                                                    "iosXeUnderlayLoopback",
                                                    "iosXeInternalLoopback",
                                                    "csrLoopback",
                                                    "csr1kvLoopback",
                                                ],
                                            ),
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
                                            secondary_ip=dict(type="str"),
                                            enable_pim=dict(type="bool"),
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
