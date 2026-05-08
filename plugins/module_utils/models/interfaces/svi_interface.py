# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
SVI (switched virtual interface) Pydantic models for Nexus Dashboard.

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload structure for SVI
interfaces (`interfaceType: "svi"`, `policyType: "svi"`, `mode: "managed"`). The playbook config uses the same
nesting so that `to_payload()` and `from_response()` work via standard Pydantic serialization with no custom
wrapping or flattening.

## Model Hierarchy

- `SviInterfaceModel` (top-level, `NDBaseModel`)
    - `interface_name` (identifier, e.g. `vlan333`)
    - `interface_type` (hardcoded: "svi")
    - `config_data` -> `SviConfigDataModel`
        - `mode` (hardcoded: "managed")
        - `network_os` -> `SviNetworkOSModel`
            - `network_os_type` (hardcoded: "nx-os")
            - `policy` -> `SviPolicyModel`
                - `policy_type` (hardcoded: SviPolicyTypeEnum.SVI), `admin_state`, `ip`, `prefix`, HSRP block, DHCP relay, etc.
    - `oper_data` -> `SviOperDataModel` (read-only, returned on GET, excluded from payload)

## Field set

Fields in `SviPolicyModel` mirror the `policyType: "svi"` schema in the ND Manage API (createInterfaceSviManagedNexusType
oneOf -> int_vlan.template), covering the full set of HSRP, DHCP relay, VRF, route tag, PIM, and Netflow options the
ND GUI exposes for managed SVIs on Nexus. OSPF / ISIS / BFD / replication-mode fields belong to other policy types
(e.g. `policyType: "vpcBackupSvi"` / int_fabric_vlan_11_1) and would be modelled as separate variants.
"""

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import SviPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription


class SviPolicyModel(NDNestedModel):
    """
    # Summary

    Policy fields for an SVI interface. Maps directly to the `configData.networkOS.policy` object in the ND API.

    `policy_type` is required by the API as a discriminator on both POST and PUT, so it carries a default of
    `SviPolicyTypeEnum.SVI` and is always serialized.

    ## Raises

    None
    """

    policy_type: SviPolicyTypeEnum = Field(default=SviPolicyTypeEnum.SVI, alias="policyType", frozen=True, description="Interface policy type (hardcoded for this module)")
    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")
    description: AsciiDescription = Field(default=None, alias="description", max_length=254, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    mtu: int | None = Field(default=None, alias="mtu", ge=68, le=9216, description="Interface MTU")
    ip: str | None = Field(default=None, alias="ip", description="IPv4 address of the SVI")
    prefix: int | None = Field(default=None, alias="prefix", ge=1, le=31, description="IPv4 netmask length used with `ip`")
    ipv6: str | None = Field(default=None, alias="ipv6", description="IPv6 address of the SVI")
    prefixv6: int | None = Field(default=None, alias="prefixv6", ge=1, le=127, description="IPv6 netmask length used with `ipv6`")
    ip_redirects: bool | None = Field(default=None, alias="ipRedirects", description="Disable both IPv4/IPv6 redirects on the interface")
    vrf_interface: str | None = Field(
        default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name; use `default` for default VRF"
    )
    routing_tag: str | None = Field(default=None, alias="routingTag", description="Routing tag associated with the interface IP address")
    pim_sparse: bool | None = Field(default=None, alias="pimSparse", description="Enable PIM sparse-mode on the interface")
    pim_dr_priority: int | None = Field(default=None, alias="pimDrPriority", ge=1, le=4294967295, description="Priority for PIM DR election on the interface")

    # --- HSRP block (gated by `hsrp=true`) ---
    hsrp: bool | None = Field(default=None, alias="hsrp", description="Enable HSRP on the interface")
    hsrp_vip: str | None = Field(default=None, alias="hsrpVip", description="HSRP IPv4 virtual IP; must match on active/standby device")
    hsrp_vipv6: str | None = Field(default=None, alias="hsrpVipv6", description="HSRP IPv6 virtual IP; must match on active/standby device")
    hsrp_group: int | None = Field(default=None, alias="hsrpGroup", ge=0, le=4095, description="HSRP group number")
    hsrp_groupv6: int | None = Field(default=None, alias="hsrpGroupv6", ge=0, le=4095, description="HSRP IPv6 group number; if unset the IPv4 group is reused")
    hsrp_version: Literal[1, 2] | None = Field(default=None, alias="hsrpVersion", description="HSRP version (1 or 2)")
    hsrp_priority: int | None = Field(default=None, alias="hsrpPriority", ge=0, le=255, description="HSRP priority for election")
    preempt: bool | None = Field(default=None, alias="preempt", description="Enable HSRP preemption (overthrow lower priority active routers)")
    mac: str | None = Field(default=None, alias="mac", description="HSRP virtual MAC address override")

    # --- DHCP relay block (up to 3 servers, each with optional VRF override) ---
    dhcp_server_address1: str | None = Field(default=None, alias="dhcpServerAddress1", description="Primary DHCP relay server IP address")
    dhcp_server_address2: str | None = Field(default=None, alias="dhcpServerAddress2", description="Secondary DHCP relay server IP address")
    dhcp_server_address3: str | None = Field(default=None, alias="dhcpServerAddress3", description="Tertiary DHCP relay server IP address")
    vrf_dhcp1: str | None = Field(default=None, alias="vrfDhcp1", description="VRF to reach DHCP server 1; `default` for default VRF, blank for interface VRF")
    vrf_dhcp2: str | None = Field(default=None, alias="vrfDhcp2", description="VRF to reach DHCP server 2; `default` for default VRF, blank for interface VRF")
    vrf_dhcp3: str | None = Field(default=None, alias="vrfDhcp3", description="VRF to reach DHCP server 3; `default` for default VRF, blank for interface VRF")

    advertise_subnet_in_underlay: bool | None = Field(
        default=None, alias="advertiseSubnetInUnderlay", description="Advertise the SVI subnet into the underlay routing protocol"
    )
    netflow: bool | None = Field(default=None, alias="netflow", description="Enable Netflow on the interface")
    netflow_monitor: str | None = Field(default=None, alias="netflowMonitor", description="Layer 3 Netflow monitor name (required when `netflow=true`)")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler", description="Netflow sampler name (applicable to N7K only)")

    # --- Validators ---

    # TODO(ND 4.3): remove this validator once ND 4.2 reaches end-of-support.
    # ND 4.2 returns `routingTag` as an integer on GET despite the OpenAPI spec declaring it as string and accepting
    # string on POST/PUT. Cisco has confirmed this is fixed in ND 4.3, so once 4.2 is deprecated this coercion is
    # dead weight. Tracked in `project_svi_hsrp_phase2.md`.
    @field_validator("routing_tag", mode="before")
    @classmethod
    def coerce_routing_tag_to_string(cls, value):
        """
        # Summary

        Accept `routing_tag` as either string or integer. ND 4.2's API accepts string form on POST/PUT (matching
        the OpenAPI spec which declares this as `string`), but GET responses return the value as an integer (e.g.
        `12345` rather than `"12345"`). Coerce ints to their decimal string form so round-trips and idempotency
        comparisons work uniformly. Lab-confirmed 2026-04-30 that PUT-back with the string form is accepted.

        Cisco has confirmed the GET-side type drift is fixed in ND 4.3; this validator can be removed once ND 4.2
        is deprecated.

        ## Raises

        None
        """
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
        return value


class SviNetworkOSModel(NDNestedModel):
    """
    # Summary

    Network OS container for an SVI interface. Maps to `configData.networkOS` in the ND API.

    ## Raises

    None
    """

    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType", frozen=True)
    policy: SviPolicyModel | None = Field(default=None, alias="policy")


class SviConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for an SVI interface. Maps to `configData` in the ND API. `mode` is always `"managed"` for
    SVIs and is required by the API as a discriminator.

    ## Raises

    None
    """

    mode: Literal["managed"] = Field(default="managed", alias="mode", frozen=True)
    network_os: SviNetworkOSModel = Field(alias="networkOS")


class SviOperDataModel(NDNestedModel):
    """
    # Summary

    Operational state container returned by GET on an SVI interface. Server-populated and read-only. Excluded from
    payloads via `SviInterfaceModel.payload_exclude_fields`.

    ## Raises

    None
    """

    admin_status: str | None = Field(default=None, alias="adminStatus")
    operational_description: str | None = Field(default=None, alias="operationalDescription")
    operational_status: str | None = Field(default=None, alias="operationalStatus")
    port_channel_id: int | None = Field(default=None, alias="portChannelId")
    switch_name: str | None = Field(default=None, alias="switchName")
    vlan_range: str | None = Field(default=None, alias="vlanRange")


class SviInterfaceModel(NDBaseModel):
    """
    # Summary

    SVI interface configuration for Nexus Dashboard.

    Uses a composite identifier (`switch_ip`, `interface_name`). The nested model structure mirrors the ND Manage
    Interfaces API payload, so `to_payload()` and `from_response()` work via standard Pydantic serialization.

    `interface_type` is sent on POST but NOT on PUT (the API rejects it on PUT). The orchestrator's `update()` method
    is responsible for popping it from the payload before sending.

    ## Raises

    None
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[list[str] | None] = ["switch_ip", "interface_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "composite"

    # --- Serialization Configuration ---

    payload_exclude_fields: ClassVar[set[str]] = {"switch_ip", "oper_data"}

    # --- Fields ---

    switch_ip: str = Field(alias="switchIp")
    interface_name: str = Field(alias="interfaceName")
    interface_type: Literal["svi"] = Field(default="svi", alias="interfaceType", frozen=True)
    config_data: SviConfigDataModel | None = Field(default=None, alias="configData")
    oper_data: SviOperDataModel | None = Field(default=None, alias="operData")

    @field_validator("interface_name", mode="before")
    @classmethod
    def normalize_interface_name(cls, value):
        """
        # Summary

        Normalize SVI interface names to the ND API convention (lowercase `vlan` prefix, e.g. `Vlan333` -> `vlan333`,
        `VLAN333` -> `vlan333`). Bare integers are accepted and prefixed with `vlan` (e.g. `333` -> `vlan333`).

        ## Raises

        None
        """
        if isinstance(value, int):
            return f"vlan{value}"
        if isinstance(value, str) and value:
            stripped = value.strip()
            if stripped.isdigit():
                return f"vlan{stripped}"
            if stripped.lower().startswith("vlan"):
                return "vlan" + stripped[4:]
        return value

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict:
        """
        # Summary

        Return the Ansible argument spec for the `nd_interface_svi` module.

        Each config item targets a single SVI identified by `interface_name` (e.g. `vlan333`). To configure multiple SVIs
        in one task, list multiple config items. Per-SVI L3 settings (ip, hsrp_*, vrf_interface, ...) live under
        `config_data.network_os.policy` and apply to that one interface only.

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
                                            description=dict(type="str"),
                                            extra_config=dict(type="str"),
                                            mtu=dict(type="int"),
                                            ip=dict(type="str"),
                                            prefix=dict(type="int"),
                                            ipv6=dict(type="str"),
                                            prefixv6=dict(type="int"),
                                            ip_redirects=dict(type="bool"),
                                            vrf_interface=dict(type="str"),
                                            routing_tag=dict(type="str"),
                                            pim_sparse=dict(type="bool"),
                                            pim_dr_priority=dict(type="int"),
                                            hsrp=dict(type="bool"),
                                            hsrp_vip=dict(type="str"),
                                            hsrp_vipv6=dict(type="str"),
                                            hsrp_group=dict(type="int"),
                                            hsrp_groupv6=dict(type="int"),
                                            hsrp_version=dict(type="int", choices=[1, 2]),
                                            hsrp_priority=dict(type="int"),
                                            preempt=dict(type="bool"),
                                            mac=dict(type="str"),
                                            dhcp_server_address1=dict(type="str"),
                                            dhcp_server_address2=dict(type="str"),
                                            dhcp_server_address3=dict(type="str"),
                                            vrf_dhcp1=dict(type="str"),
                                            vrf_dhcp2=dict(type="str"),
                                            vrf_dhcp3=dict(type="str"),
                                            advertise_subnet_in_underlay=dict(type="bool"),
                                            netflow=dict(type="bool"),
                                            netflow_monitor=dict(type="str"),
                                            netflow_sampler=dict(type="str"),
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
