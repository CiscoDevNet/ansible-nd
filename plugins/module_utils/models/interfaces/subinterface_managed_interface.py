# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Managed L3 subinterface Pydantic models for Nexus Dashboard.

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload structure for L3
subinterfaces (`interfaceType: "subInterface"`, `policyType: "subinterface"`, `mode: "managed"`). The playbook config
uses the same nesting so that `to_payload()` and `from_response()` work via standard Pydantic serialization with no
custom wrapping or flattening.

## Parents

A subinterface is created on a physical Ethernet parent (e.g. `Ethernet1/3.2`) or on a Port-channel parent
(e.g. `Port-channel10.5`). The parent type is encoded only in the `interface_name` string; the ND API does not require
a separate parent reference. The `.<sub>` portion encodes the 802.1Q dot1q sub-id.

## Model Hierarchy

- `SubinterfaceManagedInterfaceModel` (top-level, `NDBaseModel`)
    - `interface_name` (identifier, e.g. `Ethernet1/3.2`)
    - `interface_type` (hardcoded: "subInterface")
    - `config_data` -> `SubinterfaceManagedConfigDataModel`
        - `mode` (hardcoded: "managed")
        - `network_os` -> `SubinterfaceManagedNetworkOSModel`
            - `network_os_type` (hardcoded: "nx-os")
            - `policy` -> `SubinterfaceManagedPolicyModel`
                - `policy_type` (hardcoded: SubinterfaceManagedPolicyTypeEnum.SUBINTERFACE), `vlan_id`, L3 fields, PIM, Netflow

## Field set

Fields in `SubinterfaceManagedPolicyModel` mirror the `policyType: "subinterface"` schema in the ND Manage API
(createInterfaceSubInterfaceNexusType) as observed on ND 4.2.1, covering vlan_id, VRF binding, IPv4/IPv6 addressing,
routing tag, MTU, PIM, ip-redirects, admin-state, and netflow. The "unmanaged" subinterface variant
(`policyType: "monitorSubinterface"`) is handled by a separate module.
"""

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import SubinterfaceManagedPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription


class SubinterfaceManagedPolicyModel(NDNestedModel):
    """
    # Summary

    Policy fields for a managed L3 subinterface. Maps directly to the `configData.networkOS.policy` object in the
    ND API.

    `policy_type` is required by the API as a discriminator on both POST and PUT, so it carries a default of
    `SubinterfaceManagedPolicyTypeEnum.SUBINTERFACE` and is always serialized.

    ## Raises

    None
    """

    policy_type: SubinterfaceManagedPolicyTypeEnum = Field(
        default=SubinterfaceManagedPolicyTypeEnum.SUBINTERFACE,
        alias="policyType",
        frozen=True,
        description="Interface policy type (hardcoded for this module)",
    )
    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the subinterface")
    description: AsciiDescription = Field(default=None, alias="description", max_length=254, description="Subinterface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the subinterface")
    mtu: int | None = Field(default=None, alias="mtu", ge=576, le=9216, description="Subinterface MTU")
    vlan_id: int | None = Field(default=None, alias="vlanId", ge=2, le=4094, description="802.1Q VLAN tag for the subinterface")
    vrf_interface: str | None = Field(
        default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name; use `default` for default VRF"
    )
    ip: str | None = Field(default=None, alias="ip", description="IPv4 address of the subinterface")
    prefix: int | None = Field(default=None, alias="prefix", ge=8, le=31, description="IPv4 netmask length used with `ip`")
    ipv6: str | None = Field(default=None, alias="ipv6", description="IPv6 address of the subinterface")
    ipv6_prefix: int | None = Field(default=None, alias="ipv6Prefix", ge=1, le=127, description="IPv6 netmask length used with `ipv6`")
    routing_tag: str | None = Field(default=None, alias="routingTag", description="Routing tag associated with the subinterface IP address")
    ip_redirects: bool | None = Field(default=None, alias="ipRedirects", description="Disable both IPv4/IPv6 redirects on the interface")
    pim_sparse: bool | None = Field(default=None, alias="pimSparse", description="Enable PIM sparse-mode on the subinterface")
    pim_dr_priority: int | None = Field(
        default=None, alias="pimDrPriority", ge=1, le=4294967295, description="Priority for PIM DR election on the subinterface"
    )
    netflow: bool | None = Field(default=None, alias="netflow", description="Enable Netflow on the subinterface")
    netflow_monitor: str | None = Field(default=None, alias="netflowMonitor", description="Layer 3 Netflow monitor name (required when `netflow=true`)")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler", description="Netflow sampler name (applicable to N7K only)")

    # TODO(4.2.1) ND returns routingTag as int on GET despite OpenAPI declaring it string. Coerce so round-trip
    # comparisons work. Lab-confirmed against the subinterface HAR; same wire quirk as nd_interface_svi.
    @field_validator("routing_tag", mode="before")
    @classmethod
    def coerce_routing_tag_to_string(cls, value):
        """
        # Summary

        Accept `routing_tag` as either string or integer. ND 4.2's API accepts string form on POST/PUT, but GET
        responses return the value as an integer. Coerce ints to their decimal string form so round-trips and
        idempotency comparisons work uniformly.

        ## Raises

        None
        """
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
        return value


class SubinterfaceManagedNetworkOSModel(NDNestedModel):
    """
    # Summary

    Network OS container for a managed subinterface. Maps to `configData.networkOS` in the ND API.

    ## Raises

    None
    """

    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType", frozen=True)
    policy: SubinterfaceManagedPolicyModel | None = Field(default=None, alias="policy")


class SubinterfaceManagedConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for a managed subinterface. Maps to `configData` in the ND API. `mode` is always `"managed"`
    for this module and is required by the API as a discriminator.

    ## Raises

    None
    """

    mode: Literal["managed"] = Field(default="managed", alias="mode", frozen=True)
    network_os: SubinterfaceManagedNetworkOSModel = Field(alias="networkOS")


class SubinterfaceManagedOperDataModel(NDNestedModel):
    """
    # Summary

    Operational state container returned by GET on a managed subinterface. Server-populated and read-only. Excluded
    from payloads via `SubinterfaceManagedInterfaceModel.payload_exclude_fields`.

    ## Raises

    None
    """

    admin_status: str | None = Field(default=None, alias="adminStatus")
    operational_description: str | None = Field(default=None, alias="operationalDescription")
    operational_status: str | None = Field(default=None, alias="operationalStatus")
    switch_name: str | None = Field(default=None, alias="switchName")


class SubinterfaceManagedInterfaceModel(NDBaseModel):
    """
    # Summary

    Managed L3 subinterface configuration for Nexus Dashboard.

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
    interface_type: Literal["subInterface"] = Field(default="subInterface", alias="interfaceType", frozen=True)
    config_data: SubinterfaceManagedConfigDataModel | None = Field(default=None, alias="configData")
    oper_data: SubinterfaceManagedOperDataModel | None = Field(default=None, alias="operData")

    @field_validator("interface_name", mode="before")
    @classmethod
    def normalize_interface_name(cls, value):
        """
        # Summary

        Validate that `interface_name` is a dotted subinterface form on either an Ethernet or Port-channel parent
        (e.g. `Ethernet1/3.2`, `Port-channel10.5`). The parent kind is inferred from the prefix; no separate
        `parent_interface` argument is needed. The sub-id portion (`.<n>`) is required.

        Accepts any case for the parent prefix and normalizes to canonical capitalization (`Ethernet...`,
        `Port-channel...`) so user input, POST payloads, and GET responses all compare equal.

        ## Raises

        ### ValueError

        - If `value` is a string without a `.<sub>` segment.
        - If `value` does not start with `Ethernet` or `Port-channel` (case-insensitive).
        """
        if not isinstance(value, str) or not value:
            return value
        stripped = value.strip()
        if "." not in stripped:
            raise ValueError(f"interface_name must include a dot-separated subinterface id (e.g. 'Ethernet1/3.2'); got {value!r}")
        parent, sub = stripped.rsplit(".", 1)
        parent_lower = parent.lower()
        # TODO(4.2.1) ND accepts canonical-case parents on POST (`Ethernet1/3.2`) but returns the same name lowercased
        # on GET (`ethernet1/3.2`, `port-channel10.5`). Normalize both inputs to canonical case so idempotency
        # comparisons work without re-implementing case-insensitive equality everywhere.
        if parent_lower.startswith("ethernet"):
            canonical_parent = "Ethernet" + parent[len("ethernet") :]
        elif parent_lower.startswith("port-channel"):
            canonical_parent = "Port-channel" + parent[len("port-channel") :]
        else:
            raise ValueError(f"interface_name parent must be 'Ethernet...' or 'Port-channel...'; got parent={parent!r}")
        return f"{canonical_parent}.{sub}"

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict:
        """
        # Summary

        Return the Ansible argument spec for the `nd_interface_subinterface_managed` module.

        Each config item targets a single managed L3 subinterface identified by `interface_name`
        (e.g. `Ethernet1/3.2`). To configure multiple subinterfaces in one task, list multiple config items.
        Per-subinterface L3 settings (vlan_id, ip, vrf_interface, ...) live under `config_data.network_os.policy`
        and apply to that one subinterface only.

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
                                            vlan_id=dict(type="int"),
                                            vrf_interface=dict(type="str"),
                                            ip=dict(type="str"),
                                            prefix=dict(type="int"),
                                            ipv6=dict(type="str"),
                                            ipv6_prefix=dict(type="int"),
                                            routing_tag=dict(type="str"),
                                            ip_redirects=dict(type="bool"),
                                            pim_sparse=dict(type="bool"),
                                            pim_dr_priority=dict(type="int"),
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
