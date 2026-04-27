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
    - `interface_type` (default: "svi")
    - `config_data` -> `SviConfigDataModel`
        - `mode` (default: "managed")
        - `network_os` -> `SviNetworkOSModel`
            - `network_os_type` (default: "nx-os")
            - `policy` -> `SviPolicyModel`
                - `policy_type` (default: "svi"), `admin_state`, `ip`, `prefix`, etc.
    - `oper_data` -> `SviOperDataModel` (read-only, returned on GET, excluded from payload)

## Phase 1 field set

The fields in `SviPolicyModel` cover the SVI options that the ND GUI sends on create. OSPF / ISIS / BFD /
routing-protocol / replication-mode fields are deferred to phase 2 once their create/update flows have been
captured from the GUI.
"""

import copy
from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    FieldSerializationInfo,
    field_serializer,
    field_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import SviPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel


class SviPolicyModel(NDNestedModel):
    """
    # Summary

    Policy fields for an SVI interface. Maps directly to the `configData.networkOS.policy` object in the ND API.

    `policy_type` is required by the API as a discriminator on both POST and PUT, so it carries a default of
    `SviPolicyTypeEnum.SVI` and is always serialized.

    ## Raises

    None
    """

    policy_type: SviPolicyTypeEnum = Field(default=SviPolicyTypeEnum.SVI, alias="policyType", description="Interface policy type")
    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")
    description: str | None = Field(default=None, alias="description", max_length=254, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    mtu: int | None = Field(default=None, alias="mtu", ge=576, le=9216, description="Interface MTU")
    ip: str | None = Field(default=None, alias="ip", description="IPv4 address of the SVI")
    prefix: int | None = Field(default=None, alias="prefix", ge=1, le=31, description="IPv4 netmask length used with `ip`")
    ipv6: str | None = Field(default=None, alias="ipv6", description="IPv6 address of the SVI")
    v6prefix: int | None = Field(default=None, alias="v6prefix", ge=1, le=127, description="IPv6 netmask length used with `ipv6`")
    ip_redirects: bool | None = Field(default=None, alias="ipRedirects", description="Disable both IPv4/IPv6 redirects on the interface")
    pim_sparse: bool | None = Field(default=None, alias="pimSparse", description="Enable PIM sparse-mode on the interface")
    pim_dr_priority: int | None = Field(default=None, alias="pimDrPriority", ge=1, le=4294967295, description="Priority for PIM DR election on the interface")
    hsrp_group: int | None = Field(default=None, alias="hsrpGroup", description="HSRP group number")
    hsrp_version: str | None = Field(default=None, alias="hsrpVersion", description="HSRP version")
    preempt: bool | None = Field(default=None, alias="preempt", description="Enable HSRP preemption")
    advertise_subnet_in_underlay: bool | None = Field(
        default=None, alias="advertiseSubnetInUnderlay", description="Advertise the SVI subnet into the underlay routing protocol"
    )
    netflow: bool | None = Field(default=None, alias="netflow", description="Enable Netflow on the interface")

    # --- Validators ---

    @field_validator("description")
    @classmethod
    def description_must_be_ascii(cls, value):
        """
        # Summary

        Reject non-ASCII characters in `description`. Some NX-OS / ND backend code paths pipe interface descriptions
        through CLI generators that do not handle UTF-8 cleanly and return a generic 500 ("unexpected error during
        policy execution") instead of a meaningful validation error. Catching this client-side gives the user a clear
        message instead of a confusing server fault. Remove or relax this check once Cisco fixes the backend.

        ## Raises

        ### ValueError

        - If `value` contains any non-ASCII character.
        """
        if value is None:
            return value
        try:
            value.encode("ascii")
        except UnicodeEncodeError as e:
            raise ValueError(
                f"description must contain only ASCII characters; got non-ASCII at position {e.start}: {value[e.start]!r}. "
                "The ND backend currently returns a generic 500 for non-ASCII descriptions."
            ) from None
        return value

    @field_validator("policy_type", mode="before")
    @classmethod
    def normalize_policy_type(cls, value):
        """
        # Summary

        Accept `policy_type` in either Ansible (`svi`) or API (`svi`) format. They are identical for SVI so this is a
        no-op today, but the validator is kept for symmetry with the ethernet policy models in case the API ever
        diverges from the Ansible-side name.

        ## Raises

        None
        """
        if value is None:
            return value
        ansible_to_api = {e.name.lower(): e.value for e in SviPolicyTypeEnum}
        return ansible_to_api.get(value, value)

    # --- Serializers ---

    @field_serializer("policy_type")
    def serialize_policy_type(self, value: str | None, info: FieldSerializationInfo) -> str | None:
        """
        # Summary

        Serialize `policy_type` to the API's value in payload mode, or the Ansible-friendly name in config mode. With
        `use_enum_values=True`, the stored value is the enum's `.value` string (e.g. `"svi"`).

        ## Raises

        None
        """
        if value is None:
            return None
        mode = (info.context or {}).get("mode", "payload")
        if mode == "config":
            reverse = {e.value: e.name.lower() for e in SviPolicyTypeEnum}
            return reverse.get(value, value)
        return value


class SviNetworkOSModel(NDNestedModel):
    """
    # Summary

    Network OS container for an SVI interface. Maps to `configData.networkOS` in the ND API.

    ## Raises

    None
    """

    network_os_type: str = Field(default="nx-os", alias="networkOSType")
    policy: SviPolicyModel | None = Field(default=None, alias="policy")


class SviConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for an SVI interface. Maps to `configData` in the ND API. `mode` is always `"managed"` for
    SVIs and is required by the API as a discriminator.

    ## Raises

    None
    """

    mode: str = Field(default="managed", alias="mode")
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
    interface_type: str = Field(default="svi", alias="interfaceType")
    config_data: SviConfigDataModel | None = Field(default=None, alias="configData")
    oper_data: SviOperDataModel | None = Field(default=None, alias="operData")

    @classmethod
    def from_response(cls, response: dict, **kwargs) -> "SviInterfaceModel":
        """
        # Summary

        Build an `SviInterfaceModel` from an API GET response, stripping `hsrpVersion` before validation. ND's GET
        returns `hsrpVersion: 1` (integer) as a server-side default even when HSRP is not configured, and re-emitting
        that value (whether as integer `1` or string `"1"`) on a subsequent PUT causes the API to return a generic 500
        ("unexpected error during policy execution"). The empty string `""` is the canonical "no HSRP version" form.

        `hsrpGroup` is left intact — Bruno testing confirmed the API round-trips `hsrpGroup: 1` cleanly when other
        HSRP fields are at their unconfigured defaults.

        ## Raises

        None
        """
        response = copy.deepcopy(response)
        policy = response.get("configData", {}).get("networkOS", {}).get("policy")
        if isinstance(policy, dict):
            policy.pop("hsrpVersion", None)
        return super().from_response(response, **kwargs)

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

        The module accepts `vlan_ids` (a list of integer VLAN IDs) which the module entry point expands into one flat
        config item per ID (with `interface_name` set to `vlan<id>`). This mirrors the `interface_names` expansion in
        the ethernet modules.

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
                    vlan_ids=dict(type="list", elements="int", required=True),
                    interface_type=dict(type="str", default="svi"),
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
                                            policy_type=dict(
                                                type="str",
                                                choices=[e.name.lower() for e in SviPolicyTypeEnum],
                                                default="svi",
                                            ),
                                            admin_state=dict(type="bool"),
                                            description=dict(type="str"),
                                            extra_config=dict(type="str"),
                                            mtu=dict(type="int"),
                                            ip=dict(type="str"),
                                            prefix=dict(type="int"),
                                            ipv6=dict(type="str"),
                                            v6prefix=dict(type="int"),
                                            ip_redirects=dict(type="bool"),
                                            pim_sparse=dict(type="bool"),
                                            pim_dr_priority=dict(type="int"),
                                            hsrp_group=dict(type="int"),
                                            hsrp_version=dict(type="str"),
                                            preempt=dict(type="bool"),
                                            advertise_subnet_in_underlay=dict(type="bool"),
                                            netflow=dict(type="bool"),
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
