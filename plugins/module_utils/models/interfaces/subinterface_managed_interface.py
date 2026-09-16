# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Managed L3 subinterface Pydantic models for Nexus Dashboard (NX-OS `subinterface`, IOS-XE `iosXeSubinterface` /
`iosXeSubinterfaceShutNoshut`; issue #541).

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload structure for managed L3
subinterfaces (`interfaceType: "subInterface"`, `mode: "managed"`). The playbook config uses the same nesting so that `to_payload()`
and `from_response()` work via standard Pydantic serialization with no custom wrapping or flattening.

## Parents

A subinterface is created on a physical parent (NX-OS `Ethernet1/3.2`; IOS-XE `GigabitEthernet1/0/2.100`) or on a Port-channel parent
(e.g. `Port-channel10.5`). The parent type is encoded only in the `interface_name` string; the ND API does not require a separate parent
reference. The `.<sub>` portion encodes the 802.1Q dot1q sub-id.

## Model Hierarchy

- `SubinterfaceManagedInterfaceModel` (top-level, `NDBaseModel`)
    - `switch_ip` (composite identifier)
    - `interface_name` (composite identifier, e.g. `Ethernet1/3.2`)
    - `interface_type` (hardcoded: "subInterface")
    - `config_data` -> `SubinterfaceManagedConfigDataModel`
        - `mode` (hardcoded: "managed")
        - `network_os` -> `SubinterfaceManagedNetworkOSModel | XeSubinterfaceNetworkOSModel` (discriminated union on `network_os_type`;
          injected as `nx-os` when omitted so pre-#541 playbooks are unchanged)
            - `SubinterfaceManagedNetworkOSModel` (`network_os_type: "nx-os"`)
                - `policy` -> `SubinterfaceManagedPolicyModel` (`policy_type: "subinterface"`, injected when omitted): admin state,
                  `vlan_id`, L3 addressing, VRF, routing tag, MTU, ip-redirects, PIM, Netflow
            - `XeSubinterfaceNetworkOSModel` (`network_os_type: "ios-xe"`)
                - `policy` -> `XeSubinterfacePolicyModel | XeSubinterfaceShutNoshutPolicyModel` (discriminated union on `policy_type`;
                  injected as `iosXeSubinterface` when omitted)
                    - `XeSubinterfacePolicyModel` (`policy_type: "iosXeSubinterface"`): admin state, `vlan_id`, L3 addressing, VRF
                    - `XeSubinterfaceShutNoshutPolicyModel` (`policy_type: "iosXeSubinterfaceShutNoshut"`): admin state only
    - `oper_data` -> `SubinterfaceManagedOperDataModel` (read-only, returned on GET, excluded from payload)

## Field sets

`SubinterfaceManagedPolicyModel` mirrors the `policyType: "subinterface"` schema (`intSubifTemplate`). `XeSubinterfacePolicyModel` mirrors
`iosXeIntSubintfTemplate`, a strict trim of the NX-OS template (no mtu, routing tag, ip-redirects, PIM or Netflow) with its own ranges
(`vlanId` 1-4094, `ipv6Prefix` 64-127, `description` 1-200). `XeSubinterfaceShutNoshutPolicyModel` mirrors the
`ios_xe_int_subif_admin_state` template. Both IOS-XE templates are identical on ND 4.2.1 and 4.3.1. The "unmanaged" subinterface variant
(`policyType: "monitorSubinterface"`) is handled by a separate module.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    SubinterfaceManagedPolicyTypeEnum,
    XeSubinterfacePolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_common import (
    default_network_os_type,
    default_policy_type,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.policy_base import InterfacePolicyStrictBase
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription

# Alphabetic (hyphen-tolerant) parent prefix + the numeric remainder of a parent interface name (`Port-channel10` -> `Port-channel`, `10`).
_PARENT_NAME_RE = re.compile(r"^([A-Za-z][A-Za-z-]*)(\d.*)$")

# Wire-canonical parent prefixes a managed subinterface can sit on: the NX-OS `Ethernet`, the Port-channel parent, and the Catalyst
# IOS-XE physical families. A user-supplied prefix that is a case-insensitive prefix of exactly ONE canonical name is expanded to it
# (`eth1/3`, `gi1/0/2`, `te1/0/1`, `po10`); an ambiguous abbreviation (`t1/0/1`) or an unknown family passes through verbatim so a
# correctly typed name is never corrupted. Same rule as `ethernet_common.normalize_ethernet_interface_name`, with a wider family list.
#
# TODO(4.2.1) xe-subinterface-remove-leaves-switch-interface
# ND generates `no interface <parent>.<sub>` for an IOS-XE subinterface only when `interfaceActions/remove` names the switch-canonical
# spelling (the discovered record's key); a lowercase name reports "Interface deleted successfully", deletes the intent record and
# leaves the configured subinterface on the Catalyst (lab 2026-09-16, 4.2.1.10). ND stores and looks up the name case-insensitively
# otherwise. The canonical expansion here is what keeps `state: deleted` / `overridden` removing the interface from the switch, so
# the family list must stay wide enough to canonicalize every physical parent a user can abbreviate.
_CANONICAL_PARENT_PREFIXES = (
    "Ethernet",
    "Port-channel",
    "GigabitEthernet",
    "TwoGigabitEthernet",
    "FiveGigabitEthernet",
    "TenGigabitEthernet",
    "TwentyFiveGigE",
    "FortyGigabitEthernet",
    "HundredGigE",
    "AppGigabitEthernet",
)


class SubinterfaceManagedPolicyModel(InterfacePolicyStrictBase):
    """
    # Summary

    Policy fields for the NX-OS `subinterface` template (`int_subif`). Maps directly to the `configData.networkOS.policy` object in the
    ND API where `policyType == "subinterface"`.

    `policy_type` is required by the API as a discriminator on both POST and PUT; it is injected as `subinterface` when the input omits
    it, so it is always serialized.

    ## Raises

    None
    """

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND 4.2.1 `int_subif` template defaults (schema-sourced via nd-openapi `intSubifTemplate`). ND echoes these
    # for every field the user never set; the reverse pass of `get_diff` normalizes existing-side matches to absent
    # so replaced/overridden removal detection (issue #410) stays idempotent against default echoes.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        **InterfacePolicyStrictBase.reverse_diff_defaults,
        "ipRedirects": False,
        "mtu": 9216,
        "netflow": False,
        "pimDrPriority": 1,
        "pimSparse": False,
    }

    # TODO(4.3.1) ethernet-create-required-fields-431
    # ND 4.3.1 rejects a `subinterface` create body that omits `mtu` ("Policy [subinterface] - Validation failed for following fields:
    # [mtu]") where 4.2.1 defaulted it to 9216 (neither spec marks it required; first seen on the SITE1 ToR 2026-09-16). Always emit the
    # template default on the wire; 4.2.1 stores 9216 either way, so idempotency is unchanged on both releases. Payload-only: see
    # `NDBaseModel.payload_defaults`. The IOS-XE templates carry no `mtu`.
    payload_defaults: ClassVar[dict[str, Any]] = {"mtu": 9216}

    policy_type: Literal["subinterface"] = Field(
        alias="policyType", description="Subinterface policy template discriminator; injected as `subinterface` when omitted (see `default_policy_type`)"
    )

    @model_validator(mode="before")
    @classmethod
    def default_policy_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `policyType: subinterface` when the input omits the discriminator (`ethernet_common.default_policy_type`).

        ## Raises

        None
        """
        return default_policy_type(data, SubinterfaceManagedPolicyTypeEnum.SUBINTERFACE.value)

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

    @model_validator(mode="after")
    def _validate_netflow_monitor_present(self) -> SubinterfaceManagedPolicyModel:
        """
        # Summary

        Reject enabling `netflow` without supplying a `netflow_monitor`.

        The DOCUMENTATION and field description state that `netflow_monitor` is required when `netflow` is true. Enforcing it at the model layer
        fails an incomplete policy early with a clear error instead of pushing a netflow config with no monitor and deferring the outcome to ND.

        ## Raises

        ### ValueError

        - If `netflow` is true and `netflow_monitor` is missing or empty.
        """
        if self.netflow is True and not self.netflow_monitor:
            raise ValueError("netflow_monitor must be provided when netflow is true.")
        return self

    @model_validator(mode="after")
    def _validate_ip_prefix_paired(self) -> SubinterfaceManagedPolicyModel:
        """
        # Summary

        Reject supplying only one half of an address/mask pair. `ip` requires `prefix` (and `ipv6` requires `ipv6_prefix`) and vice versa, so a
        partial address is never serialized into a payload that ND would reject or apply ambiguously.

        ## Raises

        ### ValueError

        - If exactly one of `ip` / `prefix` is set.
        - If exactly one of `ipv6` / `ipv6_prefix` is set.
        """
        if (self.ip is None) != (self.prefix is None):
            raise ValueError("ip and prefix are required together; set both or neither.")
        if (self.ipv6 is None) != (self.ipv6_prefix is None):
            raise ValueError("ipv6 and ipv6_prefix are required together; set both or neither.")
        return self


class XeSubinterfacePolicyModel(InterfacePolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeSubinterface` template (`ios_xe_int_subintf`). Maps to `configData.networkOS.policy` where
    `policyType == "iosXeSubinterface"`. A strict trim of the NX-OS branch (no mtu, routing tag, ip-redirects, PIM or Netflow) with the
    template's own ranges: `vlanId` 1-4094, `ipv6Prefix` 64-127, `description` 1-200 characters.

    ## Raises

    None
    """

    policy_type: Literal["iosXeSubinterface"] = Field(
        alias="policyType", description="IOS-XE subinterface policy template discriminator; injected as `iosXeSubinterface` when omitted"
    )

    @model_validator(mode="before")
    @classmethod
    def default_policy_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `policyType: iosXeSubinterface` when the input omits the discriminator (`ethernet_common.default_policy_type`). The union
        in `XeSubinterfaceNetworkOSModel` injects the same default before it dispatches; this copy keeps a directly constructed policy
        consistent.

        ## Raises

        None
        """
        return default_policy_type(data, XeSubinterfacePolicyTypeEnum.IOS_XE_SUBINTERFACE.value)

    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=200, description="Subinterface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the subinterface")
    vlan_id: int | None = Field(default=None, alias="vlanId", ge=1, le=4094, description="802.1Q VLAN tag for the subinterface")
    vrf_interface: str | None = Field(
        default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name; use `default` for default VRF"
    )
    ip: str | None = Field(default=None, alias="ip", description="IPv4 address of the subinterface")
    prefix: int | None = Field(default=None, alias="prefix", ge=8, le=31, description="IPv4 netmask length used with `ip`")
    ipv6: str | None = Field(default=None, alias="ipv6", description="IPv6 address of the subinterface")
    ipv6_prefix: int | None = Field(default=None, alias="ipv6Prefix", ge=64, le=127, description="IPv6 netmask length used with `ipv6`")

    @model_validator(mode="after")
    def _validate_ip_prefix_paired(self) -> XeSubinterfacePolicyModel:
        """
        # Summary

        Reject supplying only one half of an address/mask pair. `ip` requires `prefix` (and `ipv6` requires `ipv6_prefix`) and vice versa, so a
        partial address is never serialized into a payload that ND would reject or apply ambiguously.

        ## Raises

        ### ValueError

        - If exactly one of `ip` / `prefix` is set.
        - If exactly one of `ipv6` / `ipv6_prefix` is set.
        """
        if (self.ip is None) != (self.prefix is None):
            raise ValueError("ip and prefix are required together; set both or neither.")
        if (self.ipv6 is None) != (self.ipv6_prefix is None):
            raise ValueError("ipv6 and ipv6_prefix are required together; set both or neither.")
        return self


class XeSubinterfaceShutNoshutPolicyModel(InterfacePolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeSubinterfaceShutNoshut` template (`ios_xe_int_subif_admin_state`). The template carries only the
    discriminator and `admin_state` (declared on the base), so any L3 field on this branch is rejected.

    ## Raises

    None
    """

    policy_type: Literal["iosXeSubinterfaceShutNoshut"] = Field(
        alias="policyType", description="IOS-XE admin-state-only subinterface policy template discriminator"
    )


class SubinterfaceManagedNetworkOSModel(NDNestedModel):
    """
    # Summary

    NX-OS branch of the network-OS container for a managed subinterface. Maps to `configData.networkOS` in the ND API. Selected from the
    outer union when `networkOSType == "nx-os"` (the injected default when the input omits it).

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field. The Literal constrains the value.
    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType", description="Network OS (platform) type discriminator")
    policy: SubinterfaceManagedPolicyModel | None = Field(default=None, alias="policy")


class XeSubinterfaceNetworkOSModel(NDNestedModel):
    """
    # Summary

    IOS-XE branch of the network-OS container for a managed subinterface. Selected from the outer union when `networkOSType == "ios-xe"`.
    The policy is a discriminated union on `policy_type` (`iosXeSubinterface` or `iosXeSubinterfaceShutNoshut`), injected as
    `iosXeSubinterface` when the input omits it.

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field. The Literal constrains the value.
    network_os_type: Literal["ios-xe"] = Field(default="ios-xe", alias="networkOSType", description="Network OS (platform) type discriminator")
    policy: XeSubinterfacePolicyModel | XeSubinterfaceShutNoshutPolicyModel | None = Field(default=None, alias="policy", discriminator="policy_type")

    @model_validator(mode="before")
    @classmethod
    def default_policy_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `policyType: iosXeSubinterface` on the `policy` input when it omits the discriminator (key absent, or `None` as the argspec
        passes an omitted suboption), so the full template is the default and `iosXeSubinterfaceShutNoshut` must be named explicitly
        (`ethernet_common.default_policy_type`).

        ## Raises

        None
        """
        if not isinstance(data, dict):
            return data
        for key in ("policy",):
            if isinstance(data.get(key), dict):
                return {**data, key: default_policy_type(data[key], XeSubinterfacePolicyTypeEnum.IOS_XE_SUBINTERFACE.value)}
        return data


class SubinterfaceManagedConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for a managed subinterface. Maps to `configData` in the ND API. `mode` is always `"managed"`
    for this module and is required by the API as a discriminator.

    ## Raises

    None
    """

    mode: Literal["managed"] = Field(default="managed", alias="mode", frozen=True)
    network_os: SubinterfaceManagedNetworkOSModel | XeSubinterfaceNetworkOSModel = Field(alias="networkOS", discriminator="network_os_type")

    @model_validator(mode="before")
    @classmethod
    def default_network_os_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `networkOSType: nx-os` on the `network_os` input when it omits the discriminator (key absent, or `None` as the argspec
        passes an omitted option), so playbooks written before the IOS-XE branch existed keep selecting the NX-OS branch
        (`ethernet_common.default_network_os_type`).

        ## Raises

        None
        """
        if not isinstance(data, dict):
            return data
        for key in ("network_os", "networkOS"):
            if isinstance(data.get(key), dict):
                return {**data, key: default_network_os_type(data[key])}
        return data


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
    port_channel_id: int | None = Field(default=None, alias="portChannelId")
    switch_name: str | None = Field(default=None, alias="switchName")
    vlan_range: str | None = Field(default=None, alias="vlanRange")


class SubinterfaceManagedInterfaceModel(NDBaseModel):
    """
    # Summary

    Managed L3 subinterface configuration for Nexus Dashboard (NX-OS `subinterface` or IOS-XE `iosXeSubinterface` /
    `iosXeSubinterfaceShutNoshut`).

    Uses a composite identifier (`switch_ip`, `interface_name`). The nested model structure mirrors the ND Manage
    Interfaces API payload, so `to_payload()` and `from_response()` work via standard Pydantic serialization.

    `interface_type` is required by the ND API on both POST and PUT. The per-interface PUT (`updateInterface`) uses
    `interfaceType` as the request-body discriminator (mapping `subInterface` -> `interfaceSubInterface`) and lists it
    in `required`, so `to_payload()` always serializes it for both verbs (verified against the ND 4.2.1 OpenAPI spec).

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

    @property
    def policy_type(self) -> str | None:
        """
        # Summary

        The `policy_type` discriminator from `config_data.network_os.policy`, or `None` when `config_data` or `policy` is unset
        (e.g. a `state: deleted` identifier-only item).

        ## Raises

        None
        """
        if self.config_data is None or self.config_data.network_os.policy is None:
            return None
        return self.config_data.network_os.policy.policy_type

    @field_validator("interface_name", mode="before")
    @classmethod
    def normalize_interface_name(cls, value):
        """
        # Summary

        Validate that `interface_name` is a dotted subinterface form (e.g. `Ethernet1/3.2`, `GigabitEthernet1/0/2.100`,
        `Port-channel10.5`). The parent kind is inferred from the prefix; no separate `parent_interface` argument is needed. The sub-id
        portion (`.<n>`) is required.

        The parent prefix is normalized to its wire-canonical form when it is a case-insensitive prefix of exactly one of
        `_CANONICAL_PARENT_PREFIXES` (`ethernet1/3`, `eth1/3` -> `Ethernet1/3`; `gi1/0/2` -> `GigabitEthernet1/0/2`; `te1/0/1` ->
        `TenGigabitEthernet1/0/1`; `po10` -> `Port-channel10`); an ambiguous abbreviation or an unknown family passes through verbatim so
        a correctly typed name is never corrupted, and ND validates the parent itself. The canonical spelling is what ND needs on the
        delete side for IOS-XE (see the `_CANONICAL_PARENT_PREFIXES` marker).

        ## Raises

        ### ValueError

        - If `value` is a string without a `.<sub>` segment.
        """
        if not isinstance(value, str) or not value:
            return value
        stripped = value.strip()
        if "." not in stripped:
            raise ValueError(f"interface_name must include a dot-separated subinterface id (e.g. 'Ethernet1/3.2'); got {value!r}")
        parent, sub = stripped.rsplit(".", 1)
        # TODO(4.2.1) ND accepts canonical-case parents on POST (`Ethernet1/3.2`) but returns the same name lowercased
        # on GET (`ethernet1/3.2`, `port-channel10.5`). Normalize both inputs to canonical case so idempotency
        # comparisons work without re-implementing case-insensitive equality everywhere.
        return f"{cls._normalize_parent(parent)}.{sub}"

    @staticmethod
    def _normalize_parent(parent: str) -> str:
        """
        # Summary

        Expand the alphabetic prefix of `parent` to the one canonical name in `_CANONICAL_PARENT_PREFIXES` it is a case-insensitive
        prefix of; return `parent` unchanged when the prefix is ambiguous, unknown, or the name has no numeric remainder.

        ## Raises

        None
        """
        match = _PARENT_NAME_RE.match(parent)
        if not match:
            return parent
        prefix, rest = match.groups()
        expansions = [canonical for canonical in _CANONICAL_PARENT_PREFIXES if canonical.lower().startswith(prefix.lower())]
        if len(expansions) == 1:
            return expansions[0] + rest
        return parent

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict:
        """
        # Summary

        Return the Ansible argument spec for the `nd_interface_subinterface_managed` module.

        Each config item targets a single managed L3 subinterface identified by `interface_name`
        (e.g. `Ethernet1/3.2`). To configure multiple subinterfaces in one task, list multiple config items.
        Per-subinterface L3 settings (vlan_id, ip, vrf_interface, ...) live under `config_data.network_os.policy`
        and apply to that one subinterface only. The policy options are the union of both branches; the branch models reject fields
        that do not belong to the selected `policy_type`.

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
                                    network_os_type=dict(type="str", default="nx-os", choices=["nx-os", "ios-xe"]),
                                    policy=dict(
                                        type="dict",
                                        options=dict(
                                            policy_type=dict(
                                                type="str",
                                                choices=[e.value for e in SubinterfaceManagedPolicyTypeEnum] + [e.value for e in XeSubinterfacePolicyTypeEnum],
                                            ),
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
