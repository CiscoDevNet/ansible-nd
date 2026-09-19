# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
SVI (switched virtual interface) Pydantic models for Nexus Dashboard (NX-OS `svi`, IOS-XE `iosXeSvi` / `iosXeSviShutNoShut`; issue #540).

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload structure for managed SVI interfaces
(`interfaceType: "svi"`, `mode: "managed"`). The playbook config uses the same nesting so that `to_payload()` and `from_response()` work
via standard Pydantic serialization with no custom wrapping or flattening.

## Model Hierarchy

- `SviInterfaceModel` (top-level, `NDBaseModel`)
    - `switch_ip` (composite identifier)
    - `interface_name` (composite identifier, e.g. `vlan333`)
    - `interface_type` (hardcoded: "svi")
    - `config_data` -> `SviConfigDataModel`
        - `mode` (hardcoded: "managed")
        - `network_os` -> `SviNetworkOSModel | XeSviNetworkOSModel` (discriminated union on `network_os_type`; injected as `nx-os` when
          omitted so pre-#540 playbooks are unchanged)
            - `SviNetworkOSModel` (`network_os_type: "nx-os"`)
                - `policy` -> `SviPolicyModel` (`policy_type: "svi"`, injected when omitted): admin state, L3 addressing, VRF, routing
                  tag, PIM, the HSRP block, the flat three-server DHCP relay block, underlay advertisement, Netflow
            - `XeSviNetworkOSModel` (`network_os_type: "ios-xe"`)
                - `policy` -> `XeSviPolicyModel | XeSviShutNoShutPolicyModel` (discriminated union on `policy_type`; injected as
                  `iosXeSvi` when omitted)
                    - `XeSviPolicyModel` (`policy_type: "iosXeSvi"`): admin state, L3 addressing, VRF, VLAN name, `dhcp_servers` list
                    - `XeSviShutNoShutPolicyModel` (`policy_type: "iosXeSviShutNoShut"`): admin state only
    - `oper_data` -> `SviOperDataModel` (read-only, returned on GET, excluded from payload)

## Field sets

`SviPolicyModel` mirrors the `policyType: "svi"` schema (`intVlanTemplate`). `XeSviPolicyModel` mirrors `iosXeIntVlanTemplate`, a strict
trim of the NX-OS template (no mtu, routing tag, PIM, HSRP, Netflow or underlay advertisement) plus two Catalyst-only fields (`vlanName`
and the `dhcpServers` list, which replaces the NX-OS `dhcpServerAddress1-3` / `vrfDhcp1-3` block). `XeSviShutNoShutPolicyModel` mirrors
`iosXeIntVlanAdminStateTemplate`. Both IOS-XE templates are identical on ND 4.2.1 and 4.3.1. The shared option name `prefixv6` is kept on
the IOS-XE branch (wire key `ipv6Prefix`) so gathered output replays across platforms.

OSPF / ISIS / BFD / replication-mode fields belong to other NX-OS policy types (e.g. `policyType: "vpcBackupSvi"` / int_fabric_vlan_11_1)
and would be modelled as separate variants.
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import SviPolicyTypeEnum, XeSviPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_common import (
    default_network_os_type,
    default_policy_type,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.policy_base import InterfacePolicyStrictBase
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import (
    AsciiDescription,
    IPv4HostStrict,
    IPv6HostStrict,
    validate_ipv4_host_strict,
)


def _coerce_numeric_string_to_int(value):
    """
    # Summary

    Return `int(value)` for a numeric string, `value` unchanged otherwise (bools and non-numeric strings are left for the field's own
    type validation to accept or reject).

    ## Raises

    None
    """
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return value


class SviPolicyModel(InterfacePolicyStrictBase):
    """
    # Summary

    Policy fields for the NX-OS `svi` template (`int_vlan`). Maps directly to the `configData.networkOS.policy` object in the ND API
    where `policyType == "svi"`.

    `policy_type` is required by the API as a discriminator on both POST and PUT; it is injected as `svi` when the input omits it, so it
    is always serialized.

    ## Raises

    None
    """

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND 4.2.1 `int_vlan` template defaults (schema-sourced via nd-openapi `intVlanTemplate`). ND echoes these
    # for every field the user never set; the reverse pass of `get_diff` normalizes existing-side matches to absent
    # so replaced/overridden removal detection (issue #410) stays idempotent against default echoes. ND 4.3.1 no longer
    # echoes `hsrpGroup` and `pimDrPriority` for unset fields; the entries are harmless there.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        **InterfacePolicyStrictBase.reverse_diff_defaults,
        "advertiseSubnetInUnderlay": False,
        "hsrpGroup": 1,
        "hsrpVersion": 1,
        "ipRedirects": True,
        "netflow": False,
        "pimDrPriority": 1,
        "pimSparse": False,
        "preempt": False,
    }

    policy_type: Literal["svi"] = Field(
        alias="policyType", description="SVI policy template discriminator; injected as `svi` when omitted (see `default_policy_type`)"
    )

    @model_validator(mode="before")
    @classmethod
    def default_policy_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `policyType: svi` when the input omits the discriminator (`ethernet_common.default_policy_type`).

        ## Raises

        None
        """
        return default_policy_type(data, SviPolicyTypeEnum.SVI.value)

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

    # TODO(4.2.1) GET returns `routingTag` as an integer though the OpenAPI spec declares it as string and POST/PUT accept string.
    # Remove this validator once ND 4.2 reaches end-of-support. Cisco has confirmed this is fixed in ND 4.3, so once 4.2 is
    # deprecated this coercion is dead weight. Tracked in `project_svi_hsrp_phase2.md`.
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

    # TODO(4.3.1) svi-hsrpversion-string-echo-431
    # ND 4.3.1 echoes the template default `hsrpVersion` as the STRING "1" on every GET (4.2.1 echoes the integer 1), and its PUT
    # gateway rejects the string with HTTP 400 schema validation. Coerce on read so the field validates and always round-trips as
    # the int both releases accept. Lab-verified 2026-09-16 on 4.2.1.10 and 4.3.1.175 (issue #380).
    @field_validator("hsrp_version", mode="before")
    @classmethod
    def coerce_hsrp_version_to_int(cls, value):
        """
        # Summary

        Accept `hsrp_version` as either an integer or a numeric string (the ND 4.3.1 GET echo) and normalize it to `int` so the
        `Literal[1, 2]` field validates and payloads carry the integer form the API schema requires on both releases.

        ## Raises

        None
        """
        return _coerce_numeric_string_to_int(value)

    @model_validator(mode="after")
    def _validate_netflow_monitor_present(self) -> SviPolicyModel:
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
    def _validate_ip_prefix_paired(self) -> SviPolicyModel:
        """
        # Summary

        Reject supplying only one half of an address/mask pair. `ip` requires `prefix` (and `ipv6` requires `prefixv6`) and vice versa, so a
        partial address is never serialized into a payload that ND would reject or apply ambiguously.

        ## Raises

        ### ValueError

        - If exactly one of `ip` / `prefix` is set.
        - If exactly one of `ipv6` / `prefixv6` is set.
        """
        if (self.ip is None) != (self.prefix is None):
            raise ValueError("ip and prefix are required together; set both or neither.")
        if (self.ipv6 is None) != (self.prefixv6 is None):
            raise ValueError("ipv6 and prefixv6 are required together; set both or neither.")
        return self


class XeSviDhcpServerModel(NDNestedModel):
    """
    # Summary

    One DHCP relay server entry of the IOS-XE `iosXeSvi` template's `dhcpServers` list. Maps to `configData.networkOS.policy.dhcpServers[]`.

    ## Raises

    None
    """

    server_ip_address: str = Field(alias="serverIpAddress", description="DHCP relay server IPv4 address (bare host form)")
    # TODO(4.2.1) xe-svi-dhcpservers-servervrf-required
    # The spec marks nothing in `dhcpServers[]` required and allows an empty `serverVrf`, but ND rejects an item without a non-empty
    # VRF (omitted: HTTP 500 / 207 failed item; empty: HTTP 400) on both 4.2.1.10 and 4.3.1.175. Required with min_length 1 here so the
    # omission fails before any controller call.
    server_vrf: str = Field(
        alias="serverVrf",
        min_length=1,
        max_length=32,
        description="VRF used to reach the server; `default` (or `global`) for the global table, `Mgmt-Vrf` for management",
    )

    # TODO(4.2.1) xe-svi-dhcpservers-echo-keys
    # ND 4.2.1 accepts `serverIpAddress` / `serverVrf` on POST/PUT but echoes the items on GET as `srvrAddr` / `srvrVrf`, and a PUT that
    # carries the echoed spelling returns HTTP 500. Fixed on 4.3.1 (echoes the spec keys). Accept both spellings on read and serialize
    # only the spec keys.
    @model_validator(mode="before")
    @classmethod
    def accept_echo_keys(cls, data: Any) -> Any:
        """
        # Summary

        Rename the ND 4.2.1 echo keys `srvrAddr` / `srvrVrf` to the spec keys `serverIpAddress` / `serverVrf` before validation, when the
        spec key is not already present.

        ## Raises

        None
        """
        if not isinstance(data, dict):
            return data
        renamed = dict(data)
        for echo_key, spec_key, field_name in (("srvrAddr", "serverIpAddress", "server_ip_address"), ("srvrVrf", "serverVrf", "server_vrf")):
            if echo_key in renamed:
                value = renamed.pop(echo_key)
                if spec_key not in renamed and field_name not in renamed:
                    renamed[spec_key] = value
        return renamed

    @field_validator("server_ip_address", mode="before")
    @classmethod
    def validate_server_ip_address(cls, value: Any) -> Any:
        """
        # Summary

        Require `server_ip_address` to be a bare IPv4 address, the format the ND template declares for `serverIpAddress`, so a malformed
        value fails before any controller call.

        ## Raises

        ### ValueError

        - If `value` is not a valid bare IPv4 address (including any CIDR form).
        """
        return validate_ipv4_host_strict(value)


class XeSviPolicyModel(InterfacePolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeSvi` template (`ios_xe_int_vlan`). Maps to `configData.networkOS.policy` where
    `policyType == "iosXeSvi"`. A strict trim of the NX-OS branch (no mtu, routing tag, PIM, HSRP, Netflow or underlay advertisement) with
    two Catalyst-only fields: `vlan_name` and the `dhcp_servers` list, which replaces the flat three-server NX-OS DHCP relay block. The
    IPv6 mask keeps the shared option name `prefixv6` and maps to the wire key `ipv6Prefix`.

    ## Raises

    None
    """

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND `ios_xe_int_vlan` template defaults as ECHOED for fields the user never set (lab 2026-09-16, 4.2.1.10 and 4.3.1.175):
    # `adminState: true` and `ipRedirects: true`.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        **InterfacePolicyStrictBase.reverse_diff_defaults,
        "ipRedirects": True,
    }

    policy_type: Literal["iosXeSvi"] = Field(alias="policyType", description="IOS-XE SVI policy template discriminator; injected as `iosXeSvi` when omitted")

    @model_validator(mode="before")
    @classmethod
    def default_policy_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `policyType: iosXeSvi` when the input omits the discriminator (`ethernet_common.default_policy_type`). The union in
        `XeSviNetworkOSModel` injects the same default before it dispatches; this copy keeps a directly constructed policy consistent.

        ## Raises

        None
        """
        return default_policy_type(data, XeSviPolicyTypeEnum.IOS_XE_SVI.value)

    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=200, description="Interface description")
    dhcp_servers: list[XeSviDhcpServerModel] | None = Field(default=None, alias="dhcpServers", description="DHCP relay servers (address + VRF per entry)")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    ip: IPv4HostStrict = Field(default=None, alias="ip", description="IPv4 address of the SVI (bare host form; the mask length is set via `prefix`)")
    prefix: int | None = Field(default=None, alias="prefix", ge=1, le=31, description="IPv4 netmask length used with `ip`")
    ipv6: IPv6HostStrict = Field(default=None, alias="ipv6", description="IPv6 address of the SVI (bare host form; the prefix length is set via `prefixv6`)")
    prefixv6: int | None = Field(default=None, alias="ipv6Prefix", ge=1, le=127, description="IPv6 prefix length used with `ipv6` (wire key `ipv6Prefix`)")
    ip_redirects: bool | None = Field(default=None, alias="ipRedirects", description="Disable both IPv4/IPv6 redirects on the interface")
    vlan_name: str | None = Field(default=None, alias="vlanName", max_length=128, description="Name of the VLAN")
    vrf_interface: str | None = Field(
        default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name; use `default` for default VRF"
    )

    @model_validator(mode="after")
    def _validate_ip_prefix_paired(self) -> XeSviPolicyModel:
        """
        # Summary

        Reject supplying only one half of an address/mask pair. `ip` requires `prefix` (and `ipv6` requires `prefixv6`) and vice versa, so a
        partial address is never serialized into a payload that ND would reject or apply ambiguously.

        ## Raises

        ### ValueError

        - If exactly one of `ip` / `prefix` is set.
        - If exactly one of `ipv6` / `prefixv6` is set.
        """
        if (self.ip is None) != (self.prefix is None):
            raise ValueError("ip and prefix are required together; set both or neither.")
        if (self.ipv6 is None) != (self.prefixv6 is None):
            raise ValueError("ipv6 and prefixv6 are required together; set both or neither.")
        return self


class XeSviShutNoShutPolicyModel(InterfacePolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeSviShutNoShut` template (`ios_xe_int_vlan_admin_state`). The template carries only the
    discriminator and `admin_state` (declared on the base), so any L3 field on this branch is rejected.

    ## Raises

    None
    """

    policy_type: Literal["iosXeSviShutNoShut"] = Field(alias="policyType", description="IOS-XE admin-state-only SVI policy template discriminator")


class SviNetworkOSModel(NDNestedModel):
    """
    # Summary

    NX-OS branch of the network-OS container for an SVI. Maps to `configData.networkOS` in the ND API. Selected from the outer union when
    `networkOSType == "nx-os"` (the injected default when the input omits it).

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field. The Literal constrains the value.
    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType", description="Network OS (platform) type discriminator")
    policy: SviPolicyModel | None = Field(default=None, alias="policy")


class XeSviNetworkOSModel(NDNestedModel):
    """
    # Summary

    IOS-XE branch of the network-OS container for an SVI. Selected from the outer union when `networkOSType == "ios-xe"`. The policy is
    a discriminated union on `policy_type` (`iosXeSvi` or `iosXeSviShutNoShut`), injected as `iosXeSvi` when the input omits it.

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field. The Literal constrains the value.
    network_os_type: Literal["ios-xe"] = Field(default="ios-xe", alias="networkOSType", description="Network OS (platform) type discriminator")
    policy: XeSviPolicyModel | XeSviShutNoShutPolicyModel | None = Field(default=None, alias="policy", discriminator="policy_type")

    @model_validator(mode="before")
    @classmethod
    def default_policy_type(cls, data: Any) -> Any:
        """
        # Summary

        Supply `policyType: iosXeSvi` on the `policy` input when it omits the discriminator (key absent, or `None` as the argspec passes
        an omitted suboption), so the full template is the default and `iosXeSviShutNoShut` must be named explicitly
        (`ethernet_common.default_policy_type`).

        ## Raises

        None
        """
        if not isinstance(data, dict):
            return data
        for key in ("policy",):
            if isinstance(data.get(key), dict):
                return {**data, key: default_policy_type(data[key], XeSviPolicyTypeEnum.IOS_XE_SVI.value)}
        return data


class SviConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for an SVI interface. Maps to `configData` in the ND API. `mode` is always `"managed"` for
    SVIs and is required by the API as a discriminator.

    ## Raises

    None
    """

    mode: Literal["managed"] = Field(default="managed", alias="mode", frozen=True)
    network_os: SviNetworkOSModel | XeSviNetworkOSModel = Field(default_factory=SviNetworkOSModel, alias="networkOS", discriminator="network_os_type")

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

    SVI interface configuration for Nexus Dashboard (NX-OS `svi` or IOS-XE `iosXeSvi` / `iosXeSviShutNoShut`).

    Uses a composite identifier (`switch_ip`, `interface_name`). The nested model structure mirrors the ND Manage
    Interfaces API payload, so `to_payload()` and `from_response()` work via standard Pydantic serialization.

    `interface_type` is required by the ND API on both POST and PUT. The per-interface PUT (`updateInterface`) uses
    `interfaceType` as the request-body discriminator (mapping `svi` -> `interfaceSvi`) and lists it in `required`, so
    `to_payload()` always serializes it for both verbs (verified against the ND 4.2.1 OpenAPI spec).

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

        Normalize SVI interface names to the ND API convention (lowercase `vlan` prefix, e.g. `Vlan333` -> `vlan333`,
        `VLAN333` -> `vlan333`). Bare integers are accepted and prefixed with `vlan` (e.g. `333` -> `vlan333`). ND stores an IOS-XE
        SVI under whatever spelling it is given, looks it up case-insensitively, and removes it from the Catalyst with the lowercase
        name (lab-verified 2026-09-16 on 4.2.1.10 and 4.3.1.175), so both branches share the lowercase identifier.

        When a numeric VLAN ID can be extracted from the input, it is range-checked against the controller-supported
        SVI VLAN range (1-4094) so an out-of-range ID fails early with a clear error instead of being rejected by ND.

        ## Raises

        ### ValueError

        - If the extracted VLAN ID is outside the range 1-4094.
        """
        normalized = value
        vlan_id: int | None = None
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            vlan_id = value
            normalized = f"vlan{value}"
        elif isinstance(value, str) and value:
            stripped = value.strip()
            if stripped.isdigit():
                vlan_id = int(stripped)
                normalized = f"vlan{stripped}"
            elif stripped.lower().startswith("vlan"):
                remainder = stripped[4:]
                normalized = "vlan" + remainder
                if remainder.isdigit():
                    vlan_id = int(remainder)
        if vlan_id is not None and not 1 <= vlan_id <= 4094:
            raise ValueError(f"SVI VLAN ID must be in the range 1-4094, got {vlan_id}.")
        return normalized

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict:
        """
        # Summary

        Return the Ansible argument spec for the `nd_interface_svi` module.

        Each config item targets a single SVI identified by `interface_name` (e.g. `vlan333`). To configure multiple SVIs
        in one task, list multiple config items. Per-SVI L3 settings (ip, hsrp_*, vrf_interface, ...) live under
        `config_data.network_os.policy` and apply to that one interface only. The policy options are the union of both branches;
        the branch models reject fields that do not belong to the selected `policy_type`.

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
                                                choices=[SviPolicyTypeEnum.SVI.value] + [e.value for e in XeSviPolicyTypeEnum],
                                            ),
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
                                            vlan_name=dict(type="str"),
                                            dhcp_servers=dict(
                                                type="list",
                                                elements="dict",
                                                options=dict(
                                                    server_ip_address=dict(type="str", required=True),
                                                    server_vrf=dict(type="str", required=True),
                                                ),
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
