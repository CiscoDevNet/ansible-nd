# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Ethernet routed-mode interface Pydantic models for Nexus Dashboard (issue #447).

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload
structure. The playbook config uses the same nesting so that `to_payload()` and `from_response()`
work via standard Pydantic serialization with no custom wrapping or flattening.

L3 routed IS supported on VXLAN fabrics: the GUI create wizard's "0 capable switches" is client-side filtering only —
both the per-interface PUT and the bulk POST accept `routedHost` on a VXLAN leaf (lab-verified 2026-07-27, ND 4.2.1).

## Model Hierarchy

- `EthernetRoutedInterfaceModel` (top-level, `NDBaseModel`)
    - `switch_ip` (composite identifier)
    - `interface_name` (composite identifier)
    - `interface_type` (hardcoded: "ethernet")
    - `config_data` -> `EthernetRoutedConfigDataModel`
        - `mode` (hardcoded: "routed")
        - `network_os` -> `NexusEthernetRoutedNetworkOSModel | XeEthernetRoutedNetworkOSModel` (outer discriminated union on `network_os_type`)
            - `NexusEthernetRoutedNetworkOSModel` (`network_os_type: "nx-os"`)
                - `policy` -> `NexusEthernetRoutedPolicyModel` (`policy_type: "routedHost"`; becomes a `policy_type` discriminated union
                  when the feature-gated follow-up branches — `endPointLocator`, `ipfmL3Port`, `dataBrokerL3Host` — are modeled)
            - `XeEthernetRoutedNetworkOSModel` (`network_os_type: "ios-xe"`)
                - `policy` -> `XeEthernetRoutedPolicyModel` (`policy_type: "iosXeRoutedHost"`)
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    FecEnum,
    SpeedEnum,
    XeEthernetSpeedEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.policy_base import InterfacePolicyStrictBase
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription, IPv4Host

# Leading alphabetic prefix + the remainder (digits, /, ., -) of an interface name.
# TODO: issue #353 consolidates per-model interface-name normalization into shared helpers; this module's
# normalizer is the first to canonicalize across BOTH network OS families and should seed that helper.
_INTERFACE_NAME_PREFIX_RE = re.compile(r"^([A-Za-z]+)(.*)$")

# Wire-canonical interface-name prefixes this module manages (lab-verified 2026-07-27: ND echoes
# `Ethernet1/7` on NX-OS and `GigabitEthernet3` on IOS-XE). A user-supplied prefix that is a
# case-insensitive prefix of exactly ONE canonical name is expanded to it (e.g. `e1/7`, `eth1/7`,
# `gi3`); anything else passes through verbatim so correctly-typed names of other XE interface
# families (e.g. `TenGigabitEthernet1/1`) are never corrupted.
_CANONICAL_INTERFACE_PREFIXES = ("Ethernet", "GigabitEthernet")


def normalize_ethernet_interface_name(value):
    """
    # Summary

    Normalize the leading alphabetic prefix of an interface name to its wire-canonical form (see
    `EthernetRoutedInterfaceModel.normalize_interface_name` for examples). Shared between the model's field validator
    and the orchestrator's config-name matching so both sides canonicalize identically.

    ## Raises

    None
    """
    if not isinstance(value, str) or not value:
        return value
    match = _INTERFACE_NAME_PREFIX_RE.match(value)
    if not match:
        return value
    prefix, rest = match.groups()
    expansions = [canonical for canonical in _CANONICAL_INTERFACE_PREFIXES if canonical.lower().startswith(prefix.lower())]
    if len(expansions) == 1:
        return expansions[0] + rest
    return value


class NexusEthernetRoutedPolicyModel(InterfacePolicyStrictBase):
    """
    # Summary

    Policy fields for the NX-OS `routedHost` template (`int_routed_host`). Maps to `configData.networkOS.policy` where
    `policyType == "routedHost"`.

    ND 4.2.1 GET responses inject an undeclared `ptp` key into this policy (absent from `intRoutedHostTemplate`; lab-verified
    2026-07-27); the read-tolerant base strips it so it can never round-trip into a payload or count as a reverse-diff removal.

    ## Raises

    None
    """

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND 4.2.1 `int_routed_host` template defaults (schema-sourced via nd-openapi `intRoutedHostTemplate`), in the model's
    # dumped form. `routingTag` (coerced to str on read) declares no default, so it has no entry. The ND-injected `ptp`
    # echo is undeclared here and dropped on read, so it never reaches the reverse pass. The orchestrator derives its
    # unconfigured-default query filter from this table - it must stay the single source of truth for these values.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        **InterfacePolicyStrictBase.reverse_diff_defaults,
        "fec": "auto",
        "ipRedirects": False,
        "mtu": 9216,
        "netflow": False,
        "pfc": False,
        "pimDrPriority": 1,
        "pimSparse": False,
        "qos": False,
        "speed": "auto",
    }

    policy_type: Literal["routedHost"] = Field(alias="policyType", description="Routed-host policy template discriminator")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=254, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    fec: FecEnum | None = Field(default=None, alias="fec", description="Forward error correction mode")
    ip: IPv4Host = Field(default=None, alias="ip", description="Interface IPv4 address (bare host form, e.g. 10.1.1.1; CIDR input is accepted and normalized)")
    ip_redirects: bool | None = Field(default=None, alias="ipRedirects", description="Disable IPv4 and IPv6 redirects on the interface")
    mtu: int | None = Field(default=None, alias="mtu", ge=576, le=9216, description="Interface MTU (576-9216)")
    netflow: bool | None = Field(default=None, alias="netflow", description="Enable netflow (requires netflow enabled on the fabric)")
    netflow_monitor: str | None = Field(default=None, alias="netflowMonitor", description="Netflow monitor name")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler", description="Netflow sampler name (N7K only)")
    pfc: bool | None = Field(default=None, alias="pfc", description="Enable priority flow control")
    pim_dr_priority: int | None = Field(default=None, alias="pimDrPriority", ge=1, le=4294967295, description="PIM DR election priority")
    pim_sparse: bool | None = Field(default=None, alias="pimSparse", description="Enable PIM sparse mode")
    prefix: int | None = Field(default=None, alias="prefix", ge=1, le=31, description="Netmask length for the IP address (1-31)")
    qos: bool | None = Field(default=None, alias="qos", description="Enable a QoS policy on the interface")
    qos_policy: str | None = Field(default=None, alias="qosPolicy", description="Custom QoS policy name (must be defined previously)")
    queuing_policy: str | None = Field(default=None, alias="queuingPolicy", description="Queuing policy name (must be defined previously)")
    routing_tag: str | None = Field(default=None, alias="routingTag", description="Routing tag associated with the interface IP")
    speed: SpeedEnum | None = Field(default=None, alias="speed", description="Interface speed")
    vrf: str | None = Field(default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name")

    # TODO(4.2.1) interface-get-field-normalization
    # ND 4.2.1 GET echoes routingTag as an integer even though the template defines it as a string (string in,
    # int out). Same drift as loopback routeMapTag - keep the coerce validators in sync.
    @field_validator("routing_tag", mode="before")
    @classmethod
    def coerce_routing_tag(cls, value):
        """
        # Summary

        Coerce `routing_tag` to a string. The ND API returns this field as an integer, but the template defines it as a string.

        ## Raises

        None
        """
        if value is None:
            return value
        return str(value)


class XeEthernetRoutedPolicyModel(InterfacePolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeRoutedHost` template (`ios_xe_int_routed_host`). Maps to `configData.networkOS.policy`
    where `policyType == "iosXeRoutedHost"`. Diverges from the NX-OS branch on `description` max length (200), `mtu` floor
    (1500), and the `speed` enum (`noNegotiate`, no 200/400/800Gb).

    ## Raises

    None
    """

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND 4.2.1 `ios_xe_int_routed_host` template defaults (schema-sourced via nd-openapi `iosXeIntRoutedHostTemplate`), in
    # the model's dumped form. The orchestrator derives its unconfigured-default query filter from this table.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        **InterfacePolicyStrictBase.reverse_diff_defaults,
        "mtu": 1500,
        "speed": "auto",
    }

    policy_type: Literal["iosXeRoutedHost"] = Field(alias="policyType", description="IOS-XE routed-host policy template discriminator")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=200, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    ip: IPv4Host = Field(default=None, alias="ip", description="Interface IPv4 address (bare host form, e.g. 10.1.1.1; CIDR input is accepted and normalized)")
    mtu: int | None = Field(default=None, alias="mtu", ge=1500, le=9216, description="Interface MTU (1500-9216)")
    prefix: int | None = Field(default=None, alias="prefix", ge=1, le=31, description="Netmask length for the IP address (1-31)")
    speed: XeEthernetSpeedEnum | None = Field(default=None, alias="speed", description="Interface speed")
    vrf: str | None = Field(default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name")


class NexusEthernetRoutedNetworkOSModel(NDNestedModel):
    """
    # Summary

    NX-OS branch of the network-OS container for a routed ethernet interface. Selected from the outer union when
    `networkOSType == "nx-os"`.

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field, and required fields are always
    # explicitly set. The Literal constrains the value; same pattern as the policy_type discriminator.
    network_os_type: Literal["nx-os"] = Field(alias="networkOSType", description="Network OS (platform) type discriminator; required by the ND API schema")
    policy: NexusEthernetRoutedPolicyModel | None = Field(default=None, alias="policy")


class XeEthernetRoutedNetworkOSModel(NDNestedModel):
    """
    # Summary

    IOS-XE branch of the network-OS container for a routed ethernet interface. Selected from the outer union when
    `networkOSType == "ios-xe"`.

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field, and required fields are always
    # explicitly set. The Literal constrains the value; same pattern as the policy_type discriminator.
    network_os_type: Literal["ios-xe"] = Field(alias="networkOSType", description="Network OS (platform) type discriminator; required by the ND API schema")
    policy: XeEthernetRoutedPolicyModel | None = Field(default=None, alias="policy")


class EthernetRoutedConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for a routed ethernet interface. Maps to `configData` in the ND API.

    ## Raises

    None
    """

    mode: Literal["routed"] = Field(default="routed", alias="mode", frozen=True)
    network_os: NexusEthernetRoutedNetworkOSModel | XeEthernetRoutedNetworkOSModel = Field(alias="networkOS", discriminator="network_os_type")


class EthernetRoutedInterfaceModel(NDBaseModel):
    """
    # Summary

    Routed-mode ethernet interface configuration for Nexus Dashboard.

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
    interface_type: Literal["ethernet"] = Field(default="ethernet", alias="interfaceType", frozen=True)
    config_data: EthernetRoutedConfigDataModel | None = Field(default=None, alias="configData")

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

    @field_validator("interface_name", mode="before")
    @classmethod
    def normalize_interface_name(cls, value):
        """
        # Summary

        Normalize the leading alphabetic prefix of an interface name to its wire-canonical form so that user-supplied
        casing or abbreviations round-trip against the wire. A prefix matching (case-insensitively) exactly one of the
        canonical names in `_CANONICAL_INTERFACE_PREFIXES` is expanded to it. Examples:

        - `ethernet1/7`, `ETHERNET1/7`, `eth1/7`, `e1/7` -> `Ethernet1/7`
        - `gigabitethernet3`, `gi3` -> `GigabitEthernet3`
        - `Ethernet1/1.10` -> `Ethernet1/1.10` (idempotent; digits and separators preserved verbatim)

        An ambiguous or unrecognized prefix (e.g. `t1/1`, `TenGigabitEthernet1/1`) passes through verbatim - never
        re-cased - so correctly-typed names of interface families outside the canonical list are not corrupted.

        ## Raises

        None
        """
        return normalize_ethernet_interface_name(value)

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict:
        """
        # Summary

        Return the Ansible argument spec for the `nd_interface_ethernet_routed` module.

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
                                                    "routedHost",
                                                    "iosXeRoutedHost",
                                                ],
                                            ),
                                            admin_state=dict(type="bool"),
                                            description=dict(type="str"),
                                            extra_config=dict(type="str"),
                                            fec=dict(type="str"),
                                            ip=dict(type="str"),
                                            ip_redirects=dict(type="bool"),
                                            mtu=dict(type="int"),
                                            netflow=dict(type="bool"),
                                            netflow_monitor=dict(type="str"),
                                            netflow_sampler=dict(type="str"),
                                            pfc=dict(type="bool"),
                                            pim_dr_priority=dict(type="int"),
                                            pim_sparse=dict(type="bool"),
                                            prefix=dict(type="int"),
                                            qos=dict(type="bool"),
                                            qos_policy=dict(type="str"),
                                            queuing_policy=dict(type="str"),
                                            routing_tag=dict(type="str"),
                                            speed=dict(type="str"),
                                            vrf=dict(type="str"),
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
