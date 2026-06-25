# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Port-channel access (accessPoHost) interface Pydantic models for Nexus Dashboard.

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload
structure for port-channel accessPoHost interfaces. The playbook config uses the same nesting
so that `to_payload()` and `from_response()` work via standard Pydantic serialization with no
custom wrapping or flattening.

The port-channel policy is the single source of truth for member configuration. Member ethernet
interfaces inherit access-mode settings from the port-channel; users do not pre-configure members.

## Model Hierarchy

- `PortChannelAccessInterfaceModel` (top-level, `NDBaseModel`)
    - `switch_ip` (composite identifier)
    - `interface_name` (composite identifier; e.g. `port-channel501`)
    - `interface_type` (default: "portChannel")
    - `config_data` -> `PortChannelAccessConfigDataModel`
        - `mode` (default: "access")
        - `network_os` -> `PortChannelAccessNetworkOSModel`
            - `network_os_type` (default: "nx-os")
            - `policy` -> `PortChannelAccessPolicyModel`
                - `admin_state`, `access_vlan`, `ports`, `port_channel_mode`,
                  `lacp_rate`, `bpdu_guard`, `description`, etc.
"""

from __future__ import annotations

import re
from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    SerializationInfo,
    field_validator,
    model_serializer,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    AccessPoHostPolicyTypeEnum,
    BpduFilterEnum,
    BpduGuardEnum,
    DuplexModeEnum,
    LacpRateEnum,
    MtuEnum,
    PortChannelModeEnum,
    SpeedEnum,
    StormControlActionEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription

# Splits an interface name into its leading alphabetic prefix and the rest (digits/separators).
_INTERFACE_NAME_PREFIX_RE = re.compile(r"^([A-Za-z]+)(.*)$")

# Member interfaces of a port-channel are always physical ethernet ports, so the canonical wire prefix
# is always "Ethernet". Any case-insensitive NX-OS abbreviation (e.g. "e", "eth", "ether") expands to the
# full form so user input matches the wire key and idempotency holds.
_CANONICAL_MEMBER_TYPE = "Ethernet"


class PortChannelAccessPolicyModel(NDNestedModel):
    """
    # Summary

    Policy fields for a port-channel accessPoHost interface. Maps directly to the `configData.networkOS.policy`
    object in the ND API.

    The `ports` field carries the list of member interface names (e.g. `Ethernet1/1`). Member interfaces inherit
    access-mode configuration from this policy; modifying a member's standalone configuration while it is a
    port-channel member is restricted by the ethernet orchestrators.

    ## Raises

    None
    """

    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")
    access_vlan: int | None = Field(default=None, alias="accessVlan", ge=1, le=4094, description="VLAN for this access port-channel")
    bpdu_filter: BpduFilterEnum | None = Field(default=None, alias="bpduFilter", description="Configure spanning-tree BPDU filter")
    bpdu_guard: BpduGuardEnum | None = Field(default=None, alias="bpduGuard", description="Enable spanning-tree BPDU guard")
    cdp: bool | None = Field(default=None, alias="cdp", description="Enable CDP on the interface")
    copy_description: bool | None = Field(default=None, alias="copyDescription", description="Propagate the port-channel description to all member interfaces")
    description: AsciiDescription = Field(default=None, alias="description", max_length=254, description="Interface description")
    duplex_mode: DuplexModeEnum | None = Field(default=None, alias="duplexMode", description="Port duplex mode")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    lacp_port_priority: int | None = Field(default=None, alias="lacpPortPriority", ge=1, le=65535, description="LACP port priority (1-65535, default 32768)")
    lacp_rate: LacpRateEnum | None = Field(default=None, alias="lacpRate", description="LACP rate (normal=30s, fast=1s)")
    lacp_suspend: bool | None = Field(default=None, alias="lacpSuspend", description="Suspend port if LACP PDUs not received")
    monitor: bool | None = Field(default=None, alias="monitor", description="Enable switchport monitor for SPAN/ERSPAN")
    mtu: MtuEnum | None = Field(default=None, alias="mtu", description="Interface MTU")
    netflow: bool | None = Field(default=None, alias="netflow", description="Enable Netflow on the interface")
    netflow_monitor: str | None = Field(default=None, alias="netflowMonitor", description="Layer 2 Netflow monitor name")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler", description="Netflow sampler name")
    policy_type: AccessPoHostPolicyTypeEnum = Field(
        default=AccessPoHostPolicyTypeEnum.ACCESS_PO_HOST, alias="policyType", frozen=True, description="Interface policy type (hardcoded for this module)"
    )
    port_channel_mode: PortChannelModeEnum | None = Field(default=None, alias="portChannelMode", description="Port-channel mode (on/active/passive)")
    ports: list[str] | None = Field(default=None, alias="ports", description="Member interface names (e.g. ['Ethernet1/1', 'Ethernet1/2'])")
    qos: bool | None = Field(default=None, alias="qos", description="Enable QoS configuration for this interface")
    qos_policy: str | None = Field(default=None, alias="qosPolicy", description="Custom QoS policy name")
    queuing_policy: str | None = Field(default=None, alias="queuingPolicy", description="Custom queuing policy name")
    speed: SpeedEnum | None = Field(default=None, alias="speed", description="Interface speed")
    storm_control: bool | None = Field(default=None, alias="stormControl", description="Enable traffic storm control")
    storm_control_action: StormControlActionEnum | None = Field(
        default=None, alias="stormControlAction", description="Storm control action on threshold violation"
    )
    storm_control_broadcast_level: float | None = Field(
        default=None,
        alias="stormControlBroadcastLevel",
        ge=0.0,
        le=100.0,
        description="Broadcast storm control level in percentage (0.00-100.00)",
    )
    storm_control_broadcast_level_pps: int | None = Field(
        default=None,
        alias="stormControlBroadcastLevelPps",
        ge=0,
        le=200000000,
        description="Broadcast storm control level in packets per second",
    )
    storm_control_multicast_level: float | None = Field(
        default=None,
        alias="stormControlMulticastLevel",
        ge=0.0,
        le=100.0,
        description="Multicast storm control level in percentage (0.00-100.00)",
    )
    storm_control_multicast_level_pps: int | None = Field(
        default=None,
        alias="stormControlMulticastLevelPps",
        ge=0,
        le=200000000,
        description="Multicast storm control level in packets per second",
    )
    storm_control_unicast_level: float | None = Field(
        default=None,
        alias="stormControlUnicastLevel",
        ge=0.0,
        le=100.0,
        description="Unicast storm control level in percentage (0.00-100.00)",
    )
    storm_control_unicast_level_pps: int | None = Field(
        default=None,
        alias="stormControlUnicastLevelPps",
        ge=0,
        le=200000000,
        description="Unicast storm control level in packets per second",
    )

    # --- Validators ---

    @field_validator("ports", mode="before")
    @classmethod
    def normalize_ports(cls, value):
        """
        # Summary

        Normalize each member interface name to ND's canonical `Ethernet` form so that any user-supplied casing or
        NX-OS abbreviation round-trips against the wire form. Members are always physical ethernet ports. Examples:

        - `ethernet1/1` -> `Ethernet1/1`
        - `ETHERNET1/1` -> `Ethernet1/1`
        - `eth1/1` -> `Ethernet1/1` (abbreviation expanded)
        - `e1/1` -> `Ethernet1/1` (abbreviation expanded)
        - `Ethernet1/1` -> `Ethernet1/1` (idempotent)

        Because the wire key is matched exactly, an abbreviated prefix that is not expanded would never match ND's
        `Ethernet...` form, silently breaking idempotency (the port-channel re-deploys on every run). Any
        case-insensitive prefix of `Ethernet` (`e`, `et`, `eth`, ...) is therefore expanded to the full canonical
        name; an unrecognized prefix falls back to Title case so it still round-trips. Only the leading alphabetic
        run is rewritten; digits and separators are preserved verbatim.

        ## Raises

        None
        """
        if not isinstance(value, list):
            return value
        return [cls._normalize_member_name(name) for name in value]

    @staticmethod
    def _normalize_member_name(name):
        """
        # Summary

        Normalize a single member interface name to ND's canonical `Ethernet` form (see `normalize_ports`).
        Non-string or empty values are returned unchanged.

        ## Raises

        None
        """
        if not isinstance(name, str) or not name:
            return name
        match = _INTERFACE_NAME_PREFIX_RE.match(name)
        if not match:
            return name
        prefix, rest = match.groups()
        if _CANONICAL_MEMBER_TYPE.lower().startswith(prefix.lower()):
            return _CANONICAL_MEMBER_TYPE + rest
        return prefix[0].upper() + prefix[1:].lower() + rest

    @model_serializer(mode="wrap")
    def _strip_policy_type_in_config(self, handler, info: SerializationInfo):
        """
        # Summary

        Omit `policy_type` from `to_config()` output while leaving payload and diff modes untouched.

        The field is hardcoded by the model (frozen at `AccessPoHostPolicyTypeEnum.ACCESS_PO_HOST`), is excluded
        from the Ansible argspec, and is therefore not something the user supplies or needs surfaced back.
        The wire form `"accessPoHost"` would otherwise appear under the `policy_type` key in
        `before`/`after`/`gathered` output and confuse playbooks that compare against the Ansible
        snake_case convention. Payload and diff serialization still emit the wire value so the POST/PUT
        body and the round-trip diff comparison line up with what ND returns.

        Implemented as a wrap-mode model serializer because `exclude_none=True` on `to_config()` evaluates
        the field value before serialization runs — returning None from a field_serializer is too late to
        drop the key.

        ## Raises

        ### AssertionError

        - If the wrapped handler returns a non-`dict`. A model-level serializer always serializes to a `dict`,
          so this is an invariant check that fails loudly rather than silently leaving `policy_type` in the
          config output.
        """
        result = handler(self)
        if not isinstance(result, dict):
            raise AssertionError(f"Expected dict from model serialization, got {type(result).__name__}")
        mode = (info.context or {}).get("mode", "payload")
        if mode == "config":
            result.pop("policy_type", None)
            result.pop("policyType", None)
        return result


class PortChannelAccessNetworkOSModel(NDNestedModel):
    """
    # Summary

    Network OS container for a port-channel accessPoHost interface. Maps to `configData.networkOS` in the ND API.

    ## Raises

    None
    """

    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType", frozen=True)
    policy: PortChannelAccessPolicyModel | None = Field(default=None, alias="policy")


class PortChannelAccessConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for a port-channel accessPoHost interface. Maps to `configData` in the ND API.

    ## Raises

    None
    """

    mode: Literal["access"] = Field(default="access", alias="mode", frozen=True)
    network_os: PortChannelAccessNetworkOSModel = Field(default_factory=PortChannelAccessNetworkOSModel, alias="networkOS")


class PortChannelAccessInterfaceModel(NDBaseModel):
    """
    # Summary

    Port-channel accessPoHost interface configuration for Nexus Dashboard.

    Uses a composite identifier (`switch_ip`, `interface_name`). The nested model structure mirrors the ND Manage
    Interfaces API payload, so `to_payload()` and `from_response()` work via standard Pydantic serialization.

    The `interface_name` is the port-channel's own name (e.g. `port-channel501`), not a member interface. Member
    interfaces are listed in `config_data.network_os.policy.ports`.

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
    interface_type: Literal["portChannel"] = Field(default="portChannel", alias="interfaceType", frozen=True)
    config_data: PortChannelAccessConfigDataModel | None = Field(default=None, alias="configData")

    @field_validator("interface_name", mode="before")
    @classmethod
    def normalize_interface_name(cls, value):
        """
        # Summary

        Normalize the port-channel interface name to lowercase to match ND API convention (e.g. `Port-Channel501` ->
        `port-channel501`).

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

        Return the Ansible argument spec for the `nd_interface_port_channel_access` module.

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
                                            access_vlan=dict(type="int"),
                                            bpdu_filter=dict(type="str", choices=[e.value for e in BpduFilterEnum]),
                                            bpdu_guard=dict(type="str", choices=[e.value for e in BpduGuardEnum]),
                                            cdp=dict(type="bool"),
                                            copy_description=dict(type="bool"),
                                            description=dict(type="str"),
                                            duplex_mode=dict(type="str", choices=[e.value for e in DuplexModeEnum]),
                                            extra_config=dict(type="str"),
                                            lacp_port_priority=dict(type="int"),
                                            lacp_rate=dict(type="str", choices=[e.value for e in LacpRateEnum]),
                                            lacp_suspend=dict(type="bool"),
                                            monitor=dict(type="bool"),
                                            mtu=dict(type="str", choices=[e.value for e in MtuEnum]),
                                            netflow=dict(type="bool"),
                                            netflow_monitor=dict(type="str"),
                                            netflow_sampler=dict(type="str"),
                                            port_channel_mode=dict(type="str", choices=[e.value for e in PortChannelModeEnum]),
                                            ports=dict(type="list", elements="str"),
                                            qos=dict(type="bool"),
                                            qos_policy=dict(type="str"),
                                            queuing_policy=dict(type="str"),
                                            speed=dict(type="str", choices=[e.value for e in SpeedEnum]),
                                            storm_control=dict(type="bool"),
                                            storm_control_action=dict(type="str", choices=[e.value for e in StormControlActionEnum]),
                                            storm_control_broadcast_level=dict(type="float"),
                                            storm_control_broadcast_level_pps=dict(type="int"),
                                            storm_control_multicast_level=dict(type="float"),
                                            storm_control_multicast_level_pps=dict(type="int"),
                                            storm_control_unicast_level=dict(type="float"),
                                            storm_control_unicast_level_pps=dict(type="int"),
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
