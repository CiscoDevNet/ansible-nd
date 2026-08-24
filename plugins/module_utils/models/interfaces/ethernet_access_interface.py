# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Ethernet access (accessHost) interface Pydantic models for Nexus Dashboard.

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload
structure for ethernet accessHost interfaces. The playbook config uses the same nesting so that
`to_payload()` and `from_response()` work via standard Pydantic serialization with no custom
wrapping or flattening.

## Model Hierarchy

- `EthernetAccessInterfaceModel` (top-level, `NDBaseModel`)
    - `interface_name` (identifier)
    - `interface_type` (default: "ethernet")
    - `config_data` -> `EthernetAccessConfigDataModel`
        - `mode` (default: "access")
        - `network_os` -> `EthernetAccessNetworkOSModel`
            - `network_os_type` (default: "nx-os")
            - `policy` -> `EthernetAccessPolicyModel`
                - `admin_state`, `access_vlan`, `bpdu_guard`, `speed`, `policy_type`, etc.
"""

from __future__ import annotations

import re
from copy import deepcopy

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    SerializationInfo,
    field_validator,
    model_serializer,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    AccessHostPolicyTypeEnum,
    BpduFilterEnum,
    BpduGuardEnum,
    DuplexModeEnum,
    FecEnum,
    LinkTypeEnum,
    MtuEnum,
    SpeedEnum,
    StormControlActionEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.storm_control import (
    StormControlMutexMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.types import (
    AsciiDescription,
)

# Module-level so it stays a real re.Pattern; Pydantic v2 wraps any leading-underscore
# class attribute in ModelPrivateAttr regardless of ClassVar annotation.
_INTERFACE_NAME_PREFIX_RE = re.compile(r"^([A-Za-z]+)(.*)$")

# This module exclusively manages ethernet interfaces (interface_type is frozen to "ethernet"),
# so the canonical wire prefix is always "Ethernet". Any case-insensitive NX-OS abbreviation of
# this name (e.g. "e", "eth", "ether") expands to the full form so user input matches the wire key.
_CANONICAL_INTERFACE_TYPE = "Ethernet"


class EthernetAccessPolicyModel(StormControlMutexMixin):
    """
    # Summary

    Policy fields for an ethernet accessHost interface. Maps directly to the `configData.networkOS.policy` object in the ND API.

    ## Raises

    None
    """

    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")
    access_vlan: int | None = Field(
        default=None,
        alias="accessVlan",
        ge=1,
        le=4094,
        description="VLAN for this access port",
    )
    bandwidth: int | None = Field(
        default=None,
        alias="bandwidth",
        ge=1,
        le=100000000,
        description="Bandwidth in kilobits",
    )
    bpdu_filter: BpduFilterEnum | None = Field(
        default=None,
        alias="bpduFilter",
        description="Configure spanning-tree BPDU filter",
    )
    bpdu_guard: BpduGuardEnum | None = Field(default=None, alias="bpduGuard", description="Enable spanning-tree BPDU guard")
    cdp: bool | None = Field(default=None, alias="cdp", description="Enable CDP on the interface")
    debounce_timer: int | None = Field(
        default=None,
        alias="debounceTimer",
        ge=0,
        le=20000,
        description="Link debounce timer in milliseconds",
    )
    debounce_linkup_timer: int | None = Field(
        default=None,
        alias="debounceLinkupTimer",
        ge=1000,
        le=10000,
        description="Link debounce link-up timer in milliseconds",
    )
    description: AsciiDescription = Field(
        default=None,
        alias="description",
        max_length=254,
        description="Interface description",
    )
    duplex_mode: DuplexModeEnum | None = Field(default=None, alias="duplexMode", description="Port duplex mode")
    error_detection_acl: bool | None = Field(
        default=None,
        alias="errorDetectionAcl",
        description="Enable error detection for ACL installation failures",
    )
    extra_config: str | None = Field(
        default=None,
        alias="extraConfig",
        description="Additional CLI for the interface",
    )
    fec: FecEnum | None = Field(default=None, alias="fec", description="Forward error correction mode")
    inherit_bandwidth: int | None = Field(
        default=None,
        alias="inheritBandwidth",
        ge=1,
        le=100000000,
        description="Inherit bandwidth in kilobits for sub-interfaces",
    )
    link_type: LinkTypeEnum | None = Field(default=None, alias="linkType", description="Spanning-tree link type")
    monitor: bool | None = Field(
        default=None,
        alias="monitor",
        description="Enable switchport monitor for SPAN/ERSPAN",
    )
    mtu: MtuEnum | None = Field(default=None, alias="mtu", description="Interface MTU")
    negotiate_auto: bool | None = Field(default=None, alias="negotiateAuto", description="Enable link auto-negotiation")
    netflow: bool | None = Field(default=None, alias="netflow", description="Enable Netflow on the interface")
    netflow_monitor: str | None = Field(default=None, alias="netflowMonitor", description="Layer 2 Netflow monitor name")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler", description="Netflow sampler name")
    orphan_port: bool | None = Field(default=None, alias="orphanPort", description="Enable vPC orphan port")
    pfc: bool | None = Field(default=None, alias="pfc", description="Enable priority flow control")
    policy_type: AccessHostPolicyTypeEnum = Field(
        default=AccessHostPolicyTypeEnum.ACCESS_HOST,
        alias="policyType",
        frozen=True,
        description="Interface policy type (hardcoded for this module)",
    )
    port_type_edge_trunk: bool | None = Field(
        default=None,
        alias="portTypeEdgeTrunk",
        description="Enable spanning-tree edge port behavior",
    )
    qos: bool | None = Field(
        default=None,
        alias="qos",
        description="Enable QoS configuration for this interface",
    )
    qos_policy: str | None = Field(default=None, alias="qosPolicy", description="Custom QoS policy name")
    queuing_policy: str | None = Field(default=None, alias="queuingPolicy", description="Custom queuing policy name")
    speed: SpeedEnum | None = Field(default=None, alias="speed", description="Interface speed")
    storm_control: bool | None = Field(default=None, alias="stormControl", description="Enable traffic storm control")
    storm_control_action: StormControlActionEnum | None = Field(
        default=None,
        alias="stormControlAction",
        description="Storm control action on threshold violation",
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

    @model_serializer(mode="wrap")
    def _strip_policy_type_in_config(self, handler, info: SerializationInfo):
        """
        # Summary

        Omit `policy_type` from `to_config()` output while leaving payload and diff modes untouched.

        The field is hardcoded by the model (frozen at `AccessHostPolicyTypeEnum.ACCESS_HOST`), is excluded
        from the Ansible argspec, and is therefore not something the user supplies or needs surfaced back.
        The wire form `"accessHost"` would otherwise appear under the `policy_type` key in
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


class EthernetAccessNetworkOSModel(NDNestedModel):
    """
    # Summary

    Network OS container for an ethernet accessHost interface. Maps to `configData.networkOS` in the ND API.

    ## Raises

    None
    """

    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType", frozen=True)
    policy: EthernetAccessPolicyModel | None = Field(default=None, alias="policy")


class EthernetAccessConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for an ethernet accessHost interface. Maps to `configData` in the ND API.

    ## Raises

    None
    """

    mode: Literal["access"] = Field(default="access", alias="mode", frozen=True)
    network_os: EthernetAccessNetworkOSModel = Field(default_factory=EthernetAccessNetworkOSModel, alias="networkOS")


class EthernetAccessInterfaceModel(NDBaseModel):
    """
    # Summary

    Ethernet accessHost interface configuration for Nexus Dashboard.

    Uses a composite identifier (`switch_ip`, `interface_name`). The nested model structure mirrors the ND Manage
    Interfaces API payload, so `to_payload()` and `from_response()` work via standard Pydantic serialization.

    ## Raises

    None
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[list[str] | None] = ["switch_ip", "interface_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "composite"

    # --- Gathered Filtering Configuration ---

    supports_gathered_filtering: ClassVar[bool] = True
    gathered_filter_properties: ClassVar[tuple[str, ...]] = (
        "switch_ip",
        "interface_name",
        "config_data.network_os.policy.admin_state",
        "config_data.network_os.policy.access_vlan",
    )
    # --- Serialization Configuration ---

    payload_exclude_fields: ClassVar[set[str]] = {"switch_ip"}

    # --- Fields ---

    switch_ip: str = Field(alias="switchIp")
    interface_name: str = Field(alias="interfaceName")
    interface_type: Literal["ethernet"] = Field(default="ethernet", alias="interfaceType", frozen=True)
    config_data: EthernetAccessConfigDataModel | None = Field(default=None, alias="configData")

    @field_validator("interface_name", mode="before")
    @classmethod
    def normalize_interface_name(cls, value):
        """
        # Summary

        Normalize the leading alphabetic prefix of an interface name to ND's canonical `Ethernet` form so that
        any user-supplied casing or NX-OS abbreviation round-trips against the wire form. Examples:

        - `ethernet1/1` -> `Ethernet1/1`
        - `ETHERNET1/1` -> `Ethernet1/1`
        - `etHernet1/1` -> `Ethernet1/1`
        - `eth1/1` -> `Ethernet1/1` (abbreviation expanded)
        - `e1/1` -> `Ethernet1/1` (abbreviation expanded)
        - `Ethernet1/1` -> `Ethernet1/1` (idempotent)

        Because the wire key is matched exactly, an abbreviated prefix that is not expanded would never match
        ND's `Ethernet...` form, silently breaking idempotency. Any case-insensitive prefix of `Ethernet`
        (`e`, `et`, `eth`, ...) is therefore expanded to the full canonical name. An unrecognized prefix falls
        back to Title case so it still round-trips. Only the leading alphabetic run is rewritten; digits and
        separators (`/`, `.`, `-`) are preserved verbatim, so subinterface and breakout forms
        (`Ethernet1/1.10`, `Ethernet1/1/1`) pass through unchanged.

        ## Raises

        None
        """
        if not isinstance(value, str) or not value:
            return value
        match = _INTERFACE_NAME_PREFIX_RE.match(value)
        if not match:
            return value
        prefix, rest = match.groups()
        if _CANONICAL_INTERFACE_TYPE.lower().startswith(prefix.lower()):
            return _CANONICAL_INTERFACE_TYPE + rest
        return prefix[0].upper() + prefix[1:].lower() + rest

    @classmethod
    def normalize_gathered_filter(cls, filter_item: dict) -> dict:
        """
        Normalize a partial gathered-state filter.

        Gathered filters are not complete EthernetAccessInterfaceModel instances,
        so the normal Pydantic interface_name validator does not run against them.
        """
        normalized = deepcopy(filter_item)
        interface_name = normalized.get("interface_name")
        if isinstance(interface_name, str) and interface_name:
            match = _INTERFACE_NAME_PREFIX_RE.match(interface_name)
            if match:
                prefix, rest = match.groups()
                if _CANONICAL_INTERFACE_TYPE.lower().startswith(prefix.lower()):
                    normalized["interface_name"] = _CANONICAL_INTERFACE_TYPE + rest
                else:
                    normalized["interface_name"] = prefix[0].upper() + prefix[1:].lower() + rest
        return normalized

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict:
        """
        # Summary

        Return the Ansible argument spec for the `nd_interface_ethernet_access` module.

        ## Raises

        None
        """
        return dict(
            fabric_name=dict(type="str", required=True),
            config=dict(
                type="list",
                elements="dict",
                required=False,
                options=dict(
                    switch_ip=dict(type="str", required=False),
                    interface_names=dict(type="list", elements="str", required=False),
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
                                            bandwidth=dict(type="int"),
                                            bpdu_filter=dict(
                                                type="str",
                                                choices=[e.value for e in BpduFilterEnum],
                                            ),
                                            bpdu_guard=dict(
                                                type="str",
                                                choices=[e.value for e in BpduGuardEnum],
                                            ),
                                            cdp=dict(type="bool"),
                                            debounce_timer=dict(type="int"),
                                            debounce_linkup_timer=dict(type="int"),
                                            description=dict(type="str"),
                                            duplex_mode=dict(
                                                type="str",
                                                choices=[e.value for e in DuplexModeEnum],
                                            ),
                                            error_detection_acl=dict(type="bool"),
                                            extra_config=dict(type="str"),
                                            fec=dict(
                                                type="str",
                                                choices=[e.value for e in FecEnum],
                                            ),
                                            inherit_bandwidth=dict(type="int"),
                                            link_type=dict(
                                                type="str",
                                                choices=[e.value for e in LinkTypeEnum],
                                            ),
                                            monitor=dict(type="bool"),
                                            mtu=dict(
                                                type="str",
                                                choices=[e.value for e in MtuEnum],
                                            ),
                                            negotiate_auto=dict(type="bool"),
                                            netflow=dict(type="bool"),
                                            netflow_monitor=dict(type="str"),
                                            netflow_sampler=dict(type="str"),
                                            orphan_port=dict(type="bool"),
                                            pfc=dict(type="bool"),
                                            port_type_edge_trunk=dict(type="bool"),
                                            qos=dict(type="bool"),
                                            qos_policy=dict(type="str"),
                                            queuing_policy=dict(type="str"),
                                            speed=dict(
                                                type="str",
                                                choices=[e.value for e in SpeedEnum],
                                            ),
                                            storm_control=dict(type="bool"),
                                            storm_control_action=dict(
                                                type="str",
                                                choices=[e.value for e in StormControlActionEnum],
                                            ),
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
                choices=["merged", "replaced", "overridden", "deleted", "gathered"],
            ),
        )
