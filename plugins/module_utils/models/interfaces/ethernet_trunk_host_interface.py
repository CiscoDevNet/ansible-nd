# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Ethernet trunk host (trunkHost) interface Pydantic models for Nexus Dashboard.

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload
structure for ethernet trunkHost interfaces. The playbook config uses the same nesting so that
`to_payload()` and `from_response()` work via standard Pydantic serialization with no custom
wrapping or flattening.

## Model Hierarchy

- `EthernetTrunkHostInterfaceModel` (top-level, `NDBaseModel`)
    - `interface_name` (identifier)
    - `interface_type` (default: "ethernet")
    - `config_data` -> `EthernetTrunkHostConfigDataModel`
        - `mode` (default: "trunk")
        - `network_os` -> `EthernetTrunkHostNetworkOSModel`
            - `network_os_type` (default: "nx-os")
            - `policy` -> `EthernetTrunkHostPolicyModel`
                - `admin_state`, `allowed_vlans`, `native_vlan`, `vlan_mapping`,
                  `vlan_mapping_entries`, `bpdu_guard`, `speed`, `policy_type`, etc.
                - `vlan_mapping_entries` -> list[`EthernetTrunkHostVlanMappingEntryModel`]
"""

from __future__ import annotations

import re
from typing import Annotated, ClassVar, Literal, Optional  # Optional needed for Annotated runtime expr (see types.py)

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BeforeValidator,
    Field,
    SerializationInfo,
    field_validator,
    model_serializer,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    BpduFilterEnum,
    BpduGuardEnum,
    DuplexModeEnum,
    FecEnum,
    LinkTypeEnum,
    MtuEnum,
    SpeedEnum,
    StormControlActionEnum,
    TrunkHostPolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.storm_control import StormControlMutexMixin
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription

# Shape regex: "none", "all", or comma-separated VLAN ids/ranges. Range bounds are validated separately.
_ALLOWED_VLANS_SHAPE = re.compile(r"^(none|all|(\d+(-\d+)?)(,\d+(-\d+)?)*)$")
# Single VLAN id or range token (e.g. "100" or "100-200"). Range bounds are validated separately.
_VLAN_ID_OR_RANGE_SHAPE = re.compile(r"^\d+(-\d+)?$")
# Module-level so it stays a real re.Pattern; Pydantic v2 wraps any leading-underscore
# class attribute in ModelPrivateAttr regardless of ClassVar annotation.
_INTERFACE_NAME_PREFIX_RE = re.compile(r"^([A-Za-z]+)(.*)$")

# This module exclusively manages ethernet interfaces (interface_type is frozen to "ethernet"),
# so the canonical wire prefix is always "Ethernet". Any case-insensitive NX-OS abbreviation of
# this name (e.g. "e", "eth", "ether") expands to the full form so user input matches the wire key.
_CANONICAL_INTERFACE_TYPE = "Ethernet"


def _validate_vlan_id_or_range(token: str, field_name: str) -> None:
    """
    # Summary

    Validate a single VLAN id or range token (e.g. `"100"` or `"100-200"`) and confirm every id is in 1..4094 and any range has start <= end.

    Shared helper used by `_validate_allowed_vlans` (per comma-split token) and `_validate_customer_vlan_id_list` (per list element).
    `field_name` is interpolated into error messages so callers see which field surfaced the failure.

    ## Raises

    ### ValueError

    - If `token` does not match `\\d+(-\\d+)?`.
    - If any VLAN id is outside 1..4094.
    - If a range has start greater than end.
    """
    if not _VLAN_ID_OR_RANGE_SHAPE.match(token):
        raise ValueError(f"{field_name} entry {token!r} must be a VLAN id or range (e.g. '100' or '100-200')")
    if "-" in token:
        start_str, end_str = token.split("-", 1)
        start, end = int(start_str), int(end_str)
        if not 1 <= start <= 4094 or not 1 <= end <= 4094:
            raise ValueError(f"{field_name} range {token!r} is out of bounds; VLAN ids must be in 1..4094")
        if start > end:
            raise ValueError(f"{field_name} range {token!r} has start greater than end")
    else:
        vid = int(token)
        if not 1 <= vid <= 4094:
            raise ValueError(f"{field_name} id {vid} is out of bounds; VLAN ids must be in 1..4094")


def _validate_allowed_vlans(value):
    """
    # Summary

    Validate `allowed_vlans` matches `"none"`, `"all"`, or a comma-separated list of VLAN ids/ranges where every id is in 1..4094 and every range start <= end.
    ND returns single-id values as JSON ints (e.g. `250`) but accepts both forms on input; this validator coerces int -> str so round-trips and idempotency
    comparisons are stable.

    Used as the `BeforeValidator` payload for the `AllowedVlans` Annotated type.

    ## Raises

    ### ValueError

    - If `value` is a non-empty string that does not match the expected shape.
    - If any VLAN id is outside 1..4094.
    - If any range has start greater than end.
    """
    if value is None or value == "":
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str):
        return value
    if value in ("none", "all"):
        return value
    if not _ALLOWED_VLANS_SHAPE.match(value):
        raise ValueError(f"allowed_vlans must be 'none', 'all', or a comma-separated list of VLAN ids/ranges (e.g. '1-200,500-2000,3000'); got {value!r}")
    for token in value.split(","):
        _validate_vlan_id_or_range(token, "allowed_vlans")
    return value


def _validate_customer_vlan_id_list(value):
    """
    # Summary

    Validate `customer_vlan_id` is a list of non-empty VLAN id or range strings where every id is in 1..4094 and every range start <= end.
    Used in `vlanMappingEntries` to identify which customer VLAN ids map to a provider VLAN id.
    ND returns single-id values as JSON ints (e.g. `250`); this validator coerces int -> str per entry, mirroring `_validate_allowed_vlans`,
    so GET responses round-trip and idempotency comparisons stay stable.

    Used as the `BeforeValidator` payload for the `CustomerVlanIdList` Annotated type.

    ## Raises

    ### ValueError

    - If any list entry is not a non-empty string (after int coercion).
    - If any entry is not a VLAN id or range, has an id outside 1..4094, or has a reversed range.
    """
    if value is None:
        return value
    if not isinstance(value, list):
        return value
    coerced = []
    for entry in value:
        if isinstance(entry, int) and not isinstance(entry, bool):
            entry = str(entry)
        if not isinstance(entry, str) or not entry:
            raise ValueError(f"customer_vlan_id entries must be non-empty strings (VLAN id or range); got {entry!r}")
        _validate_vlan_id_or_range(entry, "customer_vlan_id")
        coerced.append(entry)
    return coerced


# TODO: After all per-policy interface modules (ethernet_trunk_host, svi, port_channel_trunk_host, ...) merge to develop, consolidate
# AllowedVlans, CustomerVlanIdList, and the _validate_vlan_id_or_range helper into models/types.py so the sibling modules can share
# a single source of truth. Also introduce a shared `VlanId` type (1..4094) in the same PR and replace per-field `Field(ge=1, le=4094)`
# constraints (native_vlan, customer_inner_vlan_id, provider_vlan_id, access_vlan, ...) — the constraint is already enforced today,
# this is cosmetic/consistency cleanup. Each branch currently carries its own copy of the validators because adding VLAN-specific code
# to the loopback base branch (where types.py lives) is out of that branch's scope. Tracked in CiscoDevNet/ansible-nd#347.
# In the same consolidation, fold the interface-name normalizer into a shared helper: `normalize_interface_name`,
# `_CANONICAL_INTERFACE_TYPE`, and `_INTERFACE_NAME_PREFIX_RE` are byte-identical here and in ethernet_access_interface.py, while
# loopback_interface.py needs a different rule (it lowercases the whole name to match ND's GET form). So the shared helper must be
# parameterized (canonical prefix + an expand-vs-lowercase policy), e.g. a `normalize_interface_name(value, canonical="Ethernet", ...)`
# in models/types.py that each model calls from its own `@field_validator("interface_name")`.
# See AsciiDescription comment in models/types.py for why Optional[...] is used at runtime instead of `... | None`.
AllowedVlans = Annotated[Optional[str], BeforeValidator(_validate_allowed_vlans)]
"""Trunk allowed-VLANs spec (`str | None`): 'none', 'all', or comma-separated VLAN ids/ranges in 1..4094."""

CustomerVlanIdList = Annotated[Optional[list[str]], BeforeValidator(_validate_customer_vlan_id_list)]
"""Customer VLAN id list (`list[str] | None`): each entry is a VLAN id or range in 1..4094 (e.g. `['100', '200-300']`)."""


class EthernetTrunkHostVlanMappingEntryModel(NDNestedModel):
    """
    # Summary

    A single VLAN mapping entry for selective dot1q-tunnel on an ethernet trunkHost interface. Maps to an element of the
    `configData.networkOS.policy.vlanMappingEntries` list in the ND API.

    ## Raises

    None
    """

    customer_inner_vlan_id: int | None = Field(default=None, alias="customerInnerVlanId", ge=1, le=4094, description="Customer inner VLAN")
    customer_vlan_id: CustomerVlanIdList = Field(
        default=None,
        alias="customerVlanId",
        description="Customer VLAN ids / ranges for selective dot1q-tunnel; each entry is a VLAN id or range string in 1..4094 (e.g. ['100', '200-300'])",
    )
    dot1q_tunnel: bool | None = Field(default=None, alias="dot1qTunnel", description="Selective dot1q-tunnel")
    provider_vlan_id: int | None = Field(default=None, alias="providerVlanId", ge=1, le=4094, description="Provider VLAN")


class EthernetTrunkHostPolicyModel(StormControlMutexMixin):
    """
    # Summary

    Policy fields for an ethernet trunkHost interface. Maps directly to the `configData.networkOS.policy` object in the ND API.

    ## Raises

    ### ValueError

    - If `allowed_vlans` is not `none`, `all`, or a comma-separated list of VLAN ids / ranges
    - If both the percentage and pps level are set for the same storm-control class in a non-response context (via `StormControlMutexMixin`)
    """

    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")
    allowed_vlans: AllowedVlans = Field(
        default=None,
        alias="allowedVlans",
        description="Allowed VLANs on the trunk: 'none', 'all', or comma-separated VLAN ids/ranges in 1..4094 (e.g. '1-200,500-2000,3000')",
    )
    bandwidth: int | None = Field(default=None, alias="bandwidth", ge=1, le=100000000, description="Bandwidth in kilobits")
    bpdu_filter: BpduFilterEnum | None = Field(default=None, alias="bpduFilter", description="Configure spanning-tree BPDU filter")
    bpdu_guard: BpduGuardEnum | None = Field(default=None, alias="bpduGuard", description="Enable spanning-tree BPDU guard")
    cdp: bool | None = Field(default=None, alias="cdp", description="Enable CDP on the interface")
    debounce_timer: int | None = Field(default=None, alias="debounceTimer", ge=0, le=20000, description="Link debounce timer in milliseconds")
    debounce_linkup_timer: int | None = Field(
        default=None, alias="debounceLinkupTimer", ge=1000, le=10000, description="Link debounce link-up timer in milliseconds"
    )
    description: AsciiDescription = Field(default=None, alias="description", max_length=254, description="Interface description")
    duplex_mode: DuplexModeEnum | None = Field(default=None, alias="duplexMode", description="Port duplex mode")
    error_detection_acl: bool | None = Field(default=None, alias="errorDetectionAcl", description="Enable error detection for ACL installation failures")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    fec: FecEnum | None = Field(default=None, alias="fec", description="Forward error correction mode")
    inherit_bandwidth: int | None = Field(
        default=None, alias="inheritBandwidth", ge=1, le=100000000, description="Inherit bandwidth in kilobits for sub-interfaces"
    )
    link_type: LinkTypeEnum | None = Field(default=None, alias="linkType", description="Spanning-tree link type")
    monitor: bool | None = Field(default=None, alias="monitor", description="Enable switchport monitor for SPAN/ERSPAN")
    mtu: MtuEnum | None = Field(default=None, alias="mtu", description="Interface MTU")
    native_vlan: int | None = Field(default=None, alias="nativeVlan", ge=1, le=4094, description="Native VLAN for the trunk interface")
    negotiate_auto: bool | None = Field(default=None, alias="negotiateAuto", description="Enable link auto-negotiation")
    netflow: bool | None = Field(default=None, alias="netflow", description="Enable Netflow on the interface")
    netflow_monitor: str | None = Field(default=None, alias="netflowMonitor", description="Layer 2 Netflow monitor name")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler", description="Netflow sampler name")
    orphan_port: bool | None = Field(default=None, alias="orphanPort", description="Enable vPC orphan port")
    pfc: bool | None = Field(default=None, alias="pfc", description="Enable priority flow control")
    policy_type: TrunkHostPolicyTypeEnum = Field(
        default=TrunkHostPolicyTypeEnum.TRUNK_HOST, alias="policyType", frozen=True, description="Interface policy type (hardcoded for this module)"
    )
    port_type_edge_trunk: bool | None = Field(default=None, alias="portTypeEdgeTrunk", description="Enable spanning-tree edge port behavior")
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
    vlan_mapping: bool | None = Field(default=None, alias="vlanMapping", description="Enable VLAN mapping on the interface")
    vlan_mapping_entries: list[EthernetTrunkHostVlanMappingEntryModel] | None = Field(
        default=None, alias="vlanMappingEntries", description="List of VLAN mapping entries; required when `vlan_mapping` is true"
    )

    @model_serializer(mode="wrap")
    def _strip_policy_type_in_config(self, handler, info: SerializationInfo):
        """
        # Summary

        Omit `policy_type` from `to_config()` output while leaving payload and diff modes untouched.

        The field is hardcoded by the model (frozen at `TrunkHostPolicyTypeEnum.TRUNK_HOST`), is excluded
        from the Ansible argspec, and is therefore not something the user supplies or needs surfaced back.
        The wire form `"trunkHost"` would otherwise appear under the `policy_type` key in
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

    @model_validator(mode="after")
    def _validate_vlan_mapping_entries_present(self) -> EthernetTrunkHostPolicyModel:
        """
        # Summary

        Reject enabling `vlan_mapping` without supplying any `vlan_mapping_entries`.

        The DOCUMENTATION and field description state that `vlan_mapping_entries` is required when `vlan_mapping` is true. Enforcing it at the model
        layer fails an incomplete policy early with a clear error instead of accepting it and deferring the outcome to a later layer or to ND.

        ## Raises

        ### ValueError

        - If `vlan_mapping` is true and `vlan_mapping_entries` is missing or empty.
        """
        if self.vlan_mapping is True and not self.vlan_mapping_entries:
            raise ValueError("vlan_mapping_entries must be provided when vlan_mapping is true.")
        return self


class EthernetTrunkHostNetworkOSModel(NDNestedModel):
    """
    # Summary

    Network OS container for an ethernet trunkHost interface. Maps to `configData.networkOS` in the ND API.

    ## Raises

    None
    """

    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType", frozen=True)
    policy: EthernetTrunkHostPolicyModel | None = Field(default=None, alias="policy")


class EthernetTrunkHostConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for an ethernet trunkHost interface. Maps to `configData` in the ND API.

    ## Raises

    None
    """

    mode: Literal["trunk"] = Field(default="trunk", alias="mode", frozen=True)
    network_os: EthernetTrunkHostNetworkOSModel = Field(default_factory=EthernetTrunkHostNetworkOSModel, alias="networkOS")


class EthernetTrunkHostInterfaceModel(NDBaseModel):
    """
    # Summary

    Ethernet trunkHost interface configuration for Nexus Dashboard.

    Uses a composite identifier (`switch_ip`, `interface_name`). The nested model structure mirrors the ND Manage
    Interfaces API payload, so `to_payload()` and `from_response()` work via standard Pydantic serialization.

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
    config_data: EthernetTrunkHostConfigDataModel | None = Field(default=None, alias="configData")

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

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict:
        """
        # Summary

        Return the Ansible argument spec for the `nd_interface_ethernet_trunk_host` module.

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
                    interface_names=dict(type="list", elements="str", required=True),
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
                                            allowed_vlans=dict(type="str"),
                                            bandwidth=dict(type="int"),
                                            bpdu_filter=dict(type="str", choices=[e.value for e in BpduFilterEnum]),
                                            bpdu_guard=dict(type="str", choices=[e.value for e in BpduGuardEnum]),
                                            cdp=dict(type="bool"),
                                            debounce_timer=dict(type="int"),
                                            debounce_linkup_timer=dict(type="int"),
                                            description=dict(type="str"),
                                            duplex_mode=dict(type="str", choices=[e.value for e in DuplexModeEnum]),
                                            error_detection_acl=dict(type="bool"),
                                            extra_config=dict(type="str"),
                                            fec=dict(type="str", choices=[e.value for e in FecEnum]),
                                            inherit_bandwidth=dict(type="int"),
                                            link_type=dict(type="str", choices=[e.value for e in LinkTypeEnum]),
                                            monitor=dict(type="bool"),
                                            mtu=dict(type="str", choices=[e.value for e in MtuEnum]),
                                            native_vlan=dict(type="int"),
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
                                            speed=dict(type="str", choices=[e.value for e in SpeedEnum]),
                                            storm_control=dict(type="bool"),
                                            storm_control_action=dict(type="str", choices=[e.value for e in StormControlActionEnum]),
                                            storm_control_broadcast_level=dict(type="float"),
                                            storm_control_broadcast_level_pps=dict(type="int"),
                                            storm_control_multicast_level=dict(type="float"),
                                            storm_control_multicast_level_pps=dict(type="int"),
                                            storm_control_unicast_level=dict(type="float"),
                                            storm_control_unicast_level_pps=dict(type="int"),
                                            vlan_mapping=dict(type="bool"),
                                            vlan_mapping_entries=dict(
                                                type="list",
                                                elements="dict",
                                                options=dict(
                                                    customer_inner_vlan_id=dict(type="int"),
                                                    customer_vlan_id=dict(type="list", elements="str"),
                                                    dot1q_tunnel=dict(type="bool"),
                                                    provider_vlan_id=dict(type="int"),
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
