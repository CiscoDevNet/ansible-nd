# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NX-OS Ethernet dot1q-tunnel host policy models for ND Manage Interfaces."""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ConfigDict, Field, ValidationInfo, field_validator, model_validator
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
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_common import (
    default_policy_type,
    normalize_ethernet_interface_name,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.policy_base import InterfacePolicyStrictBase
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.storm_control import StormControlMutexMixin
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import AsciiDescription

# A multi-field merge can temporarily hold both units before clearing the old
# traffic class. Suspend only this model's guard while prevalidating a copy and
# applying that validated merge; direct input/assignment stays strict.
_DOT1Q_STORM_MERGE: ContextVar[bool] = ContextVar("dot1q_storm_merge", default=False)


class EthernetDot1qTunnelHostPolicyModel(StormControlMutexMixin, InterfacePolicyStrictBase):
    """The NX-OS ``int_dot1q_tunnel_host`` template (``dot1qTunnelHost``)."""

    model_config = ConfigDict(extra="forbid")

    # ND echoes unset template defaults. In particular, dot1qTunnelHost uses
    # bpduFilter=enable, unlike accessHost's bpduFilter=default.
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        **InterfacePolicyStrictBase.reverse_diff_defaults,
        "bpduFilter": "enable",
        "bpduGuard": "enable",
        "cdp": True,
        "debounceTimer": 100,
        "duplexMode": "auto",
        "errorDetectionAcl": True,
        "fec": "auto",
        "linkType": "auto",
        "mtu": "jumbo",
        "negotiateAuto": True,
        "netflow": False,
        "orphanPort": False,
        "pfc": False,
        "portTypeEdgeTrunk": True,
        "qos": False,
        "speed": "auto",
        "stormControl": False,
        "stormControlAction": "default",
    }

    access_vlan: int | None = Field(default=None, alias="accessVlan", ge=1, le=4094)
    bandwidth: int | None = Field(default=None, alias="bandwidth", ge=1, le=100000000)
    bpdu_filter: BpduFilterEnum | None = Field(default=None, alias="bpduFilter")
    bpdu_guard: BpduGuardEnum | None = Field(default=None, alias="bpduGuard")
    cdp: bool | None = Field(default=None, alias="cdp")
    debounce_linkup_timer: int | None = Field(default=None, alias="debounceLinkupTimer", ge=1000, le=10000)
    debounce_timer: int | None = Field(default=None, alias="debounceTimer", ge=0, le=20000)
    description: AsciiDescription = Field(default=None, alias="description", max_length=254)
    duplex_mode: DuplexModeEnum | None = Field(default=None, alias="duplexMode")
    error_detection_acl: bool | None = Field(default=None, alias="errorDetectionAcl")
    extra_config: str | None = Field(default=None, alias="extraConfig")
    fec: FecEnum | None = Field(default=None, alias="fec")
    inherit_bandwidth: int | None = Field(default=None, alias="inheritBandwidth", ge=1, le=100000000)
    link_type: LinkTypeEnum | None = Field(default=None, alias="linkType")
    mtu: MtuEnum | None = Field(default=None, alias="mtu")
    negotiate_auto: bool | None = Field(default=None, alias="negotiateAuto")
    netflow: bool | None = Field(default=None, alias="netflow")
    netflow_monitor: str | None = Field(default=None, alias="netflowMonitor")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler")
    orphan_port: bool | None = Field(default=None, alias="orphanPort")
    pfc: bool | None = Field(default=None, alias="pfc")
    policy_type: Literal["dot1qTunnelHost"] = Field(alias="policyType")
    port_type_edge_trunk: bool | None = Field(default=None, alias="portTypeEdgeTrunk")
    qos: bool | None = Field(default=None, alias="qos")
    qos_policy: str | None = Field(default=None, alias="qosPolicy")
    queuing_policy: str | None = Field(default=None, alias="queuingPolicy")
    speed: SpeedEnum | None = Field(default=None, alias="speed")
    storm_control: bool | None = Field(default=None, alias="stormControl")
    storm_control_action: StormControlActionEnum | None = Field(default=None, alias="stormControlAction")
    storm_control_broadcast_level: float | None = Field(default=None, alias="stormControlBroadcastLevel", ge=0.0, le=100.0)
    storm_control_broadcast_level_pps: int | None = Field(default=None, alias="stormControlBroadcastLevelPps", ge=0, le=200000000)
    storm_control_multicast_level: float | None = Field(default=None, alias="stormControlMulticastLevel", ge=0.0, le=100.0)
    storm_control_multicast_level_pps: int | None = Field(default=None, alias="stormControlMulticastLevelPps", ge=0, le=200000000)
    storm_control_unicast_level: float | None = Field(default=None, alias="stormControlUnicastLevel", ge=0.0, le=100.0)
    storm_control_unicast_level_pps: int | None = Field(default=None, alias="stormControlUnicastLevelPps", ge=0, le=200000000)

    @model_validator(mode="before")
    @classmethod
    def default_dot1q_policy_type(cls, data: Any) -> Any:
        """Inject the one host policy supported by this module when omitted."""
        return default_policy_type(data, "dot1qTunnelHost")

    @model_validator(mode="after")
    def reject_interface_wide_mixed_storm_units(self, info: ValidationInfo) -> "EthernetDot1qTunnelHostPolicyModel":
        """Do not stage percentage and PPS thresholds on the same interface.

        ND may echo conflicting values on GET, so response parsing stays
        permissive. Proposed writes fail closed before sending a policy body.
        Zero is a clearing sentinel, not an active threshold.
        """
        if info.context and info.context.get("mode") == "response":
            return self
        if _DOT1Q_STORM_MERGE.get():
            return self
        percentages = (
            self.storm_control_broadcast_level,
            self.storm_control_multicast_level,
            self.storm_control_unicast_level,
        )
        packets_per_second = (
            self.storm_control_broadcast_level_pps,
            self.storm_control_multicast_level_pps,
            self.storm_control_unicast_level_pps,
        )
        if any(value not in (None, 0) for value in percentages) and any(value not in (None, 0) for value in packets_per_second):
            raise ValueError("storm-control percentage and PPS thresholds cannot be mixed across the interface")
        return self

    def has_mixed_storm_units(self) -> bool:
        """Detect a live ND echo with active percentage and PPS thresholds."""
        percentages = (self.storm_control_broadcast_level, self.storm_control_multicast_level, self.storm_control_unicast_level)
        pps = (self.storm_control_broadcast_level_pps, self.storm_control_multicast_level_pps, self.storm_control_unicast_level_pps)
        return any(value not in (None, 0) for value in percentages) and any(value not in (None, 0) for value in pps)

    def merge(self, other: NDBaseModel) -> NDBaseModel:
        """Fail before assignment or a write when ND already holds unsafe units."""
        if self.has_mixed_storm_units():
            raise ValueError(
                "ND returned both percentage and PPS storm-control thresholds on this dot1q host. "
                "A merged full-policy update could replay that conflict. Use state: replaced with one consistent "
                "threshold unit across the interface to correct it before merging other properties."
            )
        token = _DOT1Q_STORM_MERGE.set(True)
        try:
            candidate = self.model_copy(deep=True)
            # Preserve the shared mixin's per-class counterpart clearing, but
            # judge interface-wide units only after every requested field is set.
            super(EthernetDot1qTunnelHostPolicyModel, candidate).merge(other)
            if candidate.has_mixed_storm_units():
                raise ValueError(
                    "A merged dot1q host policy cannot mix percentage and PPS thresholds across the interface. "
                    "Explicitly clear existing thresholds from the other unit family."
                )
            return super().merge(other)
        finally:
            _DOT1Q_STORM_MERGE.reset(token)

    def merge_would_change(self, other: NDBaseModel) -> bool:
        """An explicit empty description clears a nonempty ND description."""
        if "description" in other.model_fields_set and other.description == "" and self.description not in (None, ""):
            return True
        return super().merge_would_change(other)


class EthernetDot1qTunnelHostNetworkOSModel(NDNestedModel):
    """NX-OS-only network-OS container for a dot1q tunnel host."""

    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType")
    policy: EthernetDot1qTunnelHostPolicyModel | None = Field(default=None, alias="policy")


class EthernetDot1qTunnelHostConfigDataModel(NDNestedModel):
    """ND ``configData`` with the dot1q-tunnel operational mode."""

    mode: Literal["dot1qTunnel"] = Field(default="dot1qTunnel", alias="mode", frozen=True)
    network_os: EthernetDot1qTunnelHostNetworkOSModel = Field(default_factory=EthernetDot1qTunnelHostNetworkOSModel, alias="networkOS")


class EthernetDot1qTunnelHostInterfaceModel(NDBaseModel):
    """Standalone NX-OS Ethernet dot1q-tunnel host configuration."""

    identifiers: ClassVar[list[str]] = ["switch_ip", "interface_name"]
    identifier_strategy: ClassVar[Literal["composite"]] = "composite"
    payload_exclude_fields: ClassVar[set[str]] = {"switch_ip"}

    switch_ip: str = Field(alias="switchIp")
    interface_name: str = Field(alias="interfaceName")
    interface_type: Literal["ethernet"] = Field(default="ethernet", alias="interfaceType", frozen=True)
    config_data: EthernetDot1qTunnelHostConfigDataModel | None = Field(default=None, alias="configData")

    @property
    def policy_type(self) -> str | None:
        """Return the managed policy discriminator, or None for identifier-only deletes."""
        if self.config_data is None or self.config_data.network_os.policy is None:
            return None
        return self.config_data.network_os.policy.policy_type

    def to_diff_dict(self, **kwargs) -> dict[str, Any]:
        """Treat empty and omitted descriptions as the same cleared state."""
        data = super().to_diff_dict(**kwargs)
        policy = ((data.get("configData") or {}).get("networkOS") or {}).get("policy") or {}
        if policy.get("description") == "":
            policy.pop("description")
        return data

    @field_validator("interface_name", mode="before")
    @classmethod
    def normalize_interface_name(cls, value: Any) -> Any:
        """Canonicalize Ethernet spelling for stable `(switch, interface)` identity."""
        return normalize_ethernet_interface_name(value)

    @classmethod
    def get_argument_spec(cls) -> dict:
        """Return grouped-name Ansible options for the standalone module."""
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
                                    network_os_type=dict(type="str", default="nx-os", choices=["nx-os"]),
                                    policy=dict(
                                        type="dict",
                                        options=dict(
                                            policy_type=dict(type="str", choices=["dot1qTunnelHost"]),
                                            admin_state=dict(type="bool"),
                                            access_vlan=dict(type="int"),
                                            bandwidth=dict(type="int"),
                                            bpdu_filter=dict(type="str", choices=[e.value for e in BpduFilterEnum]),
                                            bpdu_guard=dict(type="str", choices=[e.value for e in BpduGuardEnum]),
                                            cdp=dict(type="bool"),
                                            debounce_linkup_timer=dict(type="int"),
                                            debounce_timer=dict(type="int"),
                                            description=dict(type="str"),
                                            duplex_mode=dict(type="str", choices=[e.value for e in DuplexModeEnum]),
                                            error_detection_acl=dict(type="bool"),
                                            extra_config=dict(type="str"),
                                            fec=dict(type="str", choices=[e.value for e in FecEnum]),
                                            inherit_bandwidth=dict(type="int"),
                                            link_type=dict(type="str", choices=[e.value for e in LinkTypeEnum]),
                                            mtu=dict(type="str", choices=[e.value for e in MtuEnum]),
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
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            state=dict(type="str", default="merged", choices=["merged", "replaced", "overridden", "deleted"]),
        )
