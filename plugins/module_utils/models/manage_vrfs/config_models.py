# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Playbook-facing Pydantic models for VRF configuration.

Three models covering the three deployment topologies exposed by nd_manage_vrfs.py:

- ``VrfChildConfigModel``  — per-child-fabric override entry (nested, used
  inside ``VrfParentConfigModel``).
- ``VrfConfigModel``       — standalone fabric VRF config (full field set).
- ``VrfParentConfigModel`` — parent (MSD / MFD) fabric VRF config; carries
  identity + shared fields and a list of per-child overrides.

Cross-field parameter dependencies (l3vni_wo_vlan, TRM group, no_rp,
netflow, bgp_password) are enforced by ``@model_validator`` hooks.
"""

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.validators import (
    VrfValidators,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.enums import (
    DpuAffinity,
    VrfType,
)

_CUSTOM_VRF_TEMPLATE_FIELDS = (
    "service_vrf_template_name",
    "vrf_template_name",
    "vrf_extension_template_name",
    "vrf_template_config",
)

_USER_DEFINED_VRF_FIELDS = frozenset(
    {
        "vrf_name",
        "vrf_id",
        "vrf_type",
        "vlan_id",
        "default_security_action",
        "default_security_group_tag",
        "deploy",
        "deploy_type",
        "attach",
        *_CUSTOM_VRF_TEMPLATE_FIELDS,
    }
)


def _infer_user_defined_vrf_type(data):
    """Set the internal VRF discriminator when custom template fields are supplied."""
    if not isinstance(data, dict):
        return data
    normalized = dict(data)
    has_custom_template_fields = any(normalized.get(field) is not None for field in _CUSTOM_VRF_TEMPLATE_FIELDS)
    if has_custom_template_fields and not normalized.get("vrf_type"):
        normalized["vrf_type"] = VrfType.USER_DEFINED.value
    return normalized


# =============================================================================
# VrfAttachmentOptionsConfigModel — playbook-facing instance values
# =============================================================================


class VrfAttachmentOptionsConfigModel(NDNestedModel):
    """
    Playbook-facing VRF attachment instance values.

    These fields map to the Manage API ``instanceValues`` object.  The
    playbook-facing name is ``attachment_options`` to avoid exposing the API
    field name directly.
    """

    model_config = ConfigDict(extra="forbid")

    identifiers: ClassVar[list[str]] = []

    dpu_secure: bool | None = Field(
        default=None,
        description="Enable DPU secure mode for this attachment",
    )
    dpu_affinity: DpuAffinity | None = Field(
        default=None,
        description="DPU affinity for this attachment",
    )
    loopback_id: int | None = Field(
        default=None,
        ge=0,
        le=1023,
        description="Attachment loopback interface identifier (0-1023)",
    )
    loopback_ipv4_address: str | None = Field(
        default=None,
        description="Attachment loopback IPv4 address",
    )
    loopback_ipv6_address: str | None = Field(
        default=None,
        description="Attachment loopback IPv6 address",
    )
    import_vpn_rt: list[str] | None = Field(
        default=None,
        description="Attachment-level VPN import route targets",
    )
    export_vpn_rt: list[str] | None = Field(
        default=None,
        description="Attachment-level VPN export route targets",
    )
    import_evpn_rt: list[str] | None = Field(
        default=None,
        description="Attachment-level EVPN import route targets",
    )
    export_evpn_rt: list[str] | None = Field(
        default=None,
        description="Attachment-level EVPN export route targets",
    )

    @field_validator("loopback_ipv4_address", mode="before")
    @classmethod
    def _validate_ipv4(cls, v: str | None) -> str | None:
        return VrfValidators.validate_ipv4_address(v)

    @field_validator("loopback_ipv6_address", mode="before")
    @classmethod
    def _validate_ipv6(cls, v: str | None) -> str | None:
        return VrfValidators.validate_ipv6_address(v)

    @field_validator(
        "import_vpn_rt",
        "export_vpn_rt",
        "import_evpn_rt",
        "export_evpn_rt",
        mode="before",
    )
    @classmethod
    def _normalize_rt(cls, v: str | list[str] | None) -> list[str] | None:
        return VrfValidators.normalize_route_targets(v)


# =============================================================================
# VrfAttachmentConfigModel — playbook-facing VRF attachment entry
# =============================================================================


class VrfAttachmentConfigModel(NDNestedModel):
    """
    Playbook-facing VRF attachment entry.

    The public config accepts switch management IPs.  The workflow resolves
    those IPs to switchId values before sending the ND attachment payload.
    Optional attachment-specific settings live under ``attachment_options`` and
    are translated to API ``instanceValues`` internally.
    """

    model_config = ConfigDict(extra="forbid")

    identifiers: ClassVar[list[str]] = []

    ip_address: str = Field(
        description="Management IP address of the switch to attach this VRF to",
    )
    freeform_config: str | None = Field(
        default=None,
        description="Additional free-form CLI configuration mapped to API extraConfig",
    )
    attachment_options: VrfAttachmentOptionsConfigModel | None = Field(
        default=None,
        description="Attachment-specific options mapped to API instanceValues",
    )

    @field_validator("ip_address", mode="before")
    @classmethod
    def _validate_ip_address(cls, v: str | None) -> str | None:
        return VrfValidators.validate_ipv4_address(v)


# =============================================================================
# VrfChildConfigModel — per-child-fabric override entry
# =============================================================================


class VrfChildConfigModel(NDNestedModel):
    """
    Per-child-fabric override entry within a parent VRF config.

    Identifies a child fabric by name and provides optional per-fabric
    overrides for fabric-instance settings such as TRM, advertising,
    BGP authentication, netflow, and MVPN route-target settings.

    All fields except ``fabric_name`` are optional; absent fields retain the
    existing child setting on a sparse update.

    Based on: nd_manage_vrfs.py config.child_fabric_config suboptions
    """

    identifiers: ClassVar[list[str]] = []

    # --- Identity ---

    fabric_name: str = Field(
        description="Name of the child fabric",
    )

    # --- L3VNI without VLAN override ---

    l3vni_wo_vlan: bool | None = Field(
        default=None,
        alias="l3vniWoVlan",
        description="Enable L3VNI without VLAN on this child fabric",
    )
    bgp_best_path_relax: bool | None = Field(default=None, alias="bgpBestPathRelax")
    enable_vrf_vpn_route_leaking: bool | None = Field(default=None, alias="enableVrfVpnRouteLeaking")
    bgp_log_neighbor_change: bool | None = Field(default=None, alias="bgpLogNeighborChange")

    # --- TRM overrides ---

    trm_enable: bool | None = Field(
        default=None,
        alias="trmEnable",
        description="Enable Tenant Routed Multicast for this child fabric",
    )
    ipv6_trm: bool | None = Field(default=None, alias="ipv6Trm", description="Enable IPv6 TRM on this child fabric")
    no_rp: bool | None = Field(
        default=None,
        alias="noRp",
        description="No RP for TRM (SSM only); requires trm_enable=True",
    )
    rp_external: bool | None = Field(
        default=None,
        alias="rpExternal",
        description="RP is external to the fabric; requires trm_enable=True",
    )
    v6_no_rp: bool | None = Field(default=None, alias="v6RpAbsent", description="Use IPv6 SSM without an RP")
    v6_rp_external: bool | None = Field(default=None, alias="v6RpExternal", description="IPv6 RP is external to the fabric")
    rp_address: str | None = Field(
        default=None,
        alias="rpAddress",
        description="IPv4 RP address; requires trm_enable=True",
    )
    v6_rp_address: str | None = Field(default=None, alias="v6RpAddress", description="IPv6 RP address")
    rp_loopback_id: int | None = Field(
        default=None,
        alias="rpLoopbackId",
        ge=0,
        le=1023,
        description="Loopback interface ID for an internal IPv4 or IPv6 RP (0-1023)",
    )
    underlay_mcast_ip: str | None = Field(
        default=None,
        alias="underlayMcastIp",
        description="Underlay IPv4 multicast address; required for IPv4 or IPv6 TRM",
    )
    overlay_mcast_group: str | None = Field(
        default=None,
        alias="overlayMcastGroup",
        description=("Overlay multicast group IPv4 address (224.0.0.0/4 range); " "requires trm_enable=True"),
    )
    v6_overlay_mcast_group: str | None = Field(default=None, alias="v6MulticastGroup", description="IPv6 overlay multicast group")
    mvpn_inter_as: bool | None = Field(default=None, alias="mvpnInterAs", description="Enable MVPN inter-AS on IOS XE")
    trm_bgw_msite: bool | None = Field(
        default=None,
        alias="trmBgwMsite",
        description="Enable IPv4/IPv6 TRM on border gateway multisite",
    )
    import_mvpn_rt: list[str] | None = Field(
        default=None,
        alias="importMvpnRt",
        description="MVPN import route targets (comma-separated string or list); requires IPv4 or IPv6 TRM",
    )
    export_mvpn_rt: list[str] | None = Field(
        default=None,
        alias="exportMvpnRt",
        description="MVPN export route targets (comma-separated string or list); requires IPv4 or IPv6 TRM",
    )

    # --- Routing / advertising overrides ---

    adv_host_routes: bool | None = Field(
        default=None,
        alias="advHostRoutes",
        description="Advertise /32 and /128 host routes to edge routers",
    )
    adv_default_routes: bool | None = Field(
        default=None,
        alias="advDefaultRoutes",
        description="Advertise default route internally",
    )
    static_default_route: bool | None = Field(
        default=None,
        alias="staticDefaultRoute",
        description="Configure static default route",
    )

    # --- BGP authentication overrides ---

    bgp_password: str | None = Field(
        default=None,
        alias="bgpPassword",
        min_length=4,
        max_length=32,
        pattern=r"^[a-fA-F0-9]+$",
        description="Hexadecimal BGP neighbour password (4-32 characters)",
    )
    bgp_passwd_encrypt: str | None = Field(
        default=None,
        alias="bgpPasswdEncrypt",
        description="BGP password key type: 3des, type6, or type7; required with bgp_password",
    )
    bgp_allow_as_in: bool | None = Field(default=None, alias="bgpAllowAsIn")
    bgp_allow_as_in_num: int | None = Field(default=None, alias="bgpAllowAsInNum", ge=1, le=10)
    bgp_as_override: bool | None = Field(default=None, alias="bgpAsOverride")
    bgp_disable_peer_as_check: bool | None = Field(default=None, alias="bgpDisablePeerAsCheck")
    bgp_soft_reconfig_always: bool | None = Field(default=None, alias="bgpSoftReconfigAlways")

    # --- Netflow overrides ---

    netflow_enable: bool | None = Field(
        default=None,
        alias="netflowEnable",
        description="Enable netflow on VRF-Lite sub-interface",
    )
    nf_monitor: str | None = Field(
        default=None,
        alias="nfMonitor",
        description="Netflow monitor name; required when netflow_enable=True",
    )

    # ------------------------------------------------------------------
    # Field validators
    # ------------------------------------------------------------------

    @field_validator("rp_address", "underlay_mcast_ip", mode="before")
    @classmethod
    def _validate_ipv4(cls, v: str | None) -> str | None:
        return VrfValidators.validate_ipv4_address(v)

    @field_validator("v6_rp_address", mode="before")
    @classmethod
    def _validate_ipv6(cls, v: str | None) -> str | None:
        return VrfValidators.validate_ipv6_address(v)

    @field_validator("v6_overlay_mcast_group", mode="before")
    @classmethod
    def _validate_v6_mcast_group(cls, v: str | None) -> str | None:
        return VrfValidators.validate_cidrv6(v)

    @field_validator("overlay_mcast_group", mode="before")
    @classmethod
    def _validate_mcast_group(cls, v: str | None) -> str | None:
        return VrfValidators.validate_overlay_mcast_group(v)

    @field_validator("bgp_passwd_encrypt", mode="before")
    @classmethod
    def _validate_bgp_encrypt(cls, v: str | None) -> str | None:
        return VrfValidators.validate_bgp_passwd_encrypt(v)

    @field_validator(
        "import_mvpn_rt",
        "export_mvpn_rt",
        mode="before",
    )
    @classmethod
    def _normalize_rt(cls, v: str | list[str] | None) -> list[str] | None:
        return VrfValidators.normalize_route_targets(v)

    # ------------------------------------------------------------------
    # Cross-field validators
    # ------------------------------------------------------------------

    @model_validator(mode="after")
    def _check_trm_fields(self, info: ValidationInfo):
        """Validate the effective child TRM configuration after sparse merge."""
        context = info.context or {}
        supplied = set(context.get("supplied_fields", ()))
        trm_fields = {
            "trm_enable",
            "ipv6_trm",
            "no_rp",
            "rp_external",
            "rp_address",
            "v6_no_rp",
            "v6_rp_external",
            "v6_rp_address",
            "rp_loopback_id",
            "underlay_mcast_ip",
            "overlay_mcast_group",
            "v6_overlay_mcast_group",
            "trm_bgw_msite",
            "mvpn_inter_as",
            "import_mvpn_rt",
            "export_mvpn_rt",
        }
        if not context.get("validate_effective") or not supplied.intersection(trm_fields):
            return self
        for enabled, fields in (
            (self.trm_enable, ("no_rp", "rp_external", "rp_address", "overlay_mcast_group")),
            (self.ipv6_trm, ("v6_no_rp", "v6_rp_external", "v6_rp_address", "v6_overlay_mcast_group")),
        ):
            if enabled:
                continue
            active = [name for name in fields if getattr(self, name) not in (None, False, "", [])]
            if active:
                toggle = "trm_enable" if fields[0] == "no_rp" else "ipv6_trm"
                raise ValueError(f"{', '.join(active)} requires {toggle}=True on the child")
        if not (self.trm_enable or self.ipv6_trm):
            common = ("rp_loopback_id", "underlay_mcast_ip", "trm_bgw_msite", "mvpn_inter_as", "import_mvpn_rt", "export_mvpn_rt")
            active = [name for name in common if getattr(self, name) not in (None, False, "", [])]
            if active:
                raise ValueError(f"{', '.join(active)} requires trm_enable=True or ipv6_trm=True on the child")
            return self
        if not self.underlay_mcast_ip:
            raise ValueError("underlay_mcast_ip is required when TRM is enabled")
        for enabled, no_rp, external, address, family in (
            (self.trm_enable, self.no_rp, self.rp_external, self.rp_address, "IPv4"),
            (self.ipv6_trm, self.v6_no_rp, self.v6_rp_external, self.v6_rp_address, "IPv6"),
        ):
            if not enabled or no_rp:
                continue
            if not address:
                raise ValueError(f"{family} RP address is required when {family} TRM is enabled without SSM")
            if not external and self.rp_loopback_id is None:
                raise ValueError("rp_loopback_id is required for an internal TRM RP")
        return self

    @model_validator(mode="after")
    def _check_no_rp_fields(self, info: ValidationInfo):
        """Reject RP details for an SSM-only family."""
        context = info.context or {}
        supplied = set(context.get("supplied_fields", ()))
        if not context.get("validate_effective") or not supplied.intersection(
            {"trm_enable", "ipv6_trm", "no_rp", "v6_no_rp", "rp_external", "v6_rp_external", "rp_address", "v6_rp_address"}
        ):
            return self
        for absent, external, address, field in (
            (self.no_rp, self.rp_external, self.rp_address, "no_rp"),
            (self.v6_no_rp, self.v6_rp_external, self.v6_rp_address, "v6_no_rp"),
        ):
            if absent and (external or address):
                raise ValueError(f"RP settings are not applicable when {field}=True")
        return self

    @model_validator(mode="after")
    def _check_netflow_monitor(self, info: ValidationInfo):
        """Require a monitor on an enabled child VRF Lite sub-interface."""
        context = info.context or {}
        if not context.get("validate_effective") or not set(context.get("supplied_fields", ())).intersection({"netflow_enable", "nf_monitor"}):
            return self
        if self.netflow_enable is True and not self.nf_monitor:
            raise ValueError("nf_monitor is required when netflow_enable=True")
        if self.netflow_enable is False and self.nf_monitor:
            raise ValueError("nf_monitor requires netflow_enable=True")
        return self

    @model_validator(mode="after")
    def _check_bgp_password(self, info: ValidationInfo):
        """Keep the VRF Lite password and key type together."""
        context = info.context or {}
        supplied = set(context.get("supplied_fields", ()))
        if not context.get("validate_effective"):
            return self
        if supplied.intersection({"bgp_password", "bgp_passwd_encrypt"}):
            if self.bgp_password is not None and self.bgp_passwd_encrypt is None:
                raise ValueError("bgp_passwd_encrypt is required when bgp_password is set")
            if self.bgp_passwd_encrypt is not None and self.bgp_password is None:
                raise ValueError("bgp_password is required when bgp_passwd_encrypt is set")
        if "bgp_allow_as_in_num" in supplied and not self.bgp_allow_as_in:
            raise ValueError("bgp_allow_as_in_num requires bgp_allow_as_in=True")
        return self


# =============================================================================
# VrfConfigModel — standalone fabric VRF config (full field set)
# =============================================================================


class VrfConfigModel(NDBaseModel):
    """
    Playbook-facing VRF configuration model for standalone fabrics.

    Carries the full field set from nd_manage_vrfs.py for use against a single
    (standalone) fabric.  All cross-field dependencies are validated by
    ``@model_validator`` hooks.

    Based on: nd_manage_vrfs.py config suboptions (standalone topology)
    """

    identifiers: ClassVar[list[str] | None] = ["vrf_name"]
    identifier_strategy: ClassVar[str | None] = "single"

    # --- Identity ---

    vrf_name: str = Field(
        alias="vrfName",
        description=("Name of the VRF (max 94 chars; use tenant~vrfName for multi-tenant)"),
    )
    vrf_id: int | None = Field(
        default=None,
        alias="vrfId",
        ge=1,
        le=16777214,
        description="L3 VNI (VRF segment ID), 1–16777214",
    )
    vrf_type: str | None = Field(
        default=None,
        alias="vrfType",
        description=("VRF schema type. Leave unset to derive it from fabric " "management.type; set to userDefined for custom template VRFs"),
    )

    # --- Custom/user-defined VRF templates ---

    service_vrf_template_name: str | None = Field(
        default=None,
        alias="serviceVrfTemplateName",
        description="Service VRF template name for userDefined VRFs",
    )
    vrf_template_name: str | None = Field(
        default=None,
        alias="vrfTemplateName",
        description="VRF template name for userDefined VRFs",
    )
    vrf_extension_template_name: str | None = Field(
        default=None,
        alias="vrfExtensionTemplateName",
        description="VRF extension template name for userDefined VRFs",
    )
    vrf_template_config: dict[str, str] | None = Field(
        default=None,
        alias="vrfTemplateConfig",
        description=("Template parameter values for userDefined VRFs. Schema requires " "a JSON object with string values"),
    )

    # --- Security group ---

    default_security_action: Literal["unenforcedOrNone", "enforcedPermit", "enforcedDeny"] | None = Field(
        default=None,
        alias="defaultSecurityAction",
        description="Default security group enforcement action",
    )
    default_security_group_tag: int | None = Field(
        default=None,
        alias="defaultSecurityGroupTag",
        ge=16,
        le=65535,
        description="Default security group tag ID",
    )

    # --- VLAN / SVI ---

    vlan_id: int | None = Field(
        default=None,
        alias="vlanId",
        ge=2,
        le=4094,
        description=("VLAN ID for the VRF SVI (2–4094); " "not used when l3vni_wo_vlan=True"),
    )
    vrf_vlan_name: str | None = Field(
        default=None,
        alias="vrfVlanName",
        description=("VLAN name for the VRF SVI; not used when l3vni_wo_vlan=True"),
    )
    vrf_intf_desc: str | None = Field(
        default=None,
        alias="vrfIntfDesc",
        description=("Description for the VRF SVI interface; " "not used when l3vni_wo_vlan=True"),
    )
    vrf_int_mtu: int = Field(
        default=9216,
        alias="vrfIntMtu",
        ge=68,
        le=9216,
        description=("MTU for the VRF SVI interface (68–9216); " "not used when l3vni_wo_vlan=True"),
    )

    # --- L3VNI without VLAN ---

    l3vni_wo_vlan: bool | None = Field(
        default=None,
        alias="l3vniWoVlan",
        description=("Configure L3VNI without VLAN/SVI. When True, vlan_id, " "vrf_vlan_name, and vrf_intf_desc must not be set"),
    )

    # --- Description ---

    vrf_description: str | None = Field(
        default=None,
        alias="vrfDescription",
        max_length=255,
        description="Description of the VRF (max 255 characters)",
    )

    # --- Routing ---

    loopback_route_tag: int = Field(
        default=12345,
        alias="loopbackRouteTag",
        ge=0,
        le=4294967295,
        description="Routing tag for loopback routes (0–4294967295)",
    )
    redist_direct_rmap: str = Field(
        default="FABRIC-RMAP-REDIST-SUBNET",
        alias="redistDirectRmap",
        description="Route map name for redistribute direct (IPv4)",
    )
    v6_redist_direct_rmap: str | None = Field(
        default=None,
        alias="v6RedistDirectRmap",
        description="Route map name for redistribute direct (IPv6); defaults to the IPv4 route map",
    )
    max_bgp_paths: int = Field(
        default=1,
        alias="maxBgpPaths",
        ge=1,
        le=64,
        description="Maximum eBGP multipaths (1–64)",
    )
    max_ibgp_paths: int = Field(
        default=2,
        alias="maxIbgpPaths",
        ge=1,
        le=64,
        description="Maximum iBGP multipaths (1–64)",
    )
    ipv6_linklocal_enable: bool = Field(
        default=True,
        alias="ipv6LinkLocalEnable",
        description=("Enable IPv6 link-local on VRF SVI; " "not applicable when l3vni_wo_vlan=True"),
    )
    bgp_best_path_relax: bool = Field(
        default=False,
        alias="bgpBestPathRelax",
        description="Allow BGP multipath with different remote ASNs",
    )
    bgp_log_neighbor_change: bool = Field(
        default=False,
        alias="bgpLogNeighborChange",
        description="Log BGP neighbor up/down events",
    )
    route_distinguisher_id: int | None = Field(
        default=None,
        alias="routeDistinguisherId",
        ge=0,
        le=65535,
        description="VRF route distinguisher ID on IOS XE",
    )
    enable_vrf_vpn_route_leaking: bool = Field(
        default=False,
        alias="enableVrfVpnRouteLeaking",
        description="Enable bidirectional VRF-to-VPN route leaking on NX-OS border switches",
    )

    # --- Route targets ---

    disable_rt_auto: bool = Field(
        default=False,
        alias="disableRtAuto",
        description="Disable automatic route-target assignment",
    )
    import_vpn_rt: list[str] | None = Field(
        default=None,
        alias="importVpnRt",
        description="VPN import route targets (comma-separated string or list)",
    )
    export_vpn_rt: list[str] | None = Field(
        default=None,
        alias="exportVpnRt",
        description="VPN export route targets (comma-separated string or list)",
    )
    import_evpn_rt: list[str] | None = Field(
        default=None,
        alias="importEvpnRt",
        description="EVPN import route targets (comma-separated string or list)",
    )
    export_evpn_rt: list[str] | None = Field(
        default=None,
        alias="exportEvpnRt",
        description="EVPN export route targets (comma-separated string or list)",
    )

    # --- TRM ---

    trm_enable: bool = Field(
        default=False,
        alias="trmEnable",
        description="Enable Tenant Routed Multicast",
    )
    ipv6_trm: bool = Field(
        default=False,
        alias="ipv6Trm",
        description="Enable IPv6 Tenant Routed Multicast",
    )
    no_rp: bool = Field(
        default=False,
        alias="noRp",
        description="No RP for TRM (SSM only); requires trm_enable=True",
    )
    rp_external: bool = Field(
        default=False,
        alias="rpExternal",
        description="RP is external to the fabric; requires trm_enable=True",
    )
    rp_address: str | None = Field(
        default=None,
        alias="rpAddress",
        description="IPv4 RP address; requires trm_enable=True",
    )
    v6_no_rp: bool = Field(
        default=False,
        alias="v6NoRp",
        description="Use IPv6 SSM without an RP; requires ipv6_trm=True",
    )
    v6_rp_external: bool = Field(
        default=False,
        alias="v6RpExternal",
        description="IPv6 RP is external to the fabric; requires ipv6_trm=True",
    )
    v6_rp_address: str | None = Field(
        default=None,
        alias="v6RpAddress",
        description="IPv6 RP address; requires ipv6_trm=True",
    )
    rp_loopback_id: int | None = Field(
        default=None,
        alias="rpLoopbackId",
        ge=0,
        le=1023,
        description=("Loopback interface ID for RP (0–1023); requires trm_enable=True"),
    )
    underlay_mcast_ip: str | None = Field(
        default=None,
        alias="underlayMcastIp",
        description=("Underlay IPv4 multicast address; requires trm_enable=True"),
    )
    overlay_mcast_group: str | None = Field(
        default=None,
        alias="overlayMcastGroup",
        description=("Overlay multicast group IPv4 address (224.0.0.0/4 range); " "requires trm_enable=True"),
    )
    v6_overlay_mcast_group: str | None = Field(
        default=None,
        alias="v6OverlayMcastGroup",
        description="Overlay IPv6 multicast group/prefix; requires ipv6_trm=True",
    )
    mvpn_inter_as: bool = Field(
        default=False,
        alias="mvpnInterAs",
        description="Use inter-AS MVPN routes when TRM is enabled (IOS XE)",
    )
    trm_bgw_msite: bool = Field(
        default=False,
        alias="trmBgwMsite",
        description=("Enable TRM on border gateway multisite; requires trm_enable=True"),
    )
    import_mvpn_rt: list[str] | None = Field(
        default=None,
        alias="importMvpnRt",
        description=("MVPN import route targets (comma-separated string or list); " "requires trm_enable=True"),
    )
    export_mvpn_rt: list[str] | None = Field(
        default=None,
        alias="exportMvpnRt",
        description=("MVPN export route targets (comma-separated string or list); " "requires trm_enable=True"),
    )

    # --- Advertising ---

    adv_host_routes: bool = Field(
        default=False,
        alias="advHostRoutes",
        description="Advertise /32 and /128 host routes to edge routers",
    )
    adv_default_routes: bool = Field(
        default=True,
        alias="advDefaultRoutes",
        description="Advertise default route internally",
    )
    static_default_route: bool = Field(
        default=True,
        alias="staticDefaultRoute",
        description="Configure static default route",
    )
    bgp_allow_as_in: bool = Field(
        default=False,
        alias="bgpAllowAsIn",
        description="Allow the local AS in received VRF Lite paths",
    )
    bgp_allow_as_in_num: int = Field(
        default=3,
        alias="bgpAllowAsInNum",
        ge=1,
        le=10,
        description="Allowed local-AS occurrences",
    )
    bgp_as_override: bool = Field(
        default=False,
        alias="bgpAsOverride",
        description="Override matching AS on outbound VRF Lite routes",
    )
    bgp_disable_peer_as_check: bool = Field(
        default=False,
        alias="bgpDisablePeerAsCheck",
        description="Disable peer-AS check on outbound VRF Lite routes",
    )
    bgp_soft_reconfig_always: bool = Field(
        default=False,
        alias="bgpSoftReconfigAlways",
        description="Always permit inbound BGP soft reconfiguration",
    )

    # --- BGP authentication ---

    bgp_password: str | None = Field(
        default=None,
        alias="bgpPassword",
        min_length=4,
        max_length=32,
        pattern=r"^[a-fA-F0-9]+$",
        description="Hexadecimal BGP neighbour password (4-32 characters)",
    )
    bgp_passwd_encrypt: str | None = Field(
        default=None,
        alias="bgpPasswdEncrypt",
        description="BGP password key type: 3des, type6, or type7; required with bgp_password",
    )

    # --- Netflow ---

    netflow_enable: bool = Field(
        default=False,
        alias="netflowEnable",
        description="Enable netflow on VRF-Lite sub-interface",
    )
    nf_monitor: str | None = Field(
        default=None,
        alias="nfMonitor",
        description="Netflow monitor name; required when netflow_enable=True",
    )

    # --- Attachment / deploy controls ---

    deploy: bool = Field(
        default=True,
        description="Deploy VRF attachment changes for this VRF",
    )
    deploy_type: str = Field(
        default="switch",
        alias="deployType",
        description=(
            "Deploy scope for pending VRF attachment changes. Use 'switch' "
            "to deploy only affected switches, or 'vrf' to deploy the VRF "
            "across all pending switches."
        ),
    )
    attach: list[VrfAttachmentConfigModel] | None = Field(
        default=None,
        description="Switch attachment entries for this VRF",
    )

    # ------------------------------------------------------------------
    # Field validators
    # ------------------------------------------------------------------

    @model_validator(mode="before")
    @classmethod
    def _infer_user_defined_type(cls, data):
        """Infer the internal user-defined discriminator for template configs."""
        return _infer_user_defined_vrf_type(data)

    @field_validator("vrf_name", mode="before")
    @classmethod
    def _validate_vrf_name(cls, v: str) -> str:
        return VrfValidators.require_vrf_name(v)

    @field_validator("vrf_type", mode="before")
    @classmethod
    def _validate_vrf_type(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = str(v).strip()
        if v not in VrfType.choices():
            raise ValueError(f"vrf_type must be one of {VrfType.choices()}, got: {v}")
        return v

    @field_validator("deploy_type", mode="before")
    @classmethod
    def _validate_deploy_type(cls, v: str | None) -> str:
        if v is None:
            return "switch"
        v = str(v).strip()
        if v not in ("switch", "vrf"):
            raise ValueError("deploy_type must be one of ['switch', 'vrf']")
        return v

    @field_validator("vrf_template_config", mode="before")
    @classmethod
    def _validate_vrf_template_config(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        if v is None:
            return None
        if not isinstance(v, dict):
            raise ValueError("vrf_template_config must be a dictionary")
        bad = [key for key, value in v.items() if not isinstance(value, str)]
        if bad:
            raise ValueError("vrf_template_config values must be strings for keys: " f"{', '.join(str(key) for key in bad)}")
        return v

    @field_validator("vrf_vlan_name", mode="before")
    @classmethod
    def _validate_vrf_vlan_name(cls, v: str | None) -> str | None:
        return VrfValidators.validate_vrf_vlan_name(v)

    @field_validator("rp_address", "underlay_mcast_ip", mode="before")
    @classmethod
    def _validate_ipv4(cls, v: str | None) -> str | None:
        return VrfValidators.validate_ipv4_address(v)

    @field_validator("overlay_mcast_group", mode="before")
    @classmethod
    def _validate_mcast_group(cls, v: str | None) -> str | None:
        return VrfValidators.validate_overlay_mcast_group(v)

    @field_validator("v6_rp_address", mode="before")
    @classmethod
    def _validate_v6_rp_address(cls, v: str | None) -> str | None:
        return VrfValidators.validate_ipv6_address(v)

    @field_validator("v6_overlay_mcast_group", mode="before")
    @classmethod
    def _validate_v6_mcast_group(cls, v: str | None) -> str | None:
        return VrfValidators.validate_cidrv6(v)

    @field_validator("bgp_passwd_encrypt", mode="before")
    @classmethod
    def _validate_bgp_encrypt(cls, v: str | None) -> str | None:
        return VrfValidators.validate_bgp_passwd_encrypt(v)

    @field_validator(
        "import_vpn_rt",
        "export_vpn_rt",
        "import_evpn_rt",
        "export_evpn_rt",
        "import_mvpn_rt",
        "export_mvpn_rt",
        mode="before",
    )
    @classmethod
    def _normalize_rt(cls, v: str | list[str] | None) -> list[str] | None:
        return VrfValidators.normalize_route_targets(v)

    # ------------------------------------------------------------------
    # Cross-field validators
    # ------------------------------------------------------------------

    @model_validator(mode="after")
    def _check_l3vni_wo_vlan(self, info: ValidationInfo):
        """When l3vni_wo_vlan=True, VLAN/SVI fields must not be set."""
        if (info.context or {}).get("defer_dependencies"):
            return self
        if self.l3vni_wo_vlan:
            vlan_fields = {
                "vlan_id": self.vlan_id,
                "vrf_vlan_name": self.vrf_vlan_name,
                "vrf_intf_desc": self.vrf_intf_desc,
            }
            set_fields = [k for k, v in vlan_fields.items() if v is not None]
            if "vrf_int_mtu" in self.model_fields_set:
                set_fields.append("vrf_int_mtu")
            if "ipv6_linklocal_enable" in self.model_fields_set:
                set_fields.append("ipv6_linklocal_enable")
            if set_fields:
                raise ValueError(f"The following fields must not be set when " f"l3vni_wo_vlan=True: {', '.join(set_fields)}")
        return self

    @model_validator(mode="after")
    def _check_custom_vrf_template_fields(self, info: ValidationInfo):
        """Custom template fields are valid only for vrf_type=userDefined."""
        set_fields = [field for field in _CUSTOM_VRF_TEMPLATE_FIELDS if getattr(self, field) is not None]
        if set_fields and self.vrf_type != VrfType.USER_DEFINED.value:
            raise ValueError("The following fields require vrf_type=userDefined: " f"{', '.join(set_fields)}")
        if self.vrf_type == VrfType.USER_DEFINED.value and (info.context or {}).get("state") not in ("gathered", "deleted"):
            unsupported = sorted(self.model_fields_set - _USER_DEFINED_VRF_FIELDS)
            if unsupported:
                raise ValueError(f"The following fields are not supported for userDefined VRFs: {', '.join(unsupported)}")
        return self

    @model_validator(mode="after")
    def _check_trm_fields(self, info: ValidationInfo):
        """Forbid family-specific TRM fields without their enablement."""
        if (info.context or {}).get("defer_dependencies"):
            return self
        if not self.trm_enable:
            trm_fields = {
                "no_rp": self.no_rp or None,
                "rp_external": self.rp_external or None,
                "rp_address": self.rp_address,
                "overlay_mcast_group": self.overlay_mcast_group,
            }
            set_fields = [k for k, v in trm_fields.items() if v is not None]
            if set_fields:
                raise ValueError(f"The following fields require trm_enable=True: " f"{', '.join(set_fields)}")
        if not self.ipv6_trm:
            v6_fields = {
                "v6_no_rp": self.v6_no_rp or None,
                "v6_rp_external": self.v6_rp_external or None,
                "v6_rp_address": self.v6_rp_address,
                "v6_overlay_mcast_group": self.v6_overlay_mcast_group,
            }
            set_fields = [key for key, value in v6_fields.items() if value is not None]
            if set_fields:
                raise ValueError(f"The following fields require ipv6_trm=True: {', '.join(set_fields)}")
        if not (self.trm_enable or self.ipv6_trm):
            common_fields = {
                "rp_loopback_id": self.rp_loopback_id,
                "underlay_mcast_ip": self.underlay_mcast_ip,
                "trm_bgw_msite": self.trm_bgw_msite or None,
                "mvpn_inter_as": self.mvpn_inter_as or None,
                "import_mvpn_rt": self.import_mvpn_rt,
                "export_mvpn_rt": self.export_mvpn_rt,
            }
            set_fields = [key for key, value in common_fields.items() if value is not None]
            if set_fields:
                raise ValueError(f"The following fields require trm_enable=True or ipv6_trm=True: {', '.join(set_fields)}")
        return self

    @model_validator(mode="after")
    def _check_no_rp_fields(self, info: ValidationInfo):
        """An SSM-only family cannot also configure an RP."""
        if (info.context or {}).get("defer_dependencies"):
            return self
        if self.no_rp:
            bad = {}
            if self.rp_external:
                bad["rp_external"] = self.rp_external
            if self.rp_address is not None:
                bad["rp_address"] = self.rp_address
            if bad:
                raise ValueError(f"The following fields are not applicable when no_rp=True: " f"{', '.join(bad.keys())}")
        if self.v6_no_rp:
            bad = [
                name
                for name, value in (
                    ("v6_rp_external", self.v6_rp_external),
                    ("v6_rp_address", self.v6_rp_address),
                )
                if value
            ]
            if bad:
                raise ValueError(f"The following fields are not applicable when v6_no_rp=True: {', '.join(bad)}")
        return self

    @model_validator(mode="after")
    def _check_netflow_monitor(self, info: ValidationInfo):
        """Require nf_monitor when netflow_enable=True."""
        if (info.context or {}).get("defer_dependencies"):
            return self
        if self.netflow_enable and not self.nf_monitor:
            raise ValueError("nf_monitor is required when netflow_enable=True")
        return self

    @model_validator(mode="after")
    def _check_bgp_password(self, info: ValidationInfo):
        """Only allow a key type together with a password."""
        if (info.context or {}).get("defer_dependencies"):
            return self
        if self.bgp_password is not None and self.bgp_passwd_encrypt is None:
            raise ValueError("bgp_passwd_encrypt is required when bgp_password is set")
        if self.bgp_passwd_encrypt is not None and self.bgp_password is None:
            raise ValueError("bgp_password is required when bgp_passwd_encrypt is set")
        return self


# =============================================================================
# VrfParentConfigModel — parent (MSD / MFD) fabric VRF config
# =============================================================================

PARENT_CHILD_ONLY_VRF_FIELDS = (
    "l3vni_wo_vlan",
    "bgp_best_path_relax",
    "enable_vrf_vpn_route_leaking",
    "bgp_log_neighbor_change",
    "trm_enable",
    "ipv6_trm",
    "no_rp",
    "rp_external",
    "rp_address",
    "v6_no_rp",
    "v6_rp_external",
    "v6_rp_address",
    "rp_loopback_id",
    "underlay_mcast_ip",
    "overlay_mcast_group",
    "v6_overlay_mcast_group",
    "mvpn_inter_as",
    "trm_bgw_msite",
    "import_mvpn_rt",
    "export_mvpn_rt",
    "adv_host_routes",
    "adv_default_routes",
    "static_default_route",
    "bgp_password",
    "bgp_passwd_encrypt",
    "bgp_allow_as_in",
    "bgp_allow_as_in_num",
    "bgp_as_override",
    "bgp_disable_peer_as_check",
    "bgp_soft_reconfig_always",
    "netflow_enable",
    "nf_monitor",
)


class VrfParentConfigModel(NDBaseModel):
    """
    Playbook-facing VRF configuration model for parent (MSD / MFD) fabrics.

    Carries identity, template, and shared VRF properties. Per-fabric
    advertising, BGP-auth, netflow, TRM, and MVPN route-target overrides belong in
    ``child_fabric_config`` entries (``VrfChildConfigModel``).

    Parent input excludes child-owned fabric-instance settings; the nested
    child model validates those settings separately.

    Based on: nd_manage_vrfs.py config suboptions (parent / MSD topology)
    """

    identifiers: ClassVar[list[str] | None] = ["vrf_name"]
    identifier_strategy: ClassVar[str | None] = "single"

    # --- Identity ---

    vrf_name: str = Field(
        alias="vrfName",
        description=("Name of the VRF (max 94 chars; use tenant~vrfName for multi-tenant)"),
    )
    vrf_id: int | None = Field(
        default=None,
        alias="vrfId",
        ge=1,
        le=16777214,
        description="L3 VNI (VRF segment ID), 1–16777214",
    )
    vrf_type: str | None = Field(
        default=None,
        alias="vrfType",
        description=("VRF schema type. Leave unset to derive it from fabric " "management.type; set to userDefined for custom template VRFs"),
    )

    # --- Custom/user-defined VRF templates ---

    service_vrf_template_name: str | None = Field(
        default=None,
        alias="serviceVrfTemplateName",
        description="Service VRF template name for userDefined VRFs",
    )
    vrf_template_name: str | None = Field(
        default=None,
        alias="vrfTemplateName",
        description="VRF template name for userDefined VRFs",
    )
    vrf_extension_template_name: str | None = Field(
        default=None,
        alias="vrfExtensionTemplateName",
        description="VRF extension template name for userDefined VRFs",
    )
    vrf_template_config: dict[str, str] | None = Field(
        default=None,
        alias="vrfTemplateConfig",
        description=("Template parameter values for userDefined VRFs. Schema requires " "a JSON object with string values"),
    )

    # --- Security group ---

    default_security_action: Literal["unenforcedOrNone", "enforcedPermit", "enforcedDeny"] | None = Field(
        default=None,
        alias="defaultSecurityAction",
        description="Default security group enforcement action",
    )
    default_security_group_tag: int | None = Field(
        default=None,
        alias="defaultSecurityGroupTag",
        ge=16,
        le=65535,
        description="Default security group tag ID",
    )

    # --- VLAN / SVI ---

    vlan_id: int | None = Field(
        default=None,
        alias="vlanId",
        ge=2,
        le=4094,
        description="VLAN ID for the VRF SVI (2-4094)",
    )
    vrf_vlan_name: str | None = Field(
        default=None,
        alias="vrfVlanName",
        description="VLAN name for the VRF SVI",
    )
    vrf_intf_desc: str | None = Field(
        default=None,
        alias="vrfIntfDesc",
        description="Description for the VRF SVI interface",
    )
    vrf_int_mtu: int = Field(
        default=9216,
        alias="vrfIntMtu",
        ge=68,
        le=9216,
        description="MTU for the VRF SVI interface (68-9216)",
    )

    # --- L3VNI without VLAN ---

    l3vni_wo_vlan: bool | None = Field(
        default=None,
        alias="l3vniWoVlan",
        description=("Configure L3VNI without VLAN/SVI across all member fabrics"),
    )

    # --- Description ---

    vrf_description: str | None = Field(
        default=None,
        alias="vrfDescription",
        max_length=255,
        description="Description of the VRF (max 255 characters)",
    )

    # --- Routing ---

    loopback_route_tag: int = Field(
        default=12345,
        alias="loopbackRouteTag",
        ge=0,
        le=4294967295,
        description="Routing tag for loopback routes (0–4294967295)",
    )
    redist_direct_rmap: str = Field(
        default="FABRIC-RMAP-REDIST-SUBNET",
        alias="redistDirectRmap",
        description="Route map name for redistribute direct (IPv4)",
    )
    v6_redist_direct_rmap: str = Field(
        default="FABRIC-RMAP-REDIST-SUBNET",
        alias="v6RedistDirectRmap",
        description="Route map name for redistribute direct (IPv6)",
    )
    max_bgp_paths: int = Field(
        default=1,
        alias="maxBgpPaths",
        ge=1,
        le=64,
        description="Maximum eBGP multipaths (1–64)",
    )
    max_ibgp_paths: int = Field(
        default=2,
        alias="maxIbgpPaths",
        ge=1,
        le=64,
        description="Maximum iBGP multipaths (1–64)",
    )
    ipv6_linklocal_enable: bool = Field(
        default=True,
        alias="ipv6LinkLocalEnable",
        description="Enable IPv6 link-local on VRF SVI",
    )
    route_distinguisher_id: int | None = Field(
        default=None,
        alias="routeDistinguisherId",
        ge=0,
        le=65535,
        description="VRF route distinguisher ID on IOS XE; generated when omitted",
    )

    # --- Route targets ---

    disable_rt_auto: bool = Field(
        default=False,
        alias="disableRtAuto",
        description="Disable automatic route-target assignment",
    )
    import_vpn_rt: list[str] | None = Field(
        default=None,
        alias="importVpnRt",
        description="VPN import route targets (comma-separated string or list)",
    )
    export_vpn_rt: list[str] | None = Field(
        default=None,
        alias="exportVpnRt",
        description="VPN export route targets (comma-separated string or list)",
    )
    import_evpn_rt: list[str] | None = Field(
        default=None,
        alias="importEvpnRt",
        description="EVPN import route targets (comma-separated string or list)",
    )
    export_evpn_rt: list[str] | None = Field(
        default=None,
        alias="exportEvpnRt",
        description="EVPN export route targets (comma-separated string or list)",
    )

    # --- TRM ---

    trm_enable: bool = Field(
        default=False,
        alias="trmEnable",
        description="Enable Tenant Routed Multicast",
    )
    no_rp: bool = Field(
        default=False,
        alias="noRp",
        description="No RP for TRM (SSM only); requires trm_enable=True",
    )
    rp_external: bool = Field(
        default=False,
        alias="rpExternal",
        description="RP is external to the fabric; requires trm_enable=True",
    )
    rp_address: str | None = Field(
        default=None,
        alias="rpAddress",
        description="IPv4 RP address; requires trm_enable=True",
    )
    rp_loopback_id: int | None = Field(
        default=None,
        alias="rpLoopbackId",
        ge=0,
        le=1023,
        description=("Loopback interface ID for RP (0–1023); requires trm_enable=True"),
    )
    underlay_mcast_ip: str | None = Field(
        default=None,
        alias="underlayMcastIp",
        description=("Underlay IPv4 multicast address; requires trm_enable=True"),
    )
    overlay_mcast_group: str | None = Field(
        default=None,
        alias="overlayMcastGroup",
        description=("Overlay multicast group IPv4 address (224.0.0.0/4 range); " "requires trm_enable=True"),
    )
    trm_bgw_msite: bool = Field(
        default=False,
        alias="trmBgwMsite",
        description=("Enable TRM on border gateway multisite; requires trm_enable=True"),
    )
    import_mvpn_rt: list[str] | None = Field(
        default=None,
        alias="importMvpnRt",
        description=("MVPN import route targets (comma-separated string or list); " "requires trm_enable=True"),
    )
    export_mvpn_rt: list[str] | None = Field(
        default=None,
        alias="exportMvpnRt",
        description=("MVPN export route targets (comma-separated string or list); " "requires trm_enable=True"),
    )

    # --- Advertising ---

    adv_host_routes: bool = Field(
        default=False,
        alias="advHostRoutes",
        description="Advertise /32 and /128 host routes to edge routers",
    )
    adv_default_routes: bool = Field(
        default=True,
        alias="advDefaultRoutes",
        description="Advertise default route internally",
    )
    static_default_route: bool = Field(
        default=True,
        alias="staticDefaultRoute",
        description="Configure static default route",
    )

    # --- BGP authentication ---

    bgp_password: str | None = Field(
        default=None,
        alias="bgpPassword",
        min_length=4,
        max_length=32,
        description="BGP neighbour password (4–32 characters)",
    )
    bgp_passwd_encrypt: str | None = Field(
        default=None,
        alias="bgpPasswdEncrypt",
        description="BGP password key type: 3des, type6, or type7; required with bgp_password",
    )

    # --- Netflow ---

    netflow_enable: bool = Field(
        default=False,
        alias="netflowEnable",
        description="Enable netflow on VRF-Lite sub-interface",
    )
    nf_monitor: str | None = Field(
        default=None,
        alias="nfMonitor",
        description="Netflow monitor name; required when netflow_enable=True",
    )

    # --- Child fabric configs ---

    child_fabric_config: list[VrfChildConfigModel] | None = Field(
        default=None,
        alias="childFabricConfig",
        description=("Per-child-fabric override entries for multisite / multicluster " "deployments"),
    )
    deploy: bool = Field(
        default=True,
        description=("Deploy parent VRF attachment changes once after all child fabric " "tasks complete"),
    )
    deploy_type: str = Field(
        default="switch",
        alias="deployType",
        description=(
            "Deploy scope for parent VRF attachment changes. Use 'switch' "
            "to deploy only affected switches, or 'vrf' to deploy the VRF "
            "across all pending switches."
        ),
    )
    attach: list[VrfAttachmentConfigModel] | None = Field(
        default=None,
        description="Parent-level switch attachment entries for this VRF",
    )

    # ------------------------------------------------------------------
    # Field validators
    # ------------------------------------------------------------------

    @model_validator(mode="before")
    @classmethod
    def _validate_child_only_top_level_fields(cls, data, info: ValidationInfo):
        """Reject misplaced child options in writes; ignore them in selectors.

        ## Raises

        ### ValueError

        - A child-only property is supplied at parent scope for a write.
        """
        if not isinstance(data, dict):
            return data
        filtered = dict(data)
        misplaced = []
        for field in PARENT_CHILD_ONLY_VRF_FIELDS:
            value = filtered.pop(field, None)
            alias_value = filtered.pop(VrfChildConfigModel.model_fields[field].alias, None)
            if value is not None or alias_value is not None:
                misplaced.append(field)
        if misplaced and (info.context or {}).get("state") not in ("gathered", "deleted"):
            raise ValueError("Child-only properties must be set under child_fabric_config on parent fabrics: " + ", ".join(misplaced))
        return filtered

    @model_validator(mode="before")
    @classmethod
    def _infer_user_defined_type(cls, data):
        """Infer the internal user-defined discriminator for template configs."""
        return _infer_user_defined_vrf_type(data)

    @field_validator("vrf_name", mode="before")
    @classmethod
    def _validate_vrf_name(cls, v: str) -> str:
        return VrfValidators.require_vrf_name(v)

    @field_validator("vrf_type", mode="before")
    @classmethod
    def _validate_vrf_type(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = str(v).strip()
        if v not in VrfType.choices():
            raise ValueError(f"vrf_type must be one of {VrfType.choices()}, got: {v}")
        return v

    @field_validator("deploy_type", mode="before")
    @classmethod
    def _validate_deploy_type(cls, v: str | None) -> str:
        if v is None:
            return "switch"
        v = str(v).strip()
        if v not in ("switch", "vrf"):
            raise ValueError("deploy_type must be one of ['switch', 'vrf']")
        return v

    @field_validator("vrf_template_config", mode="before")
    @classmethod
    def _validate_vrf_template_config(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        if v is None:
            return None
        if not isinstance(v, dict):
            raise ValueError("vrf_template_config must be a dictionary")
        bad = [key for key, value in v.items() if not isinstance(value, str)]
        if bad:
            raise ValueError("vrf_template_config values must be strings for keys: " f"{', '.join(str(key) for key in bad)}")
        return v

    @field_validator("vrf_vlan_name", mode="before")
    @classmethod
    def _validate_vrf_vlan_name(cls, v: str | None) -> str | None:
        return VrfValidators.validate_vrf_vlan_name(v)

    @field_validator("rp_address", "underlay_mcast_ip", mode="before")
    @classmethod
    def _validate_ipv4(cls, v: str | None) -> str | None:
        return VrfValidators.validate_ipv4_address(v)

    @field_validator("overlay_mcast_group", mode="before")
    @classmethod
    def _validate_mcast_group(cls, v: str | None) -> str | None:
        return VrfValidators.validate_overlay_mcast_group(v)

    @field_validator("bgp_passwd_encrypt", mode="before")
    @classmethod
    def _validate_bgp_encrypt(cls, v: str | None) -> str | None:
        return VrfValidators.validate_bgp_passwd_encrypt(v)

    @field_validator(
        "import_vpn_rt",
        "export_vpn_rt",
        "import_evpn_rt",
        "export_evpn_rt",
        "import_mvpn_rt",
        "export_mvpn_rt",
        mode="before",
    )
    @classmethod
    def _normalize_rt(cls, v: str | list[str] | None) -> list[str] | None:
        return VrfValidators.normalize_route_targets(v)

    # ------------------------------------------------------------------
    # Cross-field validators
    # ------------------------------------------------------------------

    @model_validator(mode="after")
    def _check_l3vni_wo_vlan(self):
        """When l3vni_wo_vlan=True, VLAN/SVI fields must not be set."""
        if self.l3vni_wo_vlan:
            vlan_fields = {
                "vlan_id": self.vlan_id,
                "vrf_vlan_name": self.vrf_vlan_name,
                "vrf_intf_desc": self.vrf_intf_desc,
            }
            set_fields = [k for k, v in vlan_fields.items() if v is not None]
            if set_fields:
                raise ValueError(f"The following fields must not be set when " f"l3vni_wo_vlan=True: {', '.join(set_fields)}")
        return self

    @model_validator(mode="after")
    def _check_trm_fields(self):
        """Forbid TRM-dependent fields when trm_enable=False."""
        if not self.trm_enable:
            trm_fields = {
                "no_rp": self.no_rp or None,
                "rp_external": self.rp_external or None,
                "rp_address": self.rp_address,
                "rp_loopback_id": self.rp_loopback_id,
                "underlay_mcast_ip": self.underlay_mcast_ip,
                "overlay_mcast_group": self.overlay_mcast_group,
                "trm_bgw_msite": self.trm_bgw_msite or None,
                "import_mvpn_rt": self.import_mvpn_rt,
                "export_mvpn_rt": self.export_mvpn_rt,
            }
            set_fields = [k for k, v in trm_fields.items() if v is not None]
            if set_fields:
                raise ValueError(f"The following fields require trm_enable=True: " f"{', '.join(set_fields)}")
        return self

    @model_validator(mode="after")
    def _check_netflow_monitor(self):
        """Require nf_monitor when netflow_enable=True."""
        if self.netflow_enable and not self.nf_monitor:
            raise ValueError("nf_monitor is required when netflow_enable=True")
        return self

    @model_validator(mode="after")
    def _check_bgp_password(self):
        """Require bgp_passwd_encrypt when bgp_password is set."""
        if self.bgp_password is not None and self.bgp_passwd_encrypt is None:
            raise ValueError("bgp_passwd_encrypt is required when bgp_password is set")
        return self

    @model_validator(mode="after")
    def _check_custom_vrf_template_fields(self):
        """Custom template fields are valid only for vrf_type=userDefined."""
        set_fields = [field for field in _CUSTOM_VRF_TEMPLATE_FIELDS if getattr(self, field) is not None]
        if set_fields and self.vrf_type != VrfType.USER_DEFINED.value:
            raise ValueError("The following fields require vrf_type=userDefined: " f"{', '.join(set_fields)}")
        return self

    @model_validator(mode="after")
    def _check_no_rp_fields(self):
        """Forbid rp_external and rp_address when no_rp=True."""
        if self.no_rp:
            bad = {}
            if self.rp_external:
                bad["rp_external"] = self.rp_external
            if self.rp_address is not None:
                bad["rp_address"] = self.rp_address
            if bad:
                raise ValueError(f"The following fields are not applicable when no_rp=True: " f"{', '.join(bad.keys())}")
        return self
