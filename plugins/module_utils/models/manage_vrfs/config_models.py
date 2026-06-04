# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Playbook-facing Pydantic models for VRF configuration.

Three models covering the three deployment topologies exposed by nd_vrf.py:

- ``VrfChildConfigModel``  — per-child-fabric override entry (nested, used
  inside ``VrfParentConfigModel``).
- ``VrfConfigModel``       — standalone fabric VRF config (full field set).
- ``VrfParentConfigModel`` — parent (MSD / MFD) fabric VRF config; carries
  identity + shared fields and a list of per-child overrides.

Cross-field parameter dependencies (l3vni_wo_vlan, TRM group, no_rp,
netflow, bgp_password) are enforced by ``@model_validator`` hooks.
"""

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
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
    VrfType,
)

_CUSTOM_VRF_TEMPLATE_FIELDS = (
    "service_vrf_template_name",
    "vrf_template_name",
    "vrf_extension_template_name",
    "vrf_template_config",
)


# =============================================================================
# VrfAttachmentConfigModel — playbook-facing VRF attachment entry
# =============================================================================


class VrfAttachmentConfigModel(NDNestedModel):
    """
    Playbook-facing VRF attachment entry.

    The public config accepts switch management IPs.  The workflow resolves
    those IPs to switchId values before sending the ND attachment payload.
    """

    identifiers: ClassVar[list[str]] = []

    ip_address: str = Field(
        alias="ipAddress",
        description="Management IP address of the switch to attach this VRF to",
    )
    loopback_id: int | None = Field(
        default=None,
        alias="loopbackId",
        ge=0,
        le=1023,
        description="Attachment loopback interface identifier (0-1023)",
    )
    loopback_ipv4_address: str | None = Field(
        default=None,
        alias="loopbackIpv4Address",
        description="Attachment loopback IPv4 address",
    )
    loopback_ipv6_address: str | None = Field(
        default=None,
        alias="loopbackIpv6Address",
        description="Attachment loopback IPv6 address",
    )
    import_vpn_rt: list[str] | None = Field(
        default=None,
        alias="importVpnRt",
        description="Attachment-level VPN import route targets",
    )
    export_vpn_rt: list[str] | None = Field(
        default=None,
        alias="exportVpnRt",
        description="Attachment-level VPN export route targets",
    )
    import_evpn_rt: list[str] | None = Field(
        default=None,
        alias="importEvpnRt",
        description="Attachment-level EVPN import route targets",
    )
    export_evpn_rt: list[str] | None = Field(
        default=None,
        alias="exportEvpnRt",
        description="Attachment-level EVPN export route targets",
    )

    @field_validator("ip_address", "loopback_ipv4_address", mode="before")
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
# VrfChildConfigModel — per-child-fabric override entry
# =============================================================================


class VrfChildConfigModel(NDNestedModel):
    """
    Per-child-fabric override entry within a parent VRF config.

    Identifies a child fabric by name and provides optional per-fabric
    overrides for fabric-instance settings such as TRM, advertising,
    BGP authentication, netflow, and MVPN route-target settings.

    All fields except ``fabric`` are optional; absent fields mean "inherit
    the parent setting".

    Based on: nd_vrf.py config.child_fabric_config suboptions
    """

    identifiers: ClassVar[list[str]] = []

    # --- Identity ---

    fabric: str = Field(
        description="Name of the child fabric",
    )

    # --- L3VNI without VLAN override ---

    l3vni_wo_vlan: bool | None = Field(
        default=None,
        alias="l3vniWoVlan",
        description="Enable L3VNI without VLAN on this child fabric",
    )

    # --- TRM overrides ---

    trm_enable: bool | None = Field(
        default=None,
        alias="trmEnable",
        description="Enable Tenant Routed Multicast for this child fabric",
    )
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
        description="Loopback interface ID for RP (0–1023); requires trm_enable=True",
    )
    underlay_mcast_ip: str | None = Field(
        default=None,
        alias="underlayMcastIp",
        description="Underlay IPv4 multicast address; requires trm_enable=True",
    )
    overlay_mcast_group: str | None = Field(
        default=None,
        alias="overlayMcastGroup",
        description=("Overlay multicast group IPv4 address (224.0.0.0/4 range); " "requires trm_enable=True"),
    )
    trm_bgw_msite: bool | None = Field(
        default=None,
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
        description="BGP neighbour password (4–32 characters)",
    )
    bgp_passwd_encrypt: int | None = Field(
        default=None,
        alias="bgpPasswdEncrypt",
        description=("BGP password encryption type: 3 (3DES) or 7 (Cisco Type-7); " "required when bgp_password is set"),
    )

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

    @field_validator("overlay_mcast_group", mode="before")
    @classmethod
    def _validate_mcast_group(cls, v: str | None) -> str | None:
        return VrfValidators.validate_overlay_mcast_group(v)

    @field_validator("bgp_passwd_encrypt", mode="before")
    @classmethod
    def _validate_bgp_encrypt(cls, v: int | None) -> int | None:
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
    def _check_trm_fields(self):
        """Forbid TRM-dependent fields when trm_enable is explicitly False."""
        if self.trm_enable is False:
            trm_fields = {
                "no_rp": self.no_rp,
                "rp_external": self.rp_external,
                "rp_address": self.rp_address,
                "rp_loopback_id": self.rp_loopback_id,
                "underlay_mcast_ip": self.underlay_mcast_ip,
                "overlay_mcast_group": self.overlay_mcast_group,
                "trm_bgw_msite": self.trm_bgw_msite,
                "import_mvpn_rt": self.import_mvpn_rt,
                "export_mvpn_rt": self.export_mvpn_rt,
            }
            set_fields = [k for k, v in trm_fields.items() if v is not None]
            if set_fields:
                raise ValueError(f"The following fields require trm_enable=True: " f"{', '.join(set_fields)}")
        return self

    @model_validator(mode="after")
    def _check_no_rp_fields(self):
        """Forbid rp_external and rp_address when no_rp=True."""
        if self.no_rp is True:
            bad = {}
            if self.rp_external is True:
                bad["rp_external"] = self.rp_external
            if self.rp_address is not None:
                bad["rp_address"] = self.rp_address
            if bad:
                raise ValueError(f"The following fields are not applicable when no_rp=True: " f"{', '.join(bad.keys())}")
        return self

    @model_validator(mode="after")
    def _check_netflow_monitor(self):
        """Require nf_monitor when netflow_enable=True."""
        if self.netflow_enable is True and not self.nf_monitor:
            raise ValueError("nf_monitor is required when netflow_enable=True")
        return self

    @model_validator(mode="after")
    def _check_bgp_password(self):
        """Require bgp_passwd_encrypt when bgp_password is set."""
        if self.bgp_password is not None and self.bgp_passwd_encrypt is None:
            raise ValueError("bgp_passwd_encrypt (3 or 7) is required when bgp_password is set")
        return self


# =============================================================================
# VrfConfigModel — standalone fabric VRF config (full field set)
# =============================================================================


class VrfConfigModel(NDBaseModel):
    """
    Playbook-facing VRF configuration model for standalone fabrics.

    Carries the full field set from nd_vrf.py for use against a single
    (standalone) fabric.  All cross-field dependencies are validated by
    ``@model_validator`` hooks.

    Based on: nd_vrf.py config suboptions (standalone topology)
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

    l3vni_wo_vlan: bool = Field(
        default=False,
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
        description=("Enable IPv6 link-local on VRF SVI; " "not applicable when l3vni_wo_vlan=True"),
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
    bgp_passwd_encrypt: int | None = Field(
        default=None,
        alias="bgpPasswdEncrypt",
        description=("BGP password encryption type: 3 (3DES) or 7 (Cisco Type-7); " "required when bgp_password is set"),
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
    def _validate_bgp_encrypt(cls, v: int | None) -> int | None:
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
    def _check_custom_vrf_template_fields(self):
        """Custom template fields are valid only for vrf_type=userDefined."""
        set_fields = [field for field in _CUSTOM_VRF_TEMPLATE_FIELDS if getattr(self, field) is not None]
        if set_fields and self.vrf_type != VrfType.USER_DEFINED.value:
            raise ValueError("The following fields require vrf_type=userDefined: " f"{', '.join(set_fields)}")
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
            raise ValueError("bgp_passwd_encrypt (3 or 7) is required when bgp_password is set")
        return self


# =============================================================================
# VrfParentConfigModel — parent (MSD / MFD) fabric VRF config
# =============================================================================


class VrfParentConfigModel(NDBaseModel):
    """
    Playbook-facing VRF configuration model for parent (MSD / MFD) fabrics.

    Carries identity, template, and shared VRF properties. Per-fabric
    advertising, BGP-auth, netflow, TRM, and MVPN route-target overrides belong in
    ``child_fabric_config`` entries (``VrfChildConfigModel``).

    Cross-field TRM and bgp_password dependencies are validated identically
    to ``VrfConfigModel``.

    Based on: nd_vrf.py config suboptions (parent / MSD topology)
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

    l3vni_wo_vlan: bool = Field(
        default=False,
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
    bgp_passwd_encrypt: int | None = Field(
        default=None,
        alias="bgpPasswdEncrypt",
        description=("BGP password encryption type: 3 (3DES) or 7 (Cisco Type-7); " "required when bgp_password is set"),
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
    def _validate_bgp_encrypt(cls, v: int | None) -> int | None:
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
            raise ValueError("bgp_passwd_encrypt (3 or 7) is required when bgp_password is set")
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
