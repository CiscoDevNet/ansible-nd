# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Enumerations for Nexus Dashboard Manage network APIs."""

from __future__ import annotations

from enum import Enum


class NetworkType(str, Enum):
    """Network discriminator values from components/schemas/networkBase."""

    VXLAN = "vxlan"
    VXLAN_IBGP = "vxlanIbgp"
    VXLAN_EBGP = "vxlanEbgp"
    VXLAN_CAMPUS = "vxlanCampus"
    AIML_VXLAN_IBGP = "aimlVxlanIbgp"
    AIML_VXLAN_EBGP = "aimlVxlanEbgp"
    AIML_ROUTED = "aimlRouted"
    ROUTED = "routed"
    CLASSIC_LAN_ENHANCED = "classicLanEnhanced"
    USER_DEFINED = "userDefined"
    VXLAN_ACI = "vxlanAci"
    ACI = "aci"
    EXTERNAL_CONNECTIVITY = "externalConnectivity"
    VXLAN_EXTERNAL = "vxlanExternal"

    @classmethod
    def choices(cls) -> list[str]:
        return [e.value for e in cls]


class ConfigurationStatus(str, Enum):
    """Configuration deployment status."""

    DEPLOYED = "deployed"
    DEPLOYMENT_IN_PROGRESS = "deploymentInProgress"
    FAILED = "failed"
    IN_PROGRESS = "inProgress"
    IN_SYNC = "inSync"
    NOT_APPLICABLE = "notApplicable"
    OUT_OF_SYNC = "outOfSync"
    PENDING = "pending"
    PREVIEW_IN_PROGRESS = "previewInProgress"
    SUCCESS = "success"

    @classmethod
    def choices(cls) -> list[str]:
        return [e.value for e in cls]


class OperationStatus(str, Enum):
    """Status values for 207 multi-status responses."""

    FAILED = "failed"
    SUCCESS = "success"

    @classmethod
    def choices(cls) -> list[str]:
        return [e.value for e in cls]


class NetworkLayer(str, Enum):
    """Layer values used by network schemas."""

    LAYER2 = "layer2"
    LAYER2_WITH_VRF = "layer2WithVrf"
    LAYER3 = "layer3"

    @classmethod
    def choices(cls) -> list[str]:
        return [e.value for e in cls]


class ClassicNetworkLayer(str, Enum):
    """Layer values used by classic/routed network schemas."""

    LAYER2 = "layer2"
    LAYER3 = "layer3"

    @classmethod
    def choices(cls) -> list[str]:
        return [e.value for e in cls]


class VlanNetworkType(str, Enum):
    """Private VLAN network type values."""

    NORMAL = "normal"
    PRIVATE_PRIMARY = "privatePrimary"
    PRIVATE_SECONDARY_COMMUNITY = "privateSecondaryCommunity"
    PRIVATE_SECONDARY_ISOLATED = "privateSecondaryIsolated"
    CHILD = "child"

    @classmethod
    def choices(cls) -> list[str]:
        return [e.value for e in cls]


PUBLIC_VLAN_NETWORK_TYPE_TO_API = {
    "normal": VlanNetworkType.NORMAL.value,
    "primary": VlanNetworkType.PRIVATE_PRIMARY.value,
    "community": VlanNetworkType.PRIVATE_SECONDARY_COMMUNITY.value,
    "isolated": VlanNetworkType.PRIVATE_SECONDARY_ISOLATED.value,
}
API_VLAN_NETWORK_TYPE_TO_PUBLIC = {value: key for key, value in PUBLIC_VLAN_NETWORK_TYPE_TO_API.items()}


def public_vlan_network_type(value: str | None) -> str | None:
    if value is None:
        return None
    return API_VLAN_NETWORK_TYPE_TO_PUBLIC.get(value, value)


class AciVlanNetworkType(str, Enum):
    """ACI-specific VLAN network type values."""

    NORMAL = "normal"
    CHILD = "child"

    @classmethod
    def choices(cls) -> list[str]:
        return [e.value for e in cls]


class DpuAffinity(str, Enum):
    """DPU affinity values for attachment instance values."""

    DYNAMIC = "dynamic"
    DPU1 = "dpu1"
    DPU2 = "dpu2"
    DPU3 = "dpu3"
    DPU4 = "dpu4"

    @classmethod
    def choices(cls) -> list[str]:
        return [e.value for e in cls]


class NetworkAttachmentMode(str, Enum):
    """Network attachment interface mode discriminator values."""

    ACCESS = "access"
    DOT1Q_TUNNEL = "dot1qTunnel"
    TRUNK = "trunk"
    PROMISCUOUS = "promiscuous"
    TRUNK_PROMISCUOUS = "trunkPromiscuous"
    HOST = "host"
    PVLAN_HOST = "pvlanHost"
    TRUNK_SECONDARY = "trunkSecondary"

    @classmethod
    def choices(cls) -> list[str]:
        return [e.value for e in cls]


class PublicNetworkAttachmentMode(str, Enum):
    """Playbook-facing network attachment interface mode values."""

    ACCESS = "access"
    DOT1Q_TUNNEL = "dot1q_tunnel"
    TRUNK = "trunk"
    PROMISCUOUS = "promiscuous"
    TRUNK_PROMISCUOUS = "trunk_promiscuous"
    PVLAN_HOST = "pvlan_host"
    TRUNK_SECONDARY = "trunk_secondary"

    @classmethod
    def choices(cls) -> list[str]:
        return [e.value for e in cls]


PUBLIC_NETWORK_ATTACHMENT_MODE_TO_API = {
    PublicNetworkAttachmentMode.ACCESS.value: NetworkAttachmentMode.ACCESS.value,
    PublicNetworkAttachmentMode.DOT1Q_TUNNEL.value: NetworkAttachmentMode.DOT1Q_TUNNEL.value,
    PublicNetworkAttachmentMode.TRUNK.value: NetworkAttachmentMode.TRUNK.value,
    PublicNetworkAttachmentMode.PROMISCUOUS.value: NetworkAttachmentMode.PROMISCUOUS.value,
    PublicNetworkAttachmentMode.TRUNK_PROMISCUOUS.value: NetworkAttachmentMode.TRUNK_PROMISCUOUS.value,
    PublicNetworkAttachmentMode.PVLAN_HOST.value: NetworkAttachmentMode.HOST.value,
    PublicNetworkAttachmentMode.TRUNK_SECONDARY.value: NetworkAttachmentMode.TRUNK_SECONDARY.value,
}
API_NETWORK_ATTACHMENT_MODE_TO_PUBLIC = {
    NetworkAttachmentMode.ACCESS.value: PublicNetworkAttachmentMode.ACCESS.value,
    NetworkAttachmentMode.DOT1Q_TUNNEL.value: PublicNetworkAttachmentMode.DOT1Q_TUNNEL.value,
    NetworkAttachmentMode.TRUNK.value: PublicNetworkAttachmentMode.TRUNK.value,
    NetworkAttachmentMode.PROMISCUOUS.value: PublicNetworkAttachmentMode.PROMISCUOUS.value,
    NetworkAttachmentMode.TRUNK_PROMISCUOUS.value: PublicNetworkAttachmentMode.TRUNK_PROMISCUOUS.value,
    NetworkAttachmentMode.HOST.value: PublicNetworkAttachmentMode.PVLAN_HOST.value,
    NetworkAttachmentMode.PVLAN_HOST.value: PublicNetworkAttachmentMode.PVLAN_HOST.value,
    NetworkAttachmentMode.TRUNK_SECONDARY.value: PublicNetworkAttachmentMode.TRUNK_SECONDARY.value,
}


def public_network_attachment_mode_choices() -> list[str]:
    """Return playbook-facing Network attachment interface mode choices."""
    return PublicNetworkAttachmentMode.choices()


def public_network_attachment_mode(value: str | NetworkAttachmentMode | PublicNetworkAttachmentMode | None) -> str | None:
    """Return the canonical playbook-facing Network attachment interface mode."""
    if value is None:
        return None
    raw = value.value if isinstance(value, (NetworkAttachmentMode, PublicNetworkAttachmentMode)) else str(value)
    return API_NETWORK_ATTACHMENT_MODE_TO_PUBLIC.get(raw, raw)


def api_network_attachment_mode(value: str | NetworkAttachmentMode | PublicNetworkAttachmentMode | None, controller_version: str | None = None) -> str | None:
    """Return the Network attachment interface mode spelling expected by the controller API."""
    public_value = public_network_attachment_mode(value)
    if public_value is None:
        return None
    if public_value == PublicNetworkAttachmentMode.PVLAN_HOST.value and _controller_version_at_least(controller_version, 4, 3):
        return NetworkAttachmentMode.PVLAN_HOST.value
    return PUBLIC_NETWORK_ATTACHMENT_MODE_TO_API.get(public_value, public_value)


def _controller_version_at_least(version: str | None, major: int, minor: int) -> bool:
    """Return True when a controller build string is at least the given major/minor release."""
    if not version:
        return False
    try:
        parts = str(version).split(".")
        return (int(parts[0]), int(parts[1])) >= (major, minor)
    except (IndexError, TypeError, ValueError):
        return False


class SwitchRole(str, Enum):
    """VXLAN and ECL switch roles used by network responses."""

    LEAF = "leaf"
    BORDER = "border"
    BORDER_GATEWAY = "borderGateway"
    BORDER_GATEWAY_SPINE = "borderGatewaySpine"
    BORDER_GATEWAY_SUPER_SPINE = "borderGatewaySuperSpine"
    ACCESS = "access"
    AGGREGATE = "aggregate"

    @classmethod
    def choices(cls) -> list[str]:
        return [e.value for e in cls]


class FabricType(str, Enum):
    """Fabric type values returned for member fabric network information."""

    VXLAN_IBGP = "vxlanIbgp"
    VXLAN_EBGP = "vxlanEbgp"
    VXLAN_CAMPUS = "vxlanCampus"
    AIML_VXLAN_IBGP = "aimlVxlanIbgp"
    AIML_VXLAN_EBGP = "aimlVxlanEbgp"
    AIML_ROUTED = "aimlRouted"
    ROUTED = "routed"
    CLASSIC_LAN = "classicLan"
    CLASSIC_LAN_ENHANCED = "classicLanEnhanced"
    IPFM = "ipfm"
    IPFM_ENHANCED = "ipfmEnhanced"
    IPFM_GENERIC_MULTICAST = "ipfmGenericMulticast"
    EXTERNAL_CONNECTIVITY = "externalConnectivity"
    VXLAN_EXTERNAL = "vxlanExternal"
    ACI = "aci"
    META = "meta"
    DATA_BROKER = "dataBroker"

    @classmethod
    def choices(cls) -> list[str]:
        return [e.value for e in cls]


class VlanPoolDomainType(str, Enum):
    """ACI VLAN pool domain types."""

    PHYSICAL = "physical"
    VIRTUAL = "virtual"

    @classmethod
    def choices(cls) -> list[str]:
        return [e.value for e in cls]


class MappingType(str, Enum):
    """VLAN mapping types."""

    NONE = "none"
    SINGLE = "single"

    @classmethod
    def choices(cls) -> list[str]:
        return [e.value for e in cls]
