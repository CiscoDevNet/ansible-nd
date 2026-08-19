# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Enumerations for Nexus Dashboard Manage network APIs."""

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
    LAYER2_WITH_SECURITY_GROUP = "layer2WithSecurityGroup"
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


def normalize_vlan_network_type(value: str | None) -> str:
    if value is None:
        return VlanNetworkType.NORMAL.value
    if value in PUBLIC_VLAN_NETWORK_TYPE_TO_API:
        return PUBLIC_VLAN_NETWORK_TYPE_TO_API[value]
    if value in VlanNetworkType.choices():
        return value
    choices = sorted(PUBLIC_VLAN_NETWORK_TYPE_TO_API)
    raise ValueError(f"vlan_network_type must be one of {choices}, got: {value}")


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
    TRUNK_SECONDARY = "trunkSecondary"

    @classmethod
    def choices(cls) -> list[str]:
        return [e.value for e in cls]


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
