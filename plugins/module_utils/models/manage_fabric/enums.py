# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position
# pylint: disable=missing-module-docstring
# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
# Summary

Enum definitions for Nexus Dashboard Ansible modules.

## Enums

- HttpVerbEnum: Enum for HTTP verb values used in endpoints.
- OperationType: Enum for operation types used by Results to determine if changes have occurred.
"""

from __future__ import annotations

__metaclass__ = type

from enum import Enum


class FabricTypeEnum(str, Enum):
    """
    # Summary

    Enumeration of supported fabric types for discriminated union.

    ## Values

    - `VXLAN_IBGP` - VXLAN fabric with iBGP overlay
    - `VXLAN_EBGP` - VXLAN fabric with eBGP overlay
    """

    VXLAN_IBGP = "vxlanIbgp"
    VXLAN_EBGP = "vxlanEbgp"
    EXTERNAL_CONNECTIVITY = "externalConnectivity"


class AlertSuspendEnum(str, Enum):
    """
    # Summary

    Enumeration for alert suspension states.

    ## Values

    - `ENABLED` - Alerts are enabled
    - `DISABLED` - Alerts are disabled
    """

    ENABLED = "enabled"
    DISABLED = "disabled"


class LicenseTierEnum(str, Enum):
    """
    # Summary

    Enumeration for license tier options.

    ## Values

    - `ESSENTIALS` - Essentials license tier
    - `ADVANTAGE` - Advantage license tier
    - `PREMIER` - Premier license tier
    """

    ESSENTIALS = "essentials"
    ADVANTAGE = "advantage"
    PREMIER = "premier"


class ReplicationModeEnum(str, Enum):
    """
    # Summary

    Enumeration for replication modes.

    ## Values

    - `MULTICAST` - Multicast replication
    - `INGRESS` - Ingress replication
    """

    MULTICAST = "multicast"
    INGRESS = "ingress"


class OverlayModeEnum(str, Enum):
    """
    # Summary

    Enumeration for overlay modes.

    ## Values

    - `CLI` - CLI based configuration
    - `CONFIG_PROFILE` - Configuration profile based
    """

    CLI = "cli"
    CONFIG_PROFILE = "config-profile"


class LinkStateRoutingProtocolEnum(str, Enum):
    """
    # Summary

    Enumeration for underlay routing protocols.

    ## Values

    - `OSPF` - Open Shortest Path First
    - `ISIS` - Intermediate System to Intermediate System
    """

    OSPF = "ospf"
    ISIS = "isis"


class CoppPolicyEnum(str, Enum):
    """
    # Summary

    Enumeration for CoPP policy options.
    """

    DENSE = "dense"
    LENIENT = "lenient"
    MODERATE = "moderate"
    STRICT = "strict"
    MANUAL = "manual"


class FabricInterfaceTypeEnum(str, Enum):
    """
    # Summary

    Enumeration for fabric interface types.
    """

    P2P = "p2p"
    UNNUMBERED = "unNumbered"


class GreenfieldDebugFlagEnum(str, Enum):
    """
    # Summary

    Enumeration for greenfield debug flag.
    """

    ENABLE = "enable"
    DISABLE = "disable"


class IsisLevelEnum(str, Enum):
    """
    # Summary

    Enumeration for IS-IS levels.
    """

    LEVEL_1 = "level-1"
    LEVEL_2 = "level-2"


class SecurityGroupStatusEnum(str, Enum):
    """
    # Summary

    Enumeration for security group status.
    """

    ENABLED = "enabled"
    ENABLED_STRICT = "enabledStrict"
    ENABLED_LOOSE = "enabledLoose"
    ENABLE_PENDING = "enablePending"
    ENABLE_PENDING_STRICT = "enablePendingStrict"
    ENABLE_PENDING_LOOSE = "enablePendingLoose"
    DISABLE_PENDING = "disablePending"
    DISABLED = "disabled"


class StpRootOptionEnum(str, Enum):
    """
    # Summary

    Enumeration for STP root options.
    """

    RPVST_PLUS = "rpvst+"
    MST = "mst"
    UNMANAGED = "unmanaged"


class VpcPeerKeepAliveOptionEnum(str, Enum):
    """
    # Summary

    Enumeration for vPC peer keep-alive options.
    """

    LOOPBACK = "loopback"
    MANAGEMENT = "management"


class DhcpProtocolVersionEnum(str, Enum):
    """
    # Summary

    Enumeration for DHCP protocol version options.
    """

    DHCPV4 = "dhcpv4"
    DHCPV6 = "dhcpv6"


class PowerRedundancyModeEnum(str, Enum):
    """
    # Summary

    Enumeration for power redundancy mode options.
    """

    REDUNDANT = "redundant"
    COMBINED = "combined"
    INPUT_SRC_REDUNDANT = "inputSrcRedundant"


class BgpAsModeEnum(str, Enum):
    """
    # Summary

    Enumeration for eBGP BGP AS mode options.
    """

    MULTI_AS = "multiAS"
    SAME_TIER_AS = "sameTierAS"


class FirstHopRedundancyProtocolEnum(str, Enum):
    """
    # Summary

    Enumeration for first-hop redundancy protocol options.
    """

    HSRP = "hsrp"
    VRRP = "vrrp"


class AimlQosPolicyEnum(str, Enum):
    """
    # Summary

    Enumeration for AI/ML QoS policy options based on fabric link speed.
    """

    V_800G = "800G"
    V_400G = "400G"
    V_100G = "100G"
    V_25G = "25G"
    USER_DEFINED = "User-defined"


class AllowVlanOnLeafTorPairingEnum(str, Enum):
    """
    # Summary

    Enumeration for allowed VLAN on leaf-TOR pairing port-channels.
    """

    NONE = "none"
    ALL = "all"


class BgpAuthenticationKeyTypeEnum(str, Enum):
    """
    # Summary

    Enumeration for BGP authentication key encryption types.
    """

    THREE_DES = "3des"
    TYPE6 = "type6"
    TYPE7 = "type7"


class DlbMixedModeDefaultEnum(str, Enum):
    """
    # Summary

    Enumeration for DLB mixed mode default options.
    """

    ECMP = "ecmp"
    FLOWLET = "flowlet"
    PER_PACKET = "per-packet"


class DlbModeEnum(str, Enum):
    """
    # Summary

    Enumeration for DLB mode options.
    """

    FLOWLET = "flowlet"
    PER_PACKET = "per-packet"
    POLICY_DRIVEN_FLOWLET = "policy-driven-flowlet"
    POLICY_DRIVEN_PER_PACKET = "policy-driven-per-packet"
    POLICY_DRIVEN_MIXED_MODE = "policy-driven-mixed-mode"


class MacsecAlgorithmEnum(str, Enum):
    """
    # Summary

    Enumeration for MACsec cryptographic algorithm options.
    """

    AES_128_CMAC = "AES_128_CMAC"
    AES_256_CMAC = "AES_256_CMAC"


class MacsecCipherSuiteEnum(str, Enum):
    """
    # Summary

    Enumeration for MACsec cipher suite options.
    """

    GCM_AES_128 = "GCM-AES-128"
    GCM_AES_256 = "GCM-AES-256"
    GCM_AES_XPN_128 = "GCM-AES-XPN-128"
    GCM_AES_XPN_256 = "GCM-AES-XPN-256"


class RendezvousPointCountEnum(int, Enum):
    """
    # Summary

    Enumeration for number of spines acting as Rendezvous-Points.
    """

    TWO = 2
    FOUR = 4


class RendezvousPointModeEnum(str, Enum):
    """
    # Summary

    Enumeration for multicast rendezvous point mode.
    """

    ASM = "asm"
    BIDIR = "bidir"


class RouteReflectorCountEnum(int, Enum):
    """
    # Summary

    Enumeration for number of spines acting as Route-Reflectors.
    """

    TWO = 2
    FOUR = 4


class UnderlayMulticastGroupAddressLimitEnum(int, Enum):
    """
    # Summary

    Enumeration for underlay multicast group address limit.
    """

    V_128 = 128
    V_512 = 512


class TelemetryCollectionTypeEnum(str, Enum):
    """
    # Summary

    Enumeration for telemetry collection method options.
    """

    IN_BAND = "inBand"
    OUT_OF_BAND = "outOfBand"


class TelemetryStreamingProtocolEnum(str, Enum):
    """
    # Summary

    Enumeration for telemetry streaming protocol options.
    """

    IPV4 = "ipv4"
    IPV6 = "ipv6"


class VrfLiteAutoConfigEnum(str, Enum):
    """
    # Summary

    Enumeration for VRF Lite auto-config deployment options.
    """

    MANUAL = "manual"
    BACK2BACK_AND_TO_EXTERNAL = "back2BackAndToExternal"
