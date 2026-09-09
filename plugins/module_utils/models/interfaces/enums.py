# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Shared enum definitions for interface models.

These enums are derived from ND interface config templates and constrain policy fields across multiple interface types.
Each enum's member values match the API's expected strings exactly.
"""

from __future__ import annotations

from enum import Enum


class AccessHostPolicyTypeEnum(str, Enum):
    """
    # Summary

    Policy type for access host interfaces.
    """

    ACCESS_HOST = "accessHost"


class AccessPoHostPolicyTypeEnum(str, Enum):
    """
    # Summary

    Policy type for port-channel access host interfaces.
    """

    ACCESS_PO_HOST = "accessPoHost"


class TrunkPoHostPolicyTypeEnum(str, Enum):
    """
    # Summary

    Policy type for port-channel trunk host interfaces.
    """

    TRUNK_PO_HOST = "trunkPoHost"


class AccessVpcHostPolicyTypeEnum(str, Enum):
    """
    # Summary

    Policy type for vPC access host interfaces (`int_vpc_access_host` template).
    """

    ACCESS_VPC_HOST = "accessVpcHost"


class TrunkVpcHostPolicyTypeEnum(str, Enum):
    """
    # Summary

    Policy type for vPC trunk host interfaces (`int_vpc_trunk_host` template).
    """

    TRUNK_VPC_HOST = "trunkVpcHost"


class BpduFilterEnum(str, Enum):
    """
    # Summary

    Spanning-tree BPDU filter settings.
    """

    ENABLE = "enable"
    DISABLE = "disable"
    DEFAULT = "default"


class BpduGuardEnum(str, Enum):
    """
    # Summary

    Spanning-tree BPDU guard settings.
    """

    ENABLE = "enable"
    DISABLE = "disable"
    DEFAULT = "default"


class DuplexModeEnum(str, Enum):
    """
    # Summary

    Port duplex mode settings.
    """

    AUTO = "auto"
    FULL = "full"
    HALF = "half"


class FecEnum(str, Enum):
    """
    # Summary

    Forward error correction (FEC) mode.
    """

    AUTO = "auto"
    FC_FEC = "fcFec"
    OFF = "off"
    RS_CONS16 = "rsCons16"
    RS_FEC = "rsFec"
    RS_IEEE = "rsIEEE"


class LacpRateEnum(str, Enum):
    """
    # Summary

    LACP rate (PDU transmit interval).
    """

    NORMAL = "normal"
    FAST = "fast"


class LinkTypeEnum(str, Enum):
    """
    # Summary

    Spanning-tree link type.
    """

    AUTO = "auto"
    POINT_TO_POINT = "pointToPoint"
    SHARED = "shared"


class MtuEnum(str, Enum):
    """
    # Summary

    Interface MTU setting.
    """

    DEFAULT = "default"
    JUMBO = "jumbo"


class PortChannelModeEnum(str, Enum):
    """
    # Summary

    Port-channel mode.
    """

    ON = "on"
    ACTIVE = "active"
    PASSIVE = "passive"


class SpeedEnum(str, Enum):
    """
    # Summary

    Interface speed setting.
    """

    AUTO = "auto"
    TEN_MB = "10Mb"
    HUNDRED_MB = "100Mb"
    ONE_GB = "1Gb"
    TWO_POINT_FIVE_GB = "2.5Gb"
    FIVE_GB = "5Gb"
    TEN_GB = "10Gb"
    TWENTY_FIVE_GB = "25Gb"
    FORTY_GB = "40Gb"
    FIFTY_GB = "50Gb"
    HUNDRED_GB = "100Gb"
    TWO_HUNDRED_GB = "200Gb"
    FOUR_HUNDRED_GB = "400Gb"
    EIGHT_HUNDRED_GB = "800Gb"


class StormControlActionEnum(str, Enum):
    """
    # Summary

    Storm control action on threshold violation.
    """

    SHUTDOWN = "shutdown"
    TRAP = "trap"
    DEFAULT = "default"


class TrunkHostPolicyTypeEnum(str, Enum):
    """
    # Summary

    Policy type for trunk host interfaces.
    """

    TRUNK_HOST = "trunkHost"


class SviPolicyTypeEnum(str, Enum):
    """
    # Summary

    Policy type for SVI (switched virtual interface) interfaces.
    """

    SVI = "svi"


class SubinterfaceManagedPolicyTypeEnum(str, Enum):
    """
    # Summary

    Policy type for managed L3 subinterfaces.
    """

    SUBINTERFACE = "subinterface"


class SubinterfaceUnmanagedPolicyTypeEnum(str, Enum):
    """
    # Summary

    Policy type for unmanaged L3 subinterfaces (NX-OS).

    The `userDefined` discriminator branch is intentionally excluded — out of scope for this module.

    ## Raises

    None
    """

    MONITOR_SUBINTERFACE = "monitorSubinterface"


class EthernetRoutedPolicyTypeEnum(str, Enum):
    """
    # Summary

    Managed NX-OS ethernet routed-mode policy types owned by the `nd_interface_ethernet_routed` module (issue #447).

    Initial scope is `routedHost` (`int_routed_host` template) only. The remaining create-side types (`endPointLocator`,
    `ipfmL3Port`, `dataBrokerL3Host`) are feature-gated follow-up branches; system-provisioned routed types (`numbered`,
    `vrfLiteLinkMember`, `multiSiteLinkMember`, `vpcPeerKeepAlive`, `mplsUplink`, ...) and `userDefined` are intentionally
    excluded so `overridden` can never touch fabric underlay intent.

    ## Raises

    None
    """

    ROUTED_HOST = "routedHost"


class XeEthernetRoutedPolicyTypeEnum(str, Enum):
    """
    # Summary

    Managed IOS-XE ethernet routed-mode policy types owned by the `nd_interface_ethernet_routed` module (issue #447).

    Initial scope is `iosXeRoutedHost` (`ios_xe_int_routed_host` template) only. `iosXeNumbered`, `csrMultisiteIfcMember`,
    and `iosXeInternalL3PoMember` are fabric-link / system-provisioned; `userDefined` is intentionally excluded.

    ## Raises

    None
    """

    IOS_XE_ROUTED_HOST = "iosXeRoutedHost"


class XeEthernetSpeedEnum(str, Enum):
    """
    # Summary

    Interface speed setting for IOS-XE ethernet templates (`ios_xe_int_routed_host`). Diverges from the Nexus `SpeedEnum`:
    adds `noNegotiate`, lacks 200/400/800Gb.

    ## Raises

    None
    """

    AUTO = "auto"
    TEN_MB = "10Mb"
    HUNDRED_MB = "100Mb"
    ONE_GB = "1Gb"
    TEN_GB = "10Gb"
    TWO_POINT_FIVE_GB = "2.5Gb"
    FIVE_GB = "5Gb"
    TWENTY_FIVE_GB = "25Gb"
    FORTY_GB = "40Gb"
    HUNDRED_GB = "100Gb"
    NO_NEGOTIATE = "noNegotiate"


class LoopbackPolicyTypeEnum(str, Enum):
    """
    # Summary

    Managed NX-OS loopback policy types owned by the `nd_interface_loopback` module. `userDefined` is intentionally excluded.

    ## Raises

    None
    """

    LOOPBACK = "loopback"
    IPFM_LOOPBACK = "ipfmLoopback"
    MPLS_LOOPBACK = "mplsLoopback"


class XeLoopbackPolicyTypeEnum(str, Enum):
    """
    # Summary

    Managed IOS-XE loopback policy types owned by the `nd_interface_loopback` module. `userDefined` is intentionally excluded.

    The ND 4.2.1 OpenAPI READ schema drifts on the CSR branch: it lists the discriminator as `csrIntLoopback`, but a
    live-lab probe (2026-07-18) proved the wire echoes the create-side `csrLoopback` on reads too. Only the
    wire-verified `csrLoopback` is listed here; the drift is recorded in the bug-tracker vault
    (`csr-loopback-read-schema-name-drift`).

    ## Raises

    None
    """

    IOS_XE_LOOPBACK = "iosXeLoopback"
    IOS_XE_LOOPBACK_SHUT_NOSHUT = "iosXeLoopbackShutNoshut"
    IOS_XE_UNDERLAY_LOOPBACK = "iosXeUnderlayLoopback"
    IOS_XE_INTERNAL_LOOPBACK = "iosXeInternalLoopback"
    CSR_LOOPBACK = "csrLoopback"
    CSR1KV_LOOPBACK = "csr1kvLoopback"
