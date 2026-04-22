# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Shared enum definitions for ethernet interface models.

These enums are derived from ND config templates (e.g. `int_access_host`, `int_trunk_host`) and constrain policy
fields across multiple interface types. Each enum's member values match the API's expected strings exactly.
"""

from __future__ import annotations

from enum import Enum


class AccessHostPolicyTypeEnum(str, Enum):
    """
    # Summary

    Policy type for access host interfaces.
    """

    ACCESS_HOST = "accessHost"


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
