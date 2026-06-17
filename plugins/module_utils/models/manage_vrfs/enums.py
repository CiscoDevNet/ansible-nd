# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Enumerations for VRF operations."""

from enum import Enum

# =============================================================================
# ENUMS
# =============================================================================


class VrfType(str, Enum):
    """
    VRF type discriminator enumeration.

    Based on: components/schemas/vrfSchema (discriminator propertyName: vrfType)
    """

    USER_DEFINED = "userDefined"
    VXLAN = "vxlan"
    VXLAN_IBGP = "vxlanIbgp"
    VXLAN_EBGP = "vxlanEbgp"
    VXLAN_CAMPUS = "vxlanCampus"
    AIML_VXLAN_IBGP = "aimlVxlanIbgp"
    AIML_VXLAN_EBGP = "aimlVxlanEbgp"
    CLASSIC_LAN_ENHANCED = "classicLanEnhanced"
    VXLAN_ACI = "vxlanAci"
    ACI = "aci"
    EXTERNAL_CONNECTIVITY = "externalConnectivity"
    VXLAN_EXTERNAL = "vxlanExternal"

    @classmethod
    def choices(cls) -> list[str]:
        """Return list of valid choices."""
        return [e.value for e in cls]


class ConfigurationStatus(str, Enum):
    """
    Configuration deployment status enumeration.

    Based on: components/schemas/configurationStatus
    Read-only field returned by the API.
    """

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
        """Return list of valid choices."""
        return [e.value for e in cls]


class OperationStatus(str, Enum):
    """
    Status of a single VRF/attachment operation (207 multi-status responses).

    Based on: components/schemas/schemas-status207
    """

    FAILED = "failed"
    SUCCESS = "success"

    @classmethod
    def choices(cls) -> list[str]:
        """Return list of valid choices."""
        return [e.value for e in cls]


class VrfAttachmentSwitchRole(str, Enum):
    """
    Role of a switch in a VRF attachment query or detail response.

    Based on: components/schemas/vxlanOverlaySwitchRole and
              components/schemas/eclOverlaySwitchRole
    """

    # VXLAN fabric roles
    LEAF = "leaf"
    BORDER = "border"
    BORDER_GATEWAY = "borderGateway"
    BORDER_GATEWAY_SPINE = "borderGatewaySpine"
    BORDER_GATEWAY_SUPER_SPINE = "borderGatewaySuperSpine"
    # ECL fabric roles
    ACCESS = "access"
    AGGREGATE = "aggregate"

    @classmethod
    def choices(cls) -> list[str]:
        """Return list of valid choices."""
        return [e.value for e in cls]


class DpuAffinity(str, Enum):
    """
    DPU affinity value for smart switch VRF instance values.

    Based on: components/schemas/dpuInstanceValues (dpuAffinity enum)
    """

    DYNAMIC = "dynamic"
    DPU1 = "dpu1"
    DPU2 = "dpu2"
    DPU3 = "dpu3"
    DPU4 = "dpu4"

    @classmethod
    def choices(cls) -> list[str]:
        """Return list of valid choices."""
        return [e.value for e in cls]


class VrfStretchTarget(str, Enum):
    """
    Border gateway list identifier for VRF stretch operations.

    Based on: components/schemas/vrfStretchItem (stretch property)
    Use ``allBgwList`` to stretch to all border gateways or ``none`` to unstretch.
    """

    ALL_BGW_LIST = "allBgwList"
    NONE = "none"

    @classmethod
    def choices(cls) -> list[str]:
        """Return list of valid choices."""
        return [e.value for e in cls]
