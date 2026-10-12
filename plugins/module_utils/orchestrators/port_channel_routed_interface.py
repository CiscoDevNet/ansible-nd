# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Routed (L3) port-channel interface orchestrator for Nexus Dashboard.

This module provides `PortChannelRoutedInterfaceOrchestrator`, which manages CRUD operations
for routed port-channel interfaces. It inherits all shared port-channel logic from
`PortChannelBaseOrchestrator` and only defines the model class and managed policy types.
"""

from __future__ import annotations

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    PortChannelRoutedPolicyTypeEnum,
    XePortChannelRoutedPolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_routed_interface import (
    PortChannelRoutedInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_base import PortChannelBaseOrchestrator


class PortChannelRoutedInterfaceOrchestrator(PortChannelBaseOrchestrator):
    """
    # Summary

    Orchestrator for routed (L3) port-channel interface CRUD operations on Nexus Dashboard.

    Inherits all shared port-channel logic from `PortChannelBaseOrchestrator`. Defines `model_class` as
    `PortChannelRoutedInterfaceModel` and manages the NX-OS `l3Po` and the IOS-XE `iosXeL3PortChannel` policy types
    (issue #549). It adds no mutation stage or queue of its own, so the stage order and queue invariants of the base apply unchanged.

    ## Raises

    ### RuntimeError

    - Via inherited methods. See `PortChannelBaseOrchestrator` for full details.
    """

    model_class: ClassVar[type[NDBaseModel]] = PortChannelRoutedInterfaceModel

    # Capability preflight (PR #577 review): `capableSwitches?interfaceType=portChannel&mode=routed` lists every switch of a VXLAN and a
    # Campus VXLAN fabric, Catalyst included (lab-verified 2026-09-21 on ND 4.2.1.10 and 4.3.1.175).
    interface_type: ClassVar[str] = "portChannel"
    interface_mode: ClassVar[str] = "routed"

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator: the NX-OS `l3Po` and the IOS-XE
        `iosXeL3PortChannel` policy types (issue #549). System-provisioned routed port-channels (`l3PoInternal`, `mplsUplinkPo`) and
        `userDefined` ones are excluded, so `overridden` never removes them.

        ## Raises

        None
        """
        return {e.value for e in PortChannelRoutedPolicyTypeEnum} | {e.value for e in XePortChannelRoutedPolicyTypeEnum}
