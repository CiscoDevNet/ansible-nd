# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Port-channel trunkPoHost interface orchestrator for Nexus Dashboard.

This module provides `PortChannelTrunkHostInterfaceOrchestrator`, which manages CRUD operations
for port-channel trunkPoHost interfaces. It inherits all shared port-channel logic from
`PortChannelBaseOrchestrator` and only defines the model class and managed policy types.
"""

from __future__ import annotations

from typing import ClassVar, Type

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import TrunkPoHostPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_trunk_host_interface import (
    PortChannelTrunkHostInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_base import PortChannelBaseOrchestrator


class PortChannelTrunkHostInterfaceOrchestrator(PortChannelBaseOrchestrator):
    """
    # Summary

    Orchestrator for port-channel trunkPoHost interface CRUD operations on Nexus Dashboard.

    Inherits all shared port-channel logic from `PortChannelBaseOrchestrator`. Defines `model_class` as
    `PortChannelTrunkHostInterfaceModel` and manages the `trunkPoHost` policy type.

    ## Raises

    ### RuntimeError

    - Via inherited methods. See `PortChannelBaseOrchestrator` for full details.
    """

    model_class: ClassVar[Type[NDBaseModel]] = PortChannelTrunkHostInterfaceModel

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator.

        ## Raises

        None
        """
        return {e.value for e in TrunkPoHostPolicyTypeEnum}
