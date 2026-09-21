# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Port-channel trunkPoHost interface orchestrator for Nexus Dashboard.

This module provides `PortChannelTrunkHostInterfaceOrchestrator`, which manages CRUD operations
for port-channel trunkPoHost interfaces. It inherits all shared port-channel logic from
`PortChannelBaseOrchestrator` and only defines the model class and managed policy types.
"""

from __future__ import annotations

from typing import ClassVar

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

    model_class: ClassVar[type[NDBaseModel]] = PortChannelTrunkHostInterfaceModel

    # ND's staged representation for a newly-created no-deploy port-channel can
    # omit policy.ports when the requested member list is explicitly empty.  The
    # state machine enables this path only for merged operations with deploy=False.
    # Keep the equivalence at the exact API alias path so non-empty member
    # mismatches and all unrelated fields remain strict.
    staged_empty_list_equivalents: ClassVar[set[tuple[str, ...]]] = {
        ("configData", "networkOS", "policy", "ports"),
    }

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator.

        ## Raises

        None
        """
        return {e.value for e in TrunkPoHostPolicyTypeEnum}
