# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Ethernet trunkHost interface orchestrator for Nexus Dashboard.

This module provides `EthernetTrunkHostInterfaceOrchestrator`, which manages CRUD operations
for ethernet trunkHost interfaces. It inherits all shared ethernet logic from
`EthernetBaseOrchestrator` and only defines the model class and managed policy types.
"""

from __future__ import annotations

from typing import ClassVar, Type

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import TrunkHostPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_trunk_host_interface import (
    EthernetTrunkHostInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import EthernetBaseOrchestrator


class EthernetTrunkHostInterfaceOrchestrator(EthernetBaseOrchestrator):
    """
    # Summary

    Orchestrator for ethernet trunkHost interface CRUD operations on Nexus Dashboard.

    Inherits all shared ethernet logic from `EthernetBaseOrchestrator`. Defines `model_class` as
    `EthernetTrunkHostInterfaceModel` and manages the `trunkHost` policy type.

    ## Raises

    ### RuntimeError

    - Via inherited methods. See `EthernetBaseOrchestrator` for full details.
    """

    model_class: ClassVar[Type[NDBaseModel]] = EthernetTrunkHostInterfaceModel

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator.

        ## Raises

        None
        """
        return {e.value for e in TrunkHostPolicyTypeEnum}
