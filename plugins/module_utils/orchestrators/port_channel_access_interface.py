# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Port-channel accessPoHost interface orchestrator for Nexus Dashboard.

This module provides `PortChannelAccessInterfaceOrchestrator`, which manages CRUD operations
for port-channel accessPoHost interfaces. It inherits all shared port-channel logic from
`PortChannelBaseOrchestrator` and only defines the model class and managed policy types.
"""

from __future__ import annotations

from typing import ClassVar, Type

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import AccessPoHostPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_access_interface import (
    PortChannelAccessInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_base import PortChannelBaseOrchestrator


class PortChannelAccessInterfaceOrchestrator(PortChannelBaseOrchestrator):
    """
    # Summary

    Orchestrator for port-channel accessPoHost interface CRUD operations on Nexus Dashboard.

    Inherits all shared port-channel logic from `PortChannelBaseOrchestrator`. Defines `model_class` as
    `PortChannelAccessInterfaceModel` and manages the `accessPoHost` policy type.

    ## Raises

    ### RuntimeError

    - Via inherited methods. See `PortChannelBaseOrchestrator` for full details.
    """

    model_class: ClassVar[Type[NDBaseModel]] = PortChannelAccessInterfaceModel

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator.

        ## Raises

        None
        """
        return {e.value for e in AccessPoHostPolicyTypeEnum}
