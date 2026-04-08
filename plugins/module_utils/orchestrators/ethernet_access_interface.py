# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Ethernet accessHost interface orchestrator for Nexus Dashboard.

This module provides `EthernetAccessInterfaceOrchestrator`, which manages CRUD operations
for ethernet accessHost interfaces. It inherits all shared ethernet logic from
`EthernetBaseOrchestrator` and only defines the model class and managed policy types.
"""

from __future__ import annotations

from typing import ClassVar, Type

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_access_interface import (
    ACCESS_HOST_POLICY_TYPE_MAPPING,
    EthernetAccessInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import EthernetBaseOrchestrator


class EthernetAccessInterfaceOrchestrator(EthernetBaseOrchestrator):
    """
    # Summary

    Orchestrator for ethernet accessHost interface CRUD operations on Nexus Dashboard.

    Inherits all shared ethernet logic from `EthernetBaseOrchestrator`. Defines `model_class` as
    `EthernetAccessInterfaceModel` and manages the `accessHost` policy type.

    ## Raises

    ### RuntimeError

    - Via inherited methods. See `EthernetBaseOrchestrator` for full details.
    """

    model_class: ClassVar[Type[NDBaseModel]] = EthernetAccessInterfaceModel

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator.

        ## Raises

        None
        """
        return set(ACCESS_HOST_POLICY_TYPE_MAPPING.data.values())
