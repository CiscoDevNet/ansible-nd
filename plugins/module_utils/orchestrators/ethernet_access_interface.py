# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Ethernet access-mode interface orchestrator for Nexus Dashboard (NX-OS `accessHost`, IOS-XE `iosXeAccess`; issue #534).

This module provides `EthernetAccessInterfaceOrchestrator`, which manages CRUD operations
for ethernet access-mode interfaces. It inherits all shared ethernet logic from
`EthernetBaseOrchestrator` (including the IOS-XE contract: per-(switch, policy_type) bulk grouping, merge-only under
`state: overridden`, per-interface reset PUT to a defaults-only `iosXeTrunkHost` under `state: deleted`) and only
defines the model class and managed policy types.
"""

from __future__ import annotations

from typing import ClassVar, Type

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    AccessHostPolicyTypeEnum,
    XeAccessHostPolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_access_interface import (
    EthernetAccessInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import EthernetBaseOrchestrator


class EthernetAccessInterfaceOrchestrator(EthernetBaseOrchestrator):
    """
    # Summary

    Orchestrator for ethernet access-mode interface CRUD operations on Nexus Dashboard.

    Inherits all shared ethernet logic from `EthernetBaseOrchestrator`. Defines `model_class` as
    `EthernetAccessInterfaceModel` and manages the `accessHost` (NX-OS) and `iosXeAccess` (IOS-XE) policy types.

    ## Raises

    ### RuntimeError

    - Via inherited methods. See `EthernetBaseOrchestrator` for full details.
    """

    model_class: ClassVar[Type[NDBaseModel]] = EthernetAccessInterfaceModel

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator: the union of the NX-OS (`accessHost`)
        and IOS-XE (`iosXeAccess`) access policy types.

        ## Raises

        None
        """
        return {e.value for e in AccessHostPolicyTypeEnum} | {e.value for e in XeAccessHostPolicyTypeEnum}
