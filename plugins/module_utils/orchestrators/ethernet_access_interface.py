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
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    AccessHostPolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_access_interface import (
    EthernetAccessInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import (
    EthernetBaseOrchestrator,
)


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
    MEMBER_FAMILY: ClassVar[str] = "access"

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator.

        ## Raises

        None
        """
        return {e.value for e in AccessHostPolicyTypeEnum}

    def query_all(self, model_instance: NDBaseModel | None = None, **kwargs):
        """Return access hosts plus named compatible member planning projections."""
        result = super().query_all(model_instance=model_instance, **kwargs)
        if not isinstance(result, list):
            return result
        return self._append_named_member_projections(result)
