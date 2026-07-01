# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
vPC trunkVpcHost interface orchestrator for Nexus Dashboard.

This module provides `TrunkVpcHostInterfaceOrchestrator`, which manages CRUD operations for vPC
`trunkVpcHost` interfaces. It inherits all shared vPC logic from `VpcInterfaceBaseOrchestrator` and only
defines the model class and managed policy types.
"""

from __future__ import annotations

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import TrunkVpcHostPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.vpc_trunk_host_interface import (
    TrunkVpcHostInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vpc_interface_base import VpcInterfaceBaseOrchestrator


class TrunkVpcHostInterfaceOrchestrator(VpcInterfaceBaseOrchestrator):
    """
    # Summary

    Orchestrator for vPC `trunkVpcHost` interface CRUD operations on Nexus Dashboard.

    Inherits all shared vPC logic from `VpcInterfaceBaseOrchestrator`. Defines `model_class` as
    `TrunkVpcHostInterfaceModel` and manages the `trunkVpcHost` policy type.

    ## Raises

    ### RuntimeError

    - Via inherited methods. See `VpcInterfaceBaseOrchestrator` for full details.
    """

    model_class: ClassVar[type[NDBaseModel]] = TrunkVpcHostInterfaceModel

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator.

        ## Raises

        None
        """
        return {e.value for e in TrunkVpcHostPolicyTypeEnum}
