# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
vPC accessVpcHost interface orchestrator for Nexus Dashboard.

This module provides `AccessVpcHostInterfaceOrchestrator`, which manages CRUD operations for vPC
`accessVpcHost` interfaces. It inherits all shared vPC logic from `VpcInterfaceBaseOrchestrator` and only
defines the model class and managed policy types.
"""

from __future__ import annotations

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import AccessVpcHostPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.vpc_access_interface import (
    AccessVpcHostInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vpc_interface_base import VpcInterfaceBaseOrchestrator


class AccessVpcHostInterfaceOrchestrator(VpcInterfaceBaseOrchestrator):
    """
    # Summary

    Orchestrator for vPC `accessVpcHost` interface CRUD operations on Nexus Dashboard.

    Inherits all shared vPC logic from `VpcInterfaceBaseOrchestrator`. Defines `model_class` as
    `AccessVpcHostInterfaceModel` and manages the `accessVpcHost` policy type.

    ## Raises

    ### RuntimeError

    - Via inherited methods. See `VpcInterfaceBaseOrchestrator` for full details.
    """

    model_class: ClassVar[type[NDBaseModel]] = AccessVpcHostInterfaceModel

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator.

        ## Raises

        None
        """
        return {e.value for e in AccessVpcHostPolicyTypeEnum}
