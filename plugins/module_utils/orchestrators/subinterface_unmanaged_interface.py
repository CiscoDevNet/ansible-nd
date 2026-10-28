# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unmanaged L3 subinterface orchestrator for Nexus Dashboard.

Handles the unmanaged variant of L3 subinterfaces
(`interfaceType: "subInterface"`, `mode: "unmanaged"`, `policyType: "monitorSubinterface"`).

All CRUD (create, update, delete, bulk create, bulk delete, query_one, query_all) comes from the shared templates on
`NDBaseInterfaceOrchestrator`. This module contributes only the wire `interfaceType` and the managed policy set.
"""

from __future__ import annotations

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
    EpManageInterfacesRemove,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import SubinterfaceUnmanagedPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.subinterface_unmanaged_interface import SubinterfaceUnmanagedInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator


class SubinterfaceUnmanagedInterfaceOrchestrator(NDBaseInterfaceOrchestrator[SubinterfaceUnmanagedInterfaceModel]):  # pylint: disable=too-few-public-methods
    """
    # Summary

    Orchestrator for unmanaged L3 subinterfaces on Nexus Dashboard. CRUD comes from `NDBaseInterfaceOrchestrator`; this class contributes only the
    wire `interfaceType` (`query_interface_type`) and the managed policy set (`_managed_policy_types`, the `monitorSubinterface` policy).

    ## Raises

    None
    """

    model_class: ClassVar[type[NDBaseModel]] = SubinterfaceUnmanagedInterfaceModel
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_modify_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    query_interface_type: ClassVar[str] = "subInterface"

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() uses bulk remove
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesRemove

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the `policyType` values this orchestrator owns, the members of `SubinterfaceUnmanagedPolicyTypeEnum`.

        ## Raises

        None
        """
        return {e.value for e in SubinterfaceUnmanagedPolicyTypeEnum}
