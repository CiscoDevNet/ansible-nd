# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
SVI (switched virtual interface) orchestrator for Nexus Dashboard (NX-OS `svi`, IOS-XE `iosXeSvi` / `iosXeSviShutNoShut`; issue #540).

All CRUD (create, update, delete, bulk create, bulk delete, query_one, query_all) comes from the shared templates on
`NDBaseInterfaceOrchestrator`. This module contributes the wire `interfaceType`, the managed policy set and the 4.3.1 HSRP-version
echo canonicalization.
"""

from __future__ import annotations

from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
    EpManageInterfacesRemove,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import SviPolicyTypeEnum, XeSviPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.svi_interface import SviInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator


class SviInterfaceOrchestrator(NDBaseInterfaceOrchestrator[SviInterfaceModel]):  # pylint: disable=too-few-public-methods
    """
    # Summary

    Orchestrator for SVI interfaces on Nexus Dashboard (NX-OS `svi`; IOS-XE `iosXeSvi`, `iosXeSviShutNoShut`; issue #540). CRUD comes from
    `NDBaseInterfaceOrchestrator`; this class contributes the wire `interfaceType` (`query_interface_type`), the managed policy set
    (`_managed_policy_types`) and `_canonicalize_bulk_wire_echo`.

    ## Raises

    None
    """

    model_class: ClassVar[type[NDBaseModel]] = SviInterfaceModel

    # Capability preflight (PR #571 review): `capableSwitches?interfaceType=svi&mode=managed` lists every switch of a VXLAN and a
    # Campus VXLAN fabric, Catalyst included (lab-verified 2026-09-21 on ND 4.2.1.10 and 4.3.1.175).
    interface_type: ClassVar[str] = "svi"
    interface_mode: ClassVar[str] = "managed"
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_full_modify: ClassVar[bool] = True
    supports_bulk_modify_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    xe_removal_requires_discovery: ClassVar[bool] = True
    query_interface_type: ClassVar[str] = "svi"

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() uses bulk remove
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesRemove

    def _canonicalize_bulk_wire_echo(self, config_data: dict[str, Any]) -> bool:
        """Normalize the ND 4.3.1 NX-OS SVI HSRP-version GET echo for writes.

        # TODO(4.3.1) svi-hsrpversion-string-echo-431: remove this when ND's
        # GET and modify schemas agree. Its PUT schema already needs integer 1/2.
        """
        network_os = config_data.get("networkOS")
        policy = network_os.get("policy") if isinstance(network_os, dict) else None
        if not isinstance(policy, dict) or policy.get("policyType") != "svi":
            return True
        version = policy.get("hsrpVersion")
        if version is None:
            return True
        if isinstance(version, str) and version in {"1", "2"}:
            policy["hsrpVersion"] = int(version)
            return True
        return isinstance(version, int) and not isinstance(version, bool) and version in {1, 2}

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator: the NX-OS `svi` and the IOS-XE `iosXeSvi` /
        `iosXeSviShutNoShut` policy types (issue #540).

        ## Raises

        None
        """
        return {e.value for e in SviPolicyTypeEnum} | {e.value for e in XeSviPolicyTypeEnum}
