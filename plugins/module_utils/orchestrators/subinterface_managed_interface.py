# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Managed L3 subinterface orchestrator for Nexus Dashboard (NX-OS `subinterface`, IOS-XE `iosXeSubinterface` /
`iosXeSubinterfaceShutNoshut`; issue #541).

Handles managed L3 subinterfaces (`interfaceType: "subInterface"`, `mode: "managed"`).

All CRUD (create, update, delete, bulk create, bulk delete, query_one, query_all) comes from the shared templates on
`NDBaseInterfaceOrchestrator`. This module contributes the IOS-XE create preflight, the wire `interfaceType` and the managed policy set.
"""

from __future__ import annotations

from collections.abc import Sequence
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
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    SubinterfaceManagedPolicyTypeEnum,
    XeSubinterfacePolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.subinterface_managed_interface import SubinterfaceManagedInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator


class SubinterfaceManagedInterfaceOrchestrator(NDBaseInterfaceOrchestrator[SubinterfaceManagedInterfaceModel]):  # pylint: disable=too-few-public-methods
    """
    # Summary

    Orchestrator for managed L3 subinterfaces on Nexus Dashboard. CRUD comes from `NDBaseInterfaceOrchestrator`; this class contributes the
    IOS-XE create preflight (`preflight_create`), the wire `interfaceType` (`query_interface_type`) and the managed policy set
    (`_managed_policy_types`: NX-OS `subinterface`; IOS-XE `iosXeSubinterface`, `iosXeSubinterfaceShutNoshut`).

    ## Raises

    ### RuntimeError

    - Via `preflight_create` if a new IOS-XE subinterface lacks `vlan_id` or `ip`.
    """

    model_class: ClassVar[type[NDBaseModel]] = SubinterfaceManagedInterfaceModel
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_full_modify: ClassVar[bool] = True
    supports_bulk_modify_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    xe_removal_requires_discovery: ClassVar[bool] = True
    query_interface_type: ClassVar[str] = "subInterface"

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() uses bulk remove
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesRemove

    def preflight_create(self, model_instances: Sequence[SubinterfaceManagedInterfaceModel]) -> None:
        """
        # Summary

        Run the inherited policy-required-on-create guard, then require the fields the controller needs to create a full IOS-XE
        `iosXeSubinterface`: `vlan_id` and `ip` (whose `prefix` the model already pairs with it). Invoked by `NDStateMachine` with only
        the proposed items absent from the existing inventory, in check mode too, so a sparse `merged` / `replaced` update of an
        existing subinterface is never affected. The admin-state-only `iosXeSubinterfaceShutNoshut` policy and the NX-OS branch are
        not checked. Every incomplete item is aggregated into one error.

        ## Raises

        ### RuntimeError

        - Propagated from `NDBaseInterfaceOrchestrator.preflight_create` (a create item without a policy).
        - If any new `iosXeSubinterface` lacks `vlan_id` or `ip`. The message names each item and its missing fields.
        """
        super().preflight_create(model_instances)
        # TODO(4.2.1) xe-subinterface-create-requires-ip-vlanid
        # ND rejects an `iosXeSubinterface` create without `ip` and `vlanId` (400 "Validation failed for following fields: [ip,
        # vlanId]") on 4.2.1.10 and 4.3.1.175, although the template schema marks neither required. The model keeps both optional so a
        # sparse update stays valid; the requirement is enforced here, on the create subset only.
        offenders: list[str] = []
        for model_instance in model_instances:
            policy = model_instance.config_data.network_os.policy if model_instance.config_data is not None else None
            if getattr(policy, "policy_type", None) != "iosXeSubinterface":
                continue
            missing = [name for name in ("vlan_id", "ip") if getattr(policy, name, None) is None]
            if missing:
                offenders.append(f"(switch_ip={model_instance.switch_ip}, interface_name={model_instance.interface_name}, missing: {', '.join(missing)})")
        if offenders:
            raise RuntimeError(
                f"Cannot create IOS-XE subinterface(s) in fabric '{self.fabric_name}': vlan_id and ip (with prefix) are required for a new "
                f"iosXeSubinterface: {', '.join(offenders)}."
            )

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator: the NX-OS `subinterface` and the IOS-XE
        `iosXeSubinterface` / `iosXeSubinterfaceShutNoshut` policy types (issue #541).

        ## Raises

        None
        """
        return {e.value for e in SubinterfaceManagedPolicyTypeEnum} | {e.value for e in XeSubinterfacePolicyTypeEnum}
