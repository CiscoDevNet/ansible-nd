# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Managed L3 subinterface orchestrator for Nexus Dashboard (NX-OS `subinterface`, IOS-XE `iosXeSubinterface` /
`iosXeSubinterfaceShutNoshut`; issue #541).

This module provides `SubinterfaceManagedInterfaceOrchestrator`, which implements CRUD operations for managed L3
subinterfaces (`interfaceType: "subInterface"`, `mode: "managed"`) via the ND Manage Interfaces API. Supports configuring
subinterfaces across multiple switches and both network OS types in a single task.

Each mutation operation (create, update, delete) is followed by a deploy call to persist changes to the switch.
Deploy and remove operations are batched per-switch and executed in bulk after all mutations are complete.

Subinterfaces are logical and support both `interfaceActions/remove` (bulk delete) and `interfaceActions/deploy`
(bulk deploy), so `state: deleted` queues both and lets the standard `remove_pending` + `deploy_pending` flow
handle the work (the same pattern used by `nd_interface_svi`, unlike physical ethernet which must use normalize).
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
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class SubinterfaceManagedInterfaceOrchestrator(NDBaseInterfaceOrchestrator[SubinterfaceManagedInterfaceModel]):
    """
    # Summary

    Orchestrator for managed L3 subinterface CRUD operations on Nexus Dashboard.

    Supports configuring subinterfaces across multiple switches in a single task. Each config item includes a
    `switch_ip` that is resolved to a `switchId` via `FabricContext`.

    Mutation methods (`create`, `update`) queue deploys instead of executing them immediately. Call `deploy_pending`
    after all mutations are complete to deploy all changes in a single API call. `delete` queues subinterfaces for
    bulk removal via `remove_pending`.

    For `state: overridden`, `query_all` queries ALL switches in the fabric to enable fabric-wide convergence.

    Uses `FabricContext` for pre-flight validation and switch resolution.

    ## Raises

    ### RuntimeError

    - Via `validate_prerequisites` if the fabric does not exist or is in deployment-freeze mode.
    - Via `_resolve_switch_id` if no switch matches the given IP in the fabric.
    - Via `create` if the create API request fails.
    - Via `update` if the update API request fails.
    - Via `remove_pending` if the bulk remove API request fails.
    - Via `deploy_pending` if the bulk deploy API request fails.
    - Via `query_one` if the query API request fails.
    - Via `query_all` if the query API request fails.
    """

    model_class: ClassVar[type[NDBaseModel]] = SubinterfaceManagedInterfaceModel
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    xe_removal_requires_discovery: ClassVar[bool] = True

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() uses bulk remove
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesRemove

    def create(self, model_instance: SubinterfaceManagedInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Create a managed L3 subinterface. Resolves `switch_ip` from the model instance, injects `switchId`, and wraps
        the payload in an `interfaces` array. Queues a deploy for later bulk execution via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If the create API request fails.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            api_endpoint = self._configure_endpoint(self.create_endpoint(), switch_sn=switch_id)
            payload = model_instance.to_payload()
            payload["switchId"] = switch_id
            request_body = {"interfaces": [payload]}
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=request_body)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return result
        except Exception as e:
            raise RuntimeError(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: SubinterfaceManagedInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Update a managed L3 subinterface. Resolves `switch_ip` from the model instance, injects `switchId` into the
        payload. Queues a deploy for later bulk execution via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If the update API request fails.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            api_endpoint = self._configure_endpoint(self.update_endpoint(), switch_sn=switch_id)
            api_endpoint.set_identifiers(model_instance.interface_name)
            payload = model_instance.to_payload()
            payload["switchId"] = switch_id
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return result
        except Exception as e:
            raise RuntimeError(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: SubinterfaceManagedInterfaceModel, **kwargs) -> None:
        """
        # Summary

        Queue a managed L3 subinterface for deferred bulk removal via `remove_pending` and bulk deploy via
        `deploy_pending`. The remove deletes the subinterface from ND's config; the subsequent deploy pushes that
        removal to the switch.

        No API calls are made until `remove_pending` and `deploy_pending` are called after all mutations are complete.

        ## Raises

        None
        """
        switch_id = self._resolve_switch_id(model_instance.switch_ip)
        self._queue_remove(model_instance.interface_name, switch_id)
        self._queue_deploy(model_instance.interface_name, switch_id)

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

    def create_bulk(self, model_instances: list[SubinterfaceManagedInterfaceModel], **kwargs) -> ResponseType:
        """
        # Summary

        Create multiple managed L3 subinterfaces in bulk. Groups subinterfaces by `(switch, policyType)` through the shared
        `bulk_create_groups` (issue #409) and sends one POST per group with all of its subinterfaces in the `interfaces` array: ND
        rejects an array that mixes policy types, which a Catalyst carrying both `iosXeSubinterface` and `iosXeSubinterfaceShutNoshut`
        subinterfaces would otherwise produce. Queues deploys for all created subinterfaces for later bulk execution via
        `deploy_pending`; inside a group that fails with a mixed 207, the subinterfaces the controller accepted are still queued
        (`_post_bulk_create_group`).

        ## Raises

        ### RuntimeError

        - If any create API request fails.
        """
        try:
            groups = self.bulk_create_groups(model_instances)
            results = []
            for group_key, items in groups.items():
                results.append(self._post_bulk_create_group(group_key, items))
            return results
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

    def delete_bulk(self, model_instances: list[SubinterfaceManagedInterfaceModel], **kwargs) -> None:
        """
        # Summary

        Queue multiple managed L3 subinterfaces for deferred bulk removal and deployment. No API calls are made until
        `remove_pending` and `deploy_pending` are called after `manage_state` completes.

        ## Raises

        None
        """
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            self._queue_remove(model_instance.interface_name, switch_id)
            self._queue_deploy(model_instance.interface_name, switch_id)

    def query_one(self, model_instance: SubinterfaceManagedInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Query a single managed L3 subinterface by name on a specific switch.

        ## Raises

        ### RuntimeError

        - If the query API request fails.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            api_endpoint = self._configure_endpoint(self.query_one_endpoint(), switch_sn=switch_id)
            api_endpoint.set_identifiers(model_instance.interface_name)
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb)
        except Exception as e:
            raise RuntimeError(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self, model_instance: NDBaseModel | None = None, **kwargs) -> ResponseType:
        """
        # Summary

        Validate the fabric context and query interfaces, filtering for subinterfaces with `interfaceType: "subInterface"` whose
        `policyType` is one this orchestrator manages (NX-OS `subinterface`; IOS-XE `iosXeSubinterface`, `iosXeSubinterfaceShutNoshut`).
        The unmanaged variant (`monitorSubinterface`) is managed by a separate orchestrator, and `userDefined` / the ND-internal
        `iosXeInternalSubinterface` are excluded. A Catalyst switch list can also carry subinterface records with `policy: null` or no
        `configData`; those are skipped rather than raised on.

        The set of switches queried is determined by `_switches_to_query`: fabric-wide for `state: overridden`,
        and limited to switches named in the user config for all other states.

        Runs `validate_prerequisites` on first call to ensure the fabric exists and is modifiable before returning
        any data.

        Each returned interface dict is enriched with a `switch_ip` field so that
        `SubinterfaceManagedInterfaceModel` can be constructed with the composite identifier
        `(switch_ip, interface_name)`.

        ## Raises

        ### RuntimeError

        - If the fabric does not exist on the target ND node.
        - If the fabric is in deployment-freeze mode.
        - If the query API request fails.
        """
        managed_policy_types = self._managed_policy_types()
        try:
            self.validate_prerequisites()
            all_subifs = []
            for switch_ip, switch_id in self._switches_to_query().items():
                interfaces = list(self._switch_interfaces(switch_id).values())
                subifs = [iface for iface in interfaces if iface.get("interfaceType") == "subInterface"]
                managed = [iface for iface in subifs if self._policy_type_of(iface) in managed_policy_types]
                for iface in managed:
                    iface["switchIp"] = switch_ip
                all_subifs.extend(managed)
            return all_subifs
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e

    @staticmethod
    def _managed_policy_types() -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator: the NX-OS `subinterface` and the IOS-XE
        `iosXeSubinterface` / `iosXeSubinterfaceShutNoshut` policy types (issue #541).

        ## Raises

        None
        """
        return {e.value for e in SubinterfaceManagedPolicyTypeEnum} | {e.value for e in XeSubinterfacePolicyTypeEnum}

    @staticmethod
    def _policy_type_of(iface: dict) -> str | None:
        """
        # Summary

        Return the `configData.networkOS.policy.policyType` of an interface record, or `None` when any level is absent or `null`
        (a discovered, policy-less record).

        ## Raises

        None
        """
        policy = ((iface.get("configData") or {}).get("networkOS") or {}).get("policy") or {}
        return policy.get("policyType")
