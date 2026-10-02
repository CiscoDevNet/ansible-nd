# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Loopback interface orchestrator for Nexus Dashboard.

This module provides `LoopbackInterfaceOrchestrator`, which implements CRUD operations
for loopback interfaces via the ND Manage Interfaces API. Supports configuring interfaces
across multiple switches in a single task.

Each mutation operation (create, update, delete) is followed by a deploy call to persist
changes to the switch. Deploy and remove operations are batched per-switch and executed
in bulk after all mutations are complete.

Uses `FabricContext` for pre-flight validation (fabric existence, deployment-freeze check)
and switch IP-to-serial resolution. The model structure mirrors the API payload, so the
orchestrator only needs to inject `switchId` and filter `query_all` results by interface type.

`query_all` manages the union of NX-OS (`loopback`, `ipfmLoopback`, `mplsLoopback` — see `LoopbackPolicyTypeEnum`) and
IOS-XE (`iosXeLoopback`, `iosXeLoopbackShutNoshut`, `iosXeUnderlayLoopback`, `iosXeInternalLoopback`, `csrLoopback`,
`csr1kvLoopback` — see `XeLoopbackPolicyTypeEnum`) managed loopback policy types. Note that IOS-XE's
`iosXeUnderlayLoopback` is user-creatable (unlike NX-OS's `underlayLoopback`, which is system-provisioned), so it is
included here. `userDefined` and other system-provisioned policy types (e.g. NX-OS `underlayLoopback`) are excluded.
The `csrLoopback` branch's wire name is lab-verified (2026-07-18): the ND 4.2.1 OpenAPI READ schema lists it as
`csrIntLoopback`, but the wire echoes `csrLoopback` on reads too (drift recorded in the bug-tracker vault).
"""

from __future__ import annotations

from collections.abc import Sequence
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
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import LoopbackPolicyTypeEnum, XeLoopbackPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import (
    LoopbackConfigDataModel,
    LoopbackInterfaceModel,
    NexusLoopbackNetworkOSModel,
    NexusLoopbackPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import BulkCreateGroupKey, BulkCreateItem, NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class LoopbackInterfaceOrchestrator(NDBaseInterfaceOrchestrator[LoopbackInterfaceModel]):
    """
    # Summary

    Orchestrator for loopback interface CRUD operations on Nexus Dashboard.

    Supports configuring interfaces across multiple switches in a single task. Each config item
    includes a `switch_ip` that is resolved to a `switchId` via `FabricContext`.

    Overrides the base orchestrator to handle the ND interfaces API, which requires `fabric_name` and `switch_sn`
    on every endpoint, injects `switchId` into payloads, and defers deploy calls for bulk execution.

    Mutation methods (`create`, `update`) queue deploys instead of executing them immediately. Call `deploy_pending`
    after all mutations are complete to deploy all changes in a single API call. `delete` queues interfaces for bulk
    removal via `remove_pending`.

    For `state: overridden`, `query_all` queries ALL switches in the fabric to enable fabric-wide convergence.

    Uses `FabricContext` for pre-flight validation and switch resolution.

    ## Raises

    ### RuntimeError

    - Via `validate_prerequisites` if the fabric does not exist or is in deployment-freeze mode.
    - Via `_resolve_switch_id` if no switch matches the given IP in the fabric.
    - Via `create` if the create API request fails, or if the response's per-item `results[]` reports a failure.
    - Via `create_bulk` if any create API request fails, or if a response's per-item `results[]` reports a failure.
    - Via `create` / `create_bulk` if an `mplsLoopback` placeholder create or its conversion PUT fails; unconverted placeholders are removed first.
    - Via `preflight` if an interface would become `mplsLoopback` while MPLS Handoff is disabled on the fabric.
    - Via `update` if the update API request fails.
    - Via `remove_pending` if the bulk remove API request fails.
    - Via `deploy_pending` if the bulk deploy API request fails.
    - Via `query_one` if the query API request fails.
    - Via `query_all` if the query API request fails.
    """

    model_class: ClassVar[type[NDBaseModel]] = LoopbackInterfaceModel
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    interface_type: ClassVar[str] = "loopback"
    interface_mode: ClassVar[str] = "managed"

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() uses bulk remove
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesRemove

    def preflight(self, model_instances: Sequence[LoopbackInterfaceModel]) -> None:
        """
        # Summary

        Pre-mutation validation for the proposed loopbacks: the shared interface preflight (switch resolution, platform match,
        capability, IOS-XE override removals), then the MPLS Handoff precondition for interfaces that would become `mplsLoopback`
        (`_check_mpls_handoff`). Invoked by `NDStateMachine.manage_state` before any create or update, in check mode too.

        ## Raises

        ### RuntimeError

        - Propagated from `NDBaseInterfaceOrchestrator.preflight`.
        - Propagated from `_check_mpls_handoff`.
        """
        super().preflight(model_instances)
        self._check_mpls_handoff(model_instances)

    def _check_mpls_handoff(self, model_instances: Sequence[LoopbackInterfaceModel]) -> None:
        """
        # Summary

        Refuse an interface that would become `mplsLoopback` while the fabric's MPLS Handoff setting is disabled. "Would become" means
        the interface is absent on the controller or present with a different policy type; it is read from the per-switch inventory
        `query_all` already cached (`_switch_interfaces`), so the selection adds no request.

        The setting is `management.mplsHandoff` in the full fabric body (`FabricContext.fabric_details`); the fabric summary does not
        carry it. That body is fetched once per run, and only when at least one interface would become `mplsLoopback`: a re-run where
        every `mplsLoopback` already exists, and a task that names none, send nothing.

        Only an explicit `false` is refused. A fabric body with no `mplsHandoff` key gives no evidence either way, so the check is
        skipped and ND answers the write. Switch role is not checked: ND does not enforce it.

        ## Raises

        ### RuntimeError

        - If one or more interfaces would become `mplsLoopback` and `management.mplsHandoff` is `false`.
        - Via `_resolve_switch_id` if no switch matches a model's `switch_ip` in the fabric.
        - Via `FabricContext.fabric_details` if the fabric details request fails.
        """
        # TODO(4.2.1) mpls-loopback-create-requires-mpls-handoff
        # With MPLS Handoff disabled, MPLS_LOOPBACK_IP_POOL is empty and ND fails the write with "[MPLS_LOOPBACK_IP_POOL] is an empty
        # pool" even when an explicit `ip` is supplied: HTTP 500 on the 4.2.1 create, HTTP 400 on the 4.3.1 PUT. Neither names the fix,
        # and without this check the failure arrives only after the placeholder POST was sent and rolled back.
        mpls_value = LoopbackPolicyTypeEnum.MPLS_LOOPBACK.value
        becoming: list[str] = []
        for model_instance in model_instances:
            if model_instance.policy_type != mpls_value:
                continue
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing = self._switch_interfaces(switch_id).get(model_instance.interface_name.lower()) or {}
            existing_policy = ((existing.get("configData") or {}).get("networkOS") or {}).get("policy") or {}
            if existing_policy.get("policyType") == mpls_value:
                continue
            becoming.append(f"{model_instance.interface_name} ({model_instance.switch_ip})")
        if not becoming:
            return
        details = self.fabric_context.fabric_details
        management = details.get("management") if isinstance(details, dict) else None
        if not isinstance(management, dict) or management.get("mplsHandoff") is not False:
            return
        raise RuntimeError(
            f"MPLS Handoff is disabled on fabric '{self.fabric_name}'; mplsLoopback requires it for {', '.join(becoming)}. "
            "Enable mpls_handoff with the fabric's nd_manage_fabric_* module and retry. No changes were made."
        )

    def create(self, model_instance: LoopbackInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Create a loopback interface. Resolves `switch_ip` from the model instance, injects `switchId`, and wraps the payload
        in an `interfaces` array. Queues a deploy for later bulk execution via `deploy_pending`. An `mplsLoopback` is created in two
        requests instead (`_create_mpls_loopbacks`).

        ## Raises

        ### RuntimeError

        - If the create API request fails, including a 207 Multi-Status response with a failed `DATA.results[]` item
          (detected centrally by `NdV1Strategy.is_success`, which `_request` consults).
        - If an `mplsLoopback` conversion fails (see `_create_mpls_loopbacks_on_switch`).
        """
        try:
            if model_instance.policy_type == LoopbackPolicyTypeEnum.MPLS_LOOPBACK.value:
                return self._create_mpls_loopbacks([model_instance])
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

    def update(self, model_instance: LoopbackInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Update a loopback interface. Resolves `switch_ip` from the model instance, injects `switchId` into the payload.
        Queues a deploy for later bulk execution via `deploy_pending`.

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

    def delete(self, model_instance: LoopbackInterfaceModel, **kwargs) -> None:
        """
        # Summary

        Queue a loopback interface for deferred bulk removal via `remove_pending` and bulk deploy via `deploy_pending`.
        The remove deletes the interface from ND's config; the deploy pushes that removal to the switch.

        No API calls are made until `remove_pending` and `deploy_pending` are called after all mutations are complete.

        ## Raises

        None
        """
        switch_id = self._resolve_switch_id(model_instance.switch_ip)
        self._queue_remove(model_instance.interface_name, switch_id)
        self._queue_deploy(model_instance.interface_name, switch_id)

    def create_bulk(self, model_instances: list[LoopbackInterfaceModel], **kwargs) -> ResponseType:
        """
        # Summary

        Create multiple loopback interfaces in bulk. Interfaces other than `mplsLoopback` are grouped by `(switch_id, policy_type)` and
        sent first, one POST per group with the group's interfaces in the `interfaces` array. `mplsLoopback` interfaces follow, created
        in two requests each (`_create_mpls_loopbacks`). Queues deploys for all successfully created interfaces for later bulk execution
        via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If any create API request fails, including a 207 Multi-Status response with a failed `DATA.results[]` item
          (detected centrally by `NdV1Strategy.is_success`, which `_request` consults). The items that response reports as accepted
          are still queued for deploy (`_post_bulk_create_group`); the rejected ones are not.
        - If an `mplsLoopback` conversion fails (see `_create_mpls_loopbacks_on_switch`).
        """
        try:
            mpls_value = LoopbackPolicyTypeEnum.MPLS_LOOPBACK.value
            direct = [model_instance for model_instance in model_instances if model_instance.policy_type != mpls_value]
            mpls = [model_instance for model_instance in model_instances if model_instance.policy_type == mpls_value]
            results: list[Any] = []
            for group_key, items in self.bulk_create_groups(direct).items():
                results.append(self._post_bulk_create_group(group_key, items))
            results.extend(self._create_mpls_loopbacks(mpls))
            return results
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

    def _mpls_placeholder_item(self, model_instance: LoopbackInterfaceModel, switch_id: str) -> BulkCreateItem:
        """
        # Summary

        Build the placeholder create item for an `mplsLoopback` interface: a plain `loopback` policy with `adminState: false` in the
        `management` VRF and no other field. It is deliberately inert. ND refuses an address-less loopback in the default VRF, and a
        plain loopback that carries an address gets underlay routing configuration generated for it, so the placeholder sits in the
        `management` VRF with no address and nothing from the requested `mplsLoopback` policy is copied. ND generates only
        `vrf member management` and `shutdown` for it; the following PUT supplies the real policy and leaves neither line behind
        (lab-verified 2026-10-02 on ND 4.2.1.10 and 4.3.1.175).

        ## Raises

        None
        """
        placeholder = LoopbackInterfaceModel(
            switch_ip=model_instance.switch_ip,
            interface_name=model_instance.interface_name,
            config_data=LoopbackConfigDataModel(
                network_os=NexusLoopbackNetworkOSModel(
                    network_os_type="nx-os",
                    policy=NexusLoopbackPolicyModel(policy_type=LoopbackPolicyTypeEnum.LOOPBACK.value, admin_state=False, vrf="management"),
                ),
            ),
        )
        payload = placeholder.to_payload()
        payload["switchId"] = switch_id
        return BulkCreateItem(interface_name=model_instance.interface_name, payload=payload)

    def _create_mpls_loopbacks(self, model_instances: list[LoopbackInterfaceModel]) -> list[Any]:
        """
        # Summary

        Create `mplsLoopback` interfaces switch by switch (`_create_mpls_loopbacks_on_switch`), in first-seen switch order. One switch
        is finished before the next starts, so at any failure only the current switch holds unconverted placeholders.

        ## Raises

        ### RuntimeError

        - Via `_resolve_switch_id` if no switch matches a model's `switch_ip` in the fabric.
        - Propagated from `_create_mpls_loopbacks_on_switch`.
        """
        by_switch: dict[str, list[LoopbackInterfaceModel]] = {}
        for model_instance in model_instances:
            by_switch.setdefault(self._resolve_switch_id(model_instance.switch_ip), []).append(model_instance)
        results: list[Any] = []
        for switch_id, switch_models in by_switch.items():
            results.extend(self._create_mpls_loopbacks_on_switch(switch_id, switch_models))
        return results

    def _create_mpls_loopbacks_on_switch(self, switch_id: str, model_instances: list[LoopbackInterfaceModel]) -> list[Any]:
        """
        # Summary

        Create the given `mplsLoopback` interfaces on one switch in two steps: one bulk POST of inert placeholders
        (`_mpls_placeholder_item`), then one PUT per interface with the requested policy (`update`, which queues the deploy when it
        succeeds). A placeholder is never queued for deploy.

        If the placeholder POST fails or any PUT fails, every placeholder on this switch that exists and was not converted is removed
        (`_roll_back_mpls_placeholders`) and the failure is raised. Interfaces already converted keep their queued deploy.

        ## Raises

        ### RuntimeError

        - If the placeholder POST fails. The message names any placeholder the controller created and what the rollback did with it.
        - If a PUT fails. The message names the removed placeholders, any left behind, and the interfaces already converted.
        """
        # TODO(4.3.1) mpls-loopback-create-requires-mpls-handoff
        # ND 4.3.1 rejects `policyType: mplsLoopback` on the create POST (HTTP 400: the create discriminator maps only `loopback`,
        # `ipfmLoopback` and `userDefined`), while a PUT of an existing plain loopback to `mplsLoopback` is accepted on 4.2.1 and 4.3.1.
        # Create an inert plain loopback, then PUT the requested policy onto it. One code path serves both releases.
        items = [self._mpls_placeholder_item(model_instance, switch_id) for model_instance in model_instances]
        group_key = BulkCreateGroupKey(switch_id=switch_id, policy_type=LoopbackPolicyTypeEnum.LOOPBACK.value)
        outcome = self._send_bulk_create_group(group_key, items)
        if outcome.error is not None:
            raise RuntimeError(self._roll_back_mpls_placeholders(outcome.error, switch_id, [], outcome.accepted)) from outcome.error
        results: list[Any] = [outcome.result]
        converted: list[str] = []
        for model_instance in model_instances:
            try:
                results.append(self.update(model_instance))
            except Exception as e:
                unconverted = [item.interface_name for item in items if item.interface_name not in converted]
                raise RuntimeError(self._roll_back_mpls_placeholders(e, switch_id, converted, unconverted)) from e
            converted.append(model_instance.interface_name)
        return results

    def _remove_placeholders(self, switch_id: str, names: list[str]) -> tuple[list[str], Exception | None]:
        """
        # Summary

        Remove the named placeholder interfaces on `switch_id` with one `interfaceActions/remove` request, sent once and never retried.
        Returns the names that were NOT confirmed removed and the error that prevented it (`([], None)` when all were removed or `names`
        is empty, in which case no request is sent).

        The endpoint answers HTTP 207 with a status per interface, keyed by `interfaceName` + `switchId`. On a failed request only the
        pairs the response reports as an exact `success` (`_accepted_multistatus_pairs`) count as removed. The response is consulted
        only when the request recorded a new one: a sender exception leaves the previous response in place (issue #554), which must
        not be mistaken for this request's result.

        This request bypasses `_pending_removes` on purpose: a placeholder was never deployed and never queued, so there is no deploy
        to pair it with and nothing for the failure-path finalizer to consider.

        ## Raises

        None
        """
        if not names:
            return [], None
        api_endpoint = EpManageInterfacesRemove()
        api_endpoint.fabric_name = self.fabric_name
        payload = {"interfaces": [{"interfaceName": name, "switchId": switch_id} for name in names]}
        recorded = self.rest_send.response_count
        try:
            self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
        except Exception as e:  # pylint: disable=broad-exception-caught
            removed: set[tuple[str, str]] = set()
            if self.rest_send.response_count > recorded:
                removed = self._accepted_multistatus_pairs()
            return [name for name in names if (name.strip().lower(), switch_id) not in removed], e
        return [], None

    def _roll_back_mpls_placeholders(self, error: Exception, switch_id: str, converted: list[str], unconverted: list[str]) -> str:
        """
        # Summary

        Remove the unconverted placeholders after a failed `mplsLoopback` create on `switch_id` and return the failure message for the
        caller to raise. The message names the original error, the placeholders removed, any that could not be removed (with the
        rollback error and how to remove them), and the interfaces already converted, whose deploy stays queued.

        ## Raises

        None
        """
        left_behind, rollback_error = self._remove_placeholders(switch_id, unconverted)
        removed = [name for name in unconverted if name not in left_behind]
        msg = f"mplsLoopback create failed on switchId {switch_id}: {error}."
        if removed:
            msg += f" Removed the placeholder loopback(s) {removed} created for this request."
        if left_behind:
            msg += f" Could not remove the placeholder loopback(s) {left_behind} ({rollback_error}); they remain staged as plain loopbacks."
            msg += " Remove them with state: deleted."
        if converted:
            msg += f" {converted} were created as mplsLoopback before the failure; their deploy stays queued."
        return msg

    def delete_bulk(self, model_instances: list[LoopbackInterfaceModel], **kwargs) -> None:
        """
        # Summary

        Queue multiple loopback interfaces for deferred bulk removal and deployment. Each interface is queued for removal
        via `remove_pending` and deployment via `deploy_pending`. No API calls are made until those methods are called
        after `manage_state` completes.

        ## Raises

        None
        """
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            self._queue_remove(model_instance.interface_name, switch_id)
            self._queue_deploy(model_instance.interface_name, switch_id)

    def query_one(self, model_instance: LoopbackInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Query a single loopback interface by name on a specific switch.

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

        Validate the fabric context and query interfaces, filtering for the loopback policy types managed by this
        module - the union of NX-OS (`loopback`, `ipfmLoopback`, `mplsLoopback` - see `LoopbackPolicyTypeEnum`) and
        IOS-XE (`iosXeLoopback`, `iosXeLoopbackShutNoshut`, `iosXeUnderlayLoopback`, `iosXeInternalLoopback`,
        `csrLoopback`, `csr1kvLoopback` - see `XeLoopbackPolicyTypeEnum`) policy types. The `csrLoopback` branch's
        wire name is lab-verified (2026-07-18): the ND 4.2.1 OpenAPI READ schema lists it as `csrIntLoopback`, but
        the wire echoes `csrLoopback` on reads too (drift recorded in the bug-tracker vault).

        The set of switches queried is determined by `_switches_to_query`: fabric-wide for `state: overridden`,
        and limited to switches named in the user config for all other states.

        IOS-XE's `iosXeUnderlayLoopback` is user-creatable (unlike NX-OS's `underlayLoopback`, which is
        system-provisioned) and is therefore included in the managed set above. System-provisioned loopbacks (e.g.
        NX-OS Loopback0 routing, Loopback1 VTEP with `policyType: "underlayLoopback"`) and the `userDefined` policy
        type are excluded - those are out of scope for this module.

        Runs `validate_prerequisites` on first call to ensure the fabric exists and is modifiable before returning any data.

        Each returned interface dict is enriched with a `switch_ip` field so that `LoopbackInterfaceModel` can be constructed
        with the composite identifier `(switch_ip, interface_name)`.

        ## Raises

        ### RuntimeError

        - If the fabric does not exist on the target ND node.
        - If the fabric is in deployment-freeze mode.
        - If the query API request fails.
        """
        try:
            self.validate_prerequisites()
            all_loopbacks = []
            managed_policy_types = {policy_type.value for policy_type in LoopbackPolicyTypeEnum} | {
                policy_type.value for policy_type in XeLoopbackPolicyTypeEnum
            }
            for switch_ip, switch_id in self._switches_to_query().items():
                interfaces = list(self._switch_interfaces(switch_id).values())
                loopbacks = [iface for iface in interfaces if iface.get("interfaceType") == "loopback"]
                managed = [lb for lb in loopbacks if lb.get("configData", {}).get("networkOS", {}).get("policy", {}).get("policyType") in managed_policy_types]
                for iface in managed:
                    iface["switchIp"] = switch_ip
                all_loopbacks.extend(managed)
            return all_loopbacks
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e
