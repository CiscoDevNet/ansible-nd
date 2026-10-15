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

import re
from typing import ClassVar, Sequence

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
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import LoopbackInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.validations.manage_fabric_bgp_validation import (
    parse_controller_version,
)


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
    - Via `preflight` if a `csrLoopback` would be created or transitioned to on an ND 4.3.1-or-later controller.
    - Via `_resolve_switch_id` if no switch matches the given IP in the fabric.
    - Via `create` if the create API request fails, or if the response's per-item `results[]` reports a failure.
    - Via `create_bulk` if any create API request fails, or if a response's per-item `results[]` reports a failure.
    - Via `update` if the update API request fails.
    - Via `remove_pending` if the bulk remove API request fails.
    - Via `deploy_pending` if the bulk deploy API request fails.
    - Via `query_one` if the query API request fails.
    - Via `query_all` if the query API request fails.
    """

    model_class: ClassVar[type[NDBaseModel]] = LoopbackInterfaceModel
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_full_modify: ClassVar[bool] = True
    supports_bulk_modify_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    interface_type: ClassVar[str] = "loopback"
    interface_mode: ClassVar[str] = "managed"
    # TODO(4.2.1) ios-xe-loopback-remove-case: Recheck whether ND removal
    # accepts lowercase names and still generates device-side deletion.
    # IOS-XE needs the switch-canonical Loopback<N> spelling on the removal wire.
    # Lowercase removal drops intent without generating `no interface Loopback<N>`.
    xe_removal_requires_discovery: ClassVar[bool] = True

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() uses bulk remove
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesRemove

    # First ND release whose request gateway rejects the `csrLoopback` policy; see `_check_csr_loopback_writable`.
    CSR_LOOPBACK_REJECTED_FROM: ClassVar[tuple[int, int, int]] = (4, 3, 1)

    def preflight_delete(self, model_instances: Sequence[LoopbackInterfaceModel]) -> None:
        """Check IOS-XE delete spelling, ownership, and discovery before removal."""
        pairs = []
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            self._switch_interfaces(switch_id)
            self._delete_side_name(model_instance.interface_name, switch_id)
            pairs.append((model_instance.interface_name, switch_id))
        self._check_xe_removal_discovered(pairs)

    def _check_overridden_removals_discovered(self, model_instances: Sequence[LoopbackInterfaceModel]) -> None:
        """Apply the same IOS-XE delete checks to managed loopbacks removed by override."""
        if self.rest_send.params.get("state") != "overridden":
            return
        proposed = {(model.switch_ip, model.interface_name.strip().lower()) for model in model_instances}
        switch_map = self.fabric_context.switch_map
        pairs = []
        for iface in self.query_all() or []:
            switch_ip = iface.get("switchIp")
            name = str(iface.get("interfaceName") or "")
            if switch_ip in switch_map and (switch_ip, name.strip().lower()) not in proposed:
                switch_id = switch_map[switch_ip]
                self._delete_side_name(name, switch_id)
                pairs.append((name, switch_id))
        self._check_xe_removal_discovered(pairs)

    def _delete_side_name(self, name: str, switch_id: str) -> str:
        """Use canonical IOS-XE spelling so ND queues an actual switch-side remove."""
        # Normal state planning and the delete preflight have already loaded
        # the complete switch inventory. Do not add a GET during queueing.
        record = self._switch_interfaces_cache.get(switch_id, {}).get(name.strip().lower())
        if not isinstance(record, dict) or record.get("interfaceType") != "loopback":
            return name
        config_data = record.get("configData") or {}
        network_os = config_data.get("networkOS") or {}
        if network_os.get("networkOSType") != "ios-xe":
            return name
        if config_data.get("mode") == "unknown" and not network_os.get("policy"):
            raise RuntimeError(
                f"Cannot delete IOS-XE loopback {name} on {switch_id}: "
                "Nexus Dashboard has only an operational-only row and no policy from which to generate a device removal."
            )
        if not network_os.get("policy"):
            raise RuntimeError(f"Cannot delete IOS-XE loopback {name} on {switch_id}: managed policy is missing")
        match = re.fullmatch(r"loopback([0-9]+)", name.strip(), flags=re.IGNORECASE)
        if match is None:
            raise RuntimeError(f"Cannot safely canonicalize IOS-XE loopback name {name!r} on {switch_id}")
        return f"Loopback{match.group(1)}"

    def preflight(self, model_instances: Sequence[LoopbackInterfaceModel]) -> None:
        """
        # Summary

        Pre-mutation validation for the proposed loopbacks: the shared interface preflight (switch resolution, platform match,
        capability, IOS-XE override removals), then the `csrLoopback` release check (`_check_csr_loopback_writable`). Invoked by
        `NDStateMachine.manage_state` before any create or update, in check mode too.

        ## Raises

        ### RuntimeError

        - Propagated from `NDBaseInterfaceOrchestrator.preflight`.
        - Propagated from `_check_csr_loopback_writable`.
        """
        super().preflight(model_instances)
        self._check_csr_loopback_writable(model_instances)

    def _check_csr_loopback_writable(self, model_instances: Sequence[LoopbackInterfaceModel]) -> None:
        """
        # Summary

        Refuse, before any write, a `csrLoopback` that would be created or transitioned to on an ND 4.3.1-or-later controller.
        "Would be" means the proposed item carries `policyType: csrLoopback` and the switch's interface inventory (already cached by
        `query_all`, so this adds no request) either lacks the interface or holds it under another policy type. A `csrLoopback` that
        already exists as such is left alone: re-stating it issues no write. Releases below 4.3.1, and an unknown controller version,
        skip the check.

        ## Raises

        ### RuntimeError

        - If one or more interfaces would become `csrLoopback` on a controller at or above `CSR_LOOPBACK_REJECTED_FROM`.
        - Via `_resolve_switch_id` if no switch matches a model's `switch_ip` in the fabric.
        - Via `_switch_interfaces` if the interface-list request fails.
        """
        # TODO(4.3.1) csr-loopback-read-schema-name-drift
        # ND 4.3.1 validates the IOS-XE loopback policy against both halves of an inconsistent schema: the per-branch enum demands
        # `csrIntLoopback` while the discriminator mapping only accepts `csrLoopback`, so every typed csrLoopback POST and PUT is
        # rejected with HTTP 400 (4.2.1 accepts `csrLoopback`). The module cannot write the policy on 4.3.1 at all; fail here with the
        # cause instead of surfacing ND's opaque "Request validation failed". Tracked as CiscoDevNet/ansible-nd#632.
        raw_version = self.rest_send.controller_version
        version = parse_controller_version(raw_version)
        if version is None or version < self.CSR_LOOPBACK_REJECTED_FROM:
            return
        csr_value = XeLoopbackPolicyTypeEnum.CSR_LOOPBACK.value
        becoming: list[str] = []
        for model_instance in model_instances:
            if self._desired_policy_type(model_instance) != csr_value:
                continue
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing = self._switch_interfaces(switch_id).get(model_instance.interface_name.strip().lower()) or {}
            existing_policy = ((existing.get("configData") or {}).get("networkOS") or {}).get("policy") or {}
            if existing_policy.get("policyType") == csr_value:
                continue
            becoming.append(f"{model_instance.interface_name} ({model_instance.switch_ip})")
        if not becoming:
            return
        raise RuntimeError(
            f"ND {raw_version} rejects the csrLoopback loopback policy on create and update (its schema enum and discriminator "
            f"mapping disagree on the policy name; CiscoDevNet/ansible-nd#632), so csrLoopback cannot be configured on ND "
            f"{'.'.join(str(part) for part in self.CSR_LOOPBACK_REJECTED_FROM)} or later. Affected: {', '.join(becoming)}. "
            "Use another IOS-XE loopback policy type, or a controller release below 4.3.1."
        )

    def create(self, model_instance: LoopbackInterfaceModel, **kwargs) -> ResponseType:
        """
        # Summary

        Create a loopback interface. Resolves `switch_ip` from the model instance, injects `switchId`, and wraps the payload
        in an `interfaces` array. Queues a deploy for later bulk execution via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If the create API request fails, including a 207 Multi-Status response with a failed `DATA.results[]` item
          (detected centrally by `NdV1Strategy.is_success`, which `_request` consults).
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
        name = self._delete_side_name(model_instance.interface_name, switch_id)
        self._queue_remove(name, switch_id)
        self._queue_deploy(name, switch_id)

    def create_bulk(self, model_instances: list[LoopbackInterfaceModel], **kwargs) -> ResponseType:
        """
        # Summary

        Create multiple loopback interfaces in bulk. Groups interfaces by `(switch_id, policy_type)` and sends one POST
        per group with the group's interfaces in the `interfaces` array, reducing API calls from N to one-per-group.
        Queues deploys for all successfully created interfaces for later bulk execution via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If any create API request fails, including a 207 Multi-Status response with a failed `DATA.results[]` item
          (detected centrally by `NdV1Strategy.is_success`, which `_request` consults). The items that response reports as accepted
          are still queued for deploy (`_post_bulk_create_group`); the rejected ones are not.
        """
        try:
            groups = self.bulk_create_groups(model_instances)
            results = []
            for group_key, items in groups.items():
                results.append(self._post_bulk_create_group(group_key, items))
            return results
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

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
            name = self._delete_side_name(model_instance.interface_name, switch_id)
            self._queue_remove(name, switch_id)
            self._queue_deploy(name, switch_id)

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
