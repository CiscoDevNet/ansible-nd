# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# pyright: reportAttributeAccessIssue=false
# ModelType is NDBaseModel which lacks interface-specific fields (switch_ip,
# interface_name, config_data). Concrete subclasses always bind ModelType to a
# model that provides these fields, so the accesses are safe at runtime.

"""
Base orchestrator for port-channel interface modules on Nexus Dashboard.

This module provides `PortChannelBaseOrchestrator`, which implements shared CRUD operations
for all port-channel interface types (accessPoHost/iosXeAccessPoHost, trunkPoHost/iosXeTrunkPoHost,
etc.) via the ND Manage Interfaces API. Type-specific orchestrators inherit from this base and
provide their own `model_class` and `_managed_policy_types()`, which name both the NX-OS and the
IOS-XE policy type for their interface flavor (issues #536/#537).

Inherits shared interface lifecycle operations (deploy queuing, fabric validation, switch
resolution) from `NDBaseInterfaceOrchestrator` and adds port-channel-specific functionality:
- Standard remove-based deletion (port-channels are virtual interfaces and are deletable); IOS-XE port-channels are queued under
  their switch-canonical `Port-channel<N>` spelling so ND generates the switch-side deletion (`_delete_side_name`)
- Fabric-wide `query_all()` filtered by `interfaceType: "portChannel"` and per-type policy filtering
- A member-already-in-use `preflight()` that rejects, before any write, a port-channel whose member ethernet is
  already owned by a different port-channel (issue #369)
- `create_bulk()` groups port-channels by `(switch_id, policy_type)` via `bulk_create_groups` and sends one POST
  per group, so an NX-OS and an IOS-XE port-channel on the same switch never share a batch (issue #409)
- An IOS-XE member-mode `preflight()` that rejects, before any write, an `iosXeAccessPoHost`/`iosXeTrunkPoHost`
  member whose current intent policy does not already match the port-channel mode (issues #536/#537)

The port-channel policy is the single source of truth for member configuration via the `ports` list.
On IOS-XE, a removed member can require its own exact-interface deploy to apply the detach.
Member field restrictions on standalone ethernet modules are enforced separately by the ethernet orchestrators.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
    EpManageInterfacesRemove,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_vpc_pair import (
    EpVpcPairGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_membership import (
    EthernetMembershipIndex,
    MemberPolicyDescriptor,
    MembershipValidationError,
    get_member_policy_descriptor_for_parent,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import (
    NDBaseInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import (
    ResponseType,
)

ModelType = NDBaseModel

# The lowercase port-channel identifier the models keep (ND echoes `port-channel<N>`); the delete side rewrites it to the
# switch-canonical `Port-channel<N>` for IOS-XE (`_delete_side_name`).
_XE_PORT_CHANNEL_NAME_RE = re.compile(r"^port-channel(\d+)$")


class PortChannelBaseOrchestrator(NDBaseInterfaceOrchestrator[ModelType]):
    """
    # Summary

    Base orchestrator for port-channel interface CRUD operations on Nexus Dashboard.

    Provides shared logic for all port-channel interface types. Subclasses must set `model_class` and implement
    `_managed_policy_types()` to define which policy types they manage.

    Supports configuring port-channels across multiple switches in a single task. Each config item includes a
    `switch_ip` that is resolved to a `switchId` via `FabricContext`.

    Mutation methods (`create`, `update`) queue deploys for bulk execution. `delete` queues port-channels for
    bulk removal via `interfaceActions/remove` and bulk deploy. Call `remove_pending` and `deploy_pending` after
    all mutations are complete.

    ## Raises

    ### RuntimeError

    - Via `validate_prerequisites` if the fabric does not exist or is in deployment-freeze mode.
    - Via `_resolve_switch_id` if no switch matches the given IP in the fabric.
    - Via `preflight` if a proposed member ethernet is already owned by a different port-channel.
    - Via `preflight` if a proposed IOS-XE member's current policy mode does not match the port-channel mode.
    - Via `create` if the create API request fails.
    - Via `update` if the update API request fails.
    - Via `remove_pending` if the bulk remove API request fails.
    - Via `deploy_pending` if the bulk deploy API request fails.
    - Via `query_one` if the query API request fails.
    - Via `query_all` if the query API request fails.
    """

    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_full_modify: ClassVar[bool] = True
    supports_bulk_modify_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    xe_removal_requires_discovery: ClassVar[bool] = True

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() uses bulk remove
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesRemove

    def model_post_init(self, __context) -> None:
        """Initialize request-local ownership and authoritative vPC-pair caches."""

        super().model_post_init(__context)
        self._member_owners_cache: dict[str, dict[str, str]] = {}
        self._membership_peer_cache: dict[str, str] = {}
        self._accepted_post_write_model: ModelType | None = None

    def _resolve_membership_peer_switch_id(self, switch_id: str) -> str:
        """Return the reciprocal authoritative vPC peer used to orient ownership."""

        cached = self._membership_peer_cache.get(switch_id)
        if cached is not None:
            return cached

        def fetch(source_switch_id: str) -> str:
            cached_peer = self._membership_peer_cache.get(source_switch_id)
            if cached_peer is not None:
                return cached_peer
            api_endpoint = EpVpcPairGet(fabric_name=self.fabric_name, switch_id=source_switch_id)
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            returned_switch_id = result.get("switchId") if isinstance(result, dict) else None
            if returned_switch_id not in (None, "", source_switch_id):
                raise RuntimeError(f"Cannot validate member ownership on switch {source_switch_id!r}: " f"vpcPair returned switchId {returned_switch_id!r}")
            peer_switch_id = result.get("peerSwitchId") if isinstance(result, dict) else None
            if not isinstance(peer_switch_id, str) or not peer_switch_id.strip():
                raise RuntimeError(
                    f"Cannot validate member ownership on switch {source_switch_id!r}: " "authoritative vpcPair record is absent or missing peerSwitchId"
                )
            peer_switch_id = peer_switch_id.strip()
            if peer_switch_id == source_switch_id:
                raise RuntimeError(f"Cannot validate member ownership on switch {source_switch_id!r}: authoritative vpcPair identifies itself as its peer")
            self._membership_peer_cache[source_switch_id] = peer_switch_id
            return peer_switch_id

        peer_switch_id = fetch(switch_id)
        reciprocal_switch_id = fetch(peer_switch_id)
        if reciprocal_switch_id != switch_id:
            raise RuntimeError(
                f"Cannot validate member ownership for vPC pair {switch_id!r}/{peer_switch_id!r}: "
                f"peer reports {reciprocal_switch_id!r} instead of {switch_id!r}"
            )
        return peer_switch_id

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator. Subclasses must override this method
        to return their specific policy types (e.g., `{"accessPoHost"}` for the access orchestrator).

        ## Raises

        ### NotImplementedError

        - Always, if not overridden by a subclass.
        """
        raise NotImplementedError("Subclasses must implement _managed_policy_types()")

    def _prepare_deploy_context(self, model_instance: ModelType, switch_id: str) -> None:
        """Retain exact members even when a workflow defers the eventual deploy."""

        derived = [(member_name, switch_id) for member_name in self._proposed_members(model_instance)]
        match = _XE_PORT_CHANNEL_NAME_RE.match(model_instance.interface_name.lower())
        if match:
            derived.extend(self._operational_port_channel_members(switch_id, int(match.group(1))))
        self._register_deploy_derived_identities(
            model_instance.interface_name,
            switch_id,
            derived,
        )

    def _prepare_no_diff_deploy_context(self, model_instance: ModelType, switch_id: str) -> None:
        """Discover pending former members even when unchanged intent still has other members."""

        if self.deploy:
            self._queue_preview_derived_discovery(model_instance.interface_name, switch_id)

    def _removed_xe_members(self, model_instance: ModelType, switch_id: str, previous_model: ModelType | None = None) -> list[str]:
        """Find only this IOS-XE parent's former members, including staged removals still on the switch."""

        network_os = getattr(getattr(model_instance, "config_data", None), "network_os", None)
        if getattr(network_os, "network_os_type", None) != "ios-xe":
            return []
        match = _XE_PORT_CHANNEL_NAME_RE.fullmatch(model_instance.interface_name.lower())
        if match is None:
            return []

        inventory = self._switch_interfaces_cache.get(switch_id)
        if inventory is None and previous_model is None:
            inventory = self._switch_interfaces(switch_id)
        before: list[str] = []
        if previous_model is not None:
            previous_os = getattr(getattr(previous_model, "config_data", None), "network_os", None)
            if (
                previous_model.interface_name.casefold() != model_instance.interface_name.casefold()
                or previous_model.switch_ip != model_instance.switch_ip
                or getattr(previous_os, "network_os_type", None) != "ios-xe"
            ):
                raise RuntimeError(f"Cannot establish previous IOS-XE membership for {model_instance.interface_name}")
            before = self._proposed_members(previous_model)
        elif inventory is not None:
            record = inventory.get(model_instance.interface_name.casefold())
            record_os = ((record or {}).get("configData") or {}).get("networkOS") or {}
            policy = record_os.get("policy") or {}
            if (
                record
                and record.get("interfaceType") == "portChannel"
                and record_os.get("networkOSType") == "ios-xe"
                and policy.get("policyType") in self._managed_policy_types()
            ):
                raw_ports = policy.get("ports") or []
                if not isinstance(raw_ports, list) or any(not isinstance(name, str) or not name for name in raw_ports):
                    raise RuntimeError(f"Cannot establish previous IOS-XE membership for {model_instance.interface_name}: invalid ports")
                before = raw_ports

        desired = {name.casefold() for name in self._proposed_members(model_instance)}
        operational = [name for name, _sid in self._operational_port_channel_members(switch_id, int(match.group(1)))]
        removed: dict[str, str] = {}
        for name in (*before, *operational):
            if name.casefold() not in desired:
                removed[name.casefold()] = name
        return list(removed.values())

    def _preview_and_queue_removed_xe_members(self, model_instance: ModelType, switch_id: str, members: Sequence[str]) -> bool:
        """Deploy a detached physical member only when its exact preview contains this parent's removal."""

        # Workflow source orchestrators stage intent with deploy=False; their
        # accepted queues are deployed later by the consolidated executor.
        if not members:
            return False
        pairs = [(name, switch_id) for name in members]
        payload = {"interfaces": [{"interfaceName": name, "switchId": switch_id} for name in members]}
        preview = self._preview_interfaces(payload)
        pending, error = self._pending_preview_pairs(preview, pairs)
        if error is not None:
            raise RuntimeError(f"Cannot safely preview removed port-channel members {pairs}: {error}")

        match = _XE_PORT_CHANNEL_NAME_RE.fullmatch(model_instance.interface_name.lower())
        if match is None:
            raise RuntimeError(f"Cannot identify IOS-XE port-channel {model_instance.interface_name}")
        removal = re.compile(rf"no channel-group[ \t]+{match.group(1)}(?:[ \t]+mode[ \t]+(?:active|passive|on))?", re.IGNORECASE)
        for row in preview["configurationDiffs"]:
            pair = self._normalized_interface_pair(row["interfaceName"], row["switchId"])
            if pair not in pending:
                continue
            pending_config = next(item for item in row["combinedConfigs"] if item["configType"].strip().lower() == "pending").get("config")
            if not isinstance(pending_config, str):
                raise RuntimeError(f"Pending config for removed member {pair!r} does not prove channel-group {match.group(1)} removal")
            lines = [line.strip() for line in pending_config.splitlines() if line.strip() and line.strip() not in {"!", "end", "exit"}]
            headers = [line.removeprefix("interface ").strip() for line in lines if line.lower().startswith("interface ")]
            commands = [line for line in lines if not line.lower().startswith("interface ")]
            if len(headers) != 1 or headers[0].casefold() != pair[0]:
                raise RuntimeError(f"Pending config for removed member {pair!r} includes another interface or no exact interface header")
            # ND can also clear the former member's description while detaching
            # it. Never deploy unrelated pending CLI (for example shutdown)
            # merely because the same preview contains a valid detach line.
            detach = [line for line in commands if removal.fullmatch(line)]
            description_clears = [line for line in commands if re.fullmatch(r"no description(?:[ \t]+[^\r\n]+)?", line, re.IGNORECASE)]
            if len(detach) != 1 or len(description_clears) > 1 or len(commands) != len(detach) + len(description_clears):
                raise RuntimeError(f"Pending config for removed member {pair!r} does not prove channel-group {match.group(1)} removal without unrelated CLI")

        if not self.rest_send.check_mode:
            for name, sid in pairs:
                if self._normalized_interface_pair(name, sid) in pending:
                    self._queue_deploy(name, sid)
        return bool(pending)

    def reconcile_no_diff(self, model_instances: Sequence[ModelType]) -> bool:
        """Recover a staged IOS-XE detach even when the parent preview is already converged."""

        parent_pending = super().reconcile_no_diff(model_instances)
        member_pending = False
        if self.deploy:
            for model_instance in model_instances:
                switch_id = self._resolve_switch_id(model_instance.switch_ip)
                removed = self._removed_xe_members(model_instance, switch_id)
                member_pending = self._preview_and_queue_removed_xe_members(model_instance, switch_id, removed) or member_pending
        return parent_pending or member_pending

    def _prepare_bulk_item(self, model_instance: ModelType, switch_id: str, **kwargs) -> None:  # pylint: disable=unused-argument
        """Retain exact parent/member context before a grouped create is sent."""

        self._prepare_deploy_context(model_instance, switch_id)

    def _bulk_full_modify_guard(self, model_instance: ModelType, current: dict[str, Any]) -> bool:
        """Keep member-bearing port-channel updates on singular PUT."""
        current_policy = ((current.get("configData") or {}).get("networkOS") or {}).get("policy") or {}
        desired_policy = ((model_instance.to_payload().get("configData") or {}).get("networkOS") or {}).get("policy") or {}

        def members(policy: dict[str, Any]) -> tuple[str, ...] | None:
            ports = policy.get("ports") or []
            if not isinstance(ports, list) or any(not isinstance(port, str) or not port for port in ports):
                return None
            return tuple(sorted(port.casefold() for port in ports))

        return members(current_policy) == members(desired_policy) == ()

    def create(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Create a port-channel interface configuration. Resolves `switch_ip` from the model instance, injects `switchId`,
        and wraps the payload in an `interfaces` array. Queues a deploy for later bulk execution via `deploy_pending`.

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
            self._prepare_deploy_context(model_instance, switch_id)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return result
        except Exception as e:
            raise RuntimeError(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Update a port-channel interface configuration. Resolves `switch_ip` from the model instance, injects `switchId`
        into the payload. Queues the parent and any proven IOS-XE member detach for later bulk execution via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If the update API request fails.
        """
        self._accepted_post_write_model = None
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            previous_model = kwargs.get("previous_model")
            removed_members = self._removed_xe_members(model_instance, switch_id, previous_model)
            if previous_model is not None:
                self._prepare_deploy_context(previous_model, switch_id)
                if not self._proposed_members(previous_model) and not self._proposed_members(model_instance):
                    self._queue_preview_derived_discovery(model_instance.interface_name, switch_id)
            api_endpoint = self._configure_endpoint(self.update_endpoint(), switch_sn=switch_id)
            api_endpoint.set_identifiers(model_instance.interface_name)
            payload = model_instance.to_payload()
            payload["switchId"] = switch_id
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
            # The PUT is accepted before the optional member preview. Preserve
            # that evidence even if the later read-only preview fails.
            self._accepted_post_write_model = model_instance
            self._prepare_deploy_context(model_instance, switch_id)
            self._queue_deploy(model_instance.interface_name, switch_id)
            if self.deploy or getattr(self, "workflow_deploy_requested", False):
                try:
                    self._preview_and_queue_removed_xe_members(model_instance, switch_id, removed_members)
                except Exception as preview_error:
                    try:
                        observed = self.query_one(model_instance)
                        if (
                            not isinstance(observed, Mapping)
                            or str(observed.get("interfaceName") or "").casefold() != model_instance.interface_name.casefold()
                        ):
                            raise RuntimeError("exact interface identity was not returned")
                        if observed.get("switchId") not in (None, switch_id):
                            raise RuntimeError("exact switch identity was not returned")
                        self._accepted_post_write_model = self.model_class.from_response(
                            {**observed, "interfaceName": model_instance.interface_name, "switchIp": model_instance.switch_ip}
                        )
                    except Exception as readback_error:
                        raise RuntimeError(
                            f"Member preview failed after the port-channel PUT was accepted: {preview_error}; "
                            f"authoritative readback failed: {readback_error}"
                        ) from preview_error
                    raise RuntimeError("Member preview failed after the port-channel PUT was accepted; current ND intent was read back.") from preview_error
            self._accepted_post_write_model = None
            return result
        except Exception as e:
            raise RuntimeError(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def prepare_bulk_modify_context(self, model_instance: ModelType, previous_model: ModelType | None = None) -> None:
        """Retain the same parent/member deployment scope as a singular update."""
        switch_id = self._resolve_switch_id(model_instance.switch_ip)
        if previous_model is not None:
            self._prepare_deploy_context(previous_model, switch_id)
            if not self._proposed_members(previous_model) and not self._proposed_members(model_instance):
                self._queue_preview_derived_discovery(model_instance.interface_name, switch_id)
        self._prepare_deploy_context(model_instance, switch_id)

    def delete(self, model_instance: ModelType, **kwargs) -> None:
        """
        # Summary

        Queue a port-channel interface for deferred bulk removal via `remove_pending` and bulk deploy via
        `deploy_pending`. The remove deletes the port-channel from ND's config; the deploy pushes that removal
        to the switch and reverts member interfaces to their fabric default configuration.

        No API calls are made until `remove_pending` and `deploy_pending` are called after all mutations are complete.

        ## Raises

        ### RuntimeError

        - Via `_resolve_switch_id` if no switch matches `model_instance.switch_ip` in the fabric.
        """
        switch_id = self._resolve_switch_id(model_instance.switch_ip)
        name = self._delete_side_name(model_instance)
        self._prepare_deploy_context(model_instance, switch_id)
        if not self._proposed_members(model_instance):
            self._queue_preview_derived_discovery(name, switch_id)
        self._queue_remove(name, switch_id)
        self._queue_deploy(name, switch_id)

    def create_bulk(self, model_instances: list[ModelType], **kwargs) -> ResponseType:
        """
        # Summary

        Create multiple port-channel interfaces in bulk. Groups by `(switch_id, policy_type)` (`bulk_create_groups`, issue #409) and
        sends one POST per group with the group's port-channels in the `interfaces` array. Deploys are queued per item after each
        accepted POST, so an earlier accepted group's deploys survive a later group's failure (the module's failure-path finalizer ships
        them). Inside a group that fails with a mixed 207, the items the controller accepted are still queued (`_post_bulk_create_group`).

        ## Raises

        ### RuntimeError

        - If any create API request fails, including a 207 Multi-Status response with a failed `DATA.results[]` item (detected by
          `NdV1Strategy.is_success` via `_request`).
        """
        try:
            groups = self.bulk_create_groups(model_instances)
            results = []
            for group_key, items in groups.items():
                results.append(self._post_bulk_create_group(group_key, items))
            return results
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

    def delete_bulk(self, model_instances: list[ModelType], **kwargs) -> None:
        """
        # Summary

        Queue multiple port-channel interfaces for deferred bulk removal and deployment. Each port-channel is queued
        for removal via `remove_pending` and deployment via `deploy_pending`. No API calls are made until those methods
        are called after `manage_state` completes.

        ## Raises

        None
        """
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            name = self._delete_side_name(model_instance)
            self._prepare_deploy_context(model_instance, switch_id)
            if not self._proposed_members(model_instance):
                self._queue_preview_derived_discovery(name, switch_id)
            self._queue_remove(name, switch_id)
            self._queue_deploy(name, switch_id)

    @staticmethod
    def _delete_side_name(model_instance: ModelType) -> str:
        """
        # Summary

        Return the interface name to queue on the delete side (`interfaceActions/remove` + `interfaceActions/deploy`): the model's
        lowercase `interface_name` for NX-OS, and the switch-canonical `Port-channel<N>` for an `ios-xe` port-channel. Both queues get
        the same spelling so the pair identity the failure-path finalizer relies on (`_unsent_delete_pairs`) is preserved.

        ## Raises

        None
        """
        # TODO(4.2.1) xe-port-channel-remove-leaves-switch-interface
        # ND keys the IOS-XE intent record by the lowercase name it echoes but the discovered switch object by `Port-channel<N>`.
        # A remove naming the lowercase record drops the intent and detaches the members only; the configured `interface Port-channel<N>`
        # stays on the Catalyst and ND's diff never lists it. A remove naming the canonical spelling flips the record to `userDefined`
        # and queues `no interface Port-channel<N>` for the next deploy (lab-verified 2026-09-16 on 4.2.1.10; the GUI delete does the
        # same through the per-interface DELETE). NX-OS deletes correctly with either spelling. The deletion is generated only once ND has
        # discovered the deployed interface; that prerequisite is enforced before anything is queued (`_check_xe_removal_discovered`).
        network_os = getattr(getattr(model_instance, "config_data", None), "network_os", None)
        name = model_instance.interface_name
        if getattr(network_os, "network_os_type", None) != "ios-xe":
            return name
        match = _XE_PORT_CHANNEL_NAME_RE.match(name)
        return f"Port-channel{match.group(1)}" if match else name

    def preflight_safety(self, model_instances: Sequence[ModelType]) -> None:
        """Run local platform and member-ownership safety without capability API calls."""
        super().preflight_safety(model_instances)
        self._validate_members_available(model_instances)
        self._validate_xe_member_modes(model_instances)

    def preflight(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Run the inherited capability preflight, then reject any proposed port-channel whose member ethernet is already
        owned by a different port-channel (issue #369), then reject any IOS-XE port-channel whose member's current
        intent policy does not match the port-channel mode (issues #536/#537). Invoked by `NDStateMachine.manage_state`
        for merged/replaced/overridden before any mutation, including in `--check` mode.

        ## Raises

        ### RuntimeError

        - Propagated from `NDBaseInterfaceOrchestrator.preflight` (capability preflight).
        - Via `_validate_members_available` if any proposed member is owned by another port-channel.
        - Via `_validate_xe_member_modes` if any proposed IOS-XE member's current policy mode does not match.
        """
        super().preflight(model_instances)

    @staticmethod
    def _policy_of(iface: dict) -> dict:
        """
        # Summary

        Return the `configData.networkOS.policy` dict of an interface record, or `{}` when any level is missing or an explicit null.

        ## Raises

        None
        """
        network_os = (iface.get("configData") or {}).get("networkOS") or {}
        return network_os.get("policy") or {}

    def _member_owners(self, switch_id: str) -> dict[str, str]:
        """
        # Summary

        Return `{member_name_lower: owning_parent_name}` for every owned ethernet on `switch_id`. Ownership is indexed from
        all supported and protected member-policy descriptors plus every standalone port-channel or pair-aware vPC parent
        member list in the unfiltered inventory. This catches protected policies whose names do not end in ``Member`` and
        temporarily host-shaped physical records that remain claimed by a vPC parent during a controller transition.

        Membership is read from ND intent, not `operData.portChannelId`: ND rejects a conflicting create against intent even
        when the owning port-channel has never been deployed (`operData.portChannelId` is still `-1`).

        ## Raises

        ### RuntimeError

        - Via `_switch_interfaces` if the interface-list API request fails with a non-404 status.
        """
        cached = self._member_owners_cache.get(switch_id)
        if cached is not None:
            return cached

        inventory = self._switch_interfaces(switch_id)
        inventories = {switch_id: inventory}
        has_vpc_parent = False
        declared_peers: set[str] = set()
        for iface in inventory.values():
            if iface.get("interfaceType") != "vpc":
                continue
            has_vpc_parent = True
            raw_peer = self._policy_of(iface).get("peerSwitchId")
            if raw_peer in (None, ""):
                continue
            if not isinstance(raw_peer, str) or not raw_peer.strip():
                raise RuntimeError(
                    f"Cannot validate member ownership on switch {switch_id!r}: " f"vPC {iface.get('interfaceName')!r} has invalid peerSwitchId {raw_peer!r}"
                )
            peer_switch_id = raw_peer.strip()
            if peer_switch_id == switch_id:
                raise RuntimeError(
                    f"Cannot validate member ownership on switch {switch_id!r}: " f"vPC {iface.get('interfaceName')!r} identifies itself as its peer"
                )
            declared_peers.add(peer_switch_id)
        if len(declared_peers) > 1:
            raise RuntimeError(
                f"Cannot validate member ownership on switch {switch_id!r}: " f"vPC records declare conflicting peers {sorted(declared_peers)!r}"
            )

        peer_switch_ids: dict[str, str] = {}
        if has_vpc_parent:
            peer_switch_id = next(iter(declared_peers)) if declared_peers else self._resolve_membership_peer_switch_id(switch_id)
            peer_inventory = self._switch_interfaces(peer_switch_id)
            inventories[peer_switch_id] = peer_inventory
            reciprocal_peers: set[str] = set()
            for iface in peer_inventory.values():
                if iface.get("interfaceType") != "vpc":
                    continue
                raw_peer = self._policy_of(iface).get("peerSwitchId")
                if raw_peer in (None, ""):
                    continue
                if not isinstance(raw_peer, str) or not raw_peer.strip():
                    raise RuntimeError(
                        f"Cannot validate member ownership on switch {peer_switch_id!r}: "
                        f"vPC {iface.get('interfaceName')!r} has invalid peerSwitchId {raw_peer!r}"
                    )
                reciprocal_peers.add(raw_peer.strip())
            if reciprocal_peers and reciprocal_peers != {switch_id}:
                raise RuntimeError(
                    f"Cannot validate member ownership for pair {switch_id!r}/{peer_switch_id!r}: " f"peer inventory declares {sorted(reciprocal_peers)!r}"
                )
            peer_switch_ids = {
                switch_id: peer_switch_id,
                peer_switch_id: switch_id,
            }

        try:
            membership_index = EthernetMembershipIndex(
                inventories,
                peer_switch_ids=peer_switch_ids,
            )
        except MembershipValidationError as exc:
            raise RuntimeError(f"Cannot validate existing member ownership on switch {switch_id!r}: {exc}") from exc

        owners: dict[str, str] = {}
        for (member_switch_id, member_name), member in membership_index.members.items():
            if member_switch_id != switch_id:
                continue
            owners[member_name] = f"unknown parent (member policyType {member.policy_type})"

        for name, iface in inventory.items():
            if iface.get("interfaceType") != "ethernet":
                continue
            claims = membership_index.claiming_parents(switch_id, name)
            if not claims:
                continue
            parent_names = sorted({claim.interface_name for claim in claims})
            owners[name] = parent_names[0] if len(parent_names) == 1 else f"multiple parents ({', '.join(parent_names)})"
        self._member_owners_cache[switch_id] = owners
        return owners

    def _validate_members_available(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Fail fast when a proposed port-channel claims a member ethernet that ND intent already assigns to a different
        port-channel, or that another port-channel in the same task also claims. ND rejects the first case at create with
        an opaque flat HTTP 500 (`Member port <Eth> is a member of <po>, remove <Eth> from <po> first`) after any earlier
        items in the batch have already been accepted; ND would accept the first claimant in the second case and reject the
        second the same way. A member already owned by the port-channel under management is allowed so an idempotent
        re-apply passes. Hard-fails in `--check` mode too: membership comes from the standard interfaces GET, so the
        dry-run answer is reliable.

        Reads the unfiltered per-switch inventory via `_member_owners`, which the state machine's initial `query_all` has
        already cached for every switch in the config, so no additional requests are issued for merged/replaced/overridden.

        Moving a member between two port-channels in one task (remove from A, add to B) is out of scope and reported as a
        conflict: ND checks the create against current intent before the update to A is applied.

        ## Raises

        ### RuntimeError

        - If any proposed member is owned by a different port-channel in ND intent.
        - If two proposed port-channels on the same switch claim the same member.
        - Via `_resolve_switch_id` if a `switch_ip` does not match any switch in the fabric.
        - Via `_member_owners` if the interface-list API request fails.
        """
        # TODO(4.2.1) port-channel-member-conflict-returns-500
        # ND rejects a conflicting member with a flat HTTP 500 {code, message} envelope (no results[]) that masquerades as a
        # transient server error, after any earlier interfaces in the same POST batch were already accepted. This preflight
        # predicts the conflict from intent so the module fails before any write. Keep it even once ND returns a 4xx: it still
        # prevents partial acceptance of earlier batch items.
        conflicts: list[str] = []
        claimed: dict[tuple[str, str], str] = {}
        for model_instance in model_instances:
            ports = self._proposed_members(model_instance)
            if not ports:
                continue
            switch_ip = model_instance.switch_ip
            po_name = model_instance.interface_name
            owners = self._member_owners(self._resolve_switch_id(switch_ip))
            for member in ports:
                key = member.lower()
                owner = owners.get(key)
                if owner and owner.lower() != po_name.lower():
                    conflicts.append(f"(switch_ip={switch_ip}, port-channel={po_name}, member={member}, current owner={owner})")
                prior = claimed.get((switch_ip, key))
                if prior and prior.lower() != po_name.lower():
                    conflicts.append(f"(switch_ip={switch_ip}, member={member} claimed by both {prior} and {po_name} in this task)")
                claimed.setdefault((switch_ip, key), po_name)
        if conflicts:
            raise RuntimeError(
                f"Cannot configure port-channel member(s) already in use in fabric '{self.fabric_name}': {', '.join(conflicts)}. "
                "Remove each member from its current port-channel first."
            )

    def _validate_xe_member_modes(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Fail fast when an IOS-XE port-channel names a member whose current intent policy does not match the port-channel mode. Unlike
        NX-OS, where the port-channel policy re-homes its members, ND requires an `iosXeAccessPoHost` member to already be `iosXeAccess`
        an `iosXeTrunkPoHost` member to be `iosXeTrunkHost` (the fabric default) and an `iosXeL3PortChannel` member to be `iosXeRoutedHost`
        (from the shared membership registry), and rejects the create otherwise: ND 4.2.1 with a flat
        HTTP 500 that masquerades as a transient error, 4.3.1 with a 207 failed item. A member ND already lists as this port-channel's own
        member type (`portChannelId` naming this port-channel) passes so an idempotent re-apply is accepted. A member absent from the
        switch inventory is refused too (ND would otherwise create a phantom record). NX-OS models are skipped. Reads the same cached
        per-switch inventory as `_member_owners`, so no additional requests are issued, and runs in `--check` mode.

        ## Raises

        ### RuntimeError

        - If any IOS-XE member's current policy type does not match, naming the member, its current policy, the required policy and the
          ethernet module that converts it.
        - Via `_resolve_switch_id` / `_switch_interfaces`.
        """
        # TODO(4.2.1) xe-port-channel-member-mode-mismatch
        # ND validates IOS-XE members against their CURRENT intent policy and refuses a mode mismatch (4.2.1: flat 500 {code,message};
        # 4.3.1: 207 failed item). Predicting it here keeps the failure before any write and out of the retry path.
        mismatches: list[str] = []
        for model_instance in model_instances:
            mismatches.extend(self._xe_member_mode_mismatches(model_instance))
        if mismatches:
            raise RuntimeError(
                f"Cannot configure IOS-XE port-channel member(s) whose policy mode does not match in fabric '{self.fabric_name}': {', '.join(mismatches)}."
            )

    def _xe_member_mode_mismatches(self, model_instance: ModelType) -> list[str]:
        """
        # Summary

        Return one formatted mismatch string per proposed member of `model_instance` whose current intent policy does not match the
        IOS-XE host policy required by `model_instance`'s desired policy type. Returns `[]` when the model is not an IOS-XE host
        port-channel type with IOS-XE pre-attach guidance in the shared membership registry (including every NX-OS model), when it claims
        no members, or when every claimed
        member already matches. Helper for `_validate_xe_member_modes`, split out (with `_xe_member_mismatch`) to keep every method
        under the local-variable limit.

        ## Raises

        ### RuntimeError

        - Via `_resolve_switch_id` if a `switch_ip` does not match any switch in the fabric.
        - Via `_switch_interfaces` if the interface-list API request fails.
        """
        requirement = get_member_policy_descriptor_for_parent(self._desired_policy_type(model_instance) or "")
        if requirement is None or requirement.required_host_policy_type is None or requirement.conversion_module is None:
            return []
        ports = self._proposed_members(model_instance)
        if not ports:
            return []
        inventory = self._switch_interfaces(self._resolve_switch_id(model_instance.switch_ip))
        po_name = model_instance.interface_name.lower()
        mismatches = (self._xe_member_mismatch(model_instance, requirement, inventory, po_name, member) for member in ports)
        return [mismatch for mismatch in mismatches if mismatch is not None]

    @staticmethod
    def _xe_member_mismatch(
        model_instance: ModelType,
        requirement: MemberPolicyDescriptor,
        inventory: dict[str, dict],
        po_name: str,
        member: str,
    ) -> str | None:
        """
        # Summary

        Compare one proposed member's current intent policy (from the cached `inventory`) against the shared relationship descriptor
        for `model_instance`'s desired IOS-XE parent policy type, returning a formatted mismatch string when
        it does not match, or `None` when the member is already the required host-side type, or is already this port-channel's own
        member type (`portChannelId` naming `po_name`). Helper for `_xe_member_mode_mismatches`.

        ## Raises

        None
        """
        host_type = requirement.required_host_policy_type
        member_type = requirement.policy_type
        module_name = requirement.conversion_module
        if host_type is None or module_name is None:  # Defensive: the caller filters relationships without pre-attach guidance.
            return None
        record = inventory.get(member.lower())
        policy = PortChannelBaseOrchestrator._policy_of(record) if record else {}
        current = policy.get("policyType")
        owner = str(policy.get("portChannelId") or "").lower()
        if current == host_type or (current == member_type and owner == po_name):
            return None
        current_description = "absent from the switch inventory" if record is None else (current or "no policy")
        return (
            f"(switch_ip={model_instance.switch_ip}, port-channel={model_instance.interface_name}, member={member}, "
            f"current policy={current_description}, required={host_type}; convert it with {module_name} first)"
        )

    @staticmethod
    def _proposed_members(model_instance: ModelType) -> list[str]:
        """
        # Summary

        Return the member interface names a proposed port-channel claims (`config_data.network_os.policy.ports`), or `[]`
        when the item carries no policy or no `ports` (e.g. a `merged` update that leaves membership untouched).

        ## Raises

        None
        """
        config_data = getattr(model_instance, "config_data", None)
        network_os = getattr(config_data, "network_os", None) if config_data is not None else None
        policy = getattr(network_os, "policy", None) if network_os is not None else None
        ports = getattr(policy, "ports", None) if policy is not None else None
        return [port for port in ports or [] if isinstance(port, str) and port]

    def _requested_policy_less_records(self, port_channels: list[dict], switch_ip: str) -> list[dict]:
        """
        # Summary

        Return a parseable copy of every policy-less IOS-XE port-channel record on `switch_ip` that the user explicitly named under
        `state: deleted`; an empty list for every other state. Matching is on the lowercase interface name.

        `query_all` otherwise keeps only records whose `policyType` this orchestrator manages, which hides such a record from the state
        machine, so an explicit delete of it would be skipped as already absent. It is never offered to `state: overridden`: with no
        policy the module cannot prove it owns the interface, so only an item the user named is eligible. The copy drops
        `configData.mode` (the record carries `unknown`, which the model's frozen mode literal rejects) so the model default applies; the
        shared inventory record is left untouched for `preflight`.

        ## Raises

        None
        """
        # TODO(4.2.1) xe-port-channel-remove-leaves-switch-interface
        # A remove issued before ND has discovered a deployed IOS-XE port-channel drops the intent record and pushes nothing; ND then
        # rediscovers the switch object as a record with `networkOSType: ios-xe` and no policy. This is the recovery path: a second
        # `state: deleted` naming the port-channel reaches `_delete_side_name`, whose canonical remove is the one ND acts on.
        if self.rest_send.params.get("state") != "deleted":
            return []
        config_items = self.rest_send.params.get("config") or []
        requested = {str(item.get("interface_name") or "").strip().lower() for item in config_items if item.get("switch_ip") == switch_ip}
        records = []
        for iface in port_channels:
            network_os = (iface.get("configData") or {}).get("networkOS") or {}
            if network_os.get("networkOSType") != "ios-xe" or self._policy_of(iface):
                continue
            if str(iface.get("interfaceName") or "").strip().lower() not in requested:
                continue
            record = dict(iface)
            record["configData"] = {key: value for key, value in iface["configData"].items() if key != "mode"}
            records.append(record)
        return records

    def _can_replay_absent_delete(self, existing_data: dict | None) -> bool:
        """A discovered deletion echo is not a competing port-channel policy.

        After a staged remove, NDFC may rediscover the switch-side Po under its
        canonical spelling with either no policy or the internal
        ``interface_delete`` policy. The managed-policy query does not return
        either echo, but its presence must not suppress an explicit,
        exact-target deploy replay. All other raw records retain the base
        class's foreign-policy protection.
        """

        if existing_data is None:
            return True
        if existing_data.get("interfaceType") != "portChannel":
            return False
        policy = self._policy_of(existing_data)
        if not policy:
            network_os = (existing_data.get("configData") or {}).get("networkOS") or {}
            return network_os.get("networkOSType") == "nx-os"
        return policy.get("policyType") == "userDefined" and policy.get("templateName") == "interface_delete"

    @staticmethod
    def _staged_remove_needs_reissue(preview: Mapping[str, Any], interface_name: str) -> bool:
        """Recognize ND's no-pending echo of a deployed, now-unowned Po.

        An exact preview can report zero pending lines even though its running
        configuration still contains the Po and expected configuration is
        empty.  A second exact remove makes ND generate the missing pending
        ``no interface`` command; an empty preview alone is not convergence.
        """

        rows = preview.get("configurationDiffs")
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], Mapping):
            raise RuntimeError(f"Cannot classify absent port-channel delete preview for {interface_name!r}.")
        configs = rows[0].get("combinedConfigs")
        if not isinstance(configs, list):
            raise RuntimeError(f"Absent port-channel delete preview lacks combinedConfigs for {interface_name!r}.")
        by_type: dict[str, list[Mapping[str, Any]]] = {}
        for config in configs:
            if isinstance(config, Mapping):
                by_type.setdefault(str(config.get("configType") or "").strip().lower(), []).append(config)
        running = by_type.get("running", [])
        expected = by_type.get("expected", [])
        if len(running) != 1 or len(expected) != 1:
            raise RuntimeError(f"Absent port-channel delete preview lacks unique running/expected config for {interface_name!r}.")
        running_lines = running[0].get("lines")
        expected_lines = expected[0].get("lines")
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in (running_lines, expected_lines)):
            raise RuntimeError(f"Absent port-channel delete preview has invalid line counts for {interface_name!r}.")
        if running_lines and expected_lines == 0:
            running_config = running[0].get("config")
            # ND represents a truly absent, undiscovered interface with this
            # one-line message in the "running" slot. It is not switch CLI.
            if running_lines == 1 and running_config == "Interface is not discovered. Current configuration is not available":
                return False
            first_line = running_config.splitlines()[0].strip().casefold() if isinstance(running_config, str) and running_config.splitlines() else ""
            if first_line != f"interface {interface_name}".casefold():
                raise RuntimeError(f"Absent port-channel delete preview does not prove the running identity {interface_name!r}.")
            return True
        return False

    def _reissue_absent_remove(self, interface_name: str, switch_id: str) -> None:
        """Require exact 207 success for one repeat remove before deployment."""

        endpoint = EpManageInterfacesRemove(fabric_name=self.fabric_name)
        recorded = self.rest_send.response_count
        result = self._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data={"interfaces": [{"interfaceName": interface_name, "switchId": switch_id}]},
        )
        rows = result.get("results") if isinstance(result, Mapping) else None
        if self.rest_send.response_count <= recorded or not isinstance(rows, list) or len(rows) != 1:
            raise RuntimeError(f"Repeat remove did not return one exact result for {(interface_name, switch_id)!r}.")
        row = rows[0]
        if (
            not isinstance(row, Mapping)
            or self._normalized_interface_pair(row.get("interfaceName"), row.get("switchId")) != self._normalized_interface_pair(interface_name, switch_id)
            or str(row.get("status") or "").strip().lower() != "success"
        ):
            raise RuntimeError(f"Repeat remove did not prove exact success for {(interface_name, switch_id)!r}.")

    def _validate_pending_absent_delete(self, preview: Mapping[str, Any], interface_name: str, switch_id: str) -> None:
        """Require a parent delete and only proven member resets before replay."""

        match = _XE_PORT_CHANNEL_NAME_RE.fullmatch(interface_name.lower())
        if match is None:
            raise RuntimeError(f"Cannot classify absent port-channel delete identity {interface_name!r}.")
        po_id = match.group(1)
        rows = preview.get("configurationDiffs")
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], Mapping):
            raise RuntimeError(f"Absent port-channel delete preview lacks one exact row for {interface_name!r}.")
        if self._normalized_interface_pair(rows[0].get("interfaceName"), rows[0].get("switchId")) != self._normalized_interface_pair(
            interface_name, switch_id
        ):
            raise RuntimeError(f"Absent port-channel delete preview has the wrong identity for {interface_name!r}.")
        configs = rows[0].get("combinedConfigs")
        if not isinstance(configs, list):
            raise RuntimeError(f"Absent port-channel delete preview lacks combinedConfigs for {interface_name!r}.")
        running = [item.get("config") for item in configs if isinstance(item, Mapping) and str(item.get("configType") or "").strip().lower() == "running"]
        pending = [item.get("config") for item in configs if isinstance(item, Mapping) and str(item.get("configType") or "").strip().lower() == "pending"]
        if len(running) != 1 or len(pending) != 1 or not isinstance(running[0], str) or not isinstance(pending[0], str):
            raise RuntimeError(f"Absent port-channel delete preview lacks unique running/pending CLI for {interface_name!r}.")
        running_lines = [line.strip().casefold() for line in running[0].splitlines() if line.strip()]
        pending_lines = [line.strip().casefold() for line in pending[0].splitlines() if line.strip()]
        parent_header = f"interface {interface_name.casefold()}"
        if not running_lines or running_lines[0] != parent_header or not pending_lines or pending_lines[0] != f"no {parent_header}":
            raise RuntimeError(f"Absent port-channel delete preview does not prove removal of {interface_name!r}.")

        running_members: set[str] = set()
        bare_on_members: set[str] = set()
        running_member = None
        for line in running_lines[1:]:
            if (header := re.fullmatch(r"interface (ethernet[0-9/]+)", line)) is not None:
                running_member = header.group(1)
            elif line.startswith("interface "):
                running_member = None
            elif running_member is not None and re.fullmatch(rf"channel-group {po_id} (?:force )?mode (?:active|passive|on)", line):
                running_members.add(running_member)
            elif running_member is not None and line == f"channel-group {po_id}":
                # NX-OS renders a deployed static (mode on) membership without
                # the mode suffix. Its exact on-mode detach must still be proven.
                running_members.add(running_member)
                bare_on_members.add(running_member)

        allowed_member_command = (
            r"no (?:storm-control (?:action .+|(?:broadcast|multicast|unicast) level .+)"
            r"|switchport (?:access vlan|trunk native vlan) [0-9]+|switchport monitor"
            r"|lacp (?:rate fast|port-priority [0-9]+)|description .+"
            r"|duplex (?:full|half|auto)|speed [0-9]+"
            r"|spanning-tree (?:bpdufilter|bpduguard) (?:enable|disable)"
            r"|load-interval counter [0-9]+ [0-9]+)"
        )
        touched_members: set[str] = set()
        detached_members: set[str] = set()
        current_member = None
        for index, line in enumerate(pending_lines[1:], 1):
            if line == "configure terminal" and index == len(pending_lines) - 1:
                continue
            if (header := re.fullmatch(r"interface (ethernet[0-9/]+)", line)) is not None:
                current_member = header.group(1)
                if current_member not in running_members:
                    raise RuntimeError(f"Absent port-channel delete preview touches an unproven member {current_member!r}.")
                touched_members.add(current_member)
                continue
            if current_member is None:
                raise RuntimeError(f"Absent port-channel delete preview includes an unproven command {line!r}.")
            if current_member in bare_on_members and line == f"no channel-group {po_id} force":
                # ND renders the corresponding static detach without a mode
                # suffix, matching the bare running channel-group command.
                detached_members.add(current_member)
                continue
            detach = re.fullmatch(rf"no channel-group {po_id} force mode (active|passive|on)", line)
            if detach:
                if current_member in bare_on_members and detach.group(1) != "on":
                    raise RuntimeError(f"Absent port-channel delete preview lacks an on-mode detach for {current_member!r}.")
                detached_members.add(current_member)
                continue
            if not (
                re.fullmatch(allowed_member_command, line)
                or re.fullmatch(r"switchport(?: mode trunk| trunk allowed vlan none)?", line)
                or re.fullmatch(r"mtu [0-9]+", line)
                or line in {"spanning-tree port type edge trunk", "no shutdown", "cdp enable"}
            ):
                raise RuntimeError(f"Absent port-channel delete preview includes an unproven member command {line!r}.")
        if touched_members != detached_members:
            raise RuntimeError(f"Absent port-channel delete preview lacks a proven detach for {interface_name!r} members.")

    def reconcile_absent_deletes(self, model_instances: Sequence[ModelType]) -> bool:
        """Recover both pending and no-pending staged NX-OS Po removals."""

        if not self.deploy or not model_instances:
            return False
        would_reissue = False
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing_data = self._switch_interfaces(switch_id).get(model_instance.interface_name.strip().lower())
            if not self._can_replay_absent_delete(existing_data):
                continue
            name = self._delete_side_name(model_instance)
            pair = (name, switch_id)
            payload = {"interfaces": [{"interfaceName": name, "switchId": switch_id}]}
            preview = self._preview_interfaces(payload)
            if isinstance(preview, Mapping) and preview.get("configurationDiffs") == []:
                # A fully removed interface has no exact preview row. The
                # shared absent-delete reconciler treats this as converged.
                continue
            pending_pairs, error = self._pending_preview_pairs(preview, [pair])
            if error is not None:
                raise RuntimeError(f"Cannot safely replay absent port-channel delete for {pair!r}: {error}")
            if pending_pairs:
                self._validate_pending_absent_delete(preview, name, switch_id)
                continue
            if not self._staged_remove_needs_reissue(preview, name):
                continue
            # Keep the IOS-XE canonical-name/discovery workaround separate until
            # the no-pending replay behavior has been qualified on that platform.
            network_os = (existing_data or {}).get("configData", {}).get("networkOS", {})
            if network_os.get("networkOSType") not in (None, "nx-os"):
                raise RuntimeError(f"Cannot safely replay an unqualified IOS-XE no-pending delete for {pair!r}.")
            if self.rest_send.check_mode:
                would_reissue = True
                continue
            self._reissue_absent_remove(name, switch_id)
            refreshed = self._preview_interfaces(payload)
            confirmed, error = self._pending_preview_pairs(refreshed, [pair])
            if error is not None or self._normalized_interface_pair(*pair) not in confirmed:
                raise RuntimeError(f"Repeat remove did not produce exact pending deletion for {pair!r}: {error or 'no pending lines'}.")
            self._validate_pending_absent_delete(refreshed, name, switch_id)
        return super().reconcile_absent_deletes(model_instances) or would_reissue

    def query_one(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Query a single port-channel interface by name on a specific switch.

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

    def query_all(self, model_instance: ModelType | None = None, **kwargs) -> ResponseType:
        """
        # Summary

        Validate the fabric context and query interfaces, filtering for port-channel interfaces with policy types
        managed by this orchestrator (as defined by `_managed_policy_types()`).

        The set of switches queried is determined by `_switches_to_query`: fabric-wide for `state: overridden`,
        and limited to switches named in the user config for all other states.

        Runs `validate_prerequisites` on first call to ensure the fabric exists and is modifiable before returning any data.

        Each switch's interface list is read through the shared `_switch_interfaces` cache, so the unfiltered inventory
        (including member ethernets and port-channels of other policy types) stays available to `preflight` without a
        second fetch.

        Each returned interface dict is enriched with a `switch_ip` field so that the model can be constructed
        with the composite identifier `(switch_ip, interface_name)`.

        ## Raises

        ### RuntimeError

        - If the fabric does not exist on the target ND node.
        - If the fabric is in deployment-freeze mode.
        - If the query API request fails.
        """
        managed_types = self._managed_policy_types()
        try:
            self.validate_prerequisites()
            all_port_channels = []
            for switch_ip, switch_id in self._switches_to_query().items():
                interfaces = list(self._switch_interfaces(switch_id).values())
                port_channels = [iface for iface in interfaces if iface.get("interfaceType") == "portChannel"]
                managed = [iface for iface in port_channels if self._policy_of(iface).get("policyType") in managed_types]
                managed.extend(self._requested_policy_less_records(port_channels, switch_ip))
                for iface in managed:
                    iface["switchIp"] = switch_ip
                all_port_channels.extend(managed)
            return all_port_channels
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e
