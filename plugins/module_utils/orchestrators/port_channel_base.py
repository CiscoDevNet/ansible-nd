# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# pyright: reportAttributeAccessIssue=false
# ModelType is NDBaseModel which lacks interface-specific fields (switch_ip,
# interface_name, config_data). Concrete subclasses always bind ModelType to a
# model that provides these fields, so the accesses are safe at runtime.

"""
Base orchestrator for port-channel interface modules on Nexus Dashboard.

This module provides `PortChannelBaseOrchestrator`, which implements shared CRUD operations
for all port-channel interface types (accessPoHost, trunkPoHost, etc.) via the ND Manage
Interfaces API. Type-specific orchestrators inherit from this base and provide their own
`model_class` and `_managed_policy_types()`.

Inherits shared interface lifecycle operations (deploy queuing, fabric validation, switch
resolution) from `NDBaseInterfaceOrchestrator` and adds port-channel-specific functionality:
- Standard remove-based deletion (port-channels are virtual interfaces and are deletable)
- Fabric-wide `query_all()` filtered by `interfaceType: "portChannel"` and per-type policy filtering
- A member-already-in-use `preflight()` that rejects, before any write, a port-channel whose member ethernet is
  already owned by a different port-channel (issue #369)

Member ethernet interfaces are not managed by this orchestrator — the port-channel policy is the
single source of truth for member configuration via the `ports` list. Member field restrictions
on standalone ethernet modules are enforced separately by the ethernet orchestrators.
"""

from __future__ import annotations

from collections import defaultdict
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
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

ModelType = NDBaseModel


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
    - Via `create` if the create API request fails.
    - Via `update` if the update API request fails.
    - Via `remove_pending` if the bulk remove API request fails.
    - Via `deploy_pending` if the bulk deploy API request fails.
    - Via `query_one` if the query API request fails.
    - Via `query_all` if the query API request fails.
    """

    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True

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

        Return the set of API-side policy type values managed by this orchestrator. Subclasses must override this method
        to return their specific policy types (e.g., `{"accessPoHost"}` for the access orchestrator).

        ## Raises

        ### NotImplementedError

        - Always, if not overridden by a subclass.
        """
        raise NotImplementedError("Subclasses must implement _managed_policy_types()")

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
            self._queue_deploy(model_instance.interface_name, switch_id)
            return result
        except Exception as e:
            raise RuntimeError(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Update a port-channel interface configuration. Resolves `switch_ip` from the model instance, injects `switchId`
        into the payload. Queues a deploy for later bulk execution via `deploy_pending`.

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
        self._queue_remove(model_instance.interface_name, switch_id)
        self._queue_deploy(model_instance.interface_name, switch_id)

    def create_bulk(self, model_instances: list[ModelType], **kwargs) -> ResponseType:
        """
        # Summary

        Create multiple port-channel interfaces in bulk. Groups port-channels by switch and sends one POST per switch
        with all port-channels in the `interfaces` array, reducing API calls from N to one-per-switch. Queues deploys
        for all created port-channels for later bulk execution via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If any create API request fails.
        """
        try:
            groups: dict[str, list[tuple[str, dict]]] = defaultdict(list)
            for model_instance in model_instances:
                switch_id = self._resolve_switch_id(model_instance.switch_ip)
                payload = model_instance.to_payload()
                payload["switchId"] = switch_id
                groups[switch_id].append((model_instance.interface_name, payload))

            results = []
            for switch_id, items in groups.items():
                # Guarded at runtime by @requires_bulk_support("supports_bulk_create")
                api_endpoint = self._configure_endpoint(self.create_bulk_endpoint(), switch_sn=switch_id)  # pyright: ignore[reportOptionalCall]
                request_body = {"interfaces": [payload for interface_name, payload in items]}
                result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=request_body)
                results.append(result)
                for interface_name, payload in items:
                    self._queue_deploy(interface_name, switch_id)
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
            self._queue_remove(model_instance.interface_name, switch_id)
            self._queue_deploy(model_instance.interface_name, switch_id)

    def preflight(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Run the inherited capability preflight, then reject any proposed port-channel whose member ethernet is already
        owned by a different port-channel (issue #369). Invoked by `NDStateMachine.manage_state` for merged/replaced/
        overridden before any mutation, including in `--check` mode.

        ## Raises

        ### RuntimeError

        - Propagated from `NDBaseInterfaceOrchestrator.preflight` (capability preflight).
        - Via `_validate_members_available` if any proposed member is owned by another port-channel.
        """
        super().preflight(model_instances)
        self._validate_members_available(model_instances)

    @staticmethod
    def _policy_of(iface: dict) -> dict:
        """
        # Summary

        Return the `configData.networkOS.policy` dict of an interface record, or `{}` when any level is missing.

        ## Raises

        None
        """
        return iface.get("configData", {}).get("networkOS", {}).get("policy", {}) or {}

    def _member_owners(self, switch_id: str) -> dict[str, str]:
        """
        # Summary

        Return `{member_name_lower: owning_port_channel_name}` for every member ethernet on `switch_id`, derived from the
        `ports` list of every `portChannel` record in the switch's unfiltered inventory -- regardless of policy type, so a
        member of an unmanaged port-channel flavor (e.g. `vpcPeerlinkPo`) is still seen as owned. A member whose own intent
        `policyType` ends in `Member` but that no port-channel record lists is mapped to its policy type (e.g.
        `accessPoMember`) so it is still treated as owned, with the owner reported as unknown.

        Membership is read from ND intent, not `operData.portChannelId`: ND rejects a conflicting create against intent even
        when the owning port-channel has never been deployed (`operData.portChannelId` is still `-1`).

        ## Raises

        ### RuntimeError

        - Via `_switch_interfaces` if the interface-list API request fails with a non-404 status.
        """
        inventory = self._switch_interfaces(switch_id)
        owners: dict[str, str] = {}
        for iface in inventory.values():
            if iface.get("interfaceType") != "portChannel":
                continue
            for member in self._policy_of(iface).get("ports") or []:
                if isinstance(member, str) and member:
                    owners[member.lower()] = iface.get("interfaceName", "")
        for name, iface in inventory.items():
            policy_type = self._policy_of(iface).get("policyType")
            if name not in owners and isinstance(policy_type, str) and policy_type.endswith("Member"):
                owners[name] = f"unknown port-channel (member policyType {policy_type})"
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
                managed = [
                    iface for iface in port_channels if iface.get("configData", {}).get("networkOS", {}).get("policy", {}).get("policyType") in managed_types
                ]
                for iface in managed:
                    iface["switchIp"] = switch_ip
                all_port_channels.extend(managed)
            return all_port_channels
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e
