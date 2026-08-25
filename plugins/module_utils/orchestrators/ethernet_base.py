# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# pyright: reportAttributeAccessIssue=false
# ModelType is NDBaseModel which lacks interface-specific fields (switch_ip,
# interface_name, config_data). Concrete subclasses always bind ModelType to a
# model that provides these fields, so the accesses are safe at runtime.

"""
Base orchestrator for ethernet interface modules on Nexus Dashboard.

This module provides `EthernetBaseOrchestrator`, which implements shared CRUD operations
for all ethernet interface types (accessHost, trunkHost, routed, etc.) via the ND Manage
Interfaces API. Type-specific orchestrators inherit from this base and provide their own
`model_class` and `_managed_policy_types()`.

Inherits shared interface lifecycle operations (deploy queuing, fabric validation, switch
resolution) from `NDBaseInterfaceOrchestrator` and adds ethernet-specific functionality:
- Normalize-based deletion (physical interfaces cannot be deleted via remove/DELETE)
- Port-channel membership enforcement with a whitelisted field set
- Fabric-wide `query_all()` with per-type policy filtering
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Sequence
from typing import ClassVar

logger = logging.getLogger(__name__)

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesNormalize,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.interface_default_config import InterfaceDefaultConfig
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

ModelType = NDBaseModel


class EthernetBaseOrchestrator(NDBaseInterfaceOrchestrator[ModelType]):
    """
    # Summary

    Base orchestrator for ethernet interface CRUD operations on Nexus Dashboard.

    Provides shared logic for all ethernet interface types. Subclasses must set `model_class` and implement
    `_managed_policy_types()` to define which policy types they manage.

    Supports configuring interfaces across multiple switches in a single task. Each config item
    includes a `switch_ip` that is resolved to a `switchId` via `FabricContext`.

    Mutation methods (`create`, `update`) enforce port-channel membership restrictions and queue deploys
    for bulk execution. Call `deploy_pending` after all mutations are complete.

    ## Raises

    ### RuntimeError

    - Via `validate_prerequisites` if the fabric does not exist or is in deployment-freeze mode.
    - Via `_resolve_switch_id` if no switch matches the given IP in the fabric.
    - Via `_check_port_channel_restrictions` if a non-whitelisted field is modified on a port-channel member.
    - Via `create` if the create API request fails.
    - Via `update` if the update API request fails.
    - Via `remove_pending` if the bulk normalize API request fails.
    - Via `deploy_pending` if the bulk deploy API request fails.
    - Via `query_one` if the query API request fails.
    - Via `query_all` if the query API request fails.
    """

    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() uses bulk normalize
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesPost
    # TODO(4.2.1) physical-interface-delete-unsupported
    # Physical ethernet interfaces cannot be deleted: interfaceActions/remove silently no-ops and the per-interface
    # DELETE returns HTTP 500, so delete is implemented as interfaceActions/normalize with the full int_trunk_host
    # template body (InterfaceDefaultConfig), which resets the interface and drops it from type-specific query filters.
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesNormalize

    PORT_CHANNEL_MODIFIABLE_FIELDS: ClassVar[set[str]] = {"description", "admin_state", "extra_config"}

    def model_post_init(self, __context) -> None:
        """
        # Summary

        Initialize ethernet-specific mutable private state after Pydantic model construction. Extends
        `NDBaseInterfaceOrchestrator.model_post_init` to add the normalize and reset queues (initialized
        the same way as the sibling `_pending_deploys` / `_pending_removes` queues).

        ## Raises

        None
        """
        super().model_post_init(__context)
        self._pending_normalizes: list[tuple[str, str]] = []
        self._pending_resets: list[tuple[str, str]] = []

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator. Subclasses must override this method
        to return their specific policy types (e.g., `{"accessHost"}` for the access orchestrator).

        ## Raises

        ### NotImplementedError

        - Always, if not overridden by a subclass.
        """
        raise NotImplementedError("Subclasses must implement _managed_policy_types()")

    def _queue_normalize(self, interface_name: str, switch_id: str) -> None:
        """
        # Summary

        Queue an `(interface_name, switch_id)` pair for deferred normalization. Call `remove_pending` after all mutations
        are complete to normalize in bulk via `interfaceActions/normalize`.

        ## Raises

        None
        """
        pair = (interface_name, switch_id)
        if pair not in self._pending_normalizes:
            self._pending_normalizes.append(pair)

    @property
    def pending_normalizes(self) -> tuple[tuple[str, str], ...]:
        """Return an immutable view of physical interfaces queued for normalization."""
        return tuple(self._pending_normalizes)

    def queue_normalize_targets(self, targets: Sequence[tuple[str, str]]) -> None:
        """Add pre-resolved physical-interface targets to the normalize queue."""
        for interface_name, switch_id in targets:
            self._queue_normalize(interface_name, switch_id)

    def _queue_reset(self, interface_name: str, switch_id: str) -> None:
        """
        # Summary

        Queue an `(interface_name, switch_id)` pair for deferred per-interface PUT-as-replace reset. Used when the existing
        wire state carries one of `InterfaceDefaultConfig.UNRESETTABLE_FIELDS` (`bandwidth`, `debounceLinkupTimer`,
        `inheritBandwidth`) — the normalize endpoint cannot clear those, so the orchestrator falls back to a per-interface
        PUT with a minimal body that lets ND apply schema defaults. Call `remove_pending` after all mutations are complete
        to flush the queue.

        ## Raises

        None
        """
        pair = (interface_name, switch_id)
        if pair not in self._pending_resets:
            self._pending_resets.append(pair)

    @property
    def pending_resets(self) -> tuple[tuple[str, str], ...]:
        """Return an immutable view of physical interfaces queued for PUT-as-replace reset."""
        return tuple(self._pending_resets)

    def queue_reset_targets(self, targets: Sequence[tuple[str, str]]) -> None:
        """Add pre-resolved physical-interface targets to the reset queue."""
        for interface_name, switch_id in targets:
            self._queue_reset(interface_name, switch_id)

    @staticmethod
    def _has_unresettable_fields(existing_data: dict | None) -> bool:
        """
        # Summary

        Return `True` if the interface's existing wire policy carries any field in `InterfaceDefaultConfig.UNRESETTABLE_FIELDS`
        with a non-null value. These fields persist across `interfaceActions/normalize` because ND's validator rejects 0/null
        on them; the orchestrator routes such interfaces to the PUT-as-replace path on `state: deleted` so they actually clear.

        ## Raises

        None
        """
        if existing_data is None:
            return False
        policy = existing_data.get("configData", {}).get("networkOS", {}).get("policy") or {}
        return any(policy.get(field) is not None for field in InterfaceDefaultConfig.UNRESETTABLE_FIELDS)

    def _existing_interface(self, interface_name: str, switch_id: str) -> dict | None:
        """
        # Summary

        Return the current wire-state dict for `interface_name` on `switch_id`, or `None` when the
        interface is absent from the switch inventory. Backed by the `_switch_interfaces` cache, so
        repeated lookups across `create` / `update` / `create_bulk` add no further requests.

        ## Raises

        ### RuntimeError

        - Via `_switch_interfaces` if the interface-list API request fails.
        """
        return self._switch_interfaces(switch_id).get(interface_name.lower())

    def _check_port_channel_restrictions(self, model_instance: ModelType, existing_data: dict | None = None) -> None:
        """
        # Summary

        Check if the interface is a port-channel member and validate that only whitelisted fields are being modified.
        If the interface is a port-channel member and non-whitelisted fields are being changed, raise `RuntimeError`.

        A field is treated as a "change" only when the proposed value differs from the corresponding value in the
        existing wire-state policy. This matters for `state: merged`, where the state machine passes the post-merge
        model (which carries every existing wire field) — flagging every non-None field would block legitimate
        whitelisted-only changes.

        ## Raises

        ### RuntimeError

        - If the interface is a port-channel member and non-whitelisted fields are being modified.
        """
        port_channel_id = self._existing_port_channel_id(existing_data)
        if port_channel_id is None:
            return

        if model_instance.config_data is None:
            return

        # existing_data is guaranteed non-None here (the helper returns None for a None input).
        if existing_data is None:
            raise AssertionError("existing_data is None despite _existing_port_channel_id returning a value")
        existing_policy = existing_data.get("configData", {}).get("networkOS", {}).get("policy") or {}

        policy = model_instance.config_data.network_os.policy if model_instance.config_data.network_os else None
        if policy is None:
            return

        # Parse the wire policy through the same model so both sides share identical Pydantic coercion before
        # comparison. Comparing the model's typed value (e.g. float 50.0 for a storm-control level, int 10 for
        # access_vlan) directly against the raw wire value (which ND may echo as int 50 or str "50"/"10") would
        # flag an unchanged field as modified (50.0 != "50") and wrongly raise on an idempotent re-run of a
        # port-channel member. from_response() applies the same coercion ND data already round-trips through in
        # query_all, so a value the model could not represent would have failed there first.
        existing_model = type(policy).from_response(existing_policy)

        changed_fields = set()
        for field_name in type(policy).model_fields:
            if field_name == "policy_type":
                continue
            proposed_value = getattr(policy, field_name)
            if proposed_value is None:
                continue
            if proposed_value != getattr(existing_model, field_name):
                changed_fields.add(field_name)

        non_whitelisted = changed_fields - self.PORT_CHANNEL_MODIFIABLE_FIELDS
        if non_whitelisted:
            raise RuntimeError(
                f"Interface {model_instance.interface_name} is a member of port-channel {port_channel_id}. "
                f"The following fields cannot be modified on port-channel members: {sorted(non_whitelisted)}. "
                f"Only these fields can be modified: {sorted(self.PORT_CHANNEL_MODIFIABLE_FIELDS)}."
            )

    @staticmethod
    def _existing_port_channel_id(existing_data: dict | None) -> int | None:
        """
        # Summary

        Return the `portChannelId` value from the interface's `operData`, or `None` when the interface is
        not a port-channel member.

        ND 4.2.1 (lab-verified): every ethernet interface carries `operData.portChannelId`. `-1` means the
        interface is not a member of any port-channel; any other integer is the parent port-channel's ID.
        The field is NOT present in `configData.networkOS.policy` — looking there always returns `None`
        and was the cause of the membership check silently never firing.

        Only a positive integer is treated as membership (NX-OS port-channel IDs are 1-4096). `None`, the
        `-1` sentinel, `0`, and any negative value all return `None`, so every caller can check membership
        uniformly with `is None` / `is not None` and a `0`/non-positive value can never be mistaken for a
        real port-channel by a truthiness test.

        ## Raises

        None
        """
        if existing_data is None:
            return None
        pc_id = existing_data.get("operData", {}).get("portChannelId")
        if not isinstance(pc_id, int) or pc_id < 1:
            return None
        return pc_id

    def _check_port_channel_delete_restriction(self, model_instance: ModelType, existing_data: dict | None) -> None:
        """
        # Summary

        Refuse to normalize an interface that is currently a port-channel member. Normalizing resets the
        interface to the `int_trunk_host` template, which silently strips the channel-group membership
        and detaches the interface from its port-channel — a destructive change that an unsuspecting user
        asking to delete an access-interface configuration almost certainly did not intend.

        ## Raises

        ### RuntimeError

        - If the existing wire state shows the interface is a port-channel member.
        """
        port_channel_id = self._existing_port_channel_id(existing_data)
        if port_channel_id is not None:
            raise RuntimeError(
                f"Interface {model_instance.interface_name} is a member of port-channel {port_channel_id}. "
                f"Refusing to normalize a port-channel member (this would strip its channel-group membership). "
                f"Remove the interface from the port-channel first, then re-run the delete."
            )

    def remove_pending(self) -> ResponseType | None:
        """
        # Summary

        Flush deferred delete-side work. Interfaces queued via `_queue_normalize` are reset in a single bulk
        `interfaceActions/normalize` POST using the `int_trunk_host` template; interfaces queued via `_queue_reset`
        (those whose wire state carries an unresettable Class C field) are reset one-at-a-time via PUT-as-replace.
        After both paths run, the interfaces share `policyType: "trunkHost"` and are invisible to subsequent
        `query_all()` calls on the type-specific filters.

        Physical ethernet interfaces cannot be deleted via `interfaceActions/remove` (silently does nothing for
        physical interfaces) or `DELETE` (returns 500). The normalize endpoint works when given the full
        `int_trunk_host` template defaults with `mode: "trunk"` and `policyType: "trunkHost"`. The PUT path is
        required for `bandwidth` / `debounceLinkupTimer` / `inheritBandwidth` because ND's validator rejects 0/null
        on those three fields, so the normalize template cannot drive them back to default.

        Clears both pending queues after their respective flushes.

        ## Raises

        ### RuntimeError

        - If the bulk normalize request fails. The message names the normalize-queued interfaces (none were reset) and
          any per-interface resets that were consequently not attempted.
        - If a per-interface PUT reset fails (raised by `_reset_interfaces` with partial-state detail).
        """
        if not self._pending_normalizes and not self._pending_resets:
            return None
        results: list = []
        if self._pending_normalizes:
            try:
                normalize_result = self._normalize_interfaces()
            except Exception as e:
                normalized = [name for name, switch_id in self._pending_normalizes]
                not_attempted = [name for name, switch_id in self._pending_resets]
                msg = f"Bulk normalize failed for {normalized}: {e}. None of these interfaces were reset."
                if not_attempted:
                    msg += f" Per-interface resets were not attempted: {not_attempted}."
                raise RuntimeError(msg) from e
            self._pending_normalizes = []
            results.append(normalize_result)
        if self._pending_resets:
            # `_reset_interfaces` raises a RuntimeError carrying precise partial-state detail on failure; let it
            # propagate unwrapped rather than re-interpolate the full (now-stale) pending list as an "everything failed" message.
            reset_results = self._reset_interfaces()
            self._pending_resets = []
            results.extend(reset_results)
        return results

    def _normalize_interfaces(self) -> ResponseType:
        """
        # Summary

        Normalize queued interfaces via `interfaceActions/normalize` using the `InterfaceDefaultConfig` model
        which provides the full `int_trunk_host` template defaults.

        ## Raises

        ### Exception

        - If the normalize API request fails (propagated to caller).
        """
        api_endpoint = EpManageInterfacesNormalize()
        api_endpoint.fabric_name = self.fabric_name
        payload = InterfaceDefaultConfig.to_normalize_payload(self._pending_normalizes)
        return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)

    def _reset_interfaces(self) -> list[ResponseType]:
        """
        # Summary

        Reset queued interfaces one-at-a-time via PUT-as-replace using the minimal `InterfaceDefaultConfig.to_reset_payload`
        body. There is no bulk PUT equivalent — this path runs only for interfaces whose wire state carries an unresettable
        Class C field (`bandwidth`, `debounceLinkupTimer`, `inheritBandwidth`), so the request count stays low in practice.

        Fail-fast: on the first PUT failure the remaining interfaces are not attempted. ND has no rollback for a per-interface
        PUT, so interfaces reset before the failure stay at fabric default; the raised error names which interfaces
        succeeded, which one failed, and which were not attempted so the user can reconcile the partial state.

        ## Raises

        ### RuntimeError

        - If a per-interface PUT request fails. The message names the failed interface, the interfaces successfully reset
          before it (now at fabric default, not rolled back), and the interfaces not attempted.
        """
        results: list[ResponseType] = []
        succeeded: list[str] = []
        for index, (interface_name, switch_id) in enumerate(self._pending_resets):
            api_endpoint = self._configure_endpoint(self.update_endpoint(), switch_sn=switch_id)
            api_endpoint.set_identifiers(interface_name)
            payload = InterfaceDefaultConfig.to_reset_payload(interface_name, switch_id)
            try:
                results.append(self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload))
            except Exception as e:
                not_attempted = [name for name, switch_id in self._pending_resets[index + 1 :]]
                raise RuntimeError(
                    f"Reset failed at {interface_name} on {switch_id}: {e}. "
                    f"Successfully reset before failure: {succeeded or 'none'}. "
                    f"Not attempted: {not_attempted or 'none'}. "
                    f"Interfaces reset before the failure are now at fabric default and were not rolled back."
                ) from e
            succeeded.append(interface_name)
        return results

    def create(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Create an ethernet interface configuration. Resolves `switch_ip` from the model instance, fetches the
        interface's current wire state to enforce port-channel membership restrictions, injects `switchId`, and
        wraps the payload in an `interfaces` array. Queues a deploy for later bulk execution via `deploy_pending`.

        An `existing_data` keyword argument, when supplied, overrides the fetched wire state (used by tests).

        ## Raises

        ### RuntimeError

        - If the interface is a port-channel member and non-whitelisted fields are being modified.
        - If the interface-list query used to resolve port-channel membership fails.
        - If the create API request fails.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing_data = kwargs.get("existing_data") or self._existing_interface(model_instance.interface_name, switch_id)
            self._check_port_channel_restrictions(model_instance, existing_data)
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

        Update an ethernet interface configuration. Resolves `switch_ip` from the model instance, fetches the
        interface's current wire state to enforce port-channel membership restrictions, injects `switchId` into
        the payload. Queues a deploy for later bulk execution via `deploy_pending`.

        An `existing_data` keyword argument, when supplied, overrides the fetched wire state (used by tests).

        ## Raises

        ### RuntimeError

        - If the interface is a port-channel member and non-whitelisted fields are being modified.
        - If the interface-list query used to resolve port-channel membership fails.
        - If the update API request fails.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing_data = kwargs.get("existing_data") or self._existing_interface(model_instance.interface_name, switch_id)
            self._check_port_channel_restrictions(model_instance, existing_data)
            api_endpoint = self._configure_endpoint(self.update_endpoint(), switch_sn=switch_id)
            api_endpoint.set_identifiers(model_instance.interface_name)
            payload = model_instance.to_payload()
            payload["switchId"] = switch_id
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return result
        except Exception as e:
            raise RuntimeError(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Queue an ethernet interface for normalization to the fabric default `int_trunk_host` template. The actual
        normalize API call is deferred to `remove_pending()` for bulk execution via `interfaceActions/normalize`.

        After normalization, the interface has `policyType: "trunkHost"` which removes it from the type-specific
        filters in `query_all()`, making it invisible to this orchestrator on subsequent runs.

        A deploy is also queued to push the normalized config to the switch.

        Refuses to act on a port-channel member: normalizing would strip the channel-group membership and silently
        detach the interface from its port-channel, which is almost never the intent behind a delete request.

        An `existing_data` keyword argument, when supplied, overrides the fetched wire state (used by tests).

        ## Raises

        ### RuntimeError

        - If switch IP resolution fails.
        - If the interface-list query used to resolve port-channel membership fails.
        - If the interface is a port-channel member.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing_data = kwargs.get("existing_data") or self._existing_interface(model_instance.interface_name, switch_id)
            self._check_port_channel_delete_restriction(model_instance, existing_data)
            if self._has_unresettable_fields(existing_data):
                self._queue_reset(model_instance.interface_name, switch_id)
            else:
                self._queue_normalize(model_instance.interface_name, switch_id)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return {}
        except Exception as e:
            raise RuntimeError(f"Delete failed for {model_instance.get_identifier_value()}: {e}") from e

    def create_bulk(self, model_instances: list[ModelType], **kwargs) -> ResponseType:
        """
        # Summary

        Create multiple ethernet interfaces in bulk. Groups interfaces by switch and sends one POST per switch with all
        interfaces in the `interfaces` array, reducing API calls from N to one-per-switch. Each interface's current wire
        state is fetched (one cached `interfaceList` GET per switch) to enforce port-channel membership restrictions.
        Queues deploys for all created interfaces for later bulk execution via `deploy_pending`.

        An `existing_data` keyword argument, when supplied, overrides the fetched wire state (used by tests).

        ## Raises

        ### RuntimeError

        - If any interface is a port-channel member and non-whitelisted fields are being modified.
        - If the interface-list query used to resolve port-channel membership fails.
        - If any create API request fails.
        """
        try:
            groups: dict[str, list[tuple[str, dict]]] = defaultdict(list)
            for model_instance in model_instances:
                switch_id = self._resolve_switch_id(model_instance.switch_ip)
                existing_data = kwargs.get("existing_data") or self._existing_interface(model_instance.interface_name, switch_id)
                self._check_port_channel_restrictions(model_instance, existing_data)
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

        Queue multiple ethernet interfaces for deferred bulk normalization and deployment. Each interface is queued
        for normalization via `remove_pending` (which resets it to the `int_trunk_host` template) and deployment via
        `deploy_pending`. No API calls are made until those methods are called after `manage_state` completes.

        Port-channel members are handled per-state:

        - `state: overridden` — silently skipped (logged at INFO). Fabric-wide convergence should not require the
          user to explicitly list every PC member in the access config just to keep them attached to their bundle.
        - any other state (i.e. user-named `state: deleted` items) — fails fast with `RuntimeError`. The user
          asked for this interface by name, so we refuse loudly rather than silently strip the channel-group
          membership.

        ## Raises

        ### RuntimeError

        - If switch IP resolution fails for any interface.
        - If the interface-list query used to resolve port-channel membership fails.
        - If any interface in the batch is a port-channel member AND `state` is not `overridden`.
        """
        state = self.rest_send.params.get("state") if self.rest_send and self.rest_send.params else None
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing_data = kwargs.get("existing_data") or self._existing_interface(model_instance.interface_name, switch_id)
            port_channel_id = self._existing_port_channel_id(existing_data)
            if port_channel_id is not None:
                if state == "overridden":
                    logger.info(
                        "Skipping port-channel member %s on switch %s (member of port-channel %s) during state:overridden",
                        model_instance.interface_name,
                        model_instance.switch_ip,
                        port_channel_id,
                    )
                    continue
                self._check_port_channel_delete_restriction(model_instance, existing_data)
            if self._has_unresettable_fields(existing_data):
                self._queue_reset(model_instance.interface_name, switch_id)
            else:
                self._queue_normalize(model_instance.interface_name, switch_id)
            self._queue_deploy(model_instance.interface_name, switch_id)

    def query_one(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Query a single ethernet interface by name on a specific switch.

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

        Validate the fabric context and query interfaces, filtering for ethernet interfaces with policy types
        managed by this orchestrator (as defined by `_managed_policy_types()`).

        The set of switches queried is determined by `_switches_to_query`: fabric-wide for `state: overridden`,
        and limited to switches named in the user config for all other states.

        Port-channel member interfaces are included in the results (they exist on the switch and need to be visible
        for port-channel restriction checks in `create` / `update`). `delete_bulk` skips PC members when invoked
        under `state: overridden` so fabric-wide convergence does not detach interfaces from their port-channels.

        Runs `validate_prerequisites` on first call to ensure the fabric exists and is modifiable before returning any data.

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
            all_interfaces = []
            for switch_ip, switch_id in self._switches_to_query().items():
                interfaces = list(self._switch_interfaces(switch_id).values())
                ethernet_interfaces = [iface for iface in interfaces if iface.get("interfaceType") == "ethernet"]
                managed = [
                    iface
                    for iface in ethernet_interfaces
                    if iface.get("configData", {}).get("networkOS", {}).get("policy", {}).get("policyType") in managed_types
                ]
                for iface in managed:
                    iface["switchIp"] = switch_ip
                all_interfaces.extend(managed)
            return all_interfaces
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e
