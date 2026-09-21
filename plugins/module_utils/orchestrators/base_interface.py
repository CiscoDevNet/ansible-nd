# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Base interface orchestrator for Nexus Dashboard.

Provides `NDBaseInterfaceOrchestrator`, an intermediate base class between `NDBaseOrchestrator` and
concrete interface orchestrators (loopback, ethernet, port-channel, etc.). Encapsulates shared
interface lifecycle operations: deploy queuing, bulk deploy/remove via `interfaceActions` endpoints,
switch IP-to-serial resolution, and fabric pre-flight validation via `FabricContext`.

Concrete interface orchestrators inherit from this class and implement their own CRUD methods
with interface-type-specific payload construction and query filtering.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_pending_config import (
    EpManageFabricsSwitchesPendingConfigGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesDeploy,
    EpManageInterfacesRemove,
)
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.interface_capability_preflight import InterfaceCapabilityPreflight
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import ModelType, NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


@dataclass(frozen=True, slots=True)
class BulkCreateGroupKey:
    """
    # Summary

    Grouping key for bulk create: one POST is sent per `(switch_id, policy_type)` group. `policy_type` is `None` for identifier-only
    items with no policy configured.

    ## Raises

    None
    """

    switch_id: str
    policy_type: str | None


@dataclass(frozen=True, slots=True)
class BulkCreateItem:
    """
    # Summary

    A single interface within a bulk-create group: the interface name (for deploy queueing) and its ready-to-send payload.

    ## Raises

    None
    """

    interface_name: str
    payload: dict


class NDBaseInterfaceOrchestrator(NDBaseOrchestrator[ModelType]):
    """
    # Summary

    Base orchestrator for interface CRUD operations on Nexus Dashboard.

    Provides shared infrastructure for all interface types: deploy/remove queuing, bulk deploy/remove
    via `interfaceActions` endpoints, switch IP-to-serial resolution via `FabricContext`, and fabric
    pre-flight validation.

    Concrete interface orchestrators (loopback, ethernet, port-channel, etc.) inherit from this class
    and implement their own CRUD methods with interface-type-specific payload construction and query filtering.

    ## Raises

    ### RuntimeError

    - Via `validate_prerequisites` if the fabric does not exist or is in deployment-freeze mode.
    - Via `_resolve_switch_id` if no switch matches the given IP in the fabric.
    - Via `deploy_pending` if the bulk deploy API request fails.
    - Via `deploy_accepted_mutations` if the failure-path deploy API request fails.
    - Via `remove_pending` if the bulk remove API request fails.
    """

    deploy: bool = False

    # Subclasses opt in to capability preflight by setting BOTH ClassVars (e.g. loopback sets
    # `interface_type = "loopback"` and `interface_mode = "managed"`). Leaving `interface_type` as ""
    # opts out — used by interface types with no capability endpoint (e.g. future breakout).
    interface_type: ClassVar[str] = ""
    interface_mode: ClassVar[str] = ""
    # Subclasses whose delete side removes IOS-XE logical interfaces (`interfaceActions/remove` + deploy) set this so `state: deleted`
    # and `state: overridden` refuse a removal ND cannot complete yet (see `_check_xe_removal_discovered`).
    xe_removal_requires_discovery: ClassVar[bool] = False

    _fabric_context: FabricContext | None = None
    _capability_preflight: InterfaceCapabilityPreflight | None = None

    def model_post_init(self, __context) -> None:
        """
        # Summary

        Initialize mutable private state after Pydantic model construction. Pydantic disallows `Field()` on
        underscore-prefixed names, so these are set here to ensure each instance gets its own container: the
        deploy/remove queues, the `_deploy_attempted` stage flag read by `deploy_accepted_mutations`, and the per-switch interface
        cache read by `_switch_interfaces`.

        ## Raises

        None
        """
        self._pending_deploys: list[tuple[str, str]] = []
        self._pending_removes: list[tuple[str, str]] = []
        self._deploy_attempted: bool = False
        self._switch_interfaces_cache: dict[str, dict[str, dict]] = {}

    def apply_config_actions(self, params: Mapping[str, Any]) -> bool:
        """
        # Summary

        Set `deploy` from the module's `config_actions` params and return the resolved value. This is the single bridge between the shared
        `config_actions_spec(include=("deploy",))` argument fragment and the orchestrator, so every `nd_interface_*` module resolves the
        deploy flag the same way. Deployment is opt-in: when `config_actions` is absent, `None`, or empty, `deploy` is `False`.

        ## Raises

        None
        """
        config_actions = params.get("config_actions") or {}
        self.deploy = bool(config_actions.get("deploy", False))
        return self.deploy

    @property
    def fabric_name(self) -> str:
        """
        # Summary

        Return `fabric_name` from module params.

        ## Raises

        None
        """
        return self.rest_send.params.get("fabric_name")

    @property
    def fabric_context(self) -> FabricContext:
        """
        # Summary

        Return a lazily-initialized `FabricContext` for this orchestrator's fabric.

        ## Raises

        None
        """
        if self._fabric_context is None:
            self._fabric_context = FabricContext(rest_send=self.rest_send, fabric_name=self.fabric_name)
        return self._fabric_context

    def _resolve_switch_id(self, switch_ip: str) -> str:
        """
        # Summary

        Resolve a `switch_ip` to its `switchId` via `FabricContext`.

        ## Raises

        ### RuntimeError

        - If no switch matches the given IP in the fabric.
        """
        return self.fabric_context.get_switch_id(switch_ip)

    def _switch_interfaces(self, switch_id: str) -> dict[str, dict]:
        """
        # Summary

        Return every interface on `switch_id`, keyed by lower-cased interface name. The underlying
        `interfaceList` GET is issued at most once per switch per module run; the result is cached so
        that `query_all` and any other per-interface lookups (e.g. ethernet's port-channel membership
        check) share a single fetch per switch rather than each querying the controller independently.

        Requires the subclass's `query_all_endpoint` to be the per-switch interfaces-list GET
        (`EpManageInterfacesListGet`). Subclasses whose `query_all_endpoint` targets a different
        resource (e.g. `MaintenanceModeOrchestrator`, which lists switches) must not call this method.

        ## Raises

        ### RuntimeError

        - Via `_request` if the interface-list API request fails with a non-404 status.
        """
        if switch_id not in self._switch_interfaces_cache:
            api_endpoint = self._configure_endpoint(self.query_all_endpoint(), switch_sn=switch_id)
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            interfaces = result.get("interfaces", []) or [] if isinstance(result, dict) else []
            self._switch_interfaces_cache[switch_id] = {iface["interfaceName"].lower(): iface for iface in interfaces if iface.get("interfaceName")}
        return self._switch_interfaces_cache[switch_id]

    def _switches_to_query(self) -> dict[str, str]:
        """
        # Summary

        Return the `{switch_ip: switch_id}` subset that `query_all` should scan.

        For `state: overridden` the scope is fabric-wide, so the full switch map is returned. For every other state
        the state machine only consults existing interfaces identified by `switch_ip` values present in the user
        config, so only those switches are returned. This keeps the interface-list request count proportional to
        config size rather than fabric size (CLAUDE.md performance rule: no per-switch fan-out over the whole fabric).

        ## Raises

        ### RuntimeError

        - Via `FabricContext.switch_map` if the switches API query fails.
        """
        switch_map = self.fabric_context.switch_map
        if self.rest_send.params.get("state") == "overridden":
            return switch_map
        config_items = self.rest_send.params.get("config") or []
        config_ips = {item.get("switch_ip") for item in config_items if item.get("switch_ip")}
        return {ip: sid for ip, sid in switch_map.items() if ip in config_ips}

    @staticmethod
    def _desired_policy_type(model_instance: ModelType) -> str | None:
        """
        # Summary

        Return the wire `policyType` a proposed model carries at `config_data.network_os.policy.policy_type`, as a plain string, or
        `None` when any level is absent (an identifier-only item). Tolerates an `Enum`-typed field by reading its `.value`.

        ## Raises

        None
        """
        config_data = getattr(model_instance, "config_data", None)
        network_os = getattr(config_data, "network_os", None) if config_data is not None else None
        policy = getattr(network_os, "policy", None) if network_os is not None else None
        policy_type = getattr(policy, "policy_type", None) if policy is not None else None
        if not policy_type:
            return None
        return str(getattr(policy_type, "value", policy_type))

    def _prepare_bulk_item(self, model_instance: ModelType, switch_id: str, **kwargs) -> None:  # pylint: disable=unused-argument
        """
        # Summary

        Hook run by `bulk_create_groups` for each model after its switch is resolved and before its payload is built. The base
        implementation does nothing; an orchestrator with per-item write guards (fabric ownership, member restrictions) overrides it.

        ## Raises

        None
        """
        return None

    def bulk_create_groups(self, model_instances: Sequence[ModelType], **kwargs) -> dict[BulkCreateGroupKey, list[BulkCreateItem]]:
        """
        # Summary

        Build the bulk-create groups: resolve each model's `switch_ip` to a `switchId`, run `_prepare_bulk_item`, inject the `switchId`
        into the payload, and group the resulting items by `(switch_id, policy_type)`. Group insertion order follows the first model of
        each group. Shared by every orchestrator that posts `interfaces[]` bodies (issue #409).

        ## Raises

        ### RuntimeError

        - Via `_resolve_switch_id` if no switch matches a model's `switch_ip` in the fabric.
        - Propagated from a subclass `_prepare_bulk_item`.
        """
        # TODO(4.2.1) bulk-interface-create-rejects-mixed-policy-types
        # ND rejects an interfaces[] array mixing policyType values (207 with a single failed item; nothing is created), even though
        # the create schema allows mixed arrays. One POST per (switch, policyType).
        groups: dict[BulkCreateGroupKey, list[BulkCreateItem]] = defaultdict(list)
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            self._prepare_bulk_item(model_instance, switch_id, **kwargs)
            payload = model_instance.to_payload()
            payload["switchId"] = switch_id
            group_key = BulkCreateGroupKey(switch_id=switch_id, policy_type=self._desired_policy_type(model_instance))
            groups[group_key].append(BulkCreateItem(interface_name=model_instance.interface_name, payload=payload))
        return dict(groups)

    def _post_bulk_create_group(self, group_key: BulkCreateGroupKey, items: list[BulkCreateItem]) -> ResponseType:
        """
        # Summary

        Send one bulk-create POST for a `(switch_id, policy_type)` group and queue a deploy for every item the controller accepted.
        On success that is the whole group, in request order.

        The endpoint answers HTTP 207 with an independent `results[]` status per interface, so one create can be accepted while a
        sibling in the same request is rejected. On a failed request, the items the response reports as an exact `success`
        (`_accepted_multistatus_names`, keyed by `name`) are queued before the error propagates, so the module's failure-path finalizer
        (`deploy_accepted_mutations`) ships them rather than stranding them staged, where a retry would classify them as unchanged and
        never deploy them. Names are matched case-insensitively and the queued pair keeps the module's identifier: ND echoes the
        switch-canonical spelling for some interface families (`Port-channel101` for a submitted `port-channel101`). The response is
        consulted only when the request recorded a new one: a sender exception leaves the previous response in place (issue #554), which
        must not be mistaken for this request's result.

        A failure that is not a 207 can still have committed part of the group: ND 4.2.1 answers a flat HTTP 500 naming only the failing
        item and creates the valid ones ahead of it. For that shape the items are recovered from the switch inventory instead
        (`_created_despite_failure`): one GET, on the failure path only.

        ## Raises

        ### RuntimeError

        - If the orchestrator defines no `create_bulk_endpoint`.
        - If the create request fails but the controller accepted (207) or created (any other failure) part of the group. The message
          names those items.

        ### Exception

        - Propagated unchanged from `_request` for every other failure.
        """
        endpoint_class = self.create_bulk_endpoint
        if endpoint_class is None:
            raise RuntimeError(f"'{self.__class__.__name__}' cannot bulk create: 'create_bulk_endpoint' is not defined.")
        api_endpoint = self._configure_endpoint(endpoint_class(), switch_sn=group_key.switch_id)
        request_body = {"interfaces": [item.payload for item in items]}
        recorded = len(self.rest_send.responses)
        cached_before = self._switch_interfaces_cache.get(group_key.switch_id)
        names_before = set(cached_before) if cached_before is not None else None
        try:
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=request_body)
        except Exception as e:
            accepted: list[str] = []
            verb = "accepted"
            if len(self.rest_send.responses) > recorded and self.rest_send.return_code == 207:
                accepted_names = self._accepted_multistatus_names()
                accepted = [item.interface_name for item in items if item.interface_name.strip().lower() in accepted_names]
            else:
                accepted = self._created_despite_failure(group_key.switch_id, items, names_before)
                verb = "created"
            for interface_name in accepted:
                self._queue_deploy(interface_name, group_key.switch_id)
            if accepted:
                raise RuntimeError(f"{e}. The controller {verb} {accepted} from the same request; their deploy stays queued.") from e
            raise
        for item in items:
            self._queue_deploy(item.interface_name, group_key.switch_id)
        return result

    def _created_despite_failure(self, switch_id: str, items: list[BulkCreateItem], names_before: set[str] | None) -> list[str]:
        """
        # Summary

        After a bulk create that failed WITHOUT an HTTP 207, return the submitted interface names the controller created anyway, in
        request order. The switch inventory is dropped from the cache and read once; a name counts only when it exists now and was
        absent from `names_before`, the lower-cased names of the inventory cached before the request. Presence alone proves nothing
        for an interface that already existed (e.g. a system-provisioned one the user merely named, which ND refuses as "already in
        use"), so with no cached "before" (`names_before is None`) the recovery is skipped and no request is made.

        The re-read never masks the create failure: if it fails, an empty list is returned and the cache entry stays dropped, so a
        later reader fetches fresh data (the request may have changed the switch either way).

        ## Raises

        None
        """
        # TODO(4.2.1) bulk-interface-create-500-partial-commit
        # ND 4.2.1 answers a bulk create whose array holds one failing item with a flat HTTP 500 that names only that item, and still
        # commits the valid items ahead of it; there is no `results[]` to read. ND 4.3.1 answers the same request with a 207. Without
        # this recovery the committed items stay staged and a retry reads them as unchanged (lab-verified 2026-09-21, 4.2.1.10).
        if names_before is None:
            return []
        self._switch_interfaces_cache.pop(switch_id, None)
        try:
            names_now = self._switch_interfaces(switch_id)
        except Exception:  # pylint: disable=broad-exception-caught
            return []
        created = []
        for item in items:
            name = item.interface_name.strip().lower()
            if name in names_now and name not in names_before:
                created.append(item.interface_name)
        return created

    @property
    def capability_preflight(self) -> InterfaceCapabilityPreflight:
        """
        # Summary

        Return a lazily-initialized `InterfaceCapabilityPreflight` for this orchestrator's fabric. Shares the orchestrator's
        `FabricContext` so error messages for incapable switches are enriched with `switch_ip`.

        ## Raises

        None
        """
        if self._capability_preflight is None:
            self._capability_preflight = InterfaceCapabilityPreflight(
                rest_send=self.rest_send,
                fabric_name=self.fabric_name,
                fabric_context=self.fabric_context,
            )
        return self._capability_preflight

    def preflight(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Pre-mutation validation for the proposed interfaces. Invoked by `NDStateMachine.manage_state` before create/update
        operations — which are skipped in `--check` mode — so a dry run fails on the same input errors a normal run would hit
        inside `create`/`update`. Four steps:

        1. Resolve every `switch_ip` to a `switchId` via `_require_resolvable_switches`. This runs for every interface
           orchestrator, including those that opt out of the capability preflight, so an unknown switch is reported in check
           mode too (PR #550 review).
        2. Platform check via `_check_platform_match`: each proposed `network_os_type` must agree with the `platformType` the
           switch reports in the inventory fetched by step 1, so a mismatch fails in check mode too (PR #558 review).
        3. Capability preflight via `validate_switches_capable`, a no-op unless the orchestrator opts in via the
           `interface_type`/`interface_mode` ClassVars.
        4. For `state: overridden`, the IOS-XE discovery prerequisite on the interfaces the override would remove, via
           `_check_overridden_removals_discovered` (a no-op unless the orchestrator sets `xe_removal_requires_discovery`).

        ## Raises

        ### RuntimeError

        - If one or more `switch_ip` values do not match any switch in the fabric (aggregated into a single message).
        - Propagated from `_check_platform_match` (requested `network_os_type` differs from the switch's `platformType`).
        - Propagated from `validate_switches_capable` (see its docstring).
        - Propagated from `_check_overridden_removals_discovered` (an override would remove an undiscovered IOS-XE interface).
        """
        self._require_resolvable_switches(model_instances)
        self._check_platform_match(model_instances)
        self.validate_switches_capable(model_instances)
        self._check_overridden_removals_discovered(model_instances)

    def preflight_delete(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Pre-mutation validation for `state: deleted`, invoked by `NDStateMachine` with the existing interfaces about to be removed,
        in check mode too. A no-op unless the orchestrator sets `xe_removal_requires_discovery`; then every interface must pass
        `_check_xe_removal_discovered` before anything is queued.

        ## Raises

        ### RuntimeError

        - Via `_resolve_switch_id` if no switch matches a model's `switch_ip` in the fabric.
        - Propagated from `_check_xe_removal_discovered`.
        """
        if not self.xe_removal_requires_discovery:
            return
        self._check_xe_removal_discovered([(model.interface_name, self._resolve_switch_id(model.switch_ip)) for model in model_instances])

    def _check_overridden_removals_discovered(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Apply `_check_xe_removal_discovered` to the interfaces a `state: overridden` run would remove: the managed interfaces
        `query_all` returns that the proposed config does not name. `NDStateMachine` runs no delete preflight for the fabric-wide
        override set and removes only after its creates and updates, so the check belongs here, ahead of every mutation. A no-op for
        every other state and unless the orchestrator sets `xe_removal_requires_discovery`. `query_all` reads the inventory the state
        machine already cached, so this adds no request of its own.

        ## Raises

        ### RuntimeError

        - Propagated from `query_all` and `_check_xe_removal_discovered`.
        """
        if not self.xe_removal_requires_discovery or self.rest_send.params.get("state") != "overridden":
            return
        proposed = {(model.switch_ip, model.interface_name.strip().lower()) for model in model_instances}
        switch_map = self.fabric_context.switch_map
        pairs = []
        for iface in self.query_all() or []:
            if not isinstance(iface, dict):
                continue
            switch_ip = iface.get("switchIp")
            name = str(iface.get("interfaceName") or "")
            if switch_ip in switch_map and (switch_ip, name.strip().lower()) not in proposed:
                pairs.append((name, switch_map[switch_ip]))
        self._check_xe_removal_discovered(pairs)

    def _check_xe_removal_discovered(self, pairs: Sequence[tuple[str, str]]) -> None:
        """
        # Summary

        Fail before any mutation when an IOS-XE interface about to be removed is deployed but not yet discovered by the controller.
        `pairs` are the `(interface_name, switch_id)` removal candidates; names are matched case-insensitively against the cached
        per-switch inventory (`_switch_interfaces`), so the common case costs no request.

        A candidate is discovered when its `operData.operationalStatus` is `up` or `down` (the spec enum is `up` / `down` / `unknown`;
        a missing or unrecognized value counts as not discovered). An undiscovered candidate is one of two things the interface record
        cannot tell apart, so the switch's pending configuration is read once per affected switch to separate them:

        - Its `interface <name>` line is pending: the intent was never deployed (e.g. created with `config_actions.deploy: false`).
          Nothing is on the switch and the removal is safe.
        - It is not pending: the intent is deployed and discovery has not caught up. The removal is refused; the module neither polls
          nor retries, so the caller decides how to wait.

        An undiscovered interface that was deployed and then edited without a deploy also shows pending lines and is let through; the
        explicit-delete recovery of the rediscovered record covers that corner.

        ## Raises

        ### RuntimeError

        - If any candidate is an undiscovered IOS-XE interface absent from its switch's pending configuration. The message names every
          such interface with its `operationalStatus`.
        - Via `_request` if the pending-configuration query fails.
        """
        # TODO(4.2.1) xe-interface-removal-requires-discovery
        # ND generates the switch-side removal of an IOS-XE logical interface (port-channel, SVI, subinterface) only once it has
        # discovered the deployed interface, seconds to tens of seconds after the create deploy. A remove inside that window drops the
        # intent record, the deploy pushes nothing, and the interface stays on the switch (lab-verified 2026-09-21 on 4.2.1.10 and
        # 4.3.1.175). NX-OS is unaffected.
        undiscovered: dict[str, list[tuple[str, str]]] = {}
        for interface_name, switch_id in pairs:
            record = self._switch_interfaces(switch_id).get(interface_name.strip().lower())
            if record is None:
                continue
            network_os = (record.get("configData") or {}).get("networkOS") or {}
            if network_os.get("networkOSType") != "ios-xe":
                continue
            status = str((record.get("operData") or {}).get("operationalStatus") or "").strip().lower()
            if status not in ("up", "down"):
                undiscovered.setdefault(switch_id, []).append((interface_name, status or "missing"))
        blocked: list[str] = []
        for switch_id, candidates in undiscovered.items():
            api_endpoint = self._configure_endpoint(EpManageFabricsSwitchesPendingConfigGet(), switch_sn=switch_id)
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb)
            lines = result.get("pendingConfigs") if isinstance(result, dict) else None
            pending = {str(line).strip().lower() for line in lines or []}
            for interface_name, status in candidates:
                if f"interface {interface_name.strip().lower()}" not in pending:
                    blocked.append(f"{interface_name} on {switch_id} (operationalStatus={status})")
        if blocked:
            raise RuntimeError(
                f"Cannot remove IOS-XE interface(s) {blocked} because Nexus Dashboard has not finished discovering them. "
                "Retry after operationalStatus becomes up or down."
            )

    def _check_platform_match(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Refuse any proposed interface whose `config_data.network_os.network_os_type` disagrees with the `platformType` its switch reports,
        so a `--check` run fails on a platform mismatch exactly like a normal run would when ND rejects the write (PR #558 review). The
        controller rejects the incompatible request before persisting intent, so this guard changes no outcome; it makes the outcome the
        same in both modes and reports it in the module's own words before any request is sent.

        Reads only the switch inventory `_require_resolvable_switches` already fetched (`FabricContext.get_platform_type` is an O(1)
        index lookup), so no request is added. Each unique `(switch_ip, network_os_type)` pair is compared once and every mismatch is
        aggregated into a single `RuntimeError`. A switch that reports no recognizable `platformType`, or a model without a
        `network_os_type`, is skipped: there is no evidence of a mismatch to act on.

        ## Raises

        ### RuntimeError

        - If one or more proposed interfaces request a `network_os_type` that differs from the switch's reported `platformType`.
        """
        by_pair: dict[tuple[str, str], list[str]] = {}
        for model_instance in model_instances:
            network_os = getattr(getattr(model_instance, "config_data", None), "network_os", None)
            requested = getattr(network_os, "network_os_type", None)
            switch_ip = getattr(model_instance, "switch_ip", None)
            if not isinstance(requested, str) or not isinstance(switch_ip, str):
                continue
            by_pair.setdefault((switch_ip, requested), []).append(str(getattr(model_instance, "interface_name", "")))
        mismatches: list[str] = []
        for (switch_ip, requested), interface_names in by_pair.items():
            platform = self.fabric_context.get_platform_type(switch_ip)
            if platform is None or platform.value == requested:
                continue
            mismatches.append(
                f"Switch {switch_ip} reports platformType '{platform.value}', but the requested network_os_type is '{requested}' "
                f"({', '.join(interface_names)})"
            )
        if mismatches:
            raise RuntimeError(f"{'; '.join(mismatches)}. No changes were made.")

    def _require_resolvable_switches(self, model_instances: Sequence[ModelType]) -> set[str]:
        """
        # Summary

        Resolve every `switch_ip` in `model_instances` and return the set of resolved `switchId` values. Unresolvable IPs are
        aggregated into a single `RuntimeError` naming every unknown IP, so a typo on one entry does not mask resolution
        problems on the remaining entries (issue #301). Backed by `FabricContext`, so repeated calls add no requests.

        ## Raises

        ### RuntimeError

        - If one or more `switch_ip` values do not match any switch in the fabric.
        """
        switch_ids: set[str] = set()
        unresolved: list[str] = []
        for model_instance in model_instances:
            switch_ip = model_instance.switch_ip
            try:
                switch_ids.add(self._resolve_switch_id(switch_ip))
            except RuntimeError:
                unresolved.append(switch_ip)
        if unresolved:
            raise RuntimeError(f"Cannot resolve switch_ip to switchId in fabric '{self.fabric_name}' for: {', '.join(sorted(set(unresolved)))}.")
        return switch_ids

    def preflight_create(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Require a policy on every interface being created. ND rejects a policy-less create per-interface (`mode is
        required` / `invalid policyType ''`) and never creates an empty interface, but the failure surfaces as
        `interface[0] '<name>'` inside a generic create error after a round-trip. This guard is local-only and fails
        fast — before the API-backed capability preflight and before any mutation, in check mode too — naming the
        offending `(switch_ip, interface_name)` in module terms (issue #350). Only the initial inventory fetch
        precedes it.

        Invoked by `NDStateMachine` with only the proposed items not present in the existing inventory (the create
        subset), so a `merged`/`replaced` update that legitimately omits a policy already present on the switch is
        never affected. A config item with no `config_data` (identifier only) is correct for `state: deleted`, which
        does not route through this hook. Offenders are aggregated into a single `RuntimeError` so one message names
        every policy-less create item.

        ## Raises

        ### RuntimeError

        - If any create item has no `config_data.network_os.policy`.
        """
        offenders: list[str] = []
        for model_instance in model_instances:
            config_data = getattr(model_instance, "config_data", None)
            network_os = getattr(config_data, "network_os", None) if config_data is not None else None
            policy = getattr(network_os, "policy", None) if network_os is not None else None
            if policy is None:
                offenders.append(f"(switch_ip={model_instance.switch_ip}, interface_name={model_instance.interface_name})")
        if offenders:
            raise RuntimeError(
                f"Cannot create interface(s) without a policy (config_data.network_os.policy is required to create an interface) "
                f"in fabric '{self.fabric_name}': {', '.join(offenders)}. Supply a policy, or use state: deleted to remove an interface."
            )

    def validate_switches_capable(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Pre-flight the set of target switches against the ND `capableSwitches` endpoint for this orchestrator's
        `interface_type` and `interface_mode` ClassVars. A single GET covers every target switch. On failure, raises a
        `RuntimeError` naming every offending switch.

        When `interface_type` is `""` (default on the base class) this method is a no-op — subclasses opt in by setting
        both the `interface_type` and `interface_mode` ClassVars.

        All `switch_ip` values are resolved before the capability check runs; if any are unresolvable, a single aggregate
        `RuntimeError` names every unknown IP so a typo on one entry does not mask resolution or capability problems on
        the remaining entries (issue #301).

        In `--check` mode the capability GET is still issued, but a failure of the capability check itself — whether an
        endpoint outage or one or more incapable switches — is downgraded to a warning rather than re-raised, so dry-runs
        stay green when the unpublished endpoint is unavailable (issue #302). Unresolvable `switch_ip` values are always
        raised, including in check mode, because they reflect user input errors rather than environmental flakiness.

        ## Raises

        ### RuntimeError

        - If one or more switches are not capable of hosting the requested `(interface_type, interface_mode)` pair
          (outside `--check` mode).
        - If the orchestrator sets `interface_type` but leaves `interface_mode` empty.
        - If one or more `switch_ip` values do not match any switch in the fabric (aggregated into a single message).
        - If the underlying capability GET request fails (outside `--check` mode).
        """
        if not self.interface_type:
            return
        if not self.interface_mode:
            raise RuntimeError(
                f"{type(self).__name__} sets interface_type but not interface_mode; both ClassVars are required to enable capability preflight."
            )
        switch_ids = self._require_resolvable_switches(model_instances)
        if not switch_ids:
            return
        try:
            self.capability_preflight.validate(self.interface_type, self.interface_mode, switch_ids)
        except RuntimeError as e:
            if not self.rest_send.check_mode:
                raise
            self.rest_send.warn(f"Capability preflight skipped in check mode: {e}")

    def validate_prerequisites(self) -> None:
        """
        # Summary

        Run pre-flight validation before any CRUD operations. Checks that the fabric exists and is modifiable.

        ## Raises

        ### RuntimeError

        - If the fabric does not exist on the target ND node.
        - If the fabric is in deployment-freeze mode.
        """
        self.fabric_context.validate_for_mutation()

    def _configure_endpoint(self, api_endpoint, switch_sn: str):
        """
        # Summary

        Set `fabric_name` and `switch_sn` on an endpoint instance before path generation.

        ## Raises

        None
        """
        api_endpoint.fabric_name = self.fabric_name
        api_endpoint.switch_sn = switch_sn
        return api_endpoint

    def _queue_deploy(self, interface_name: str, switch_id: str) -> None:
        """
        # Summary

        Queue an `(interface_name, switch_id)` pair for deferred deployment. Call `deploy_pending` after all mutations
        are complete to deploy in bulk.

        ## Raises

        None
        """
        pair = (interface_name, switch_id)
        if pair not in self._pending_deploys:
            self._pending_deploys.append(pair)

    def _queue_remove(self, interface_name: str, switch_id: str) -> None:
        """
        # Summary

        Queue an `(interface_name, switch_id)` pair for deferred bulk removal. Call `remove_pending` after all mutations
        are complete to remove in bulk.

        ## Raises

        None
        """
        pair = (interface_name, switch_id)
        if pair not in self._pending_removes:
            self._pending_removes.append(pair)

    def deploy_pending(self) -> ResponseType | None:
        """
        # Summary

        Deploy all queued interface configurations in a single API call via `interfaceActions/deploy`. Clears the pending
        queue after deployment.

        When `deploy` is `False`, returns `None` without making any API call.

        Sets `_deploy_attempted` before sending so that, if this request fails, the failure-path finalizer
        (`deploy_accepted_mutations`) does not resubmit the identical deployment (PR #547 review).

        ## Raises

        ### RuntimeError

        - If the deploy API request fails. The queue is retained.
        """
        if not self.deploy or not self._pending_deploys:
            return None
        self._deploy_attempted = True
        try:
            result = self._deploy_interfaces(self._pending_deploys)
            self._pending_deploys = []
            return result
        except Exception as e:
            raise RuntimeError(f"Bulk deploy failed for interfaces {self._pending_deploys}: {e}") from e

    def deploy_accepted_mutations(self) -> list[tuple[str, str]]:
        """
        # Summary

        Failure-path finalizer: deploy the queued interfaces whose create/update the controller has already accepted, so a mid-run
        failure does not leave an earlier successful mutation staged-but-undeployed. Without this, a retry classifies the accepted
        interfaces as unchanged (`no_diff`), never re-queues their deploy, and can finish successfully while controller intent and
        switch running state remain divergent (PR #403 review).

        A deploy is queued only after its mutation request succeeds, so every queued pair is controller-accepted intent — except
        pairs queued by the delete paths, which queue the deploy BEFORE `remove_pending` sends the removal / normalize / reset.
        Pairs still present in any deferred-delete queue (`_unsent_delete_pairs`: `_pending_removes` here, plus the normalize /
        reset queues subclasses add) are excluded: their delete intent never reached the controller — the request failed or was
        never attempted — and deploying them would ship whatever unrelated pending intent those interfaces happen to carry
        (PR #550 review). Delete paths dequeue a pair as soon as its request succeeds, so a pair still queued after a failure is
        exactly one that was not accepted.

        Returns the deployed `(interface_name, switch_id)` pairs so the caller can name them in the failure report. Returns an
        empty list without any API call when `deploy` is `False` (staged intent is the documented contract in that case), when
        the normal `deploy_pending` request was already attempted (a failed normal deploy is reported by its own error and must not
        be resubmitted — PR #547 review), or when no accepted-mutation pairs are queued.

        ## Raises

        ### RuntimeError

        - If the failure-path deploy API request fails. The accepted pairs remain queued in that case.
        """
        if not self.deploy or self._deploy_attempted:
            return []
        unsent = self._unsent_delete_pairs()
        accepted = [pair for pair in self._pending_deploys if pair not in unsent]
        if not accepted:
            return []
        try:
            self._deploy_interfaces(accepted)
        except Exception as e:
            raise RuntimeError(f"Failure-path deploy failed for accepted interfaces {accepted}: {e}") from e
        self._pending_deploys = [pair for pair in self._pending_deploys if pair in unsent]
        return accepted

    def _unsent_delete_pairs(self) -> set[tuple[str, str]]:
        """
        # Summary

        Return the `(interface_name, switch_id)` pairs whose delete-side request has not (yet) been accepted by the controller: the
        contents of every deferred-delete queue. The base class has one such queue (`_pending_removes`); subclasses with their own
        deferred queues (ethernet's normalize / reset queues, routed's IOS-XE reset queue) extend the set. Consumed by
        `deploy_accepted_mutations` so the failure-path finalizer never deploys an interface whose reset failed or was never sent.

        ## Raises

        None
        """
        return set(self._pending_removes)

    def _accepted_multistatus_names(self) -> set[str]:
        """
        # Summary

        Return the lower-cased `name` of every `DATA.results[]` item in the most recent response whose `status` is exactly
        `success` (case/whitespace-tolerant). Used after a bulk POST that failed with HTTP 207 Multi-Status to recover the subset
        the controller accepted, so that subset can still be queued for deploy (PR #550 review). On a 207 the per-item status
        vocabulary is unreliable (vault: `multi-status-207-status-field-inconsistent`; issue #397), so only an exact `success`
        is trusted — the same allowlist `NdV1Strategy.is_success` applies when classifying the response. Returns an empty set
        when the last response was not a 207 or carries no `results[]` envelope.

        ## Raises

        None
        """
        if self.rest_send.return_code != 207:
            return set()
        data = self.rest_send.response_current.get("DATA")
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            return set()
        accepted: set[str] = set()
        for item in results:
            if not isinstance(item, dict):
                continue
            if str(item.get("status") or "").strip().lower() != "success":
                continue
            name = item.get("name")
            if isinstance(name, str) and name.strip():
                accepted.add(name.strip().lower())
        return accepted

    def _deploy_interfaces(self, pairs: list[tuple[str, str]]) -> ResponseType:
        """
        # Summary

        Deploy the given interfaces via `interfaceActions/deploy`. Sends the explicit list of `{interfaceName, switchId}` pairs.

        ## Raises

        ### Exception

        - If the deploy API request fails (propagated to caller).
        """
        api_endpoint = EpManageInterfacesDeploy()
        api_endpoint.fabric_name = self.fabric_name
        payload = {"interfaces": [{"interfaceName": name, "switchId": switch_id} for name, switch_id in pairs]}
        return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)

    def _accepted_multistatus_pairs(self) -> set[tuple[str, str]]:
        """
        # Summary

        Return the `(interface_name, switch_id)` pair (name lower-cased) of every `DATA.results[]` item in the most recent response
        whose `status` is exactly `success` (case/whitespace-tolerant). The pair-keyed counterpart of `_accepted_multistatus_names`
        for the bulk endpoints whose 207 items carry `interfaceName` and `switchId` (`interfaceActions/remove`), so the same name on
        two switches is told apart. Only an exact `success` is trusted (vault: `multi-status-207-status-field-inconsistent`; issue
        #397). Returns an empty set when the last response was not a 207 or carries no `results[]` envelope.

        ## Raises

        None
        """
        if self.rest_send.return_code != 207:
            return set()
        data = self.rest_send.response_current.get("DATA")
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            return set()
        accepted: set[tuple[str, str]] = set()
        for item in results:
            if not isinstance(item, dict):
                continue
            if str(item.get("status") or "").strip().lower() != "success":
                continue
            name = item.get("interfaceName")
            switch_id = item.get("switchId")
            if isinstance(name, str) and name.strip() and isinstance(switch_id, str) and switch_id.strip():
                accepted.add((name.strip().lower(), switch_id.strip()))
        return accepted

    def remove_pending(self) -> ResponseType | None:
        """
        # Summary

        Remove all queued interfaces in a single API call via `interfaceActions/remove`. Clears the pending queue after removal.

        Returns `None` without making any API call if the queue is empty.

        The endpoint answers HTTP 207 with an independent `results[]` status per interface, so one removal can succeed while another
        is rejected. On a failed request, the pairs the response reports as an exact `success` (`_accepted_multistatus_pairs`) are
        dequeued — their removal IS on the controller, and the module's failure-path finalizer (`deploy_accepted_mutations`) must
        ship it rather than strand it staged, where a retry would no longer find the interface and never deploy it (PR #547 review).
        Rejected, status-less, and unknown-status pairs stay queued as unsent. The response is consulted only when the request
        recorded a new one: a sender exception leaves the previous response in place (issue #554), which must not be mistaken for
        this request's result.

        ## Raises

        ### RuntimeError

        - If the remove API request fails. The message names the pairs the controller rejected and, for a mixed 207, the pairs it
          accepted from the same request (whose deploy stays queued).
        """
        if not self._pending_removes:
            return None
        submitted = list(self._pending_removes)
        recorded = self.rest_send.response_count
        try:
            result = self._remove_interfaces()
            self._pending_removes = []
            return result
        except Exception as e:
            accepted: list[tuple[str, str]] = []
            if self.rest_send.response_count > recorded:
                accepted_pairs = self._accepted_multistatus_pairs()
                accepted = [pair for pair in submitted if (pair[0].lower(), pair[1]) in accepted_pairs]
                self._pending_removes = [pair for pair in self._pending_removes if pair not in accepted]
            msg = f"Bulk remove failed for interfaces {self._pending_removes}: {e}"
            if accepted:
                msg += f" The controller accepted the removal of {accepted} from the same request; their deploy stays queued."
            raise RuntimeError(msg) from e

    def _remove_interfaces(self) -> ResponseType:
        """
        # Summary

        Remove queued interfaces via `interfaceActions/remove`. Sends the explicit list of `{interfaceName, switchId}` pairs.

        ## Raises

        ### Exception

        - If the remove API request fails (propagated to caller).
        """
        api_endpoint = EpManageInterfacesRemove()
        api_endpoint.fabric_name = self.fabric_name
        payload = {"interfaces": [{"interfaceName": name, "switchId": switch_id} for name, switch_id in self._pending_removes]}
        return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)


def finalize_accepted_intent(orchestrator: NDBaseOrchestrator | None, check_mode: bool, module_log: logging.Logger) -> str:
    """
    # Summary

    Failure-path finalizer shared by the `nd_interface_*` modules (PR #403 review): when a module fails after some mutations
    succeeded, deploy the already-accepted subset via `deploy_accepted_mutations` so it does not remain staged-but-undeployed.
    Without this, a retry classifies the accepted interfaces as unchanged and never deploys them, so controller intent and
    switch running state stay divergent even after a successful retry.

    Call it from every `except` handler in a module's `main()` and append the result to the failure message. It returns a
    sentence naming what was finalized (or reporting that finalization itself failed), or an empty string when there is nothing
    to do: check mode (no mutations were sent), `deploy: false` (staged intent is the documented contract), no accepted
    mutations queued, the failure preceded orchestrator creation (`orchestrator` is `None`), or the orchestrator is not an
    `NDBaseInterfaceOrchestrator`.

    ## Raises

    None (a finalization failure is folded into the returned message so it cannot mask the original error).
    """
    if orchestrator is None or check_mode:
        return ""
    if not isinstance(orchestrator, NDBaseInterfaceOrchestrator):
        return ""
    try:
        deployed = orchestrator.deploy_accepted_mutations()
    except Exception as deploy_error:  # pylint: disable=broad-except
        module_log.exception("Failure-path deploy of accepted mutations failed")
        return f" NOTE: the controller accepted some interface changes before the failure and deploying them also failed; they remain staged: {deploy_error}"
    if not deployed:
        return ""
    names = ", ".join(sorted(f"{name} (switchId {switch_id})" for name, switch_id in deployed))
    return f" NOTE: before the failure, the controller had already accepted changes for interface(s) [{names}]; those changes were deployed."
