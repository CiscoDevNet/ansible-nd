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
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from time import sleep
from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_deployment_history import (
    EpManageFabricsSwitchesDeploymentHistoryGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesDeploy,
    EpManageInterfacesPreview,
    EpManageInterfacesRemove,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.interface_pagination import (
    InterfaceOffsetPaginator,
    InterfacePaginationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import (
    FabricContext,
)
from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import build_lucene_expressions
from ansible_collections.cisco.nd.plugins.module_utils.interface_capability_preflight import (
    InterfaceCapabilityPreflight,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    ModelType,
    NDBaseOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import (
    ResponseType,
)

_INTERFACE_HEADER_RE = re.compile(r"(?im)^[ \t]*interface[ \t]+([^ \t\r\n]+)[ \t]*$")
_DEPLOY_DERIVED_INTERFACE_RE = re.compile(
    r"(?i)^(?:ethernet|gigabitethernet|tengigabitethernet|twentyfivegige|fortygigabitethernet|hundredgige|port-channel)[0-9][0-9/.:_-]*$"
)


class _InterfaceSwitchIdentityMismatch(ValueError):
    """Signal a transient mixed-switch row in a switch-scoped inventory."""


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

    - Via `validate_prerequisites` if the fabric does not exist or is owned by
      another controller.
    - For mutation states, also if the fabric is in deployment-freeze mode.
    - Read-only gathered operations remain permitted during deployment freeze.
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
    # Newest deployment-history records read per undiscovered IOS-XE removal candidate (see `_xe_interface_deployed`).
    XE_HISTORY_MAX: ClassVar[int] = 10
    # NDFC can briefly return a mixed-peer interface snapshot immediately after a deployed vPC
    # deletion. Restart the complete paginated read instead of publishing partial or mixed state.
    INTERFACE_INVENTORY_SNAPSHOT_ATTEMPTS: ClassVar[int] = 6
    INTERFACE_INVENTORY_RETRY_DELAY_SECONDS: ClassVar[int] = 2

    # Subclasses opt in to server-side gathered filtering by setting gathered_lucene_spec.
    # _MAX_EXPRESSIONS_PER_SWITCH caps per-switch fan-out and _MAX_TOTAL_REQUESTS caps fabric-wide
    # fan-out: beyond these thresholds a single broad query is cheaper than N targeted ones;
    # the local post-filter guarantees correctness.
    gathered_lucene_spec: ClassVar[Any] = None
    _MAX_EXPRESSIONS_PER_SWITCH: ClassVar[int] = 3
    _MAX_TOTAL_REQUESTS: ClassVar[int] = 300

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
        self._deploy_derived_identities: dict[tuple[str, str], set[tuple[str, str]]] = {}
        self._pending_preview_derived_discovery: set[tuple[str, str]] = set()

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
            paginator = InterfaceOffsetPaginator()

            def fetch_page(offset: int, page_size: int):
                api_endpoint = self._configure_endpoint(self.query_all_endpoint(), switch_sn=switch_id)
                api_endpoint.endpoint_params.max = page_size
                api_endpoint.endpoint_params.offset = offset
                api_endpoint.endpoint_params.sort = "interfaceName:asc"
                return self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)

            def identity(interface: Mapping[str, Any]) -> tuple[str, str]:
                interface_name = interface.get("interfaceName")
                if not isinstance(interface_name, str) or not interface_name:
                    raise ValueError("interfaceName must be a non-empty string")
                returned_switch_id = interface.get("switchId")
                if returned_switch_id is not None:
                    if not isinstance(returned_switch_id, str) or not returned_switch_id:
                        raise ValueError("row switchId must be a non-empty string when supplied")
                    if returned_switch_id != switch_id:
                        raise _InterfaceSwitchIdentityMismatch(f"row switchId {returned_switch_id!r} does not match requested switch {switch_id!r}")
                return switch_id, interface_name.lower()

            interfaces: list[dict[str, Any]] | None = None
            for attempt in range(1, self.INTERFACE_INVENTORY_SNAPSHOT_ATTEMPTS + 1):
                try:
                    interfaces = paginator.collect(
                        fetch_page=fetch_page,
                        identity=identity,
                        context=f"interface inventory for switch {switch_id!r}",
                    )
                    break
                except InterfacePaginationError as error:
                    retryable = isinstance(error.__cause__, _InterfaceSwitchIdentityMismatch)
                    if not retryable or attempt == self.INTERFACE_INVENTORY_SNAPSHOT_ATTEMPTS:
                        raise
                    delay = self.INTERFACE_INVENTORY_RETRY_DELAY_SECONDS * attempt
                    self.rest_send.log.warning(
                        "Interface inventory snapshot %s/%s for switch %r was inconsistent; restarting from offset 0 after %s second(s): %s",
                        attempt,
                        self.INTERFACE_INVENTORY_SNAPSHOT_ATTEMPTS,
                        switch_id,
                        delay,
                        error,
                    )
                    sleep(delay)
            if interfaces is None:
                raise AssertionError("interface inventory retry loop exited unexpectedly")
            self._switch_interfaces_cache[switch_id] = {iface["interfaceName"].lower(): iface for iface in interfaces}
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
            group_key = BulkCreateGroupKey(
                switch_id=switch_id,
                policy_type=self._desired_policy_type(model_instance),
            )
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
        recorded = self.rest_send.response_count
        cached_before = self._switch_interfaces_cache.get(group_key.switch_id)
        names_before = set(cached_before) if cached_before is not None else None
        try:
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=request_body)
        except Exception as e:
            accepted: list[str] = []
            verb = "accepted"
            if self.rest_send.response_count > recorded and self.rest_send.return_code == 207:
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

    def _enforce_gathered_query_limits(
        self,
        query_plan: dict[str, tuple[str, set[str]]],
        base_expression: str,
    ) -> None:
        """
        Limit gathered-state REST fan-out without silently omitting switches.

        Per-switch expression sets that exceed the configured threshold are replaced
        with the broad base expression. If the complete plan still exceeds the total
        request budget, every switch is reduced to one base request.

        Broadening the server query is safe because the generic local gathered filter
        remains the final correctness layer.

        Raises:
            ValueError: If the number of distinct switches alone exceeds the total
                request limit, because one request per switch is the irreducible
                minimum.
        """
        for _switch_id, expressions in query_plan.values():
            if len(expressions) > self._MAX_EXPRESSIONS_PER_SWITCH:
                expressions.clear()
                expressions.add(base_expression)

        total_requests = sum(len(expressions) for _switch_id, expressions in query_plan.values())

        if total_requests > self._MAX_TOTAL_REQUESTS:
            for _switch_id, expressions in query_plan.values():
                expressions.clear()
                expressions.add(base_expression)

            total_requests = len(query_plan)

        if total_requests > self._MAX_TOTAL_REQUESTS:
            raise ValueError(f"Gathered query requires {total_requests} switch requests, exceeding the supported limit of {self._MAX_TOTAL_REQUESTS}.")

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
        cannot tell apart, so `_xe_interface_deployed` asks the switch's deployment history, one GET per such candidate:

        - Its configuration was never pushed, or its last push was a successful `no interface <name>`: nothing is on the switch and the
          removal is safe (e.g. intent created with `config_actions.deploy: false`).
        - Its last push was a create or update, or a removal that did not succeed: the intent is on the switch and discovery has not
          caught up. The removal is refused; the module neither polls nor retries, so the caller decides how to wait.

        Unlike the interface diff or the switch's pending configuration, the history is not rewritten by a later staged edit, so a
        deployed, undiscovered interface that was then edited without a deploy is still refused.

        ## Raises

        ### RuntimeError

        - If any candidate is an undiscovered IOS-XE interface whose deployment history shows it on the switch. The message names
          every such interface with its `operationalStatus`.
        - Via `_request` if a deployment-history query fails.
        """
        # TODO(4.2.1) xe-interface-removal-requires-discovery
        # ND generates the switch-side removal of an IOS-XE logical interface (port-channel, SVI, subinterface) only once it has
        # discovered the deployed interface, seconds to minutes after the create deploy. A remove inside that window drops the
        # intent record, the deploy pushes nothing, and the interface stays on the switch (lab-verified 2026-09-21 on 4.2.1.10 and
        # 4.3.1.175). NX-OS is unaffected. The record reads `unknown` / `Not discovered` whether the intent was deployed or not, the
        # per-interface diff reads all-`insert` for both staged intent and a deployed-undiscovered interface with a staged edit, and
        # the pending configuration lists both; only the per-switch deployment history separates them (lab-verified 2026-09-22).
        blocked: list[str] = []
        for interface_name, switch_id in pairs:
            record = self._switch_interfaces(switch_id).get(interface_name.strip().lower())
            if record is None:
                continue
            network_os = (record.get("configData") or {}).get("networkOS") or {}
            if network_os.get("networkOSType") != "ios-xe":
                continue
            status = str((record.get("operData") or {}).get("operationalStatus") or "").strip().lower()
            if status in ("up", "down"):
                continue
            if self._xe_interface_deployed(interface_name, switch_id):
                blocked.append(f"{interface_name} on {switch_id} (operationalStatus={status or 'missing'})")
        if blocked:
            raise RuntimeError(
                f"Cannot remove IOS-XE interface(s) {blocked} because Nexus Dashboard has not finished discovering them. "
                "Retry after operationalStatus becomes up or down."
            )

    def _xe_interface_deployed(self, interface_name: str, switch_id: str) -> bool:
        """
        # Summary

        Return whether the switch's deployment history says `interface_name`'s configuration is on the switch. One GET of the
        per-switch `deploymentHistory`, filtered to the interface's records (`entityName:<name>`, matched case-insensitively by the
        controller), newest first, at most `XE_HISTORY_MAX` records. Only records whose first pushed line is `interface <name>` or
        `no interface <name>` count; ND files companion pushes under the same entity (an SVI's `vlan <id>` / `no vlan <id>`), which are
        skipped. The newest counted record decides, by its own `completeTimestamp` rather than the response order:

        - none: never deployed -> `False`
        - a successful `no interface <name>`: removed from the switch -> `False`
        - anything else (a create or update push, or a removal that did not succeed): on the switch -> `True`

        A response without `deploymentRecords` counts as no history.

        ## Raises

        ### RuntimeError

        - Via `_request` if the deployment-history query fails.
        """
        name = interface_name.strip().lower()
        api_endpoint = self._configure_endpoint(EpManageFabricsSwitchesDeploymentHistoryGet(), switch_sn=switch_id)
        api_endpoint.endpoint_params.filter = f"entityName:{name}"
        api_endpoint.endpoint_params.sort = "completeTimestamp:desc"
        api_endpoint.endpoint_params.max = self.XE_HISTORY_MAX
        result = self._request(path=api_endpoint.path, verb=api_endpoint.verb)
        records = result.get("deploymentRecords") if isinstance(result, dict) else None
        newest: tuple[str, bool] | None = None  # (timestamp, removed_from_switch)
        for record in records if isinstance(records, list) else []:
            if not isinstance(record, dict):
                continue
            commands = record.get("configCommandResponses") or []
            first = commands[0] if commands and isinstance(commands[0], dict) else {}
            first_line = " ".join(str(first.get("command") or "").split()).lower()
            if first_line == f"interface {name}":
                removed = False
            elif first_line == f"no interface {name}":
                removed = str(record.get("status") or "").strip().lower() == "success"
            else:
                continue
            stamp = str(record.get("completeTimestamp") or record.get("startTimestamp") or "")
            if newest is None or stamp > newest[0]:
                newest = (stamp, removed)
        return newest is not None and not newest[1]

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

        Run pre-flight validation before any CRUD operation.

        Read-only states require that the fabric exists and is accessible through
        the targeted controller. Mutation states additionally require that the
        fabric is not in deployment-freeze mode.

        `query_all()` is the common inventory entry point for every state, so the
        read-versus-mutation decision is derived from the current module state here
        instead of being duplicated in individual interface orchestrators.

        ## Raises

        ### RuntimeError

        - If the fabric does not exist on the target ND node.
        - If the fabric is owned by a different controller in the cluster.
        - If the fabric is in deployment-freeze mode and the current state is not
        read-only.
        """
        if self.is_read_only_operation:
            self.fabric_context.validate_for_read()
            return

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

    def _build_gathered_query_plan(self, gathered_filters: list[dict]) -> dict[str, tuple[str, set[str]]]:
        """
        # Summary

        Build one or more Lucene expressions for each target switch from gathered filters.

        Uses the orchestrator's ``gathered_lucene_spec`` ClassVar to map Ansible filter fields to Lucene
        fields names. Each filter item produces a separate expression (the interface endpoint does not
        reliably support Lucene OR). If a filter item includes ``switch_ip``, only that switch is targeted;
        otherwise all switches in the fabric are queried.

        Per-switch fan-out capping: if more than ``_MAX_EXPRESSIONS_PER_SWITCH`` expressions accumulate
        for one switch, they collapse to the base expression. Fabric-wide filters are additionally budgeted
        against ``_MAX_TOTAL_REQUESTS`` before being expanded across switches. The local post-filter
        guarantees correctness; the server filter only reduces candidate volume.

        ## Raises

        ### ValueError

        - If a filter references a ``switch_ip`` that does not exist in the fabric.
        """
        # TODO(4.2.1) interface-lucene-or-silently-empty
        switch_map = self.fabric_context.switch_map
        query_plan: dict[str, tuple[str, set[str]]] = {}
        base_expression = build_lucene_expressions(filters=[], spec=self.gathered_lucene_spec)[0]

        filter_items = gathered_filters or [{}]

        fabric_wide_filters: list[dict] = []
        switch_scoped_filters: list[tuple[str, str, dict]] = []

        for filter_item in filter_items:
            requested_switch_ip = filter_item.get("switch_ip")
            if requested_switch_ip:
                switch_id = switch_map.get(requested_switch_ip)
                if switch_id is None:
                    raise ValueError(
                        f"Gathered filter references switch_ip '{requested_switch_ip}' " f"which does not exist in fabric '{self.fabric_context.fabric_name}'."
                    )
                switch_scoped_filters.append((requested_switch_ip, switch_id, filter_item))
            else:
                fabric_wide_filters.append(filter_item)

        if fabric_wide_filters:
            fabric_wide_expressions: set[str] | None = set()
            for expression in build_lucene_expressions(fabric_wide_filters, self.gathered_lucene_spec):
                if expression == base_expression:
                    fabric_wide_expressions = {base_expression}
                    break
                fabric_wide_expressions.add(expression)

            # Budget the fabric-wide fan-out before expanding it across every switch.
            if len(switch_map) * len(fabric_wide_expressions) > self._MAX_TOTAL_REQUESTS:
                fabric_wide_expressions = {base_expression}
        else:
            fabric_wide_expressions = None

        if fabric_wide_expressions is not None:
            for switch_ip, switch_id in switch_map.items():
                query_plan[switch_ip] = (switch_id, set(fabric_wide_expressions))

        for switch_ip, switch_id, filter_item in switch_scoped_filters:
            if switch_ip not in query_plan:
                query_plan[switch_ip] = (switch_id, set())
            planned_expressions = query_plan[switch_ip][1]
            for expression in build_lucene_expressions([filter_item], self.gathered_lucene_spec):
                if expression == base_expression:
                    planned_expressions.clear()
                    planned_expressions.add(base_expression)
                elif base_expression not in planned_expressions:
                    planned_expressions.add(expression)

        self._enforce_gathered_query_limits(
            query_plan=query_plan,
            base_expression=base_expression,
        )
        return query_plan

    def _configure_lucene_endpoint(self, api_endpoint) -> None:
        """
        Hook for subclasses to set endpoint-specific params before a Lucene query.

        The default implementation is a no-op. Loopback overrides this to set
        ``config_only = False`` because the full config is needed for local filtering.
        """
        pass

    def _query_interfaces_with_lucene(self, switch_id: str, expression: str) -> list[dict]:
        """
        # Summary

        Execute one paginated Lucene query against the interfaces endpoint for a single switch.

        Pages through results using ``meta.counts.remaining``. Returns raw API dicts (not yet
        enriched with ``switchIp`` or filtered by ``policyType``).

        ## Raises

        ### RuntimeError

        - If pagination exceeds 100 pages (50,000 interfaces), indicating a possible runaway query.
        """
        page_size = 500
        max_pages = 100
        offset = 0
        candidates: list[dict] = []

        for _page_number in range(max_pages):
            api_endpoint = self._configure_endpoint(
                self.query_all_endpoint(),
                switch_sn=switch_id,
            )
            self._configure_lucene_endpoint(api_endpoint)
            api_endpoint.lucene_params.filter = expression
            api_endpoint.lucene_params.max = page_size
            api_endpoint.lucene_params.offset = offset

            result = self._request(
                path=api_endpoint.path,
                verb=api_endpoint.verb,
                not_found_ok=True,
            )
            if not isinstance(result, dict):
                break

            page = result.get("interfaces", []) or []
            candidates.extend(page)

            if not page:
                break

            meta = result.get("meta") or {}
            counts = meta.get("counts") or {}
            remaining_raw = counts.get("remaining")

            if remaining_raw is not None:
                try:
                    remaining = int(remaining_raw)
                except (TypeError, ValueError):
                    remaining = None
            else:
                remaining = None

            if remaining is not None and remaining <= 0:
                break
            if remaining is None and len(page) < page_size:
                break

            offset += len(page)
        else:
            raise RuntimeError(
                f"Pagination limit reached ({max_pages} pages, {len(candidates)} candidates collected) "
                f"for switch '{switch_id}'. Results may be incomplete."
            )
        return candidates

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

    def _register_deploy_derived_identities(
        self,
        interface_name: str,
        switch_id: str,
        derived_pairs: Sequence[tuple[str, str]],
    ) -> None:
        """Record controller result identities that are proven children of one deploy target."""

        parent = self._normalized_interface_pair(interface_name, switch_id)
        if parent is None:
            raise RuntimeError(f"Cannot register invalid deploy identity {(interface_name, switch_id)!r}")
        normalized: set[tuple[str, str]] = set()
        for derived_name, derived_switch_id in derived_pairs:
            derived = self._normalized_interface_pair(derived_name, derived_switch_id)
            if derived is None:
                raise RuntimeError(f"Cannot register invalid derived deploy identity {(derived_name, derived_switch_id)!r}")
            if derived != parent:
                normalized.add(derived)
        # One update can affect children present either before or after the
        # transition (for example, a removed port-channel member is still
        # reported by ND's deploy response).  Accumulate both exact snapshots;
        # never broaden the allow-list beyond identities proven by those
        # parent models.
        self._deploy_derived_identities.setdefault(parent, set()).update(normalized)

    def _operational_port_channel_members(self, switch_id: str, port_channel_id: int) -> list[tuple[str, str]]:
        """Return exact ethernet identities operationally attached to one port-channel.

        Controller intent can run ahead of switch state when a prior invocation
        used ``deploy: false``.  A later parent deploy may therefore report a
        physical member that is absent from the parent's current ``ports`` list.
        The initial, identity-validated switch inventory still records that
        exact running-state relationship in ``operData.portChannelId``.  Expose
        only those same-switch ethernet identities so parent orchestrators can
        register them as preview-required derived deploy evidence.
        """

        if not isinstance(port_channel_id, int) or isinstance(port_channel_id, bool) or port_channel_id < 0:
            return []
        # State-machine planning populates this cache before mutation.  Do not
        # turn deploy-result bookkeeping into an otherwise-unexpected inventory
        # request for direct orchestrator callers.
        inventory = self._switch_interfaces_cache.get(switch_id)
        if inventory is None:
            return []
        members: list[tuple[str, str]] = []
        for record in inventory.values():
            if record.get("interfaceType") != "ethernet":
                continue
            oper_data = record.get("operData") or {}
            if not isinstance(oper_data, Mapping) or oper_data.get("portChannelId") != port_channel_id:
                continue
            interface_name = record.get("interfaceName")
            if isinstance(interface_name, str) and interface_name.strip():
                members.append((interface_name, switch_id))
        return members

    def _prepare_deploy_context(self, model_instance: ModelType, switch_id: str) -> None:
        """Hook for parent orchestrators to register exact derived deploy identities."""

        return None

    def _prepare_no_diff_deploy_context(self, model_instance: ModelType, switch_id: str) -> None:
        """Hook for parent orchestrators to request pending-child discovery."""

        return None

    def _queue_preview_derived_discovery(self, interface_name: str, switch_id: str) -> None:
        """Mark one parent whose pending preview must prove stale switch-side children."""

        parent = self._normalized_interface_pair(interface_name, switch_id)
        if parent is None:
            raise RuntimeError(f"Cannot register invalid preview discovery identity {(interface_name, switch_id)!r}")
        self._pending_preview_derived_discovery.add(parent)

    def _register_pending_preview_derived_identities(
        self,
        result: ResponseType,
        pairs: list[tuple[str, str]],
    ) -> set[tuple[str, str]]:
        """Register exact ethernet children named by valid parent-scoped pending CLI."""

        originals: dict[tuple[str, str], tuple[str, str]] = {}
        for name, switch_id in pairs:
            normalized = self._normalized_interface_pair(name, switch_id)
            if normalized in self._pending_preview_derived_discovery:
                originals[normalized] = (name, switch_id)
        if not originals or not isinstance(result, Mapping):
            return set()
        rows = result.get("configurationDiffs")
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
            return set()

        row_by_pair: dict[tuple[str, str], Mapping[str, Any]] = {}
        for row in rows:
            if not isinstance(row, Mapping):
                return set()
            row_pair = self._normalized_interface_pair(row.get("interfaceName"), row.get("switchId"))
            if row_pair is None or row_pair in row_by_pair:
                return set()
            row_by_pair[row_pair] = row

        verification_pairs = self._preview_verification_pairs(pairs)
        expected_rows: set[tuple[str, str]] = set()
        for name, switch_id in verification_pairs:
            normalized = self._normalized_interface_pair(name, switch_id)
            if normalized is None:
                return set()
            expected_rows.add(normalized)
        if len(expected_rows) != len(verification_pairs):
            return set()
        if set(row_by_pair) != expected_rows:
            return set()

        processed: set[tuple[str, str]] = set()
        for parent, original in originals.items():
            verification: set[tuple[str, str]] = set()
            for name, switch_id in self._preview_verification_pairs([original]):
                normalized = self._normalized_interface_pair(name, switch_id)
                if normalized is not None:
                    verification.add(normalized)
            if not verification or not verification.issubset(row_by_pair):
                continue

            derived: list[tuple[str, str]] = []
            valid = True
            for row_pair in verification:
                row = row_by_pair[row_pair]
                if str(row.get("status") or "").strip().lower() != "success":
                    valid = False
                    break
                combined_configs = row.get("combinedConfigs")
                if not isinstance(combined_configs, Sequence) or isinstance(combined_configs, (str, bytes)):
                    valid = False
                    break
                pending = [
                    entry for entry in combined_configs if isinstance(entry, Mapping) and str(entry.get("configType") or "").strip().lower() == "pending"
                ]
                if len(pending) != 1:
                    valid = False
                    break
                pending_lines = pending[0].get("lines")
                pending_config = pending[0].get("config")
                if not isinstance(pending_lines, int) or isinstance(pending_lines, bool) or pending_lines < 0 or not isinstance(pending_config, str):
                    valid = False
                    break
                inventory = self._switch_interfaces_cache.get(row_pair[1], {})
                for interface_name in _INTERFACE_HEADER_RE.findall(pending_config):
                    record = inventory.get(interface_name.lower())
                    if isinstance(record, Mapping) and record.get("interfaceType") in {"ethernet", "portChannel"}:
                        canonical_name = record.get("interfaceName")
                        if isinstance(canonical_name, str) and canonical_name.strip():
                            derived.append((canonical_name, row_pair[1]))
                            continue
                    # A create preview can name generated child port-channels
                    # before they exist in the pre-mutation inventory cache.
                    # Trust only canonical physical/port-channel interface
                    # headers from the exact parent-scoped preview row.
                    if _DEPLOY_DERIVED_INTERFACE_RE.fullmatch(interface_name.strip()):
                        derived.append((interface_name.strip(), row_pair[1]))
            if not valid:
                continue
            self._register_deploy_derived_identities(original[0], original[1], derived)
            processed.add(parent)

        self._pending_preview_derived_discovery.difference_update(processed)
        return processed

    def _discover_pending_preview_derived_identities(self, pairs: list[tuple[str, str]]) -> None:
        """Preview marked parent transitions before deploy and register exact pending children."""

        marked_pairs = [
            (name, switch_id) for name, switch_id in pairs if self._normalized_interface_pair(name, switch_id) in self._pending_preview_derived_discovery
        ]
        if not marked_pairs:
            return
        payload = {"interfaces": [{"interfaceName": name, "switchId": switch_id} for name, switch_id in marked_pairs]}
        preview = self._preview_interfaces(payload)
        self._register_pending_preview_derived_identities(preview, marked_pairs)

    def _preview_interfaces(self, payload: dict[str, list[dict[str, str]]]) -> ResponseType:
        """Send the read-only interface preview POST, including in check mode.

        ``RestSend`` simulates every non-GET request while Ansible check mode is
        active.  The NDFC preview endpoint is a read-only POST, so simulation
        would discard the controller's ``configurationDiffs`` and make every
        unchanged ``deploy: true`` request look unconverged.  Temporarily bypass
        write suppression for this endpoint only and always restore the caller's
        check-mode setting.
        """

        api_endpoint = EpManageInterfacesPreview()
        api_endpoint.fabric_name = self.fabric_name
        check_mode = self.rest_send.check_mode
        self.rest_send.check_mode = False
        try:
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
        finally:
            self.rest_send.check_mode = check_mode

    def _reconcile_deploy_models(
        self,
        model_instances: Sequence[ModelType],
        *,
        empty_preview_is_converged: bool,
    ) -> bool:
        """Preview exact models and queue unconverged deployment outside check mode."""

        if not self.deploy or not model_instances:
            return False
        pairs: list[tuple[str, str]] = []
        seen_pairs: set[tuple[str, str]] = set()
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            pair = (model_instance.interface_name, switch_id)
            if pair not in seen_pairs:
                pairs.append(pair)
                seen_pairs.add(pair)
            self._prepare_deploy_context(model_instance, switch_id)
            self._prepare_no_diff_deploy_context(model_instance, switch_id)

        payload = {"interfaces": [{"interfaceName": name, "switchId": switch_id} for name, switch_id in pairs]}
        preview = self._preview_interfaces(payload)
        rows = preview.get("configurationDiffs") if isinstance(preview, Mapping) else None
        if empty_preview_is_converged and rows == []:
            return False
        self._register_pending_preview_derived_identities(preview, pairs)
        verification_pairs = self._preview_verification_pairs(pairs)
        pending_pairs, preview_error = self._pending_preview_pairs(preview, verification_pairs)
        if preview_error is not None:
            raise RuntimeError(f"Interface preview cannot safely determine deployment state for {verification_pairs}: {preview_error}")
        deployment_required = bool(pending_pairs)
        if deployment_required and not self.rest_send.check_mode:
            deploy_pairs = self._pending_deploy_pairs(pairs, pending_pairs)
            if not deploy_pairs:
                raise RuntimeError(f"Pending preview identities cannot be mapped to deploy identities for {verification_pairs}")
            for interface_name, switch_id in deploy_pairs:
                self._queue_deploy(interface_name, switch_id)
        return deployment_required

    def _pending_deploy_pairs(self, pairs: list[tuple[str, str]], pending_pairs: set[tuple[str, str]]) -> list[tuple[str, str]]:
        """Map pending switch-scoped preview rows to the submitted deploy identities."""

        return [pair for pair in pairs if self._normalized_interface_pair(*pair) in pending_pairs]

    def reconcile_no_diff(self, model_instances: Sequence[ModelType]) -> bool:
        """Queue unchanged interfaces when preview cannot prove deployment convergence.

        A successful intent mutation can outlive a failed or inconclusive deploy
        response.  A fresh invocation then has no configuration diff.  For an
        explicit ``deploy: true`` replay, preview every unchanged target: exact
        successful rows with zero pending lines need no action; any structurally
        valid but unconverged result is queued for deployment and will pass
        through the normal strict 207/preview verification path.
        """

        return self._reconcile_deploy_models(model_instances, empty_preview_is_converged=False)

    def _can_replay_absent_delete(self, existing_data: dict | None) -> bool:
        """An absent delete may replay only if no raw interface record remains.

        ``query_all`` filters by policy type, so an absent model can still name
        an interface owned by another module. Previewing that identity would
        deploy the other policy's staged configuration.
        """

        return existing_data is None

    def reconcile_absent_deletes(self, model_instances: Sequence[ModelType]) -> bool:
        """Recover an accepted deletion whose switch-side deploy remains pending.

        Explicit ``state: deleted`` retains the exact requested identities even
        after controller intent disappears.  Preview those identities and queue
        a deploy only when pending configuration remains. Check the unfiltered
        switch inventory first: a policy-filtered ``query_all`` cannot establish
        that the name is truly absent. Subclasses may recognize an exact reset
        echo as a safe replay target. A controller that returns an empty preview
        for an eligible target is already converged. Check mode performs only
        the read-only preview and reports whether a normal run would deploy.
        """

        if not self.deploy or not model_instances:
            return False
        replay_targets = []
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing_data = self._switch_interfaces(switch_id).get(model_instance.interface_name.strip().lower())
            if self._can_replay_absent_delete(existing_data):
                replay_targets.append(model_instance)
        return self._reconcile_deploy_models(replay_targets, empty_preview_is_converged=True)

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

        ND 4.3.1 can return HTTP 207 with an empty or incomplete successful `results` array after a successful deploy. When
        that evidence is merely insufficient, verify the applicable switch-scoped identities through `interfaceActions/preview`
        and require exact successful identities with zero pending configuration before returning. Contradictory 207 evidence
        (malformed, failed, duplicate, or unexpected rows) fails closed without preview and preserves the deploy queue. An
        orchestrator may classify unique successful derived-resource rows as insufficient when that controller endpoint is
        documented to expand identities; exact preview convergence is still required in that case.

        ## Raises

        ### Exception

        - If the deploy API request fails (propagated to caller).
        """
        api_endpoint = EpManageInterfacesDeploy()
        api_endpoint.fabric_name = self.fabric_name
        payload = {"interfaces": [{"interfaceName": name, "switchId": switch_id} for name, switch_id in pairs]}
        self._discover_pending_preview_derived_identities(pairs)
        result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
        deploy_return_code = self.rest_send.return_code
        if deploy_return_code == 207:
            # TODO(4.3.1) deploy-207-incomplete-success-results
            deploy_confirmed, deploy_error = self._classify_deploy_results(result, pairs)
            if deploy_error is not None:
                raise RuntimeError(f"Deploy multi-status response is contradictory for {pairs}: {deploy_error}")
            if not deploy_confirmed:
                verification_pairs = self._preview_verification_pairs(pairs)
                self._verify_deployed_pairs_with_preview(verification_pairs, payload)
        return result

    def _preview_verification_pairs(self, pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
        """Return identities whose preview convergence proves the submitted deployment.

        Ordinary interfaces map one-to-one to the submitted list. Pair-aware
        orchestrators override this hook when preview expands one submitted
        resource to additional switch-scoped rows.
        """

        return list(pairs)

    @staticmethod
    def _normalized_interface_pair(interface_name: object, switch_id: object) -> tuple[str, str] | None:
        """Return a comparison key for one response identity, or ``None`` when malformed."""

        if not isinstance(interface_name, str) or not interface_name.strip():
            return None
        if not isinstance(switch_id, str) or not switch_id.strip():
            return None
        return interface_name.strip().lower(), switch_id.strip()

    def _allowed_derived_deploy_pairs(self, pairs: list[tuple[str, str]]) -> set[tuple[str, str]]:
        """Return only derived identities registered for the submitted parents."""

        allowed: set[tuple[str, str]] = set()
        for interface_name, switch_id in pairs:
            parent = self._normalized_interface_pair(interface_name, switch_id)
            if parent is not None:
                allowed.update(self._deploy_derived_identities.get(parent, set()))
        return allowed

    @staticmethod
    def _is_canonical_deploy_child_name(interface_name: str) -> bool:
        """Return whether a controller result names a supported derived interface."""

        return _DEPLOY_DERIVED_INTERFACE_RE.fullmatch(interface_name.strip()) is not None

    def _preview_scoped_unregistered_child_requires_verification(
        self,
        pair: tuple[str, str],
        submitted_pairs: list[tuple[str, str]],
    ) -> bool:
        """Return whether an unregistered child may fall back to strict post-deploy preview.

        Ordinary interfaces require every derived result identity to be proven
        before deployment. Pair-aware orchestrators may override this only for
        controller behavior where a structurally exact pre-deploy preview omits
        one peer's generated children. Returning true never accepts the deploy
        response by itself; it forces exact post-deploy preview verification.
        """

        return False

    def _classify_deploy_results(self, result: ResponseType, pairs: list[tuple[str, str]]) -> tuple[bool, str | None]:
        """Classify deploy evidence as exact, insufficient, or contradictory.

        The boolean is true only when one unique successful result identifies
        every submitted pair. ``(False, None)`` means ND supplied no evidence or
        only a unique successful subset, for which preview may prove convergence.
        A non-``None`` error identifies contradictory evidence that must fail
        closed rather than being replaced by a later preview result.
        """

        expected = {self._normalized_interface_pair(name, switch_id) for name, switch_id in pairs}
        if None in expected or len(expected) != len(pairs):
            return False, "submitted interface identities are invalid or duplicated"
        if not isinstance(result, Mapping):
            return False, None
        if "results" not in result:
            return False, None
        results = result.get("results")
        if not isinstance(results, Sequence) or isinstance(results, (str, bytes)):
            return False, "results is not a list"
        if not results:
            return False, None
        observed: set[tuple[str, str]] = set()
        observed_submitted: set[tuple[str, str]] = set()
        saw_derived_identity = False
        allowed_derived = self._allowed_derived_deploy_pairs(pairs)
        for item in results:
            if not isinstance(item, Mapping):
                return False, "results contains a non-mapping row"
            if str(item.get("status") or "").strip().lower() != "success":
                return False, "results contains a row whose status is not success"
            pair = self._normalized_interface_pair(item.get("interfaceName"), item.get("switchId"))
            if pair is None:
                return (
                    False,
                    "results contains a row without a valid interfaceName and switchId",
                )
            if pair in observed:
                return False, f"results contains duplicate identity {pair!r}"
            observed.add(pair)
            if pair not in expected:
                if pair not in allowed_derived:
                    if not self._preview_scoped_unregistered_child_requires_verification(pair, pairs):
                        return False, f"results contains unexpected identity {pair!r}"
                saw_derived_identity = True
                continue
            observed_submitted.add(pair)
        if saw_derived_identity:
            return False, None
        return observed_submitted == expected, None

    def _verify_deployed_pairs_with_preview(self, pairs: list[tuple[str, str]], payload: dict[str, list[dict[str, str]]]) -> None:
        """Fail closed unless preview proves every pair has no pending configuration."""

        preview = self._preview_interfaces(payload)
        error = self._preview_verification_error(preview, pairs)
        if error is not None:
            raise RuntimeError(
                "Deploy response did not prove exact per-interface success and post-deploy preview " f"did not prove convergence for {pairs}: {error}"
            )

    @classmethod
    def _preview_verification_error(cls, result: ResponseType, pairs: list[tuple[str, str]]) -> str | None:
        """Return ``None`` only for exact successful preview rows with zero pending lines."""

        preview_state, error = cls._classify_preview(result, pairs)
        if error is not None:
            return error
        if preview_state == "pending":
            return "preview contains pending configuration"
        return None

    @classmethod
    def _classify_preview(cls, result: ResponseType, pairs: list[tuple[str, str]]) -> tuple[str, str | None]:
        """Classify exact preview evidence as ``converged``, ``pending``, or contradictory.

        A structurally valid row with a positive pending-line count proves that
        deployment is required. Malformed rows, failed statuses, duplicate or
        unexpected identities, and invalid pending counts are contradictory
        evidence and must never be converted into a mutating deploy request.
        """

        pending_pairs, error = cls._pending_preview_pairs(result, pairs)
        if error is not None:
            return "contradictory", error
        return ("pending" if pending_pairs else "converged"), None

    @classmethod
    def _pending_preview_pairs(cls, result: ResponseType, pairs: list[tuple[str, str]]) -> tuple[set[tuple[str, str]], str | None]:
        """Validate exact preview evidence and return only identities with pending lines."""

        if not isinstance(result, Mapping):
            return set(), "preview response is not a mapping"
        rows = result.get("configurationDiffs")
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
            return set(), "preview response lacks a configurationDiffs list"

        expected = {cls._normalized_interface_pair(name, switch_id) for name, switch_id in pairs}
        if None in expected or len(expected) != len(pairs):
            return set(), "submitted interface identities are invalid or duplicated"
        observed: set[tuple[str, str]] = set()
        pending_pairs: set[tuple[str, str]] = set()
        for row in rows:
            if not isinstance(row, Mapping):
                return set(), "preview contains a non-mapping row"
            pair = cls._normalized_interface_pair(row.get("interfaceName"), row.get("switchId"))
            if pair is None:
                return set(), "preview contains a row without a valid interfaceName and switchId"
            if pair in observed:
                return set(), f"preview contains duplicate identity {pair!r}"
            observed.add(pair)
            if str(row.get("status") or "").strip().lower() != "success":
                return set(), f"preview status for {pair!r} is not success"
            combined_configs = row.get("combinedConfigs")
            if not isinstance(combined_configs, Sequence) or isinstance(combined_configs, (str, bytes)):
                return set(), f"preview for {pair!r} lacks combinedConfigs"
            if any(not isinstance(item, Mapping) for item in combined_configs):
                return set(), f"preview for {pair!r} contains a non-mapping combinedConfigs entry"
            if any(not isinstance(item.get("configType"), str) or not item.get("configType").strip() for item in combined_configs):
                return set(), f"preview for {pair!r} contains a combinedConfigs entry without a valid configType"
            pending = [item for item in combined_configs if item.get("configType", "").strip().lower() == "pending"]
            pending_lines = pending[0].get("lines") if len(pending) == 1 else None
            if len(pending) != 1 or not isinstance(pending_lines, int) or isinstance(pending_lines, bool) or pending_lines < 0:
                return set(), f"preview for {pair!r} does not prove zero pending configuration"
            if pending_lines > 0:
                pending_pairs.add(pair)

        if observed != expected:
            missing = sorted(expected - observed)
            unexpected = sorted(observed - expected)
            return set(), f"preview identities differ from the submitted pairs: missing={missing!r}, unexpected={unexpected!r}"
        return pending_pairs, None

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


def finalize_accepted_intent(
    orchestrator: NDBaseOrchestrator | None,
    check_mode: bool,
    module_log: logging.Logger,
) -> str:
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
