# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Orchestrator for ND Policy Group CRUD and deploy operations.

Extends ``NDBaseOrchestrator`` with custom logic for:
- Bulk create via ``POST /policyGroups`` with ``{"policyGroups": [...]}`` wrapper
- Update via ``PUT /policyGroups/{policyGroupId}`` (resolves server-generated ID)
- Delete via ``markDelete`` with direct-DELETE fallback, then optional
  consolidated switch-level deploy
- Deploy via ``POST /switchActions/deploy`` for create,update and delete
- Query via ``GET /policySummary`` because ``GET /policyGroups`` is unreliable
  for ``priority`` and ``markDeleted`` on supported controller releases.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, ClassVar

log = logging.getLogger("nd.PolicyGroupOrchestrator")

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    PrivateAttr,
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_policy_group_actions import (
    EpManagePolicyGroupActionsMarkDeletePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_policy_groups import (
    EpManagePolicyGroupsDelete,
    EpManagePolicyGroupsGet,
    EpManagePolicyGroupsPost,
    EpManagePolicyGroupsPut,
    EpManagePolicySummaryGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switch_actions import (
    EpManageSwitchActionsDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policy_groups.policy_group_base import (
    PolicyGroupCreate,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    NDBaseOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import (
    ResponseType,
)

if TYPE_CHECKING:
    # Type-hint-only import to avoid a circular dependency at runtime
    # (``nd_state_machine`` itself imports from ``orchestrators.base``).
    from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
        NDStateMachine,
    )


class PolicyGroupOrchestrator(NDBaseOrchestrator[PolicyGroupCreate]):
    """Orchestrator for policy group lifecycle operations.

    Overrides base CRUD methods because the policy group API has
    non-standard patterns:

    - **Create**: POST expects ``{"policyGroups": [...]}`` bulk wrapper.
    - **Update**: PUT requires the server-generated ``policyGroupId``
      in the URL path, not the model's composite identifier.
    - **Delete**: bulk ``markDelete`` first; policy groups whose markDelete
      result is not success are retried with direct ``DELETE``.
    - **Deploy**: ``POST /switchActions/deploy`` with
      ``{"switchIds": [...]}`` against the union of switches
      affected by the create/update/delete batch. The
      ``policyActions/pushConfig`` endpoint is not honoured for policy
      groups, so it is never used here.
    - **Query**: read paths use ``GET /policySummary`` and normalize
      ``policyType=group`` rows into the policy-group shape expected by the
      rest of the module.  Mutations still use the policy-group endpoints.
    """

    model_class: ClassVar[type[NDBaseModel]] = PolicyGroupCreate

    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True

    # Endpoint assignments — used by custom methods below, not base CRUD
    create_endpoint: type[NDEndpointBaseModel] = EpManagePolicyGroupsPost
    update_endpoint: type[NDEndpointBaseModel] = EpManagePolicyGroupsPut
    delete_endpoint: type[NDEndpointBaseModel] = EpManagePolicyGroupsDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpManagePolicyGroupsGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManagePolicyGroupsGet
    policy_summary_endpoint: type[NDEndpointBaseModel] = EpManagePolicySummaryGet

    # Bulk endpoints (required when supports_bulk_* = True)
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManagePolicyGroupsPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManagePolicyGroupsDelete

    # Additional endpoints not in base
    mark_delete_endpoint: type[NDEndpointBaseModel] = EpManagePolicyGroupActionsMarkDeletePost
    switch_deploy_endpoint: type[NDEndpointBaseModel] = EpManageSwitchActionsDeployPost

    # Configuration
    fabric_name: str | None = None
    deploy: bool = True

    # Change Control / multi-cluster query parameters.  When set, these are
    # forwarded as ``ticketId`` and ``clusterName`` on every policy-group
    # endpoint that accepts them.  ``ticket_id`` is omitted from read paths
    # and from ``switchActions/deploy`` (these endpoints do not accept it).
    # See ``_apply_endpoint_params`` for the per-endpoint dispatch logic.
    #
    # NOTE on validation timing:  The endpoint ``EndpointParams`` Pydantic
    # models declare pattern / min_length / max_length validators on these
    # fields, but their base (``EndpointQueryParams``) does NOT set
    # ``validate_assignment=True``.  As a result, validators run at
    # construction time only — plain attribute assignment via
    # ``_apply_endpoint_params`` does not re-run them, and invalid values
    # are surfaced as a controller-side 400 rather than a client-side
    # exception.  The defensive ``try / except ValidationError`` in
    # ``_apply_endpoint_params`` remains so that, if a future base-class
    # change enables ``validate_assignment``, the orchestrator already
    # produces a readable error message instead of a raw Pydantic
    # traceback.
    ticket_id: str | None = None
    cluster_name: str | None = None

    # Per-instance cache of the raw ``query_all`` response (with the
    # ``source``-artifact filter applied).  Declared as a Pydantic
    # PrivateAttr so it is a first-class private attribute rather than
    # an undeclared instance dict entry (which only "works" because the
    # base config does not forbid extras).  ``query_all`` populates it
    # on first call; mutation methods reset it to ``None`` via
    # ``_invalidate_cache``.
    _raw_cache: list | None = PrivateAttr(default=None)
    _policy_summary_cache: list | None = PrivateAttr(default=None)
    _pending_delete_switch_ids: set[str] | None = PrivateAttr(default=None)
    _pending_delete_wants: list[dict] | None = PrivateAttr(default=None)

    # ------------------------------------------------------------------ #
    # Endpoint-parameter plumbing
    # ------------------------------------------------------------------ #

    def _apply_endpoint_params(self, ep, *, with_ticket: bool = True) -> None:
        """Forward ``cluster_name`` (and optionally ``ticket_id``) to an endpoint.

        Centralises the assignment of the two Change-Control / multi-cluster
        query parameters so every endpoint call site stays a single line and
        the same error-handling wrapper is applied uniformly.

        - ``cluster_name`` is forwarded whenever the endpoint's
          ``endpoint_params`` model declares the attribute.
        - ``ticket_id`` is forwarded only when ``with_ticket=True`` AND the
          endpoint's ``endpoint_params`` model declares the attribute.  This
          avoids ``ValidationError`` / ``AttributeError`` on endpoints whose
          ``EndpointParams`` model intentionally omits ``ticket_id`` (e.g.
          read endpoints and ``switchActions/deploy``).

        Args:
            ep: An endpoint instance with an ``endpoint_params`` attribute.
            with_ticket: When False, never set ``ticket_id`` even if the
                endpoint model exposes it.  Read paths and the
                switch-deploy endpoint set this to False.

        Raises:
            Exception: Defensive wrapper around any ``ValidationError``
                that would propagate from the underlying Pydantic model.
                The base ``EndpointQueryParams`` does NOT currently enable
                ``validate_assignment``, so attribute assignment does not
                re-run pattern / min_length / max_length validators —
                invalid values are surfaced as a controller-side HTTP 400
                instead.  This wrapper keeps the orchestrator forward-
                compatible if the base class ever enables
                ``validate_assignment=True``.
        """
        params = getattr(ep, "endpoint_params", None)
        if params is None:
            return
        try:
            if self.cluster_name and hasattr(params, "cluster_name"):
                params.cluster_name = self.cluster_name
            if with_ticket and self.ticket_id and hasattr(params, "ticket_id"):
                params.ticket_id = self.ticket_id
        except ValidationError as exc:
            raise Exception("Invalid value for orchestrator parameter " "(ticket_id / cluster_name) on endpoint " f"{type(ep).__name__}: {exc}") from exc

    # ------------------------------------------------------------------ #
    # Query operations
    # ------------------------------------------------------------------ #

    def query_all(
        self,
        model_instance=None,
        *,
        include_no_description: bool = False,
        deduplicate: bool = True,
        **kwargs,
    ) -> ResponseType:
        """GET /policySummary — return active policy-group rows.

        Results from the underlying API call are cached on the orchestrator
        instance (``_raw_cache``) so that subsequent ``query_all`` calls within
        the same module run can derive their view by re-applying the requested
        filters in memory. The cache is invalidated automatically by any
        mutation method (``create_bulk``, ``update``, ``delete_bulk``).

        The cache stores the broadest possible active user-managed view (no
        description filtering applied here on the raw response). Generated
        ``source`` artifacts and fully ``markDeleted`` rows are filtered out
        here because those records are not active user-managed groups.
        ``include_no_description`` and ``deduplicate`` are then applied as
        Python-side filters on the cached list.

        Args:
            include_no_description: When False (default), exclude policy groups
                whose ``description`` is missing/null/empty. Per the ``policyBase``
                schema, ``description`` is ``nullable: true`` and may be ``""``
                or absent — the truthiness check ``g.get("description")`` covers
                all three forms. Such groups cannot be uniquely indexed by the
                (description, templateName) composite identifier and would crash
                ``NDStateMachine`` initialization. Callers that need the full
                set (e.g. ``state: gathered`` or the ID-resolution step in the
                module's main()) pass ``True``.
            deduplicate: When True (default), collapse multiple groups that
                share ``(description, templateName)`` down to the most recently
                updated one so the result is safe for ``NDConfigCollection``.
                When False, every distinct ``policyId`` is returned — required
                for ``state: gathered`` and any ID-based lookup so that legitimate
                duplicates (ND permits them) are not silently hidden.
        """
        try:
            raw = self._raw_cache
            if raw is None:
                groups = self._query_policy_summary_groups()
                raw = [g for g in groups if self._is_active_user_group(g)]
                # Cache without the per-call filters so other callers can re-derive
                # their view.  ``_raw_cache`` is a Pydantic PrivateAttr so plain
                # assignment is correct here.
                self._raw_cache = raw

            groups = raw
            # Exclude no-description groups for state-machine consumers so the
            # composite identifier (description, templateName) is never None.
            if not include_no_description:
                groups = [g for g in groups if g.get("description")]
            if deduplicate:
                return self._deduplicate_groups(groups)
            return list(groups)
        except Exception as e:
            raise Exception(f"Query all policy groups failed: {e}") from e

    def _invalidate_cache(self) -> None:
        """Drop cached policy-summary and active query views after mutation."""
        self._raw_cache = None
        self._policy_summary_cache = None

    @staticmethod
    def _is_policy_group_summary(row: dict) -> bool:
        """Return True when a policySummary row represents a policy group."""
        policy_id = str(row.get("policyId") or "")
        return policy_id.startswith("POLICY-GROUP-") or row.get("policyType") == "group"

    @staticmethod
    def _summary_switch_rows(row: dict) -> list[dict]:
        """Return policySummary ``switches`` entries as a list of dicts."""
        switches = row.get("switches") or []
        if not isinstance(switches, list):
            return []
        return [s for s in switches if isinstance(s, dict)]

    @classmethod
    def _summary_switch_ids(cls, row: dict, *, deleted: bool | None = None) -> list[str]:
        """Return switch IDs from policySummary.

        Args:
            row: Raw policySummary policy row.
            deleted: When True, return only markDeleted switch IDs. When False,
                return only non-markDeleted switch IDs. When None, return all
                switch IDs.
        """
        switch_ids: list[str] = []
        for switch in cls._summary_switch_rows(row):
            if deleted is not None and bool(switch.get("markDeleted", False)) is not deleted:
                continue
            switch_id = switch.get("switchId")
            if switch_id:
                switch_ids.append(switch_id)
        return switch_ids

    @classmethod
    def _summary_mark_deleted(cls, row: dict) -> bool:
        """Return True when every policySummary switch row is markDeleted."""
        switches = cls._summary_switch_rows(row)
        if switches:
            return all(bool(switch.get("markDeleted", False)) for switch in switches)
        return bool(row.get("markDeleted", False))

    @classmethod
    def _summary_priority(cls, row: dict) -> int | None:
        """Return the first valid switch priority from policySummary."""
        switches = cls._summary_switch_rows(row)
        ordered = [switch for switch in switches if not bool(switch.get("markDeleted", False))] or switches
        for switch in ordered:
            try:
                return int(switch.get("priority"))
            except (TypeError, ValueError):
                continue
        try:
            return int(row.get("priority"))
        except (TypeError, ValueError):
            return None

    @classmethod
    def _summary_to_policy_group(cls, row: dict) -> dict:
        """Normalize a policySummary group row into policy-group response shape."""
        mark_deleted = cls._summary_mark_deleted(row)
        active_switch_ids = cls._summary_switch_ids(row, deleted=False)
        deleted_switch_ids = cls._summary_switch_ids(row, deleted=True)
        all_switch_ids = cls._summary_switch_ids(row, deleted=None)

        normalized = dict(row)
        normalized["switchIds"] = deleted_switch_ids if mark_deleted else active_switch_ids or all_switch_ids
        normalized["markDeleted"] = mark_deleted
        normalized["_allSwitchIds"] = all_switch_ids
        normalized["_deletedSwitchIds"] = deleted_switch_ids

        priority = cls._summary_priority(row)
        if priority is not None:
            normalized["priority"] = priority
        return normalized

    def _query_policy_summary_groups(self) -> list[dict]:
        """Fetch policySummary rows and normalize the policy-group subset.

        The controller does not reliably honor ``filter=policyType:group``.
        Use the policy ID wildcard as the request-level reduction and still
        guard in Python so non-group rows never reach module logic.
        """
        raw = self._policy_summary_cache
        if raw is not None:
            return list(raw)

        ep = self.policy_summary_endpoint()
        ep.fabric_name = self.fabric_name
        self._apply_endpoint_params(ep, with_ticket=False)
        ep.lucene_params.max = 10000
        ep.lucene_params.filter = "policyId:*POLICY-GROUP-*"
        result = self._request(path=ep.path, verb=ep.verb, not_found_ok=True)
        policies = result.get("policies", []) if isinstance(result, dict) else []
        raw = [self._summary_to_policy_group(policy) for policy in (policies or []) if isinstance(policy, dict) and self._is_policy_group_summary(policy)]
        self._policy_summary_cache = raw
        return list(raw)

    @staticmethod
    def _deduplicate_groups(groups: list) -> list:
        """Remove duplicate (description, templateName) entries.

        When duplicates exist, the entry with the latest ``updateTimestamp``
        (or ``createTimestamp``) is kept.  This handles the edge case where
        groups with identical identifiers are created outside of Ansible
        (e.g. via the ND UI).

        Args:
            groups: Raw list of policy group dicts from the API.

        Returns:
            Deduplicated list preserving original order of kept entries.
        """
        seen: dict[tuple, dict] = {}
        for group in groups:
            key = (group.get("description", ""), group.get("templateName", ""))
            if key in seen:
                # Keep the one with the later timestamp
                existing_ts = seen[key].get("updateTimestamp") or seen[key].get("createTimestamp") or 0
                current_ts = group.get("updateTimestamp") or group.get("createTimestamp") or 0
                if current_ts > existing_ts:
                    seen[key] = group
            else:
                seen[key] = group
        return list(seen.values())

    @staticmethod
    def _is_active_user_group(group: dict) -> bool:
        """Return True when a policy-group record belongs in normal reads.

        Normal query/gathered/idempotency paths should expose only active,
        user-managed policy groups. Pending-delete cleanup uses dedicated raw
        helpers so it can still inspect ``source`` and ``markDeleted`` records.
        """
        return not group.get("source") and not group.get("markDeleted", False)

    def query_by_id(self, policy_group_id: str) -> ResponseType:
        """Fetch a single policy group by ID from policySummary."""
        try:
            for group in self._query_policy_summary_groups():
                if group.get("policyId") == policy_group_id:
                    return dict(group)
            return None
        except Exception as e:
            raise Exception(f"Query policy group by ID failed: {e}") from e

    def query_filtered(
        self,
        template_name: str | None = None,
        description: str | None = None,
        *,
        deduplicate: bool = True,
    ) -> ResponseType:
        """Filter policySummary policy-group rows in Python.

        Args:
            template_name: Filter by templateName using exact Python matching.
            description: Filter by description using exact Python matching.
            deduplicate: See :meth:`query_all`. Defaults to True for safe
                state-machine consumption; ``state: gathered`` passes False
                so duplicate policies with distinct ``policyId``s are visible.

        Returns:
            Filtered list of policy group dicts (deduplicated by default).
        """
        try:

            def filter_groups(groups: list) -> list:
                groups = [g for g in groups if self._is_active_user_group(g)]
                if template_name:
                    groups = [g for g in groups if g.get("templateName") == template_name]
                if description:
                    groups = [g for g in groups if g.get("description") == description]
                if deduplicate:
                    return self._deduplicate_groups(groups)
                return list(groups)

            # Serve from active cache if populated; otherwise fetch the summary
            # cache.  Template/description filters are applied in Python because
            # policySummary server-side filtering has controller-version quirks.
            raw = self._raw_cache
            if raw is not None:
                return filter_groups(raw)

            return filter_groups(self._query_policy_summary_groups())
        except Exception as e:
            raise Exception(f"Query filtered policy groups failed: {e}") from e

    @staticmethod
    def _record_switch_ids(record: dict) -> list[str]:
        """Return switch IDs from either policy-group response key."""
        switch_ids = record.get("switchIds")
        if switch_ids is None:
            switch_ids = record.get("switchId")
        if switch_ids is None:
            return []
        if isinstance(switch_ids, list):
            return [sid for sid in switch_ids if sid]
        if switch_ids:
            return [switch_ids]
        return []

    @staticmethod
    def _entry_switch_ids(entry: dict) -> list[str]:
        """Return switch IDs from user config key variants."""
        switch_ids = entry.get("switch_ids")
        if switch_ids is None:
            switch_ids = entry.get("switchIds")
        if switch_ids is None:
            return []
        if isinstance(switch_ids, list):
            return [sid for sid in switch_ids if sid]
        if switch_ids:
            return [switch_ids]
        return []

    @staticmethod
    def _cleanup_identity(entry: dict) -> tuple[str | None, str | None]:
        """Extract the cleanup identity from a user config entry."""
        policy_group_id = entry.get("policy_id")
        name = entry.get("name") or ""
        if not policy_group_id and name.startswith("POLICY-GROUP-"):
            policy_group_id = name
        return policy_group_id, entry.get("description")

    def schedule_pending_deleted_cleanup(self, config_entries: list[dict]) -> dict:
        """Queue switch cleanup for markDeleted rows hidden from active view."""
        summary = {
            "switch_ids": [],
            "skipped": [],
            "wants": [],
            "matched_policy_ids": [],
            "changed": False,
            "validation": "policy_summary_markDeleted",
        }
        if not self.deploy:
            return summary

        for index, entry in enumerate(config_entries):
            matches = self._pending_deleted_matches(entry)
            if len(matches) > 1 and not self._cleanup_identity(entry)[0]:
                summary["skipped"].append(
                    {
                        "index": index,
                        "reason": "ambiguous pending-delete description; use policy group ID",
                        "entry": entry,
                        "matched_policy_ids": [match.get("policyId") for match in matches if match.get("policyId")],
                    }
                )
                continue
            if not matches:
                summary["skipped"].append(
                    {
                        "index": index,
                        "reason": "no matching markDeleted policySummary row",
                        "entry": entry,
                    }
                )
                continue

            switch_ids: list[str] = []
            matched_policy_ids: list[str] = []
            for match in matches:
                matched_policy_ids.append(match.get("policyId"))
                switch_ids.extend(match.get("_deletedSwitchIds") or match.get("switchIds") or self._record_switch_ids(match))
            if not switch_ids:
                switch_ids = self._entry_switch_ids(entry)
            if not switch_ids:
                summary["skipped"].append(
                    {
                        "index": index,
                        "reason": "switch_ids unavailable for matched pending-delete cleanup",
                        "entry": entry,
                        "matched_policy_ids": matched_policy_ids,
                    }
                )
                continue
            summary["wants"].append(dict(entry))
            summary["switch_ids"] = sorted(set(summary["switch_ids"]) | set(switch_ids))
            summary["matched_policy_ids"] = sorted(set(summary["matched_policy_ids"]) | {pid for pid in matched_policy_ids if pid})

        if summary["switch_ids"]:
            if self._pending_delete_switch_ids is None:
                self._pending_delete_switch_ids = set()
            if self._pending_delete_wants is None:
                self._pending_delete_wants = []
            self._pending_delete_switch_ids.update(summary["switch_ids"])
            self._pending_delete_wants.extend(summary["wants"])

        return summary

    def _pending_deleted_matches(self, entry: dict) -> list[dict]:
        """Return markDeleted summary rows matching a cleanup entry.

        A requested policy-group ID can match either the hidden row's own
        ``policyId`` (for callers that provide the generated child/pending row
        ID) or its ``source`` (for callers that provide the original ID).
        Description matching is a fallback for delete intents that did not carry
        a controller ID.
        """
        policy_group_id, description = self._cleanup_identity(entry)
        matches: list[dict] = []
        for group in self._query_policy_summary_groups():
            if not group.get("markDeleted", False):
                continue
            if policy_group_id:
                if group.get("policyId") == policy_group_id or group.get("source") == policy_group_id:
                    matches.append(group)
                continue
            if description and group.get("description") == description:
                matches.append(group)
        return matches

    def _consume_pending_deleted_cleanup(self) -> tuple[set[str], list[dict]]:
        """Return and clear queued pending-delete switch targets."""
        switch_ids = set(self._pending_delete_switch_ids or set())
        wants = list(self._pending_delete_wants or [])
        self._pending_delete_switch_ids = set()
        self._pending_delete_wants = []
        return switch_ids, wants

    def deploy_scheduled_pending_deleted_cleanup(self) -> dict:
        """Deploy queued pending-delete cleanup when no delete consumed it."""
        switch_ids, wants = self._consume_pending_deleted_cleanup()
        summary = {
            "switch_ids": sorted(switch_ids),
            "wants": wants,
            "skipped": [],
            "matched_policy_ids": [],
            "changed": False,
            "validation": "policy_summary_markDeleted",
        }
        if not self.deploy or not switch_ids:
            return summary

        summary["changed"] = True
        if self.rest_send.check_mode:
            return summary

        self._switch_deploy(sorted(switch_ids))
        return summary

    def deploy_pending_deleted_cleanup(self, config_entries: list[dict]) -> dict:
        """Deploy switch cleanup for summary-matched pending delete targets.

        Kept as a public helper for tests and direct callers.  Normal module
        flow schedules first so the switches can be unioned into the same
        deploy call as active deletes.
        """
        scheduled = self.schedule_pending_deleted_cleanup(config_entries)
        deployed = self.deploy_scheduled_pending_deleted_cleanup()
        if scheduled["skipped"]:
            deployed["skipped"].extend(scheduled["skipped"])
        if scheduled["switch_ids"] and not deployed["switch_ids"]:
            deployed["switch_ids"] = scheduled["switch_ids"]
        if scheduled["matched_policy_ids"] and not deployed["matched_policy_ids"]:
            deployed["matched_policy_ids"] = scheduled["matched_policy_ids"]
        return deployed

    # ------------------------------------------------------------------ #
    # Create operations
    # ------------------------------------------------------------------ #

    def create(self, model_instance: PolicyGroupCreate, **kwargs) -> ResponseType:
        """Create a single policy group (wraps in bulk API)."""
        return self.create_bulk([model_instance], **kwargs)

    def create_bulk(self, model_instances: list[PolicyGroupCreate], **kwargs) -> ResponseType:
        """POST /policyGroups with ``{"policyGroups": [...]}`` wrapper.

        The endpoint always returns HTTP 207 (Multi-Status); per-item
        ``status`` is ``"success"`` or ``"failed"``. We surface failures as
        an exception so the user sees them rather than getting a silent
        partial create with ``changed=true``.
        """
        try:
            ep = self.create_bulk_endpoint()
            ep.fabric_name = self.fabric_name
            self._apply_endpoint_params(ep)

            payload = {"policyGroups": [self._with_create_defaults(m.to_payload()) for m in model_instances]}
            result = self._request(path=ep.path, verb=ep.verb, data=payload)

            # Populate server-generated policyIds back onto model instances
            response_groups = []
            if isinstance(result, dict):
                response_groups = result.get("policyGroups", [])
            self._populate_policy_ids(model_instances, response_groups)

            # Detect per-item failures in the 207 response body.
            failures: list[str] = []
            for idx, rg in enumerate(response_groups):
                if not isinstance(rg, dict):
                    continue
                status = (rg.get("status") or "").lower()
                if status and status != "success":
                    # Best-effort identifier for the failed item from the request
                    if idx < len(model_instances):
                        m = model_instances[idx]
                        ident = f"{m.template_name!r} (description={m.description!r})"
                    else:
                        ident = f"index {idx}"
                    msg = rg.get("message") or "unknown error"
                    failures.append(f"{ident}: {msg}")

            if failures:
                raise Exception("Bulk create reported {0} failed item(s): {1}".format(len(failures), "; ".join(failures)))

            # Deploy if requested.
            if self.deploy:
                affected_switches: set[str] = set()
                for m in model_instances:
                    for sid in m.switch_ids or []:
                        if sid:
                            affected_switches.add(sid)
                if affected_switches:
                    self._switch_deploy(sorted(affected_switches))

            self._invalidate_cache()
            return result
        except Exception as e:
            raise Exception(f"Bulk create policy groups failed: {e}") from e

    # ------------------------------------------------------------------ #
    # Update operations
    # ------------------------------------------------------------------ #

    def update(self, model_instance: PolicyGroupCreate, **kwargs) -> ResponseType:
        """PUT /policyGroups/{policyGroupId}.

        Uses the server-generated ``policy_id`` stored on the model instance.

        When switch_ids are removed and deploy is True, performs a
        switch-level deploy on the removed switches so the controller
        pushes the negative (removal) config to those switches.
        """
        try:
            policy_group_id = model_instance.policy_id
            if not policy_group_id:
                raise ValueError(f"Cannot update policy group — no policy_id found. " f"Description: {model_instance.description!r}")

            current_group = self._get_current_policy_group(policy_group_id)
            old_switch_ids = self._extract_switch_ids(current_group)
            desired_payload = self._with_update_priority(model_instance.to_payload(), current_group)
            update_payloads = self._build_update_payloads(current_group, desired_payload)

            if len(update_payloads) > 1:
                log.info(
                    "Splitting policy group update for %s into %d PUT requests because switch membership and intent changed together.",
                    policy_group_id,
                    len(update_payloads),
                )

            result = {}
            for payload in update_payloads:
                result = self._put_policy_group(policy_group_id, payload)

            # Deploy if requested.
            #
            # NOTE: ``policyActions/pushConfig`` is not supported for
            # policy groups, so we deploy at the switch level instead.
            # The set of affected switches is the union of the new
            # switch_ids (so the updated config is pushed) and any
            # switches that were removed from the group (so the negative
            # / removal config is pushed to them).
            if self.deploy:
                new_switch_ids = set(desired_payload.get("switchIds", []) or [])
                removed_switches = old_switch_ids - new_switch_ids
                affected_switches = {sid for sid in new_switch_ids | removed_switches if sid}
                if affected_switches:
                    self._switch_deploy(sorted(affected_switches))

            self._invalidate_cache()
            return result
        except Exception as e:
            raise Exception(f"Update policy group failed for {model_instance.description!r}: {e}") from e

    def _put_policy_group(self, policy_group_id: str, payload: dict) -> ResponseType:
        """Send one ``PUT /policyGroups/{policyGroupId}`` request.

        Keeping this as a small helper ensures split updates are registered as
        separate API calls in ``Results`` with their own payload/response data.
        """
        ep = self.update_endpoint()
        ep.fabric_name = self.fabric_name
        ep.policy_group_id = policy_group_id
        self._apply_endpoint_params(ep)
        return self._request(
            path=ep.path,
            verb=ep.verb,
            data=payload,
            operation_type=OperationType.UPDATE,
        )

    def _get_current_policy_group(self, policy_group_id: str) -> dict:
        """Return the raw current policy group dict for ``policy_group_id``.

        The cached ``query_all`` response is preferred because module execution
        usually performs that broad read before the state machine runs.
        """
        raw = self._raw_cache
        if raw is not None:
            for group in raw:
                if group.get("policyId") == policy_group_id:
                    return dict(group)
            return {}
        try:
            result = self.query_by_id(policy_group_id)
            return dict(result or {}) if isinstance(result, dict) else {}
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "_get_current_policy_group: GET for %s failed (%s: %s) — using desired payload as the only update request",
                policy_group_id,
                type(exc).__name__,
                exc,
            )
            return {}

    @classmethod
    def _build_update_payloads(cls, current_group: dict, desired_payload: dict) -> list[dict]:
        """Build one or two update payloads for a policy group.

        The controller rejects a single PUT that changes switch membership and
        policy intent together. Instead of maintaining a hardcoded list of
        intent fields, compare the payloads after removing only ``switchIds``.
        """
        if not current_group:
            return [desired_payload]

        try:
            current_payload = cls._policy_group_to_payload(current_group)
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "Could not normalize current policy group for split update detection (%s: %s); using single PUT.",
                type(exc).__name__,
                exc,
            )
            return [desired_payload]
        current_switch_ids = cls._extract_switch_ids(current_payload)
        desired_switch_ids = cls._extract_switch_ids(desired_payload)
        membership_changed = current_switch_ids != desired_switch_ids
        if not membership_changed:
            return [desired_payload]

        current_intent = cls._without_switch_ids(current_payload)
        desired_intent = cls._without_switch_ids(desired_payload)
        membership_payload = cls._policy_group_to_membership_payload(current_group, current_payload)
        membership_payload["switchIds"] = desired_payload.get("switchIds", [])
        if current_intent == desired_intent:
            return [membership_payload]

        return [membership_payload, desired_payload]

    @staticmethod
    def _with_create_defaults(payload: dict) -> dict:
        """Materialize create-only defaults before sending the POST body."""
        out = dict(payload)
        if out.get("priority") is None:
            out["priority"] = 500
        return out

    @classmethod
    def _with_update_priority(cls, desired_payload: dict, current_group: dict) -> dict:
        """Preserve existing priority when the user omitted it on update."""
        if desired_payload.get("priority") is not None:
            return desired_payload
        out = dict(desired_payload)
        current_priority = current_group.get("priority") if current_group else None
        if current_priority is None and current_group:
            try:
                current_priority = cls._policy_group_to_payload(current_group).get("priority")
            except Exception:  # noqa: BLE001
                current_priority = None
        try:
            parsed_priority = int(current_priority)
        except (TypeError, ValueError):
            parsed_priority = 500
        out["priority"] = parsed_priority if 1 <= parsed_priority <= 2000 else 500
        return out

    @staticmethod
    def _policy_group_to_payload(group: dict) -> dict:
        """Normalize an API policy group dict to the PUT payload shape."""
        normalized = dict(group)
        if "switchIds" not in normalized and "switchId" in normalized:
            normalized["switchIds"] = normalized["switchId"]
        return PolicyGroupCreate.from_response(normalized).to_payload()

    @staticmethod
    def _policy_group_to_membership_payload(group: dict, normalized_payload: dict) -> dict:
        """Build a membership-only payload from the controller's current shape.

        ``normalized_payload`` is used for validation/defaults, but values
        echoed by the controller are preferred so the membership PUT changes
        only ``switchIds`` from the controller's perspective.
        """
        payload = dict(normalized_payload)
        for key in list(payload):
            if key in group:
                payload[key] = group[key]
            elif key == "switchIds" and "switchId" in group:
                payload[key] = group["switchId"]
        return payload

    @staticmethod
    def _extract_switch_ids(payload: dict) -> set:
        """Return switch IDs from either API or payload key variants."""
        switch_ids = payload.get("switchIds")
        if switch_ids is None:
            switch_ids = payload.get("switch_ids")
        if switch_ids is None:
            switch_ids = payload.get("switchId")
        return {sid for sid in switch_ids or [] if sid}

    @staticmethod
    def _without_switch_ids(payload: dict) -> dict:
        """Return a payload copy with only membership removed."""
        return {key: value for key, value in payload.items() if key != "switchIds"}

    # ------------------------------------------------------------------ #
    # Delete operations
    # ------------------------------------------------------------------ #

    def delete(self, model_instance: PolicyGroupCreate, **kwargs) -> ResponseType:
        """Delete a single policy group (delegates to delete_bulk)."""
        return self.delete_bulk([model_instance], **kwargs)

    def delete_bulk(self, model_instances: list[PolicyGroupCreate], **kwargs) -> ResponseType:
        """Delete multiple policy groups with markDelete-first fallback.

        Deletion strategy:

        1. **markDelete** all policy group IDs.
        2. For any policy group whose markDelete result is not success:
           direct ``DELETE /policyGroups/<id>``.  This is primarily a
           controller workaround for freeform/PYTHON failures, but the local
           fallback is driven by the controller's per-policy result rather
           than by a hardcoded template classification.
        3. **Single** ``switchActions/deploy`` against the **union** of all
           affected switches (both markDelete-succeeded and direct-deleted).

        Consolidating the deploy into one call avoids hitting the same
        switch twice when a batch mixes markDelete-eligible and
        direct-delete groups that share switches.

        When ``deploy=False``, markDelete (and direct DELETE for failures)
        is performed without the trailing switch deploy.
        """
        try:
            pending_switch_ids, pending_wants = self._consume_pending_deleted_cleanup()
            policy_ids = [m.policy_id for m in model_instances if m.policy_id]
            if not policy_ids:
                if self.deploy and pending_switch_ids:
                    log.debug(
                        "delete_bulk: No active policy_ids; deploying pending cleanup switches=%s",
                        sorted(pending_switch_ids),
                    )
                    if not self.rest_send.check_mode:
                        self._switch_deploy(sorted(pending_switch_ids))
                    return {
                        "policyIds": [],
                        "status": "success",
                        "pendingDeletedCleanupSwitchIds": sorted(pending_switch_ids),
                        "pendingDeletedCleanupWants": pending_wants,
                    }
                log.debug("delete_bulk: No policy_ids to delete, returning early.")
                return {}

            log.debug(
                "delete_bulk: Starting deletion for policy_ids=%s, deploy=%s",
                policy_ids,
                self.deploy,
            )

            # Build switch_ids lookup for switch-level deploy
            switch_ids_by_policy: dict[str, list[str]] = {}
            for m in model_instances:
                if m.policy_id and m.switch_ids:
                    switch_ids_by_policy[m.policy_id] = list(m.switch_ids)
            log.debug("delete_bulk: switch_ids_by_policy=%s", switch_ids_by_policy)

            # Step 1: Attempt markDelete for all policy groups
            log.debug("delete_bulk: Step 1 - markDelete for policy_ids=%s", policy_ids)
            mark_result = self._mark_delete(policy_ids)
            log.debug("delete_bulk: markDelete response=%s", mark_result)

            # Inspect 207 response for per-policy failures
            mark_succeeded = []
            mark_failed_ids = []
            mark_failure_messages: list[str] = []
            if isinstance(mark_result, dict):
                policies_response = mark_result.get("policyGroups", [])
                failed_set = set()
                for p in policies_response:
                    pid = p.get("policyId", "")
                    status = str(p.get("status", "")).lower()
                    if status != "success":
                        failed_set.add(pid)
                        mark_failed_ids.append(pid)
                        msg = p.get("message") or "unknown error"
                        mark_failure_messages.append(f"{pid}: {msg}")
                mark_succeeded = [pid for pid in policy_ids if pid not in failed_set]
                # If empty response, treat all as succeeded (ambiguous)
                if not policies_response and policy_ids:
                    mark_succeeded = list(policy_ids)
            else:
                mark_succeeded = list(policy_ids)

            if mark_failure_messages:
                # Log the reason at WARNING so the cause of the direct-DELETE
                # fallback is visible even when the fallback ultimately succeeds.
                log.warning(
                    "delete_bulk: markDelete reported failures (will retry via direct DELETE): %s",
                    "; ".join(mark_failure_messages),
                )

            log.debug(
                "delete_bulk: markDelete succeeded=%s, failed=%s",
                mark_succeeded,
                mark_failed_ids,
            )

            # Step 2: Direct DELETE fallback for markDelete failures.
            # TODO(4.2.1): Workaround — switch_freeform-type policies fail
            # markDelete on ND; we fall back to direct DELETE /policyGroups/<id>.
            # Remove once ND supports markDelete for these templates natively.
            direct_deleted: list[str] = []
            if mark_failed_ids:
                log.debug(
                    "delete_bulk: Step 2 - Direct DELETE fallback for failed=%s",
                    mark_failed_ids,
                )
                for pid in mark_failed_ids:
                    ep = self.delete_endpoint()
                    ep.fabric_name = self.fabric_name
                    ep.policy_group_id = pid
                    self._apply_endpoint_params(ep)
                    self._request(path=ep.path, verb=ep.verb)
                    direct_deleted.append(pid)

            # Step 3: Single consolidated switchActions/deploy against the
            # union of all affected switches.  One call covers the removal
            # for both markDelete-succeeded and direct-deleted groups so
            # shared switches are not redeployed twice.
            if self.deploy:
                affected_switches: set[str] = set()
                for pid in (*mark_succeeded, *direct_deleted):
                    affected_switches.update(switch_ids_by_policy.get(pid, []))
                affected_switches.update(pending_switch_ids)
                if affected_switches:
                    log.debug(
                        "delete_bulk: Step 3 - consolidated switchActions/deploy, switches=%s",
                        sorted(affected_switches),
                    )
                    self._switch_deploy(sorted(affected_switches))
                else:
                    log.debug("delete_bulk: Step 3 skipped (no affected switches).")

            log.debug(
                "delete_bulk: Complete. mark_succeeded=%s, direct_deleted=%s",
                mark_succeeded,
                direct_deleted,
            )
            self._invalidate_cache()
            result = {"policyIds": policy_ids, "status": "success"}
            if pending_switch_ids:
                result["pendingDeletedCleanupSwitchIds"] = sorted(pending_switch_ids)
                result["pendingDeletedCleanupWants"] = pending_wants
            return result
        except Exception as e:
            raise Exception(f"Bulk delete policy groups failed: {e}") from e

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _mark_delete(self, policy_ids: list[str]) -> ResponseType:
        """POST /policyGroups/actions/markDelete with policy IDs."""
        ep = self.mark_delete_endpoint()
        ep.fabric_name = self.fabric_name
        self._apply_endpoint_params(ep)
        payload = {"policyIds": policy_ids}
        return self._request(path=ep.path, verb=ep.verb, data=payload)

    def _switch_deploy(self, switch_ids: list[str]) -> ResponseType:
        """POST /switchActions/deploy to deploy config to specific switches.

        Sends a single bulk request with every ``switchId`` in one
        ``{"switchIds": [...]}`` payload. The controller normally responds with
        a per-switch status array of the form::

            {
                "switchIds": [
                    {"switchId": "<sn>", "status": "success",     "message": "Deployed Successfully"},
                    {"switchId": "<sn>", "status": "notExecuted", "message": "No Commands to execute"},
                    {"switchId": "<sn>", "status": "failed",      "message": "<reason>"},
                ]
            }

        Some successful controller responses are empty/None or a bare list.
        Those shapes are treated as success unless an explicit failed switch
        status is present.

        """
        ep = self.switch_deploy_endpoint()
        ep.fabric_name = self.fabric_name
        # switchActions/deploy accepts ``clusterName`` but does NOT accept
        # ``ticketId``; suppress the ticket assignment for this endpoint.
        self._apply_endpoint_params(ep, with_ticket=False)
        payload = {"switchIds": switch_ids}
        log.debug(
            "switchActions/deploy: dispatching to %d switch(es): %s",
            len(switch_ids),
            switch_ids,
        )
        result = self._request(path=ep.path, verb=ep.verb, data=payload)

        # Parse per-switch status.  ``DATA`` body has been unwrapped to
        # ``result`` already by ``_request``.  Be defensive about shape:
        # some controller versions/error paths return list/None instead
        # of the documented dict.
        per_switch = []
        if isinstance(result, dict):
            per_switch = result.get("switchIds") or []
        elif isinstance(result, list):
            per_switch = result

        not_executed: list[str] = []
        failures: list[str] = []
        for entry in per_switch:
            if not isinstance(entry, dict):
                continue
            sid = entry.get("switchId") or entry.get("switchSn") or "?"
            status = str(entry.get("status", "")).lower()
            message = entry.get("message") or ""
            if status == "success":
                continue
            if status == "notexecuted":
                not_executed.append(f"{sid}: {message}")
                continue
            failures.append(f"{sid}: status={status!r} message={message!r}")

        if not_executed:
            log.warning(
                "switchActions/deploy: %d/%d switch(es) returned notExecuted (controller considers them already in-sync): %s",
                len(not_executed),
                len(per_switch),
                not_executed,
            )

        if failures:
            raise Exception("switchActions/deploy reported {0} failed switch(es): {1}".format(len(failures), "; ".join(failures)))

        return result

    def deploy_unchanged_user_mentioned(self, state_machine: NDStateMachine) -> None:
        """Push ``switchActions/deploy`` for user-mentioned policy groups that had no diff.

        When the user sets ``deploy=true`` and lists a policy group in
        ``config:`` whose desired state already matches the controller
        (no diff), the state machine does not ``send`` it. But the user
        expressed intent to deploy, so push the running config to the
        affected switches anyway.

        Strictly scoped to *user-mentioned* policies (the intersection of
        ``state_machine.proposed`` and ``state_machine.existing``, minus
        anything actually sent in this run). Never touches unrelated
        fabric policies.

        No-op when ``self.deploy`` is False; safe to call unconditionally
        from the module's main() once the state machine has run.

        ## Args

        -   ``state_machine``: The fully-managed ``NDStateMachine`` whose
            ``sent`` / ``proposed`` / ``existing`` collections describe
            what just happened in this run.
        """
        if not self.deploy:
            return

        sent_identifiers = {item.get_identifier_value() for item in state_machine.sent}
        proposed_identifiers = {item.get_identifier_value() for item in state_machine.proposed}
        log.debug(
            "deploy-unchanged: proposed_identifiers=%s",
            sorted(map(str, proposed_identifiers)),
        )
        log.debug(
            "deploy-unchanged: sent_identifiers=%s",
            sorted(map(str, sent_identifiers)),
        )

        unchanged_switch_ids: set[str] = set()
        unchanged_policy_ids: list[str] = []
        for item in state_machine.existing:
            ident = item.get_identifier_value()
            in_proposed = ident in proposed_identifiers
            in_sent = ident in sent_identifiers
            pid = getattr(item, "policy_id", None)
            log.debug(
                "deploy-unchanged: existing item ident=%s policy_id=%s in_proposed=%s in_sent=%s",
                ident,
                pid,
                in_proposed,
                in_sent,
            )
            if in_proposed and not in_sent and pid:
                unchanged_policy_ids.append(pid)
                for sid in getattr(item, "switch_ids", None) or []:
                    if sid:
                        unchanged_switch_ids.add(sid)

        if unchanged_switch_ids:
            log.info(
                "Deploying %d unchanged policy group(s) [%s] via switchActions/deploy on switches: %s",
                len(unchanged_policy_ids),
                unchanged_policy_ids,
                sorted(unchanged_switch_ids),
            )
            self._switch_deploy(sorted(unchanged_switch_ids))
        else:
            log.debug("deploy-unchanged: no unchanged user-mentioned policies to push")

    def _get_current_switch_ids(self, policy_group_id: str) -> set:
        """Return a policy group's current switch_ids.

        Prefers the cached ``query_all`` response when available so we avoid
        a redundant lookup; falls back to ``query_by_id`` only when the cache is
        empty (e.g. orchestrator used standalone without a prior ``query_all``).
        ``query_by_id`` resolves from ``policySummary`` in the same normalized
        shape as ``query_all``.
        """
        raw = self._raw_cache
        if raw is not None:
            for g in raw:
                if g.get("policyId") == policy_group_id:
                    return set(g.get("switchIds", []) or [])
            # Cache present but ID not found — group was likely just created in
            # this run; treat as having no prior switches.
            return set()
        try:
            result = self.query_by_id(policy_group_id)
            if isinstance(result, dict):
                return set(result.get("switchIds", []) or [])
            return set()
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "_get_current_switch_ids: GET for %s failed (%s: %s) — treating as no prior switches (removal-deploy may be skipped)",
                policy_group_id,
                type(exc).__name__,
                exc,
            )
            return set()

    @staticmethod
    def _populate_policy_ids(
        model_instances: list[PolicyGroupCreate],
        response_groups: list,
    ) -> None:
        """Match API response items back to model instances and set policy_id.

        The POST /policyGroups response item does NOT echo the ``description``
        field of the request (see API docs example: only ``entityName``,
        ``entityType``, ``message``, ``policyId``, ``status``, ``switchIds``
        and ``templateName`` are returned).  We therefore cannot match by
        ``(templateName, description)``.
        """
        if not response_groups:
            return

        for idx, model in enumerate(model_instances):
            if idx >= len(response_groups):
                break
            rg = response_groups[idx] or {}
            status = (rg.get("status") or "").lower()
            if status and status != "success":
                # Failed item — no policyId to populate; let caller surface error
                continue
            pid = rg.get("policyId") or rg.get("policy_id")
            if not pid:
                # Some templates embed the assigned ID inside templateInputs
                ti = rg.get("templateInputs") or rg.get("template_inputs") or {}
                if isinstance(ti, dict):
                    pid = ti.get("POLICY_ID")
            if pid:
                model.policy_id = pid
