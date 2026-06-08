# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Orchestrator for ND Policy Group CRUD and deploy operations.

Extends ``NDBaseOrchestrator`` with custom logic for:
- Bulk create via ``POST /policyGroups`` with ``{"policyGroups": [...]}`` wrapper
- Update via ``PUT /policyGroups/{policyGroupId}`` (resolves server-generated ID)
- Delete via ``markDelete`` → switch-level deploy (pushes removal config)
- Deploy via ``POST /switchActions/deploy`` for create,update and delete
- Query extracting ``policyGroups`` list from GET response
"""

from __future__ import annotations

import logging
from typing import ClassVar

log = logging.getLogger("nd.PolicyGroupOrchestrator")

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
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switch_actions import (
    EpManageSwitchActionsDeployPost,
)
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


class PolicyGroupOrchestrator(NDBaseOrchestrator[PolicyGroupCreate]):
    """Orchestrator for policy group lifecycle operations.

    Overrides base CRUD methods because the policy group API has
    non-standard patterns:

    - **Create**: POST expects ``{"policyGroups": [...]}`` bulk wrapper.
    - **Update**: PUT requires the server-generated ``policyGroupId``
      in the URL path, not the model's composite identifier.
    - **Delete**: Two-step flow — ``markDelete`` then ``DELETE`` verb
      per individual policy group.
    - **Deploy**: ``POST /switchActions/deploy`` with
      ``{"switchIds": [...]}`` against the union of switches
      affected by the create/update/delete batch. The
      ``policyActions/pushConfig`` endpoint is not honoured for policy
      groups, so it is never used here.
    - **Query**: GET response wraps results in ``{"policyGroups": [...]}``.
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

    # Bulk endpoints (required when supports_bulk_* = True)
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManagePolicyGroupsPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManagePolicyGroupsDelete

    # Additional endpoints not in base
    mark_delete_endpoint: type[NDEndpointBaseModel] = EpManagePolicyGroupActionsMarkDeletePost
    switch_deploy_endpoint: type[NDEndpointBaseModel] = EpManageSwitchActionsDeployPost

    # Configuration
    fabric_name: str | None = None
    deploy: bool = True

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
        """GET /policyGroups — extract ``policyGroups`` list from response.

        Results from the underlying API call are cached on the orchestrator
        instance (``_raw_cache``) so that subsequent ``query_all`` calls within
        the same module run can derive their view by re-applying the requested
        filters in memory. The cache is invalidated automatically by any
        mutation method (``create_bulk``, ``update``, ``delete_bulk``).

        The cache stores the broadest possible view (no description and source
        filtering applied here on the raw response — only the spec-mandated
        ``source`` artifact filter is always applied since those records are
        never user-managed). ``include_no_description`` and ``deduplicate``
        are then applied as Python-side filters on the cached list.

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
            raw = getattr(self, "_raw_cache", None)
            if raw is None:
                ep = self.query_all_endpoint()
                ep.fabric_name = self.fabric_name
                ep.lucene_params.max = 10000
                result = self._request(path=ep.path, verb=ep.verb, not_found_ok=True)
                groups = result.get("policyGroups", []) or []
                # Filter out internal controller artifacts (e.g. switch_freeform_config
                # records auto-generated during deletion of PYTHON content-type
                # policy groups). These have a non-empty "source" field referencing
                # the original policy ID and are never user-managed.
                # Per the policyBase schema, ``source`` defaults to ``""`` and is
                # falsy for user-created groups; ``not g.get("source")`` covers
                # ``""``, ``None``, and missing — all spec-valid forms.
                raw = [g for g in groups if not g.get("source")]
                # Cache without the per-call filters so other callers can re-derive
                # their view. Use object.__setattr__ to bypass Pydantic validation.
                object.__setattr__(self, "_raw_cache", raw)

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
        """Drop the cached query_all response after any mutation."""
        object.__setattr__(self, "_raw_cache", None)

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

    def query_by_id(self, policy_group_id: str) -> ResponseType:
        """GET /policyGroups/{policyGroupId} — fetch a single policy group by ID."""
        try:
            ep = self.query_one_endpoint()
            ep.fabric_name = self.fabric_name
            ep.policy_group_id = policy_group_id
            result = self._request(path=ep.path, verb=ep.verb, not_found_ok=True)
            if isinstance(result, dict) and result.get("policyId"):
                return result
            return None
        except Exception as e:
            raise Exception(f"Query policy group by ID failed: {e}") from e

    def query_filtered(
        self,
        template_name: str = None,
        description: str = None,
        *,
        deduplicate: bool = True,
    ) -> ResponseType:
        """GET /policyGroups with Lucene filter — server-side filtering.

        Args:
            template_name: Filter by templateName (exact match via Lucene).
            description: Filter by description (exact match via Lucene).
            deduplicate: See :meth:`query_all`. Defaults to True for safe
                state-machine consumption; ``state: gathered`` passes False
                so duplicate policies with distinct ``policyId``s are visible.

        Returns:
            Filtered list of policy group dicts (deduplicated by default).
        """
        try:
            # Serve from cache if populated; ``_raw_cache`` already has the
            # ``source``-artifact filter applied. We re-apply the requested
            # template_name / description filters in memory to mirror the
            # semantics of the server-side Lucene query.
            raw = getattr(self, "_raw_cache", None)
            if raw is not None:
                groups = raw
                if template_name:
                    groups = [g for g in groups if g.get("templateName") == template_name]
                if description:
                    groups = [g for g in groups if g.get("description") == description]
                if deduplicate:
                    return self._deduplicate_groups(groups)
                return list(groups)

            ep = self.query_all_endpoint()
            ep.fabric_name = self.fabric_name
            ep.lucene_params.max = 10000

            # Build Lucene filter expression
            filters = []
            if template_name:
                filters.append(f"templateName:{template_name}")
            if description:
                filters.append(f"description:{description}")
            if filters:
                ep.lucene_params.filter = " AND ".join(filters)

            result = self._request(path=ep.path, verb=ep.verb, not_found_ok=True)
            groups = result.get("policyGroups", []) or []
            groups = [g for g in groups if not g.get("source")]
            if deduplicate:
                return self._deduplicate_groups(groups)
            return groups
        except Exception as e:
            raise Exception(f"Query filtered policy groups failed: {e}") from e

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

            payload = {"policyGroups": [m.to_payload() for m in model_instances]}
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

            # Capture current switch_ids before update for removal detection
            old_switch_ids = self._get_current_switch_ids(policy_group_id)

            ep = self.update_endpoint()
            ep.fabric_name = self.fabric_name
            ep.policy_group_id = policy_group_id

            result = self._request(path=ep.path, verb=ep.verb, data=model_instance.to_payload())

            # Deploy if requested.
            #
            # NOTE: ``policyActions/pushConfig`` is not supported for
            # policy groups, so we deploy at the switch level instead.
            # The set of affected switches is the union of the new
            # switch_ids (so the updated config is pushed) and any
            # switches that were removed from the group (so the negative
            # / removal config is pushed to them).
            if self.deploy:
                new_switch_ids = set(model_instance.switch_ids or [])
                removed_switches = old_switch_ids - new_switch_ids
                affected_switches = {sid for sid in new_switch_ids | removed_switches if sid}
                if affected_switches:
                    self._switch_deploy(sorted(affected_switches))

            self._invalidate_cache()
            return result
        except Exception as e:
            raise Exception(f"Update policy group failed for {model_instance.description!r}: {e}") from e

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
        2. For mark-failed groups (switch_freeform/PYTHON types): direct
           ``DELETE /policyGroups/<id>``.
        3. **Single** ``switchActions/deploy`` against the **union** of all
           affected switches (both markDelete-succeeded and direct-deleted).

        Consolidating the deploy into one call avoids hitting the same
        switch twice when a batch mixes markDelete-eligible and
        direct-delete groups that share switches.

        When ``deploy=False``, markDelete (and direct DELETE for failures)
        is performed without the trailing switch deploy.
        """
        try:
            policy_ids = [m.policy_id for m in model_instances if m.policy_id]
            if not policy_ids:
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

            # Step 2: Direct DELETE fallback for markDelete failures
            # (switch_freeform / PYTHON-type groups that the controller does
            # not allow to be markDeleted).
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
                if affected_switches:
                    log.debug(
                        "delete_bulk: Step 3 - consolidated switchActions/deploy, switches=%s",
                        sorted(affected_switches),
                    )
                    self._switch_deploy(list(affected_switches))
                else:
                    log.debug("delete_bulk: Step 3 skipped (no affected switches).")

            log.debug(
                "delete_bulk: Complete. mark_succeeded=%s, direct_deleted=%s",
                mark_succeeded,
                direct_deleted,
            )
            self._invalidate_cache()
            return {"policyIds": policy_ids, "status": "success"}
        except Exception as e:
            raise Exception(f"Bulk delete policy groups failed: {e}") from e

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _mark_delete(self, policy_ids: list[str]) -> ResponseType:
        """POST /policyGroups/actions/markDelete with policy IDs."""
        ep = self.mark_delete_endpoint()
        ep.fabric_name = self.fabric_name
        payload = {"policyIds": policy_ids}
        return self._request(path=ep.path, verb=ep.verb, data=payload)

    def _switch_deploy(self, switch_ids: list[str]) -> ResponseType:
        """POST /switchActions/deploy to deploy config to specific switches.

        Sends a single bulk request with every ``switchId`` in one
        ``{"switchIds": [...]}`` payload. The controller responds with a
        per-switch status array of the form::

            {
                "switchIds": [
                    {"switchId": "<sn>", "status": "success",     "message": "Deployed Successfully"},
                    {"switchId": "<sn>", "status": "notExecuted", "message": "No Commands to execute"},
                    {"switchId": "<sn>", "status": "failed",      "message": "<reason>"},
                ]
            }

        """
        ep = self.switch_deploy_endpoint()
        ep.fabric_name = self.fabric_name
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

    def _get_current_switch_ids(self, policy_group_id: str) -> set:
        """Return a policy group's current switch_ids.

        Prefers the cached ``query_all`` response when available so we avoid
        a redundant ``GET /policyGroups/{id}`` round-trip; falls back to the
        single-resource endpoint only when the cache is empty (e.g. orchestrator
        used standalone without a prior ``query_all``).
        """
        raw = getattr(self, "_raw_cache", None)
        if raw is not None:
            for g in raw:
                if g.get("policyId") == policy_group_id:
                    return set(g.get("switchIds", []) or [])
            # Cache present but ID not found — group was likely just created in
            # this run; treat as having no prior switches.
            return set()
        try:
            ep = self.query_one_endpoint()
            ep.fabric_name = self.fabric_name
            ep.policy_group_id = policy_group_id
            result = self._request(path=ep.path, verb=ep.verb, not_found_ok=True)
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
