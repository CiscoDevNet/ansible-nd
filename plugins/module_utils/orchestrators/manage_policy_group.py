# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Orchestrator for ND Policy Group CRUD and deploy operations.

Extends ``NDBaseOrchestrator`` with custom logic for:
- Bulk create via ``POST /policyGroups`` with ``{"policyGroups": [...]}`` wrapper
- Update via ``PUT /policyGroups/{policyGroupId}`` (resolves server-generated ID)
- Delete via ``markDelete`` → switch-level deploy (pushes removal config)
- Deploy via ``POST /policyActions/pushConfig`` (create/update) or
  ``POST /switchActions/deploy`` (delete — pushes removal config)
- Query extracting ``policyGroups`` list from GET response
"""

from __future__ import annotations

import logging
from typing import ClassVar

log = logging.getLogger("nd.PolicyGroupOrchestrator")

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_policy_actions import (
    EpManagePolicyActionsPushConfigPost,
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
    - **Deploy (merged)**: ``POST /policyActions/pushConfig`` with
      ``{"policyIds": [...]}`` containing the server-generated IDs.
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
    push_config_endpoint: type[NDEndpointBaseModel] = EpManagePolicyActionsPushConfigPost
    switch_deploy_endpoint: type[NDEndpointBaseModel] = EpManageSwitchActionsDeployPost

    # Configuration
    fabric_name: str | None = None
    deploy: bool = True

    # ------------------------------------------------------------------ #
    # Query operations
    # ------------------------------------------------------------------ #

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        """GET /policyGroups — extract ``policyGroups`` list from response.

        Deduplicates results by ``(description, templateName)`` composite key.
        If the controller returns multiple groups with the same key (e.g. created
        via UI), the most recently updated group is kept and others are silently
        dropped to prevent ``NDConfigCollection`` from raising on duplicate keys.
        """
        try:
            ep = self.query_all_endpoint()
            ep.fabric_name = self.fabric_name
            ep.lucene_params.max = 10000
            result = self._request(path=ep.path, verb=ep.verb, not_found_ok=True)
            groups = result.get("policyGroups", []) or []
            # Filter out internal controller artifacts (e.g. switch_freeform_config
            # records created during deletion of PYTHON content-type policy groups).
            # These have a non-empty "source" field referencing the original policy ID.
            groups = [g for g in groups if not g.get("source")]
            return self._deduplicate_groups(groups)
        except Exception as e:
            raise Exception(f"Query all policy groups failed: {e}") from e

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

    def query_filtered(self, template_name: str = None, description: str = None) -> ResponseType:
        """GET /policyGroups with Lucene filter — server-side filtering.

        Args:
            template_name: Filter by templateName (exact match via Lucene).
            description: Filter by description (exact match via Lucene).

        Returns:
            Filtered, deduplicated list of policy group dicts.
        """
        try:
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
            return self._deduplicate_groups(groups)
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

        After creation, populates ``policy_id`` on each model instance
        from the API response for subsequent deploy/update operations.
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

            # Deploy if requested
            if self.deploy:
                policy_ids = [m.policy_id for m in model_instances if m.policy_id]
                if policy_ids:
                    self._push_config(policy_ids)

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

            # Deploy if requested
            if self.deploy:
                new_switch_ids = set(model_instance.switch_ids or [])
                removed_switches = old_switch_ids - new_switch_ids

                # Push config for the policy group itself
                self._push_config([policy_group_id])

                # Switch-level deploy on removed switches to push negative config
                if removed_switches:
                    self._switch_deploy(list(removed_switches))

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
        2. **Switch-level deploy** on all affected switches (bulk) to push
           the removal (negative) configuration.
        3. For mark-failed groups (switch_freeform/PYTHON types): direct
           DELETE, then switch-level deploy on their affected switches.

        When ``deploy=False``, markDelete is performed for normal
        groups, and direct DELETE for PYTHON-type groups (no switch deploy).
        """
        try:
            policy_ids = [m.policy_id for m in model_instances if m.policy_id]
            if not policy_ids:
                log.debug("delete_bulk: No policy_ids to delete, returning early.")
                return {}

            log.debug("delete_bulk: Starting deletion for policy_ids=%s, deploy=%s", policy_ids, self.deploy)

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
            if isinstance(mark_result, dict):
                policies_response = mark_result.get("policyGroups", [])
                failed_set = set()
                for p in policies_response:
                    pid = p.get("policyId", "")
                    status = str(p.get("status", "")).lower()
                    if status != "success":
                        failed_set.add(pid)
                        mark_failed_ids.append(pid)
                mark_succeeded = [pid for pid in policy_ids if pid not in failed_set]
                # If empty response, treat all as succeeded (ambiguous)
                if not policies_response and policy_ids:
                    mark_succeeded = list(policy_ids)
            else:
                mark_succeeded = list(policy_ids)

            log.debug("delete_bulk: markDelete succeeded=%s, failed=%s", mark_succeeded, mark_failed_ids)

            # Step 2: Switch-level deploy for markDeleted groups to push removal config
            if self.deploy and mark_succeeded:
                affected_switches = set()
                for pid in mark_succeeded:
                    switch_ids = switch_ids_by_policy.get(pid, [])
                    affected_switches.update(switch_ids)
                log.debug("delete_bulk: Step 2 - switchActions/deploy for markDeleted groups, switches=%s", affected_switches)
                if affected_switches:
                    self._switch_deploy(list(affected_switches))

            # Step 3: Direct DELETE fallback for markDelete failures (switch_freeform/PYTHON types)
            direct_deleted = []
            if mark_failed_ids:
                log.debug("delete_bulk: Step 3 - Direct DELETE fallback for failed=%s", mark_failed_ids)
                for pid in mark_failed_ids:
                    ep = self.delete_endpoint()
                    ep.fabric_name = self.fabric_name
                    ep.policy_group_id = pid
                    self._request(path=ep.path, verb=ep.verb)
                    direct_deleted.append(pid)

            # Step 4: Switch-level deploy for direct-deleted groups
            if self.deploy and direct_deleted:
                affected_switches = set()
                for pid in direct_deleted:
                    switch_ids = switch_ids_by_policy.get(pid, [])
                    affected_switches.update(switch_ids)
                log.debug("delete_bulk: Step 4 - switchActions/deploy for direct-deleted groups, switches=%s", affected_switches)
                if affected_switches:
                    self._switch_deploy(list(affected_switches))

            log.debug("delete_bulk: Complete. mark_succeeded=%s, direct_deleted=%s", mark_succeeded, direct_deleted)
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

    def _push_config(self, policy_ids: list[str]) -> ResponseType:
        """POST /policyActions/pushConfig with policy IDs."""
        ep = self.push_config_endpoint()
        ep.fabric_name = self.fabric_name
        payload = {"policyIds": policy_ids}
        return self._request(path=ep.path, verb=ep.verb, data=payload)

    def _switch_deploy(self, switch_ids: list[str]) -> ResponseType:
        """POST /switchActions/deploy to deploy config to specific switches.

        Used after removing switches from a policy group to push the
        negative (removal) configuration to those switches.
        """
        ep = self.switch_deploy_endpoint()
        ep.fabric_name = self.fabric_name
        payload = {"switchIds": switch_ids}
        return self._request(path=ep.path, verb=ep.verb, data=payload)

    def _get_current_switch_ids(self, policy_group_id: str) -> set:
        """Query the API for a policy group's current switch_ids."""
        try:
            ep = self.query_one_endpoint()
            ep.fabric_name = self.fabric_name
            ep.policy_group_id = policy_group_id
            result = self._request(path=ep.path, verb=ep.verb, not_found_ok=True)
            if isinstance(result, dict):
                return set(result.get("switchIds", []) or [])
            return set()
        except Exception:
            return set()

    @staticmethod
    def _populate_policy_ids(
        model_instances: list[PolicyGroupCreate],
        response_groups: list,
    ) -> None:
        """Match API response items back to model instances and set policy_id.

        Matching is done by templateName + description since those form
        the user-facing identity of a policy group.
        """
        if not response_groups:
            return

        # Build lookup from (templateName, description) → policyId
        response_lookup = {}
        for rg in response_groups:
            key = (rg.get("templateName", ""), rg.get("description", ""))
            pid = rg.get("policyId")
            if pid:
                response_lookup[key] = pid

        for model in model_instances:
            key = (model.template_name, model.description or "")
            pid = response_lookup.get(key)
            if pid:
                model.policy_id = pid
