# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import copy
import logging
import time

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModule
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_config_model import (
    ResourceManagerConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_response_model import ResourceManagerResponse
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.remove_resource_by_id_request_model import (
    RemoveResourcesByIdsRequest,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.remove_resource_by_id_response_model import (
    RemoveResourcesByIdsResponse,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_request_model import (
    ResourceManagerBatchRequest,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_response_model import (
    ResourcesManagerBatchResponse,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_resources import (
    EpManageFabricResourcesGet,
    EpManageFabricResourcesPost,
    EpManageFabricResourcesActionsRemovePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDModuleError
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.switch_data_models import (
    SwitchDataModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.fabric_inventory import FabricSwitchInventory
from ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.resource_manager_diff import ResourceManagerDiffEngine
from ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.resource_manager_helpers import ResourceManagerResourceHelpersMixin

# =========================================================================
# Resource Manager module
# =========================================================================


class NDResourceManagerModule(ResourceManagerResourceHelpersMixin):
    """
    Manage resources in Cisco Nexus Dashboard via the ND Manage v1 API.

    Uses pydantic models for input validation and smart endpoints for path/verb generation.
    Preserves the same business logic as nd_manage_resource_manager.py.
    """

    RESOURCE_PAGE_SIZE = 500

    def __init__(
        self,
        nd: NDModule,
        results: Results,
        log: logging.Logger | None = None,
    ):
        """Initialise the module and resolve fabric/state from ND params.

        Resource inventory is intentionally loaded after validation in
        ``manage_state()`` so gathered, merged, and deleted states can use paginated
        and, where safe, API-filtered candidate reads instead of a constructor-time
        fabric-wide scan.

        Args:
            nd: Initialised ``NDModule`` wrapper that holds the Ansible module params
                and the underlying ``RestSend`` HTTP client.
            results: ``Results`` instance used to accumulate API call results and
                build the final module output.
            log: External logger if provided. If not, a module-level logger
                (``logging.getLogger("nd.NDResourceManagerModule")``) is used.
        """
        self.nd = nd
        self.results = results
        self.log = log if log is not None else logging.getLogger("nd.NDResourceManagerModule")
        self.fabric = nd.params["fabric"]
        self.state = nd.params["state"]
        self.config = nd.params.get("config") or []

        # ND-compatible tracking dicts
        self.changed_dict = [{"merged": [], "deleted": [], "gathered": [], "debugs": []}]
        self.api_responses = []

        # Cached GET results — resources
        self._all_resources = []
        self._resources_fetched = False

        # Translate playbook switch IPs to switch IDs through the shared fabric inventory helper.
        self.config = self._resolve_switch_ids_in_config(self.config)

        # Resource collections — populated after validation in manage_state.
        self.existing: list[ResourceManagerResponse] = []
        self.previous: list[ResourceManagerResponse] = []
        self.proposed: list[ResourceManagerConfigModel] = []

        # NDOutput for building consistent Ansible output across all states
        self.output: NDOutput = NDOutput(output_level=nd.params.get("output_level", "normal"))

        # Proposed config list (plain dicts) for NDOutput proposed field
        self._proposed_list: list = []

        # Propagate Results metadata so every register_api_call() inherits state/check_mode
        self.results.state = self.state
        self.results.check_mode = nd.module.check_mode

        self.log.info(
            "NDResourceManagerModule initialized: fabric=%s, state=%s, config_count=%s",
            self.fabric,
            self.state,
            len(self.config),
        )

    # ------------------------------------------------------------------
    # Results registration helper
    # ------------------------------------------------------------------

    def _register_result(self, action, operation_type, message, changed, diff=None, verb=HttpVerbEnum.GET, path="", payload=None):
        """Register a successful API call result with the Results tracker.

        Centralises the repeated pattern of setting action, operation_type,
        response_current, result_current, diff_current and calling
        ``register_api_call()``.  All calls use ``RETURN_CODE=200`` and
        ``success=True``; error paths in the main module entry point set
        these fields directly.

        Args:
            action: Short label for the operation (e.g. ``'merge'``, ``'delete'``, ``'gathered'``).
            operation_type: ``OperationType`` enum value.
            message: Human-readable message for ``response_current["MESSAGE"]``.
            changed: Whether the operation mutated state.
            diff: Diff dict to attach when provided. Defaults to ``{}``.
            verb: ``HttpVerbEnum`` value for the HTTP method used.  Defaults to ``GET``.
            path: API endpoint path string.  Defaults to ``""``.
            payload: Request payload dict, or ``None`` for GET / no-body requests.
        """
        self.results.action = action
        self.results.operation_type = operation_type
        self.results.verb_current = verb
        self.results.path_current = path
        self.results.payload_current = payload
        self.results.response_current = {"RETURN_CODE": 200, "MESSAGE": message}
        self.results.result_current = {"success": True, "changed": changed}
        self.results.diff_current = diff if diff is not None else {}
        self.results.register_api_call()

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------

    def _validate_required_fields_compat(self):
        """Preserve legacy first-missing-field error messages for modifying states."""
        for item in self.config:
            for field in ("scope_type", "pool_type", "pool_name", "entity_name"):
                if item.get(field) is None:
                    self.log.error(
                        "Mandatory parameter '%s' is missing in config item: %s",
                        field,
                        item,
                    )
                    raise ValueError("Mandatory parameter '{0}' missing".format(field))

            if item.get("scope_type") != "fabric" and not item.get("switches"):
                self.log.error(
                    "'switches' is required for scope_type='%s' but is missing in config item: %s",
                    item.get("scope_type"),
                    item,
                )
                raise ValueError("switches : Required parameter not found")

    def _validate_input(self):
        """Validate playbook config items and return typed proposed config.

        ``ResourceManagerConfigModel`` is the primary validation surface. For
        ``merged`` and ``deleted`` it enforces mandatory fields, resource format,
        strict ID pool names, pool/scope compatibility, and required switch lists.
        For ``gathered`` it validates any supplied filter fields while allowing
        partial criteria such as only ``entity_name`` or only ``pool_name``.

        Raises:
            ValueError: On any validation failure.

        Returns:
            Validated config models for ``merged``/``deleted``. Gathered returns
            an empty list because gathered config is used as raw filter criteria.
        """
        self.log.info(
            "Validating input: state=%s, config_count=%s",
            self.state,
            len(self.config),
        )

        if not self.config:
            if self.state in ("merged", "deleted"):
                self.log.error(
                    "'config' is mandatory for state '%s' but was not provided",
                    self.state,
                )
                raise ValueError("'config' element is mandatory for state '{0}'".format(self.state))
            return []

        if self.state != "gathered":
            self._validate_required_fields_compat()
            return ResourceManagerDiffEngine.validate_configs(self.config, self.state, log=self.log)

        for idx, item in enumerate(self.config):
            try:
                ResourceManagerConfigModel.model_validate(item, context={"state": self.state})
            except ValidationError as exc:
                error_detail = exc.errors() if hasattr(exc, "errors") else str(exc)
                error_msg = f"Gathered filter validation failed for config index {idx}: {error_detail}"
                self.log.error(error_msg)
                raise ValueError(error_msg) from exc
            except Exception as exc:
                error_msg = f"Gathered filter validation failed for config index {idx}: {str(exc)}"
                self.log.error(error_msg)
                raise ValueError(error_msg) from exc
            self.log.debug(
                "Gathered filter [%s] validated: entity_name=%s, pool_name=%s, switches=%s",
                idx,
                item.get("entity_name"),
                item.get("pool_name"),
                item.get("switches"),
            )

        return []

    # ------------------------------------------------------------------
    # ND API interaction helpers
    # ------------------------------------------------------------------

    def _build_resources_get_endpoint(self, pool_name=None, switch_id=None, filter_expr=None, max_results=None, offset=None):
        """Build a resources GET endpoint with safe optional query parameters."""
        self.log.debug(
            "_build_resources_get_endpoint: fabric=%s, pool_name=%s, switch_id=%s, filter_expr=%s, max=%s, offset=%s",
            self.fabric,
            pool_name,
            switch_id,
            filter_expr,
            max_results,
            offset,
        )
        ep = EpManageFabricResourcesGet(fabric_name=self.fabric)
        if pool_name:
            ep.endpoint_params.pool_name = pool_name
        if switch_id:
            ep.endpoint_params.switch_id = switch_id
        if filter_expr:
            ep.lucene_params.filter = filter_expr
        if max_results is not None:
            ep.lucene_params.max = max_results
        if offset is not None:
            ep.lucene_params.offset = offset
        self.log.debug("_build_resources_get_endpoint: built path=%s, verb=%s", ep.path, ep.verb)
        return ep

    def _resources_from_response(self, data):
        """Extract a resources list from supported ND API response shapes."""
        if isinstance(data, list):
            self.log.debug("_resources_from_response: response is bare list with %s resource(s)", len(data))
            return data
        if isinstance(data, dict) and isinstance(data.get("resources"), list):
            self.log.debug(
                "_resources_from_response: response dict contains resources list with %s resource(s)",
                len(data["resources"]),
            )
            return data["resources"]
        if isinstance(data, dict) and data and "resources" not in data and "meta" not in data:
            self.log.debug("_resources_from_response: response is single resource dict, wrapping in list")
            return [data]
        self.log.debug(
            "_resources_from_response: response shape has no resources, treating as empty (type=%s)",
            type(data).__name__,
        )
        return []

    def _remaining_from_response(self, data):
        """Return ``meta.counts.remaining`` from a response when present."""
        if not isinstance(data, dict):
            self.log.debug("_remaining_from_response: response is %s, no pagination metadata", type(data).__name__)
            return None
        meta = data.get("meta")
        if not isinstance(meta, dict):
            self.log.debug("_remaining_from_response: no meta dict in response")
            return None
        counts = meta.get("counts")
        if not isinstance(counts, dict):
            self.log.debug("_remaining_from_response: no meta.counts dict in response")
            return None
        remaining = counts.get("remaining")
        if remaining is None:
            self.log.debug("_remaining_from_response: meta.counts.remaining is absent")
            return None
        try:
            remaining_int = int(remaining)
            self.log.debug("_remaining_from_response: remaining_raw=%s, remaining_int=%s", remaining, remaining_int)
            return remaining_int
        except (TypeError, ValueError):
            self.log.debug("_remaining_from_response: remaining value is not an integer: %s", remaining)
            return None

    def _has_next_page(self, data):
        """Return True when response metadata advertises a next page."""
        if not isinstance(data, dict):
            self.log.debug("_has_next_page: response is %s, no next-page metadata", type(data).__name__)
            return False
        meta = data.get("meta")
        if not isinstance(meta, dict):
            self.log.debug("_has_next_page: no meta dict in response")
            return False
        links = meta.get("links")
        has_next = isinstance(links, dict) and bool(links.get("next"))
        self.log.debug("_has_next_page: has_next=%s, next=%s", has_next, links.get("next") if isinstance(links, dict) else None)
        return has_next

    def _parse_resource_list(self, raw_list):
        """Normalise raw resource entries to response models, preserving raw dicts on parse failure."""
        self.log.debug("_parse_resource_list: parsing %s raw resource item(s)", len(raw_list))
        resources = []
        for raw in raw_list:
            try:
                resource_model = ResourceManagerResponse.from_response(raw)
                self.log.debug(
                    "Parsed resource: entity_name=%s, pool_name=%s",
                    getattr(resource_model, "entity_name", None),
                    getattr(resource_model, "pool_name", None),
                )
                resources.append(resource_model)
            except Exception as exc:
                self.log.warning(
                    "Failed to parse resource into ResourceManagerResponse (keeping raw): %s | raw=%s",
                    exc,
                    raw,
                )
                resources.append(raw)
        self.log.debug("_parse_resource_list: parsed %s resource item(s)", len(resources))
        return resources

    def _fetch_resources_paginated(self, pool_name=None, switch_id=None, filter_expr=None):
        """Fetch resource inventory through the paginated resources GET endpoint."""
        self.log.info(
            "_fetch_resources_paginated: starting resource fetch for fabric=%s, pool_name=%s, switch_id=%s, filter_expr=%s",
            self.fabric,
            pool_name,
            switch_id,
            filter_expr,
        )
        resources = []
        offset = 0
        page_size = self.RESOURCE_PAGE_SIZE
        visited_offsets = set()
        page_count = 0
        max_pages = 10000

        while True:
            if offset in visited_offsets:
                self.log.warning(
                    "_fetch_resources_paginated: detected repeated offset=%s; stopping pagination to avoid loop",
                    offset,
                )
                break
            visited_offsets.add(offset)
            page_count += 1
            if page_count > max_pages:
                self.log.warning(
                    "_fetch_resources_paginated: exceeded max_pages=%s; stopping pagination for safety",
                    max_pages,
                )
                break

            self.log.debug(
                "_fetch_resources_paginated: requesting page offset=%s, page_size=%s, pool_name=%s, switch_id=%s, filter_expr=%s",
                offset,
                page_size,
                pool_name,
                switch_id,
                filter_expr,
            )
            ep = self._build_resources_get_endpoint(
                pool_name=pool_name,
                switch_id=switch_id,
                filter_expr=filter_expr,
                max_results=page_size,
                offset=offset,
            )
            api_start = time.monotonic()
            try:
                data = self.nd.request(ep.path, ep.verb)
            except NDModuleError as exc:
                api_elapsed = time.monotonic() - api_start
                if exc.status == 404:
                    self.log.info(
                        "_fetch_resources_paginated: GET resources returned 404 after %.3f second(s) "
                        "(path=%s, state=%s), treating as empty",
                        api_elapsed,
                        ep.path,
                        self.state,
                    )
                    break
                self.log.exception(
                    "_fetch_resources_paginated: GET resources API call failed after %.3f second(s) (path=%s, state=%s)",
                    api_elapsed,
                    ep.path,
                    self.state,
                )
                raise ValueError(
                    f"_fetch_resources_paginated: GET resources API call failed after {api_elapsed:.3f} second(s)"
                    f" (path={ep.path}, state={self.state})"
                ) from exc
            except Exception:
                api_elapsed = time.monotonic() - api_start
                self.log.exception(
                    "_fetch_resources_paginated: GET resources API call failed after %.3f second(s) (path=%s, state=%s)",
                    api_elapsed,
                    ep.path,
                    self.state,
                )
                raise ValueError(
                    f"_fetch_resources_paginated: GET resources API call failed after {api_elapsed:.3f} second(s)"
                    f" (path={ep.path}, state={self.state})"
                )

            api_elapsed = time.monotonic() - api_start
            raw_list = self._resources_from_response(data)
            remaining = self._remaining_from_response(data)
            remaining_raw = None
            total_count = None
            if isinstance(data, dict):
                meta = data.get("meta")
                if isinstance(meta, dict):
                    counts = meta.get("counts")
                    if isinstance(counts, dict):
                        remaining_raw = counts.get("remaining")
                        total_count = counts.get("total")
            has_next = self._has_next_page(data)
            self.log.info(
                "_fetch_resources_paginated: GET resources API response time %.3f second(s) "
                "(path=%s, state=%s, response_count=%s, remaining=%s, remaining_raw=%s, total=%s, has_next=%s)",
                api_elapsed,
                ep.path,
                self.state,
                len(raw_list),
                remaining,
                remaining_raw,
                total_count,
                has_next,
            )

            resources.extend(self._parse_resource_list(raw_list))
            batch_count = len(raw_list)
            self.log.info(
                "_fetch_resources_paginated: pagination iteration=%s "
                "(offset=%s, page_size=%s, fetched_this_page=%s, cumulative_fetched=%s, remaining=%s, remaining_raw=%s, total=%s, has_next=%s)",
                page_count,
                offset,
                page_size,
                batch_count,
                len(resources),
                remaining,
                remaining_raw,
                total_count,
                has_next,
            )

            # Stop pagination when response is a bare list (no pagination metadata)
            if isinstance(data, list):
                self.log.debug("_fetch_resources_paginated: stopping pagination because response was a bare list")
                break
            # Stop pagination when page returned no resources
            if not raw_list:
                self.log.debug("_fetch_resources_paginated: stopping pagination because page returned no resources")
                break

            next_offset = offset + batch_count
            if next_offset <= offset:
                self.log.warning(
                    "_fetch_resources_paginated: non-increasing next_offset detected (offset=%s, batch_count=%s); "
                    "stopping pagination to avoid loop",
                    offset,
                    batch_count,
                )
                break

            # Use remaining count as primary pagination indicator (most reliable)
            if remaining is not None:
                if remaining <= 0:
                    self.log.debug("_fetch_resources_paginated: stopping pagination because remaining=%s", remaining)
                    if remaining < 0:
                        self.log.warning(
                            "_fetch_resources_paginated: API returned negative remaining count (%s); "
                            "stopping pagination early to avoid infinite loop or further data loss",
                            remaining,
                        )
                    break
                # Continue to next page when remaining > 0
                self.log.debug(
                    "_fetch_resources_paginated: continuing pagination because remaining=%s > 0; next_offset=%s",
                    remaining,
                    next_offset,
                )
                offset = next_offset
                continue

            # Fallback: use next-page metadata when remaining count not available
            if has_next:
                self.log.debug(
                    "_fetch_resources_paginated: continuing pagination because has_next=True; next_offset=%s",
                    next_offset,
                )
                offset = next_offset
                continue

            # Final fallback: continue if we got a full page, stop if partial page
            if batch_count < page_size:
                self.log.debug(
                    "_fetch_resources_paginated: stopping pagination because response_count=%s is smaller than page_size=%s",
                    batch_count,
                    page_size,
                )
                break

            # Safeguard: always continue fetching when we got a full page
            self.log.debug(
                "_fetch_resources_paginated: continuing pagination via fallback (full page retrieved); next_offset=%s",
                next_offset,
            )
            offset = next_offset

        self.log.info(
            "_fetch_resources_paginated: completed resource fetch for fabric=%s, total_resources=%s, total_iterations=%s",
            self.fabric,
            len(resources),
            page_count,
        )
        return resources

    def _get_all_resources(self):
        """Fetch all existing resources for the fabric from the ND Manage API and cache them."""
        if self._resources_fetched:
            self.log.debug(
                "Resources already cached for fabric=%s: %s resource(s)",
                self.fabric,
                len(self._all_resources),
            )
            return

        self.log.info("Fetching all resources for fabric=%s", self.fabric)
        self._all_resources = self._fetch_resources_paginated()
        self._resources_fetched = True
        self.log.info(
            "Fetched %s resource(s) for fabric=%s",
            len(self._all_resources),
            self.fabric,
        )

    def _entity_filter(self, entity_name):
        """Build the exact entityName Lucene filter used for safe gathered narrowing."""
        filter_expr = f"entityName:{entity_name}" if entity_name else None
        self.log.debug("_entity_filter: entity_name=%s, filter_expr=%s", entity_name, filter_expr)
        return filter_expr

    def _resource_unique_key(self, resource):
        """Return a stable fallback key for deduplicating resources without IDs."""
        key = (
            self._get_entity_name(resource),
            self._get_pool_name(resource),
            self._get_resource_value(resource),
            self._get_scope_type(resource),
            self._get_switch_id(resource),
        )
        self.log.debug("_resource_unique_key: key=%s", key)
        return key

    def _deduplicate_resources(self, resources):
        """Deduplicate resources returned by overlapping filtered API calls."""
        self.log.debug("_deduplicate_resources: starting with %s resource candidate(s)", len(resources))
        deduped = []
        seen_ids = set()
        seen_keys = set()
        for resource in resources:
            resource_id = self._get_resource_id(resource)
            if resource_id is not None:
                if resource_id in seen_ids:
                    self.log.debug("_deduplicate_resources: skipping duplicate resource_id=%s", resource_id)
                    continue
                seen_ids.add(resource_id)
                deduped.append(resource)
                continue

            key = self._resource_unique_key(resource)
            if key in seen_keys:
                self.log.debug("_deduplicate_resources: skipping duplicate fallback key=%s", key)
                continue
            seen_keys.add(key)
            deduped.append(resource)
        self.log.debug(
            "_deduplicate_resources: reduced %s candidate(s) to %s unique resource(s)",
            len(resources),
            len(deduped),
        )
        return deduped

    def _fetch_resources_for_criteria(self, criteria):
        """Fetch and deduplicate resource candidates for a list of query criteria."""
        if not criteria:
            self.log.debug("_fetch_resources_for_criteria: no criteria supplied, returning empty resource list")
            return []

        self.log.info("_fetch_resources_for_criteria: fetching resources for %s criteria item(s)", len(criteria))
        resources = []
        seen_criteria = set()
        for idx, (pool_name, switch_id, filter_expr) in enumerate(criteria):
            criteria_key = (pool_name, switch_id, filter_expr)
            if criteria_key in seen_criteria:
                self.log.debug("_fetch_resources_for_criteria: skipping duplicate criteria[%s]=%s", idx, criteria_key)
                continue
            seen_criteria.add(criteria_key)
            self.log.debug(
                "_fetch_resources_for_criteria: fetching criteria[%s]: pool_name=%s, switch_id=%s, filter_expr=%s",
                idx,
                pool_name,
                switch_id,
                filter_expr,
            )
            resources.extend(
                self._fetch_resources_paginated(
                    pool_name=pool_name,
                    switch_id=switch_id,
                    filter_expr=filter_expr,
                )
            )
        deduped = self._deduplicate_resources(resources)
        self.log.info(
            "_fetch_resources_for_criteria: fetched %s resource candidate(s), %s unique resource(s)",
            len(resources),
            len(deduped),
        )
        return deduped

    def _build_gathered_resource_criteria(self):
        """Build safe filtered GET criteria from gathered config filters."""
        self.log.debug(
            "_build_gathered_resource_criteria: building criteria from %s gathered filter item(s)",
            len(self.config or []),
        )
        criteria = []
        for idx, filter_item in enumerate(self.config):
            if not self._filter_has_active_criteria(filter_item):
                self.log.debug("_build_gathered_resource_criteria: skipping empty filter item at index=%s", idx)
                continue

            pool_name = filter_item.get("pool_name")
            filter_expr = self._entity_filter(filter_item.get("entity_name"))
            filter_switches = filter_item.get("switches") or [None]
            for switch_id in filter_switches:
                criteria.append((pool_name, switch_id, filter_expr))
                self.log.debug(
                    "_build_gathered_resource_criteria: added criteria from filter index=%s: pool_name=%s, switch_id=%s, filter_expr=%s",
                    idx,
                    pool_name,
                    switch_id,
                    filter_expr,
                )
        self.log.debug("_build_gathered_resource_criteria: built %s criteria item(s)", len(criteria))
        return criteria

    def _switch_filter_supported(self, scope_type):
        """Return True when the resources GET switchId filter safely maps to the scope."""
        supported = scope_type in ("device", "device_interface")
        self.log.debug("_switch_filter_supported: scope_type=%s, supported=%s", scope_type, supported)
        return supported

    def _build_candidate_resource_criteria(self, configs):
        """Build safe filtered GET criteria for modifying states."""
        self.log.debug(
            "_build_candidate_resource_criteria: building criteria from %s validated config item(s)",
            len(configs or []),
        )
        criteria = []
        for idx, cfg in enumerate(configs):
            pool_name = cfg.pool_name
            if self._switch_filter_supported(cfg.scope_type) and cfg.switches:
                for switch_id in cfg.switches:
                    criteria.append((pool_name, switch_id, None))
                    self.log.debug(
                        "_build_candidate_resource_criteria: added switch-filtered criteria from config index=%s: pool_name=%s, switch_id=%s",
                        idx,
                        pool_name,
                        switch_id,
                    )
                continue
            criteria.append((pool_name, None, None))
            self.log.debug(
                "_build_candidate_resource_criteria: added pool-only criteria from config index=%s: pool_name=%s, scope_type=%s",
                idx,
                pool_name,
                cfg.scope_type,
            )
        self.log.debug("_build_candidate_resource_criteria: built %s criteria item(s)", len(criteria))
        return criteria

    def _refresh_existing_resources(self, update_previous=False):
        """Load the current candidate resource snapshot for the active state."""
        self.log.info(
            "_refresh_existing_resources: loading resource snapshot for fabric=%s, state=%s, update_previous=%s",
            self.fabric,
            self.state,
            update_previous,
        )
        if self.state == "gathered":
            if not self.config:
                self.log.debug("_refresh_existing_resources: gathered without config, fetching full paginated inventory")
                resources = self._fetch_resources_paginated()
            else:
                self.log.debug("_refresh_existing_resources: gathered with config, fetching filtered candidate inventory")
                resources = self._fetch_resources_for_criteria(self._build_gathered_resource_criteria())
        else:
            self.log.debug("_refresh_existing_resources: modifying state, fetching filtered candidate inventory")
            resources = self._fetch_resources_for_criteria(self._build_candidate_resource_criteria(self.proposed))

        self._all_resources = resources
        self._resources_fetched = True
        self.existing = list(resources)
        if update_previous:
            self.previous = list(resources)
        self.log.info(
            "_refresh_existing_resources: loaded %s resource(s) for fabric=%s, state=%s",
            len(resources),
            self.fabric,
            self.state,
        )

    def _resolve_switch_ids_in_config(self, config):
        """Translate config ``switches`` values from management IPs to switch IDs.

        Uses ``FabricSwitchInventory`` from ``fabric_inventory.py`` with ``SwitchDataModel`` so
        resource manager shares the same inventory lookup behavior as switch manager.
        Values already provided as switch IDs are preserved.  Unresolved values fail
        early with a clear validation error instead of being passed to the ND API.

        Args:
            config: Raw config list from ``nd.params["config"]``. Not mutated.

        Returns:
            A deep copy of ``config`` with switch IPs replaced by switch IDs.
        """
        config_copy = copy.deepcopy(config or [])

        needs_inventory = any(item.get("switches") for item in config_copy if isinstance(item, dict))
        if not needs_inventory:
            self.log.debug(
                "_resolve_switch_ids_in_config: no switches found in %s config item(s), skipping inventory lookup",
                len(config_copy),
            )
            return config_copy

        self.log.debug(
            "_resolve_switch_ids_in_config: querying switch inventory for fabric=%s to translate %s config item(s)",
            self.fabric,
            len(config or []),
        )

        inventory = FabricSwitchInventory.from_fabric(self.nd, self.fabric, self.log, SwitchDataModel)
        switches_by_ip = inventory.by_ip()
        switches_by_id = inventory.by_id()

        if not getattr(inventory, "switches", None) or (not switches_by_ip and not switches_by_id):
            msg = "No switch inventory found for fabric '{0}'; cannot resolve switches for resource manager config".format(self.fabric)
            self.log.error("_resolve_switch_ids_in_config: %s", msg)
            raise ValueError(msg)

        self.log.debug(
            "_resolve_switch_ids_in_config: inventory indexes built for fabric=%s (by_ip=%s, by_id=%s)",
            self.fabric,
            len(switches_by_ip),
            len(switches_by_id),
        )

        for idx, item in enumerate(config_copy):
            raw_switch_list = item.get("switches") or []
            entity_name = item.get("entity_name")
            scope_type = item.get("scope_type")

            self.log.debug(
                "_resolve_switch_ids_in_config: [%s] entity='%s', scope_type='%s', raw_switch_list=%s",
                idx,
                entity_name,
                scope_type,
                raw_switch_list,
            )

            if not raw_switch_list:
                self.log.debug(
                    "_resolve_switch_ids_in_config: [%s] entity='%s' — no switch list present, skipping translation",
                    idx,
                    entity_name,
                )
                continue

            resolved = []
            for switch_value in raw_switch_list:
                switch_key = str(switch_value).strip()

                if switch_key in switches_by_ip:
                    sw_id = switches_by_ip[switch_key].switch_id
                    self.log.debug(
                        "_resolve_switch_ids_in_config: [%s] entity='%s' switch '%s' -> resolved switchId='%s'",
                        idx,
                        entity_name,
                        switch_value,
                        sw_id,
                    )
                    resolved.append(sw_id)
                    continue

                if switch_key in switches_by_id:
                    self.log.debug(
                        "_resolve_switch_ids_in_config: [%s] entity='%s' switch '%s' is already a switchId",
                        idx,
                        entity_name,
                        switch_value,
                    )
                    resolved.append(switch_key)
                    continue

                msg = (
                    "Switch '{0}' from config item index {1} (entity_name='{2}', "
                    "scope_type='{3}') was not found in fabric '{4}' by management IP "
                    "or switch ID."
                ).format(switch_value, idx, entity_name, scope_type, self.fabric)
                self.log.error("_resolve_switch_ids_in_config: %s", msg)
                raise ValueError(msg)

            item["switches"] = resolved
            self.log.debug(
                "_resolve_switch_ids_in_config: [%s] entity='%s' final switches list: %s -> %s",
                idx,
                entity_name,
                raw_switch_list,
                resolved,
            )

        self.log.debug(
            "_resolve_switch_ids_in_config: completed, returning %s translated config item(s)",
            len(config_copy),
        )
        return config_copy

    def _validate_batch_create_response_for_failures(self, batch_response, pending_count):
        """Validate batch response for any failed resource creation items.

        Checks that:
        1. Response count matches the request count (no missing items)
        2. Each item in the response has a success-like status (or no status)
        3. No items have failure status values

        Args:
            batch_response: ``ResourcesManagerBatchResponse`` instance with resources list.
            pending_count: Expected number of resources in the response.

        Raises:
            ValueError: On any validation failure (missing responses, non-success status, etc).
        """
        self.log.debug(
            "_validate_batch_create_response_for_failures: validating %s response item(s) against expected count=%s",
            len(batch_response.resources),
            pending_count,
        )

        # Check for response count mismatch (partial success)
        if len(batch_response.resources) != pending_count:
            failed_msg = (
                f"Partial success in batch create: expected {pending_count} responses, "
                f"but received only {len(batch_response.resources)} resource(s). "
                f"Module cannot continue with incomplete batch results."
            )
            self.log.error("_validate_batch_create_response_for_failures: %s", failed_msg)
            raise ValueError(failed_msg)

        # Validate that all items in the response indicate success (not failure status)
        failed_items = []
        for idx, resp_item in enumerate(batch_response.resources):
            # Log each response item for debugging
            self.log.debug(
                "_validate_batch_create_response_for_failures: response_item[%s] entity_name=%s, status=%s, message=%s",
                idx,
                resp_item.entity_name,
                resp_item.status,
                resp_item.message,
            )

            # Check if status indicates failure (if status is present and not success-like)
            if resp_item.status:
                status_lower = resp_item.status.lower()
                # Recognized success status values
                if status_lower not in ("success", "created", "ok", "succeeded"):
                    failed_items.append({
                        "index": idx,
                        "entity_name": resp_item.entity_name or "unknown",
                        "status": resp_item.status,
                        "message": resp_item.message or "no details provided",
                    })
                    self.log.error(
                        "_validate_batch_create_response_for_failures: response_item[%s] has failure status: entity_name=%s, status=%s, message=%s",
                        idx,
                        resp_item.entity_name,
                        resp_item.status,
                        resp_item.message,
                    )

        if failed_items:
            failed_details = "\n".join(
                f"  [{item['index']}] entity_name={item['entity_name']}: status={item['status']}, message={item['message']}"
                for item in failed_items
            )
            failed_msg = (
                f"Partial success in batch create: {len(failed_items)} out of {pending_count} "
                f"resource(s) failed:\n{failed_details}"
            )
            self.log.error("_validate_batch_create_response_for_failures: %s", failed_msg)
            raise ValueError(failed_msg)

        self.log.info(
            "_validate_batch_create_response_for_failures: all %s resource(s) validated successfully",
            len(batch_response.resources),
        )

    def _validate_remove_response_for_failures(self, remove_response, pending_count):
        """Validate delete response for partial success or per-item failures.

        Checks that:
        1. Response count matches the request count (no missing responses)
        2. Each item in the response has a success-like status when status is present

        Args:
            remove_response: ``RemoveResourcesByIdsResponse`` instance with resources list.
            pending_count: Expected number of resources in the response.

        Raises:
            ValueError: On any validation failure.
        """
        self.log.debug(
            "_validate_remove_response_for_failures: validating %s response item(s) against expected count=%s",
            len(remove_response.resources),
            pending_count,
        )

        if len(remove_response.resources) != pending_count:
            failed_msg = (
                f"Partial success in batch delete: expected {pending_count} responses, "
                f"but received only {len(remove_response.resources)} resource(s). "
                f"Module cannot continue with incomplete batch results."
            )
            self.log.error("_validate_remove_response_for_failures: %s", failed_msg)
            raise ValueError(failed_msg)

        failed_items = []
        for idx, resp_item in enumerate(remove_response.resources):
            self.log.debug(
                "_validate_remove_response_for_failures: response_item[%s] resource_value=%s, status=%s, message=%s",
                idx,
                resp_item.resource_value,
                resp_item.status,
                resp_item.message,
            )

            if resp_item.status:
                status_lower = resp_item.status.lower()
                if status_lower not in ("success", "deleted", "ok", "succeeded"):
                    failed_items.append(
                        {
                            "index": idx,
                            "resource_value": resp_item.resource_value or "unknown",
                            "status": resp_item.status,
                            "message": resp_item.message or "no details provided",
                        }
                    )
                    self.log.error(
                        "_validate_remove_response_for_failures: response_item[%s] has failure status: resource_value=%s, status=%s, message=%s",
                        idx,
                        resp_item.resource_value,
                        resp_item.status,
                        resp_item.message,
                    )

        if failed_items:
            failed_details = "\n".join(
                f"  [{item['index']}] resource_value={item['resource_value']}: status={item['status']}, message={item['message']}"
                for item in failed_items
            )
            failed_msg = (
                f"Partial success in batch delete: {len(failed_items)} out of {pending_count} "
                f"resource(s) failed:\n{failed_details}"
            )
            self.log.error("_validate_remove_response_for_failures: %s", failed_msg)
            raise ValueError(failed_msg)

        self.log.info(
            "_validate_remove_response_for_failures: all %s resource(s) validated successfully",
            len(remove_response.resources),
        )

    def manage_merged(self):
        """Create or update resources to match the desired state defined in the playbook.

        Delegates diff computation to ``ResourceManagerDiffEngine.compute_changes`` to
        classify each proposed resource as ``to_add`` (new) or ``to_update`` (value
        changed).  Idempotent resources (already matching) are skipped.

        In check mode, logs what would be created without issuing any API calls.
        Otherwise, sends a single batch POST request containing all pending payloads and
        validates each item in the response against the sent config via
        ``ResourceManagerDiffEngine.validate_resource_api_fields``.

        Raises:
            NDModuleError: Propagated from ``self.nd.request`` on API failure.
        """
        self.log.info(
            "manage_merged: Processing %s config item(s) for fabric=%s",
            len(self.config),
            self.fabric,
        )

        # Use compute_changes as the canonical diff engine.
        changes = ResourceManagerDiffEngine.compute_changes(self.proposed, self.existing, log=self.log)

        # Propagate partial-match mismatch diagnostics to the output diff (GAP-7).
        self.changed_dict[0]["debugs"].extend(changes["debugs"])

        # Resources that need to be created: new (to_add) or value changed (to_update).
        pending_items: list[tuple[ResourceManagerConfigModel, str, ResourceManagerResponse]] = changes["to_add"] + changes["to_update"]

        if not pending_items:
            self.log.debug("manage_merged: No resources to create (all idempotent).")
            self._register_result("merge", OperationType.QUERY, "all resources idempotent", changed=False)
            return

        # Build payload list alongside a cfg reference for post-create validation (GAP-5).
        pending_payloads = []
        for cfg, sw, _existing in pending_items:
            payload = self._build_create_payload(cfg, switch_ip=sw)
            pending_payloads.append((cfg, payload))
            self.log.debug(
                "manage_merged: Queuing resource for batch create: entity_name=%s, pool_name=%s, scope_type=%s, switch_ip=%s",
                cfg.entity_name,
                cfg.pool_name,
                cfg.scope_type,
                sw,
            )

        # Track diff BEFORE the API call so --check mode also shows what would change (GAP-3).
        self.changed_dict[0]["merged"].extend(p for _cfg, p in pending_payloads)

        ep = EpManageFabricResourcesPost(fabric_name=self.fabric)
        if self.nd.module.check_mode:
            self.log.info(
                "Check mode: would create %s resource(s) for fabric=%s",
                len(pending_payloads),
                self.fabric,
            )

            payloads_only = [p for _cfg, p in pending_payloads]
            batch_payload = ResourceManagerBatchRequest.model_validate({"resources": payloads_only}).to_payload()
            self._register_result(
                "merge",
                OperationType.CREATE,
                "check mode — skipped",
                changed=True,
                diff={"merged": payloads_only},
                verb=HttpVerbEnum.POST,
                path=ep.path,
                payload=batch_payload,
            )
            return

        self.log.info(
            "manage_merged: Making batch API call with %s resource(s) for fabric=%s",
            len(pending_payloads),
            self.fabric,
        )

        payloads_only = [p for _cfg, p in pending_payloads]
        batch = ResourceManagerBatchRequest.model_validate({"resources": payloads_only})
        api_start = time.monotonic()
        try:
            resp_data = self.nd.request(ep.path, ep.verb, data=batch.to_payload())
        except Exception:
            self.log.exception(
                "manage_merged: Batch create API call failed after %.3f second(s) (path=%s, resource_count=%s)",
                time.monotonic() - api_start,
                ep.path,
                len(pending_payloads),
            )
            raise ValueError(
                f"manage_merged: Batch create API call failed {time.monotonic() - api_start:.3f} second(s)"
                f" (path={ep.path}, resource_count={len(pending_payloads)})"
            )
        api_elapsed = time.monotonic() - api_start
        self.log.info(
            "manage_merged: Batch create API response time %.3f second(s) (path=%s, resource_count=%s)",
            api_elapsed,
            ep.path,
            len(pending_payloads),
        )

        # Parse batch response.
        batch_response = ResourcesManagerBatchResponse.from_response(resp_data)
        self.log.debug(
            "manage_merged: Batch API response parsed — %s item(s) returned",
            len(batch_response.resources),
        )

        # Validate that batch response is complete and all items succeeded
        self._validate_batch_create_response_for_failures(batch_response, len(pending_payloads))

        # Build a normalised entity_name → cfg lookup for GAP-5 field validation.
        # If two items share a normalised name (unusual), the last one wins; that is
        # acceptable because validate_resource_api_fields uses order-insensitive comparison.
        cfg_by_entity: dict[str, ResourceManagerConfigModel] = {
            ResourceManagerDiffEngine._normalize_entity_key(cfg.entity_name, log=self.log): cfg for cfg, _payload in pending_payloads
        }

        for resp_item in batch_response.resources:
            self.api_responses.append({"RETURN_CODE": 200, "DATA": resp_item.model_dump(by_alias=True, exclude_none=True)})
            # GAP-5: Validate that the API response fields match what we sent.
            if resp_item.entity_name is not None:
                norm_key = ResourceManagerDiffEngine._normalize_entity_key(resp_item.entity_name, log=self.log)
                matched_cfg = cfg_by_entity.get(norm_key)
                if matched_cfg is not None:
                    ResourceManagerDiffEngine.validate_resource_api_fields(self.nd, matched_cfg, resp_item, "Resource", log=self.log)

        self.log.info(
            "manage_merged: Batch create successful — %s resource(s) created for fabric=%s",
            len(pending_payloads),
            self.fabric,
        )

        # Register the batch create with Results
        self._register_result(
            "merge",
            OperationType.CREATE,
            f"batch create successful — {len(pending_payloads)} resource(s)",
            changed=True,
            diff={"merged": [p for _cfg, p in pending_payloads]},
            verb=HttpVerbEnum.POST,
            path=ep.path,
            payload=batch.to_payload(),
        )

    def manage_deleted(self):
        """Delete resources that are listed in the playbook config and exist in the fabric.

        Uses ``ResourceManagerDiffEngine.compute_changes`` to identify which proposed
        resources are present in the ND fabric (``idempotent`` or ``to_update`` buckets).
        Only explicitly listed resources are deleted; unrelated existing resources are
        left untouched, matching the ND nd_rm_get_diff_deleted() behaviour.

        In check mode, records which resource IDs would be removed without issuing any
        API calls.  Otherwise, sends a batch remove POST request with the collected
        resource IDs.

        Raises:
            NDModuleError: Propagated from ``self.nd.request`` on API failure.
        """
        self.log.info(
            "manage_deleted: Processing %s config item(s) for fabric=%s",
            len(self.config),
            self.fabric,
        )

        # Use compute_changes as the canonical diff engine.
        changes = ResourceManagerDiffEngine.compute_changes(self.proposed, self.existing, log=self.log)

        # Propagate partial-match mismatch diagnostics to the output diff (GAP-7).
        self.changed_dict[0]["debugs"].extend(changes["debugs"])

        # Collect resource IDs for entries that exist in the fabric.
        # idempotent  → resource exists with the same value   → still delete it.
        # to_update   → resource exists but with a different value → still delete it.
        # to_add      → resource does not exist               → nothing to delete.
        # to_delete   → "override" bucket (unmatched existing) → ignored; deleted state
        #               only removes what is explicitly listed in the playbook config,
        #               matching ND's nd_rm_get_diff_deleted() behaviour.
        resource_ids = []
        for _cfg, _sw, existing_res in changes["idempotent"] + changes["to_update"]:
            rid = self._get_resource_id(existing_res)
            if rid is not None and rid not in resource_ids:
                self.log.debug(
                    "manage_deleted: Queuing resource ID '%s' for deletion (entity_name=%s, pool_name=%s, switch_ip=%s)",
                    rid,
                    _cfg.entity_name,
                    _cfg.pool_name,
                    _sw,
                )
                resource_ids.append(rid)
            elif rid is not None:
                self.log.debug(
                    "manage_deleted: Resource ID '%s' already queued, skipping duplicate",
                    rid,
                )
            else:
                self.log.debug(
                    "manage_deleted: Matched resource has no resource ID, skipping: %s",
                    existing_res,
                )

        if not resource_ids:
            # Nothing to delete — idempotent
            self.log.info(
                "manage_deleted: No matching resources found to delete for fabric=%s, nothing to do",
                self.fabric,
            )
            self._register_result("delete", OperationType.QUERY, "no matching resources to delete", changed=False)
            return

        self.log.info(
            "manage_deleted: Collected %s resource ID(s) to delete: %s",
            len(resource_ids),
            resource_ids,
        )

        self.changed_dict[0]["deleted"].extend(str(r) for r in resource_ids)

        if self.nd.module.check_mode:
            self.log.info(
                "Check mode: would delete %s resource(s): %s",
                len(resource_ids),
                resource_ids,
            )
            self.api_responses.append({"RETURN_CODE": 200, "DATA": {"resourceIds": resource_ids}})
            ep = EpManageFabricResourcesActionsRemovePost(fabric_name=self.fabric)
            remove_req = RemoveResourcesByIdsRequest(resource_ids=resource_ids)
            self._register_result(
                "delete",
                OperationType.DELETE,
                "check mode — skipped",
                changed=True,
                diff={"deleted": resource_ids},
                verb=HttpVerbEnum.POST,
                path=ep.path,
                payload=remove_req.to_payload(),
            )
            return

        ep = EpManageFabricResourcesActionsRemovePost(fabric_name=self.fabric)
        remove_req = RemoveResourcesByIdsRequest(resource_ids=resource_ids)
        api_start = time.monotonic()
        try:
            resp_data = self.nd.request(ep.path, ep.verb, data=remove_req.to_payload())
        except Exception:
            self.log.exception(
                "manage_deleted: Delete API call failed after %.3f second(s) (path=%s, resource_count=%s)",
                time.monotonic() - api_start,
                ep.path,
                len(resource_ids),
            )
            raise ValueError(
                f"manage_deleted: Delete API call failed {time.monotonic() - api_start:.3f} second(s) (path={ep.path}, resource_count={len(resource_ids)})"
            )
        api_elapsed = time.monotonic() - api_start
        self.log.info(
            "manage_deleted: Delete API response time %.3f second(s) (path=%s, resource_count=%s)",
            api_elapsed,
            ep.path,
            len(resource_ids),
        )

        remove_response = RemoveResourcesByIdsResponse.from_response(resp_data)

        self.log.debug(
            "manage_deleted: Delete API response parsed — %s item(s) returned",
            len(remove_response.resources),
        )

        self._validate_remove_response_for_failures(remove_response, len(resource_ids))

        for resp_item in remove_response.resources:
            self.api_responses.append({"RETURN_CODE": 200, "DATA": resp_item.model_dump(by_alias=True, exclude_none=True)})

        self.log.info(
            "manage_deleted: Successfully deleted %s resource(s): %s",
            len(resource_ids),
            resource_ids,
        )

        # Register the delete with Results
        self._register_result(
            "delete",
            OperationType.DELETE,
            f"deleted {len(resource_ids)} resource(s)",
            changed=True,
            diff={"deleted": resource_ids},
            verb=HttpVerbEnum.POST,
            path=ep.path,
            payload=remove_req.to_payload(),
        )

    def manage_gathered(self):
        """Return resources from the ND fabric, optionally filtered by config criteria.

        ``_refresh_existing_resources()`` (called by ``manage_state()``) already fetched
        and stored the correctly scoped resources in ``self._all_resources`` before this
        method is invoked:
          - No ``config``  → full paginated fabric inventory.
          - With ``config`` → API-filtered fetch via ``_build_gathered_resource_criteria()``
            (pool_name, switchId, and Lucene entityName params applied server-side).

        This method therefore only translates ``self._all_resources`` to the playbook
        config format and stores the results.

        Results are stored in ``self.changed_dict[0]['gathered']`` and
        ``self.api_responses``.
        """
        config_count = len(self.config) if self.config else 0
        self.log.info(
            "manage_gathered: Gathering resources for fabric=%s, filter_count=%s",
            self.fabric,
            config_count,
        )

        # _refresh_existing_resources() already populated self._all_resources with
        # API-filtered resources (via _build_gathered_resource_criteria() for gathered+config,
        # or a full paginated fetch for gathered without config). Translate and return directly
        # without a second in-memory filter pass.
        results = self.translate_gathered_results(self._all_resources)

        self.log.info(
            "manage_gathered: Gather complete, %s resource(s) returned for fabric=%s (filter_count=%s)",
            len(results),
            self.fabric,
            config_count,
        )
        self.api_responses.extend(results)
        self.changed_dict[0]["gathered"].extend(results)

        # Register the gathered query with Results
        ep = EpManageFabricResourcesGet(fabric_name=self.fabric)
        self._register_result("gathered", OperationType.QUERY, f"gathered {len(results)} resource(s)", changed=False, path=ep.path)

    def manage_state(self):
        """Validate input and dispatch to the appropriate state handler.

        Runs model-backed validation on the raw config and dispatches to
        ``manage_merged``, ``manage_deleted``, or ``manage_gathered`` through a
        small state handler map.
        """
        self.log.info("manage_state: Dispatching to state handler: state=%s", self.state)
        validated_configs = self._validate_input()

        if self.state != "gathered":
            self.proposed = validated_configs
            self._proposed_list = [cfg.model_dump(by_alias=True, exclude_none=True) for cfg in self.proposed]

        state_handlers = {
            "merged": self.manage_merged,
            "deleted": self.manage_deleted,
            "gathered": self.manage_gathered,
        }
        handler = state_handlers.get(self.state)
        if handler is None:
            raise ValueError("Unsupported state '{0}'".format(self.state))

        self._refresh_existing_resources(update_previous=True)

        self.log.info("manage_state: Dispatching to %s()", handler.__name__)
        handler()

        self.log.info("manage_state: State handler completed for state=%s", self.state)

    def exit_module(self):
        """Build the final module result and call ``exit_json`` to return it to Ansible.

        Uses ``NDOutput.format_with_verbosity()`` so generic module output stays
        stable and API-call metadata is exposed only under ``api_*`` keys when
        Ansible verbosity requests it.
        """
        verbosity = self.nd.module._verbosity if hasattr(self.nd.module, "_verbosity") else 0

        if self.state == "gathered":
            self.log.info(
                "exit_module: gathered state, returning %s resource(s)",
                len(self.changed_dict[0]["gathered"]),
            )
            final = self.output.format_with_verbosity(
                verbosity,
                self.results,
                changed=False,
                after=self.translate_gathered_results(self.existing),
                gathered=self.changed_dict[0]["gathered"],
            )
            self.nd.module.exit_json(**final)
            return

        changed = len(self.changed_dict[0]["merged"]) > 0 or len(self.changed_dict[0]["deleted"]) > 0

        self.log.info(
            "exit_module: merged=%s, deleted=%s, gathered=%s, changed=%s, check_mode=%s",
            len(self.changed_dict[0]["merged"]),
            len(self.changed_dict[0]["deleted"]),
            len(self.changed_dict[0]["gathered"]),
            changed,
            self.nd.module.check_mode,
        )
        self.log.debug(
            "exit_module: changed=%s reflects check_mode=%s state (check mode does NOT override changed flag)",
            changed,
            self.nd.module.check_mode,
        )

        # Re-query to capture post-operation state for current snapshot
        if not self.nd.module.check_mode and changed:
            self._refresh_existing_resources(update_previous=False)

        final_results_data = {
            "changed": changed,
            "before": self.translate_gathered_results(self.previous),
            "after": self.translate_gathered_results(self.existing),
            "diff": self.changed_dict,
        }

        output_level = self.nd.params.get("output_level", "normal")
        if output_level in ("info", "debug"):
            final_results_data["proposed"] = self._proposed_list

        final = self.output.format_with_verbosity(verbosity, self.results, **final_results_data)
        self.nd.module.exit_json(**final)
