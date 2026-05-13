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

    def __init__(
        self,
        nd: NDModule,
        results: Results,
        log: logging.Logger | None = None,
    ):
        """Initialise the module, resolve fabric/state from ND params, and pre-fetch all resources.

        Queries the ND Manage API for all existing resources in ``fabric`` at construction
        time and caches the result in ``self._all_resources``.  The cached list is used as
        the ``existing`` baseline for diff computation in both merged and deleted states,
        avoiding repeated GET requests during the same module run.

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

        # Get All resources for the given fabric and cache them for matching during merged/deleted operations
        self._get_all_resources()

        # Translate playbook switch IPs to switch IDs through the shared fabric inventory helper.
        self.config = self._resolve_switch_ids_in_config(self.config)

        # Resource collections — existing/previous snapshot at init, proposed populated in manage_state
        self.existing: list[ResourceManagerResponse] = list(self._all_resources)
        self.previous: list[ResourceManagerResponse] = list(self._all_resources)
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

    def _get_all_resources(self):
        """Fetch all existing resources for the fabric from the ND Manage API and cache them.

        Issues a single GET request to the fabric resources endpoint.  The response is
        normalised to a flat list of ``ResourceManagerResponse`` model instances (or raw
        dicts when model parsing fails) and stored in ``self._all_resources``.  Subsequent
        calls return immediately without hitting the API again (``self._resources_fetched``
        flag).

        A 404 response is treated as an empty fabric (no resources allocated yet) rather
        than an error.  Any other ``NDModuleError`` is re-raised to the caller.
        """
        if self._resources_fetched:
            self.log.debug(
                "Resources already cached for fabric=%s: %s resource(s)",
                self.fabric,
                len(self._all_resources),
            )
            return

        self.log.info("Fetching all resources for fabric=%s", self.fabric)

        ep = EpManageFabricResourcesGet(fabric_name=self.fabric)
        api_start = time.monotonic()
        try:
            data = self.nd.request(ep.path, ep.verb)
        except NDModuleError as exc:
            api_elapsed = time.monotonic() - api_start
            if exc.status == 404:
                # Fabric has no resources yet — that is valid
                self.log.info(
                    "_get_all_resources: GET resources API response time %.3f second(s) (path=%s, state=%s, status=404)",
                    api_elapsed,
                    ep.path,
                    self.state,
                )
                self.log.info(
                    "No resources found (404) for fabric=%s, treating as empty",
                    self.fabric,
                )
                self._resources_fetched = True
                return
            self.log.exception(
                "_get_all_resources: GET resources API call failed after %.3f second(s) (path=%s, state=%s)",
                api_elapsed,
                ep.path,
                self.state,
            )
            raise ValueError(
                f"_get_all_resources: GET resources API call failed after {api_elapsed:.3f} second(s) (path={ep.path}, state={self.state})"
            ) from exc
        except Exception:
            self.log.exception(
                "_get_all_resources: GET resources API call failed after %.3f second(s) (path=%s, state=%s)",
                time.monotonic() - api_start,
                ep.path,
                self.state,
            )
            raise ValueError(
                f"_get_all_resources: GET resources API call failed after {time.monotonic() - api_start:.3f} second(s) (path={ep.path}, state={self.state})"
            )
        api_elapsed = time.monotonic() - api_start
        _resp_count = len(data) if isinstance(data, list) else len(data["resources"]) if isinstance(data, dict) and "resources" in data else 0
        self.log.info(
            "_get_all_resources: GET resources API response time %.3f second(s) (path=%s, state=%s, response_count=%s)",
            api_elapsed,
            ep.path,
            self.state,
            _resp_count,
        )

        # The ND API may return a list directly or {"resources": [...], "meta": {...}}
        if isinstance(data, list):
            self.log.debug("API returned a list with %s item(s)", len(data))
            raw_list = data
        elif isinstance(data, dict) and "resources" in data:
            self.log.debug(
                "API returned dict with 'resources' key, %s resource(s)",
                len(data["resources"]),
            )
            raw_list = data["resources"]
        elif isinstance(data, dict) and data:
            self.log.debug("API returned a non-empty dict without 'resources' key, wrapping in list")
            raw_list = [data]
        else:
            self.log.debug("API returned empty or unexpected data, treating as empty list")
            raw_list = []

        for raw in raw_list:
            try:
                resource_model = ResourceManagerResponse.from_response(raw)
                self.log.debug(
                    "Parsed resource: entity_name=%s, pool_name=%s",
                    getattr(resource_model, "entity_name", None),
                    getattr(resource_model, "pool_name", None),
                )
                self._all_resources.append(resource_model)
            except Exception as exc:
                # If parsing fails, keep the raw dict so we can still match on it
                self.log.warning(
                    "Failed to parse resource into ResourceManagerResponse (keeping raw): %s | raw=%s",
                    exc,
                    raw,
                )
                self._all_resources.append(raw)

        self._resources_fetched = True
        self.log.info(
            "Fetched %s resource(s) for fabric=%s",
            len(self._all_resources),
            self.fabric,
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
                changed=False,
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
                changed=False,
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

        When no ``config`` is provided, all resources cached in ``self._all_resources`` are
        translated to the playbook format and returned.  When ``config`` is provided, each
        filter item is processed in sequence; a resource must satisfy every non-None
        criterion in the filter (``entity_name``, ``pool_name``, ``switches``) to be
        included.  Deduplication is applied across filter items using the resource ID so
        that a resource matching multiple filters appears only once in the output.

        Results are stored in ``self.changed_dict[0]['gathered']`` and
        ``self.api_responses``.
        """
        config_count = len(self.config) if self.config else 0
        self.log.info(
            "manage_gathered: Gathering resources for fabric=%s, filter_count=%s",
            self.fabric,
            config_count,
        )

        if not self.config:
            # No filters — return everything translated to merged format
            results = self.translate_gathered_results(self._all_resources)
            self.log.info(
                "manage_gathered: No filter criteria provided, returning all %s resource(s)",
                len(results),
            )
            self.api_responses.extend(results)
            self.changed_dict[0]["gathered"].extend(results)
            return

        results = self._apply_gathered_filters()

        self.log.info(
            "manage_gathered: Gather complete, %s resource(s) matched filters",
            len(results),
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

        self.log.info("manage_state: Dispatching to %s()", handler.__name__)
        handler()

        self.log.info("manage_state: State handler completed for state=%s", self.state)

    def exit_module(self):
        """Build the final module result and call ``exit_json`` to return it to Ansible.

        Uses ``Results.build_final_result()`` to collect per-API-call metadata,
        then overlays ``NDOutput.format(**kwargs)`` for the standard output fields
        (before, after, diff, proposed, etc.).
        """
        self.results.build_final_result()
        final = self.results.final_result

        if self.state == "gathered":
            self.log.info(
                "exit_module: gathered state, returning %s resource(s)",
                len(self.changed_dict[0]["gathered"]),
            )
            final.update(
                self.output.format(
                    changed=False,
                    after=self.translate_gathered_results(self.existing),
                    gathered=self.changed_dict[0]["gathered"],
                )
            )
            self.nd.module.exit_json(**final)
            return

        changed = len(self.changed_dict[0]["merged"]) > 0 or len(self.changed_dict[0]["deleted"]) > 0
        if self.nd.module.check_mode:
            self.log.info(
                "exit_module: check_mode is enabled, overriding changed=False (would have been changed=%s)",
                changed,
            )
            changed = False

        self.log.info(
            "exit_module: merged=%s, deleted=%s, gathered=%s, changed=%s, check_mode=%s",
            len(self.changed_dict[0]["merged"]),
            len(self.changed_dict[0]["deleted"]),
            len(self.changed_dict[0]["gathered"]),
            changed,
            self.nd.module.check_mode,
        )

        # Re-query to capture post-operation state for current snapshot
        if not self.nd.module.check_mode and changed:
            self._resources_fetched = False
            self._all_resources = []
            self._get_all_resources()
            self.existing = list(self._all_resources)

        final_results_data = {
            "changed": changed,
            "before": self.translate_gathered_results(self.previous),
            "after": self.translate_gathered_results(self.existing),
            "diff": self.changed_dict,
            "response": self.api_responses,
        }

        output_level = self.nd.params.get("output_level", "normal")
        if output_level in ("info", "debug"):
            final_results_data["proposed"] = self._proposed_list

        final.update(self.output.format(**final_results_data))
        self.nd.module.exit_json(**final)
