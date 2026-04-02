#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import ipaddress
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import ValidationError

from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModule
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
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
    ResourceManagerRequest,
    FabricScope,
    DeviceScope,
    DeviceInterfaceScope,
    DevicePairScope,
    LinkScope,
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
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.constants import (
    API_SCOPE_TYPE_TO_PLAYBOOK as _API_SCOPE_TYPE_TO_PLAYBOOK,
    POOL_SCOPE_MAP as _POOLNAME_TO_SCOPE_TYPE,
    SCOPE_TYPE_TO_API as _SCOPE_TYPE_TO_API,
)


# =========================================================================
# Validation & Diff
# =========================================================================

class ResourceManagerDiffEngine:
    """Provide stateless validation and diff computation helpers."""

    @staticmethod
    def _normalize_entity_key(entity_name: str) -> str:
        """Normalize entity_name for order-insensitive comparison.

        Args:
            entity_name: Raw entity name string.

        Returns:
            Tilde-separated string with parts sorted alphabetically.
        """
        return "~".join(sorted(entity_name.split("~")))

    @staticmethod
    def _extract_scope_switch_key_val(scope_details, switch_key, src_switch_key) -> Optional[str]:
        """Extract a switch identifier from a scope_details model using the correct attribute name.

        Selects between ``switch_key`` (for single-switch scopes: device, device_interface)
        and ``src_switch_key`` (for dual-switch scopes: device_pair, link).  Returns None
        for fabric-scoped resources which carry no switch identity.

        Args:
            scope_details: A scope model instance (FabricScope, DeviceScope,
                DeviceInterfaceScope, DevicePairScope, LinkScope) or None.
            switch_key: Attribute name to read for single-switch scopes
                (e.g. ``'switch_id'`` or ``'switch_ip'``).
            src_switch_key: Attribute name to read for dual-switch scopes
                (e.g. ``'src_switch_id'`` or ``'src_switch_ip'``).

        Returns:
            The switch identifier string, or None if the scope is fabric-level
            or ``scope_details`` is None.
        """
        if scope_details is None:
            return None
        if isinstance(scope_details, FabricScope):
            return None
        if isinstance(scope_details, (DeviceScope, DeviceInterfaceScope)):
            return getattr(scope_details, switch_key, None)
        if isinstance(scope_details, (DevicePairScope, LinkScope)):
            return getattr(scope_details, src_switch_key, None)
        # Fallback: try common attribute names
        return getattr(scope_details, switch_key, None) or getattr(scope_details, src_switch_key, None)

    @staticmethod
    def _extract_scope_type(scope_details) -> Optional[str]:
        """Extract and map the playbook-style scope_type from a scope_details model.

        Args:
            scope_details: A scope model instance.

        Returns:
            Playbook-style scope_type string (e.g. 'device_interface'), or None.
        """
        if scope_details is None:
            return None
        raw = getattr(scope_details, "scope_type", None)
        return _API_SCOPE_TYPE_TO_PLAYBOOK.get(raw, raw) if raw else None

    @staticmethod
    def _compare_resource_values(have: Optional[str], want: Optional[str]) -> bool:
        """Compare resource values with IPv4/IPv6 network awareness.

        Args:
            have: Existing resource value from the API.
            want: Proposed resource value from the playbook.

        Returns:
            True if the values are functionally equivalent, False otherwise.
        """
        if have is None and want is None:
            return True
        if have is None or want is None:
            return False

        have = str(have).strip()
        want = str(want).strip()

        def _classify(val):
            if "/" in val:
                try:
                    return "network", ipaddress.ip_network(val, strict=False)
                except ValueError:
                    pass
            try:
                return "address", ipaddress.ip_address(val)
            except ValueError:
                pass
            return "raw", val

        th, vh = _classify(have)
        tw, vw = _classify(want)

        if th == tw == "address":
            return vh.exploded == vw.exploded
        if th == tw == "network":
            return vh == vw
        return have == want

    @staticmethod
    def _make_resource_key(
        entity_name: Optional[str],
        pool_name: Optional[str],
        scope_type: Optional[str],
        switch_ip: Optional[str],
    ) -> Tuple:
        """Build a normalized deduplication key for a resource entry.

        Args:
            entity_name: Resource entity name (will be tilde-normalized).
            pool_name: Pool name.
            scope_type: Playbook-style scope type.
            switch_ip: Switch IP, or None for fabric-scoped resources.

        Returns:
            Tuple used as a dict key for matching proposed vs existing.
        """
        norm_entity = (
            ResourceManagerDiffEngine._normalize_entity_key(entity_name)
            if entity_name else None
        )
        # device_pair and link encode both endpoints in entity_name;
        # normalize switch to None so existing_index and proposed lookups align.
        norm_switch = None if scope_type in ("device_pair", "link") else switch_ip
        return (norm_entity, pool_name, scope_type, norm_switch)

    @staticmethod
    def validate_configs(
        config: Union[Dict[str, Any], List[Dict[str, Any]]],
        state: str,
        nd: NDModule,
        log: logging.Logger,
    ) -> List[ResourceManagerConfigModel]:
        """Validate raw module config and return typed resource configurations.

        Args:
            config: Raw config dict or list of dicts from module parameters.
            state: Requested module state.
            nd: ND module wrapper used for failure handling.
            log: Logger instance.

        Returns:
            List of validated ``ResourceManagerConfigModel`` objects.
        """
        log.debug("ENTER: validate_configs()")

        configs_list = config if isinstance(config, list) else [config]
        log.debug(f"Normalized to {len(configs_list)} configuration(s)")

        validated_configs: List[ResourceManagerConfigModel] = []
        for idx, cfg in enumerate(configs_list):
            try:
                validated = ResourceManagerConfigModel.model_validate(
                    cfg, context={"state": state}
                )
                validated_configs.append(validated)
            except ValidationError as e:
                error_detail = e.errors() if hasattr(e, "errors") else str(e)
                error_msg = (
                    f"Configuration validation failed for "
                    f"config index {idx}: {error_detail}"
                )
                log.error(error_msg)
                if hasattr(nd, "module"):
                    nd.module.fail_json(msg=error_msg)
                else:
                    raise ValueError(error_msg) from e
            except Exception as e:
                error_msg = (
                    f"Configuration validation failed for "
                    f"config index {idx}: {str(e)}"
                )
                log.error(error_msg)
                if hasattr(nd, "module"):
                    nd.module.fail_json(msg=error_msg)
                else:
                    raise ValueError(error_msg) from e

        if not validated_configs:
            log.warning("No valid configurations found in input")
            return validated_configs

        # Duplicate check: (entity_name, pool_name, scope_type, frozenset(switch))
        seen_keys: set = set()
        duplicate_keys: set = set()
        log.debug(
            f"validate_configs: starting duplicate check on "
            f"{len(validated_configs)} validated config(s)"
        )
        for cfg_dup_idx, cfg in enumerate(validated_configs):
            key = (
                cfg.entity_name,
                cfg.pool_name,
                cfg.scope_type,
                frozenset(cfg.switch or []),
            )
            log.debug(
                f"validate_configs: duplicate-check [{cfg_dup_idx}] — "
                f"entity_name='{cfg.entity_name}', pool_name='{cfg.pool_name}', "
                f"scope_type='{cfg.scope_type}', switch={list(cfg.switch or [])}, "
                f"key_seen_before={key in seen_keys}"
            )
            if key in seen_keys:
                log.warning(
                    f"validate_configs: [{cfg_dup_idx}] duplicate key detected — "
                    f"entity_name='{cfg.entity_name}', pool_name='{cfg.pool_name}', "
                    f"scope_type='{cfg.scope_type}'"
                )
                duplicate_keys.add(key)
            else:
                log.debug(
                    f"validate_configs: [{cfg_dup_idx}] key is unique so far — "
                    f"entity_name='{cfg.entity_name}'"
                )
            seen_keys.add(key)

        if duplicate_keys:
            error_msg = (
                f"Duplicate config entries found: "
                f"{[str(k) for k in duplicate_keys]}. "
                f"Each resource must appear only once."
            )
            log.error(error_msg)
            if hasattr(nd, "module"):
                nd.module.fail_json(msg=error_msg)
            else:
                raise ValueError(error_msg)

        log.info(
            f"Successfully validated {len(validated_configs)} configuration(s)"
        )
        log.debug(f"EXIT: validate_configs() -> {len(validated_configs)} configs")
        return validated_configs

    @staticmethod
    def compute_changes(
        proposed: List[ResourceManagerConfigModel],
        existing: List[ResourceManagerResponse],
        log: logging.Logger,
    ) -> Dict[str, List]:
        """Compare proposed and existing resources and categorize changes.

        Uses ``ResourceManagerResponse`` fields (``entity_name``, ``pool_name``,
        ``scope_details``, ``resource_value``) to build a matching index and
        classify each proposed entry.

        Args:
            proposed: Validated ``ResourceManagerConfigModel`` objects
                representing desired state.
            existing: ``ResourceManagerResponse`` models from the ND API
                representing current state.
            log: Logger instance.

        Returns:
            Dict mapping change buckets to item lists:
              - ``to_add``:     ``(ResourceManagerConfigModel, switch_ip)`` tuples
              - ``to_update``:  ``(ResourceManagerConfigModel, switch_ip)`` tuples
              - ``to_delete``:  ``ResourceManagerResponse`` items
              - ``idempotent``: ``(ResourceManagerConfigModel, switch_ip)`` tuples
        """
        log.debug("ENTER: compute_changes()")
        log.debug(
            f"Comparing {len(proposed)} proposed vs {len(existing)} existing resources"
        )
        log.debug(
            f"Comparing proposed : {proposed}  vs  existing : {existing} existing resources"
        )

        # Build index of existing resources keyed by
        # (normalized_entity, pool_name, playbook_scope_type, switch_id)
        existing_index: Dict[Tuple, ResourceManagerResponse] = {}
        for res in existing:
            entity = res.entity_name
            pool = res.pool_name
            scope_type = ResourceManagerDiffEngine._extract_scope_type(res.scope_details)
            switch_id = ResourceManagerDiffEngine._extract_scope_switch_key_val(res.scope_details, switch_key="switch_id", src_switch_key="src_switch_id")
            key = ResourceManagerDiffEngine._make_resource_key(entity, pool, scope_type, switch_id)
            existing_index[key] = res
            log.debug(
                f"Existing index entry: entity={entity}, pool={pool}, "
                f"scope_type={scope_type}, switch_id={switch_id}"
            )

        log.debug(f"Built existing index with {len(existing_index)} entries")

        changes: Dict[str, List] = {
            "to_add": [],
            "to_update": [],
            "to_delete": [],
            "idempotent": [],
            "debugs": [],
        }

        # Build a secondary index keyed by normalised entity_name only.
        # Used to detect partial matches (same entity, different pool/scope/switch)
        # and populate the debugs bucket to mirror ND's mismatch logging.
        entity_only_index: Dict[str, List[ResourceManagerResponse]] = {}
        for res in existing:
            norm = ResourceManagerDiffEngine._normalize_entity_key(res.entity_name or "")
            entity_only_index.setdefault(norm, []).append(res)
            log.debug(
                f"entity_only_index: added entity='{res.entity_name}' "
                f"under norm_key='{norm}' (total under key: {len(entity_only_index[norm])})"
            )

        log.debug(f"Built entity_only_index with {len(entity_only_index)} unique normalised key(s)")

        # Track which existing keys matched at least one proposed entry
        matched_existing_keys: set = set()

        # Categorise proposed resources
        for cfg in proposed:
            scope_type = cfg.scope_type
            pool_name = cfg.pool_name
            entity_name = cfg.entity_name
            resource_value = cfg.resource

            log.debug(
                f"Processing proposed cfg: entity={entity_name}, pool={pool_name}, "
                f"scope={scope_type}, resource={resource_value}, switch={cfg.switch}"
            )

            # device_pair and link encode both endpoints in entity_name; one lookup covers the pair.
            if scope_type in ("device_pair", "link"):
                switches = [None]
                log.debug(
                    f"scope_type='{scope_type}' is multi-endpoint — "
                    f"using single switch=None lookup for entity='{entity_name}'"
                )
            else:
                switches = cfg.switch if (scope_type != "fabric" and cfg.switch) else [None]
                log.debug(
                    f"scope_type='{scope_type}' — resolved switches={switches} "
                    f"for entity='{entity_name}'"
                )

            for sw in switches:
                key = ResourceManagerDiffEngine._make_resource_key(
                    entity_name, pool_name, scope_type, sw
                )
                log.debug(
                    f"Lookup key={key} for entity='{entity_name}', "
                    f"pool='{pool_name}', scope='{scope_type}', switch={sw}"
                )
                existing_res = existing_index.get(key)

                if existing_res is None:
                    log.info(
                        f"Resource (entity={entity_name}, pool={pool_name}, "
                        f"scope={scope_type}, switch={sw}) not found in existing — "
                        f"marking to_add"
                    )
                    changes["to_add"].append((cfg, sw, None))

                    # GAP-7: Partial-match detection — same entity_name, different
                    # pool_name / scope_type / switch_ip.  Mirrors ND's
                    # nd_rm_get_mismatched_values() / changed_dict["debugs"] logic.
                    norm = ResourceManagerDiffEngine._normalize_entity_key(entity_name)
                    partials = entity_only_index.get(norm, [])
                    log.debug(
                        f"Partial-match scan for entity='{entity_name}' "
                        f"(norm='{norm}'): {len(partials)} candidate(s)"
                    )
                    for partial in partials:
                        partial_pool = partial.pool_name
                        partial_scope = ResourceManagerDiffEngine._extract_scope_type(
                            partial.scope_details
                        )
                        partial_sw = ResourceManagerDiffEngine._extract_scope_switch_key_val(
                            partial.scope_details, switch_key="switch_ip", src_switch_key="src_switch_ip"
                        )
                        mismatch = {
                            "have_pool_name": partial_pool,
                            "want_pool_name": pool_name,
                            "have_scope_type": partial_scope,
                            "want_scope_type": scope_type,
                            "have_switch_ip": partial_sw,
                        }
                        log.debug(
                            f"compute_changes: partial match for entity='{entity_name}': {mismatch}"
                        )
                        changes["debugs"].append(
                            {"Entity Name": entity_name, "MISMATCHED_VALUES": mismatch}
                        )
                else:
                    log.debug(
                        f"Resource (entity={entity_name}, pool={pool_name}, "
                        f"scope={scope_type}, switch={sw}) found in existing — "
                        f"resource_id={getattr(existing_res, 'resource_id', None)}, "
                        f"existing_value='{existing_res.resource_value}'"
                    )
                    matched_existing_keys.add(key)
                    existing_value = existing_res.resource_value

                    if ResourceManagerDiffEngine._compare_resource_values(
                        existing_value, resource_value
                    ):
                        log.debug(
                            f"Resource (entity={entity_name}, pool={pool_name}, "
                            f"scope={scope_type}, switch={sw}) is idempotent "
                            f"(value={existing_value})"
                        )
                        changes["idempotent"].append((cfg, sw, existing_res))
                    else:
                        log.info(
                            f"Resource (entity={entity_name}, pool={pool_name}, "
                            f"scope={scope_type}, switch={sw}) value differs "
                            f"(existing={existing_value}, desired={resource_value}) — "
                            f"marking to_update"
                        )
                        changes["to_update"].append((cfg, sw, existing_res))

        log.debug(
            f"Proposed scan complete — matched_existing_keys={len(matched_existing_keys)}, "
            f"total existing_index keys={len(existing_index)}"
        )

        # Resources in existing but not matched by any proposed entry → to_delete
        for key, res in existing_index.items():
            if key not in matched_existing_keys:
                log.info(
                    f"Existing resource (entity={res.entity_name}, pool={res.pool_name}) "
                    f"not in proposed — marking to_delete"
                )
                changes["to_delete"].append(res)
            else:
                log.debug(
                    f"Existing resource (entity={res.entity_name}, pool={res.pool_name}, "
                    f"key={key}) was matched by a proposed entry — skipping to_delete"
                )

        log.info(
            f"Compute changes summary: "
            f"to_add={len(changes['to_add'])}, "
            f"to_update={len(changes['to_update'])}, "
            f"to_delete={len(changes['to_delete'])}, "
            f"idempotent={len(changes['idempotent'])}, "
            f"debugs={len(changes['debugs'])}"
        )
        log.debug("EXIT: compute_changes()")
        return changes

    @staticmethod
    def validate_resource_api_fields(
        nd: NDModule,
        resource_cfg: ResourceManagerConfigModel,
        api_resource: ResourceManagerResponse,
        log: logging.Logger,
        context: str,
    ) -> None:
        """Validate user-supplied resource fields against the ND API response.

        Only fields that are non-None in ``resource_cfg`` are validated.
        Fields omitted by the user are silently accepted from the API response.
        Uses ``ResourceManagerResponse`` model attributes directly for
        field access (``entity_name``, ``pool_name``, ``resource_value``,
        ``scope_details``).

        Args:
            nd: ND module wrapper used for failure handling.
            resource_cfg: Validated resource config from the playbook.
            api_resource: Matching ``ResourceManagerResponse`` from the ND API.
            log: Logger instance.
            context: Label used in error messages (e.g. ``"Resource"``).

        Returns:
            None.
        """
        mismatches: List[str] = []

        # entity_name: tilde-order-insensitive comparison
        if resource_cfg.entity_name is not None:
            cfg_norm = ResourceManagerDiffEngine._normalize_entity_key(
                resource_cfg.entity_name
            )
            api_norm = (
                ResourceManagerDiffEngine._normalize_entity_key(api_resource.entity_name)
                if api_resource.entity_name else None
            )
            log.debug(
                f"validate_resource_api_fields: checking entity_name — "
                f"cfg_norm='{cfg_norm}', api_norm='{api_norm}'"
            )
            if cfg_norm != api_norm:
                log.debug(
                    f"validate_resource_api_fields: entity_name MISMATCH — "
                    f"provided='{resource_cfg.entity_name}', API='{api_resource.entity_name}'"
                )
                mismatches.append(
                    f"entity_name: provided '{resource_cfg.entity_name}', "
                    f"API reports '{api_resource.entity_name}'"
                )
            else:
                log.debug(
                    f"validate_resource_api_fields: entity_name OK — "
                    f"'{resource_cfg.entity_name}' matches API"
                )
        else:
            log.debug(
                f"validate_resource_api_fields: entity_name not provided in cfg — skipping check "
                f"(api_entity_name='{api_resource.entity_name}')"
            )

        # pool_name: exact match
        if resource_cfg.pool_name is not None:
            log.debug(
                f"validate_resource_api_fields: checking pool_name — "
                f"cfg='{resource_cfg.pool_name}', api='{api_resource.pool_name}'"
            )
            if resource_cfg.pool_name != api_resource.pool_name:
                log.debug(
                    f"validate_resource_api_fields: pool_name MISMATCH — "
                    f"provided='{resource_cfg.pool_name}', API='{api_resource.pool_name}'"
                )
                mismatches.append(
                    f"pool_name: provided '{resource_cfg.pool_name}', "
                    f"API reports '{api_resource.pool_name}'"
                )
            else:
                log.debug(
                    f"validate_resource_api_fields: pool_name OK — "
                    f"'{resource_cfg.pool_name}' matches API"
                )
        else:
            log.debug(
                f"validate_resource_api_fields: pool_name not provided in cfg — skipping check "
                f"(api_pool_name='{api_resource.pool_name}')"
            )

        # resource vs resource_value: IPv4/v6-aware comparison
        if resource_cfg.resource is not None:
            log.debug(
                f"validate_resource_api_fields: checking resource value — "
                f"cfg='{resource_cfg.resource}', api='{api_resource.resource_value}'"
            )
            if not ResourceManagerDiffEngine._compare_resource_values(
                api_resource.resource_value, resource_cfg.resource
            ):
                log.debug(
                    f"validate_resource_api_fields: resource value MISMATCH — "
                    f"provided='{resource_cfg.resource}', API='{api_resource.resource_value}'"
                )
                mismatches.append(
                    f"resource: provided '{resource_cfg.resource}', "
                    f"API reports '{api_resource.resource_value}'"
                )
            else:
                log.debug(
                    f"validate_resource_api_fields: resource value OK — "
                    f"'{resource_cfg.resource}' matches API '{api_resource.resource_value}'"
                )
        else:
            log.debug(
                f"validate_resource_api_fields: resource not provided in cfg — skipping check "
                f"(api_resource_value='{api_resource.resource_value}')"
            )

        if mismatches:
            nd.module.fail_json(
                msg=(
                    f"{context} field mismatch for entity '{resource_cfg.entity_name}'. "
                    f"The following provided values do not match the API data:\n"
                    + "\n".join(f"  - {m}" for m in mismatches)
                )
            )

        log.debug(
            f"validate_resource_api_fields: all provided fields match API for "
            f"entity='{resource_cfg.entity_name}', pool='{resource_cfg.pool_name}'"
        )


class NDResourceManagerModule:
    """
    Manage resources in Cisco Nexus Dashboard via the ND Manage v1 API.

    Uses pydantic models for input validation and smart endpoints for path/verb generation.
    Preserves the same business logic as nd_manage_resource_manager.py.
    """

    def __init__(
        self,
        nd: NDModule,
        results: Results,
        logger: Optional[logging.Logger] = None,
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
            logger: Optional external logger.  If not provided a module-level logger
                (``logging.getLogger(__name__)``) is used.
        """
        self.nd = nd
        self.results = results
        self.log = logger if logger is not None else logging.getLogger(__name__)

        self.fabric = nd.params["fabric"]
        self.state = nd.params["state"]
        self.config = nd.params.get("config") or []

        # ND-compatible tracking dicts
        self.changed_dict = [{"merged": [], "deleted": [], "gathered": [], "debugs": []}]
        self.api_responses = []

        # Cached GET results
        self._all_resources = []
        self._resources_fetched = False

        # Get All resources for the given fabric and cache them for matching during merged/deleted operations
        self._get_all_resources()

        # Resource collections — existing/previous snapshot at init, proposed populated in manage_state
        self.existing: List[ResourceManagerResponse] = list(self._all_resources)
        self.previous: List[ResourceManagerResponse] = list(self._all_resources)
        self.proposed: List[ResourceManagerConfigModel] = []

        # NDOutput for building consistent Ansible output across all states
        self.output: NDOutput = NDOutput(output_level=nd.params.get("output_level", "normal"))

        self.log.info(
            f"NDResourceManagerModule initialized: fabric={self.fabric}, "
            f"state={self.state}, config_count={len(self.config)}"
        )

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------

    def _validate_resource_params(self, item):
        """Validate that the combination of pool_type, pool_name, and scope_type is allowed.

        Maps pool_type to an internal check_key (the pool_name for ID pools, 'IP_POOL' for
        IP pools, 'SUBNET' for subnet pools), then looks up the allowed scope_type list in
        ``_POOLNAME_TO_SCOPE_TYPE``.  Fails fast with an informative message if the
        combination is not permitted by the ND Manage API.

        Args:
            item: A single config dict from the playbook ``config`` list, expected to
                contain ``pool_type``, ``pool_name``, and ``scope_type`` keys.

        Returns:
            Tuple ``(True, '')`` when validation passes.
            Tuple ``(False, error_message)`` when an invalid combination is detected.
        """
        pool_type = item.get("pool_type")
        pool_name = item.get("pool_name")
        scope_type = item.get("scope_type")

        self.log.debug(
            f"Validating resource params: pool_type={pool_type}, "
            f"pool_name={pool_name}, scope_type={scope_type}"
        )

        if pool_type == "ID":
            self.log.debug(f"pool_type is 'ID', using pool_name as check_key: {pool_name}")
            check_key = pool_name
        elif pool_type == "IP":
            self.log.debug("pool_type is 'IP', using check_key='IP_POOL'")
            check_key = "IP_POOL"
        elif pool_type == "SUBNET":
            self.log.debug("pool_type is 'SUBNET', using check_key='SUBNET'")
            check_key = "SUBNET"
        else:
            msg = (
                "Given pool type = '{0}' is invalid,"
                " Allowed pool types = ['ID', 'IP', 'SUBNET']".format(pool_type)
            )
            self.log.warning(f"Validation failed: {msg}")
            return False, msg

        allowed_scopes = _POOLNAME_TO_SCOPE_TYPE.get(check_key)
        if allowed_scopes is None:
            msg = "Given pool name '{0}' is not valid".format(pool_name)
            self.log.warning(f"Validation failed: {msg}")
            return False, msg

        if scope_type not in allowed_scopes:
            msg = (
                "Given scope type '{0}' is not valid for pool name = '{1}',"
                " Allowed scope_types = {2}".format(
                    scope_type, pool_name, allowed_scopes
                )
            )
            self.log.warning(f"Validation failed: {msg}")
            return False, msg

        self.log.debug(
            f"Validation passed: pool_name={pool_name}, scope_type={scope_type}, "
            f"allowed_scopes={allowed_scopes}"
        )
        return True, ""

    def _validate_input(self):
        """Validate all playbook config items against the requirements of the current state.

        For ``merged`` and ``deleted`` states, ensures that ``config`` is provided and that
        every item carries the four mandatory fields (``entity_name``, ``pool_type``,
        ``pool_name``, ``scope_type``).  Also verifies that ``switch`` is present for any
        non-fabric scope type, runs pool_type/pool_name/scope_type compatibility checks via
        ``_validate_resource_params``, and performs pydantic cross-field validation via
        ``ResourceManagerConfigModel.from_config``.

        For ``gathered`` state, mandatory field checks are skipped so that partial filter
        criteria (e.g. only ``pool_name`` or only ``switch``) are accepted.

        Calls ``self.nd.module.fail_json`` directly on any validation failure.
        """
        self.log.info(
            f"Validating input: state={self.state}, config_count={len(self.config)}"
        )

        if not self.config:
            if self.state in ("merged", "deleted", "overridden"):
                self.log.error(
                    f"'config' is mandatory for state '{self.state}' but was not provided"
                )
                self.nd.module.fail_json(
                    msg="'config' element is mandatory for state '{0}'".format(
                        self.state
                    )
                )
            return

        for item in self.config:
            self.log.debug(
                f"Validating config item: entity_name={item.get('entity_name')}, "
                f"pool_name={item.get('pool_name')}, scope_type={item.get('scope_type')}, "
                f"pool_type={item.get('pool_type')}"
            )
            if self.state != "gathered":
                # Mandatory parameter checks
                for field in ("scope_type", "pool_type", "pool_name", "entity_name"):
                    if item.get(field) is None:
                        self.log.error(
                            f"Mandatory parameter '{field}' is missing in config item: {item}"
                        )
                        self.nd.module.fail_json(
                            msg="Mandatory parameter '{0}' missing".format(field)
                        )
                    else:
                        self.log.debug(f"Mandatory parameter '{field}' present: {item.get(field)}")

                # Switch required for non-fabric scopes
                if item.get("scope_type") != "fabric" and not item.get("switch"):
                    self.log.error(
                        f"'switch' is required for scope_type='{item.get('scope_type')}' "
                        f"but is missing in config item: {item}"
                    )
                    self.nd.module.fail_json(msg="switch : Required parameter not found")
                elif item.get("scope_type") != "fabric":
                    self.log.debug(
                        f"'switch' provided for scope_type='{item.get('scope_type')}': "
                        f"{item.get('switch')}"
                    )

            # Validate pool_name / scope_type combination (only when pool_type is provided)
            if item.get("pool_type") is not None:
                self.log.debug(
                    f"Running pool_type/pool_name/scope_type compatibility check for: "
                    f"pool_type={item.get('pool_type')}, pool_name={item.get('pool_name')}, "
                    f"scope_type={item.get('scope_type')}"
                )
                rc, mesg = self._validate_resource_params(item)
                if not rc:
                    self.log.error(f"Pool/scope compatibility check failed: {mesg}")
                    self.nd.module.fail_json(msg=mesg)
                else:
                    self.log.debug("Pool/scope compatibility check passed")

            # Pydantic cross-field validation for merged/deleted
            if self.state != "gathered":
                try:
                    ResourceManagerConfigModel.from_config(item)
                    self.log.debug(
                        f"Pydantic validation passed for entity_name={item.get('entity_name')}"
                    )
                except Exception as exc:
                    self.log.error(
                        f"Pydantic validation failed for entity_name={item.get('entity_name')}: {exc}"
                    )
                    self.nd.module.fail_json(
                        msg="Invalid parameters in playbook: {0}".format(str(exc))
                    )

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
                f"Resources already cached for fabric={self.fabric}: "
                f"{len(self._all_resources)} resource(s)"
            )
            return

        self.log.info(f"Fetching all resources for fabric={self.fabric}")

        ep = EpManageFabricResourcesGet(fabric_name=self.fabric)
        try:
            data = self.nd.request(ep.path, ep.verb)
        except NDModuleError as exc:
            if exc.status == 404:
                # Fabric has no resources yet — that is valid
                self.log.info(
                    f"No resources found (404) for fabric={self.fabric}, treating as empty"
                )
                self._resources_fetched = True
                return
            raise

        # The ND API may return a list directly or {"resources": [...], "meta": {...}}
        if isinstance(data, list):
            self.log.debug(f"API returned a list with {len(data)} item(s)")
            raw_list = data
        elif isinstance(data, dict) and "resources" in data:
            self.log.debug(
                f"API returned dict with 'resources' key, "
                f"{len(data['resources'])} resource(s)"
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
                    f"Parsed resource: entity_name={getattr(resource_model, 'entity_name', None)}, "
                    f"pool_name={getattr(resource_model, 'pool_name', None)}"
                )
                self._all_resources.append(resource_model)
            except Exception as exc:
                # If parsing fails, keep the raw dict so we can still match on it
                self.log.warning(
                    f"Failed to parse resource into ResourceManagerResponse (keeping raw): {exc} | raw={raw}"
                )
                self._all_resources.append(raw)

        self._resources_fetched = True
        self.log.info(
            f"Fetched {len(self._all_resources)} resource(s) for fabric={self.fabric}"
        )

    # ------------------------------------------------------------------
    # Resource attribute accessors (handle both ResourceManagerResponse and raw dict)
    # ------------------------------------------------------------------

    def _attr(self, resource, model_attr, dict_key):
        """Return a field value from a resource that may be a model instance or a raw dict.

        Tries to read ``model_attr`` from the resource via ``getattr`` first (for typed
        ``ResourceManagerResponse`` instances), then falls back to ``resource.get(dict_key)``
        for raw dict responses returned when model parsing failed at fetch time.

        Args:
            resource: A ``ResourceManagerResponse`` model instance or a plain dict.
            model_attr: Attribute name to access on a model instance (snake_case).
            dict_key: Key to access on a raw dict (camelCase, e.g. ``'entityName'``).

        Returns:
            The field value, or None if neither path resolves.
        """
        if hasattr(resource, model_attr):
            value = getattr(resource, model_attr)
            self.log.debug(f"_attr: resolved '{model_attr}' from model: {value}")
            return value
        if isinstance(resource, dict):
            value = resource.get(dict_key)
            self.log.debug(f"_attr: resolved '{dict_key}' from dict: {value}")
            return value
        self.log.debug(f"_attr: could not resolve '{model_attr}'/'{dict_key}' from resource type {type(resource)}")
        return None

    def _get_entity_name(self, resource):
        """Return the entity_name field from a resource model or raw dict."""
        return self._attr(resource, "entity_name", "entityName")

    def _get_pool_name(self, resource):
        """Return the pool_name field from a resource model or raw dict."""
        return self._attr(resource, "pool_name", "poolName")

    def _get_resource_id(self, resource):
        """Return the resource_id field from a resource model or raw dict."""
        return self._attr(resource, "resource_id", "resourceId")

    def _get_resource_value(self, resource):
        """Return the resource_value field from a resource model or raw dict."""
        return self._attr(resource, "resource_value", "resourceValue")

    def _get_scope_type(self, resource):
        """Return the playbook-style scope_type string for a resource.

        Reads the raw ND API ``scopeType`` value from either the model's
        ``scope_details.scope_type`` attribute or the ``scopeDetails.scopeType`` key of a
        raw dict, then maps it from the API camelCase format (e.g. ``'deviceInterface'``)
        to the playbook format (e.g. ``'device_interface'``) using
        ``_API_SCOPE_TYPE_TO_PLAYBOOK``.

        Args:
            resource: A ``ResourceManagerResponse`` model instance or a plain dict.

        Returns:
            Playbook-style scope_type string, or None if the resource type is unrecognised.
        """
        if hasattr(resource, "scope_details") and resource.scope_details:
            raw = getattr(resource.scope_details, "scope_type", None)
            self.log.debug(f"_get_scope_type: from model scope_details, raw={raw}")
        elif isinstance(resource, dict):
            sd = resource.get("scopeDetails") or {}
            raw = sd.get("scopeType")
            self.log.debug(f"_get_scope_type: from dict scopeDetails, raw={raw}")
        else:
            self.log.debug(f"_get_scope_type: unrecognised resource type {type(resource)}, returning None")
            return None
        mapped = _API_SCOPE_TYPE_TO_PLAYBOOK.get(raw, raw) if raw else None
        self.log.debug(f"_get_scope_type: mapped API scope '{raw}' -> playbook scope '{mapped}'")
        return mapped

    def _get_switch_ip(self, resource):
        """Return the primary switch IP/ID from scopeDetails (src switch for device_pair/link).

        Delegates to ResourceManagerDiffEngine._extract_scope_switch_key_val for model
        instances so that all scope types are handled uniformly:
          - fabric              → None
          - device / device_interface → switch_ip
          - device_pair / link  → src_switch_ip
        """
        if hasattr(resource, "scope_details") and resource.scope_details:
            value = ResourceManagerDiffEngine._extract_scope_switch_key_val(resource.scope_details, switch_key="switch_ip", src_switch_key="src_switch_ip")
            self.log.debug(f"_get_switch_ip: from model scope_details, switch_ip={value}")
            return value
        if isinstance(resource, dict):
            sd = resource.get("scopeDetails") or {}
            # device/deviceInterface use "switchIp"; device_pair/link use "srcSwitchIp"
            value = sd.get("switchIp") or sd.get("srcSwitchIp")
            self.log.debug(f"_get_switch_ip: from dict scopeDetails, switch_ip={value}")
            return value
        self.log.debug(f"_get_switch_ip: unrecognised resource type {type(resource)}, returning None")
        return None

    def _to_dict(self, resource):
        """Convert a resource to a plain dict suitable for API response output.

        Calls ``resource.to_payload()`` for ``ResourceManagerResponse`` model instances
        (which serialises to the ND API camelCase wire format).  Returns raw dicts
        unchanged, since they are already in the correct format.

        Args:
            resource: A ``ResourceManagerResponse`` model instance or a plain dict.

        Returns:
            A plain dict representation of the resource.
        """
        if hasattr(resource, "to_payload"):
            result = resource.to_payload()
            self.log.debug(f"_to_dict: converted ResourceManagerResponse to dict via to_payload(): {result}")
            return result
        self.log.debug(f"_to_dict: resource is already a raw dict, returning as-is")
        return resource

    # ------------------------------------------------------------------
    # Matching helpers
    # ------------------------------------------------------------------

    def _entity_names_match(self, e1, e2):
        """Compare two entity names in a tilde-order-insensitive way.

        Splits each name on ``'~'``, sorts the resulting parts alphabetically, and
        compares the sorted lists.  This ensures that a device_pair entity such as
        ``'SER1~SER2~label'`` matches ``'SER2~SER1~label'`` regardless of the order
        in which the serial numbers appear in the playbook vs the ND API response.

        Args:
            e1: First entity name string.
            e2: Second entity name string.

        Returns:
            True if both names are non-None and their sorted tilde-parts are equal,
            False otherwise.
        """
        if e1 is None or e2 is None:
            self.log.debug(
                f"_entity_names_match: one or both entity names are None "
                f"(e1={e1}, e2={e2}), returning False"
            )
            return False
        result = sorted(e1.split("~")) == sorted(e2.split("~"))
        self.log.debug(
            f"_entity_names_match: e1='{e1}', e2='{e2}', "
            f"sorted_e1={sorted(e1.split('~'))}, sorted_e2={sorted(e2.split('~'))}, "
            f"match={result}"
        )
        return result

    # ------------------------------------------------------------------
    # API payload builders
    # ------------------------------------------------------------------

    def _build_scope_details(self, scope_type, switch_ip=None, entity_name=None):
        """Build the scopeDetails Pydantic model for the ND Manage API.

        ``switch_ip`` is the translated switchId (serial number) of the source switch
        from the playbook ``switch`` list.  The entity_name encodes the full topology
        (src and dst) as tilde-separated fields — the server uses it to resolve
        additional context, so we only need to supply srcSwitchId for multi-switch
        scopes (device_pair, link) and let the server derive dst from entityName.

          - fabric:           FabricScope(fabricName)
          - device:           DeviceScope(switchId)
          - device_interface: DeviceInterfaceScope(switchId, interfaceName)
          - device_pair:      DevicePairScope(srcSwitchId)  — dst derived by server from entityName
          - link:             LinkScope(srcSwitchId, srcInterfaceName)  — dst derived by server from entityName
        """
        self.log.debug(
            f"_build_scope_details: scope_type={scope_type}, switch_ip={switch_ip}, "
            f"entity_name={entity_name}, fabric={self.fabric}"
        )

        if scope_type == "fabric":
            self.log.debug(
                f"_build_scope_details: fabric scope -> fabricName={self.fabric}"
            )
            result = FabricScope(fabric_name=self.fabric)

        elif scope_type == "device":
            self.log.debug(
                f"_build_scope_details: device scope -> switchId={switch_ip}"
            )
            result = DeviceScope(switch_id=switch_ip)

        elif scope_type == "device_interface":
            # entity_name format: <serialNumber>~<interfaceName>
            # switch_ip is already the translated switchId (serial number)
            parts = (entity_name or "").split("~", 1)
            if_name = parts[1] if len(parts) > 1 else None
            self.log.debug(
                f"_build_scope_details: device_interface scope -> "
                f"switchId={switch_ip}, interfaceName={if_name} "
                f"(interfaceName parsed from entity_name='{entity_name}')"
            )
            if not if_name:
                self.log.warning(
                    f"_build_scope_details: device_interface scope: could not parse "
                    f"interfaceName from entity_name='{entity_name}'"
                )
            result = DeviceInterfaceScope(switch_id=switch_ip, interface_name=if_name)

        elif scope_type == "device_pair":
            # entity_name format: <srcSN>~<dstSN>[~<label>]
            # Both srcSwitchId and dstSwitchId must be sent — the server does not derive
            # dstSwitchId from entityName and returns "JSONObject["dstSwitchId"] not found."
            # if it is missing.
            parts = (entity_name or "").split("~")
            src_sn = parts[0] if len(parts) > 0 else None
            dst_sn = parts[1] if len(parts) > 1 else None
            self.log.debug(
                f"_build_scope_details: device_pair scope -> srcSwitchId={src_sn}, "
                f"dstSwitchId={dst_sn} (parsed from entity_name='{entity_name}')"
            )
            result = DevicePairScope(src_switch_id=src_sn, dst_switch_id=dst_sn)

        elif scope_type == "link":
            # entity_name format: <srcSN>~<srcIF>~<dstSN>~<dstIF>
            # All four fields must be supplied — the server does not derive dst context
            # from entityName alone.
            parts = (entity_name or "").split("~")
            src_sn = parts[0] if len(parts) > 0 else None
            src_if = parts[1] if len(parts) > 1 else None
            dst_sn = parts[2] if len(parts) > 2 else None
            dst_if = parts[3] if len(parts) > 3 else None
            self.log.debug(
                f"_build_scope_details: link scope -> srcSwitchId={src_sn}, "
                f"srcInterfaceName={src_if}, dstSwitchId={dst_sn}, "
                f"dstInterfaceName={dst_if} (parsed from entity_name='{entity_name}')"
            )
            result = LinkScope(
                src_switch_id=src_sn,
                src_interface_name=src_if,
                dst_switch_id=dst_sn,
                dst_interface_name=dst_if,
            )

        else:
            self.log.warning(
                f"_build_scope_details: unrecognised scope_type='{scope_type}', "
                f"falling back to generic DeviceScope payload"
            )
            result = DeviceScope(switch_id=switch_ip)

        self.log.debug(f"_build_scope_details: result={result}")
        return result

    def _build_create_payload(self, cfg, switch_ip=None):
        """Build the POST body for a single resource creation request.

        Accepts either a typed ``ResourceManagerConfigModel`` instance or a legacy dict
        (backward-compatible path).  Delegates scope construction to
        ``_build_scope_details`` and serialises the complete request via
        ``ResourceManagerRequest.to_payload()``.

        Args:
            cfg: A ``ResourceManagerConfigModel`` instance or a dict with keys
                ``scope_type``, ``entity_name``, ``pool_name``, ``pool_type``,
                and optionally ``resource``.
            switch_ip: The resolved switchId (serial number) for the primary switch,
                or None for fabric-scoped resources.

        Returns:
            A plain dict payload ready to be sent to the ND Manage API POST endpoint.
        """
        if isinstance(cfg, ResourceManagerConfigModel):
            scope_type = cfg.scope_type
            entity_name = cfg.entity_name
            pool_name = cfg.pool_name
            pool_type = cfg.pool_type
            resource_value = cfg.resource
        else:
            # Legacy dict path (kept for backward-compat with any callers not yet refactored)
            scope_type = cfg["scope_type"]
            entity_name = cfg["entity_name"]
            pool_name = cfg["pool_name"]
            pool_type = cfg.get("pool_type")
            resource_value = cfg.get("resource")

        self.log.debug(
            f"_build_create_payload: pool_name={pool_name}, pool_type={pool_type}, "
            f"entity_name={entity_name}, scope_type={scope_type}, "
            f"switch_ip={switch_ip}, resource={resource_value}"
        )

        scope = self._build_scope_details(scope_type, switch_ip, entity_name=entity_name)

        request = ResourceManagerRequest(
            pool_name=pool_name,
            pool_type=pool_type,
            entity_name=entity_name,
            scope_details=scope,
            is_pre_allocated=True,
            resource_value=str(resource_value) if resource_value is not None else None,
        )

        if resource_value is not None:
            self.log.debug(
                f"_build_create_payload: adding resourceValue='{resource_value}' to payload"
            )
        else:
            self.log.debug(
                "_build_create_payload: no resource value provided, omitting resourceValue field"
            )

        payload = request.to_payload()
        self.log.debug(f"_build_create_payload: final payload={payload}")
        return payload


    # ------------------------------------------------------------------
    # Gathered results translation
    # ------------------------------------------------------------------

    def _determine_pool_type(self, resource_value):
        """Infer the pool_type from a resource value string.

        Attempts to parse the value as an IP network (returns ``'SUBNET'``), then as an
        IP address (returns ``'IP'``), and falls back to ``'ID'`` for plain integer or
        string identifiers.  Used when translating raw API responses back into the playbook
        config format during gathered-state output.

        Args:
            resource_value: The raw resource value string from the ND API response,
                e.g. ``'101'``, ``'10.1.1.1'``, or ``'10.1.1.0/24'``.  May be None.

        Returns:
            One of ``'ID'``, ``'IP'``, or ``'SUBNET'``.
        """
        self.log.debug(
            f"_determine_pool_type: evaluating resource_value='{resource_value}'"
        )
        if not resource_value:
            self.log.debug(
                "_determine_pool_type: resource_value is None/empty — returning 'ID'"
            )
            return "ID"
        val = str(resource_value).strip()
        if "/" in val:
            self.log.debug(
                f"_determine_pool_type: value='{val}' contains '/' — "
                f"attempting ip_network parse"
            )
            try:
                ipaddress.ip_network(val, strict=False)
                self.log.debug(
                    f"_determine_pool_type: '{val}' is a valid IP network — returning 'SUBNET'"
                )
                return "SUBNET"
            except ValueError:
                self.log.debug(
                    f"_determine_pool_type: '{val}' failed ip_network parse — "
                    f"falling through to ip_address check"
                )
        else:
            self.log.debug(
                f"_determine_pool_type: value='{val}' has no '/' — "
                f"skipping ip_network check"
            )
        try:
            ipaddress.ip_address(val)
            self.log.debug(
                f"_determine_pool_type: '{val}' is a valid IP address — returning 'IP'"
            )
            return "IP"
        except ValueError:
            self.log.debug(
                f"_determine_pool_type: '{val}' is not an IP address — returning 'ID'"
            )
        return "ID"

    def translate_gathered_results(self, resources):
        """Translate raw API resource items to the merged-state config format.

        Converts each resource from the ND API response shape
        (camelCase keys, nested scopeDetails) into the playbook ``config``
        format used by ``state: merged``:
          entity_name, pool_type, pool_name, scope_type, resource[, switch].
        """
        translated = []
        self.log.debug(
            f"translate_gathered_results: translating {len(resources)} resource(s) "
            f"to playbook config format"
        )
        for res_idx, res in enumerate(resources):
            entity_name = self._get_entity_name(res)
            pool_name = self._get_pool_name(res)
            resource_value = self._get_resource_value(res)
            scope_type = self._get_scope_type(res)
            switch_ip = self._get_switch_ip(res)
            pool_type = self._determine_pool_type(resource_value)
            self.log.debug(
                f"translate_gathered_results: [{res_idx}] resolved fields — "
                f"entity_name='{entity_name}', pool_name='{pool_name}', "
                f"scope_type='{scope_type}', pool_type='{pool_type}', "
                f"resource_value='{resource_value}', switch_ip='{switch_ip}'"
            )

            item = {
                "entity_name": entity_name,
                "pool_type": pool_type,
                "pool_name": pool_name,
                "scope_type": scope_type,
                "resource": resource_value,
            }
            if scope_type != "fabric" and switch_ip:
                item["switch"] = [switch_ip]
                self.log.debug(
                    f"translate_gathered_results: [{res_idx}] entity='{entity_name}' — "
                    f"non-fabric scope ('{scope_type}'), adding switch=['{switch_ip}'] to item"
                )
            else:
                self.log.debug(
                    f"translate_gathered_results: [{res_idx}] entity='{entity_name}' — "
                    f"scope_type='{scope_type}', switch_ip='{switch_ip}' — "
                    f"no switch field added"
                )

            translated.append(item)
            self.log.debug(
                f"translate_gathered_results: [{res_idx}] appended item={item}"
            )
        self.log.debug(
            f"translate_gathered_results: completed — "
            f"{len(translated)} item(s) translated"
        )
        return translated

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
            f"manage_merged: Processing {len(self.config)} config item(s) "
            f"for fabric={self.fabric}"
        )

        # Use compute_changes as the canonical diff engine (GAP-4).
        changes = ResourceManagerDiffEngine.compute_changes(
            self.proposed, self.existing, self.log
        )

        # Propagate partial-match mismatch diagnostics to the output diff (GAP-7).
        self.changed_dict[0]["debugs"].extend(changes["debugs"])

        # Resources that need to be created: new (to_add) or value changed (to_update).
        pending_items: List[Tuple] = changes["to_add"] + changes["to_update"]

        if not pending_items:
            self.log.debug("manage_merged: No resources to create (all idempotent).")
            return

        # Build payload list alongside a cfg reference for post-create validation (GAP-5).
        pending_payloads = []
        for cfg, sw, _existing in pending_items:
            payload = self._build_create_payload(cfg, switch_ip=sw)
            pending_payloads.append((cfg, payload))
            self.log.debug(
                f"manage_merged: Queuing resource for batch create: "
                f"entity_name={cfg.entity_name}, pool_name={cfg.pool_name}, "
                f"scope_type={cfg.scope_type}, switch_ip={sw}"
            )

        # Track diff BEFORE the API call so --check mode also shows what would change (GAP-3).
        self.changed_dict[0]["merged"].extend(p for _, p in pending_payloads)

        if self.nd.module.check_mode:
            self.log.info(
                f"Check mode: would create {len(pending_payloads)} resource(s) "
                f"for fabric={self.fabric}"
            )
            return

        self.log.info(
            f"manage_merged: Making batch API call with {len(pending_payloads)} resource(s) "
            f"for fabric={self.fabric}"
        )

        payloads_only = [p for _, p in pending_payloads]
        batch = ResourceManagerBatchRequest.model_validate({"resources": payloads_only})
        ep = EpManageFabricResourcesPost(fabric_name=self.fabric)
        resp_data = self.nd.request(ep.path, ep.verb, data=batch.to_payload())

        # Parse batch response.
        batch_response = ResourcesManagerBatchResponse.from_response(resp_data)
        self.log.debug(
            f"manage_merged: Batch API response parsed — "
            f"{len(batch_response.resources)} item(s) returned"
        )

        # Build a normalised entity_name → cfg lookup for GAP-5 field validation.
        # If two items share a normalised name (unusual), the last one wins; that is
        # acceptable because validate_resource_api_fields uses order-insensitive comparison.
        cfg_by_entity: Dict[str, ResourceManagerConfigModel] = {
            ResourceManagerDiffEngine._normalize_entity_key(cfg.entity_name): cfg
            for cfg, _ in pending_payloads
        }

        for resp_item in batch_response.resources:
            self.api_responses.append(
                {"RETURN_CODE": 200, "DATA": resp_item.model_dump(by_alias=True, exclude_none=True)}
            )
            # GAP-5: Validate that the API response fields match what we sent.
            if resp_item.entity_name is not None:
                norm_key = ResourceManagerDiffEngine._normalize_entity_key(resp_item.entity_name)
                matched_cfg = cfg_by_entity.get(norm_key)
                if matched_cfg is not None:
                    ResourceManagerDiffEngine.validate_resource_api_fields(
                        self.nd, matched_cfg, resp_item, self.log, "Resource"
                    )

        self.log.info(
            f"manage_merged: Batch create successful — {len(pending_payloads)} resource(s) created "
            f"for fabric={self.fabric}"
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
            f"manage_deleted: Processing {len(self.config)} config item(s) "
            f"for fabric={self.fabric}"
        )

        # Use compute_changes as the canonical diff engine (GAP-4).
        changes = ResourceManagerDiffEngine.compute_changes(
            self.proposed, self.existing, self.log
        )

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
        for _cfg, _sw, existing_res in (changes["idempotent"] + changes["to_update"]):
            rid = self._get_resource_id(existing_res)
            if rid is not None and rid not in resource_ids:
                self.log.debug(
                    f"manage_deleted: Queuing resource ID '{rid}' for deletion "
                    f"(entity_name={_cfg.entity_name}, pool_name={_cfg.pool_name}, switch_ip={_sw})"
                )
                resource_ids.append(rid)
            elif rid is not None:
                self.log.debug(
                    f"manage_deleted: Resource ID '{rid}' already queued, skipping duplicate"
                )
            else:
                self.log.debug(
                    f"manage_deleted: Matched resource has no resource ID, skipping: {existing_res}"
                )

        if not resource_ids:
            # Nothing to delete — idempotent
            self.log.info(
                f"manage_deleted: No matching resources found to delete "
                f"for fabric={self.fabric}, nothing to do"
            )
            return

        self.log.info(
            f"manage_deleted: Collected {len(resource_ids)} resource ID(s) "
            f"to delete: {resource_ids}"
        )

        self.changed_dict[0]["deleted"].extend(str(r) for r in resource_ids)

        if self.nd.module.check_mode:
            self.log.info(
                f"Check mode: would delete {len(resource_ids)} resource(s): {resource_ids}"
            )
            self.api_responses.append(
                {"RETURN_CODE": 200, "DATA": {"resourceIds": resource_ids}}
            )
            return

        ep = EpManageFabricResourcesActionsRemovePost(fabric_name=self.fabric)
        remove_req = RemoveResourcesByIdsRequest(resource_ids=resource_ids)
        resp_data = self.nd.request(ep.path, ep.verb, data=remove_req.to_payload())

        remove_response = RemoveResourcesByIdsResponse.from_response(resp_data)

        self.log.debug(
            f"manage_deleted: Delete API response parsed — "
            f"{len(remove_response.resources)} item(s) returned"
        )

        for resp_item in remove_response.resources:
            self.api_responses.append(
                {"RETURN_CODE": 200, "DATA": resp_item.model_dump(by_alias=True, exclude_none=True)}
            )

        self.log.info(
            f"manage_deleted: Successfully deleted {len(resource_ids)} resource(s): "
            f"{resource_ids}"
        )

    def manage_gathered(self):
        """Return resources from the ND fabric, optionally filtered by config criteria.

        When no ``config`` is provided, all resources cached in ``self._all_resources`` are
        translated to the playbook format and returned.  When ``config`` is provided, each
        filter item is processed in sequence; a resource must satisfy every non-None
        criterion in the filter (``entity_name``, ``pool_name``, ``switch``) to be
        included.  Deduplication is applied across filter items using the resource ID so
        that a resource matching multiple filters appears only once in the output.

        Results are stored in ``self.changed_dict[0]['gathered']`` and
        ``self.api_responses``.
        """
        config_count = len(self.config) if self.config else 0
        self.log.info(
            f"manage_gathered: Gathering resources for fabric={self.fabric}, "
            f"filter_count={config_count}"
        )

        if not self.config:
            # No filters — return everything translated to merged format
            results = self.translate_gathered_results(self._all_resources)
            self.log.info(
                f"manage_gathered: No filter criteria provided, "
                f"returning all {len(results)} resource(s)"
            )
            self.api_responses.extend(results)
            self.changed_dict[0]["gathered"].extend(results)
            return

        seen_ids = set()
        results = []

        for filter_item in self.config:
            filter_entity = filter_item.get("entity_name")
            filter_pool = filter_item.get("pool_name")
            filter_switches = filter_item.get("switch") or []

            # Skip filter items with no active criteria to avoid matching all resources
            if not filter_entity and not filter_pool and not filter_switches:
                self.log.debug(
                    "manage_query: Skipping filter item with no active criteria "
                    f"(entity_name={filter_entity}, pool_name={filter_pool}, switches={filter_switches})"
                )
                continue

            self.log.debug(
                f"manage_query: Applying filter: entity_name={filter_entity}, "
                f"pool_name={filter_pool}, switches={filter_switches}"
            )

            for res in self._all_resources:
                rid = self._get_resource_id(res)

                # Deduplicate across filter criteria
                if rid is not None and rid in seen_ids:
                    self.log.debug(
                        f"manage_query: Skipping resource id='{rid}' (already included via previous filter)"
                    )
                    continue

                res_entity = self._get_entity_name(res)
                res_pool = self._get_pool_name(res)
                # Use switchId (serial number) from scopeDetails to match playbook switch config values
                if hasattr(res, "scope_details") and res.scope_details:
                    res_sw = ResourceManagerDiffEngine._extract_scope_switch_key_val(
                        res.scope_details, switch_key="switch_id", src_switch_key="src_switch_id"
                    )
                elif isinstance(res, dict):
                    sd = res.get("scopeDetails") or {}
                    res_sw = sd.get("switchId") or sd.get("srcSwitchId")
                else:
                    res_sw = None

                # Apply entity_name filter
                if filter_entity and not self._entity_names_match(
                    res_entity, filter_entity
                ):
                    self.log.debug(
                        f"manage_query: Skipping resource id='{rid}', entity_name mismatch: "
                        f"resource='{res_entity}' vs filter='{filter_entity}'"
                    )
                    continue

                # Apply pool_name filter
                if filter_pool and res_pool != filter_pool:
                    self.log.debug(
                        f"manage_query: Skipping resource id='{rid}', pool_name mismatch: "
                        f"resource='{res_pool}' vs filter='{filter_pool}'"
                    )
                    continue

                # Apply switch filter: match switchId (serial number) from scopeDetails;
                # fabric-scoped resources (no switchId) are correctly excluded
                if filter_switches and res_sw not in filter_switches:
                    self.log.debug(
                        f"manage_query: Skipping resource id='{rid}', switchId not in filter: "
                        f"resource_switch='{res_sw}', filter_switches={filter_switches}"
                    )
                    continue

                self.log.debug(
                    f"manage_query: Resource id='{rid}' matched all filters "
                    f"(entity_name='{res_entity}', pool_name='{res_pool}', switch_ip='{res_sw}')"
                )
                result_dict = self.translate_gathered_results([res])[0]
                results.append(result_dict)
                if rid is not None:
                    seen_ids.add(rid)

        self.log.info(
            f"manage_gathered: Gather complete, {len(results)} resource(s) matched filters"
        )
        self.api_responses.extend(results)
        self.changed_dict[0]["gathered"].extend(results)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def manage_overridden(self):
        """Reconcile the fabric to exactly match the desired config.

        Implements a two-phase Delete → Create workflow:

        **Phase 1 — Delete**: resources present in the fabric but absent from the
        desired config (orphans) are deleted.  Resources present in both but with a
        differing value (``to_update``) are also deleted so they can be recreated with
        the new value in Phase 2.

        **Phase 2 — Create**: resources absent from the fabric (``to_add``) plus
        resources whose old value was just deleted (``to_update``) are created in a
        single batch POST.

        Resources whose value already matches the desired config (``idempotent``) are
        left untouched.

        In check mode, the method logs and records what *would* change without issuing
        any API calls.

        Raises:
            NDModuleError: Propagated from ``self.nd.request`` on API failure.
        """
        self.log.debug("ENTER: manage_overridden()")
        self.log.info(
            f"manage_overridden: Processing {len(self.proposed)} proposed config item(s) "
            f"against {len(self.existing)} existing resource(s) for fabric={self.fabric}"
        )

        # Compute the full diff in one pass
        changes = ResourceManagerDiffEngine.compute_changes(
            self.proposed, self.existing, self.log
        )

        # Propagate partial-match diagnostics
        self.changed_dict[0]["debugs"].extend(changes["debugs"])
        self.log.debug(
            f"manage_overridden: compute_changes result — "
            f"to_add={len(changes['to_add'])}, "
            f"to_update={len(changes['to_update'])}, "
            f"to_delete={len(changes['to_delete'])}, "
            f"idempotent={len(changes['idempotent'])}, "
            f"debugs={len(changes['debugs'])}"
        )

        has_work = bool(
            changes["to_add"] or changes["to_update"] or changes["to_delete"]
        )
        if not has_work:
            self.log.info(
                "manage_overridden: nothing to do — "
                "all existing resources match desired config (fully idempotent)"
            )
            self.log.debug("EXIT: manage_overridden()")
            return

        # ------------------------------------------------------------------
        # Check mode — log what would change and return without API calls
        # ------------------------------------------------------------------
        if self.nd.module.check_mode:
            self.log.info(
                f"manage_overridden: check mode — "
                f"would_delete={len(changes['to_delete']) + len(changes['to_update'])}, "
                f"would_create={len(changes['to_add']) + len(changes['to_update'])}"
            )

            if changes["to_delete"]:
                self.log.info(
                    "manage_overridden: check mode — orphan resources that would be deleted:"
                )
                for res in changes["to_delete"]:
                    rid = self._get_resource_id(res)
                    entity = self._get_entity_name(res)
                    pool = self._get_pool_name(res)
                    self.log.info(
                        f"  [check-mode delete] entity='{entity}', pool='{pool}', id='{rid}'"
                    )
                    self.changed_dict[0]["deleted"].append(str(rid) if rid else entity)
            else:
                self.log.info("manage_overridden: check mode — no orphan resources to delete")

            if changes["to_update"]:
                self.log.info(
                    "manage_overridden: check mode — resources with changed values "
                    "(would delete-old then create-new):"
                )
                for cfg, sw, existing_res in changes["to_update"]:
                    rid = self._get_resource_id(existing_res)
                    self.log.info(
                        f"  [check-mode update] entity='{cfg.entity_name}', "
                        f"pool='{cfg.pool_name}', switch={sw}, id='{rid}'"
                    )
                    self.changed_dict[0]["deleted"].append(str(rid) if rid else cfg.entity_name)
                    self.changed_dict[0]["merged"].append(cfg.entity_name)
            else:
                self.log.info("manage_overridden: check mode — no value-changed resources")

            if changes["to_add"]:
                self.log.info(
                    "manage_overridden: check mode — new resources that would be created:"
                )
                for cfg, sw, _existing in changes["to_add"]:
                    self.log.info(
                        f"  [check-mode add] entity='{cfg.entity_name}', "
                        f"pool='{cfg.pool_name}', switch={sw}"
                    )
                    self.changed_dict[0]["merged"].append(cfg.entity_name)
            else:
                self.log.info("manage_overridden: check mode — no new resources to create")

            self.log.debug("EXIT: manage_overridden() [check mode]")
            return

        # ------------------------------------------------------------------
        # Phase 1: Delete — orphans + old values for resources being updated
        # ------------------------------------------------------------------
        delete_ids: List[str] = []

        self.log.info(
            f"manage_overridden: Phase 1 — collecting resource IDs to delete: "
            f"{len(changes['to_delete'])} orphan(s), "
            f"{len(changes['to_update'])} to-update (old value) resource(s)"
        )

        # Orphans: exist in fabric, not in desired config
        if changes["to_delete"]:
            self.log.info(
                f"manage_overridden: Phase 1 — processing {len(changes['to_delete'])} orphan resource(s)"
            )
            for res_idx, res in enumerate(changes["to_delete"]):
                rid = self._get_resource_id(res)
                entity = self._get_entity_name(res)
                pool = self._get_pool_name(res)
                scope_type = self._get_scope_type(res)
                switch_ip = self._get_switch_ip(res)
                self.log.info(
                    f"  [Phase1-orphan idx={res_idx}] entity='{entity}', pool='{pool}', "
                    f"scope_type='{scope_type}', switch='{switch_ip}', id='{rid}'"
                )
                if rid is not None and rid not in delete_ids:
                    self.log.debug(
                        f"  [Phase1-orphan idx={res_idx}] queuing id='{rid}' for deletion"
                    )
                    delete_ids.append(rid)
                    self.changed_dict[0]["deleted"].append(str(rid))
                elif rid is not None:
                    self.log.debug(
                        f"  [Phase1-orphan idx={res_idx}] id='{rid}' already queued — skipping duplicate"
                    )
                else:
                    self.log.warning(
                        f"  [Phase1-orphan idx={res_idx}] entity='{entity}' has no resource ID — skipping"
                    )
        else:
            self.log.info("manage_overridden: Phase 1 — no orphan resources to delete")

        # Value-changed resources: delete old value before recreating with new value
        if changes["to_update"]:
            self.log.info(
                f"manage_overridden: Phase 1 — processing "
                f"{len(changes['to_update'])} value-changed resource(s) for old-value deletion"
            )
            for upd_idx, (cfg, sw, existing_res) in enumerate(changes["to_update"]):
                rid = self._get_resource_id(existing_res)
                old_val = self._get_resource_value(existing_res)
                self.log.info(
                    f"  [Phase1-update idx={upd_idx}] entity='{cfg.entity_name}', "
                    f"pool='{cfg.pool_name}', switch={sw}, old_value='{old_val}', "
                    f"new_value='{cfg.resource}', id='{rid}'"
                )
                if rid is not None and rid not in delete_ids:
                    self.log.debug(
                        f"  [Phase1-update idx={upd_idx}] queuing old id='{rid}' for deletion"
                    )
                    delete_ids.append(rid)
                    self.changed_dict[0]["deleted"].append(str(rid))
                elif rid is not None:
                    self.log.debug(
                        f"  [Phase1-update idx={upd_idx}] id='{rid}' already queued — skipping duplicate"
                    )
                else:
                    self.log.warning(
                        f"  [Phase1-update idx={upd_idx}] entity='{cfg.entity_name}' "
                        f"has no resource ID — cannot delete old value"
                    )
        else:
            self.log.info(
                "manage_overridden: Phase 1 — no value-changed resources to delete"
            )

        if delete_ids:
            self.log.info(
                f"manage_overridden: Phase 1 — executing bulk delete for "
                f"{len(delete_ids)} resource ID(s): {delete_ids}"
            )
            ep = EpManageFabricResourcesActionsRemovePost(fabric_name=self.fabric)
            remove_req = RemoveResourcesByIdsRequest(resource_ids=delete_ids)
            resp_data = self.nd.request(ep.path, ep.verb, data=remove_req.to_payload())
            remove_response = RemoveResourcesByIdsResponse.from_response(resp_data)
            self.log.info(
                f"manage_overridden: Phase 1 — bulk delete complete, "
                f"API returned {len(remove_response.resources)} item(s)"
            )
            for resp_item in remove_response.resources:
                self.api_responses.append(
                    {"RETURN_CODE": 200, "DATA": resp_item.model_dump(by_alias=True, exclude_none=True)}
                )
        else:
            self.log.info(
                "manage_overridden: Phase 1 — delete_ids list is empty, "
                "skipping bulk delete API call"
            )

        # ------------------------------------------------------------------
        # Phase 2: Create — new resources + reissued resources with new values
        # ------------------------------------------------------------------
        pending_items: List[Tuple] = changes["to_add"] + changes["to_update"]

        self.log.info(
            f"manage_overridden: Phase 2 — preparing to create "
            f"{len(pending_items)} resource(s): "
            f"{len(changes['to_add'])} new, {len(changes['to_update'])} value-changed"
        )

        if not pending_items:
            self.log.info(
                "manage_overridden: Phase 2 — no resources to create (nothing to add or update)"
            )
            self.log.debug("EXIT: manage_overridden()")
            return

        # Build create payloads
        pending_payloads: List[Tuple] = []
        for item_idx, (cfg, sw, _existing) in enumerate(pending_items):
            payload = self._build_create_payload(cfg, switch_ip=sw)
            pending_payloads.append((cfg, payload))
            self.log.debug(
                f"  [Phase2-create idx={item_idx}] entity='{cfg.entity_name}', "
                f"pool='{cfg.pool_name}', scope_type='{cfg.scope_type}', switch={sw}, "
                f"resource='{cfg.resource}'"
            )
            self.changed_dict[0]["merged"].append(payload)

        self.log.info(
            f"manage_overridden: Phase 2 — sending batch create POST with "
            f"{len(pending_payloads)} payload(s) for fabric={self.fabric}"
        )
        payloads_only = [p for _, p in pending_payloads]
        batch = ResourceManagerBatchRequest.model_validate({"resources": payloads_only})
        ep = EpManageFabricResourcesPost(fabric_name=self.fabric)
        resp_data = self.nd.request(ep.path, ep.verb, data=batch.to_payload())

        batch_response = ResourcesManagerBatchResponse.from_response(resp_data)
        self.log.info(
            f"manage_overridden: Phase 2 — batch create returned "
            f"{len(batch_response.resources)} item(s)"
        )

        # Build cfg lookup for post-create field validation
        cfg_by_entity: Dict[str, ResourceManagerConfigModel] = {
            ResourceManagerDiffEngine._normalize_entity_key(cfg.entity_name): cfg
            for cfg, _ in pending_payloads
        }

        for resp_idx, resp_item in enumerate(batch_response.resources):
            self.log.debug(
                f"  [Phase2-validate idx={resp_idx}] validating response for "
                f"entity='{resp_item.entity_name}'"
            )
            self.api_responses.append(
                {"RETURN_CODE": 200, "DATA": resp_item.model_dump(by_alias=True, exclude_none=True)}
            )
            if resp_item.entity_name is not None:
                norm_key = ResourceManagerDiffEngine._normalize_entity_key(resp_item.entity_name)
                matched_cfg = cfg_by_entity.get(norm_key)
                if matched_cfg is not None:
                    self.log.debug(
                        f"  [Phase2-validate idx={resp_idx}] matched cfg for entity='{resp_item.entity_name}' — validating fields"
                    )
                    ResourceManagerDiffEngine.validate_resource_api_fields(
                        self.nd, matched_cfg, resp_item, self.log, "Resource"
                    )
                else:
                    self.log.debug(
                        f"  [Phase2-validate idx={resp_idx}] no cfg match for entity='{resp_item.entity_name}' — skipping field validation"
                    )

        self.log.info(
            f"manage_overridden: Phase 2 — batch create successful, "
            f"{len(pending_payloads)} resource(s) created for fabric={self.fabric}"
        )
        self.log.debug("EXIT: manage_overridden()")

    def manage_state(self):
        """Validate input and dispatch to the appropriate state handler.

        Runs ``_validate_input`` on the raw config, then converts the config list to
        typed ``ResourceManagerConfigModel`` objects via
        ``ResourceManagerDiffEngine.validate_configs`` (skipped for ``gathered`` state).
        Dispatches to ``manage_merged``, ``manage_deleted``, ``manage_overridden``, or
        ``manage_gathered`` depending on ``self.state``.
        """
        self.log.info(f"manage_state: Dispatching to state handler: state={self.state}")
        self._validate_input()

        if self.config and self.state != "gathered":
            self.proposed = ResourceManagerDiffEngine.validate_configs(
                self.config, self.state, self.nd, self.log
            )
            self.output.assign(
                proposed_configs=[
                    cfg.model_dump(by_alias=True, exclude_none=True)
                    for cfg in self.proposed
                ]
            )

        if self.state == "merged":
            self.log.info("manage_state: Dispatching to manage_merged()")
            self.manage_merged()
        elif self.state == "overridden":
            self.log.info("manage_state: Dispatching to manage_overridden()")
            self.manage_overridden()
        elif self.state == "deleted":
            self.log.info("manage_state: Dispatching to manage_deleted()")
            self.manage_deleted()
        elif self.state == "gathered":
            self.log.info("manage_state: Dispatching to manage_gathered()")
            self.manage_gathered()

        self.log.info(f"manage_state: State handler completed for state={self.state}")

    def exit_module(self):
        """Build the final module result and call ``exit_json`` to return it to Ansible.

        For ``gathered`` state, passes the gathered list through ``NDOutput.format``
        so the output always includes the ``output_level`` key.
        For all other states, computes the ``changed`` flag from whether any resources
        were merged or deleted, re-queries the ND API to capture post-operation state
        (unless in check mode), assigns ``previous``/``current`` snapshots via
        ``self.output.assign``, and calls ``self.output.format`` before
        ``self.nd.module.exit_json``.
        """
        # gathered state: return gathered list via NDOutput so output_level is always present
        if self.state == "gathered":
            self.log.info(
                f"exit_module: gathered state, returning "
                f"{len(self.changed_dict[0]['gathered'])} resource(s)"
            )
            self.output.assign(
                current=self.translate_gathered_results(self.existing)
            )
            result = self.output.format(
                changed=False,
                gathered=self.changed_dict[0]["gathered"],
            )
            self.nd.module.exit_json(**result)
            return

        changed = (
            len(self.changed_dict[0]["merged"]) > 0
            or len(self.changed_dict[0]["deleted"]) > 0
        )
        if self.nd.module.check_mode:
            self.log.info(
                "exit_module: check_mode is enabled, overriding changed=False "
                f"(would have been changed={changed})"
            )
            changed = False

        self.log.info(
            f"exit_module: merged={len(self.changed_dict[0]['merged'])}, "
            f"deleted={len(self.changed_dict[0]['deleted'])}, "
            f"gathered={len(self.changed_dict[0]['gathered'])}, "
            f"changed={changed}, check_mode={self.nd.module.check_mode}"
        )

        # Re-query to capture post-operation state for current snapshot
        if not self.nd.module.check_mode and changed:
            self._resources_fetched = False
            self._all_resources = []
            self._get_all_resources()
            self.existing = list(self._all_resources)

        self.output.assign(
            previous=self.translate_gathered_results(self.previous),
            current=self.translate_gathered_results(self.existing),
        )
        result = self.output.format(
            changed=changed,
            diff=self.changed_dict,
            response=self.api_responses,
        )
        self.nd.module.exit_json(**result)
